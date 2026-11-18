"""Cloudflare mTLS: a client certificate for every Home Assistant app install."""

from __future__ import annotations

import asyncio
import base64
from datetime import timedelta
import html
from ipaddress import ip_address
import logging
import secrets
import time
from typing import Any

from aiohttp import web
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID
import voluptuous as vol

from homeassistant.config_entries import (
    SIGNAL_CONFIG_ENTRY_CHANGED,
    ConfigEntry,
    ConfigEntryChange,
)
from homeassistant.core import (
    HomeAssistant,
    ServiceCall,
    ServiceResponse,
    SupportsResponse,
    callback,
)
from homeassistant.exceptions import HomeAssistantError, ServiceValidationError
from homeassistant.helpers import config_validation as cv, device_registry as dr, issue_registry as ir
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.event import async_track_time_interval
from homeassistant.helpers.http import KEY_HASS, HomeAssistantView
from homeassistant.helpers.network import get_url
from homeassistant.helpers.storage import Store
from homeassistant.util import slugify
from homeassistant.util.network import is_local

from .cloudflare import CloudflareApi, CloudflareError, restricted_token_url
from .const import (
    CERT_DAYS,
    CONF_ACCOUNT_ID,
    CONF_API_TOKEN,
    CONF_HOSTNAME,
    CONF_ZONE_ID,
    CONF_ZONE_NAME,
    DOMAIN,
    DOWNLOAD_GRACE,
    ENROLL_PATH,
    ISSUE_BROAD_TOKEN,
    ISSUE_MTLS_OFF,
    LINK_TTL,
    NOTIFY_WAIT,
)

_LOGGER = logging.getLogger(__name__)

CONFIG_SCHEMA = cv.config_entry_only_config_schema(DOMAIN)

DEVICE_SCHEMA = vol.Schema({vol.Required("device_id"): cv.string})
ADOPT_SCHEMA = DEVICE_SCHEMA.extend({vol.Required("certificate_id"): cv.string})


def _make_csr(common_name: str) -> tuple[ec.EllipticCurvePrivateKey, str]:
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .sign(key, hashes.SHA256())
    )
    return key, csr.public_bytes(serialization.Encoding.PEM).decode()


def _make_p12(key: ec.EllipticCurvePrivateKey, cert_pem: str, name: str, password: str) -> bytes:
    # SHA1/3DES is the PKCS#12 encoding both Android's installer and iOS accept
    encryption = (
        serialization.PrivateFormat.PKCS12.encryption_builder()
        .kdf_rounds(2048)
        .key_cert_algorithm(pkcs12.PBES.PBESv1SHA1And3KeyTripleDESCBC)
        .hmac_hash(hashes.SHA1())
        .build(password.encode())
    )
    cert = x509.load_pem_x509_certificate(cert_pem.encode())
    return pkcs12.serialize_key_and_certificates(name.encode(), key, cert, None, encryption)


class CertManager:
    """Keeps one client certificate per mobile_app entry in step with Cloudflare."""

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        self.hass = hass
        self.api = CloudflareApi(async_get_clientsession(hass), entry.data[CONF_API_TOKEN])
        self.zone_id = entry.data[CONF_ZONE_ID]
        self._store: Store[dict[str, Any]] = Store(hass, 1, DOMAIN)
        # known: mobile_app entry ids seen; certs: entry id -> cert; links: token -> pending download
        self.data: dict[str, Any] = {"known": None, "certs": {}, "links": {}}
        self._lock = asyncio.Lock()

    async def async_load(self) -> None:
        if stored := await self._store.async_load():
            self.data = stored

    async def _save(self) -> None:
        await self._store.async_save(self.data)

    def mobile_entries(self) -> dict[str, ConfigEntry]:
        return {e.entry_id: e for e in self.hass.config_entries.async_entries("mobile_app")}

    def link_url(self, token: str) -> str:
        base = get_url(self.hass, allow_external=False, allow_cloud=False, prefer_external=False)
        return f"{base}{ENROLL_PATH}/{token}"

    async def async_seed(self) -> None:
        """On first setup, record the existing app installs without issuing anything."""
        if self.data["known"] is None:
            self.data["known"] = sorted(self.mobile_entries())
            await self._save()
            _LOGGER.info("Recorded %d existing app install(s)", len(self.data["known"]))

    async def async_catch_up(self) -> None:
        current = self.mobile_entries()
        new = [e for e in current if e not in self.data["known"]]
        gone = [e for e in self.data["certs"] if e not in current]
        self.data["known"] = sorted(current)
        await self._save()
        if gone and not current:
            _LOGGER.warning("No mobile_app entries found; not revoking %d certificate(s)", len(gone))
            gone = []
        for eid in gone:
            try:
                await self.async_revoke(eid)
            except HomeAssistantError as err:  # stays recorded, so the next setup retries
                _LOGGER.error("Revoking the certificate of removed app %s: %s", eid, err)
        for eid in new:
            try:
                await self.async_issue(current[eid])
            except HomeAssistantError as err:
                _LOGGER.error("Issuing a certificate for %s: %s", current[eid].title, err)

    @callback
    def async_entry_changed(self, change: ConfigEntryChange, entry: ConfigEntry) -> None:
        if entry.domain != "mobile_app":
            return
        if change == ConfigEntryChange.ADDED:
            self.hass.async_create_task(self._async_added(entry))
        elif change == ConfigEntryChange.REMOVED:
            self.hass.async_create_task(self._async_removed(entry.entry_id))

    async def _async_added(self, entry: ConfigEntry) -> None:
        self.data["known"].append(entry.entry_id)
        await self._save()
        try:
            await self.async_issue(entry)
        except HomeAssistantError as err:
            _LOGGER.error("Issuing a certificate for %s: %s", entry.title, err)

    async def _async_removed(self, entry_id: str) -> None:
        if entry_id in self.data["known"]:
            self.data["known"].remove(entry_id)
            await self._save()
        try:
            await self.async_revoke(entry_id)
        except HomeAssistantError as err:
            _LOGGER.error("Revoking the certificate of removed app %s: %s", entry_id, err)

    async def async_issue(self, entry: ConfigEntry) -> str:
        """Issue a certificate for the app install, replacing any earlier one; return the link."""
        eid, title = entry.entry_id, entry.title
        async with self._lock:
            key, csr = await self.hass.async_add_executor_job(_make_csr, f"hass {title[:32]} {eid[-8:]}")
            res = await self.api.create_cert(self.zone_id, csr, CERT_DAYS)
            password = "-".join(secrets.token_hex(2) for _ in range(4))
            p12 = await self.hass.async_add_executor_job(
                _make_p12, key, res["certificate"], f"Home Assistant ({title})", password
            )
            old = self.data["certs"].get(eid)
            self.data["certs"][eid] = {"cf_id": res["id"], "title": title, "issued": int(time.time())}
            self._drop_links(eid)
            token = secrets.token_urlsafe(24)
            self.data["links"][token] = {
                "entry_id": eid,
                "title": title,
                "password": password,
                "p12": base64.b64encode(p12).decode(),
                "expires": int(time.time()) + LINK_TTL,
            }
            await self._save()
        _LOGGER.info("Issued client certificate %s for %s", res["id"], title)
        self.hass.async_create_background_task(self._async_notify(entry, token), f"{DOMAIN} notify {title}")
        if old:
            try:
                await self.api.revoke_cert(self.zone_id, old["cf_id"])
            except HomeAssistantError as err:
                _LOGGER.error("Revoke the replaced certificate %s in Cloudflare: %s", old["cf_id"], err)
        return self.link_url(token)

    async def async_revoke(self, entry_id: str) -> bool:
        async with self._lock:
            if not (cert := self.data["certs"].get(entry_id)):
                return False
            await self.api.revoke_cert(self.zone_id, cert["cf_id"])
            del self.data["certs"][entry_id]
            self._drop_links(entry_id)
            await self._save()
        _LOGGER.info("Revoked client certificate %s of %s", cert["cf_id"], cert["title"])
        return True

    async def async_adopt(self, entry: ConfigEntry, cert_id: str) -> None:
        """Record a certificate made elsewhere (e.g. in the dashboard) as this device's."""
        cert = await self.api.get_cert(self.zone_id, cert_id)
        if cert["status"] != "active":
            raise ServiceValidationError(f"Certificate {cert_id} is {cert['status']}")
        async with self._lock:
            self.data["certs"][entry.entry_id] = {"cf_id": cert_id, "title": entry.title, "issued": int(time.time())}
            await self._save()

    async def _async_notify(self, entry: ConfigEntry, token: str) -> None:
        # mobile_app registers notify.mobile_app_<device name> once the app has sent its push token
        service = slugify(f"mobile_app_{entry.data['device_name']}")
        deadline = time.monotonic() + NOTIFY_WAIT
        while not self.hass.services.has_service("notify", service):
            if time.monotonic() > deadline or entry.entry_id not in self.mobile_entries():
                _LOGGER.warning(
                    "%s has no push registration; get its link with the cloudflare_mtls.list action", entry.title
                )
                return
            await asyncio.sleep(10)
        url = self.link_url(token)
        await self.hass.services.async_call(
            "notify",
            service,
            {
                "title": "Remote access certificate",
                "message": "Only works on home Wi-Fi. Expires in 24 hours.",
                "data": {
                    "clickAction": url,
                    "url": url,
                    "tag": DOMAIN,
                    "actions": [{"action": "URI", "title": "Install", "uri": url}],
                },
            },
            blocking=True,
        )
        _LOGGER.info("Sent the certificate link to %s", entry.title)

    def _drop_links(self, entry_id: str) -> None:
        for token in [t for t, link in self.data["links"].items() if link["entry_id"] == entry_id]:
            del self.data["links"][token]

    async def async_expire_links(self, _now: Any = None) -> None:
        now = time.time()
        stale = [
            t
            for t, link in self.data["links"].items()
            if link["expires"] < now or link.get("downloaded", now) + DOWNLOAD_GRACE < now
        ]
        for token in stale:
            del self.data["links"][token]
        if stale:
            await self._save()


PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Remote access certificate</title>
<style>
:root{{--bg:#f6f7f9;--fg:#1c1f24;--muted:#5d6470;--card:#fff;--accent:#0b72c7;--line:#dde1e6}}
@media (prefers-color-scheme:dark){{:root{{--bg:#15171a;--fg:#e8eaed;--muted:#9aa1ab;--card:#1f2226;--accent:#4aa3f0;--line:#33373d}}}}
body{{margin:0;background:var(--bg);color:var(--fg);font:16px/1.5 system-ui,sans-serif}}
main{{max-width:34rem;margin:0 auto;padding:24px 16px}}
.card{{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:20px;margin:16px 0}}
code{{display:block;font:600 1.5rem/1.3 ui-monospace,monospace;letter-spacing:.04em;margin:8px 0;user-select:all;word-break:break-all}}
a.btn{{display:block;text-align:center;background:var(--accent);color:#fff;text-decoration:none;font-weight:600;padding:14px;border-radius:10px}}
ol{{padding-left:1.2rem}} li{{margin:6px 0}} small{{color:var(--muted)}}
</style></head><body><main>
<h1>Remote access for {title}</h1>
<div class="card"><small>Certificate password</small><code>{password}</code>
<a class="btn" href="{token}/hass.p12" download="hass.p12">Download certificate</a></div>
<div class="card"><strong>Android</strong><ol>
<li>Copy the password above, then tap <b>Download certificate</b>.</li>
<li>Open the downloaded <b>hass.p12</b>. If the phone says it can't be installed from there, go to
Settings &gt; Security &amp; privacy &gt; More security settings &gt; Encryption &amp; credentials &gt;
Install a certificate &gt; <b>VPN &amp; app user certificate</b> and pick the file.</li>
<li>Enter the password and keep the suggested name.</li>
<li>When the Home Assistant app asks you to choose a certificate, pick this one.</li></ol></div>
<div class="card"><strong>iPhone</strong><ol>
<li>Copy the password, download the certificate and save it to Files.</li>
<li>In the Home Assistant app, open the server's settings, choose the client certificate option and import <b>hass.p12</b> with the password.</li></ol></div>
<p><small>This link only works on home Wi-Fi. It stops working 10 minutes after the download, or at the latest {expires}.</small></p>
</main></body></html>"""


class EnrollView(HomeAssistantView):
    """One-time certificate download page, for local client addresses only."""

    url = ENROLL_PATH + "/{token}"
    extra_urls = [ENROLL_PATH + "/{token}/hass.p12"]
    name = "api:cloudflare_mtls:enroll"
    requires_auth = False

    async def get(self, request: web.Request, token: str) -> web.Response:
        hass = request.app[KEY_HASS]
        try:
            local = is_local(ip_address(request.remote or ""))
        except ValueError:
            local = False
        # Belt and braces: never serve anything that came through Cloudflare, even if a
        # reverse proxy without X-Forwarded-For makes it look local
        local = local and not any(h in request.headers for h in ("CF-Connecting-IP", "CF-Ray"))
        headers = {"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"}
        if not local:
            return web.Response(status=403, text="Forbidden\n", headers=headers)
        manager: CertManager | None = hass.data.get(DOMAIN)
        if manager:
            await manager.async_expire_links()
        link = manager.data["links"].get(token) if manager else None
        if not link:
            return web.Response(status=404, text="This link has expired or was already used.\n", headers=headers)
        if request.path.endswith("/hass.p12"):
            link.setdefault("downloaded", int(time.time()))
            await manager._save()
            headers["Content-Disposition"] = 'attachment; filename="hass.p12"'
            return web.Response(body=base64.b64decode(link["p12"]), content_type="application/x-pkcs12", headers=headers)
        page = PAGE.format(
            title=html.escape(link["title"]),
            password=html.escape(link["password"]),
            token=html.escape(token),
            expires=time.strftime("%a %d %b %H:%M", time.localtime(link["expires"])),
        )
        return web.Response(text=page, content_type="text/html", headers=headers)


def _entry_for_device(hass: HomeAssistant, device_id: str) -> ConfigEntry:
    device = dr.async_get(hass).async_get(device_id)
    entry = hass.config_entries.async_get_entry(device.config_entry_id) if device else None
    if entry and entry.domain == "mobile_app":
        return entry
    raise ServiceValidationError("Pick a device registered by the Home Assistant app")


async def async_check_cloudflare(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Raise repair issues for a token broader than needed and a hostname without mTLS."""
    api = CloudflareApi(async_get_clientsession(hass), entry.data[CONF_API_TOKEN])
    zone_id = entry.data[CONF_ZONE_ID]
    try:
        zones = await api.zones()
        if not entry.data.get(CONF_ACCOUNT_ID) and (zone := next((z for z in zones if z["id"] == zone_id), None)):
            # Entries made before 1.1 only stored the zone ID
            hass.config_entries.async_update_entry(
                entry, data={**entry.data, CONF_ACCOUNT_ID: zone["account"]["id"], CONF_ZONE_NAME: zone["name"]}
            )
        caps = await api.capabilities(zone_id, entry.data.get(CONF_ACCOUNT_ID), len(zones))
    except CloudflareError as err:
        _LOGGER.warning("Checking the Cloudflare token: %s", err)
        return
    if caps.broad:
        ir.async_create_issue(
            hass,
            DOMAIN,
            ISSUE_BROAD_TOKEN,
            is_fixable=True,
            severity=ir.IssueSeverity.WARNING,
            translation_key=ISSUE_BROAD_TOKEN,
            translation_placeholders={
                "extras": ", ".join(caps.extras),
                "url": restricted_token_url(entry.data.get(CONF_ACCOUNT_ID), zone_id),
            },
            data={"entry_id": entry.entry_id},
        )
    else:
        ir.async_delete_issue(hass, DOMAIN, ISSUE_BROAD_TOKEN)

    host = entry.data.get(CONF_HOSTNAME)
    if host and caps.hosts and host not in await api.mtls_hostnames(zone_id):
        ir.async_create_issue(
            hass,
            DOMAIN,
            ISSUE_MTLS_OFF,
            is_fixable=True,
            severity=ir.IssueSeverity.ERROR,
            translation_key=ISSUE_MTLS_OFF,
            translation_placeholders={"host": host},
            data={"entry_id": entry.entry_id},
        )
    else:
        ir.async_delete_issue(hass, DOMAIN, ISSUE_MTLS_OFF)


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    manager = CertManager(hass, entry)
    await manager.async_load()
    await manager.async_seed()
    hass.data[DOMAIN] = manager
    entry.async_on_unload(async_dispatcher_connect(hass, SIGNAL_CONFIG_ENTRY_CHANGED, manager.async_entry_changed))
    entry.async_on_unload(async_track_time_interval(hass, manager.async_expire_links, timedelta(hours=1)))
    entry.async_create_background_task(hass, manager.async_catch_up(), f"{DOMAIN} catch up")
    entry.async_create_background_task(hass, async_check_cloudflare(hass, entry), f"{DOMAIN} check token")

    if not hass.data.get(f"{DOMAIN}_view"):  # views can't be unregistered; it answers 404 while unloaded
        hass.http.register_view(EnrollView())
        hass.data[f"{DOMAIN}_view"] = True

    async def issue(call: ServiceCall) -> ServiceResponse:
        return {"url": await manager.async_issue(_entry_for_device(hass, call.data["device_id"]))}

    async def revoke(call: ServiceCall) -> ServiceResponse:
        return {"revoked": await manager.async_revoke(_entry_for_device(hass, call.data["device_id"]).entry_id)}

    async def adopt(call: ServiceCall) -> None:
        await manager.async_adopt(_entry_for_device(hass, call.data["device_id"]), call.data["certificate_id"])

    async def list_certs(call: ServiceCall) -> ServiceResponse:
        apps = manager.mobile_entries()
        return {
            "devices": [
                {
                    "name": app.title,
                    "certificate_id": manager.data["certs"].get(eid, {}).get("cf_id"),
                    "links": [
                        manager.link_url(t) for t, link in manager.data["links"].items() if link["entry_id"] == eid
                    ],
                }
                for eid, app in apps.items()
            ]
        }

    hass.services.async_register(DOMAIN, "issue", issue, DEVICE_SCHEMA, SupportsResponse.OPTIONAL)
    hass.services.async_register(DOMAIN, "revoke", revoke, DEVICE_SCHEMA, SupportsResponse.OPTIONAL)
    hass.services.async_register(DOMAIN, "adopt", adopt, ADOPT_SCHEMA)
    hass.services.async_register(DOMAIN, "list", list_certs, supports_response=SupportsResponse.ONLY)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    for service in ("issue", "revoke", "adopt", "list"):
        hass.services.async_remove(DOMAIN, service)
    hass.data.pop(DOMAIN, None)
    return True
