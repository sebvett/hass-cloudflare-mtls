"""Config flow for Cloudflare mTLS."""

from __future__ import annotations

from typing import Any

import aiohttp
import voluptuous as vol

from homeassistant.config_entries import ConfigFlow, ConfigFlowResult
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.network import NoURLAvailableError, get_url
from homeassistant.helpers.selector import (
    BooleanSelector,
    SelectOptionDict,
    SelectSelector,
    SelectSelectorConfig,
    TextSelector,
    TextSelectorConfig,
    TextSelectorType,
)

from .cloudflare import Capabilities, CloudflareApi, CloudflareError, setup_token_url
from .const import CONF_ACCOUNT_ID, CONF_API_TOKEN, CONF_HOSTNAME, CONF_ZONE_ID, CONF_ZONE_NAME, DOMAIN

NO_TUNNEL = "none"
PASSWORD = TextSelector(TextSelectorConfig(type=TextSelectorType.PASSWORD))


class CloudflareMtlsConfigFlow(ConfigFlow, domain=DOMAIN):
    """Token, zone, then the automatic or the manual path."""

    VERSION = 1

    def __init__(self) -> None:
        self._token = ""
        self._zones: list[dict[str, Any]] = []
        self._zone: dict[str, Any] = {}
        self._caps = Capabilities()
        self._host = ""
        self._report: list[str] = []

    def _api(self, token: str | None = None) -> CloudflareApi:
        return CloudflareApi(async_get_clientsession(self.hass), token or self._token)

    @property
    def _account_id(self) -> str | None:
        return self._zone.get("account", {}).get("id")

    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        errors: dict[str, str] = {}
        if user_input is not None:
            self._token = user_input[CONF_API_TOKEN]
            try:
                self._zones = await self._api().zones()
            except CloudflareError:
                errors["base"] = "invalid_auth"
            else:
                if not self._zones:
                    errors["base"] = "no_zones"
                elif len(self._zones) == 1:
                    return await self._async_pick_zone(self._zones[0])
                else:
                    return await self.async_step_zone()
        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema({vol.Required(CONF_API_TOKEN): PASSWORD}),
            errors=errors,
            description_placeholders={"setup_url": setup_token_url()},
        )

    async def async_step_zone(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        if user_input is not None:
            return await self._async_pick_zone(next(z for z in self._zones if z["id"] == user_input[CONF_ZONE_ID]))
        options = [SelectOptionDict(value=z["id"], label=z["name"]) for z in self._zones]
        return self.async_show_form(
            step_id="zone",
            data_schema=vol.Schema({vol.Required(CONF_ZONE_ID): SelectSelector(SelectSelectorConfig(options=options))}),
        )

    async def _async_pick_zone(self, zone: dict[str, Any]) -> ConfigFlowResult:
        self._zone = zone
        await self.async_set_unique_id(zone["id"])
        self._abort_if_unique_id_configured()
        self._caps = await self._api().capabilities(zone["id"], self._account_id, len(self._zones))
        if not self._caps.certs:
            return self.async_abort(reason="missing_certs")
        if self._caps.hosts and self._caps.waf:
            return await self.async_step_automatic()
        return await self.async_step_manual()

    def _check_host(self, user_input: dict[str, Any]) -> str | None:
        """Normalise the hostname into self._host; return an error key if it's not in the zone."""
        self._host = user_input[CONF_HOSTNAME].strip().lower().rstrip(".")
        zone = self._zone["name"]
        return None if self._host == zone or self._host.endswith("." + zone) else "not_in_zone"

    def _create(self) -> ConfigFlowResult:
        return self.async_create_entry(
            title=self._host,
            data={
                CONF_API_TOKEN: self._token,
                CONF_ZONE_ID: self._zone["id"],
                CONF_ZONE_NAME: self._zone["name"],
                CONF_ACCOUNT_ID: self._account_id,
                CONF_HOSTNAME: self._host,
            },
        )

    async def async_step_automatic(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        caps, zone = self._caps, self._zone["name"]
        can_route = bool(caps.tunnels and caps.dns)
        errors: dict[str, str] = {}
        placeholders = {
            "zone": zone,
            "tunnel": " and, if you pick a tunnel, route the hostname through it" if can_route else "",
            "after": (
                f"restrict its own token to SSL and Certificates: Edit on {zone}"
                if caps.can_restrict
                else "ask you, in Repairs, to swap the token for a restricted one"
            ),
            "error": "",
        }
        if user_input is not None and not (error := self._check_host(user_input)):
            try:
                await self._async_configure(user_input)
            except CloudflareError as err:
                errors["base"] = "setup_failed"
                placeholders["error"] = str(err)
            else:
                return self._create()
        elif user_input is not None:
            errors[CONF_HOSTNAME] = error

        fields: dict[Any, Any] = {
            vol.Required(CONF_HOSTNAME, default=f"hass.{zone}"): str,
            vol.Required("block_mcp", default=True): BooleanSelector(),
        }
        if can_route:
            options = [SelectOptionDict(value=NO_TUNNEL, label="Don't change routing")] + [
                SelectOptionDict(value=t["id"], label=t["name"]) for t in caps.tunnels
            ]
            default = caps.tunnels[0]["id"] if len(caps.tunnels) == 1 else NO_TUNNEL
            fields[vol.Required("tunnel", default=default)] = SelectSelector(SelectSelectorConfig(options=options))
            fields[vol.Required("service", default=self._local_url())] = str
        return self.async_show_form(
            step_id="automatic",
            data_schema=self.add_suggested_values_to_schema(vol.Schema(fields), user_input or {}),
            errors=errors,
            description_placeholders=placeholders,
        )

    def _local_url(self) -> str:
        try:
            return get_url(self.hass, allow_external=False, allow_cloud=False, prefer_external=False)
        except NoURLAvailableError:
            return "http://homeassistant.local:8123"

    async def _async_configure(self, options: dict[str, Any]) -> None:
        api, zone_id, host = self._api(), self._zone["id"], self._host
        await api.ensure_mtls_hostname(zone_id, host)
        await api.ensure_waf_rule(zone_id, host, options.get("block_mcp", True))
        if options.get("tunnel", NO_TUNNEL) != NO_TUNNEL:
            await api.ensure_tunnel_route(zone_id, self._account_id, options["tunnel"], host, options["service"].rstrip("/"))
        # Last, since it takes away the permissions the steps above need
        if self._caps.can_restrict:
            await api.restrict_self(self._account_id, zone_id)

    async def async_step_manual(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        zone = self._zone["name"]
        errors: dict[str, str] = {}
        if user_input is not None:
            if error := self._check_host(user_input):
                errors[CONF_HOSTNAME] = error
            else:
                self._report = await self._async_check_manual_setup()
                return await self.async_step_manual_check()
        return self.async_show_form(
            step_id="manual",
            data_schema=vol.Schema({vol.Required(CONF_HOSTNAME, default=f"hass.{zone}"): str}),
            errors=errors,
            description_placeholders={"zone": zone, "setup_url": setup_token_url()},
        )

    async def _async_check_manual_setup(self) -> list[str]:
        """Check what can be checked of a hand-made setup, fixing mTLS if the token may."""
        report: list[str] = []
        api, host = self._api(), self._host
        if self._caps.hosts:
            try:
                if await api.ensure_mtls_hostname(self._zone["id"], host):
                    report.append(f"✅ Client certificates were not required on {host}; they are now.")
                else:
                    report.append(f"✅ Cloudflare requires client certificates on {host}.")
            except CloudflareError as err:
                report.append(f"⚠️ Could not turn on client certificates for {host}: {err}")
        else:
            report.append("⚠️ This token can't see which hostnames require client certificates; check it in Cloudflare.")
        report.append(await self._async_probe(host))
        return report

    async def _async_probe(self, host: str) -> str:
        """Request the hostname without a certificate: Cloudflare should block it."""
        session = async_get_clientsession(self.hass)
        try:
            async with session.get(
                f"https://{host}/manifest.json", allow_redirects=False, timeout=aiohttp.ClientTimeout(total=15)
            ) as resp:
                status, cloudflare = resp.status, "cf-ray" in resp.headers
        except (aiohttp.ClientError, TimeoutError) as err:
            return f"⚠️ {host} can't be reached yet ({type(err).__name__}). Check its DNS record and tunnel route."
        if status == 403 and cloudflare:
            return "✅ A request without a certificate is blocked by Cloudflare."
        if not cloudflare:
            return f"⚠️ {host} doesn't seem to be served through Cloudflare (HTTP {status})."
        return (
            f"⚠️ A request without a certificate got HTTP {status}, so it isn't blocked. Add the WAF rule from the "
            "documentation. (A brand-new certificate or rule can take a few minutes to apply.)"
        )

    async def async_step_manual_check(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        if user_input is not None:
            return self._create()
        return self.async_show_form(
            step_id="manual_check",
            data_schema=vol.Schema({}),
            description_placeholders={"report": "\n".join(f"- {line}" for line in self._report)},
        )

    async def async_step_reconfigure(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        entry = self._get_reconfigure_entry()
        errors: dict[str, str] = {}
        if user_input is not None:
            api = self._api(user_input[CONF_API_TOKEN])
            try:
                await api.call("GET", f"/zones/{entry.data[CONF_ZONE_ID]}/client_certificates", params={"per_page": 5})
            except CloudflareError:
                errors["base"] = "invalid_auth"
            else:
                return self.async_update_reload_and_abort(entry, data_updates=user_input)
        return self.async_show_form(
            step_id="reconfigure",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_API_TOKEN): PASSWORD,
                    vol.Required(CONF_HOSTNAME, default=entry.data.get(CONF_HOSTNAME, "")): str,
                }
            ),
            errors=errors,
        )
