"""The parts of the Cloudflare API this integration uses."""

from __future__ import annotations

from dataclasses import dataclass, field
import json
from typing import Any
from urllib.parse import quote

import aiohttp

from homeassistant.exceptions import HomeAssistantError

API = "https://api.cloudflare.com/client/v4"
WAF_PHASE = "http_request_firewall_custom"
RULE_DESCRIPTION = "cloudflare_mtls: require a client certificate on {host}"


class CloudflareError(HomeAssistantError):
    """A Cloudflare API call failed."""


@dataclass
class Capabilities:
    """What a token can do on a zone, found by trying harmless reads."""

    certs: bool = False
    hosts: bool = False
    waf: bool = False
    dns: bool = False
    tunnels: list[dict[str, Any]] | None = None  # remotely managed tunnels, if any are visible
    other_zones: int = 0
    can_restrict: bool = False  # the token may rewrite its own policy (API Tokens Write)
    extras: list[str] = field(default_factory=list)

    @property
    def broad(self) -> bool:
        """True if the token can do more than manage client certificates on its zone."""
        return bool(self.extras)


def restricted_token_url(account_id: str | None, zone_id: str) -> str:
    """Dashboard link pre-filled with the one permission this integration needs."""
    keys = quote(json.dumps([{"key": "ssl_and_certificates", "type": "edit"}], separators=(",", ":")))
    return (
        f"https://dash.cloudflare.com/profile/api-tokens?permissionGroupKeys={keys}"
        f"&accountId={account_id or '*'}&zoneId={zone_id}&name=Home%20Assistant%20mTLS"
    )


def setup_token_url() -> str:
    """Dashboard link pre-filled with what first-time setup can use (add Tunnel edit by hand)."""
    keys = [
        {"key": "ssl_and_certificates", "type": "edit"},
        {"key": "firewall_services", "type": "edit"},
        {"key": "dns", "type": "edit"},
        {"key": "zone", "type": "read"},
    ]
    encoded = quote(json.dumps(keys, separators=(",", ":")))
    return (
        f"https://dash.cloudflare.com/profile/api-tokens?permissionGroupKeys={encoded}"
        "&accountId=*&zoneId=all&name=Home%20Assistant%20mTLS%20setup"
    )


class CloudflareApi:
    """Thin async client; every method raises CloudflareError on failure."""

    def __init__(self, session: aiohttp.ClientSession, token: str) -> None:
        self._session = session
        self._headers = {"Authorization": f"Bearer {token}"}

    async def _request(self, method: str, path: str, **kwargs: Any) -> tuple[int, dict[str, Any]]:
        try:
            async with self._session.request(method, API + path, headers=self._headers, **kwargs) as resp:
                return resp.status, (await resp.json(content_type=None)) or {}
        except (aiohttp.ClientError, TimeoutError, ValueError) as err:
            raise CloudflareError(f"Cloudflare API unreachable: {err}") from err

    async def call(self, method: str, path: str, **kwargs: Any) -> Any:
        status, body = await self._request(method, path, **kwargs)
        if not body.get("success"):
            errors = "; ".join(e.get("message", "") for e in body.get("errors", [])) or f"HTTP {status}"
            raise CloudflareError(f"Cloudflare {method} {path}: {errors}")
        return body.get("result")

    async def _can(self, path: str, missing_ok: bool = False) -> bool:
        status, body = await self._request("GET", path)
        if body.get("success"):
            return True
        # A missing resource (e.g. no WAF entrypoint yet) still proves read access
        return missing_ok and status == 404

    async def zones(self) -> list[dict[str, Any]]:
        return await self.call("GET", "/zones", params={"per_page": 50})

    async def capabilities(self, zone_id: str, account_id: str | None, zone_count: int) -> Capabilities:
        caps = Capabilities(other_zones=max(zone_count - 1, 0))
        caps.certs = await self._can(f"/zones/{zone_id}/client_certificates?per_page=5")
        caps.hosts = await self._can(f"/zones/{zone_id}/certificate_authorities/hostname_associations")
        caps.waf = await self._can(f"/zones/{zone_id}/rulesets/phases/{WAF_PHASE}/entrypoint", missing_ok=True)
        caps.dns = await self._can(f"/zones/{zone_id}/dns_records?per_page=1")
        if account_id:
            status, body = await self._request("GET", f"/accounts/{account_id}/cfd_tunnel?is_deleted=false")
            # Listing succeeds even without tunnel access; it just shows only what the token may see
            if body.get("success") and body["result"]:
                caps.tunnels = [t for t in body["result"] if t.get("remote_config")]
        caps.can_restrict = await self.can_restrict_self(account_id)
        if caps.other_zones:
            caps.extras.append(f"access to {caps.other_zones} other zone(s)")
        if caps.waf:
            caps.extras.append("WAF rules")
        if caps.dns:
            caps.extras.append("DNS records")
        if caps.tunnels is not None:
            caps.extras.append("Cloudflare Tunnels")
        if caps.can_restrict:
            caps.extras.append("API token management")
        return caps

    async def _own_token(self, account_id: str | None) -> tuple[str, str] | None:
        """Return (tokens endpoint, token id) for this token, user- or account-owned."""
        _status, body = await self._request("GET", "/user/tokens/verify")
        if body.get("success"):
            return "/user/tokens", body["result"]["id"]
        if account_id:
            _status, body = await self._request("GET", f"/accounts/{account_id}/tokens/verify")
            if body.get("success"):
                return f"/accounts/{account_id}/tokens", body["result"]["id"]
        return None

    async def can_restrict_self(self, account_id: str | None) -> bool:
        if not (own := await self._own_token(account_id)):
            return False
        _status, body = await self._request("GET", f"{own[0]}/{own[1]}")
        if not body.get("success"):
            return False
        names = {g["name"] for p in body["result"].get("policies", []) for g in p["permission_groups"]}
        return any(name.endswith("API Tokens Write") for name in names)

    async def restrict_self(self, account_id: str | None, zone_id: str) -> None:
        """Rewrite this token's policy to SSL and Certificates Write on one zone; the secret stays."""
        if not (own := await self._own_token(account_id)):
            raise CloudflareError("Cloudflare: the token can't look itself up")
        base, token_id = own
        token = await self.call("GET", f"{base}/{token_id}")
        groups = await self.call("GET", f"{base}/permission_groups")
        ssl = next(
            (g for g in groups if g["name"] == "SSL and Certificates Write" and "com.cloudflare.api.account.zone" in g["scopes"]),
            None,
        )
        if not ssl:
            raise CloudflareError("Cloudflare: no zone-level SSL and Certificates Write permission group")
        body = {
            "name": token["name"],
            "status": token.get("status", "active"),
            "policies": [
                {
                    "effect": "allow",
                    "resources": {f"com.cloudflare.api.account.zone.{zone_id}": "*"},
                    "permission_groups": [{"id": ssl["id"]}],
                }
            ],
        }
        for key in ("not_before", "expires_on", "condition"):
            if token.get(key):
                body[key] = token[key]
        await self.call("PUT", f"{base}/{token_id}", json=body)

    async def create_cert(self, zone_id: str, csr: str, days: int) -> dict[str, Any]:
        return await self.call("POST", f"/zones/{zone_id}/client_certificates", json={"csr": csr, "validity_days": days})

    async def get_cert(self, zone_id: str, cert_id: str) -> dict[str, Any]:
        return await self.call("GET", f"/zones/{zone_id}/client_certificates/{cert_id}")

    async def revoke_cert(self, zone_id: str, cert_id: str) -> None:
        await self.call("DELETE", f"/zones/{zone_id}/client_certificates/{cert_id}")

    async def mtls_hostnames(self, zone_id: str) -> list[str]:
        result = await self.call("GET", f"/zones/{zone_id}/certificate_authorities/hostname_associations")
        return result.get("hostnames") or []

    async def ensure_mtls_hostname(self, zone_id: str, host: str) -> bool:
        """Require client certificates (Cloudflare-managed CA) on host; True if it changed."""
        hosts = await self.mtls_hostnames(zone_id)
        if host in hosts:
            return False
        # PUT replaces the whole list, so keep the existing hostnames
        await self.call(
            "PUT", f"/zones/{zone_id}/certificate_authorities/hostname_associations", json={"hostnames": [*hosts, host]}
        )
        return True

    async def ensure_waf_rule(self, zone_id: str, host: str, block_mcp: bool) -> None:
        """Block requests to host without a valid, unrevoked client certificate."""
        expression = f'(http.host eq "{host}" and (not cf.tls_client_auth.cert_verified or cf.tls_client_auth.cert_revoked))'
        if block_mcp:
            expression += f' or (http.host eq "{host}" and starts_with(http.request.uri.path, "/api/mcp"))'
        rule = {
            "action": "block",
            "expression": expression,
            "description": RULE_DESCRIPTION.format(host=host),
            "enabled": True,
        }
        status, body = await self._request("GET", f"/zones/{zone_id}/rulesets/phases/{WAF_PHASE}/entrypoint")
        if status == 404:
            await self.call("PUT", f"/zones/{zone_id}/rulesets/phases/{WAF_PHASE}/entrypoint", json={"rules": [rule]})
            return
        if not body.get("success"):
            raise CloudflareError("Cloudflare: cannot read the zone's WAF custom rules")
        ruleset = body["result"]
        existing = next((r for r in ruleset.get("rules", []) if r.get("description") == rule["description"]), None)
        if existing:
            await self.call("PATCH", f"/zones/{zone_id}/rulesets/{ruleset['id']}/rules/{existing['id']}", json=rule)
        else:
            await self.call("POST", f"/zones/{zone_id}/rulesets/{ruleset['id']}/rules", json=rule)

    async def ensure_tunnel_route(self, zone_id: str, account_id: str, tunnel_id: str, host: str, service: str) -> None:
        """Route host to service through a remotely managed tunnel, and point DNS at it."""
        path = f"/accounts/{account_id}/cfd_tunnel/{tunnel_id}/configurations"
        config = (await self.call("GET", path) or {}).get("config") or {}
        ingress = config.get("ingress") or [{"service": "http_status:404"}]
        for item in ingress:
            if item.get("hostname") == host:
                item["service"] = service
                break
        else:
            catch_all = next((i for i, item in enumerate(ingress) if not item.get("hostname")), len(ingress))
            ingress.insert(catch_all, {"hostname": host, "service": service})
        config["ingress"] = ingress
        await self.call("PUT", path, json={"config": config})

        target = f"{tunnel_id}.cfargotunnel.com"
        records = await self.call("GET", f"/zones/{zone_id}/dns_records", params={"name": host})
        if not records:
            await self.call(
                "POST",
                f"/zones/{zone_id}/dns_records",
                json={"type": "CNAME", "name": host, "content": target, "proxied": True, "comment": "cloudflare_mtls"},
            )
        elif not any(r["type"] == "CNAME" and r["content"] == target for r in records):
            raise CloudflareError(f"{host} already has a DNS record that doesn't point at the tunnel; not changing it")
