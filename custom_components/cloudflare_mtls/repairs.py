"""Repair flows for Cloudflare mTLS."""

from __future__ import annotations

from typing import Any

import voluptuous as vol

from homeassistant.components.repairs import RepairsFlow
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResult
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.selector import TextSelector, TextSelectorConfig, TextSelectorType

from .cloudflare import CloudflareApi, CloudflareError, restricted_token_url
from .const import CONF_ACCOUNT_ID, CONF_API_TOKEN, CONF_HOSTNAME, CONF_ZONE_ID, CONF_ZONE_NAME, ISSUE_BROAD_TOKEN


class RestrictTokenFlow(RepairsFlow):
    """Swap the setup token for one limited to client certificates on the zone."""

    def __init__(self, entry_id: str) -> None:
        self._entry_id = entry_id

    async def async_step_init(self, user_input: dict[str, Any] | None = None) -> FlowResult:
        # HA passes {"issue_id": ...} here, so the forms live in their own steps
        entry = self.hass.config_entries.async_get_entry(self._entry_id)
        api = CloudflareApi(async_get_clientsession(self.hass), entry.data[CONF_API_TOKEN])
        if await api.can_restrict_self(entry.data.get(CONF_ACCOUNT_ID)):
            return self.async_show_menu(step_id="choose", menu_options=["restrict", "token"])
        return await self.async_step_token()

    async def async_step_restrict(self, user_input: dict[str, Any] | None = None) -> FlowResult:
        entry = self.hass.config_entries.async_get_entry(self._entry_id)
        errors: dict[str, str] = {}
        placeholders = {"zone": entry.data.get(CONF_ZONE_NAME, entry.data[CONF_ZONE_ID]), "error": ""}
        if user_input is not None:
            api = CloudflareApi(async_get_clientsession(self.hass), entry.data[CONF_API_TOKEN])
            try:
                await api.restrict_self(entry.data.get(CONF_ACCOUNT_ID), entry.data[CONF_ZONE_ID])
            except CloudflareError as err:
                errors["base"] = "restrict_failed"
                placeholders["error"] = str(err)
            else:
                self.hass.config_entries.async_schedule_reload(entry.entry_id)
                return self.async_create_entry(data={})
        return self.async_show_form(
            step_id="restrict", data_schema=vol.Schema({}), errors=errors, description_placeholders=placeholders
        )

    async def async_step_token(self, user_input: dict[str, Any] | None = None) -> FlowResult:
        entry = self.hass.config_entries.async_get_entry(self._entry_id)
        errors: dict[str, str] = {}
        if user_input is not None:
            api = CloudflareApi(async_get_clientsession(self.hass), user_input[CONF_API_TOKEN])
            try:
                await api.call("GET", f"/zones/{entry.data[CONF_ZONE_ID]}/client_certificates", params={"per_page": 5})
                zones = await api.zones()
                caps = await api.capabilities(entry.data[CONF_ZONE_ID], entry.data.get(CONF_ACCOUNT_ID), len(zones))
            except CloudflareError:
                errors["base"] = "invalid_auth"
            else:
                if caps.broad:
                    errors["base"] = "still_broad"
                else:
                    self.hass.config_entries.async_update_entry(
                        entry, data={**entry.data, CONF_API_TOKEN: user_input[CONF_API_TOKEN]}
                    )
                    self.hass.config_entries.async_schedule_reload(entry.entry_id)
                    return self.async_create_entry(data={})
        return self.async_show_form(
            step_id="token",
            data_schema=vol.Schema(
                {vol.Required(CONF_API_TOKEN): TextSelector(TextSelectorConfig(type=TextSelectorType.PASSWORD))}
            ),
            errors=errors,
            description_placeholders={
                "url": restricted_token_url(entry.data.get(CONF_ACCOUNT_ID), entry.data[CONF_ZONE_ID])
            },
        )


class EnableMtlsFlow(RepairsFlow):
    """Turn client-certificate checking back on for the hostname."""

    def __init__(self, entry_id: str) -> None:
        self._entry_id = entry_id

    async def async_step_init(self, user_input: dict[str, Any] | None = None) -> FlowResult:
        return await self.async_step_confirm()

    async def async_step_confirm(self, user_input: dict[str, Any] | None = None) -> FlowResult:
        entry = self.hass.config_entries.async_get_entry(self._entry_id)
        host = entry.data[CONF_HOSTNAME]
        errors: dict[str, str] = {}
        placeholders = {"host": host, "error": ""}
        if user_input is not None:
            api = CloudflareApi(async_get_clientsession(self.hass), entry.data[CONF_API_TOKEN])
            try:
                await api.ensure_mtls_hostname(entry.data[CONF_ZONE_ID], host)
            except CloudflareError as err:
                errors["base"] = "setup_failed"
                placeholders["error"] = str(err)
            else:
                return self.async_create_entry(data={})
        return self.async_show_form(
            step_id="confirm", data_schema=vol.Schema({}), errors=errors, description_placeholders=placeholders
        )


async def async_create_fix_flow(
    hass: HomeAssistant, issue_id: str, data: dict[str, Any] | None
) -> RepairsFlow:
    entry_id = (data or {})["entry_id"]
    if issue_id == ISSUE_BROAD_TOKEN:
        return RestrictTokenFlow(entry_id)
    return EnableMtlsFlow(entry_id)
