"""Config flow for Cloudflare mTLS."""

from __future__ import annotations

from typing import Any

import aiohttp
import voluptuous as vol

from homeassistant.config_entries import ConfigFlow, ConfigFlowResult
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.selector import TextSelector, TextSelectorConfig, TextSelectorType

from .const import CF_API, CONF_API_TOKEN, CONF_ZONE_ID, DOMAIN


def _schema(defaults: dict[str, Any]) -> vol.Schema:
    return vol.Schema(
        {
            vol.Required(CONF_API_TOKEN): TextSelector(TextSelectorConfig(type=TextSelectorType.PASSWORD)),
            vol.Required(CONF_ZONE_ID, default=defaults.get(CONF_ZONE_ID, vol.UNDEFINED)): str,
        }
    )


async def _validate(hass: HomeAssistant, data: dict[str, Any]) -> str | None:
    """Return an error key, or None if the token can read the zone's client certificates."""
    try:
        async with async_get_clientsession(hass).get(
            CF_API.format(zone=data[CONF_ZONE_ID]),
            params={"per_page": 5},
            headers={"Authorization": f"Bearer {data[CONF_API_TOKEN]}"},
        ) as resp:
            body = await resp.json(content_type=None)
    except aiohttp.ClientError:
        return "cannot_connect"
    return None if resp.status == 200 and body and body.get("success") else "invalid_auth"


class CloudflareMtlsConfigFlow(ConfigFlow, domain=DOMAIN):
    """Ask for a Cloudflare token that can manage the zone's client certificates."""

    VERSION = 1

    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        errors: dict[str, str] = {}
        if user_input is not None:
            if not (error := await _validate(self.hass, user_input)):
                return self.async_create_entry(title="Cloudflare mTLS", data=user_input)
            errors["base"] = error
        return self.async_show_form(step_id="user", data_schema=_schema(user_input or {}), errors=errors)

    async def async_step_reconfigure(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        entry = self._get_reconfigure_entry()
        errors: dict[str, str] = {}
        if user_input is not None:
            if not (error := await _validate(self.hass, user_input)):
                return self.async_update_reload_and_abort(entry, data=user_input)
            errors["base"] = error
        return self.async_show_form(
            step_id="reconfigure", data_schema=_schema(user_input or dict(entry.data)), errors=errors
        )
