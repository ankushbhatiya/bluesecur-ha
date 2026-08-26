"""Button platform for Hoermann BlueSecur - one button per configured channel."""
from __future__ import annotations

import json
import logging

import voluptuous as vol

import homeassistant.helpers.config_validation as cv
from homeassistant.components.button import ButtonEntity, PLATFORM_SCHEMA
from homeassistant.const import CONF_ADDRESS
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.typing import ConfigType, DiscoveryInfoType

from .protocol import send_channel_command

_LOGGER = logging.getLogger(__name__)

CONF_CREDENTIALS_FILE = "credentials_file"

PLATFORM_SCHEMA = PLATFORM_SCHEMA.extend({
    vol.Required(CONF_ADDRESS): cv.string,
    vol.Required(CONF_CREDENTIALS_FILE): cv.string,
})


async def async_setup_platform(
    hass: HomeAssistant,
    config: ConfigType,
    async_add_entities: AddEntitiesCallback,
    discovery_info: DiscoveryInfoType | None = None,
) -> None:
    address = config[CONF_ADDRESS]
    creds_path = config[CONF_CREDENTIALS_FILE]

    def _load_credentials():
        with open(creds_path) as f:
            return json.load(f)

    creds = await hass.async_add_executor_job(_load_credentials)

    entities = [
        BlueSecurButton(
            address=address,
            root_id=creds["root_id"],
            user_id=creds["user_id"],
            key_hex=creds["key_data_hex"],
            channel_name=name,
            command_id=info["commandId"],
        )
        for name, info in creds["channels"].items()
    ]
    async_add_entities(entities)


class BlueSecurButton(ButtonEntity):
    """A single BlueSecur channel, exposed as a button (matches how the app
    presents it - a momentary trigger, not a stateful toggle)."""

    _attr_has_entity_name = True

    def __init__(self, address: str, root_id: int, user_id: int, key_hex: str,
                 channel_name: str, command_id: int) -> None:
        self._address = address
        self._root_id = root_id
        self._user_id = user_id
        self._key_hex = key_hex
        self._command_id = command_id
        self._attr_name = channel_name
        self._attr_unique_id = f"bluesecur_{address}_{command_id}"

    async def async_press(self) -> None:
        _LOGGER.info("BlueSecur: sending channel %s (0x%04x) to %s",
                     self._attr_name, self._command_id, self._address)
        await send_channel_command(
            address=self._address,
            root_id=self._root_id,
            user_id=self._user_id,
            key_hex=self._key_hex,
            command_id=self._command_id,
        )
