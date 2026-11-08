"""AwoX integration."""

import asyncio
import logging

from .awox_mesh import AwoxMesh
from .connectz_mesh import AwoxMeshZ
from .const import DOMAIN, CONF_MESH_NAME, CONF_MESH_PASSWORD, CONF_MESH_KEY

from homeassistant.components.light import DOMAIN as LIGHT_DOMAIN
from homeassistant.components.switch import DOMAIN as SWITCH_DOMAIN
from homeassistant.components.sensor import DOMAIN as SENSOR_DOMAIN
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.const import CONF_DEVICES


PLATFORMS = [SENSOR_DOMAIN, LIGHT_DOMAIN, SWITCH_DOMAIN]

_LOGGER = logging.getLogger(__name__)


async def async_setup(hass, config):
    """Set up a skeleton component."""

    hass.data[DOMAIN] = {}
    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up awox light via a config (flow) entry."""

    _LOGGER.info('setup config flow entry %s', entry.data)

    # EGLO connect.Z devices (cloud type ".ble.zigbee...") need the connect.Z BLE protocol
    connect_z = any(d.get('type', '').startswith('.ble.zigbee') for d in entry.data.get(CONF_DEVICES, []))
    if connect_z:
        # connect.Z: HA's Bluetooth stack (bleak), status from advertisements
        mesh = AwoxMeshZ(hass, entry.data[CONF_MESH_NAME], entry.data[CONF_MESH_PASSWORD])
    else:
        mesh = AwoxMesh(hass, entry.data[CONF_MESH_NAME], entry.data[CONF_MESH_PASSWORD], entry.data[CONF_MESH_KEY])

    # Make `mesh` accessible for all platforms
    hass.data[DOMAIN][entry.entry_id] = mesh

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    if connect_z:
        # Only now: advertisement callbacks fire immediately and need the entities to be added
        mesh.async_start()

    return True


async def async_unload_entry(hass, entry) -> bool:
    """Unload a config entry."""
    _LOGGER.info('Unload entry %s', entry.entry_id)
    if entry.entry_id in hass.data[DOMAIN]:
        await hass.data[DOMAIN][entry.entry_id].async_shutdown()

    unload_ok = all(
        await asyncio.gather(
            *[
                hass.config_entries.async_forward_entry_unload(entry, component)
                for component in PLATFORMS
            ]
        )
    )
    if unload_ok:
        hass.data[DOMAIN].pop(entry.entry_id)

    return unload_ok
