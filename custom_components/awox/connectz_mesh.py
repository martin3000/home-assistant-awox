"""Coordinator for EGLO connect.Z meshes using HA's Bluetooth stack (bleak).

* Status: taken from the unencrypted state in each light's advertisement via HA's Bluetooth
  callbacks; no connection, no polling.
* Commands: a light only executes commands while we are connected to it, so each command connects
  to its target (HA picks the best local adapter or proxy), pairs, writes and keeps the connection
  for a few seconds for follow-up commands. A held connection blocks the light's Zigbee side,
  hence the short idle timeout (the AwoX app behaves the same).
* Notifications are never enabled: connect.Z lights have no real CCCD and hang when one is written.
"""
from __future__ import annotations

import asyncio
import logging
import os
from collections.abc import Callable

from bleak import BleakClient
from bleak.exc import BleakError
from bleak_retry_connector import BleakClientWithServiceCache, establish_connection

import homeassistant.util.dt as dt_util
from homeassistant.components import bluetooth
from homeassistant.core import CALLBACK_TYPE, HomeAssistant, callback
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator

from . import connectz as cz
from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)

# Keep the connection this long after the last command so follow-up commands (e.g. brightness
# right after color temperature) need no new connection; longer would block Zigbee needlessly
IDLE_DISCONNECT_S = 5
# Connection attempts per establish_connection call (it retries transient BlueZ errors itself)
CONNECT_ATTEMPTS = 3
# Attempts per command; a second attempt reconnects, which helps when a cached connection died
COMMAND_ATTEMPTS = 2

# Errors of the BLE transport that are worth a reconnect
TRANSPORT_ERRORS = (BleakError, TimeoutError, EOFError)


class PairingRejected(HomeAssistantError):
    """The light rejected our mesh credentials."""


class _Link:
    """An established and paired connection to one light."""

    def __init__(self, client: BleakClient, session_key: bytes):
        """Store client and session key."""
        self.client = client
        self.session_key = session_key
        self.idle_timer: asyncio.TimerHandle | None = None


class AwoxMeshZ(DataUpdateCoordinator):
    """Mesh of connect.Z lights; same interface towards the entities as AwoxMesh."""

    def __init__(self, hass: HomeAssistant, mesh_name: str, mesh_password: str):
        """Create the coordinator.

        Args:
            hass: HomeAssistant core.
            mesh_name: mesh name (cloud 'zigbee' credential).
            mesh_password: mesh password.
        """
        # Status is pushed by advertisements, nothing to poll
        super().__init__(hass, _LOGGER, name=DOMAIN, update_interval=None)
        self._mesh_name = mesh_name
        self._name_bytes = mesh_name.encode()
        self._password_bytes = mesh_password.encode()
        self._state = {
            'last_rssi_check': None,
            'last_connection': None,
            'connected_device': None,
        }
        # mesh_id -> {'mac', 'name', 'callback', 'status', 'lock', 'link'}
        self._devices: dict[int, dict] = {}
        self._unsubscribe: list[CALLBACK_TYPE] = []

    @property
    def mesh_name(self) -> str:
        """Mesh name."""
        return self._mesh_name

    @property
    def identifier(self) -> str:
        """Identifier of the mesh device in HA's device registry."""
        return 'awox_mesh.' + self._mesh_name

    @property
    def state(self) -> dict:
        """State shown by the mesh sensors."""
        return self._state

    def register_device(self, mesh_id: int, mac: str, name: str, callback_func: Callable[[dict], None]):
        """Register an entity; called from the entity constructor.

        Args:
            mesh_id: mesh address of the light.
            mac: Bluetooth address.
            name: name for logs.
            callback_func: receives status dicts (classic AwoxMeshLight format).
        """
        self._devices[mesh_id] = {
            'mac': mac.upper(),
            'name': name,
            'callback': callback_func,
            'status': None,
            'lock': asyncio.Lock(),
            'link': None,
        }
        _LOGGER.info('[%s] Registered [%s] %d', self.mesh_name, mac, mesh_id)

    @callback
    def async_start(self):
        """Subscribe to advertisements; call after the entities were added (callbacks fire immediately)."""
        for mesh_id, device in self._devices.items():
            self._unsubscribe.append(bluetooth.async_register_callback(
                self.hass, self._async_on_advertisement,
                bluetooth.BluetoothCallbackMatcher(address=device['mac'], manufacturer_id=cz.AWOX_COMPANY_ID,
                                                   connectable=False),
                bluetooth.BluetoothScanningMode.ACTIVE))
            self._unsubscribe.append(bluetooth.async_track_unavailable(
                self.hass, self._async_on_unavailable, device['mac'], connectable=False))

    async def _async_update_data(self):
        """Nothing to fetch, the state is pushed."""
        return self._state

    # --- status from advertisements ---

    def _device_by_mac(self, mac: str) -> tuple[int, dict] | tuple[None, None]:
        """Find a registered device by Bluetooth address."""
        mac = mac.upper()
        for mesh_id, device in self._devices.items():
            if device['mac'] == mac:
                return mesh_id, device
        return None, None

    @callback
    def _async_on_advertisement(self, service_info: bluetooth.BluetoothServiceInfoBleak,
                                change: bluetooth.BluetoothChange):
        """Forward the advertised state of a light to its entity when it changed."""
        status = cz.parse_advertisement(service_info.manufacturer_data.get(cz.AWOX_COMPANY_ID, b''))
        if status is None:
            return
        mesh_id, device = self._device_by_mac(service_info.address)
        if device is None or status['mesh_id'] != mesh_id:
            _LOGGER.debug('[%s] Advertisement of unexpected device %s: %s', self.mesh_name, service_info.address, status)
            return
        if status == device['status']:
            return
        _LOGGER.debug('[%s][%s] Advertised status %s (RSSI %s)', self.mesh_name, device['name'], status,
                      service_info.rssi)
        device['status'] = status
        device['callback'](status)

    @callback
    def _async_on_unavailable(self, service_info: bluetooth.BluetoothServiceInfoBleak):
        """Mark a light unavailable when HA stops receiving its advertisements."""
        _mesh_id, device = self._device_by_mac(service_info.address)
        if device is None:
            return
        _LOGGER.info('[%s][%s] No advertisements anymore, unavailable', self.mesh_name, device['name'])
        device['status'] = None
        device['callback']({'state': None})

    # --- commands ---

    async def async_on(self, mesh_id: int):
        """Turn a light on."""
        await self._async_command(mesh_id, cz.PKT_TYPE_ZCL, cz.body_on_off(mesh_id, True))

    async def async_off(self, mesh_id: int):
        """Turn a light off."""
        await self._async_command(mesh_id, cz.PKT_TYPE_ZCL, cz.body_on_off(mesh_id, False))

    async def async_set_color(self, mesh_id: int, r: int, g: int, b: int):
        """Set RGB color (0..255 each)."""
        await self._async_command(mesh_id, cz.PKT_TYPE_ZCL, cz.body_color(mesh_id, r, g, b))

    async def async_set_color_brightness(self, mesh_id: int, brightness: int):
        """Set brightness on the classic color scale (0x0a..0x64)."""
        await self._async_command(mesh_id, cz.PKT_TYPE_ZCL, cz.body_color_brightness(mesh_id, brightness))

    async def async_set_white_temperature(self, mesh_id: int, white_temperature: int):
        """Set color temperature on the classic scale (0 = cool .. 0x7f = warm)."""
        await self._async_command(mesh_id, cz.PKT_TYPE_ZCL, cz.body_white_temperature(mesh_id, white_temperature))

    async def async_set_white_brightness(self, mesh_id: int, brightness: int):
        """Set brightness on the classic white scale (1..0x7f)."""
        await self._async_command(mesh_id, cz.PKT_TYPE_ZCL, cz.body_white_brightness(mesh_id, brightness))

    async def _async_command(self, mesh_id: int, pkt_type: int, body: bytes):
        """Send one command to its target light, connecting if needed.

        Raises:
            HomeAssistantError when the light is unreachable or the command could not be written.
        """
        device = self._devices[mesh_id]
        async with device['lock']:
            last_error = None
            for attempt in range(COMMAND_ATTEMPTS):
                try:
                    link = device['link'] or await self._async_connect(mesh_id)
                    self._cancel_idle(link)
                    packet = cz.make_packet(link.session_key, pkt_type, body)
                    _LOGGER.debug('[%s][%s] Write frame type %#04x: %s', self.mesh_name, device['name'], pkt_type,
                                  cz.make_frame(body).hex())
                    await link.client.write_gatt_char(cz.COMMAND_CHAR_UUID, packet, response=True)
                    # loop.call_later runs the callback in the event loop (async_call_later would run a
                    # plain lambda in the executor, where tasks cannot be created)
                    link.idle_timer = self.hass.loop.call_later(IDLE_DISCONNECT_S, self._async_idle_disconnect,
                                                                mesh_id)
                    # Let the next advertisement through even if it equals the last one, it confirms the command
                    device['status'] = None
                    return
                except HomeAssistantError as e:
                    # Not reachable / pairing rejected: retrying won't help; HA only shows this in the UI, so log it
                    _LOGGER.warning('[%s][%s] Command failed - %s', self.mesh_name, device['name'], e)
                    raise
                except TRANSPORT_ERRORS as e:
                    last_error = e
                    _LOGGER.info('[%s][%s] Command attempt %d failed - [%s] %s', self.mesh_name, device['name'],
                                 attempt + 1, type(e).__name__, e)
                    await self._async_disconnect(mesh_id)
            _LOGGER.warning('[%s][%s] Command failed after %d attempts - [%s] %s', self.mesh_name, device['name'],
                            COMMAND_ATTEMPTS, type(last_error).__name__, last_error)
            raise HomeAssistantError(f'{device["name"]}: command failed ({type(last_error).__name__}: {last_error})')

    async def _async_connect(self, mesh_id: int) -> _Link:
        """Connect to and pair with a light; caller holds the device lock.

        Returns:
            The new link.
        Raises:
            HomeAssistantError when no adapter/proxy can reach the light, PairingRejected on wrong credentials.
        """
        device = self._devices[mesh_id]
        ble_device = bluetooth.async_ble_device_from_address(self.hass, device['mac'], connectable=True)
        if ble_device is None:
            raise HomeAssistantError(f'{device["name"]} is not in range of any connectable Bluetooth adapter or proxy')

        start = dt_util.utcnow()
        client = await establish_connection(
            BleakClientWithServiceCache, ble_device, device['name'],
            disconnected_callback=lambda c: self._async_on_disconnected(mesh_id, c),
            max_attempts=CONNECT_ATTEMPTS,
            # Pick up a better path (other adapter/proxy) between attempts
            ble_device_callback=lambda: bluetooth.async_ble_device_from_address(
                self.hass, device['mac'], connectable=True) or ble_device,
        )
        try:
            session_random = os.urandom(cz.PAIR_RANDOM_LEN)
            await client.write_gatt_char(cz.PAIR_CHAR_UUID,
                                         cz.make_pair_packet(self._name_bytes, self._password_bytes, session_random),
                                         response=True)
            reply = bytes(await client.read_gatt_char(cz.PAIR_CHAR_UUID))
        except BaseException:
            await client.disconnect()
            raise
        if not reply or reply[0] != cz.PAIR_OK:
            await client.disconnect()
            raise PairingRejected(f'{device["name"]} rejected the mesh credentials (reply {reply.hex()})')

        link = _Link(client, cz.make_session_key(self._name_bytes, self._password_bytes, session_random,
                                                 reply[1:1 + cz.PAIR_RANDOM_LEN]))
        device['link'] = link
        # HA's BLEDevice details name the adapter/proxy that is used
        details = ble_device.details if isinstance(ble_device.details, dict) else {}
        _LOGGER.info('[%s][%s] Connected via %s in %.1f s', self.mesh_name, device['name'],
                     details.get('source', 'bluetooth'), (dt_util.utcnow() - start).total_seconds())
        self._state['last_connection'] = dt_util.now()
        self._update_connected_state()
        return link

    @callback
    def _cancel_idle(self, link: _Link):
        """Stop a pending idle disconnect."""
        if link.idle_timer:
            link.idle_timer.cancel()
            link.idle_timer = None

    @callback
    def _async_idle_disconnect(self, mesh_id: int):
        """Timer callback: release the connection so the light's Zigbee side works again."""
        self.hass.async_create_background_task(self._async_disconnect_locked(mesh_id),
                                               f'{DOMAIN} idle disconnect {mesh_id}')

    async def _async_disconnect_locked(self, mesh_id: int):
        """Disconnect unless a command is running (it re-arms the idle timer)."""
        device = self._devices[mesh_id]
        if device['lock'].locked():
            return
        async with device['lock']:
            _LOGGER.debug('[%s][%s] Idle, disconnecting', self.mesh_name, device['name'])
            await self._async_disconnect(mesh_id)

    async def _async_disconnect(self, mesh_id: int):
        """Drop the link to a light; caller holds the device lock (or shuts down)."""
        device = self._devices[mesh_id]
        link, device['link'] = device['link'], None
        if link is None:
            return
        self._cancel_idle(link)
        try:
            await link.client.disconnect()
        except Exception as e:  # disconnect errors are irrelevant, the link is gone either way
            _LOGGER.debug('[%s][%s] Disconnect failed - [%s] %s', self.mesh_name, device['name'], type(e).__name__, e)
        self._update_connected_state()

    @callback
    def _async_on_disconnected(self, mesh_id: int, client: BleakClient):
        """bleak callback: the light dropped the connection."""
        device = self._devices.get(mesh_id)
        if device and device['link'] and device['link'].client is client:
            _LOGGER.debug('[%s][%s] Disconnected by device', self.mesh_name, device['name'])
            self._cancel_idle(device['link'])
            device['link'] = None
            self._update_connected_state()

    @callback
    def _update_connected_state(self):
        """Refresh the 'connected device' sensor."""
        names = [d['name'] for d in self._devices.values() if d['link'] is not None]
        self._state['connected_device'] = ', '.join(names) or None
        self.async_update_listeners()

    async def async_shutdown(self):
        """Unsubscribe and close all connections."""
        _LOGGER.info('[%s] Shutdown mesh', self.mesh_name)
        while self._unsubscribe:
            self._unsubscribe.pop()()
        for mesh_id in list(self._devices):
            await self._async_disconnect(mesh_id)
        await super().async_shutdown()
