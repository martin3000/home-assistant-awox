"""BLE protocol of EGLO connect.Z (Zigbee + BLE) lights, transport independent.

connect.Z lights (cloud type ".ble.zigbee...", e.g. EGLO-ZM-RGB-TW, firmware 3.x) use the classic
Telink pairing on the pair characteristic, but a different packet format afterwards:

* Packet  = 1 type byte + 16 byte block encrypted with the session key (Telink AES-ECB byte order).
* Frame   = CRC-8 + length + body; the CRC covers length and body.
* Commands are Zigbee ZCL commands: body = dest mesh id (big endian), endpoint, cluster (LE), cmd, params.
* A light only executes commands addressed to itself while we are connected to it; mesh relaying
  of commands does not work, so every command needs a connection to its target.
* Status is broadcast unencrypted in the advertisement (manufacturer data, company 0x0160), so no
  connection is needed to follow the state. The status characteristic must NOT be subscribed:
  it has no real CCCD and writing one makes the light's BLE stack hang until power cycled.

Reverse engineered from an Android HCI snoop log of the AwoX app; advertisement layout as documented
by https://github.com/BastiAKA/awoxble2mqtt-api.
"""
from __future__ import annotations

import colorsys
import struct

from Crypto.Cipher import AES

PAIR_CHAR_UUID = '00010203-0405-0607-0809-0a0b0c0d1914'
COMMAND_CHAR_UUID = '00010203-0405-0607-0809-0a0b0c0d1912'

# Telink pairing: client hello opcode and the opcode of a successful device reply
PAIR_REQUEST = 0x0c
PAIR_OK = 0x0d
PAIR_RANDOM_LEN = 8
BLOCK_LEN = 16               # AES block = name/password/key length

# Packet type bytes (first byte of a packet written to the command characteristic)
PKT_TYPE_ZCL = 0x00          # ZCL command
PKT_TYPE_MESH = 0x02         # mesh management (status request, time, time zone)

# CRC-8 of the frame: reflected polynomial 0x6c, init 0, no final xor (determined from app traffic)
CRC8_POLY_REFLECTED = 0x6c

ZCL_ENDPOINT = 0x01
CLUSTER_ON_OFF = 0x0006
CLUSTER_LEVEL = 0x0008
CLUSTER_COLOR = 0x0300
CMD_OFF, CMD_ON = 0x00, 0x01
CMD_MOVE_TO_LEVEL_ON_OFF = 0x04
CMD_MOVE_TO_HUE_SAT = 0x06
CMD_MOVE_TO_COLOR_TEMP = 0x0a
# Transition time in 1/10 s, as used by the app
TRANSITION_DS = 2
# The app appends options mask/override (+1 reserved byte) to Move to Level
LEVEL_TRAILER = b'\x00\x00\x00'

ZCL_MAX = 0xfe               # max level / hue / saturation in ZCL
# Classic AwoX scales used by the HA light entity (see light.py)
WHITE_BRIGHTNESS_MIN, WHITE_BRIGHTNESS_MAX = 1, 0x7f
COLOR_BRIGHTNESS_MIN, COLOR_BRIGHTNESS_MAX = 0x0a, 0x64
WHITE_TEMP_MAX = 0x7f        # 0 = coolest (6500 K), 0x7f = warmest (2700 K)
MIRED_COOL, MIRED_WARM = 154, 370  # 6500 K and 2700 K
MIRED_INVALID = 0xffff       # reported while in color mode

# Advertisement: company id and offsets in the company-stripped manufacturer data
#   [0:2] 9620  [2:6] MAC (LE, lower 4 bytes)  [6:9] 03 00 0x  [9:11] mesh id LE
#   [11] mode (bit0 on, bit1 color)  [12] level  [13:15] mired LE  [15] hue  [16] sat
AWOX_COMPANY_ID = 0x0160
ADV_LAYOUT = 6               # 2 bytes, 03 00 = connect.Z layout
ADV_LAYOUT_CONNECT_Z = b'\x03\x00'
ADV_MESH_ID = 9
ADV_MODE = 11
ADV_LEVEL = 12
ADV_MIRED = 13
ADV_HUE = 15
ADV_SAT = 16
ADV_MIN_LEN = 17             # shorter "base" adverts carry no state
MODE_ON = 0x01
MODE_COLOR = 0x02


def crc8(data: bytes) -> int:
    """CRC-8 over a frame's length byte and body.

    Args:
        data: length byte + body.
    Returns:
        The CRC as int.
    """
    crc = 0
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ CRC8_POLY_REFLECTED if crc & 1 else crc >> 1
    return crc


def make_frame(body: bytes) -> bytes:
    """Build a frame: CRC-8, length, body."""
    lb = bytes([len(body)]) + body
    return bytes([crc8(lb)]) + lb


def telink_encrypt(key: bytes, value: bytes) -> bytes:
    """AES-ECB encrypt one block in Telink's byte-reversed convention.

    Args:
        key: 16 byte key.
        value: up to 16 bytes plaintext, zero padded.
    Returns:
        16 bytes ciphertext.
    """
    k = bytes(reversed(key))
    v = bytes(reversed(bytes(value).ljust(BLOCK_LEN, b'\0')))
    return bytes(reversed(AES.new(k, AES.MODE_ECB).encrypt(v)))


def _name_xor_password(mesh_name: bytes, mesh_password: bytes) -> bytes:
    """XOR of the zero-padded mesh name and password (Telink pairing secret)."""
    return bytes(a ^ b for a, b in zip(mesh_name.ljust(BLOCK_LEN, b'\0'), mesh_password.ljust(BLOCK_LEN, b'\0')))


def make_pair_packet(mesh_name: bytes, mesh_password: bytes, session_random: bytes) -> bytes:
    """Build the pairing hello written to the pair characteristic.

    Args:
        mesh_name / mesh_password: mesh credentials.
        session_random: 8 random bytes chosen by us.
    Returns:
        17 byte packet.
    """
    secret = telink_encrypt(session_random.ljust(BLOCK_LEN, b'\0'), _name_xor_password(mesh_name, mesh_password))
    return bytes([PAIR_REQUEST]) + session_random + secret[:PAIR_RANDOM_LEN]


def make_session_key(mesh_name: bytes, mesh_password: bytes, session_random: bytes, response_random: bytes) -> bytes:
    """Derive the session key from both pairing randoms.

    Returns:
        16 byte session key.
    """
    return telink_encrypt(_name_xor_password(mesh_name, mesh_password), session_random + response_random)


def make_packet(session_key: bytes, pkt_type: int, body: bytes) -> bytes:
    """Build an encrypted packet for the command characteristic.

    Args:
        session_key: key from make_session_key.
        pkt_type: PKT_TYPE_ZCL or PKT_TYPE_MESH.
        body: frame body (max 14 bytes so the frame fits into one AES block).
    Returns:
        17 byte packet.
    """
    frame = make_frame(body)
    if len(frame) > BLOCK_LEN:
        raise ValueError('frame too long for a single block')
    return bytes([pkt_type]) + telink_encrypt(session_key, frame)


def scale(value, src_min, src_max, dst_min, dst_max) -> int:
    """Linearly map value from one range to another and clamp it to the destination range."""
    value = min(max(value, src_min), src_max)
    result = round(dst_min + (value - src_min) * (dst_max - dst_min) / (src_max - src_min))
    return int(min(max(result, min(dst_min, dst_max)), max(dst_min, dst_max)))


def _zcl(dest: int, cluster: int, command: int, params: bytes = b'') -> bytes:
    """Body of a ZCL command to mesh id dest."""
    return struct.pack('>H', dest) + bytes([ZCL_ENDPOINT]) + struct.pack('<H', cluster) + bytes([command]) + params


def body_on_off(dest: int, on: bool) -> bytes:
    """ZCL body: switch on or off."""
    return _zcl(dest, CLUSTER_ON_OFF, CMD_ON if on else CMD_OFF)


def body_level(dest: int, level: int) -> bytes:
    """ZCL body: move to level (1..254) with on/off."""
    params = bytes([min(max(level, 1), ZCL_MAX)]) + struct.pack('<H', TRANSITION_DS) + LEVEL_TRAILER
    return _zcl(dest, CLUSTER_LEVEL, CMD_MOVE_TO_LEVEL_ON_OFF, params)


def body_white_brightness(dest: int, brightness: int) -> bytes:
    """ZCL body: brightness given on the classic white scale (1..0x7f)."""
    return body_level(dest, scale(brightness, WHITE_BRIGHTNESS_MIN, WHITE_BRIGHTNESS_MAX, 1, ZCL_MAX))


def body_color_brightness(dest: int, brightness: int) -> bytes:
    """ZCL body: brightness given on the classic color scale (0x0a..0x64)."""
    return body_level(dest, scale(brightness, COLOR_BRIGHTNESS_MIN, COLOR_BRIGHTNESS_MAX, 1, ZCL_MAX))


def body_white_temperature(dest: int, temp: int) -> bytes:
    """ZCL body: color temperature on the classic scale (0 = 6500 K .. 0x7f = 2700 K)."""
    mired = scale(temp, 0, WHITE_TEMP_MAX, MIRED_COOL, MIRED_WARM)
    return _zcl(dest, CLUSTER_COLOR, CMD_MOVE_TO_COLOR_TEMP, struct.pack('<HH', mired, TRANSITION_DS))


def body_color(dest: int, red: int, green: int, blue: int) -> bytes:
    """ZCL body: RGB color (0..255 each) as hue/saturation; brightness stays unchanged."""
    h, s, _v = colorsys.rgb_to_hsv(red / 255, green / 255, blue / 255)
    params = bytes([round(h * ZCL_MAX), round(s * ZCL_MAX)]) + struct.pack('<H', TRANSITION_DS)
    return _zcl(dest, CLUSTER_COLOR, CMD_MOVE_TO_HUE_SAT, params)


def parse_advertisement(data: bytes) -> dict | None:
    """Decode the state broadcast in a connect.Z advertisement.

    Args:
        data: manufacturer data of company AWOX_COMPANY_ID without the company id.
    Returns:
        Status dict in the format of the classic AwoxMeshLight ('mesh_id', 'state', 'color_mode',
        brightness/temperature/rgb on the classic scales), or None if the advert carries no state.
    """
    data = bytes(data)
    if len(data) < ADV_MIN_LEN or data[ADV_LAYOUT:ADV_LAYOUT + 2] != ADV_LAYOUT_CONNECT_Z:
        return None
    mode = data[ADV_MODE]
    level = data[ADV_LEVEL]
    mired = struct.unpack_from('<H', data, ADV_MIRED)[0]
    color_mode = bool(mode & MODE_COLOR)
    status = {
        'type': 'status',
        'mesh_id': struct.unpack_from('<H', data, ADV_MESH_ID)[0],
        'state': bool(mode & MODE_ON),
        'color_mode': color_mode,
        # One level for white and color; expose it on both classic scales
        'white_brightness': scale(level, 1, ZCL_MAX, WHITE_BRIGHTNESS_MIN, WHITE_BRIGHTNESS_MAX),
        'color_brightness': scale(level, 1, ZCL_MAX, COLOR_BRIGHTNESS_MIN, COLOR_BRIGHTNESS_MAX),
    }
    if mired != MIRED_INVALID:
        status['white_temperature'] = scale(mired, MIRED_COOL, MIRED_WARM, 0, WHITE_TEMP_MAX)
    if color_mode:
        r, g, b = colorsys.hsv_to_rgb(data[ADV_HUE] / ZCL_MAX, data[ADV_SAT] / ZCL_MAX, 1.0)
        status.update(red=round(r * 255), green=round(g * 255), blue=round(b * 255))
    return status
