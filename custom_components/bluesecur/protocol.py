"""
Hoermann BlueSecur BLE protocol - reverse-engineered from the official app
(eu.hoermann.ast.bluesecur v26.1.3). See the project notes for the full writeup.

Talks directly to a Hoermann BiSecur BLE receiver to trigger a door channel
(open/close/partial-open/light/ventilation), the same way the phone app does.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import logging
import struct

from bleak import BleakClient

_LOGGER = logging.getLogger(__name__)

SERVICE_UUID = "669a9001-0008-968f-e311-6050405558b3"
CHAR_TX = "669a900c-0008-968f-e311-6050405558b3"  # write: HA -> operator
CHAR_RX = "669a900a-0008-968f-e311-6050405558b3"  # notify: operator -> HA

IO_ID_SIGNED = 1
MTU_CHUNK = 20  # PAYLOAD_SIZE in the decompiled app

CONNECT_TIMEOUT = 15.0
CHALLENGE_TIMEOUT = 10.0


def _parse_notification(data: bytes) -> bytes | None:
    """Returns the 8-byte challenge from a BC_RX notification, or None.

    Notifications carry the same 3-byte outer envelope as writes:
    [IO_ID(1)][TotalLength u16 LE(2)][inner frame...], where inner frame is
    challenge(8) + type(u16 LE) + header_const(u16 LE) + payload...
    """
    if len(data) < 3:
        return None
    _io_id, total_len = struct.unpack_from("<BH", data, 0)
    inner = data[3:3 + max(total_len - 3, 0)] if total_len >= 3 else data[3:]
    if len(inner) < 8:
        return None
    return inner[0:8]


def _build_switch_relais_frame(command_id: int, root_id: int, user_id: int,
                                key_bytes: bytes, challenge: bytes) -> bytes:
    """
    Builds a SIGNED SwitchRelaisCmd frame for a USER_KEY.
    Frame: RootId(u16) + Command(u16) + Length(u16) + payload + HMAC-SHA256(32)
    USER_KEY payload: UserID(u8) + ValidFrom(u64, 0) + ValidUntil(u64, 0xFF...FF)
    """
    command = command_id | 0x100  # USER_KEY/ONE_TIME_KEY -> Command |= 256

    payload = struct.pack("<B", user_id)
    payload += struct.pack("<Q", 0)
    payload += struct.pack("<Q", 0xFFFFFFFFFFFFFFFF)

    length = 6 + len(payload) + 32
    header = struct.pack("<HHH", root_id, command, length)
    message = header + payload

    signature = hmac.new(key_bytes, message + challenge, hashlib.sha256).digest()
    return message + signature


def _wrap_envelope(io_id: int, inner_frame: bytes) -> bytes:
    total_len = len(inner_frame) + 3
    return struct.pack("<BH", io_id, total_len) + inner_frame


async def send_channel_command(address: str, root_id: int, user_id: int,
                                key_hex: str, command_id: int) -> None:
    """Connects to the BlueSecur BLE receiver, waits for the initial
    challenge, signs and sends a channel-trigger command, then disconnects.
    """
    key_bytes = bytes.fromhex(key_hex)
    challenge_box: dict[str, bytes] = {}
    got_challenge = asyncio.Event()

    def on_notify(_handle, data: bytearray) -> None:
        challenge = _parse_notification(bytes(data))
        if challenge is not None:
            challenge_box["challenge"] = challenge
        got_challenge.set()

    async with BleakClient(address, timeout=CONNECT_TIMEOUT) as client:
        await client.start_notify(CHAR_RX, on_notify)
        try:
            got_challenge.clear()
            await asyncio.wait_for(got_challenge.wait(), timeout=CHALLENGE_TIMEOUT)
            challenge = challenge_box.get("challenge")
            if challenge is None:
                raise RuntimeError("No usable challenge received from device")

            frame = _build_switch_relais_frame(command_id, root_id, user_id,
                                                key_bytes, challenge)
            envelope = _wrap_envelope(IO_ID_SIGNED, frame)
            _LOGGER.debug("BlueSecur sending envelope: %s", envelope.hex())

            for i in range(0, len(envelope), MTU_CHUNK):
                piece = envelope[i:i + MTU_CHUNK]
                await client.write_gatt_char(CHAR_TX, piece, response=False)
                await asyncio.sleep(0.02)

            # give the operator a moment to process/ack before disconnecting
            await asyncio.sleep(1.0)
        finally:
            try:
                await client.stop_notify(CHAR_RX)
            except Exception:  # noqa: BLE001 - best effort cleanup
                pass
