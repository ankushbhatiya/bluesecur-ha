#!/usr/bin/env python3
"""
BlueSecur BLE protocol client - reverse-engineered from the official app
(eu.hoermann.ast.bluesecur v26.1.3, decompiled 2026-08-26, see
~/ha/todo_ideas/hormann_bluesecur_ble.md for the full protocol writeup).

Talks directly to a Hoermann BiSecur BLE receiver to trigger a door channel
(open/close/partial-open/light/ventilation), the same way the phone app does.

Usage:
    python3 bluesecur_client.py scan                  # find the device, print its address
    python3 bluesecur_client.py channel "Open partially"
    python3 bluesecur_client.py channel Close
    python3 bluesecur_client.py status                # just connect and print notifications

Needs a credentials.json (see extract_credentials.py) with the raw 32-byte key,
root_id, and channel action codes for this specific door.

NOTE: this has NOT yet been tested against real hardware - it must run on a
machine with a Bluetooth radio in physical range of the garage door operator.
This machine (dev Mac) is not in range of the user's door; testing needs to
happen from HA host or another nearby device.
"""
import asyncio
import hashlib
import hmac
import json
import struct
import sys
import time
from pathlib import Path

from bleak import BleakClient, BleakScanner

CREDENTIALS_PATH = Path(__file__).parent.parent / "secrets" / "credentials.json"

SERVICE_UUID = "669a9001-0008-968f-e311-6050405558b3"
CHAR_TX = "669a900c-0008-968f-e311-6050405558b3"  # write: phone -> operator
CHAR_RX = "669a900a-0008-968f-e311-6050405558b3"  # notify: operator -> phone

IO_ID_SIGNED = 1
IO_ID_ENCRYPTED = 2
IO_ID_CONFIGURATION = 3

MTU_CHUNK = 20  # PAYLOAD_SIZE in the decompiled app


def load_credentials():
    with open(CREDENTIALS_PATH) as f:
        return json.load(f)


def utc_ts_now() -> int:
    return int(time.time())


def build_switch_relais_frame(command_id: int, root_id: int, key_bytes: bytes,
                               challenge: bytes) -> bytes:
    """
    Builds a SIGNED SwitchRelaisCmd frame for a USER_KEY (matches this
    credential's key_type=1). For a ROOT_KEY the payload differs (see
    SwitchRelaisCmd.cs) - not implemented here since we only have a user key.

    Frame: RootId(u16) + Command(u16) + Length(u16) + payload + HMAC-SHA256(32)
    USER_KEY payload: UserID(u8) + ValidFrom(u64, 0 if none) + ValidUntil(u64,
    0xFFFFFFFFFFFFFFFF if none)
    """
    creds = load_credentials()
    user_id = creds["user_id"]

    command = command_id
    # SwitchRelaisCmd.Key setter: ONE_TIME_KEY or USER_KEY -> Command |= 256
    command |= 0x100

    payload = struct.pack("<B", user_id)
    payload += struct.pack("<Q", 0)  # ValidFrom = none
    payload += struct.pack("<Q", 0xFFFFFFFFFFFFFFFF)  # ValidUntil = none

    length = 6 + len(payload) + 32  # header(6) + payload + signature(32)
    header = struct.pack("<HHH", root_id, command, length)
    message = header + payload

    signature = hmac.new(key_bytes, message + challenge, hashlib.sha256).digest()
    return message + signature


def wrap_envelope(io_id: int, inner_frame: bytes) -> bytes:
    """[IO_ID(1)][TotalLength(u16 LE, includes these 3 bytes)][inner_frame]"""
    total_len = len(inner_frame) + 3
    return struct.pack("<BH", io_id, total_len) + inner_frame


def chunk(data: bytes, size: int = MTU_CHUNK):
    for i in range(0, len(data), size):
        yield data[i:i + size]


class BlueSecurSession:
    def __init__(self, address: str):
        self.address = address
        self.client: BleakClient | None = None
        self.challenge: bytes | None = None
        self._notify_event = asyncio.Event()

    async def __aenter__(self):
        self.client = BleakClient(self.address)
        await self.client.connect()
        await self.client.start_notify(CHAR_RX, self._on_notify)
        return self

    async def __aexit__(self, *exc):
        if self.client and self.client.is_connected:
            await self.client.stop_notify(CHAR_RX)
            await self.client.disconnect()

    def _on_notify(self, _handle, data: bytearray):
        data = bytes(data)
        print(f"[notify raw] {data.hex()}")
        # Notifications carry the SAME 3-byte outer envelope as writes:
        # [IO_ID(1)][TotalLength u16 LE(2)][inner SignedReader frame...]
        # inner frame: challenge(8) + type(u16 LE) + header_const(u16 LE) + payload...
        if len(data) < 3:
            return
        io_id, total_len = struct.unpack_from("<BH", data, 0)
        inner = data[3:3 + max(total_len - 3, 0)] if total_len >= 3 else data[3:]
        if len(inner) >= 8:
            self.challenge = inner[0:8]
            info = f"io_id={io_id} total_len={total_len} challenge={self.challenge.hex()}"
            if len(inner) >= 12:
                ntype, hconst = struct.unpack_from("<HH", inner, 8)
                payload = inner[12:]
                info += f" type={ntype} payload={payload.hex()}"
            print(f"[notify parsed] {info}")
        self._notify_event.set()

    async def wait_for_challenge(self, timeout=10.0):
        self._notify_event.clear()
        await asyncio.wait_for(self._notify_event.wait(), timeout=timeout)
        return self.challenge

    async def send_envelope(self, envelope: bytes):
        for piece in chunk(envelope):
            await self.client.write_gatt_char(CHAR_TX, piece, response=False)
            await asyncio.sleep(0.02)

    async def send_channel_command(self, command_id: int):
        creds = load_credentials()
        root_id = creds["root_id"]
        key_bytes = bytes.fromhex(creds["key_data_hex"])

        if self.challenge is None:
            print("No challenge received yet - waiting for initial notification...")
            await self.wait_for_challenge()

        frame = build_switch_relais_frame(command_id, root_id, key_bytes, self.challenge)
        envelope = wrap_envelope(IO_ID_SIGNED, frame)
        print(f"[send] envelope={envelope.hex()}")
        await self.send_envelope(envelope)


async def scan():
    print(f"Scanning for BLE devices advertising service {SERVICE_UUID} ...")
    devices = await BleakScanner.discover(timeout=8.0, service_uuids=[SERVICE_UUID])
    if not devices:
        print("No matching devices found. Trying unfiltered scan (prints all devices)...")
        devices = await BleakScanner.discover(timeout=8.0)
        for d in devices:
            print(d.address, d.name, d.metadata.get("uuids"))
        return
    for d in devices:
        print(f"FOUND: {d.address}  name={d.name}")


async def run_channel(address: str, channel_name: str):
    creds = load_credentials()
    if channel_name not in creds["channels"]:
        print(f"Unknown channel {channel_name!r}. Options: {list(creds['channels'].keys())}")
        return
    command_id = creds["channels"][channel_name]["commandId"]
    print(f"Channel {channel_name!r} -> commandId 0x{command_id:04x}")

    async with BlueSecurSession(address) as session:
        await session.wait_for_challenge()
        await session.send_channel_command(command_id)
        # give the device a moment to respond/act, then read any trailing notification
        await asyncio.sleep(3.0)


async def run_status(address: str):
    async with BlueSecurSession(address) as session:
        print("Connected, listening for notifications for 15s (e.g. GATE_STATE)...")
        await asyncio.sleep(15.0)


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return
    cmd = sys.argv[1]
    if cmd == "scan":
        asyncio.run(scan())
    elif cmd == "channel":
        if len(sys.argv) < 3:
            print("Usage: channel <name> [address]")
            return
        channel_name = sys.argv[2]
        address = sys.argv[3] if len(sys.argv) > 3 else None
        if not address:
            print("No address given - run 'scan' first and pass the address explicitly.")
            return
        asyncio.run(run_channel(address, channel_name))
    elif cmd == "status":
        if len(sys.argv) < 3:
            print("Usage: status <address>")
            return
        asyncio.run(run_status(sys.argv[2]))
    else:
        print(__doc__)


if __name__ == "__main__":
    main()
