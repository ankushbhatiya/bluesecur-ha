# bluesecur-ha

Direct Bluetooth LE control of a Hörmann garage door / gate operator, reverse-engineered
from the official **Hörmann BlueSecur** Android app, packaged as a Home Assistant
custom integration (plus a standalone Python client).

Unlike Hörmann's BiSecur Gateway integrations (which only expose full open/close),
talking to the operator's built-in Bluetooth receiver directly gives you **every
channel the app has** — including **partial open** and **ventilation position** — with
no extra hardware, no gateway box, and no cloud dependency.

> **Unofficial project.** Not affiliated with, endorsed by, or supported by Hörmann.
> Built by observing the official app's own Bluetooth traffic/behavior for personal use
> with hardware I own. Use at your own risk — see [Disclaimer](#disclaimer).

## What this gives you

- A Home Assistant `button` entity per configured channel on your door (Open, Close,
  Open Partially, Light, Ventilation Position, Impulse — whatever channels your
  operator/app have configured)
- A standalone `bluesecur_client.py` script if you just want to trigger the door from a
  shell/cron/other automation system, no Home Assistant required

## Requirements

- A Hörmann operator with a **Bluetooth (BiSecur BLE) receiver**, already set up and
  working with the official BlueSecur app (Series 4 SupraMatic/ProMatic — this was
  built and tested against a SupraMatic 4)
- A machine with a Bluetooth radio physically in range of the operator (a Home
  Assistant host, a Raspberry Pi, etc.)
- Python 3.10+ and [`bleak`](https://github.com/hbldh/bleak) (Home Assistant installs
  this automatically via the integration's manifest)
- Your own **key material** for the door — see below, this is the part you can't skip

## Getting your own key

This integration needs a real signing key for *your* door — there's no shared/default
key, and there can't be (see [How it works](#how-it-works)). You have to extract one
from a BlueSecur app instance that's already been granted access to your door:

1. In the BlueSecur app (on the phone that's already paired with your door), buy an
   extra key slot if needed, create a new named key (e.g. "Home Assistant"), and use
   the app's built-in **share/invite key** feature to send it to an email address you
   control.
2. Redeem that invite on an Android device or emulator you can get **root** access to.
   Note: the app bundles Google Play Integrity checks that block most emulators
   (`google_apis` images without Play Store fail; images with Play Store are usually
   locked builds that block root) — a real rooted device is the more reliable option,
   or a rooted `google_apis` emulator combined with sideloading the invite via its deep
   link (`hoermannbleapp://sharedkey/...`) worked in testing despite the Play Integrity
   warning screen on cold launch.
3. With root, read the app's own local backup export:
   `/data/data/eu.hoermann.ast.bluesecur/files/export/backup.json` — this is a
   **plaintext JSON file** the app keeps for its own backup/restore feature, containing
   the appliance's channel list and the raw base64 key material (`KeyData`) alongside
   `RootId`/`UserId`. No crypto to break, no LiteDB/SQLite parsing needed.
4. Copy `credentials.example.json` to `credentials.json`, fill in the fields from that
   export (`root_id`, `user_id`, `key_type`, and `key_data_hex` — hex-decode the
   base64 `KeyData`), and list your actual channels/action codes.

**Treat `credentials.json` like a password** — it can operate your real door. It's
gitignored; never commit your real one.

## Installing the Home Assistant integration

1. Copy `custom_components/bluesecur/` into your HA config's `custom_components/`
   directory.
2. Put your filled-in `credentials.json` somewhere HA can read (e.g.
   `/config/bluesecur_credentials.json`), `chmod 600` it.
3. Add to `configuration.yaml`:
   ```yaml
   button:
     - platform: bluesecur
       address: "AA:BB:CC:DD:EE:FF"   # your door's BLE MAC - see "Finding your device" below
       credentials_file: /config/bluesecur_credentials.json
   ```
4. Restart Home Assistant. One `button.*` entity is created per channel listed in your
   `credentials.json`.

### Finding your device

```
python3 tools/bluesecur_client.py scan
```
Scans for BLE devices advertising the BiSecur service UUID and prints their address.

### Using the standalone script

```
python3 tools/bluesecur_client.py channel "Open partially" AA:BB:CC:DD:EE:FF
```

## How it works

The app talks to a custom BLE GATT service (`669a9001-0008-968f-e311-6050405558b3`)
with a write characteristic (`...900c...`) and a notify characteristic (`...900a...`).
Writes and notifications both share a small outer envelope
(`[IO_ID][TotalLength][inner frame]`, chunked to 20-byte GATT packets), and — somewhat
surprisingly — commands aren't encrypted at all: each channel-trigger command is a short
binary frame (`RootId + Command + Length + payload`) authenticated with
**HMAC-SHA256**, using a raw per-user 32-byte key and an 8-byte challenge the operator
sends in its notifications (classic challenge-response, prevents replay). Pairing a new
key with the door is a one-time RSA handshake (not implemented here — this project
piggybacks on a key issued via the app's own official multi-user "share key" feature
instead of re-implementing that handshake).

Channels (Open, Close, Open Partially, Light, Ventilation Position, Impulse) are just
different numeric IDs sent through the exact same signed-command mechanism — there's no
special "partial open" protocol, it's whichever relay output your operator has
configured for that function (same as it would be for a physical remote button).

## Known limitations

- Long BLE notifications (e.g. the full `GATE_STATE` status payload) can span multiple
  20-byte packets; this client reads enough of the first packet to get the
  challenge/command-ack but doesn't reassemble multi-packet payloads yet, so there's no
  door-position sensor here (yet) — only command triggering.
- Only tested against a SupraMatic 4. Other Series 4 operators/gate types likely work
  the same way but haven't been verified.

## Disclaimer

This project is the result of independently observing the official BlueSecur app's own
network/Bluetooth behavior on hardware and an account the author owns, for personal
home-automation use. It does not include, redistribute, or depend on any of Hörmann's
proprietary application code or assets. No warranty of any kind — operating a garage
door/gate is a safety-relevant action; test carefully, keep the official app as a
fallback, and don't rely on this for anything where a missed/misfired command could
cause harm.

## License

MIT — see [LICENSE](LICENSE). Applies to this project's own code only.
