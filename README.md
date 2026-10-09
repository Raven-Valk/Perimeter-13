# Project 13: Secure Perimeter Intrusion Detection (v5)

> **Repository note.** Each `secrets.h` is stored here as `secrets.example.h` with demo values only. Copy it to `secrets.h` in the same folder before compiling, and use your own keys and PINs. `secrets.h` is in `.gitignore` and must never be committed.

| Folder | What | Runs on |
|---|---|---|
| `SensorModule/` | Module A and Module B (one sketch: `MODULE_ID 'A'` or `'B'`) | ESP32 DevKitC, 38-pin |
| `Gateway/` | The control box: card + PIN, keypad, LCD, event log, link to the server | ESP32 DevKit V1, 30-pin |
| `Server/` | The dashboard website and the gateway's link to it | The server laptop (Linux; Windows works too) |
| `tests/` | Protocol, log-recovery and C++/Python interop tests | Any PC with g++ and Python |
| `Tools/` | `WiFi_Link_Test` (Wi-Fi range check) and `make_wokwi.py` (builds the Wokwi sketches) | |
| `Diagrams/` | Wiring diagrams for both boards | |

The Wokwi versions are in `Wokwi/`. They are made from this folder by `python3 Tools/make_wokwi.py`.

## How the parts talk

```
 Module A ──ESP-NOW── Module B          radio, encrypted per link, every packet signed
     \                  /
      ESP-NOW      ESP-NOW
           \        /
            Gateway ──Wi-Fi── laptop hotspot or router ── Server laptop
                         MQTT inside TLS (port 8883)       broker + dashboard (HTTPS, port 8443)
```

- **Inside the box layer:** the modules and the gateway use ESP-NOW. The radio runs on the gateway's Wi-Fi channel; the modules find that channel by themselves.
- **To the server:** the gateway joins the Wi-Fi network and connects to the broker (Mosquitto) on the server laptop. TLS with the system's own certificate authority: the gateway refuses any other server. The broker refuses anyone without the gateway's password, and lets each side use only its own topics.
- **The same signed packets everywhere:** every packet carries an HMAC-SHA256 signature, a boot ID and a sequence number, on the radio and inside TLS alike. A copied, replayed or altered packet is refused at the other end.
- **Who is allowed what is decided by the gateway:** the dashboard's sign-in is a challenge-response with the gateway. The password never reaches the gateway, and the server never stores it.

## Setup order

1. **Wire and upload the boards.** See `SensorModule/README.md` and `Gateway/README.md`.
2. **Set the MAC addresses** in every `secrets.h` and upload again. The radio links are encrypted from then on.
3. **Install the server** on the laptop: `Server/README.md`. Its setup prints a block for `Gateway/secrets.h` (key, broker password, CA certificate). Add the Wi-Fi name and password, then upload the gateway again.
4. **Open the dashboard** at `https://<laptop address>:8443`.

To try the dashboard first, with no hardware and no setup: `cd Server && pip install -r requirements.txt && python3 -m p13server --emulate`, then open http://127.0.0.1:8080 (user `admin`, password `admin123`).

**`link_protocol.h` must be identical in every board's folder.** The keys in each `secrets.h` must match across boards and the server.

## Changes in v5

| | |
|---|---|
| **Gateway** | The PC dongle is gone. The gateway reaches the server over Wi-Fi: MQTT over TLS, with retries that keep the modules' radio channel steady. Its status now includes Wi-Fi signal, channel and firmware version. The LCD shows the channel and IP address when it joins. |
| **Modules** | They find the gateway's radio channel by themselves when it goes quiet (about 2 s) and remember it. Their status now includes the channel. |
| **Server** | New: the dashboard, the broker setup, an emulated gateway for testing, and tests. |
| **Protocol** | Same packet format (v3). The `PC dongle` node is now the server (`NODE_SERVER`, same number). |
