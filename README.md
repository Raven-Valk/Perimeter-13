# Project 13: Secure Perimeter Intrusion Detection (v6.0)

> **Repository note.** Each `secrets.h` is stored here as `secrets.example.h` with demo values only. Copy it to `secrets.h` in the same folder before compiling, and use your own keys and PINs. `secrets.h` is in `.gitignore` and must never be committed.

| Folder | What | Runs on |
|---|---|---|
| `SensorModule/` | Modules A, B, C and D (one sketch: set `MODULE_ID`) | ESP32 DevKitC, 38-pin |
| `Gateway/` | The control box: card + PIN, keypad, LCD, event log, link to the server | ESP32 DevKit V1, 30-pin |
| `Server/` | The dashboard website and the gateway's link to it | The server laptop (Linux; Windows works too) |
| `tests/` | Protocol, mesh/relay, log-recovery and C++/Python interop tests | Any PC with g++ and Python |
| `Tools/` | `make_keys.py` (keys for the 10 radio links), `make_wokwi.py` (Wokwi sketches), `WiFi_Link_Test` | |
| `Diagrams/` | Wiring diagrams: gateway, modules A/B, modules C/D | |

The Wokwi versions are in `Wokwi/` (five projects). They are made from this folder by `python3 Tools/make_wokwi.py`.

## The site

```
          zone 2 (wall A–B)
     A ════════════════════ B          A, B: two PIRs, buzzer, tamper switch, 3 LEDs, LCD, keypad
     ║ ╲                  ╱ ║          C, D: one PIR, LCD, keypad (tamper and LEDs optional, no buzzer)
zone ║   ╲              ╱   ║ zone     G:    the gateway, in the middle
  1  ║        G             ║  3
     ║   ╱              ╲   ║          Each zone is one wall with a PIR at both ends, mounted on the
     ║ ╱                  ╲ ║          OUTSIDE face and looking along it (a curtain), at low
     D ──────────────────── C          sensitivity and short range. Wall C–D has no sensors.
          (no sensors)
```

| Zone | Wall | PIRs | Buzzer that sounds |
|---|---|---|---|
| 1 | A–D | A-Z1, D-Z1 | A |
| 2 | A–B | A-Z2, B-Z2 | A and B |
| 3 | B–C | B-Z3, C-Z3 | B |

**Rules.** A single trigger is a warning (P1). An intrusion (P2) is confirmed when, within 20 s, both PIRs of a wall fire, or both PIRs of one corner (A or B), or one PIR fires 3 times. Every armed module then goes to INTRUSION, and the buzzers on the walls in alarm sound. **While that intrusion is not acknowledged, any single PIR anywhere is an intrusion at once** (in its own zone): no 20-second window, no 3 hits. After acknowledging, the normal rules are back.

## How the parts talk

```
   A ─────── B         The radio is a full mesh: each of the 5 boards talks straight to
   │ ╲     ╱ │         the other 4 (10 links, each with its own key, ESP-NOW encrypted).
   │   ╲ ╱   │         If one link fails (a wall, distance, interference), its packets go
   │   ╱ G   │         through a board that still hears both ends: one hop, chosen by
   │ ╱     ╲ │         itself in about 3 s, back to direct when the link returns.
   D ─────── C
              G ──Wi-Fi── laptop hotspot or router ── Server laptop
                    MQTT inside TLS (port 8883)        broker + dashboard (HTTPS, port 8443)
```

- **Signed end to end:** every packet carries an HMAC-SHA256 signature made with the key of the two END boards, a boot ID and a sequence number. A relayed packet is passed on unchanged: the board in the middle can't read the key, alter the packet or make one up. Each radio hop is also encrypted with that hop's own link key.
- **Every board says who it hears.** Each packet carries the sender's list of boards it hears directly, so each end knows whether a link works both ways, and which board can relay. The dashboard draws the 10 links from these reports, with the way round when one is relayed.
- **To the server:** the gateway joins the Wi-Fi network and connects to the broker (Mosquitto) on the server laptop over TLS with the system's own certificate authority.
- **Who is allowed what is decided by the gateway:** the dashboard's sign-in is a challenge-response with the gateway. The password never reaches the gateway, and the server never stores it.

## Setup order

1. **Make the link keys:** `python3 Tools/make_keys.py` (writes both `secrets.h` files; demo keys are already in them).
2. **Wire and upload the five boards.** See `SensorModule/README.md` and `Gateway/README.md`. Set `MODULE_ID` to `'A'`, `'B'`, `'C'` or `'D'` for each module.
3. **Set the MAC addresses** in both `secrets.h` files and upload all five again. The radio links are encrypted from then on.
4. **Install the server** on the laptop: `Server/README.md`. Its setup prints a block for `Gateway/secrets.h` (key, broker password, CA certificate). Add the Wi-Fi name and password, then upload the gateway again.
5. **Open the dashboard** at `https://<laptop address>:8443`.

To try the dashboard first, with no hardware and no setup: `cd Server && pip install -r requirements.txt && python3 -m p13server --emulate`, then open http://127.0.0.1:8080 (user `admin`, password `admin123`).

**`link_protocol.h` and `mesh.h` must be identical in every board's folder.**

## Changes in 6.0

| | |
|---|---|
| **Mesh** | Four modules and the gateway in a full mesh: 10 direct links, each with its own key. When a link fails, a one-hop relay through another board, chosen automatically; end-to-end signatures, so relays can't fake anything. A relay test (dashboard or `cut` on a module's serial) cuts one link on purpose to show it. |
| **Site** | Rectangle with modules at the corners and three protected walls (zones 1–3), two outside-facing PIRs per wall. Modules C and D are the low-cost corners: one PIR, LCD, keypad; tamper switch and LEDs optional. |
| **Rules** | Wall-pair confirmation by zone; buzzers per zone (A for zone 1, A + B for zone 2, B for zone 3). New: while an intrusion is unacknowledged, any single PIR is an intrusion at once. |
| **Gateway** | Commands to all four or one module, results from each. Keypad menu targets 1–4 = A–D, 5 = all. LCD pages A/B and C/D + mesh. Log recovery for four modules. Passes on packets between modules whose own link failed. |
| **Dashboard** | Menu (☰) with two views: Overview (plan + control) and Log (events, units, link integrity). Plan of the site with PIR curtains outside the walls, the 10 radio links and relay routes, buzzers. Browser notifications for warnings and intrusions, and a loud siren on intrusion until acknowledged or silenced. |
| **Protocol** | v4: nodes C and D, packets are 206 bytes (`via` and `mesh` added), a 32-packet replay window so a relayed copy and a direct copy are each accepted once. New command `TEST_CUT`. |

## Version history

Every version of the project is a tagged commit in this repository. Full notes: [`CHANGELOG.md`](CHANGELOG.md).

| Tag | Date | Version |
|---|---|---|
| `v1` | 2026-10-05 | two-node firmware (main controller + sensor node over ESP-NOW) |
| `v2` | 2026-10-06 | teammate's single-board draft (draft2.ino) |
| `v3` | 2026-10-06 | one controller board with both PIRs + listen-only gateway to the PC |
| `v3.1` | 2026-10-07 | Wokwi simulation of the controller and gateway, bench tools |
| `v4` | 2026-10-08 | sensor module firmware for two identical modules (A, B) |
| `v4.1` | 2026-10-08 | clear a tamper or fault on the module with a MAINTENANCE PIN |
| `v4.2` | 2026-10-09 | gateway control box, PC login protocol, links off until MACs are set |
| `v4.3` | 2026-10-09 | built-in pull-ups instead of resistors, new pin map, wiring diagrams |
| `v5` | 2026-10-10 | gateway on Wi-Fi (MQTT over TLS) + server and dashboard website |
| `v6` | 2026-10-10 | four modules in a full mesh with relay, three walled zones, new dashboard |
