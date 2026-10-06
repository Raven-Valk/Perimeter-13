# Pinnacle 1 · Project 13 — Firmware v3 (controller + gateway)

> **Repository note.** Each `secrets.h` is stored here as `secrets.example.h` with demo values only. Copy it to `secrets.h` in the same folder before compiling, and use your own keys and PINs. `secrets.h` is in `.gitignore` and must never be committed.

```
Pinnacle13_Firmware_v4/
├── Board1_Controller/   ← 38-pin ESP32: both PIRs, tamper, RFID, keypad, LCD, LEDs, buzzer, all logic
│   ├── Board1_Controller.ino
│   ├── link_protocol.h  (identical in both folders)
│   └── secrets.h        (shared key, PIN hashes, card UIDs)
├── Gateway/             ← second ESP32, plugged into the PC by USB
│   ├── Gateway.ino
│   ├── link_protocol.h
│   └── secrets.h        (shared key only)
└── pc_logger.py         ← optional: saves the gateway output with real date/time
```

Both sketches compile on **Arduino-ESP32 core 3.3.0**, board **"ESP32 Dev Module"**, with no warnings.

```
 PIR-L ─┐                                              USB
 PIR-R ─┤                     ESP-NOW (signed)         serial
 Lid   ─┼─► BOARD 1 ─────────────────────────► GATEWAY ─────► PC (Serial Monitor
 RFID  ─┤   decides,          ◄──── ACK ─────                    or pc_logger.py)
 Keypad─┘   alarms, logs
```

Board 1 works fully on its own. The gateway only carries copies of the log and status to the PC. If the gateway or PC disappears, Board 1 logs "PC link DOWN", shows it on the LCD and keeps protecting. The PC can never send commands to the alarm.

## What came from where

| From the teammate's draft | From v1 | New in v3 |
|---|---|---|
| Code split into parts (ZoneSensor, TamperSensor, Display, RfidReader, GatewayLink) | Card + PIN for every login, 2 roles | Both PIRs on one board, plus a slot for the IR sensor |
| Full state saved on every change; INTRUSION and TAMPER survive a power cut | P1 warning vs P2 confirmed (both sides, or 3 hits one side) | Gateway → PC link with signed status + log lines |
| Time-based tamper debounce; open lid and cut wire both alarm | PIR warm-up + stuck / unplugged detection | Log lines numbered so lost radio packets show as `GAP` |
| Can't arm with the lid open | Lockout 60/120/240 s that survives reboot | PC logger adds real date/time |
| RC522 RST tied to 3.3 V (saves a pin) | Maintenance mode with 5-min timeout | Gateway only listens: PC cannot control the alarm |
| Distinct buzzer patterns per alarm; unknown state fails closed | Recovery re-check before re-arming | |
| PIN masked; PINs never printed | PINs stored as salted hashes, event log in flash | |

**Draft problems fixed:**
- Keypad moved off the input-only pins.
- **D** + card + PIN disarms.
- Clearing an alarm runs RECOVERY first, so a PIR still reading "motion" can't re-trigger it.
- PIR warm-up after reboot.
- PIR pins have pull-ups.
- An RFID glitch no longer arms the system.
- Tamper is watched in every state.
- The watchdog timeout is actually applied.

## 1. Install

1. Arduino IDE → Boards Manager → **esp32 by Espressif Systems** (3.x). Board: **ESP32 Dev Module**, partition scheme **Default**.
2. Library Manager → **MFRC522** (GithubCommunity), **Keypad** (Mark Stanley, Alexander Brevig), **LiquidCrystal I2C** (Frank de Brabander). Ignore the "avr" warning for the LCD library.

## 2. First-time setup

1. **Shared key.** Make your own and paste it into **both** `secrets.h` files:
   `python3 -c "import os;print(', '.join('0x%02X'%b for b in os.urandom(32)))"`
2. **Cards.** Set `#define ENROLL_MODE 1` in `Board1_Controller.ino`, upload, open Serial Monitor (115200), and scan each card. Copy the printed UIDs into `USERS[]`, choose which card is OPERATOR and which is MAINTENANCE, then set `ENROLL_MODE` back to 0 and upload again.
3. **PINs** (4–6 digits): `python3 -c "import hashlib;print(hashlib.sha256(b'pinnacle13-demo-salt'+b'1234').hexdigest())"`. Paste the hash into `USERS[]`. Demo values are 1234 (operator) and 9876 (maintenance); change them.
4. Upload `Gateway` to the second ESP32. No MAC addresses to copy: Board 1 broadcasts signed packets and the gateway replies to whichever board signed correctly.

## 3. Wiring — Board 1 (38-pin ESP32 DevKitC, WROOM-32)

| Part | Part pin → ESP32 | Note |
|---|---|---|
| LCD1602 I2C | SDA → 21, SCL → 22, VCC → 5 V rail, GND | blank LCD? try `LCD_ADDR 0x3F` |
| RC522 | SDA/SS → 5, SCK → 18, MOSI → 23, MISO → 19, **RST → 3.3 V**, IRQ → nothing, **3.3V → ESP32 3V3**, GND | never 5 V |
| Keypad pins 1–4 (rows) | 13, 14, 27, 26 | male-to-male jumpers |
| Keypad pins 5–8 (cols) | 25, 33, 32, 4 | wrong keys? swap order in `KP_ROWS`/`KP_COLS` |
| PIR-L (Zone 1) | OUT → 35, VCC → 5 V rail, GND | **10 kΩ from 35 to 3V3** |
| PIR-R (Zone 2) | OUT → 34, VCC → 5 V rail, GND | **10 kΩ from 34 to 3V3** |
| MAGREED tamper reed | wire A → 39, wire B → GND | **10 kΩ from 39 to 3V3**; magnet on the lid |
| Buzzer module | I/O → 16, VCC → 5 V rail, GND | beeps when quiet? `BUZZER_ACTIVE_LOW = true` |
| Green / Red / Yellow LED | 2 / 15 / 12, each through 220 Ω, short leg to GND | |
| FC-51 IR (later, Zone 3) | OUT → 36, VCC → 3V3, GND | set `enabled` true in `zones[]` |

- **Power:** ESP32 from laptop USB. MB102 5 V rail for the LCD, both PIRs and the buzzer. RC522 and the three pull-ups take 3.3 V from the ESP32's 3V3 pin. Join all GNDs. Never join the MB102 5 V to the ESP32's 5V/VIN pin while USB is plugged in.
- **Check the metal shield on your 38-pin board.** It should say **WROOM-32**. If it says **WROVER**, GPIO 16 is used internally and the buzzer must move. The easiest fix is to put the buzzer on GPIO 2 (`PIN_BUZZER = 2`) and drop the green LED; the LCD already shows ARMED/DISARMED.
- **PIRs:** jumper on **L**, time and sensitivity pots fully anticlockwise, and a small card hood so they only see the model. Both need about 60 s to settle after power-on; the code waits.

**Gateway:** no wiring. Plug it into the PC by USB. Its on-board LED (GPIO 2) is on while Board 1 is online.

## 4. Seeing events on the PC

- **Simple:** open Serial Monitor on the gateway's COM port at 115200.
- **With real timestamps (recommended for evidence):** close Serial Monitor, then run
  `pip install pyserial` and `python pc_logger.py COM5` (your port). Each line gets the PC date/time and is saved to `events_YYYY-MM-DD.csv`. P2/P3, `LOST`, `GAP` and `SEC` lines are marked `!!`.

```
2026-10-06T15:02:11,LINK,Controller online
2026-10-06T15:02:12,STATUS,MONITORING,P0,Z1-LEFT:OK,Z2-RIGHT:OK,LID:SHUT,RFID:OK,LCD:OK
2026-10-06T15:02:40,LOG,57,4,95112,P1,MONITORING,ALERT,Motion warning 1/3,Z2-RIGHT,OPERATOR,-,-
```
*(example lines showing the format)*

## 5. Using the system

| State | LEDs | Buzzer | LCD |
|---|---|---|---|
| BOOT (60 s warm-up) | yellow blinking | – | "Warming up 45s" |
| WAIT_AUTH (disarmed) | green slow blink | – | "DISARMED" |
| MONITORING P0 / P1 | green / yellow | P1: one chirp | "ARMED P0" / "WARNING P1 18s" |
| INTRUSION P2 | red | double beep | "!! INTRUSION !!" |
| TAMPER / FAULT P3 | red fast blink | long pulses | "!! TAMPER P3 !!" + reason |
| MAINTENANCE | yellow blinking | – | "MAINT 287s" |

- **Log in:** scan card → type PIN (`****`) → **#**. **\*** clears. The PIN must follow the card within 30 s.
- **Arm:** card + PIN while disarmed. This is refused while the lid is open or a sensor is faulty.
- **Disarm:** **D**, then card + PIN.
- **Silence an intrusion:** card + PIN. The system re-checks itself, then goes back to ARMED.
- **Clear a tamper / fault:** maintenance card + PIN only.
- **Maintenance:** maintenance card + PIN while armed. Keys: **1** test outputs, **2** zone status, **3** dump log to USB, **C** exit. It exits by itself after 5 minutes.
- **Power cut:** the system comes back in the same state. ARMED re-arms after warm-up; INTRUSION and TAMPER come back immediately.

## 6. Test script (spec §19)

| Test | Do | Expect |
|---|---|---|
| T01 | Arm, stay still | green, "ARMED P0"; PC shows `STATUS,MONITORING,P0` |
| T02 | Wrong PIN or unknown card | "Access denied", `Login failed … FAIL` |
| T03 | 3 wrong PINs, then power-cycle Board 1 | locked, and still locked after reboot |
| T04 | One short wave at PIR-R | yellow + chirp, `Motion warning 1/3` |
| T05a | PIR-R then PIR-L within 20 s | P2, `Corroborated Z2-RIGHT+Z1-LEFT` |
| T05b | Keep moving at one PIR ~15 s | P2, `Sustained motion … x3` |
| T06 | Pull PIR-L's OUT wire | after ~30 s: FAULT "Z1-LEFT STUCK" (not intrusion) |
| T07 | Move the magnet off the lid reed | P3 TAMPER in any state; cannot arm while open |
| T08 | **A** while armed; 7-digit PIN; **9** in maintenance | `INPUT … REJECTED` |
| T08+ | Flash the gateway with a different `SHARED_KEY` | Board 1: `Bad signature`; gateway: `SEC,REJECTED` |
| T09 | Unplug the gateway | Board 1 logs "PC link DOWN", **alarm keeps working**; plug back → "PC link UP" |
| T09+ | Unplug Board 1 | gateway prints `LINK,CONTROLLER LOST` within 3 s |
| T10 | Pull Board 1's USB while armed / during an alarm | boot log shows the reason; comes back armed / still alarming |
| T11 | Maintenance card + PIN while armed; then operator card | maintenance mode / "Already armed"; auto-exit 5 min |
| T12 | Fix a fault, clear with maintenance card + PIN | "Revalidating…" → ARMED |

## 7. Settings (top of `Board1_Controller.ino`)

| Setting | Value |
|---|---|
| `CORROBORATION_MS` | 20 s |
| `REPEAT_TRIGGERS` | 3 |
| `SENSOR_MAX_ACTIVE_MS` | 30 s |
| `GATEWAY_TIMEOUT_MS` | 3 s |
| `MAX_ATTEMPTS` · `BASE_LOCKOUT_S` | 3 · 60 s |
| `PIN_TIMEOUT_MS` | 30 s |
| `MAINT_TIMEOUT_MS` | 5 min |
| `LCD_ADDR` · `BUZZER_ACTIVE_LOW` | 0x27 · false |

## 8. Known limits (residual-risk table)

- Two PIRs cover roughly 220–240°. The back of the model is not covered.
- PIRs can't tell people from pets or heat sources. Corroboration reduces false alarms but doesn't remove them.
- Radio packets are signed and replay-protected but **not encrypted**: a listener can see that events happen, but can't fake them.
- After Board 1 restarts, the first gateway packet is trusted to set the counter.
- Log lines lost on the radio are detected (`GAP`) but not re-sent. The full log is always kept on Board 1 (maintenance key **3**).
- Board timestamps are boot number + milliseconds. Real date/time comes from the PC logger.
- PINs are 4–6 digits. Someone who reads the flash chip could brute-force the hashes, which is why the lockout and the tamper switch matter.
- RFID card UIDs can be cloned, so a PIN is always required as well.
