# Pinnacle 1 · Project 13 — Firmware (two-node version)

> **Repository note.** Each `secrets.h` is stored here as `secrets.example.h` with demo values only. Copy it to `secrets.h` in the same folder before compiling, and use your own keys and PINs. `secrets.h` is in `.gitignore` and must never be committed.

```
Pinnacle13_Firmware/
├── Node1_MainController/      ← upload to ESP32 #1 (LEFT PIR = zone 1, tamper, RFID, keypad, LCD, buzzer, LEDs)
│   ├── Node1_MainController.ino
│   ├── common.h               (identical in both folders)
│   └── secrets.h              (shared key, PIN hashes, card UIDs — do not upload to GitHub)
└── Node2_SensorNode/          ← upload to ESP32 #2 (RIGHT PIR = zone 2, IR later)
    ├── Node2_SensorNode.ino
    ├── common.h
    └── secrets.h              (shared key + Node 1's MAC address)
```

Both sketches compile on **Arduino-ESP32 core 3.3.0**, board **"ESP32 Dev Module"**, with no warnings.

---

## 1. Install

1. Arduino IDE → **Boards Manager** → install **esp32 by Espressif Systems** (3.x).
2. **Library Manager** → install:
   - **MFRC522** (by GithubCommunity / miguelbalboa)
   - **Keypad** (by Mark Stanley, Alexander Brevig)
   - **LiquidCrystal I2C** (by Frank de Brabander). It may warn "claims to run on avr" — ignore that, it works on ESP32.
3. Board: **ESP32 Dev Module**. Partition scheme: **Default** (needed for the log storage).

## 2. First-time setup (do these in order)

1. **Make your own shared key.** Run this once and paste the result into **both** `secrets.h` files:
   ```
   python3 -c "import os;print(', '.join('0x%02X'%b for b in os.urandom(32)))"
   ```
2. **Upload Node 1.** Open Serial Monitor at 115200 baud. Copy the line `Node 1 MAC: 24:6F:28:..`.
3. Put that MAC in **Node 2's `secrets.h`** as `NODE1_MAC` (e.g. `{0x24, 0x6F, 0x28, 0xAA, 0xBB, 0xCC}`), then **upload Node 2**.
4. **Enrol your RFID cards.**
   - In `Node1_MainController.ino` set `#define ENROLL_MODE 1` and upload.
   - Scan each card. The Serial Monitor prints `ENROLL card UID: 0x.., 0x.., ..`.
   - Copy each UID into the `USERS[]` table in Node 1's `secrets.h`. Decide which card is the OPERATOR and which is MAINTENANCE.
   - Set `ENROLL_MODE` back to **0** and upload again.
5. **Set PINs** (4–6 digits). Make the hash for each PIN and paste it into `USERS[]`:
   ```
   python3 -c "import hashlib;print(hashlib.sha256(b'pinnacle13-demo-salt'+b'1234').hexdigest())"
   ```
   The demo values in the file are PIN **1234** (operator) and **9876** (maintenance). Change them.
6. Add a `.gitignore` containing `secrets.h` before pushing to GitHub (one is included).

## 3. Wiring

### Node 1 (main controller)

| Part | Part pin → ESP32 |
|---|---|
| LCD1602 I2C | SDA → 21, SCL → 22, VCC → 5 V (see note), GND |
| RC522 RFID | SDA/SS → 5, SCK → 18, MOSI → 23, MISO → 19, RST → 4, **3.3V → 3.3 V only**, GND |
| 4×4 keypad (left→right pins) | R1 → 13, R2 → 14, R3 → 27, R4 → 26, C1 → 25, C2 → 33, C3 → 32, C4 → 16 |
| Buzzer module | I/O → 17, VCC → 5 V, GND |
| Green LED | 2 → 220 Ω → LED → GND |
| Red LED | 15 → 220 Ω → LED → GND |
| Yellow LED | 12 → 220 Ω → LED → GND (keeps GPIO 12 LOW at boot — don't change) |
| HC-SR501 PIR (Zone 1, faces LEFT) | OUT → 35, **10 kΩ from 35 to 3.3 V**, VCC → 5 V, GND |
| MAGREED tamper reed | one wire → 34, other wire → GND, **10 kΩ from 34 to 3.3 V**. Magnet on the lid. |

- The keypad pin order differs between keypads. If the wrong keys appear, swap the row/column order in `KP_ROWS` / `KP_COLS`.
- LCD on 5 V pulls SDA/SCL up to 5 V. Use an I2C level shifter if you have one, or try VCC → 3.3 V and turn the contrast pot.
- If the LCD stays blank, change `LCD_ADDR` to `0x3F`.
- If the buzzer beeps when it should be silent, set `BUZZER_ACTIVE_LOW = true`.
- Tie every GND together (ESP32, MB102 rails, all modules).

### Node 2 (sensor node)

| Part | Part pin → ESP32 |
|---|---|
| HC-SR501 PIR (Zone 2, faces RIGHT) | OUT → 27 (internal pull-up used), VCC → 5 V (VIN), GND |
| FC-51 IR (Zone 3, later) | OUT → 26, VCC → 3.3 V, GND |
| Status | on-board LED (GPIO 2) blinks every heartbeat |

Power Node 2 from USB (laptop or power bank).

**Coverage:** an HC-SR501 sees a cone of roughly 100–120°, not 180°. Two of them facing left and right cover about 220–240°, with gaps at the front and back. Angle them so their views **overlap a little at the front**. Someone walking through the overlap triggers both sides at once, which counts as a confirmed intrusion straight away.

**PIR settings (both nodes):** jumper on **L** (single trigger), time pot fully anticlockwise (~3 s). Both PIRs need ~60 s to settle after power-on, and the code waits for that.

**Adding the IR sensor later:**
- Node 2: set `enabled` to `true` in the IR row of `sensors[]`.
- Node 1: uncomment the `Z3-IR` line in `zones[]`.

Both are needed. If only one side is changed, Node 1 reports Zone 3 as OFFLINE.

## 4. Using the system

| State | LEDs | Buzzer | LCD |
|---|---|---|---|
| BOOT (60 s warm-up) | yellow blinking | – | "Warming up 45s" |
| WAIT_AUTH (disarmed) | green slow blink | – | "DISARMED" |
| MONITORING, P0 | green | – | "ARMED P0" |
| MONITORING, P1 warning | yellow | one chirp | "WARNING P1 18s" / "Z1-LEFT 1/3" |
| INTRUSION, P2 | red | continuous | "!! INTRUSION !!" |
| TAMPER / FAULT, P3 | red fast blink | fast pulsing | "!! TAMPER P3 !!" / "!! FAULT P3 !!" + reason |
| MAINTENANCE | yellow blinking | – | "MAINT 287s" |

**Logging in:** scan card → type PIN (shows `****`) → press **#**. **\*** clears the PIN.

| Want to… | Do this | Who |
|---|---|---|
| Arm | Card + PIN while DISARMED | Operator or Maintenance |
| Disarm | Press **D**, then card + PIN | Operator or Maintenance |
| Silence an intrusion | Card + PIN | Operator or Maintenance |
| Clear a tamper / fault | Card + PIN | **Maintenance only** |
| Enter maintenance | Maintenance card + PIN while ARMED | **Maintenance only** |
| In maintenance | **1** test LEDs/buzzer · **2** zone status · **3** send log to USB · **C** exit | auto-exit after 5 min |

- 3 wrong logins → locked 60 s, then 120 s, 240 s… The lock survives a power cut.
- If the RFID reader stops working, operators can log in with PIN only; maintenance is refused.

**Getting the log for your report:** enter maintenance, press **3**, and copy the CSV from the Serial Monitor. Every line is also printed live on Serial. The columns are:

```
boot,uptime_ms,priority,state,type,event,zone,role,uid,result
```

## 5. Test script (spec §19)

Allow the 60 s warm-up first. Watch the Serial Monitor on Node 1 while you test.

| Test | Do | Expect |
|---|---|---|
| T01 | Arm, stay still | green, "ARMED P0" |
| T02 | Wrong PIN / unknown card | "Access denied", `AUTH,Login failed,...,FAIL` |
| T03 | 3 wrong PINs, then unplug and re-power Node 1 | "LOCKED", still locked after reboot |
| T04 | One short wave at the RIGHT PIR, then stay still | yellow + chirp, `Motion warning 1/3`, back to P0 after 20 s |
| T05a | Wave at the RIGHT PIR, then the LEFT within 20 s | red + buzzer, `Corroborated both sides` |
| T05b | Keep moving in front of ONE PIR for ~15 s | red + buzzer, `Sustained motion Z1-LEFT x3` |
| T06 | Pull Node 1's PIR OUT wire | after ~30 s: "FAULT Z1-LEFT STUCK" (not intrusion) |
| T07 | Move the magnet away from the lid reed | "TAMPER P3" in any state |
| T08 | Press **A** while armed; type 7 digits; press **9** in maintenance | `INPUT,...,REJECTED` |
| T09 | Unplug Node 2's USB | within 3 s: "Node 2 lost", FAULT |
| T10 | Unplug Node 1's power while armed, plug back | boot log shows reason; re-arms after self-test |
| T11 | Maintenance card + PIN while armed; then try with operator card | maintenance mode / "Already armed"; auto-exit after 5 min |
| T12 | Fix the fault, clear with maintenance card + PIN | "Revalidating..." → back to ARMED |

**Optional T08 extra:** flash a copy of Node 2 with a different `SHARED_KEY`. Node 1 logs `Bad signature (spoofed?)` and ignores it.

**Check in Week 3:** unplug the RC522 and confirm Node 1 logs "RFID reader OFFLINE". With some boards the floating MISO line still looks like a reader. If that happens, unplug the 3.3 V wire to the RC522 instead.

## 6. Settings to agree at Design Review 1

All of these are constants at the top of `Node1_MainController.ino`:

- `CORROBORATION_MS` (20 s) and `REPEAT_TRIGGERS` (3). With the PIR on L mode and minimum time, it re-triggers about every 5–6 s, so 3 triggers take about 11–15 s of continuous movement.
- `NODE_TIMEOUT_MS` (3 s)
- `PIR_MAX_HIGH_MS` (30 s)
- `MAX_ATTEMPTS` (3) / `BASE_LOCKOUT_S` (60)
- `MAINT_TIMEOUT_MS` (5 min)
- **Re-arm after power cut:** see `handleBoot()`

## 7. Known limits (put these in the residual-risk table)

- Node 2 has no tamper switch. Unplugging it is detected; covering its PIR is not.
- Radio messages are signed (HMAC-SHA256) and replay-protected, but not encrypted.
- The first message after Node 1 restarts is trusted to set the counter.
- Timestamps are boot number + milliseconds since boot. Add a DS3231 RTC for real date/time.
- PINs are salted SHA-256 hashes. With only 4–6 digits they could be brute-forced by someone who reads the flash, which is why the lockout and the enclosure tamper switch matter.
- Card UIDs can be cloned, so a PIN is always required as well.
