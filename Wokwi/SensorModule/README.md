# Sensor Module in Wokwi (two tabs = Module A + Module B)

| File | Goes into Wokwi as |
|---|---|
| `sketch.ino` | replaces `sketch.ino`. It's a single file: `link_protocol.h` and `secrets.h` are already inside it |
| `diagram.json` | replaces `diagram.json`. ESP32 DevKitC 38-pin, LCD, keypad, 2 PIRs, slide switch as the tamper, buzzer, 3 LEDs |
| `libraries.txt` | new file with the same name (Keypad, LiquidCrystal I2C, PubSubClient) |

The sketch already has `WOKWI_SIM 1` and `BENCH_COMMANDS 1`. **Don't upload it to a real board.** Use the firmware folder for that. This sketch is generated from the firmware by `Tools/make_wokwi.py`.

## Set up (about 5 minutes)

1. wokwi.com → **New Project → ESP32**.
2. Paste `diagram.json`, `sketch.ino` and `libraries.txt` into the matching tabs. Use **▾ → New file…** for `libraries.txt`. **Save** the project and name it "P13 Module A".
3. Make the second module: **▾ → Save a copy**. Name the copy "P13 Module B". In its `sketch.ino`, change one line:
   ```cpp
   #define MODULE_ID 'B'
   ```
   Save again.
4. Open the two projects in **two separate browser windows, side by side**. Browsers slow down background tabs, and then the link times out.
5. Press ▶ in both. The first build takes about 1 minute. Connecting takes 5–15 s.

You should see:
- **Serial Monitor:** `[sim] MQTT connected`, then `Module B link UP` (in A) and `Module A link UP` (in B).
- **LCD:** "A Warming up 5s", then **A DISARMED**.

"GW link DOWN" is expected until you also run the gateway (see `../Gateway/README.md` for the three-tab setup).

## Controls

| Do this in Wokwi | Means |
|---|---|
| Click in the **Serial Monitor**, type `arm`, then Enter | arm (acts as the gateway). Also: `disarm`, `ack`, `clear`, `maint 30`, `end`, `status`, `log` |
| Click a **PIR → Simulate motion** | the **left** PIR is **WALL** (GPIO 17), the right one is **SIDE** (GPIO 19) |
| Keypad: `1234` then **#** | silence this module's alarm (PIN 1234 = Operator1, 9876 = Maint1) |
| Keypad: `9876` then **#** during a tamper | clear the tamper (MAINTENANCE PIN only, lid shut) |
| **Slide switch** to the right | lid opened (tamper). Slide it left = lid shut |

## Test script

Type `arm` in **both** tabs first.

| # | Do | Module A shows | Module B shows |
|---|---|---|---|
| 1 Warning | A: motion on **WALL** once | yellow LED + beep, "A-WALL 1/3" | log: "Motion seen by Module A", LCD "A-WALL motion" |
| 2 **Corroborated** | within 20 s, B: motion on **WALL** | **"!! INTRUSION !!"**, red + beeps | **"!! INTRUSION !!"**, red + beeps |
| 3 Silence one | A keypad: `1234#` | RECOVERY, then ARMED | **still sounding** (silenced only on its own keypad) |
| 4 Silence other | B: `ack` in Serial Monitor | — | RECOVERY, then ARMED |
| 5 One module alone | A: WALL 3 times within 20 s | INTRUSION ("A-WALL x3") | INTRUSION ("Module A confirmed") |
| 6 Own pair | after acknowledging: A: WALL, then A: SIDE | INTRUSION ("A-WALL + A-SIDE") | INTRUSION |
| 7 Wrong PIN + lockout | during an alarm: `1111#` three times | "Wrong PIN…", then "LOCKED 60 s" | — |
| 8 Tamper | A: slide switch right | "!! TAMPER P3 !!" | — |
| | keypad `9876#` while the switch is still right | "Cannot clear, Lid open" | — |
| | slide it left, then keypad `1234#` | "Access denied, Needs MAINT PIN" | — |
| | keypad `9876#` (or type `clear`) | "Fault cleared", RECOVERY, then ARMED | — |
| 9 Link loss | **Stop** tab B | within ~8 s: "Module B DOWN" (alarms still work) | — |
| | Press ▶ on B again | "Module B restarted", "link UP" | starts DISARMED (Wokwi keeps no memory between runs) |
| 10 Fake module | in B, change one byte of `KEY_A_B` (e.g. `0x6E` to `0x6F`), ▶ | log: "Module B: bad signature (spoofed?) REJECTED" | its events are ignored by A |
| 11 Maintenance | `maint 30` | "A MAINT 30s"; motion only logs "Test trigger"; times out to RECOVERY, then ARMED | — |

## Differences from the real board

- **Radio:** ESP-NOW becomes MQTT through a public server (same signed packets). Each module listens on `pinnacle13/p13-2d386efc/v5/to/A` (or `/B`).
- **PIR warm-up:** 5 s instead of 60 s. Link timeouts are 8 s instead of 3 s.
- **Buzzer:** plays a 2 kHz tone (Wokwi's buzzer needs a tone).
- **Nothing survives stopping Wokwi** (armed state, lockout, log, restart counter). Test T10 power-cut on the real board.
- **No encryption and no MAC allow-list** (MQTT has no MACs). Signatures, replay protection and the stale-command check are the same as on the real board.
