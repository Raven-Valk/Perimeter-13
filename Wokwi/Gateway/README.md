# Gateway in Wokwi (three tabs: Module A + Module B + Gateway)

| File | Goes into Wokwi as |
|---|---|
| `sketch.ino` | replaces `sketch.ino`. It's a single file: `link_protocol.h` and `secrets.h` are already inside it |
| `diagram.json` | replaces `diagram.json`. ESP32 DevKit V1 (30-pin), LCD, RFID reader, keypad, slide switch as the tamper, 3 LEDs |
| `libraries.txt` | new file with the same name (MFRC522, Keypad, LiquidCrystal I2C, PubSubClient) |

The sketch already has `WOKWI_SIM 1`, which also selects Wokwi's preset cards. **Don't upload it to a real board.**

**Update your two module projects too** whenever you update the gateway: paste the **new** `SensorModule/sketch.ino` into both "P13 Module A" and "P13 Module B", then set `MODULE_ID 'B'` again in B.

These sketches are generated from the real firmware by `Tools/make_wokwi.py`. Change the firmware, then run that script, rather than editing these files.

## Set up

1. wokwi.com → **New Project → ESP32**. Paste `diagram.json`, `sketch.ino` and `libraries.txt`. **Save** it as "P13 Gateway".
2. Open **three browser windows** side by side: Gateway, Module A and Module B. Browsers slow down background tabs, and that makes links time out.
3. Press ▶ in all three. The first build takes about 1 minute; connecting takes 5–15 s.
4. The gateway LCD shows `SYS DISARMED P0` and `A:DIS B:DIS PC:N`. Its Serial Monitor shows `LOG,…` lines from all three boards.

## Controls (gateway tab)

| Do this | Means |
|---|---|
| Click the **RFID reader → Blue card → Tap** | OPERATOR card (PIN **1234**) |
| **Green card** → Tap | MAINTENANCE card (PIN **9876**) |
| Keypad: PIN, then **#** | log in. The menu appears: 1 Arm, 2 Disarm, 3 Ack, 4 Maint, 5 Clear, 6 End, * log out |
| **Slide switch** to the right | gateway lid opened (tamper) |

In the module tabs: **PIR → Simulate motion** (left = WALL, right = SIDE), the module keypad (silence or clear with a PIN), and its own slide switch.

## Test script

| # | Do (tab) | Gateway shows | Modules show |
|---|---|---|---|
| 1 Arm | G: Blue card, `1234#`, **1** | "ARM OK, A:OK B:OK", then `SYS ARMED P0` | "A ARMED" / "B ARMED" |
| 2 Intrusion | A: motion on WALL; then B: motion on WALL within 20 s | "!! INTRUSION !!", red LED | both sound |
| 3 Acknowledge | G: Blue card, `1234#`, **3** | "ACK OK, A:OK B:OK" | RECOVERY, then ARMED |
| 4 Wrong PIN | G: Blue card, `1111#` (3 times) | "Access denied…", then "LOCKED 60 s" | (alarm still works) |
| 5 Role check | G: Blue card, `1234#`, **4** | "Access denied, Needs MAINT card" | — |
| 6 Maintenance | G: Green card, `9876#`, **4**, **1** | "MAINT OK", then `A:MNT` | A: "A MAINT 300s" |
| 7 End it | G: Green card, `9876#`, **6**, **1** | "END OK" | A: RECOVERY, then ARMED |
| 8 Module tamper | A: slide switch right | "!! MOD TAMPER !!", `A:TMP` | A: "!! TAMPER P3 !!" |
| 9 Clear at gateway | A: switch left; G: Green card, `9876#`, **5**, **1** | "CLEAR OK" | A: RECOVERY, then ARMED |
| 10 Clear refused | (repeat 8) then G: Green, `9876#`, **5**, **1** with A's switch still right | "CLEAR FAILED, A:Lid open" | still tamper |
| 11 Gateway tamper | G: slide switch right | "!! GW TAMPER !!", red flashing | — |
| | G: Blue card, `1234#` | "Access denied, Needs MAINT card" | — |
| | G: switch left; Green card, `9876#` | "CLEAR OK" | — |
| 12 Disarm | G: Blue card, `1234#`, **2** | "DISARM OK", `SYS DISARMED` | DISARMED |
| 13 Module lost | while armed: **Stop** tab B | within ~8 s: `B:--`, red flashing, log "Module B LOST while armed" | — |
| 14 Log recovery | **Stop** G; in A make some events (`status` doesn't count; use motion or `maint 30`); ▶ G | A's lines from while G was off appear in G's Serial Monitor | — |
| 15 Fake gateway | G: change one byte of `KEY_A_GW` (e.g. `0x5B` to `0x5C`), ▶ | `A:--` | A: log "Gateway: bad signature (spoofed?) REJECTED" |

The modules' typed bench commands (`arm`, `ack`…) still work in Wokwi, alongside the gateway.

## Differences from the real board

- **Radio:** MQTT through a public server instead of ESP-NOW (same signed packets). No encryption and no MAC allow-list.
- **Nothing survives stopping Wokwi** (lockouts, tamper state, log, restart counters). Because there are no restart counters, the simulator accepts any new boot. Anyone on that public server could replay an old "I restarted" packet. Test the restart protection on the real boards.
- **Timeouts are longer:** 8 s for links and up to 9 s for a command answer, because MQTT over the internet is slower.
- **No Wi-Fi channel finding:** in Wokwi everything goes through MQTT, so the module's channel search is switched off.

## The dashboard with Wokwi

The real dashboard can follow the simulation. On any computer with Python 3.11+ (internet needed, for the public broker):

```
cd Server
pip install -r requirements.txt
python3 scripts/setup.py --key-hex f23eaba527c7e035a8178ec427f504d091601abacc939e6a717d14e88dabb71e
python3 -m p13server --mode wokwi
```

The `--key-hex` value is the Wokwi gateway's `KEY_GW_SERVER` (the demo key). Open https://127.0.0.1:8443 (accept the certificate warning) and sign in as `operator` / `operator123` or `admin` / `admin123`. The LCD's `PC:` changes to `Y`, then to `L` when someone has control. The page shows a banner: the public broker means anyone can read the packets, although they still can't forge them.
