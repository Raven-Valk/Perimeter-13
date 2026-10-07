# Project 13 — Board 1 in the Wokwi simulator

This is the v3 **Board 1 controller** wired on a 30-pin ESP32 DevKit V1 in Wokwi. The pins and wiring are the same as the real build.

| File | Goes into Wokwi as |
|---|---|
| `diagram.json` | the circuit: replaces Wokwi's `diagram.json` |
| `sketch_single_file.ino` | **easiest:** paste this into Wokwi's `sketch.ino`. Everything is in one file, so the two `.h` files aren't needed |
| `sketch.ino` | the multi-file version: needs `link_protocol.h` and `secrets.h` added as extra files |
| `link_protocol.h` | new file, same name |
| `secrets.h` | new file, same name. Cards set to Wokwi's preset cards |
| `libraries.txt` | new file, same name: MFRC522, Keypad, LiquidCrystal I2C, PubSubClient |
| `Gateway/` | the second Wokwi project, for testing the gateway online. See `Gateway/README.md` |

## Set it up (about 3 minutes)

1. Go to **wokwi.com** and sign in. You need an account to save the project.
2. Click **New Project → ESP32** (any ESP32 starter).
3. Click the **diagram.json** tab, select all, delete, and paste in our `diagram.json`.
4. Click the **sketch.ino** tab, select all, delete, and paste in our `sketch.ino`.
5. Click the **▾ arrow next to the file tabs → New file…** three times, creating **`link_protocol.h`**, **`secrets.h`** and **`libraries.txt`**. Paste the matching file into each.
6. Click **Save**, then the green **▶ Play** button. The first build takes about 1 minute.

## What you'll see

The LCD shows "Warming up 5s", then **DISARMED**. The Serial Monitor (bottom panel) prints every event-log line.

**"PC link DOWN"** appears when the gateway tab isn't running. That's correct: the alarm works on its own without the PC link (test T09). To bring the link up, run the `Gateway/` project in a second tab.

## Controls in the simulator

| Do this in Wokwi | Means |
|---|---|
| Click the **RFID reader** → pick **Blue card** → **Tap** | scan the OPERATOR card (PIN **1234**) |
| Click the RFID reader → **Green card** → Tap | scan the MAINTENANCE card (PIN **9876**) |
| Click keypad keys, then **#** | enter the PIN; **\*** clears |
| Click a **PIR sensor** → **Simulate motion** | motion on that side (left PIR on D35, right PIR on D34) |
| Slide the **slide switch** to the **right** | enclosure lid opened (tamper); slide left = lid shut |

## Demo script

| Test | Steps | Expect |
|---|---|---|
| Arm (T01) | Blue card → 1 2 3 4 # | green LED, "ARMED P0" |
| Wrong PIN (T02/T03) | Blue card → 1 1 1 1 #, three times | "Access denied" ×2, then "LOCKED 60 s" |
| Warning (T04) | Simulate motion on **one** PIR | yellow LED + beep, "Z1-LEFT 1/3" |
| Intrusion (T05a) | Motion on one PIR, then the other within 20 s | red LED, buzzer, "!! INTRUSION !!" |
| Intrusion (T05b) | Motion on the same PIR 3 times within 20 s | same as above |
| Acknowledge | Blue card → 1234 # | "RECOVERY" → back to ARMED |
| Tamper (T07) | Slide the switch right | red blinking, "!! TAMPER P3 !!" |
| Clear tamper | Slide the switch left, then **Green** card → 9876 # | RECOVERY → ARMED (Blue card is refused: "Needs MAINTENANCE") |
| Invalid key (T08) | While armed, press **A** | "Invalid input" |
| Maintenance (T11) | While armed: Green card → 9876 # | "MAINT 300s"; keys 1 / 2 / 3, **C** to exit |
| Disarm | Press **D**, then Blue card → 1234 # | "DISARMED" |
| Stuck sensor (T06) | Stop the simulation, delete the wire from **pirL OUT** to D35, press Play, arm, wait ~35 s | FAULT "Z1-LEFT STUCK" (the pull-up resistor holds the pin HIGH, like an unplugged PIR) |

## Differences from the real board

- **Buzzer:** the real board uses an active buzzer (steady ON). Wokwi's buzzer needs a tone, so `WOKWI_SIM 1` makes the code play a 2 kHz tone instead.
- **PIR warm-up:** 5 s here instead of 60 s, so you don't have to wait.
- **Gateway / PC link:** run on its own, Board 1 shows "PC link DOWN". To test the gateway online, open the `Gateway/` project in a second Wokwi tab (see `Gateway/README.md`). In simulation the link runs over MQTT instead of ESP-NOW.
- **Power cut:** saved state such as lockout or armed may not survive stopping and restarting Wokwi. Test T10 on the real board.
- **Before uploading to the real ESP32,** use `Board1_Controller.ino` from the firmware folder, which has `WOKWI_SIM 0`, plus your real card UIDs in `secrets.h`.
