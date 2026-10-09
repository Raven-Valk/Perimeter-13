# Project 13: Sensor Module firmware (v4.2)

One sketch runs on **both** sensor modules. The only line that differs between them is near the top of `SensorModule.ino`:

```cpp
#define MODULE_ID 'A'   // 'B' for the second module
```

| File | What it is |
|---|---|
| `SensorModule.ino` | the module firmware |
| `link_protocol.h` | the shared radio protocol (v3). The gateway and PC dongle use the **same file** |
| `secrets.h` | link keys, board MAC addresses, PIN hashes. **Never upload it to GitHub** |

Libraries (Arduino Library Manager): **Keypad** (Mark Stanley, Alexander Brevig) and **LiquidCrystal I2C** (Frank de Brabander). Board: **ESP32 Dev Module**.

## What the module does

**Sensors:**
- The **WALL PIR** looks along the wall toward the other module.
- The **SIDE PIR** looks down this module's own side wall.

**Confirmed intrusion (P2).** Any one of these, within 20 seconds:
- This module's WALL PIR and the other module's WALL PIR both fire.
- This module's WALL and SIDE PIRs both fire. You can switch this rule off with `SIDE_PAIRS_WITH_OWN_WALL 0`.
- One PIR fires 3 times.

A single trigger is only a warning (P1): a short beep, the yellow LED, and the LCD shows "A-WALL 1/3".

**On P2, both modules sound.** The module that confirmed it sends an alarm to the other one: 3 quick copies, then a repeat every 2 seconds while the alarm lasts.

**Who can do what:**

| Action | How |
|---|---|
| Arm, disarm, maintenance mode | **Only at the gateway** (card + PIN) or from the logged-in PC. The module still checks the role and its own state. For example, it never arms with the lid open or a PIR stuck. |
| Clear a tamper or fault | **Either** at the gateway (maintenance card + PIN, or the PC) **or** on this module's keypad with a **MAINTENANCE PIN**, then **#**. The lid must be shut. An operator PIN is refused and logged. The module then runs its self-test and returns to the mode it was in (armed or disarmed). |
| Silence this module's alarm | Any valid PIN, then **#**, on this module's keypad. It silences this module only. |
| Wrong PINs (alarm or tamper) | 3 wrong PINs lock the keypad for 60 s, then 120 s, then 240 s. The lockout survives a restart. |

**If the gateway or the other module goes offline,** this module keeps detecting and sounding. The LCD shows "GW link DOWN" or "Module B DOWN". Without the other module, a WALL trigger can only be confirmed by the 3-hit rule or the module's own SIDE PIR.

| LEDs and buzzer | Meaning |
|---|---|
| green blinking | disarmed |
| green steady | armed, all quiet (P0) |
| yellow steady | warning (P1) or recovery |
| yellow blinking | warming up (60 s after power-on) or maintenance |
| red steady + double beeps | intrusion (P2) |
| red fast blink + long beeps | tamper or fault (P3) |

## Pin map: ESP32 DevKitC 38-pin

The LEDs moved off the boot pins (2, 12, 15) that Board 1 used before. The PIRs stay on 35 and 34, so your existing PIR breadboard wiring still fits: **PIR-L is now WALL (35)** and **PIR-R is now SIDE (34)**.

| Part | Part pin | ESP32 pin | Notes |
|---|---|---|---|
| LCD 16×2 (I2C) | SDA / SCL | **21 / 22** | VCC to the 5 V rail |
| Keypad 4×4 | pins 1–4 (rows) | **13, 14, 27, 26** | pin 1 is the leftmost with the keys facing you |
| Keypad 4×4 | pins 5–8 (columns) | **25, 33, 32, 4** | |
| WALL PIR | OUT | **35** | + pull-up (3 × 2.2 kΩ in series) from 35 to the 3.3 V rail. VCC to 5 V |
| SIDE PIR | OUT | **34** | + pull-up (3 × 2.2 kΩ in series) from 34 to the 3.3 V rail. VCC to 5 V |
| Tamper reed switch | wire 1 / wire 2 | **39 (VN)** / GND | + 2.2 kΩ from 39 to the 3.3 V rail |
| Buzzer module (3-pin) | S (signal) | **16** | VCC to the 3.3 V rail. If it beeps when it should be quiet, set `BUZZER_ACTIVE_LOW true` |
| Green LED | anode (long leg) | **18** | through 220–330 Ω. A 2.2 kΩ resistor also works, but the LED is dim |
| Yellow LED | anode | **19** | same |
| Red LED | anode | **23** | same |
| (spare) IR sensor | OUT | 36 (VP) | for later |

**Power rails:**
- ESP32 **5V** pin goes to the top + rail, and **GND** to the top − rail.
- ESP32 **3V3** goes to the bottom + rail, and **GND** to the bottom − rail.
- Join the two − rails.
- Power the ESP32 from a 5 V USB adapter.

## Setting up the boards (both modules and the gateway)

1. Wire both modules the same way.
2. Upload with `MODULE_ID 'A'` to one board and with `'B'` to the other. Label the boards.
3. Open Serial Monitor (115200). Each board prints `Sensor Module A, MAC 24:6F:28:…`, and the gateway prints `Gateway, MAC …`. Write all three down (four once the PC dongle exists).
4. Put the MACs into `secrets.h` on **every** board:
   - `MAC_MOD_A`, `MAC_MOD_B` and `MAC_GATEWAY` (and `MAC_DONGLE` on the gateway), written as `0x24, 0x6F, …`.
   - Upload all boards again.
   - From then on every link is **encrypted**, and packets from any other MAC are refused.
5. **Until the MACs are set, the radio links stay OFF.** The log says "MAC not set in secrets.h: link OFF". That's on purpose: the boards never send anything readable over the air.
   - For a quick first test before step 4, you can set `#define ALLOW_UNENCRYPTED 1` (near the top of each sketch). The links then work signed but readable.
   - Set it back to 0 for the demo.
6. Change the demo keys before the real demo. The comment in `secrets.h` shows the one-line command. Module A, Module B and the gateway must hold the same bytes for each shared key.

**After a restart, links come back within about a second.** A board that has just restarted only listens for a fresh "I restarted" (HELLO) packet from the others, so old recorded packets can't be fed to it.

**After erasing a board's flash** ("Erase All Flash" or a factory reset), restart the other boards too. Each board counts its restarts in flash, and the others refuse a restart number older than one they have already seen. That's what stops replayed packets. The log then says "older boot number refused (flash erased? restart this board)".

## Testing without the gateway: bench commands

Set `#define BENCH_COMMANDS 1` and upload. In Serial Monitor (115200, line ending "Newline"), type:

| Command | Does |
|---|---|
| `arm` / `disarm` | arm or disarm |
| `maint 60` / `end` | maintenance for 60 s / end it |
| `ack` | acknowledge an intrusion |
| `clear` | clear a tamper or fault (close the lid first) |
| `status` | print the status line |
| `log` | print the whole event log |

These act as a MAINTENANCE user, with no card or PIN. **Set `BENCH_COMMANDS 0` again before the demo.** The module logs a warning at every boot while bench commands are on.

## Test script (one module, bench commands on)

| Test | Do | Expect |
|---|---|---|
| T01 Arm | `arm` (after the 60 s warm-up) | green LED, LCD "A ARMED P0" |
| T04 Warning | wave at the WALL PIR once | beep, yellow LED, "A-WALL 1/3" |
| T05b Intrusion (repeat) | the same PIR 3 times within 20 s | red LED, double beeps, "!! INTRUSION !!" |
| T05a Intrusion (pair) | WALL then SIDE within 20 s (with two modules: WALL A then WALL B) | intrusion on **both** modules |
| T02 Wrong PIN | during the alarm: `1111#` | "Wrong PIN, 2 tries left" |
| T03 Lockout | 3 wrong PINs | "LOCKED 60 s" |
| T12 Acknowledge + recovery | `1234#` (or `ack`) | RECOVERY, self-test, back to ARMED |
| T07 Tamper | open the lid (pull the reed's magnet away) | red fast blink, "!! TAMPER P3 !!" |
| Clear tamper (module) | close the lid, then `9876#` on the module keypad | "Fault cleared", RECOVERY, then ARMED |
| Clear tamper (operator) | during a tamper: `1234#` | "Access denied, Needs MAINT PIN" |
| Clear tamper (gateway) | close the lid, then `clear` (bench) or the gateway's clear | RECOVERY, then ARMED |
| T06 Stuck sensor | unplug a PIR's OUT wire while armed | after ~30 s: "FAULT P3 A-WALL STUCK" |
| T08 Invalid input | while armed, press **A** | "Invalid input" |
| T09 Link loss | switch Module B off | A logs "Module B link DOWN". A still alarms (3-hit rule) |
| T10 Power cut | while armed (or in alarm), unplug and replug | comes back armed (or still in alarm). The lockout is kept |
| T11 Maintenance | `maint 30`, wait | "A MAINT 30s", times out to RECOVERY, then back to ARMED |

## Event log

Every event is written to the module's flash (`/log.csv`, the last ~128 KB is kept), to USB serial, and to the gateway. The gateway can ask for any lines it missed. After a restart the numbering carries on exactly from the last line in the file.

```
log_no,boot,uptime_ms,unix_time,module,priority,state,type,event,zone,user,result
1042,7,183220,1760000000,A,P2,ARMED,ALERT,Intrusion: B-WALL + A-WALL,A-WALL,-,-
```

`unix_time` is 0 until the gateway has sent the real time.

## Known limits (for your report)

- **Keys and PIN hashes in flash:** anyone who has the board in hand can read them out. Opening the lid still raises P3. ESP32 flash encryption fixes this, but it can't be undone, so leave it off the demo boards.
- **Radio jamming:** it can't be prevented. It shows up as "link DOWN" in the log and on the LCD, and each module keeps alarming on its own.
- **Module keypads are PIN-only** (no card reader). That's why they can only silence their own module's alarm and, with a MAINTENANCE PIN, clear a tamper. Arming, disarming and maintenance mode still need the gateway.
- **`BENCH_COMMANDS 1` lets USB bypass card + PIN.** It's for testing only.
