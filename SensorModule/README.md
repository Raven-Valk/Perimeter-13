# Project 13: Sensor Module firmware (v6.1)

One sketch runs on **all four** sensor modules. The line that differs between them is near the top of `SensorModule.ino`:

```cpp
#define MODULE_ID 'A'   // 'A', 'B', 'C' or 'D'
```

| File | What it is |
|---|---|
| `SensorModule.ino` | the module firmware |
| `link_protocol.h` | the shared radio protocol (v4) and the site layout (zones). The gateway uses the **same file**; the server has the same format in Python |
| `mesh.h` | the mesh: who hears whom, choosing a relay, passing packets on. **Same file** in `Gateway/` |
| `secrets.h` | link keys (each module gets only its own 4), board MAC addresses, PIN hashes. **Never upload it to GitHub** |

Libraries (Arduino Library Manager): **Keypad** (Mark Stanley, Alexander Brevig) and **LiquidCrystal I2C** (Frank de Brabander). Board: **ESP32 Dev Module**.

## The four modules

```
        A ──── zone 2 ──── B
        │                  │
     zone 1      G      zone 3
        │                  │
        D ~~~~ zone 4 ~~~~ C      (IR beam: D sends, C receives)
```

| Module | Sensors (zone = wall) | Other parts |
|---|---|---|
| A | PIRs **A-Z2** on GPIO 17 (wall A–B), **A-Z1** on GPIO 19 (wall A–D) | LCD, keypad, tamper reed, buzzer, green/yellow/red LEDs |
| B | PIRs **B-Z2** on GPIO 17 (wall A–B), **B-Z3** on GPIO 19 (wall B–C) | as A |
| C | PIR **C-Z3** on GPIO 17 (wall B–C), IR receiver **C-Z4** on GPIO 19 (wall C–D) | LCD, keypad, 3-pin buzzer. Optional: tamper reed, LEDs |
| D | PIR **D-Z1** on GPIO 17 (wall A–D), IR sender on GPIO 19 (wall C–D) | as C |

What C and D have fitted is set near the top of the sketch:

```cpp
#define CD_TAMPER_FITTED 0   // 1 = reed switch on pin 23
#define CD_LED_GREEN     0   // 1 = LED on pin 18
#define CD_LED_YELLOW    1   // 1 = LED on pin 2 (many boards already have one there)
#define CD_LED_RED       0   // 1 = LED on pin 15
#define CD_BUZZER_FITTED 1   // 1 = 3-pin buzzer module on pin 16
#define CD_BUZZER_ACTIVE_LOW 0  // 1 if that buzzer beeps when its pin is LOW
#define BEAM_FITTED      1   // 1 = zone 4: IR beam on wall C-D (pin 19 on C and D)
```

The code for everything else is the same as on A and B, so C and D can be made fully featured just by fitting the parts and setting these to 1. With fewer than three LEDs, every LED fitted shows one pattern: **fast blink** = alarm or fault, **slow blink** = warning or busy, **steady** = armed and quiet, **1 s blink** = disarmed.

## Mounting the PIRs: outside, along the wall

Each PIR sits on the **outside face** of its wall, at the corner, and looks **along** the wall toward the other corner. The two PIRs of a wall face each other, so their fields overlap along the whole wall: a narrow "curtain" just outside it. Someone has to reach the wall to be seen, and both ends see them.

Turn the HC-SR501 down so it only covers that strip and not the street beyond:

| HC-SR501 setting | Set it to | Why |
|---|---|---|
| **Sensitivity / range pot** (the one marked *Sx*, usually next to the jumper) | **fully anticlockwise**, then up a little until a person at the far corner is seen | about 3 m instead of 7 m: only the wall's length |
| **Time-delay pot** (*Tx*) | **fully anticlockwise** (about 3 s) | short pulses, so separate passes count as separate hits |
| **Jumper** | **L** (single trigger) | one pulse per pass; repeat triggers would add up to "3 hits" too fast |
| **Lens** | tape off the half that faces away from the wall | stops it looking out across the street |

## Zone 4: the IR beam on wall C–D

Two **IR-08H** modules (4 pins: **EN, OUT, +, GND**). Each has an infrared LED driven at 38 kHz by a 555 timer, which only runs while EN is HIGH, and an HS0038 receiver that pulls OUT LOW while it sees 38 kHz infrared. One is used as the sender (at D), the other as the receiver (at C).

| | D: sender | C: receiver |
|---|---|---|
| Jumper on the module | **remove it** (it ties EN to + and the LED would never switch off) | **remove it** |
| EN | **GPIO 19** | **GND** (its own LED stays dark) |
| OUT | not connected | **GPIO 19** |
| + / GND | **3.3 V** / GND | **3.3 V** / GND (3.3 V keeps OUT safe for the ESP32) |
| Points | along the outside of wall C–D, at C's receiver | back at D's LED |

**Why bursts.** The HS0038 ignores infrared that never stops (it takes it for sunlight). So D switches its sender on for **1 ms every 10 ms**: the ESP32's LEDC hardware does it, no CPU time. Each burst gives C one short LOW pulse on OUT, counted by an interrupt. About 10 pulses per 100 ms = beam intact; none for 60 ms = broken.

**Range.** The IR-08H is made as a reflective obstacle sensor (2–40 cm). Pointed straight at each other, the two modules reach further, but **test the distance on the real wall**. If it is too short: a narrow tube (black straw or heat-shrink) over D's LED and C's receiver, both at the same height, lined up carefully.

**Rules for zone 4** (the beam is the only sensor on that wall):
- broken once → warning (P1): C chirps, C's LCD shows "Beam C-Z4 1/2"; D logs "Beam broken, seen by Module C";
- broken **twice within 20 s** → intrusion in zone 4; buzzers at C and D;
- broken while an intrusion is active → zone 4 joins the alarm at once;
- two breaks closer than 2 s (two legs, a bag) count as one crossing;
- blocked for 30 s, OUT held LOW for 1 s (wiring), or no signal from D 5 s after start-up → **fault (P3)**, like a stuck PIR. The module won't arm with the beam faulty.

### Beam check

`signalValid()` in `beam.h` decides whether what C receives really is D's beam. It is marked **TODO(team)**: right now it only checks that a pulse arrived in the last 60 ms. A stricter check can also look at the pulse **rate** (`lastWindowPulses` over `lastWindowMs`; D sends one burst every 10 ms): a TV remote or another 38 kHz source gives a different rate than D. Too strict and normal jitter (missed or extra pulses) looks like a break; too loose and someone could hold a remote at C to hide a crossing. `tests/beam_tests.cpp` checks whatever you choose.

## What the module does

**Confirmed intrusion (P2), zones 1–3.** Any one of these, within 20 seconds:
- **Both PIRs of a wall** fire: this module's and the one at the other end (A-Z1 + D-Z1, A-Z2 + B-Z2, B-Z3 + C-Z3).
- **Both PIRs of this module** fire (A or B: someone going round the corner). Off with `CORNER_PAIRS 0`.
- **One PIR fires 3 times.**

A single trigger is only a warning (P1): a short beep (A, B), the yellow LED, and the LCD shows "A-Z2 1/3". The module at the other end of that wall logs "Motion seen by Module A".

Zone 4 (the beam) has its own rule, above: two breaks within 20 s.

**On P2, every armed module goes to INTRUSION.** The module that confirmed it sends the alarm to the other three: 3 quick copies, then a repeat every 2 seconds. The alarm carries its zones: **the buzzer sounds on each module standing on a wall in alarm** — zone 1 → A and D, zone 2 → A and B, zone 3 → B and C, zone 4 → C and D. Every module shows "!! INTRUSION !!" and lights its red LED (or blinks its LED fast).

**While the alarm is not acknowledged, any single sensor is an intrusion.** If a module's PIR (or the beam) fires during the alarm, its zone joins the alarm at once ("Intrusion zone 3 (escalated)"), no 20-second window and no 3 hits; the buzzers for that wall start. A module that is already acknowledged but sees another module still in alarm does the same. Once every module has been acknowledged, the normal rules are back.

**Who can do what:**

| Action | How |
|---|---|
| Arm, disarm, maintenance mode | **Only at the gateway** (card + PIN) or from the dashboard. The module still checks the role and its own state. For example, it never arms with the lid open or a PIR stuck. |
| Clear a tamper or fault | At the gateway (maintenance card + PIN, or the dashboard) **or** on this module's keypad with a **MAINTENANCE PIN**, then **#**. The lid must be shut. |
| Silence this module's alarm | Any valid PIN, then **#**, on this module's keypad. It silences this module only. |
| Wrong PINs (alarm or tamper) | 3 wrong PINs lock the keypad for 60 s, then 120 s, then 240 s. The lockout survives a restart. |
| Relay test | From the dashboard (maintenance) or `cut` in bench mode: treat one direct link as broken for up to 5 min. |

## The mesh

Each module talks straight to the other three and the gateway, every second (status beats), each link with its own key and encryption. Every packet says which boards the sender hears directly, so each end knows whether a link works **both ways**.

When a direct link stops working (nothing heard on it for 2.5 s, or the other end says it can't hear us), packets for that board are **also** sent through a relay: a board that hears both ends (the gateway first, as it's in the middle, then the strongest signal). The relay passes the packet on unchanged; it can't read or change it, because it's signed with the key of the two end boards. The receiver keeps the first copy and drops the second. When the direct link works again, the relay stops. Changes are logged: "Module C: direct link lost, relayed through Gateway" … "Module C: direct link back".

A board only passes on packets that name it as relay and come straight from their sender (one hop, no loops), at most 40 a second. The status line shows how this module reaches each board (`NET:`) and how many packets it has relayed (`FWD:`).

**Radio channel.** The gateway's radio runs on its Wi-Fi network's channel. Every message from the gateway says which channel that is, and the modules move there at once. If nobody can reach the gateway at all (not straight, not through another module), the first module of those that still hear each other (A, then B …) steps through the other channels until the gateway answers; the others follow.

**If the gateway or other modules go offline,** each module keeps detecting and sounding. Without the module at the other end of a wall, that wall confirms by the 3-hit rule (or A's/B's corner rule).

## Pin map: ESP32 DevKitC 38-pin

The PIRs and the tamper switch use the ESP32's **built-in pull-up**: **no resistors**.

| Part | Part pin | ESP32 pin | A, B | C, D |
|---|---|---|---|---|
| LCD 16×2 (I2C) | SDA / SCL | **21 / 22** | ✓ | ✓ |
| Keypad 4×4 | pins 1–4 (rows) | **13, 14, 27, 26** | ✓ | ✓ |
| Keypad 4×4 | pins 5–8 (columns) | **25, 33, 32, 4** | ✓ | ✓ |
| PIR 1 | OUT | **17** | Z2 | its only PIR |
| PIR 2 | OUT | **19** | A: Z1, B: Z3 | — |
| IR-08H (zone 4) | C: OUT, D: EN | **19** | — | C: receiver, D: sender (see Zone 4) |
| Tamper reed switch | wire 1 / wire 2 | **23** / GND | ✓ | optional |
| Buzzer module (3-pin) | S (I/O) | **16** | ✓ | ✓ |
| Green LED | anode, via 220–330 Ω | **18** | ✓ | optional |
| Yellow LED | anode, via 220–330 Ω | **2** | ✓ | optional (often on the board already) |
| Red LED | anode, via 220–330 Ω | **15** | ✓ | optional |

PIR VCC to 5 V, LCD VCC to 5 V, buzzer VCC to 3.3 V, IR-08H + to **3.3 V**. See `../Diagrams/` for both wirings.

## Setting up the boards

1. `python3 Tools/make_keys.py` once (new keys for the 10 links; demo keys are already in place).
2. Upload with `MODULE_ID 'A'`, `'B'`, `'C'`, `'D'` to the four boards. Label them.
3. Open Serial Monitor (115200). Each board prints `Sensor Module C (walls: zone 3+4), MAC 24:6F:28:…, IR beam receiver`; the gateway prints `Gateway, MAC …`. Write all five down.
4. Put the MACs into **both** `secrets.h` files (`MAC_MOD_A` … `MAC_MOD_D`, `MAC_GATEWAY`) and upload all five again. From then on every link is **encrypted**, and packets from any other MAC are refused.
5. **Until the MACs are set, the radio links stay OFF** ("MAC not set in secrets.h: link OFF"). For a first bench test you can set `ALLOW_UNENCRYPTED 1`; set it back to 0 for the demo.

**After erasing a board's flash**, restart the other boards too (they refuse a restart number older than one already seen; that's what stops replays).

## Testing without the gateway: bench commands

Set `#define BENCH_COMMANDS 1` and upload. In Serial Monitor (115200, "Newline"):

| Command | Does |
|---|---|
| `arm` / `disarm` | arm or disarm |
| `maint 60` / `end` | maintenance for 60 s / end it |
| `ack` / `clear` | acknowledge an intrusion / clear a tamper or fault |
| `cut c 60` | relay test: treat the direct link to C as broken for 60 s (`a`, `b`, `c`, `d`, `g`; `0` s ends it) |
| `status` / `log` | print the status line / the whole event log |

These act as a MAINTENANCE user, with no card or PIN. **Set `BENCH_COMMANDS 0` again before the demo.**

## Test script (all five boards)

| Test | Do | Expect |
|---|---|---|
| T01 Arm | gateway: card + PIN, **1** | "ARM OK, A:OK B:OK C:OK D:OK" |
| T04 Warning | wave at D's PIR once | D: "D-Z1 1/3"; A logs "Motion seen by Module D" |
| T05a Wall pair | within 20 s, A's zone-1 PIR | INTRUSION everywhere, **A and D beep** |
| Escalation | while still in alarm: C's PIR once | "Intrusion zone 3 (escalated)", **B and C beep too** |
| T12 Acknowledge | gateway **3** (or dashboard) | RECOVERY, self-test, ARMED; a single trigger is a warning again |
| T05b Three hits | one PIR 3 times within 20 s | INTRUSION ("C-Z3 x3") |
| Corner | A's two PIRs within 20 s | "Intrusion zone 1+2 … (corner)" |
| Relay | dashboard: Test the relays → Link A–C, 1 min (or `cut c 60` on A) | plan shows A–C relayed via GW; log "Module C: direct link lost, relayed through Gateway"; alarms still reach C |
| Real relay | move D far away / behind metal until G loses it | "Gateway: direct link lost, relayed through Module A" on D; D still reports |
| Beam warning | walk through the beam on wall C–D once | C: chirp, "Beam C-Z4 1/2"; D: "Beam broken, seen by Module C"; dashboard: warning on zone 4 |
| Beam confirm | walk back through within 20 s (more than 2 s later) | "Intrusion zone 4: C-Z4 beam broken x2", **C and D beep** |
| Beam fault | cover C's receiver for 30 s | C: "Beam STUCK" → TAMPER_FAULT; uncover, clear with `9876#` |
| Beam no signal | unplug D's sender, restart C | C: "Beam NO SIGNAL", won't arm |
| T09 Lost board | switch C off | others log "Module C link DOWN"; zone 3 then confirms by B's 3-hit or corner rule |
| T07 Tamper | open A's lid | "!! TAMPER P3 !!"; clear with `9876#` once shut |
| T10 Power cut | in alarm, unplug A and replug | back in INTRUSION with its zones, buzzer again |

## Event log

Every event goes to the module's flash (`/log.csv`, the last ~128 KB), USB serial and the gateway, which fetches lines it missed.

```
log_no,boot,uptime_ms,unix_time,module,priority,state,type,event,zone,user,result
1042,7,183220,1760000000,A,P2,ARMED,ALERT,Intrusion zone 2: B-Z2 + A-Z2,A-Z2,-,-
```

## Known limits (for your report)

- **Keys and PIN hashes in flash:** anyone with the board in hand can read them. A stolen module only holds the keys of its own 4 links. ESP32 flash encryption fixes this but can't be undone, so it is left off the demo boards.
- **Radio jamming** can't be prevented. Relays get round one blocked link, not a jammed channel. It shows as "link DOWN", and each module keeps alarming on its own.
- **One hop only.** If a board can't reach any board that reaches the other end, the link is down. With 5 boards in a 2-D layout, one hop covers every single link failure.
- **C and D without a tamper switch** can be opened unnoticed. Fit the reed and set `CD_TAMPER_FITTED 1` to close that gap.
- **`BENCH_COMMANDS 1` lets USB bypass card + PIN.** Testing only.
- **Zone 4 has one sensor.** A single crossing (in once, not back) is only a warning. Someone who knows where the beam is can step over or crawl under it; mount it at knee height, and consider a second beam later.
- **The beam can be fooled by a 38 kHz source held at C** (a TV remote) unless `signalValid()` checks the pulse rate (see "Beam check").
