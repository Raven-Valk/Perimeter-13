# Version history

Pinnacle Project 13: Secure Perimeter Intrusion Detection (ESP32).

Each version is one commit with a tag of the same name. To see the files of a version on GitHub, pick its tag in the branch menu; on a PC: `git checkout <tag>`.

The version numbers here are the final ones. During development some versions had other working names (shown in the last column); those names still appear inside a few files, such as folder names, the `FIRMWARE_VERSION` string and MQTT topics. "Protocol v2/v3/v4" in the docs is the radio packet format, numbered on its own.

| Version | Date | What changed | Working name |
|---|---|---|---|
| [`v4.3`](#v43) | 2026-10-09 | built-in pull-ups instead of resistors, new pin map, wiring diagrams | v5.3 |
| [`v4.2`](#v42) | 2026-10-09 | gateway control box, PC login protocol, links off until MACs are set | v5.2 |
| [`v4.1`](#v41) | 2026-10-08 | clear a tamper or fault on the module with a MAINTENANCE PIN | v5.1 |
| [`v4`](#v4) | 2026-10-08 | sensor module firmware for two identical modules (A, B) | v5 (SensorModule) |
| [`v3.1`](#v31) | 2026-10-07 | Wokwi simulation of the controller and gateway, bench tools | Pinnacle13_Firmware_v4 + Wokwi |
| [`v3`](#v3) | 2026-10-06 | one controller board with both PIRs + listen-only gateway to the PC | Pinnacle13_Firmware_v4 (first) |
| [`v2`](#v2) | 2026-10-06 | teammate's single-board draft (draft2.ino) | draft2.ino |
| [`v1`](#v1) | 2026-10-05 | two-node firmware (main controller + sensor node over ESP-NOW) | Pinnacle13_Firmware |

## v4.3

*2026-10-09* · built-in pull-ups instead of resistors, new pin map, wiring diagrams · worked on as v5.3

Simpler wiring: the PIRs and tamper switches move to pins that have the ESP32's built-in pull-up, so the 2.2 kOhm resistor chains are no longer needed. Wiring diagrams for both boards.

**Sensor module pins**

- WALL PIR 35 -> 17, SIDE PIR 34 -> 19, tamper 39 -> 23, all with INPUT_PULLUP and no resistors.
- Yellow and red LEDs move to boot pins 2 and 15 (an LED + resistor to GND is safe there).
- Note for long sensor wires (over about 50 cm): add a 10 kOhm pull-up if false triggers appear.

**Gateway pins**

- Tamper 39 -> RX2 (16) with the built-in pull-up; yellow LED -> D15.

**Docs and simulation**

- Wiring diagrams (SVG + PNG) for the gateway and the sensor module (Diagrams/).
- Wokwi diagrams updated to the new pins (resistors removed).

## v4.2

*2026-10-09* · gateway control box, PC login protocol, links off until MACs are set · worked on as v5.2

Adds the gateway: the control box with the RFID reader, keypad and LCD that sends commands to both modules and collects their logs. The protocol gains the PC login messages, and the radio links stay off until every board's MAC address is set.

**Gateway (new)**

- Card + PIN then a menu: arm, disarm, acknowledge, maintenance, clear tamper/fault, per module or both.
- Each module's result comes back to the LCD; a repeated command is recognised and not run twice.
- Log recovery: asks the modules again for any log lines it missed, also after a restart.
- Tamper switch, 3 LEDs; 3 wrong card/PIN tries lock the keypad (60 s up to 960 s), surviving a restart.

**PC login (prepared for the dashboard)**

- Challenge-response: the gateway stores PBKDF2-HMAC-SHA256 password hashes (100,000 rounds); the password never travels.
- Sessions: one at a time, 5 min idle / 30 min total; separate lockout for PC logins.

**Radio security**

- Links are OFF until the MAC addresses are set, so nothing readable is ever sent (ALLOW_UNENCRYPTED 1 only for a first bench test).
- After a restart a board accepts only a fresh HELLO; boards answer an out-of-date boot number with a HELLO, so links come back in about a second.
- Log numbering carries on from the last line in flash after a restart.

**Tests and simulation**

- 60 protocol checks (including the PC login against a Python reference) and 11 log-recovery checks; run_tests.sh.
- Wokwi projects for the gateway and a sensor module.

## v4.1

*2026-10-08* · clear a tamper or fault on the module with a MAINTENANCE PIN · worked on as v5.1

A tamper or fault can now be cleared at the module itself, not only from the gateway, but only with a MAINTENANCE PIN and only with the lid shut.

**Sensor module**

- During TAMPER_FAULT, a MAINTENANCE PIN + # on the module keypad clears it; the module runs its self-test (RECOVERY) and returns to armed or disarmed.
- An OPERATOR PIN is refused and logged ("Access denied, Needs MAINT PIN"); a clear with the lid open is refused and logged.
- The wrong-PIN lockout now also applies during a tamper or fault.
- The LCD tells the user what is needed ("MAINT PIN + #").

**Docs**

- README test script extended: clear at the module, operator refused, clear from the gateway.

## v4

*2026-10-08* · sensor module firmware for two identical modules (A, B) · worked on as v5 (SensorModule)

Start of the new architecture: two identical sensor modules (A and B, one sketch with MODULE_ID) that each detect, decide and sound on their own, and a separate gateway control box (next step). This version is the sensor module firmware.

**Sensor modules A and B**

- WALL PIR along the wall towards the other module, SIDE PIR along its own side wall; tamper switch, buzzer, 3 LEDs, LCD, keypad.
- P2 when, within 20 s: both WALL PIRs, or a module's WALL + SIDE PIRs, or one PIR 3 times. Both modules sound.
- Arm, disarm and maintenance only by signed commands from the gateway; the module still checks the role and its own state (never arms with the lid open or a PIR stuck).
- Any valid PIN on the module keypad silences that module; 3 wrong PINs lock the keypad (60, 120, 240 s), and the lockout survives a restart.
- Keeps detecting and sounding if the gateway or the other module goes offline.

**Radio security (protocol v3)**

- A separate key for each link; HMAC-SHA256 on every packet; ESP-NOW encryption per link once the MAC addresses are set; MAC allow-list.
- Boot counter and sequence numbers: replays, stale commands after a restart and old HELLOs are refused.

**Tests and simulation**

- PC protocol tests (signatures per link, tampering in transit, replay, stale commands, key derivation).
- Wokwi project for one sensor module with bench commands.

## v3.1

*2026-10-07* · Wokwi simulation of the controller and gateway, bench tools · worked on as Pinnacle13_Firmware_v4 + Wokwi

Same firmware as v3, plus a simulator mode so the whole system can be shown in Wokwi, and two bench tools for the hardware build.

**Simulator mode (WOKWI_SIM 1)**

- Wokwi can't do ESP-NOW between two simulations, so the same signed packets travel over MQTT on a public broker instead (simulator only; real boards ignore it).
- Shorter PIR warm-up (5 s) and a longer gateway timeout in the simulator; the buzzer uses tone().

**Wokwi projects (Wokwi/)**

- Board 1 controller and the gateway, each with diagram.json, libraries and a single-file sketch.

**Bench tools**

- Tools/RFID_Card_Reader: prints each card's UID ready to paste into secrets.h (ESP32 or Arduino Uno).
- docs/diagrams/PIR_breadboard: breadboard wiring for testing the PIRs.

## v3

*2026-10-06* · one controller board with both PIRs + listen-only gateway to the PC · worked on as Pinnacle13_Firmware_v4 (first)

Merges the teammate's draft (v2) with the two-node firmware (v1). Board 1 now holds both PIRs, the tamper switch, RFID, keypad, LCD, LEDs, buzzer and all the logic. A second ESP32 is a gateway on the PC's USB that only carries signed copies of the log and status to the PC.

**From the teammate's draft (v2)**

- Code split into parts (ZoneSensor, TamperSensor, Display, RfidReader, GatewayLink).
- Full state saved on every change: INTRUSION and TAMPER survive a power cut.
- Time-based tamper debounce; an open lid and a cut wire both alarm; can't arm with the lid open.
- Distinct buzzer patterns per alarm; an unknown state fails closed; PIN masked and never printed.

**Kept from v1**

- Card + PIN for every login, 2 roles; P1 warning vs P2 confirmed (both sides, or 3 hits on one side).
- PIR warm-up, stuck and unplugged detection; lockout 60/120/240 s that survives a reboot.
- Maintenance mode with a 5-minute timeout; RECOVERY self-check before re-arming; salted PIN hashes; event log in flash.

**New in v3**

- Gateway to PC link with signed status and log lines; log lines numbered so lost packets show as GAP.
- pc_logger.py adds real date and time to the log.
- The gateway only listens: the PC can't control the alarm.
- Draft problems fixed: keypad off input-only pins, PIR pull-ups, RFID glitch can no longer arm, tamper watched in every state, watchdog applied.

## v2

*2026-10-06* · teammate's single-board draft (draft2.ino) · worked on as draft2.ino

A teammate's single-board version, written as separate classes. Several of its ideas were merged into v3.

**Design**

- One ESP32 (30-pin) with PIR, tamper contact, RC522 RFID, 4x4 keypad, LCD, green/red LEDs, buzzer.
- Code split into classes: SecurityStorage, Display, TamperSensor, RfidReader, AlarmOutputs, PinInput.
- States DISARMED, ARMED, ALARM, TAMPER_ALARM, FAULT; ARMED and the alarm states survive a power cut.

**Security rules**

- PIN arms only from DISARMED; an open enclosure can't be armed.
- Clearing an alarm needs an authorised RFID card, then the PIN within 30 s: PIN-only or card-only clearing is impossible.
- Time-based tamper debounce; RC522 RST tied to 3.3 V; watchdog; PIN masked on the LCD.

**Demo values**

- PIN 1234 and an example card UID are placeholders in the configuration section.

## v1

*2026-10-05* · two-node firmware (main controller + sensor node over ESP-NOW) · worked on as Pinnacle13_Firmware

First firmware. Two ESP32 boards: Node 1 (main controller) and Node 2 (sensor node), linked directly by ESP-NOW, so no router or institutional network is needed. The design documents that led to it are in docs/design.

**Node 1, main controller**

- PIR zone 1, reed-switch tamper on the enclosure lid, RC522 RFID, 4x4 keypad, LCD1602, buzzer, red/green/yellow LEDs.
- Full state machine (DISARMED, ARMED, INTRUSION, TAMPER_FAULT, MAINTENANCE, RECOVERY), card + PIN login with two roles (OPERATOR, MAINTENANCE), alert priorities P0-P3.
- PINs stored as salted SHA-256 hashes; card enrolment mode; event log as CSV in flash (boot number + uptime).

**Node 2, sensor node**

- PIR zone 2 (outer zone), pin reserved for an IR sensor (zone 3); sends authenticated messages to Node 1.

**Detection and security**

- Corroboration: both zones within 20 s = confirmed intrusion (P2); one zone only = warning (P1).
- PIR warm-up (60 s) and stuck-sensor detection; lockout after 3 wrong PINs.
- Heartbeats from Node 2: unplugging it is noticed within 3 s (communication-loss test T09).
- Packets signed with a shared key (HMAC-SHA256, 8 bytes), with boot ID and sequence number against replay.

**Design documents (docs/design)**

- Pseudocode_1_first_draft: the first pseudocode, mapped to tests T01-T12.
- Pseudocode_2_review: hardware gaps and logic issues in the first draft, buy list, pin map, revised pseudocode.
- Pseudocode_3_two_node: the two-node design this firmware implements.
