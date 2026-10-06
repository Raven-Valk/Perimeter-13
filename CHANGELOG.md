# Version history

Pinnacle Project 13: Secure Perimeter Intrusion Detection (ESP32).

Each version is one commit with a tag of the same name. To see the files of a version on GitHub, pick its tag in the branch menu; on a PC: `git checkout <tag>`.

The version numbers here are the final ones. During development some versions had other working names (shown in the last column); those names still appear inside a few files, such as folder names, the `FIRMWARE_VERSION` string and MQTT topics. "Protocol v2/v3/v4" in the docs is the radio packet format, numbered on its own.

| Version | Date | What changed | Working name |
|---|---|---|---|
| [`v2`](#v2) | 2026-10-06 | teammate's single-board draft (draft2.ino) | draft2.ino |
| [`v1`](#v1) | 2026-10-05 | two-node firmware (main controller + sensor node over ESP-NOW) | Pinnacle13_Firmware |

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
