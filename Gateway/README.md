# Project 13: Gateway firmware (v5)

The control box: an ESP32 DevKit V1 (30-pin) on a 5 V adapter, with the RFID reader, 4×4 keypad, 16×2 LCD, a tamper switch and 3 LEDs (no buzzer). It talks by radio (ESP-NOW) to Module A and Module B, and over Wi-Fi to the server laptop that runs the dashboard.

| File | What it is |
|---|---|
| `Gateway.ino` | the gateway firmware |
| `link_protocol.h` | the shared radio protocol. **Must be identical** to the one in `SensorModule/` |
| `secrets.h` | link keys, MACs, card UIDs + PIN hashes, dashboard accounts, Wi-Fi and server settings. **Never upload it to GitHub** |

Libraries: **MFRC522** (GithubCommunity), **Keypad** (Mark Stanley, Alexander Brevig), **LiquidCrystal I2C** (Frank de Brabander). The server link uses ESP-MQTT, which comes with the ESP32 core (3.x). Board: **ESP32 Dev Module**.

## What it does

**At the gateway: card + PIN, then a menu.** Tap a card, type the PIN, press **#**. The LCD then shows a menu:

| Key | Action | Who |
|---|---|---|
| **1** | Arm both modules | operator or maintenance |
| **2** | Disarm both modules | operator or maintenance |
| **3** | Acknowledge an intrusion on both | operator or maintenance |
| **4** | Maintenance mode (300 s) → then **1** = A, **2** = B, **3** = both | maintenance only |
| **5** | Clear a tamper or fault → **1** A, **2** B, **3** both, **0** the gateway itself | maintenance only |
| **6** | End maintenance → 1 / 2 / 3 | operator or maintenance |
| **\*** | log out | |

- **One command per card tap.** The menu closes after 20 s without a key.
- **3 wrong card/PIN tries lock the keypad.** The lock lasts 60 s, then 120 s, 240 s, and so on up to 960 s, and survives a restart.
- **There is no PIN-only login here.** If the RFID reader fails, use the dashboard.

**Each command goes to the modules, and their answers come back to the LCD.** For example "ARM OK, A:OK B:OK", or "ARM FAILED, A:OK B:Lid open". If a module's reply is lost, the gateway sends the command again; the module recognises the repeat and doesn't run it twice. Each module still checks the role and its own state, so the gateway can't make a module arm with its lid open.

**From the dashboard (the server laptop):**
- **Sign-in:** user name and password, checked here by the gateway. The password never reaches the gateway; the server proves it knows it by answering a random challenge.
- **Lockout:** 3 wrong tries lock dashboard sign-ins, the same way as the keypad. That lock is separate from the keypad's.
- **Sessions:** one at a time. A session ends after 5 min idle, after 30 min in total, when someone else signs in, or if the server link drops.
- **Same rules as the keypad:** roles, the commands above, and the same checks.
- **The dashboard has priority:** its command cancels a half-typed keypad entry. If a keypad command is already being sent, the dashboard's command runs straight after it.

Demo dashboard accounts (change them in `secrets.h`):

| User | Password | Role |
|---|---|---|
| `operator` | `operator123` | OPERATOR |
| `admin` | `admin123` | MAINTENANCE |

**Wi-Fi and the server link:**
- **Joining:** at power-on the gateway joins the Wi-Fi network in `secrets.h` (laptop hotspot or router, 2.4 GHz) and the LCD shows the channel and its IP address for a few seconds.
- **The connection:** it connects to the broker on the server laptop with MQTT inside TLS, and checks the server's certificate against the CA in `secrets.h` and the name `p13-server`. It never connects to anything else.
- **Radio channel:** ESP-NOW runs on the Wi-Fi network's channel. The modules find that channel by themselves (see `SensorModule/README.md`).
- **If the Wi-Fi network is gone:** the gateway stays on the last channel, so the modules keep their link, and tries again after 30 s, 60 s, 2 min, 4 min, then every 5 min. Every attempt and its outcome goes into the log.
- **What keeps working without Wi-Fi:** the keypad, the card reader and the module links. The dashboard catches up on the log when the link is back.

**Gateway tamper:** opening the gateway's lid raises **P3** (red LED flashing, "!! GW TAMPER !!"). The gateway then **refuses every command** until a MAINTENANCE card + PIN (or a dashboard maintenance user) clears it, with the lid shut. A restart doesn't clear it.

**One event log for the whole system:**
- **What goes in:** every event from the gateway, Module A and Module B, numbered in one sequence (`gw_no`). It's kept in the gateway's flash (~5,000 lines) and printed on USB as `LOG,…`.
- **Missing lines:** if the radio drops some module lines, the gateway notices the gap and asks that module to send them again. No line is stored twice. Lines that can't be recovered are logged as `LOST`.
- **For the server:** the gateway sends every line, and the server asks for any it missed.

## LEDs and LCD

| LED | Meaning |
|---|---|
| green steady / blinking | system armed (both modules) / not armed |
| yellow steady | warning (P1), or a module in maintenance or recovery |
| yellow blinking | a module is not connected |
| red steady | intrusion (P2) somewhere |
| red fast blink | tamper or fault (P3), the gateway's own tamper, or an armed module that went silent |

The idle LCD shows, for example:

```
SYS ARMED P0
A:ARM B:ARM PC:Y
```

| Module code | Meaning |
|---|---|
| `DIS` | disarmed |
| `ARM` | armed |
| `ALM` | intrusion |
| `TMP` | tamper |
| `MNT` | maintenance |
| `REC` | recovery |
| `BT` | starting |
| `--` | not connected |

`PC:Y` means the server is connected, `PC:L` means someone has control from the dashboard, and `PC:N` means no server link.

## Pin map: ESP32 DevKit V1, 30-pin

The RFID reader, keypad and LCD use the same pins as Board 1 before. The tamper switch is on RX2 and uses the ESP32's **built-in pull-up**, so it needs **no resistor**. The LEDs are on D2, D15 and TX2. D2 and D15 are boot pins; an LED with its resistor to GND is safe there, and the yellow LED may blink once at power-on.

| Part | Part pin | ESP32 pin (label) | Notes |
|---|---|---|---|
| LCD 16×2 (I2C) | SDA / SCL | **D21 / D22** | VCC to the 5 V rail |
| RC522 RFID | SDA (SS) | **D5** | **3.3 V only:** never connect it to 5 V |
| | SCK | **D18** | |
| | MOSI | **D23** | |
| | MISO | **D19** | |
| | RST | 3.3 V rail | |
| | 3.3V / GND | 3.3 V rail / GND | |
| Keypad 4×4 | pins 1–4 (rows) | **D13, D14, D27, D26** | pin 1 is the leftmost with the keys facing you |
| | pins 5–8 (columns) | **D25, D33, D32, D4** | |
| Tamper reed switch | wire 1 / wire 2 | **RX2 (GPIO 16)** / GND | no resistor |
| Green LED | anode (long leg) | **D2** | through 220–330 Ω (2.2 kΩ works, but dim). The blue on-board LED lights with it |
| Yellow LED | anode | **D15** | same |
| Red LED | anode | **TX2 (GPIO 17)** | same |

**Power rails:**
- **VIN** goes to the top + rail (5 V when powered by the USB adapter), and **GND** to the top − rail.
- **3V3** goes to the bottom + rail, and **GND** to the bottom − rail.
- Join the two − rails.

## Setting up

1. Wire it as above and upload. Serial Monitor (115200) prints `Gateway, MAC …`.
2. **Cards:**
   - Set `#define ENROLL_MODE 1`, upload, and tap each card. Serial Monitor prints `ENROLL card UID: 0x.., 0x.., …`.
   - Put the UIDs into `USERS` in `secrets.h` (the `#else` part). Set `ENROLL_MODE 0` and upload again.
3. **MACs:**
   - Put all the board MACs into `secrets.h` on **every** board: `MAC_MOD_A`, `MAC_MOD_B` and `MAC_GATEWAY`.
   - Until then, the radio links stay **OFF** and the log says "link OFF".
   - For a quick first test you can set `#define ALLOW_UNENCRYPTED 1`. Set it back to 0 for the demo.
4. **Keys:**
   - `KEY_A_GW` and `KEY_B_GW` here must be the same bytes as `KEY_MOD_GW` in each module's `secrets.h`. The demo files already match.
   - If you make new keys, change both sides.
5. **Server link:** install the server (`Server/README.md`). Its setup writes `gateway_secrets.txt`: paste that into `secrets.h` (it sets `KEY_GW_SERVER`, the broker password, `SITE_ID`, `SERVER_HOST` and `SERVER_CA_PEM`). Fill in `WIFI_SSID` and `WIFI_PASSWORD` yourself, then upload. Serial Monitor shows "Wi-Fi joined ..." and then "Server link connected (TLS)".
6. **Dashboard passwords:** make a new hash with the one-line command in `secrets.h`. Use long passwords for the real demo.

## Test script (gateway + both modules)

| Test | Do | Expect |
|---|---|---|
| Links | power all three | gateway LCD `A:DIS B:DIS PC:N`; modules show "All OK" (or "GW link DOWN" until the gateway is up) |
| T01 Arm | operator card, `1234#`, **1** | "ARM OK, A:OK B:OK"; both modules ARMED; green LED steady |
| T02 Wrong PIN | operator card, `1111#` | "Access denied, 2 tries left" |
| T03 Lockout | 3 wrong tries | "LOCKED 60 s"; the keypad ignores input; the alarm keeps working |
| T05 Intrusion | motion on A's WALL, then B's WALL, within 20 s | both modules sound; gateway "!! INTRUSION !!", red LED |
| Acknowledge | operator card, `1234#`, **3** | "ACK OK"; both modules go RECOVERY, then ARMED |
| Role check | operator card, `1234#`, **4** | "Access denied, Needs MAINT card" (logged) |
| T11 Maintenance | maintenance card, `9876#`, **4**, **1** | Module A "MAINT 300s"; gateway `A:MNT`. End with **6**, **1** |
| T07 Module tamper | open Module A's lid | gateway "!! MOD TAMPER !!", `A:TMP` |
| Clear it | shut the lid; maintenance card, `9876#`, **5**, **1** | "CLEAR OK"; A goes RECOVERY, then ARMED |
| Gateway tamper | open the gateway's lid | "!! GW TAMPER !!"; any card + menu is refused |
| Clear it | shut the lid; maintenance card, `9876#` | "CLEAR OK" (no menu: it clears straight away) |
| T09 Module lost | switch Module B off while armed | `B:--`; red blinks; log "Module B LOST while armed" (P3) |
| Log recovery | switch the gateway off; make a few events on A; switch it back on | within a few seconds those lines appear in the gateway's log (`LOG,…` on USB) |
| T08 Fake board | change one byte of `KEY_A_GW` in the gateway, upload | log "Module A: bad signature (spoofed?) REJECTED"; `A:--` |
| Server link | power on with Wi-Fi + server set | LCD "Wi-Fi ch N" + IP, then `PC:Y`; dashboard "Gateway link: Up" |
| Dashboard command | sign in as `operator`, press Arm | dashboard "Armed. A: OK, B: OK"; gateway LCD "Web ARM OK" |
| Server gone | stop the server, wait 10 s, start it | `PC:N`, then `PC:Y`; the dashboard's log has no gaps |
| Wi-Fi gone | switch the hotspot off | log "Wi-Fi lost: rejoining", "... not found: retry in 30 s"; modules stay linked |
| Wrong server | in `secrets.h` set `SERVER_NAME` to `"someone-else"`, upload | log "Server link: TLS check failed"; never connects |

## Log format

```
gw_no,log_no,boot,uptime_ms,unix_time,module,priority,state,type,event,zone,user,result
2051,1042,7,183220,1760000000,A,P2,ARMED,ALERT,Intrusion: B-WALL + A-WALL,A-WALL,-,-
2052,2052,3,9921,1760000001,G,P2,READY,CMD,ACK_ALARM: A:OK B:OK,-,Operator1@GW,OK
```

- `module` is A, B, or G (the gateway).
- For the gateway's own lines, `log_no` equals `gw_no`.
- `unix_time` is 0 until the server has sent the real time.

## Known limits (for your report)

- **Keys, PIN hashes and password hashes in flash:** anyone who has the gateway in hand can read them out. Opening the lid raises P3. ESP32 flash encryption fixes this, but it can't be undone, so leave it off the demo boards.
- **Radio jamming:** it can't be prevented, but it is detected ("LOST while armed", P3). The modules keep alarming on their own.
- **Dashboard passwords:** they're protected by a slow hash, but a weak password can still be guessed offline from a stolen gateway. Use long ones.
- **Wi-Fi password and broker password in flash:** the same applies. Someone holding the gateway can read them, but not the server's private keys (the gateway only holds the CA certificate).
- **While the gateway rejoins Wi-Fi** (a few seconds per attempt) its radio scans other channels, so a module link can drop briefly. Alarms keep working on the modules.
- **`ALLOW_UNENCRYPTED 1` and `ENROLL_MODE 1` are for setup only.** Both are logged as warnings at every boot.
