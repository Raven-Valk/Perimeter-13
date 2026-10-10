# Project 13 server

The program on the server laptop. It keeps the link to the gateway, stores the system's event log, and serves the dashboard.

```
Gateway ──MQTT over TLS, port 8883──> Mosquitto ──localhost──> p13server ──HTTPS, port 8443──> browsers
```

| Folder / file | What |
|---|---|
| `p13server/` | The server (Python 3.11 or newer). `protocol.py` is `link_protocol.h` in Python |
| `web/` | The dashboard page (plain HTML, CSS and JavaScript; fonts included, no internet needed) |
| `scripts/setup.py` | Makes the certificates, broker users and access rules, and the settings |
| `scripts/install_linux.sh` | Installs everything on Debian / Ubuntu as services |
| `tools/gateway_emulator.py` | Pretends to be the gateway over the real broker, for testing without hardware |
| `tests/` | `python3 -m unittest tests.test_server` |

## Try it without hardware

```sh
pip install -r requirements.txt
python3 -m p13server --emulate
```

Open http://127.0.0.1:8080 and sign in as `operator` / `operator123` or `admin` / `admin123` (the demo accounts in `Gateway/secrets.h`). An emulated gateway and four modules run inside the server. The dashboard shows a striped banner the whole time, so nobody mistakes it for the real system. Every 45 s or so something moves along a wall; arm the system to see warnings, alarms and escalation. Now and then a radio link "fails" for a minute and is relayed.

For a faster demo: `P13_EMULATOR_INTERVAL=8 P13_EMULATOR_CONFIRM=1 python3 -m p13server --emulate` makes every trigger lead to a confirmed intrusion, every 8 seconds. `P13_EMULATOR_LINK_FAULTS` (0 to 1, default 0.25) sets how often a link fails.

## The dashboard

The **☰ menu** (top left) opens a side drawer:

- **Overview:** the plan of the site — the four modules at the corners and the gateway in the middle, the PIR curtains on the **outside** of walls A–D, A–B and B–C, the 10 radio links (solid = direct, dashed amber = relayed, with the way round drawn through the relay), and which buzzers are sounding. Next to it, the controls.
- **Log:** the event log with filters and search, the units table (gateway + A–D), and link integrity (each of the 10 links, the server link, refused packets, the server's own audit).
- **Alerts on this device:** browser **notifications** for intrusions and (optionally) warnings, and a loud **siren** on an intrusion that keeps sounding until the alarm is acknowledged or you press **Silence**. A new zone joining the alarm sounds it again. Settings are kept in this browser only. Notifications need the HTTPS address (or 127.0.0.1); browsers only play sound after you've clicked once on the page.
- **Account:** who is signed in, and Sign out.

The sentence at the top says what is going on and stays on both views. During an alarm a red dot shows on the ☰ button and on "Log".

**Relay test** (maintenance role, Overview → Test the relays): pick a link and a time. That direct link is treated as broken; within a few seconds the plan shows its packets going round through another board, and the log records it. "End test" puts it back at once.

## Install on the server laptop (Linux)

From this folder, as your normal user:

```sh
sh scripts/install_linux.sh --ip 192.168.137.1
```

`--ip` is the laptop's address on the network the gateway joins: `192.168.137.1` for a Windows-style hotspot, or the router's address for the laptop (give it a fixed one in the router). Repeat `--ip` for more than one.

The script:
1. Installs Mosquitto and a Python environment.
2. Runs `setup.py`.
3. Installs the broker config in `/etc/mosquitto/conf.d/p13.conf`.
4. Starts `p13server` as a service that restarts by itself and starts at boot.
5. Opens ports 8883 and 8443 if the `ufw` firewall is on.

Then:
1. **Gateway:** open `gateway_secrets.txt`. Paste it into `Gateway/secrets.h`, replacing the lines with the same names. Fill in `WIFI_SSID` and `WIFI_PASSWORD`, then upload the gateway.
2. **Dashboard:** open `https://<laptop address>:8443`. The browser warns once because the certificate comes from your own CA. To stop the warning, install `certs/ca.crt` as a trusted authority on the computers that open the dashboard.

Logs: `journalctl -u p13server -f` and `journalctl -u mosquitto -f`.

### On Windows instead

1. **Install the software:** Python 3.11+ and Mosquitto (from mosquitto.org).
2. **Run the setup** in this folder:
   ```
   pip install -r requirements.txt
   python scripts\setup.py --ip 192.168.137.1 --mosquitto-dir "C:/Program Files/mosquitto/p13"
   ```
3. **Set up Mosquitto:**
   - Copy `config\mosquitto\passwd`, `acl`, `server.crt` and `server.key` into `C:\Program Files\mosquitto\p13\`.
   - Replace Mosquitto's `mosquitto.conf` with `config\mosquitto\p13.conf`.
   - Restart the Mosquitto service.
4. **Start the server:** `python -m p13server`. Allow ports 8883 and 8443 in Windows Firewall.

## Changing things later

| You want to | Do this |
|---|---|
| The laptop's address changed | Run `scripts/setup.py --ip <new address>` again: it re-issues the server certificate and keeps everything else. Restart Mosquitto and p13server. On the gateway, change only `SERVER_HOST`. |
| Use the Wokwi simulator | Set `mode = "wokwi"` in `config/p13server.toml` (or run `python3 -m p13server --mode wokwi`), and run the Wokwi gateway. It goes through the public broker: signed, but anyone can read it. |
| Add or change a dashboard account | Accounts live on the gateway: `PC_USERS` in `Gateway/secrets.h`. The hash command is in the comment above it. |
| New keys after a demo | `setup.py --new-key --new-passwords` (and `--new-ca` if `ca.key` may have leaked), then paste the new `gateway_secrets.txt` into the gateway. |

## How sign-in and control work

- **Sign-in:** you type your user name and password into the dashboard. The server turns the password into the same slow hash the gateway stores (PBKDF2, 100,000 rounds) and answers the gateway's random challenge with it. The password is never sent and never stored.
- **The gateway decides:** it checks the answer and, if it's right, gives this dashboard a session with your role (operator or maintenance). Wrong answers count toward the gateway's own lockout: 3 tries, then 60 s, 120 s, and so on.
- **Control:** one person at a time has control, meaning they can send commands. Control ends after 5 minutes without a command, after 30 minutes in total, or when someone else signs in. You stay signed in to watch. To send commands again, enter your password under "Take control".
- **Every command is checked twice more:** the gateway checks the role, and each module checks its role and state again. For example, a module never arms with its lid open.
- **Viewing while the gateway is down:** someone who has signed in before can still sign in to view. The server keeps a salted hash of the gateway's password hash for this. It can't be used to log in to the gateway, and view-only sessions can't send commands.
- **Browser protections:**
  - The session cookie is `HttpOnly`, `Secure` and `SameSite=Strict`, and requests from other sites are refused.
  - The page allows no outside scripts, styles or frames (Content Security Policy).
  - Sign-in attempts are limited to 5 a minute per address.

## The event log

The gateway numbers every line: its own and the four modules'. The server stores each line once, in `data/p13.db` (SQLite).

- **Missing lines:** if a number is missing for 2 seconds, the server asks the gateway to send it again. After 3 tries the range is recorded as lost.
- **Server outages:** after the server was down, it fetches up to 3,000 missed lines.
- **Gateway flash erased:** if the gateway's numbering ever goes back, the server starts a new log series instead of mixing old and new lines.
- **Export:** "Export CSV" downloads the whole log.

The **Server audit** list shows what happened on the server itself: sign-ins (with the address they came from), commands, control changes, link changes, and refused packets (at most one line per kind every 30 seconds; the counters show all of them).

## Troubleshooting

| The dashboard says | Check |
|---|---|
| The server can't reach its message broker | `systemctl status mosquitto`. On Linux the broker must be able to read `/etc/mosquitto/p13/` (the install script sets this). |
| No contact with the gateway | The gateway's LCD: "PC:N" means it has no server link. Its USB log (`LOG,...` lines) says why: Wi-Fi not found, broker refused the password, TLS check failed (wrong CA, or `SERVER_NAME` not `p13-server`), or server not reachable (`SERVER_HOST`, firewall). |
| Refused packets: bad signature | `KEY_GW_SERVER` in `Gateway/secrets.h` differs from `[gateway] key` in `config/p13server.toml`. |
| A module isn't reporting | Its LCD shows the mesh ("GW DOWN 2/4" = no gateway, 2 of its 4 links up). After a channel change it takes up to about 10 s to find the gateway again. If it is out of range of the gateway, it should still report through another module. |
| A link stays "relayed" | Normal if a wall or distance is in the way. Move the boards, or the antenna ends of the ESP32s, to face each other. |
