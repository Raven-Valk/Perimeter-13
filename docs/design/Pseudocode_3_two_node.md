# Secure Perimeter Intrusion Detection — Pseudocode v3 (two-node design)

## Design summary

| | **Node 1 — Main controller** (ESP32 #1) | **Node 2 — Sensor node** (ESP32 #2) |
|---|---|---|
| Sensors | PIR → Zone 1 (inner zone) | PIR → Zone 2 (outer zone) · free pin reserved for IR → Zone 3 later |
| Tamper | MAGREED reed switch on the controller enclosure lid | none for now (residual risk; see notes) |
| Operator I/O | RC522 RFID, 4×4 keypad, LCD1602 | on-board LED only (heartbeat blink) |
| Alarm outputs | Buzzer + red / green / yellow LEDs | — |
| Runs | Full state machine, authentication, alert priority, event log | Reads its sensors, sends authenticated messages to Node 1 |
| Breadboard | 830-point (or two 400s) | the existing 400-point board |
| Power | MB102 | USB (power bank or laptop) |

- **Radio link:** ESP-NOW, which is ESP32-to-ESP32 direct and needs no Wi-Fi router. That keeps the project off institutional networks (spec §29).
- **No relay.**
- **No physical maintenance switch:** a MAINTENANCE RFID card + PIN replaces it.
- **Corroboration:** a person crossing from the outer zone (Node 2) to the inner zone (Node 1) within 15 s = confirmed intrusion (P2). Only one zone = warning (P1).
- **Communication loss (T09):** now a real test. Unplug Node 2 and Node 1 notices missing heartbeats within 3 s.

### What to add to the component list
- Second **ESP32** and second **HC-SR501 PIR**
- **LEDs**: red, green, yellow + 3 × 220 Ω resistors
- **Male-to-male jumpers** (the keypad ribbon is a female socket)
- **10 kΩ resistor** ×1 (pull-up for Node 1's PIR on an input-only pin)
- **830-point breadboard** for Node 1 (RFID + keypad + LCD + LEDs don't fit on 400)
- **USB cable / power bank** for Node 2
- Later: IR sensor(s) for Node 2

### Wiring notes
- **RC522 → 3.3 V only.**
- **Tamper reed switch:** one side to a GPIO with `INPUT_PULLUP`, other side to GND. Lid closed (magnet near) = LOW. Lid open **or wire cut** = HIGH. Both count as tamper, so no extra resistors are needed. Confirm your MAGREED is "closed when magnet is near" with a multimeter first.
- **PIR:** set jumper to **L (single trigger)** and the time pot to minimum (~3 s). Allow **60 s warm-up**. Use a pull-up on the PIR input, so an unplugged PIR reads HIGH constantly → detected as "stuck". Test this in Week 3: unplug the PIR and check the pin reads HIGH.
- **LCD I2C backpack on 5 V** pulls SDA/SCL to 5 V. Either use a level shifter, or try powering it from 3.3 V.
- Tie all grounds together on Node 1.

### Node 1 pin map (30-pin ESP32 DevKit V1 — check against your board)

| Function | GPIO |
|---|---|
| LCD SDA / SCL | 21 / 22 |
| RC522 SCK / MISO / MOSI / SS / RST | 18 / 19 / 23 / 5 / 4 |
| Keypad rows / cols | 13, 14, 27, 26 / 25, 33, 32, 16 |
| Buzzer | 17 |
| LED green / red / yellow | 2 / 15 / 12 (12 must be LOW at boot — LED + resistor to GND is fine) |
| PIR (Zone 1) | 35 + external 10 kΩ pull-up to 3.3 V |
| Tamper reed | 34 + external 10 kΩ pull-up (34–39 have no internal pull-ups) — or swap with a free normal GPIO |

So that's **2 × 10 kΩ** in total. Node 2 needs very few pins: PIR on GPIO 27 with `INPUT_PULLUP`, IR reserved on GPIO 26, and the on-board LED on GPIO 2.

---

## Pseudocode — Node 2 (sensor node)

```python
# =====================================================================
# NODE 2 — SENSOR NODE
# Reads PIR (and IR later). Sends authenticated messages to Node 1.
# =====================================================================
NODE_ID          = 2
MAIN_MAC         = <Node 1 MAC address>      # from config.h, not committed to Git
SHARED_KEY       = <32-byte secret>          # from config.h, not committed to Git
HEARTBEAT_MS     = 1000
PIR_WARMUP_S     = 60
PIR_MAX_HIGH_S   = 30

SENSORS = [ {zone: 2, type: "PIR", pin: 27, enabled: True},
            {zone: 3, type: "IR",  pin: 26, enabled: False} ]   # flip to True when IR is added

def setup():
    pinMode(PIR pin, INPUT_PULLUP)
    init_espnow(); add_peer(MAIN_MAC)
    start_watchdog(5 s)
    boot_id = random_32bit()                  # new every boot (replay protection)
    seq = 0
    send("HELLO", {reset_reason: esp_reset_reason()})   # Node 1 logs that Node 2 rebooted

def loop():
    feed_watchdog()
    for s in SENSORS where s.enabled:
        value  = digital_read(s.pin)
        health = check_health(s, value)       # OK | WARMUP | STUCK_HIGH
        if rising_edge(s) and health == OK:
            send("EVENT", {zone: s.zone, type: s.type})          # immediate
    if every(HEARTBEAT_MS):
        send("HEARTBEAT", {sensors: [(zone, value, health) for each enabled sensor]})
        blink_onboard_led()                   # visible "alive" sign for the demo

def check_health(s, value):
    if uptime_s() < PIR_WARMUP_S and s.type == "PIR": return "WARMUP"
    if value == HIGH and high_duration(s) > PIR_MAX_HIGH_S: return "STUCK_HIGH"
    return "OK"

def send(msg_type, data):
    seq = seq + 1
    body = [NODE_ID, boot_id, seq, msg_type, data]
    mac  = hmac_sha256(SHARED_KEY, body)[0:8]     # first 8 bytes is enough here
    espnow_send(MAIN_MAC, body + mac)
```

---

## Pseudocode — Node 1 (main controller)

```python
# =====================================================================
# NODE 1 — MAIN CONTROLLER
# =====================================================================

# ---------- CONSTANTS (finalise at Design Review 1) ----------
LOOP_MS             = 100
PIR_WARMUP_S        = 60
PIR_MAX_HIGH_S      = 30
CORROBORATION_S     = 15
NODE_TIMEOUT_S      = 3          # no heartbeat for 3 s = node offline
MAX_ATTEMPTS        = 3
BASE_LOCKOUT_S      = 60         # 60, 120, 240 ...
PIN_TIMEOUT_S       = 20
MAINT_TIMEOUT_S     = 300
LOG_MAX_LINES       = 500

# ---------- GLOBAL STATE ----------
GLOBAL state         = "BOOT"
GLOBAL session_role  = "NONE"          # NONE | OPERATOR | MAINTENANCE
GLOBAL zones = {
   1: {source: "LOCAL",  type: "PIR", health: OK, triggered: False},
   2: {source: "NODE2",  type: "PIR", health: OK, triggered: False},
   # 3: {source: "NODE2", type: "IR", ...}   <- add when IR is fitted
}
GLOBAL node2 = {last_heard: 0, boot_id: None, last_seq: 0, online: False}
GLOBAL window_until = 0;  window_zone = None
GLOBAL maint_until  = 0
GLOBAL rfid_online  = True;  lcd_online = True
# Persisted in NVS (survive power loss):
NVS failed_attempts, lockout_level, lockout_remaining_s, was_armed, boot_number

ALLOWED = {
  "BOOT":         ["WAIT_AUTH", "MONITORING", "TAMPER_FAULT"],
  "WAIT_AUTH":    ["MONITORING", "TAMPER_FAULT"],
  "MONITORING":   ["INTRUSION", "TAMPER_FAULT", "MAINTENANCE", "WAIT_AUTH"],
  "INTRUSION":    ["RECOVERY", "TAMPER_FAULT"],
  "TAMPER_FAULT": ["RECOVERY"],
  "MAINTENANCE":  ["RECOVERY", "TAMPER_FAULT"],
  "RECOVERY":     ["MONITORING", "WAIT_AUTH", "TAMPER_FAULT"],
}

def go_to(new_state, reason):
    if new_state not in ALLOWED[state]:
        log_event("STATE", "Invalid " + state + "->" + new_state, result="REJECTED")
        return
    log_event("STATE", state + " -> " + new_state + " (" + reason + ")")
    state = new_state
    on_enter(new_state)


# =====================================================================
# 1. SETUP
# =====================================================================
def setup():
    init_pins(); init_lcd(); init_rfid(); init_littlefs(); init_espnow()
    start_watchdog(5 s)
    boot_number += 1
    log_event("SYSTEM", "Boot #" + boot_number + " reason=" + esp_reset_reason())   # T10
    boot_started = now()
    state = "BOOT"


# =====================================================================
# 2. MAIN LOOP
# =====================================================================
def loop():
    feed_watchdog()
    process_radio_messages()       # from Node 2 (queued by ESP-NOW callback)
    check_node_timeout()           # T09
    read_local_pir()               # Zone 1 + health
    check_rfid_lcd_health()        # every 10 s
    tick_lockout()                 # blocks keypad/RFID only, never the sensors

    # Tamper is checked in EVERY state
    if tamper_open():              # lid open OR wire cut
        if state == "MAINTENANCE":
            log_once("TAMPER", "Lid opened during maintenance", result="ALLOWED")
        elif state not in ["TAMPER_FAULT", "BOOT"]:
            go_to("TAMPER_FAULT", "Enclosure tamper")          # T07

    if   state == "BOOT":         handle_boot()
    elif state == "WAIT_AUTH":    handle_wait_auth()
    elif state == "MONITORING":   handle_monitoring()
    elif state == "INTRUSION":    handle_intrusion()
    elif state == "TAMPER_FAULT": handle_tamper_fault()
    elif state == "MAINTENANCE":  handle_maintenance()
    elif state == "RECOVERY":     handle_recovery()

    update_outputs(evaluate_alert_priority())
    wait(LOOP_MS)


# =====================================================================
# 3. RADIO — messages from Node 2  (T08, T09, integrity)
# =====================================================================
def process_radio_messages():
    for msg in radio_queue:
        if not well_formed(msg):
            log_event("COMM", "Malformed message", result="REJECTED"); continue      # T08
        if msg.node_id != 2:
            log_event("COMM", "Unknown node", result="REJECTED"); continue
        if hmac_sha256(SHARED_KEY, msg.body)[0:8] != msg.mac:
            log_event("COMM", "Bad signature (spoof?)", result="REJECTED"); continue

        if msg.type == "HELLO":
            node2.boot_id = msg.boot_id;  node2.last_seq = msg.seq
            log_event("COMM", "Node 2 booted, reason=" + msg.reset_reason)
        elif msg.boot_id != node2.boot_id or msg.seq <= node2.last_seq:
            log_event("COMM", "Replayed/old message", result="REJECTED"); continue
        node2.last_seq   = msg.seq
        node2.last_heard = now()
        if not node2.online:
            node2.online = True;  log_event("COMM", "Node 2 online")

        if msg.type == "HEARTBEAT":
            for (zone, value, health) in msg.sensors:
                zones[zone].health    = "OK" if health in ["OK", "WARMUP"] else health
                zones[zone].triggered = (value == HIGH and health == "OK")
        elif msg.type == "EVENT":
            zones[msg.zone].event_pending = True        # used by handle_monitoring

def check_node_timeout():
    if node2.online and seconds_since(node2.last_heard) > NODE_TIMEOUT_S:
        node2.online = False
        for z in zones where z.source == "NODE2":
            z.health = "OFFLINE"
        log_event("COMM", "Node 2 lost (no heartbeat " + NODE_TIMEOUT_S + "s)")       # T09


# =====================================================================
# 4. LOCAL SENSOR HEALTH (Zone 1)  — T06
# =====================================================================
def read_local_pir():
    if seconds_since(boot_started) < PIR_WARMUP_S: return
    v = digital_read(PIR_PIN)                  # pulled up: unplugged = HIGH
    if v == HIGH and high_duration(1) > PIR_MAX_HIGH_S:
        zones[1].health = "STUCK_HIGH"         # stuck or disconnected
    else:
        if zones[1].health == "STUCK_HIGH" and v == LOW: zones[1].health = OK
        if rising_edge(1): zones[1].event_pending = True
        zones[1].triggered = (v == HIGH)


# =====================================================================
# 5. BOOT / SELF-TEST  (T01, T10)
# =====================================================================
def handle_boot():
    left = PIR_WARMUP_S - seconds_since(boot_started)
    if left > 0:
        show("Warming up " + left + "s"); return
    if not self_test():
        state = "TAMPER_FAULT"; log_event("SYSTEM", "Self-test FAILED"); return
    log_event("SYSTEM", "Self-test OK")
    if was_armed:                               # TEAM DECISION: re-arm after power cut
        go_to("MONITORING", "re-armed after power loss")
    else:
        go_to("WAIT_AUTH", "boot complete")

def self_test():
    ok = True
    if tamper_open():          ok = False; log_event("TEST", "Tamper open")
    if zones[1].health != OK:  ok = False; log_event("TEST", "Zone 1 PIR " + zones[1].health)
    if not node2.online:       ok = False; log_event("TEST", "Node 2 not responding")
    elif zones[2].health != OK: ok = False; log_event("TEST", "Zone 2 PIR " + zones[2].health)
    if not rfid_online:        log_event("TEST", "RFID offline - degraded")   # not fatal
    flash_all_leds(); chirp()
    return ok


# =====================================================================
# 6. AUTHENTICATION — card + PIN  (T02, T03, T08)
# =====================================================================
# Non-blocking; returns role once on success, else "NONE".
# Scan card -> type PIN (shown as ****) -> '#' submits, '*' clears.
def authenticate():
    if lockout_remaining_s > 0:
        show("LOCKED " + lockout_remaining_s + "s"); discard_input(); return "NONE"
    if rfid_online and card_waiting():
        pending_uid = read_uid(); pin_buf = ""; pin_started = now(); show("Enter PIN")
    key = keypad_get_key()
    if key is None:
        if pin_started and seconds_since(pin_started) > PIN_TIMEOUT_S:
            reset_entry(); log_event("AUTH", "PIN timeout")
        return "NONE"
    if   key is digit and len(pin_buf) < 6: pin_buf += key; show_masked(pin_buf)
    elif key is digit:                      reject_input("PIN too long")         # T08
    elif key == '*':                        pin_buf = ""
    elif key == '#':                        return check_credentials(pending_uid, pin_buf)
    return "NONE"

def check_credentials(uid, pin):
    if len(pin) < 4: reject_input("PIN too short"); return "NONE"
    if rfid_online:
        user = lookup_by_uid(uid)
        ok   = user and hash(pin) == user.pin_hash
        role = user.role if ok else "NONE"          # card decides OPERATOR or MAINTENANCE
    else:                                            # RFID reader dead -> degraded
        user = lookup_operator_by_pin(hash(pin))
        ok   = user is not None;  role = "OPERATOR" if ok else "NONE"
        log_event("AUTH", "PIN-only login (RFID offline)")
    reset_entry()
    if ok:
        failed_attempts = 0; lockout_level = 0
        log_event("AUTH", "Login", role=role, uid=mask(uid), result="SUCCESS")
        return role
    failed_attempts += 1
    log_event("AUTH", "Login", uid=mask(uid), result="FAIL")                    # T02
    show("Wrong. " + (MAX_ATTEMPTS - failed_attempts) + " left"); chirp()
    if failed_attempts >= MAX_ATTEMPTS:                                          # T03
        lockout_remaining_s = BASE_LOCKOUT_S * 2 ** lockout_level
        lockout_level += 1; failed_attempts = 0
        log_event("AUTH", "Lockout " + lockout_remaining_s + "s")
    return "NONE"
# Store SHA-256 PIN hashes + card UIDs in config.h (not in Git). Log only last 2 bytes of UID.


# =====================================================================
# 7. WAIT_AUTH (disarmed)
# =====================================================================
def handle_wait_auth():
    show("DISARMED  Card+PIN")
    role = authenticate()
    if role != "NONE":
        session_role = role; was_armed = True
        go_to("MONITORING", role + " armed")


# =====================================================================
# 8. MONITORING (armed)  — T01, T04, T05, T06, T09, T11
# =====================================================================
def handle_monitoring():
    for z in zones:
        if z.health not in [OK, "WARMUP"]:
            go_to("TAMPER_FAULT", "Zone " + z.id + " " + z.health)   # STUCK_HIGH / OFFLINE
            return

    for z in zones where z.event_pending:
        z.event_pending = False
        log_event("SENSOR", "Zone " + z.id + " motion", zone=z.id)
        if now() < window_until and z != window_zone:
            log_event("ALERT", "Corroborated Z" + window_zone.id + "+Z" + z.id, priority="P2")
            go_to("INTRUSION", "corroborated"); return                   # T05
        window_until = now() + CORROBORATION_S;  window_zone = z
        chirp(); log_event("ALERT", "Single-zone warning", zone=z.id, priority="P1")  # T04

    role = authenticate()                   # any card+PIN while armed
    if role == "MAINTENANCE":               # maintenance card = the "override switch"
        maint_until = now() + MAINT_TIMEOUT_S
        go_to("MAINTENANCE", "maintenance card")                         # T11
    elif role == "OPERATOR":
        if last_command_key == 'D':         # operator pressed D before scanning = disarm
            was_armed = False; session_role = "NONE"
            go_to("WAIT_AUTH", "operator disarmed")
        else:
            show("Armed. D+card to disarm")
    if keypad_key in ['A', 'B', 'C']:
        reject_input("Key not valid when armed")                         # T08


# =====================================================================
# 9. INTRUSION (P2)
# =====================================================================
def handle_intrusion():
    show("!! INTRUSION !!  Card+PIN")
    role = authenticate()
    if role != "NONE":
        log_event("ALERT", "Intrusion acknowledged", role=role)
        session_role = role
        go_to("RECOVERY", "acknowledged")


# =====================================================================
# 10. TAMPER / FAULT (P3) — T06, T07, T09
# =====================================================================
def handle_tamper_fault():
    show_reason()                           # "TAMPER", "Z1 STUCK", "NODE 2 LOST"
    log_every(60, "FAULT", "Condition persists")
    for z in zones where z.health == OK and z.event_pending:     # keep watching healthy zones
        z.event_pending = False
        log_event("SENSOR", "Zone " + z.id + " motion during FAULT", priority="P3")
    role = authenticate()
    if role == "MAINTENANCE":
        session_role = role
        go_to("RECOVERY", "maintenance cleared")
    elif role == "OPERATOR":
        log_event("FAULT", "Clear by OPERATOR", result="DENIED"); show("Needs MAINTENANCE")


# =====================================================================
# 11. MAINTENANCE (override) — T11
# =====================================================================
def handle_maintenance():
    show("MAINT " + seconds_left(maint_until) + "s 1/2/3/C")
    for z in zones where z.event_pending:
        z.event_pending = False; log_event("MAINT", "Zone " + z.id + " test trigger")
    if now() > maint_until:
        log_event("MAINT", "Session timed out"); go_to("RECOVERY", "timeout"); return
    key = keypad_get_key()
    if   key == '1': test_buzzer_and_leds()
    elif key == '2': show_live_zone_status()      # incl. Node 2 online / last heartbeat
    elif key == '3': show_last_log_lines(5)
    elif key == 'C' or maintenance_card_scanned_again():
        log_event("MAINT", "Maintenance ended", role="MAINTENANCE")
        go_to("RECOVERY", "maintenance exit")
    elif key is not None:
        reject_input("Unknown maintenance command")                      # T08


# =====================================================================
# 12. RECOVERY — T12
# =====================================================================
def handle_recovery():
    show("Revalidating...")
    if self_test():
        window_until = 0
        log_event("SYSTEM", "Recovery OK"); go_to("MONITORING", "revalidated")
    else:
        go_to("TAMPER_FAULT", "revalidation failed")


# =====================================================================
# 13. PRIORITY, OUTPUTS, LOG
# =====================================================================
def evaluate_alert_priority():
    if state == "TAMPER_FAULT":   return "P3"
    if state == "INTRUSION":      return "P2"
    if now() < window_until:      return "P1"
    return "P0"

#  P0  green LED     buzzer silent           "ARMED OK"
#  P1  yellow LED    one chirp per event     "WARN Z2"
#  P2  red LED       continuous              "INTRUSION Z2+Z1"
#  P3  red blinking  fast pulse              "TAMPER" / "NODE 2 LOST" / "Z1 STUCK"
#  MAINTENANCE: yellow blinking, silent

def log_event(type, event, zone="-", role=session_role, uid="-", result="-", priority=None):
    record = [boot_number, uptime_ms(), priority or evaluate_alert_priority(),
              state, type, event, zone, role, uid, result]
    append_line("/log.csv", record)              # LittleFS; rotate after LOG_MAX_LINES
    serial_print(record)                         # copy into report as evidence
    # Log on change only. Never log PINs, keys or full card UIDs.

def reject_input(why):
    log_event("INPUT", why, result="REJECTED"); show("Invalid: " + why); chirp()
```

---

## Test mapping (spec §19)

| Test | Demo on the model |
|---|---|
| T01 Normal | Both PIRs quiet, lid closed, Node 2 online → green, "ARMED OK" |
| T02 Bad auth | Wrong PIN or unknown card → FAIL logged |
| T03 Lockout | 3 wrong PINs → 60 s lock; power-cycle Node 1 → lock still there |
| T04 Single event | Wave at Node 2's PIR only → yellow + chirp (P1) |
| T05 Corroborated | Wave at Node 2, then Node 1 within 15 s → alarm (P2) |
| T06 Sensor fault | Unplug Node 1's PIR signal wire → "Z1 STUCK" (P3, not intrusion) |
| T07 Tamper | Open enclosure lid (move magnet away) → P3 in any state |
| T08 Invalid command | Press A when armed / 7-digit PIN / unknown key in maintenance. Optional: send a packet with a wrong key from a test sketch → "Bad signature" |
| T09 Comm loss | Unplug Node 2's USB → "NODE 2 LOST" within 3 s |
| T10 Power loss | Pull Node 1 power → boot log shows reason; lockout + armed state restored. Pull Node 2 → "Node 2 booted" logged when it returns |
| T11 Override | Maintenance card + PIN → maintenance mode; operator card denied; auto-exit after 5 min |
| T12 Recovery | Maintenance clears fault → self-test → back to MONITORING |

## Team decisions to confirm with your supervisor
1. **Re-arm after a power cut** (v3 does this) or stay disarmed? Staying disarmed means cutting power disables the alarm.
2. **Node 2 offline = P3 fault** (v3) or a lower "degraded" warning? With only two zones, losing one means corroboration is impossible, so v3 treats it as critical.
3. **Only MAINTENANCE can clear a tamper/fault** (v3), while OPERATOR can arm, disarm and acknowledge intrusions. This is your two-role demo for C3.

## Residual risks to list in the report
- Node 2's box has no tamper switch. Removing its power is caught (heartbeat), but covering the PIR is not.
- The PIR can't tell people from pets or heat sources. Corroboration across two zones reduces false alarms but doesn't remove them.
- MIFARE card UIDs can be cloned, which is why the PIN is also required.
- ESP-NOW messages are signed but not encrypted. Someone listening can see when motion happens, but can't fake or replay messages.
- Timestamps are boot number + uptime, not real time. A DS3231 RTC would fix this.
