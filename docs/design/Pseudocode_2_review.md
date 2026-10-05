# Secure Perimeter Intrusion Detection — Pseudocode v2

Revised against (a) the Project 13 specification and (b) the new component list:
ESP32, HC-SR501 PIR, MAGREED-2538 reed switch, RC522 RFID, 4×4 keypad, LCD1602 (I2C), active buzzer, MB102 supply, 400-pin breadboard, M-F jumpers.

---

## Part A — Hardware gaps (fix before Design Review 1)

### A1. Things v1 code uses that are NOT in the new component list

| v1 code calls | Status with new list | What to do |
|---|---|---|
| `majority_ir_beams_broken()` | No IR sensor any more | Remove, or keep one FC-51 IR sensor (you already had one in the lit-review build). Strongly suggested — see A3. |
| `green_light / red_light / yellow_light` | No LEDs | Add 3 LEDs (R/G/Y) + 220 Ω resistors. Spec §11 and §13 require visual indicators. |
| `siren()` + `relay()` | Only one active buzzer; no relay | Use buzzer patterns per priority (Part C). Relay is optional in the spec — drop it. |
| `tamper_switch_is_open()` | **No tamper switch** | **Must add.** C7 / T07 cannot pass without it. A second MAGREED + magnet on the enclosure lid, or a micro limit switch. |
| `maintenance_switch_is_on()` | No switch | Use keypad key `B` after a MAINTENANCE login (better than a toggle switch anyone can flip). |
| `get_current_time()` | ESP32 has no battery-backed clock | Log `boot_number + uptime`, or add a DS3231 RTC module if you want real date/time. |

### A2. Buy / check list

- Tamper switch ×1–2 (second reed switch or limit switch) — **required**
- Red, green, yellow LEDs + 220 Ω resistors — **required by spec**
- Resistors for end-of-line wiring: 10 kΩ ×3, 4.7 kΩ ×4 (EOL wiring for gate + tamper, plus the PIR pull-up)
- **Male-to-male jumpers** — the list has only male-to-female. The keypad ribbon ends in a female socket, and breadboard-to-breadboard links need M-M. (Your lit-review table already lists both types.)
- 830-point breadboard, or a second 400-point one. An ESP32 DevKit covers almost the whole width of a 400-point board, leaving one free hole row per side — not enough for RFID + keypad + LCD + LEDs.
- DC adapter (6.5–12 V) for the MB102, unless you power it from USB.
- Optional: DS3231 RTC (real timestamps), I2C level shifter for the LCD (see A4).

### A3. Sensor count and corroboration

With only PIR + gate reed, "two sensors agree" means *motion near the fence* **and** *gate opened*. That works, but the IR boundary sensor is what makes the perimeter story convincing (spec §13 lists 2–4 IR/proximity sensors). Keeping one FC-51 gives three zones: IR = fence line, PIR = inner zone, reed = gate.

### A4. Electrical cautions

- **RC522 is 3.3 V only.** Never connect it to the MB102 5 V rail.
- LCD1602 I2C backpack: on 5 V, its built-in pull-ups pull SDA/SCL to 5 V, and ESP32 pins are 3.3 V parts. Either use a level shifter, or try powering the LCD from 3.3 V and turn the contrast pot.
- HC-SR501: set jumper to **L (single trigger)** and the time pot to minimum (~3 s). It needs **~60 s warm-up** after power-on and gives false triggers during that time.
- Check whether your buzzer module is *low-level trigger* (sounds when pin is LOW). If so, it will beep during boot — invert the logic in code.
- Tie all grounds together (ESP32 GND, both MB102 rails).
- While flashing over USB, don't also feed 5 V from the MB102 into the ESP32's VIN.

### A5. Suggested pin map (ESP32 DevKit V1, 30-pin — verify against your exact board)

| Function | GPIO | Note |
|---|---|---|
| LCD SDA / SCL | 21 / 22 | I2C |
| RC522 SCK / MISO / MOSI / SS / RST | 18 / 19 / 23 / 5 / 4 | VSPI |
| Keypad rows | 13, 14, 27, 26 | need internal pull-ups → not 34–39 |
| Keypad cols | 25, 33, 32, 16 | |
| Buzzer | 17 | |
| LED green / red / yellow | 2 / 15 / 12 | 12 must be LOW at boot — an LED + resistor to GND keeps it low. Don't put anything that pulls it HIGH. |
| Gate reed (EOL, analog) | 34 | ADC1 — works with Wi-Fi on |
| Tamper (EOL, analog) | 39 | ADC1 |
| PIR | 35 | input-only: add external 10 kΩ pull-up to 3.3 V |
| Spare (optional FC-51 IR) | 36 | input-only |

Pins to avoid: 6–11 (flash), 0 and 1/3 (boot/serial). This uses 19 general I/O pins plus 3 input-only pins, so almost every usable pin on a 30-pin board is taken. If you add more, move the keypad to a PCF8574 I2C expander.

---

## Part B — Logic issues found in v1

| # | Issue in v1 | Why it matters | Fix in v2 |
|---|---|---|---|
| 1 | Lockout `continue` skips the whole loop | 3 wrong PINs = 60 s where **nothing is monitored**, including tamper. An attacker can blind the system on purpose. | Lockout blocks only keypad/RFID input. Sensors and tamper keep running. |
| 2 | Tamper checked only in MONITORING and MAINTENANCE | Opening the box in WAIT_FOR_AUTH, INTRUSION or RECOVERY goes unnoticed. | Tamper is checked at the top of every loop, in every state. |
| 3 | TAMPER_FAULT clears itself when the lid closes | Attacker opens box, does something, closes it → alarm stops on its own. Not a "protected state". | Leaving TAMPER_FAULT needs an authenticated MAINTENANCE acknowledgement. |
| 4 | `failed_attempts` reset on reboot | Wrong PIN ×3 → pull the power → lockout gone. Lockout bypass. | Store attempt count + lockout in NVS (flash). Lockout doubles each time: 60 → 120 → 240 s. |
| 5 | `failed_attempts` never reset after lockout ends | One more wrong try re-locks immediately. Might be intended, but undocumented. | Explicit escalation rule (above); reset only on successful login. |
| 6 | PIN entry in INTRUSION has no attempt limit | Unlimited guessing of the disarm PIN while the alarm rings. | Every auth prompt uses the same function with lockout. |
| 7 | Sensor health = "no change for 30 s → FAULT" | Normal for these sensors: gate stays closed for hours, PIR stays LOW when nobody's there. **T01 (normal monitoring) would fail** — everything shows FAULT. | Per-sensor health rules (Part C, `update_sensor_health`). |
| 8 | A cut reed-switch wire reads the same as "gate open" | Can't tell sensor fault from intrusion — exactly what spec §10 says you must do. | End-of-line (EOL) resistors read on an ADC pin: CLOSED / OPEN / CUT / SHORT are different voltages. |
| 9 | `triggered_count >= 2` at the same instant | PIR and gate rarely fire in the same 200 ms. T05 would be hard to reproduce. Spec §16 asks for "timing/sequence rules". | 15 s corroboration window: event in one zone, then a different healthy zone. |
| 10 | P1 warning beeps + logs every 200 ms while PIR is HIGH | PIR holds HIGH for seconds → constant beeping and hundreds of log lines. Yellow light never turns off. | Act on the rising edge only. Warning clears when the window expires. |
| 11 | Faulty sensors still counted in `count_triggered_sensors()` | A broken sensor could "corroborate" an intrusion. | Only HEALTHY zones count. |
| 12 | Auth is "PIN **or** RFID" | Your own slides say "RFID card **plus** keypad PIN". Also, MIFARE card UIDs can be cloned, so card-only is weak. | Card + PIN. If the reader is offline, PIN-only for OPERATOR; MAINTENANCE denied. |
| 13 | No maintenance session timeout | Spec §12: "Privileged maintenance mode expires automatically." | 5-minute timeout → RECOVERY. |
| 14 | Tamper alarm fires during maintenance | The maintenance person can't open the enclosure — which is usually why they're there. | In MAINTENANCE, a lid opening is logged, not alarmed. On exit, lid must be closed and revalidated. |
| 15 | T08 (invalid command) not handled | Required test scenario, no code for it. | Key validation per state; wrong keys rejected + logged. |
| 16 | T09 (communication loss) not handled | Required test scenario. | RC522 and LCD health checks; defined degraded behaviour. |
| 17 | No disarm path from MONITORING | Once armed, the only way out is to trigger an alarm. | `D` + auth → disarm → WAIT_AUTH. |
| 18 | `evaluate_alert_priority()` never called | P0–P3 is a headline feature but never reaches the display or log. | Priority computed every loop; drives LEDs/buzzer/LCD and goes in every log line. |
| 19 | No transition validation | Spec §16: "Prevent invalid transitions." | `go_to()` checks an allowed-transitions table; rejects + logs anything else. |
| 20 | Log line = timestamp + message | Spec §16: "Timestamp + event + type + user/result". Logging every 5–10 s also wears out flash. | Structured log record; log on change only; capped file size; never log PINs or full card UIDs. |
| 21 | Power loss → always disarmed | An attacker can disarm the system by cutting power. | Team decision (flagged in code): v2 remembers "armed" in NVS and re-arms after self-test, logging the power loss. |
| 22 | Variables assigned inside functions | In Python these would be local and the state would never change. In C++, make the state variables global. | Shown as `GLOBAL` below. |

---

## Part C — Pseudocode v2

```python
# =====================================================================
# SECURE PERIMETER INTRUSION DETECTION — v2
# Sensors: Z1 = PIR (inner zone), Z2 = GATE reed switch
#          (optional Z3 = FC-51 IR at fence line)
# Tamper:  enclosure lid switch
# Auth:    RC522 card + keypad PIN
# Output:  LCD1602, buzzer, R/G/Y LEDs
# =====================================================================

# ---------- CONSTANTS (finalise values at Design Review 1) ----------
LOOP_MS               = 100
PIR_WARMUP_S          = 60
PIR_MAX_HIGH_S        = 30      # PIR in L-mode, hold ~3 s; HIGH longer = stuck / disconnected
CORROBORATION_S       = 15      # second zone must fire within this window
MAX_ATTEMPTS          = 3
BASE_LOCKOUT_S        = 60      # doubles each lockout: 60, 120, 240 ...
PIN_ENTRY_TIMEOUT_S   = 20
MAINT_TIMEOUT_S       = 300
HEALTH_CHECK_EVERY_S  = 10      # RFID / LCD bus checks
LOG_MAX_LINES         = 500

# Reed-switch EOL voltage bands (measure yours in Week 3 and adjust)
#   3.3V --[10k]--+-- ADC pin
#                 |
#         (at the sensor end) [4.7k EOL] -- [switch || 4.7k ALARM] -- GND
#   CLOSED ≈ 1.06 V | OPEN ≈ 1.60 V | CUT ≈ 3.3 V | SHORT ≈ 0 V
BAND_SHORT  = (0.00, 0.40)
BAND_CLOSED = (0.70, 1.30)
BAND_OPEN   = (1.40, 2.00)
BAND_CUT    = (2.80, 3.30)

# ---------- GLOBAL STATE ----------
GLOBAL state            = "BOOT"
GLOBAL session_role     = "NONE"      # NONE | OPERATOR | MAINTENANCE
GLOBAL zones            = {Z1: {health: OK, triggered: False, last_edge: 0},
                           Z2: {health: OK, triggered: False, last_edge: 0}}
GLOBAL window_open_until = 0
GLOBAL window_zone       = None
GLOBAL maint_expires     = 0
GLOBAL rfid_online       = True
GLOBAL lcd_online        = True
GLOBAL priority          = "P0"
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
        log_event("STATE", "Invalid transition " + state + "->" + new_state,
                  result="REJECTED")                                     # spec §16
        return
    log_event("STATE", state + " -> " + new_state + " (" + reason + ")")
    state = new_state
    on_enter(new_state)            # reset per-state timers, clear key buffer


# =====================================================================
# 1. SETUP (runs once)
# =====================================================================
def setup():
    init_pins(); init_lcd(); init_rfid(); init_littlefs()
    start_watchdog(timeout_s = 5)
    boot_number = boot_number + 1                       # NVS
    reason = esp_reset_reason()          # POWER_ON / WATCHDOG / BROWNOUT / ...
    log_event("SYSTEM", "Boot #" + boot_number + " reason=" + reason)   # T10 evidence
    if lockout_remaining_s > 0:
        log_event("AUTH", "Lockout restored after reboot")              # fix #4
    state = "BOOT"
    boot_started = now()


# =====================================================================
# 2. MAIN LOOP
# =====================================================================
def loop():
    feed_watchdog()
    read_inputs()                  # raw PIR, gate ADC, tamper ADC, keypad, RFID
    update_sensor_health()         # every state (fix #7, #8)
    update_comm_health()           # every HEALTH_CHECK_EVERY_S (T09)
    tick_lockout()                 # count down; blocks input only (fix #1)

    # --- Tamper overrides every state (fix #2) ---
    if tamper_reading() != CLOSED:
        if state == "MAINTENANCE":
            log_once("TAMPER", "Lid opened during maintenance", result="ALLOWED")
        elif state != "TAMPER_FAULT" and state != "BOOT":
            go_to("TAMPER_FAULT", "Enclosure tamper")

    # --- State machine ---
    if   state == "BOOT":          handle_boot()
    elif state == "WAIT_AUTH":     handle_wait_auth()
    elif state == "MONITORING":    handle_monitoring()
    elif state == "INTRUSION":     handle_intrusion()
    elif state == "TAMPER_FAULT":  handle_tamper_fault()
    elif state == "MAINTENANCE":   handle_maintenance()
    elif state == "RECOVERY":      handle_recovery()

    priority = evaluate_alert_priority()           # fix #18
    update_outputs(priority)
    wait(LOOP_MS)


# =====================================================================
# 3. BOOT / SELF-TEST  (T01, T10)
# =====================================================================
def handle_boot():
    remaining = PIR_WARMUP_S - seconds_since(boot_started)
    if remaining > 0:
        show("Warming up " + remaining + "s")      # PIR settle; tamper still read above
        return
    if not self_test():
        state = "TAMPER_FAULT"                       # BOOT -> fault allowed
        log_event("SYSTEM", "Self-test FAILED", priority="P3")
        return
    log_event("SYSTEM", "Self-test OK")
    # TEAM DECISION (fix #21): re-arm after power loss, or stay disarmed?
    if was_armed:
        log_event("SYSTEM", "Power restored - re-armed automatically")
        go_to("MONITORING", "resume after power loss")
    else:
        go_to("WAIT_AUTH", "boot complete")

def self_test():
    ok = True
    if tamper_reading() != CLOSED:        ok = False; log_event("TEST", "Tamper open")
    if zones[Z2].health != OK:            ok = False; log_event("TEST", "Gate sensor " + zones[Z2].health)
    if zones[Z1].health != OK:            ok = False; log_event("TEST", "PIR " + zones[Z1].health)
    if not rfid_online:                   log_event("TEST", "RFID offline - degraded")   # not fatal
    if not lcd_online:                    log_event("TEST", "LCD offline - degraded")    # not fatal
    flash_all_leds(); chirp()             # visible lamp/buzzer test
    return ok


# =====================================================================
# 4. AUTHENTICATION  (T02, T03, T08, T09) — shared by every state
# =====================================================================
# Non-blocking: called every loop; returns a role once, otherwise "NONE".
# Flow: scan card -> enter PIN -> '#' to submit.  '*' clears.
def authenticate(prompt):
    if lockout_remaining_s > 0:
        show("LOCKED " + lockout_remaining_s + "s")
        discard_keys_and_cards()                    # input blocked, sensors are not
        return "NONE"

    if rfid_online and card_waiting():
        pending_uid = read_card_uid()
        show("PIN for card ..")
        pin_buffer = ""; pin_started = now()

    key = keypad_get_key()
    if key is None:
        if pin_started and seconds_since(pin_started) > PIN_ENTRY_TIMEOUT_S:
            reset_auth_entry(); log_event("AUTH", "PIN entry timeout")
        return "NONE"

    if key is digit:
        if len(pin_buffer) < 6: pin_buffer += key;  show_masked(pin_buffer)   # ******
        else: reject_input("PIN too long")                                    # T08
    elif key == '*':
        pin_buffer = ""
    elif key == '#':
        return check_credentials(pending_uid, pin_buffer)
    else:
        pass   # A-D are state commands, handled by the caller
    return "NONE"

def check_credentials(uid, pin):
    if len(pin) < 4:
        reject_input("PIN too short"); return "NONE"           # T08

    if rfid_online:
        user = lookup_user_by_uid(uid)                         # card + PIN (fix #12)
        ok   = user is not None and hash(pin) == user.pin_hash
        role = user.role if ok else "NONE"
    else:
        # T09: reader offline -> PIN-only, OPERATOR rights only
        user = lookup_operator_by_pin_hash(hash(pin))
        ok   = user is not None
        role = "OPERATOR" if ok else "NONE"
        log_event("AUTH", "PIN-only login (RFID offline)")

    reset_auth_entry()
    if ok:
        failed_attempts = 0; lockout_level = 0                 # NVS
        log_event("AUTH", "Login", role=role, uid=mask(uid), result="SUCCESS")
        return role

    failed_attempts += 1                                        # NVS
    log_event("AUTH", "Login", uid=mask(uid), result="FAIL")    # T02
    show("Wrong. " + (MAX_ATTEMPTS - failed_attempts) + " left")
    chirp()
    if failed_attempts >= MAX_ATTEMPTS:                         # T03
        lockout_remaining_s = BASE_LOCKOUT_S * 2 ** lockout_level
        lockout_level += 1; failed_attempts = 0                 # NVS
        log_event("AUTH", "Lockout " + lockout_remaining_s + "s", priority="P1")
    return "NONE"

# Credentials: store SHA-256 PIN hashes + card UIDs in a config file that is
# NOT committed to Git. Never print PINs; log only the last 2 bytes of a UID.


# =====================================================================
# 5. WAIT_AUTH (disarmed)  — "monitor basic health"
# =====================================================================
def handle_wait_auth():
    show("DISARMED  Card+PIN")
    role = authenticate("arm")
    if role != "NONE":
        session_role = role
        was_armed = True                                    # NVS
        go_to("MONITORING", role + " armed system")
    reject_command_keys(allowed = [])                       # A-D invalid here (T08)


# =====================================================================
# 6. MONITORING (armed)  (T01, T04, T05, T06, T11)
# =====================================================================
def handle_monitoring():
    # --- sensor faults -> FAULT state, never auto-intrusion (spec §10) ---
    for z in zones:
        if z.health != OK:
            go_to("TAMPER_FAULT", "Sensor fault " + z.name + " " + z.health)   # T06
            return

    # --- edge-triggered events from HEALTHY zones only (fix #10, #11) ---
    for z in zones:
        if z.health == OK and rising_edge(z):
            log_event("SENSOR", z.name + " triggered", zone=z.name)
            if now() < window_open_until and z != window_zone:
                log_event("ALERT", "Corroborated: " + window_zone.name + " + " + z.name,
                          priority="P2")
                go_to("INTRUSION", "corroborated")                   # T05
                return
            window_open_until = now() + CORROBORATION_S              # T04 -> P1
            window_zone = z
            chirp()                                                  # once, not every loop
            log_event("ALERT", "Single-zone warning", zone=z.name, priority="P1")

    # --- operator commands (need fresh auth) ---
    key = peek_command_key()
    if key == 'D':                               # disarm (fix #17)
        role = authenticate("disarm")
        if role != "NONE":
            was_armed = False; session_role = "NONE"
            go_to("WAIT_AUTH", role + " disarmed")
    elif key == 'B':                             # maintenance request (T11)
        role = authenticate("maintenance")
        if role == "MAINTENANCE":
            maint_expires = now() + MAINT_TIMEOUT_S
            go_to("MAINTENANCE", "authorised")
        elif role == "OPERATOR":
            log_event("AUTH", "Maintenance request by OPERATOR", result="DENIED")
            show("Not permitted")
    elif key in ['A', 'C']:
        reject_input("Key not valid when armed")                     # T08


# =====================================================================
# 7. INTRUSION  (P2)
# =====================================================================
def handle_intrusion():
    show("!! INTRUSION !!  Card+PIN")
    role = authenticate("acknowledge")           # same lockout rules (fix #6)
    if role != "NONE":
        log_event("ALERT", "Intrusion acknowledged", role=role)
        session_role = role
        go_to("RECOVERY", "intrusion acknowledged")


# =====================================================================
# 8. TAMPER / FAULT  (P3)  (T06, T07)
# =====================================================================
def handle_tamper_fault():
    show_reason()                                # "TAMPER" or "FAULT Z2 CUT"
    log_every(60, "TAMPER", "Condition persists")   # not every 5 s: flash wear

    # remaining healthy zones still reported ("isolate affected logic")
    for z in zones:
        if z.health == OK and rising_edge(z):
            log_event("SENSOR", z.name + " triggered during FAULT", priority="P3")

    role = authenticate("clear fault")
    if role == "MAINTENANCE":                    # authorisation demo (C3) (fix #3)
        log_event("TAMPER", "Clear requested", role=role)
        session_role = role
        go_to("RECOVERY", "maintenance clear")
    elif role == "OPERATOR":
        log_event("TAMPER", "Clear by OPERATOR", result="DENIED")
        show("Needs MAINTENANCE")


# =====================================================================
# 9. MAINTENANCE / MANUAL OVERRIDE  (T11)
# =====================================================================
def handle_maintenance():
    show("MAINT " + seconds_left(maint_expires) + "s  1/2/3/C")
    # intrusion alarms suppressed here; sensors still read and logged
    for z in zones:
        if rising_edge(z): log_event("MAINT", z.name + " test trigger", zone=z.name)

    if now() > maint_expires:                                    # fix #13
        log_event("MAINT", "Session timed out")
        go_to("RECOVERY", "maintenance timeout")
        return

    key = keypad_get_key()
    if   key == '1': test_buzzer_and_leds();   log_event("MAINT", "Output test")
    elif key == '2': show_live_sensor_values(); log_event("MAINT", "Live sensor view")
    elif key == '3': show_last_log_lines(5)
    elif key == 'C':
        log_event("MAINT", "Maintenance ended", role=session_role)
        go_to("RECOVERY", "maintenance exit")
    elif key is not None:
        reject_input("Unknown maintenance command")              # T08


# =====================================================================
# 10. RECOVERY  (T12)
# =====================================================================
def handle_recovery():
    show("Revalidating...")
    if self_test():
        log_event("SYSTEM", "Recovery OK")
        clear_corroboration_window()
        go_to("MONITORING", "revalidated")       # spec T12: back to monitoring
    else:
        log_event("SYSTEM", "Recovery FAILED", priority="P3")
        go_to("TAMPER_FAULT", "revalidation failed")


# =====================================================================
# 11. SENSOR HEALTH  (spec §10, T06) — fix #7, #8
# =====================================================================
def update_sensor_health():
    # --- Z2 gate reed: EOL voltage bands ---
    v = analog_read_volts(GATE_PIN)
    if   in_band(v, BAND_CLOSED): zones[Z2].health = OK;  zones[Z2].triggered = False
    elif in_band(v, BAND_OPEN):   zones[Z2].health = OK;  zones[Z2].triggered = True
    elif in_band(v, BAND_CUT):    set_fault(Z2, "CUT")     # wire disconnected
    elif in_band(v, BAND_SHORT):  set_fault(Z2, "SHORT")   # wire bridged / bypassed
    else:                         set_fault(Z2, "IMPLAUSIBLE")

    # --- Z1 PIR: pull-up on input, so an unplugged PIR reads HIGH forever ---
    #     In L-mode a real trigger drops after ~3 s, so HIGH > 30 s = stuck/disconnected.
    #     (Verify in Week 3: unplug PIR, pin should read HIGH steadily.)
    if state == "BOOT" and seconds_since(boot_started) < PIR_WARMUP_S:
        return                                             # ignore during warm-up
    pir = digital_read(PIR_PIN)
    if pir == HIGH and high_duration(Z1) > PIR_MAX_HIGH_S:
        set_fault(Z1, "STUCK_HIGH")
    else:
        zones[Z1].triggered = (pir == HIGH)
        if zones[Z1].health != OK and pir == LOW:
            zones[Z1].health = OK                          # recovery still needs RECOVERY state

def tamper_reading():
    # same EOL banding as the gate, or a simple pulled-up switch
    return CLOSED / OPEN / CUT / SHORT

def update_comm_health():                                  # T09
    if every(HEALTH_CHECK_EVERY_S):
        v = rc522_read_version_register()                  # expect 0x91 / 0x92
        new_rfid = v not in [0x00, 0xFF]
        if new_rfid != rfid_online:
            log_event("COMM", "RFID " + ("online" if new_rfid else "OFFLINE - PIN-only operator"))
        rfid_online = new_rfid
        new_lcd = i2c_device_acks(0x27)
        if new_lcd != lcd_online:
            log_event("COMM", "LCD " + ("online" if new_lcd else "OFFLINE - buzzer/LEDs only"))
        lcd_online = new_lcd


# =====================================================================
# 12. ALERT PRIORITY + OUTPUTS  (spec §11)
# =====================================================================
def evaluate_alert_priority():
    if state == "TAMPER_FAULT":           return "P3"
    if state == "INTRUSION":              return "P2"
    if now() < window_open_until:         return "P1"
    return "P0"

def update_outputs(p):
    # LED           Buzzer                     LCD line 2
    # P0  green     silent                     ARMED OK / DISARMED
    # P1  yellow    one chirp on the event     WARN <zone>
    # P2  red       continuous                 INTRUSION <zones>
    # P3  red blink fast pulse (on/off 200 ms) TAMPER / FAULT <zone> <type>
    # MAINTENANCE: yellow blink, silent
    # (if LCD offline, LEDs + buzzer still carry the state)
    ...


# =====================================================================
# 13. EVENT LOG  (spec §16, T08 evidence, C9) — fix #20
# =====================================================================
def log_event(type, event, zone="-", role=session_role, uid="-",
              result="-", priority=None):
    record = [boot_number, uptime_ms(),          # or RTC/NTP time if available
              priority or evaluate_alert_priority(),
              state, type, event, zone, role, uid, result]
    append_line("/log.csv", join(record, ","))    # LittleFS
    if line_count("/log.csv") > LOG_MAX_LINES:
        rotate_log()                              # keep last N lines
    serial_print(record)                          # copy to report as evidence

def reject_input(why):                            # T08
    log_event("INPUT", why, result="REJECTED")
    show("Invalid: " + why); chirp()
```

---

## Part D — Test mapping (spec §19)

| Test | Where in v2 | How to run on the model |
|---|---|---|
| T01 Normal | MONITORING, P0 | Gate closed, no motion → green LED, "ARMED OK" |
| T02 Bad auth | `check_credentials` | Wrong PIN or unknown card → FAIL logged |
| T03 Lockout | `check_credentials` | 3 wrong → 60 s lockout; **also power-cycle and show it survives** |
| T04 Single event | MONITORING window | Wave at PIR only → yellow + one chirp, P1 |
| T05 Corroborated | MONITORING window | PIR then open gate within 15 s → P2 alarm |
| T06 Sensor fault | `update_sensor_health` | Unplug gate wire → "FAULT Z2 CUT", P3 (not intrusion) |
| T07 Tamper | top of loop | Open enclosure lid → P3 in **any** state |
| T08 Invalid command | `reject_input` | Press `A` when armed, 7-digit PIN, `9` in maintenance |
| T09 Comm loss | `update_comm_health` | Unplug RC522 → "RFID OFFLINE", PIN-only operator, maintenance denied |
| T10 Power loss | `setup` / BOOT | Remove MB102 power → boot log shows reason, lockout + armed state restored |
| T11 Override | MAINTENANCE | Maintenance card+PIN + `B`; operator gets "Not permitted"; timeout after 5 min |
| T12 Recovery | RECOVERY | Clear fault → self-test → back to MONITORING |

---

## Part E — Also update the lit-review paper

The paper (Section III table, Section IV, Table II) still describes the older build:

- Table I lists the **FC-51 IR sensor and one LED**, with **no RFID reader and no reed switch**. Update it to the new component list plus the additions in A2.
- Section IV-B/C say login is **PIN only**; the intro and slides say **RFID + PIN**. Make them consistent.
- Section IV-D says lockout makes the system "inaccessible" (permanent). The spec asks for a **temporary** lockout, and the pseudocode uses 60 s. Align these.
- Section IV-D says "when the intrusion ends, the buzzer goes quiet". The pseudocode latches the alarm until someone authenticates (the safer design). Pick one and use it everywhere.
- Table II tests T1–T7 should be renumbered to the spec's T01–T12.
- References [5] and [7] still have `[add …]` placeholders.
