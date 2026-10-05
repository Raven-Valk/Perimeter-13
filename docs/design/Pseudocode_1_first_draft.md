# ============================================
# SIMPLE PERIMETER SECURITY SYSTEM
# ============================================

# --- 1. SETUP (Runs once when powered ON) ---
def setup():
    print("System Starting...")
    
    # T10: ALWAYS start in safe/disarmed mode after power loss
    current_state = "WAIT_FOR_AUTH"  
    alarm_active = False
    lockout_timer = 0
    failed_attempts = 0
    auth_role = "NONE"  # NONE, OPERATOR, or MAINTENANCE
    
    # Check all sensors and tamper switches
    if self_test() == False:
        print("BOOT FAILED! Staying safe.")
        current_state = "TAMPER_FAULT"
    else:
        print("Self-test OK. System ready.")
    
    # Start a safety timer (watchdog) so software crashes auto-restart
    start_watchdog_timer()


# --- 2. MAIN LOOP (Runs forever, ~200ms per cycle) ---
def main_loop():
    while True:
        reset_watchdog()  # Tell system "I'm still alive"
        
        # Read all sensors every loop
        read_all_sensors()
        
        # Check if we are in "lockout" mode (T03)
        if lockout_timer > 0 and time_now() < lockout_timer:
            show_on_screen("LOCKED. Wait...")
            continue  # Skip everything until lockout ends
        
        # ===== STATE MACHINE =====
        
        if current_state == "WAIT_FOR_AUTH":
            handle_wait_for_auth()   # T02, T03
            
        elif current_state == "MONITORING":
            handle_monitoring()      # T01, T04, T05, T06
            
        elif current_state == "INTRUSION":
            handle_intrusion()       # T04, T05
            
        elif current_state == "TAMPER_FAULT":
            handle_tamper_fault()    # T06, T07
            
        elif current_state == "MAINTENANCE":
            handle_maintenance()     # T11
            
        elif current_state == "RECOVERY":
            handle_recovery()        # T12
        
        wait(0.2)  # 200ms delay between checks


# --- 3. AUTHENTICATION STATE (T02, T03) ---
def handle_wait_for_auth():
    show_on_screen("Enter PIN or Scan RFID")
    
    # Check if user entered PIN or scanned card
    user_input = check_keypad_and_rfid()
    
    if user_input == "valid_operator":
        auth_role = "OPERATOR"
        current_state = "MONITORING"
        log_event("Operator logged in")
        failed_attempts = 0
        
    elif user_input == "valid_maintenance":
        auth_role = "MAINTENANCE"
        current_state = "MONITORING"
        log_event("Maintenance logged in")
        failed_attempts = 0
        
    elif user_input == "invalid":
        failed_attempts = failed_attempts + 1
        log_event("Failed login attempt")
        beep_once()
        
        # T03: Lockout after 3 wrong tries
        if failed_attempts >= 3:
            lockout_timer = time_now() + 60  # 60 seconds
            show_on_screen("LOCKED FOR 60 SEC")
            log_event("Account locked for 60s")
            alarm_buzzer(1)  # Short warning beep


# --- 4. MONITORING STATE (T01, T04, T05, T06) ---
def handle_monitoring():
    green_light(ON)
    red_light(OFF)
    show_on_screen("SYSTEM ARMED")
    
    # T06: First, check if sensors are healthy (don't trust blindly!)
    check_sensor_health()
    
    # T07: Check if someone opened the box or fence
    if tamper_switch_is_open():
        log_event("TAMPER DETECTED!")
        current_state = "TAMPER_FAULT"
        return
    
    # Count how many sensors are triggered right now
    triggered_count = count_triggered_sensors()
    
    # T05: Corroborated intrusion (2+ sensors agree, or 2 out of 3 IR beams broken)
    if triggered_count >= 2 or majority_ir_beams_broken():
        log_event("INTRUSION CONFIRMED")
        current_state = "INTRUSION"
        return
    
    # T04: Single sensor triggered (low confidence)
    if triggered_count == 1:
        log_event("Warning: single sensor")
        yellow_light(ON)      # Just a warning light
        beep_once()           # Small beep, not full alarm
        # Stay in MONITORING, don't change state
    
    # T11: Check if maintenance switch is flipped
    if maintenance_switch_is_on():
        if auth_role == "MAINTENANCE":
            log_event("Maintenance mode started")
            current_state = "MAINTENANCE"
        else:
            log_event("Unauthorized override attempt!")
            beep_once()


# --- 5. INTRUSION STATE (T04, T05) ---
def handle_intrusion():
    red_light(ON)
    green_light(OFF)
    siren(ON)           # Full alarm
    relay(ON)           # External alarm
    show_on_screen("!!! BREACH !!!")
    
    # Alarm keeps ringing until authorized person stops it
    if valid_rfid_or_pin_entered():
        log_event("Intrusion acknowledged by user")
        siren(OFF)
        relay(OFF)
        current_state = "RECOVERY"


# --- 6. TAMPER / FAULT STATE (T06, T07) ---
def handle_tamper_fault():
    red_light(BLINKING)
    siren(ON)           # High priority alarm
    relay(ON)
    show_on_screen("TAMPER OR FAULT!")
    
    # Keep logging that fault is still active (every 5 seconds)
    if every_5_seconds():
        log_event("Fault condition persists")
    
    # Exit only when problem is fixed AND sensors are healthy
    if tamper_switch_is_closed() and all_sensors_healthy():
        log_event("Tamper/fault cleared")
        current_state = "RECOVERY"


# --- 7. MAINTENANCE / OVERRIDE STATE (T11) ---
def handle_maintenance():
    yellow_light(ON)
    show_on_screen("MAINTENANCE MODE")
    
    # Even in maintenance, tamper switch is still watched!
    if tamper_switch_is_open():
        log_event("Tamper during maintenance!")
        current_state = "TAMPER_FAULT"
        return
    
    # Log every 10 seconds that we are in override
    if every_10_seconds():
        log_event("Maintenance mode active")
    
    # Exit when switch is turned off or 'C' pressed
    if maintenance_switch_is_off():
        log_event("Maintenance ended")
        current_state = "RECOVERY"


# --- 8. RECOVERY STATE (T12) ---
def handle_recovery():
    show_on_screen("Checking system...")
    
    # Re-run all tests before going back to normal
    if self_test() == True and all_sensors_healthy() and tamper_switch_is_closed():
        log_event("Recovery complete")
        auth_role = "NONE"        # Force re-login!
        current_state = "WAIT_FOR_AUTH"
    else:
        log_event("Recovery failed")
        current_state = "TAMPER_FAULT"


# --- 9. HELPER FUNCTIONS ---

def check_sensor_health():
    # T06 / V1: If a sensor hasn't changed in 30 seconds, it's probably broken/disconnected
    for each sensor:
        if sensor_has_not_changed_for(30_seconds):
            mark_sensor_as_FAULT(sensor)
            log_event("Sensor fault detected: " + sensor.name)

def log_event(message):
    # T08 / V8: Save to memory with timestamp
    timestamp = get_current_time()
    save_to_eeprom_or_spiffs(timestamp + " | " + message)
    print("LOG:", timestamp, message)

def self_test():
    # T01: Check all sensors respond
    for each sensor:
        read_sensor()
    # Check tamper switches are closed at start
    if tamper_switch_is_open():
        return False
    return True

def evaluate_alert_priority():
    # P0 = Normal, P1 = Warning, P2 = Intrusion, P3 = Tamper
    if tamper_or_fault_exists():
        return "P3"
    if two_or_more_sensors_triggered():
        return "P2"
    if one_sensor_triggered():
        return "P1"
    return "P0"