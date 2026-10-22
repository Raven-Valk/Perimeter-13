// =====================================================================
//  beam.h  —  the infrared beam along wall C-D (firmware 6.1)
//
//  Hardware: two IR-08H modules (4 pins: EN, OUT, +, GND). Each has an IR LED
//  driven at 38 kHz by a 555 timer (it only runs while EN is HIGH) and an
//  HS0038 receiver that pulls OUT LOW while it sees 38 kHz infrared.
//    * D, transmitter: jumper OFF, EN -> GPIO 19. The firmware switches the
//      555 on in short bursts with the ESP32's LEDC hardware (no CPU time).
//    * C, receiver:    jumper OFF, EN -> GND (its own LED stays dark), OUT -> GPIO 19.
//      Power both modules from 3.3 V: OUT then never goes above 3.3 V.
//  D's LED points along the outside of wall C-D at C's receiver. The beam is
//  zone 4, the only sensor on that wall: 2 breaks within 20 s = intrusion.
//
//  Why bursts and not a steady beam: the HS0038 treats infrared that never
//  stops as background light and stops reporting it after a moment. Bursts of
//  1 ms every 10 ms are what it is built for, and each one gives C a short LOW
//  pulse on OUT. So:
//      beam intact  -> C sees about 10 short pulses every 100 ms
//      beam broken  -> no pulses (OUT stays HIGH)
//      OUT stuck LOW for a second or more -> wiring fault
//
//  This file is plain C++ with no Arduino calls, so tests/beam_tests.cpp can
//  check it on a PC. In the firmware a tiny interrupt counts the pulses and
//  the main loop hands the count to the tracker (sync()).
// =====================================================================
#pragma once
#include <stdint.h>

const uint32_t BEAM_PERIOD_MS   = 10;      // D: one burst every 10 ms (100 Hz) ...
const uint32_t BEAM_BURST_MS    = 1;       // ... of 1 ms (about 38 cycles of 38 kHz)
const uint32_t BEAM_WINDOW_MS   = 100;     // C counts pulses per 100 ms window
const uint8_t  BEAM_EXPECTED    = BEAM_WINDOW_MS / BEAM_PERIOD_MS;   // 10 pulses per window
const uint32_t BEAM_GAP_MS      = 60;      // no pulse for this long = broken (6 bursts missed)
const uint32_t BEAM_GRACE_MS    = 5000;    // after start-up: this long to find the signal, else NOSIG
const uint32_t BEAM_STUCK_MS    = 30000;   // broken this long = blocked or D down: a FAULT, like a stuck PIR
const uint32_t BEAM_LOW_STUCK_MS = 1000;   // OUT held LOW this long = shorted wire / receiver fault
const uint32_t BEAM_MERGE_MS    = 2000;    // breaks this close together are one crossing (two legs, a bag...)
const uint8_t  BEAM_REPEATS     = 2;       // separate breaks within 20 s that confirm an intrusion (zone 4)

// Beam health, same numbers as link_protocol.h Health: OK / WARMUP / STUCK / OFFLINE
enum BeamHealth : uint8_t { BH_OK = 0, BH_WARMUP = 1, BH_STUCK = 2, BH_NOSIG = 3 };

inline const char* beamHealthName(uint8_t h) {
  switch (h) { case BH_OK: return "OK"; case BH_WARMUP: return "WARMUP"; case BH_STUCK: return "STUCK"; default: return "NO SIGNAL"; }
}

class BeamTracker {
public:
  // One falling edge on OUT (a burst from D arrived). Used by the tests.
  void pulse(uint32_t nowMs) { lastPulse = nowMs; pulses++; everPulsed = true; }

  // The firmware: the interrupt's running pulse count and the time of the last one.
  void sync(uint32_t lastPulseMs, uint32_t pulseCount) {
    if (pulseCount != pulses) { pulses = pulseCount; lastPulse = lastPulseMs; everPulsed = true; }
  }

  // Wokwi has no infrared: the simulator calls this every loop pass while the
  // "beam" button is not pressed, as if D's bursts were arriving.
  void fakeSignal(uint32_t nowMs) {
    if (!everPulsed || nowMs - fakeAt > 1000) fakeAt = nowMs;          // (re)start the fake bursts
    while (nowMs - fakeAt >= BEAM_PERIOD_MS) { fakeAt += BEAM_PERIOD_MS; pulses++; }
    lastPulse = nowMs; everPulsed = true;
  }

  // Every loop pass. outLow = the OUT pin reads LOW right now.
  void update(uint32_t nowMs, bool outLow) {
    if (!started) { started = true; startedAt = nowMs; windowStart = nowMs; windowCount = pulses; }
    if (nowMs - windowStart >= BEAM_WINDOW_MS) {          // close the counting window
      lastWindowPulses = (uint16_t)(pulses - windowCount);
      lastWindowMs = (uint16_t)(nowMs - windowStart);   // 100-150 ms: the loop isn't exactly regular
      windowCount = pulses;
      windowStart = nowMs;
    }
    // Stuck LOW = OUT reads LOW *and* no burst edge for a second. (Reading LOW on
    // its own proves nothing: each good burst holds OUT LOW for 1 ms, and a loop
    // that happens to run in step with D's 10 ms bursts could catch it every time.)
    bool lowStuck = outLow && nowMs - lastPulse >= BEAM_LOW_STUCK_MS;

    bool ok = everPulsed && !lowStuck && signalValid(nowMs);
    if (ok) {                                             // intact (again, or for the first time)
      intactNow = true;
      health = BH_OK;
      return;
    }
    if (intactNow) {                                      // it just broke
      intactNow = false;
      brokenSince = nowMs;
      if (health == BH_OK && (!eventAt || nowMs - eventAt >= BEAM_MERGE_MS)) {   // a new crossing
        eventPending = true;
        eventAt = nowMs ? nowMs : 1;
      }
    }
    if (lowStuck) { health = BH_STUCK; return; }
    if (!everPulsed) { health = nowMs - startedAt < BEAM_GRACE_MS ? BH_WARMUP : BH_NOSIG; return; }
    if (nowMs - brokenSince >= BEAM_STUCK_MS) health = BH_STUCK;
  }

  // ------------------------------------------------------------------
  //  Is what C receives right now really D's beam?  (only asked once at
  //  least one pulse has arrived since start-up)
  //  nowMs - lastPulse = how long since the most recent pulse (ms)
  //  lastWindowPulses  = pulses counted in the last complete window ...
  //  lastWindowMs      = ... which lasted this long (100 ms or a bit more)
  //  BEAM_PERIOD_MS    = D sends one burst every 10 ms, so expect lastWindowMs / 10
  //  true = intact. false for long enough (BEAM_GAP_MS) = a break.
  // ------------------------------------------------------------------
  bool signalValid(uint32_t nowMs) const {
    // TODO(team): decide how strict this check is. See README "Beam check".
    return nowMs - lastPulse < BEAM_GAP_MS;
  }

  bool intact() const { return intactNow; }
  bool faulty() const { return health == BH_STUCK || health == BH_NOSIG; }
  bool warming() const { return health == BH_WARMUP; }
  const char* stateText() const {                         // status field IR:
    switch (health) {
      case BH_OK:     return intactNow ? "OK" : "BRK";
      case BH_WARMUP: return "WARMUP";
      case BH_STUCK:  return "STUCK";
      default:        return "NOSIG";
    }
  }
  const char* healthText() const { return beamHealthName(health); }

  // Break history: the last BEAM_REPEATS break times (same idea as a PIR's).
  void addTrigger(uint32_t t) {
    if (trigN < BEAM_REPEATS) { trig[trigN++] = t; return; }
    for (uint8_t i = 0; i + 1 < BEAM_REPEATS; i++) trig[i] = trig[i + 1];
    trig[BEAM_REPEATS - 1] = t;
  }
  uint8_t recentCount(uint32_t t, uint32_t windowMs) const {
    uint8_t c = 0;
    for (uint8_t i = 0; i < trigN; i++) if (t - trig[i] < windowMs) c++;
    return c;
  }
  bool recent(uint32_t t, uint32_t windowMs) const { return trigN > 0 && t - trig[trigN - 1] < windowMs; }
  uint32_t lastTrig() const { return trigN ? trig[trigN - 1] : 0; }
  void clearWindow() { trigN = 0; eventPending = false; }

  uint8_t  health = BH_WARMUP;
  bool     eventPending = false;
  uint8_t  loggedHealth = 0xFF;            // last health written to the log
  uint16_t lastWindowPulses = 0, lastWindowMs = BEAM_WINDOW_MS;

private:
  uint32_t lastPulse = 0, pulses = 0, fakeAt = 0;
  bool     everPulsed = false;
  uint32_t eventAt = 0, startedAt = 0, windowStart = 0, windowCount = 0, brokenSince = 0;
  bool     started = false, intactNow = false;
  uint32_t trig[BEAM_REPEATS] = {};
  uint8_t  trigN = 0;
};
