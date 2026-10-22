// Tests for SensorModule/beam.h (zone 4: the IR beam on wall C-D), run on a PC.
//   g++ -std=c++17 -I. -o beam_tests beam_tests.cpp && ./beam_tests
// run_tests.sh copies beam.h here first.
#include <cstdio>
#include <cstring>
#include "beam.h"

static int fails = 0, checks = 0;
#define CHECK(cond, msg) do { checks++; if (cond) printf("  %-62s PASS\n", msg); \
                              else { fails++; printf("  %-62s FAIL\n", msg); } } while (0)

// Runs the tracker from `from` to `to` (ms) in 50 ms loop passes, like the
// firmware. `beam` true = D's bursts arrive (a pulse every 10 ms, OUT LOW for 1 ms).
static uint32_t run(BeamTracker& b, uint32_t from, uint32_t to, bool beam, bool outStuckLow = false) {
  for (uint32_t t = from; t < to; t++) {
    if (beam && t % BEAM_PERIOD_MS == 0) b.pulse(t);
    if (t % 50 == 0) {
      bool low = outStuckLow || (beam && t % BEAM_PERIOD_MS < BEAM_BURST_MS);
      b.update(t, low);
    }
  }
  return to;
}

int main() {
  printf("beam.h\n");
  {
    BeamTracker b;
    run(b, 0, 2000, false);
    CHECK(b.health == BH_WARMUP && !b.eventPending, "no signal yet, first 5 s: WARMUP, no event");
    run(b, 2000, 6000, false);
    CHECK(b.health == BH_NOSIG && b.faulty(), "no signal after 5 s: NO SIGNAL (fault)");
    run(b, 6000, 7000, true);
    CHECK(b.health == BH_OK && b.intact() && !b.eventPending, "signal found: OK, intact, no event");
    CHECK(strcmp(b.stateText(), "OK") == 0, "status text OK");
  }
  {
    BeamTracker b;
    uint32_t t = run(b, 0, 3000, true);
    CHECK(b.intact() && b.lastWindowPulses >= 9 && b.lastWindowPulses <= 11, "steady beam: about 10 pulses per 100 ms");
    t = run(b, t, t + 40, false);
    CHECK(b.intact() && !b.eventPending, "gap shorter than 60 ms: still intact");
    t = run(b, t, t + 200, false);
    CHECK(!b.intact() && b.eventPending, "beam blocked: broken, one event");
    CHECK(strcmp(b.stateText(), "BRK") == 0 && !b.faulty(), "status text BRK, not a fault");
    b.eventPending = false;
    t = run(b, t, t + 300, true);
    t = run(b, t, t + 200, false);
    CHECK(!b.eventPending, "second break within 2 s: same crossing, no new event");
    t = run(b, t, t + 3000, true);
    t = run(b, t, t + 200, false);
    CHECK(b.eventPending, "break 3 s later: new event");
    b.eventPending = false;
    t = run(b, t, t + 31000, false);
    CHECK(b.health == BH_STUCK && b.faulty(), "blocked for 30 s: STUCK (fault)");
    t = run(b, t, t + 500, true);
    CHECK(b.health == BH_OK && b.intact() && !b.eventPending, "beam back: OK again, no event");
  }
  {
    BeamTracker b;
    uint32_t t = run(b, 0, 2000, true);
    t = run(b, t, t + 1500, false, true);
    CHECK(b.health == BH_STUCK, "OUT held LOW for over 1 s: STUCK (wiring fault)");
  }
  {
    BeamTracker b;
    b.addTrigger(1000);
    CHECK(b.recentCount(5000, 20000) == 1, "one break: 1/2, a warning");
    b.addTrigger(9000);
    CHECK(b.recentCount(15000, 20000) >= BEAM_REPEATS, "two breaks inside 20 s: zone 4 intrusion");
    CHECK(b.recentCount(26000, 20000) == 1, "older breaks drop out of the 20 s window");
    b.clearWindow();
    CHECK(!b.recent(26000, 20000), "clearWindow forgets them");
  }
  printf("%s (%d checks, %d failed)\n", fails ? "SOME TESTS FAILED" : "ALL TESTS PASSED", checks, fails);
  return fails ? 1 : 0;
}
