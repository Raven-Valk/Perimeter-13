#include <cstdio>
#include <vector>
#include <map>
#include "win.h"
int fails=0;
#define CHECK(c,msg) do{ bool ok=(c); printf("%-66s %s\n", msg, ok?"PASS":"FAIL"); if(!ok) fails++; }while(0)
// Mirrors onModuleLog's store rule: store only if not already had
struct Sim { ModuleView m; std::map<uint32_t,int> stored;
  void line(uint32_t n){ if(!n||m.win.has(n)) return; m.win.mark(n); if(n>m.top) m.top=n; stored[n]++; }
  bool dup(){ for(auto&kv:stored) if(kv.second>1) return true; return false; } };
int main(){
  { Sim s; s.m.win.reset(101); s.m.top=100;              // gateway knew lines up to 100
    for(uint32_t n=117;n<=140;n++) s.line(n);              // module queue kept only 117-140
    s.m.top=140;
    CHECK(lowestMissing(s.m,140)==101 && missingRunEnd(s.m,101,140)==116, "Queue overflow: asks for exactly 101-116");
    for(uint32_t n=101;n<=140;n++) s.line(n);              // module re-sends 101..140 (overlap)
    CHECK(!s.dup() && s.stored.size()==40, "...re-send fills the gap, no line stored twice (reviewer 3a)");
    CHECK(lowestMissing(s.m,140)==0, "...nothing missing afterwards"); }
  { Sim s; s.m.win.reset(1);
    for(uint32_t n=1;n<=100;n++) s.line(n);
    for(uint32_t n=102;n<=149;n++) s.line(n);             // 101 lost
    for(uint32_t n=151;n<=160;n++) s.line(n);             // 150 lost
    CHECK(lowestMissing(s.m,160)==101 && missingRunEnd(s.m,101,160)==101, "Two gaps: first request is just line 101");
    s.line(101);
    CHECK(lowestMissing(s.m,160)==150 && missingRunEnd(s.m,150,160)==150, "...then just line 150 (no 102-149 again)");
    for(uint32_t n=101;n<=160;n++) s.line(n);
    CHECK(!s.dup() && s.stored.size()==160, "...even a wide re-send stores nothing twice (reviewer 3b)"); }
  { Sim s; s.m.win.reset(51); s.m.top=50;                // after a gateway reboot: had up to 50
    for(uint32_t n=40;n<=60;n++) s.line(n);
    CHECK(s.stored.size()==10 && s.stored.begin()->first==51, "After a gateway restart, lines it already had are not stored again (3c)"); }
  { Sim s; s.m.win.reset(1);
    for(uint32_t n=1;n<=5000;n++) if(n%97) s.line(n);     // every 97th line missing
    uint32_t lm=lowestMissing(s.m,5000);
    CHECK(lm==97*((5000-1023+96)/97), "Window slides: only the last 1024 lines are checked");
    CHECK(s.m.win.has(3000)==true && s.m.win.has(4946)==true && s.m.win.has(4947)==false, "Old lines count as 'have', recent missing ones don't");
    CHECK(!s.dup(), "...and still nothing stored twice"); }
  { Sim s; s.m.win.reset(1); s.line(1); s.line(5000);    // huge jump
    CHECK(s.m.win.has(5000) && !s.m.win.has(4999) && s.m.win.base==5000-1023, "A huge jump resets the window cleanly"); }
  printf("\n%s (%d failed)\n", fails?"SOME TESTS FAILED":"ALL TESTS PASSED", fails); return fails; }
