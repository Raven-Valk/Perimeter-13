#include <cstdio>
#include "link_protocol.h"
static const uint8_t K_AGW[32] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32};
static const uint8_t K_BGW[32] = {9,9,9};
static const uint8_t K_AB[32]  = {7,7,7};
int fails=0;
#define CHECK(c,msg) do{ bool ok=(c); printf("%-64s %s\n", msg, ok?"PASS":"FAIL"); if(!ok) fails++; }while(0)
LinkPacket mk(uint8_t src,uint8_t dst,uint8_t type,uint32_t boot,uint32_t seq,uint32_t dstBoot,const uint8_t* key,
              uint8_t code=0,uint8_t role=0,uint32_t arg=0,const char* txt="Operator1@KEYPAD"){
  LinkPacket p={}; p.version=LINK_VERSION; p.src=src; p.dst=dst; p.type=type; p.bootId=boot; p.seq=seq; p.dstBoot=dstBoot;
  p.code=code; p.role=role; p.arg=arg; p.textLen=strlen(txt); memcpy(p.text,txt,p.textLen); linkSign(key,32,p,p.sig); return p; }
bool verify(const LinkPacket& p,const uint8_t* key){ uint8_t e[SIG_LEN]; linkSign(key,32,p,e); return sameBytes(e,p.sig,SIG_LEN); }

// Same acceptance order as SensorModule.ino handlePacket() for Module A
enum Verdict { ACCEPT, IGNORE, R_MALFORMED, R_UNKNOWN, R_SIG, R_REPLAY, R_STALE };
const uint32_t MY_BOOT = 0xA0A0A0A0;
const uint32_t G1 = makeBootId(5, 0x1111), G2 = makeBootId(6, 0x2222), BB1 = makeBootId(9, 0x3333);
PeerTracker gwT, peerT;
Verdict moduleA(const LinkPacket& p, int len=sizeof(LinkPacket)){
  if(!linkWellFormed(p,len)) return R_MALFORMED;
  if(p.dst!=NODE_MOD_A) return IGNORE;
  const uint8_t* key; PeerTracker* t;
  if(p.src==NODE_GATEWAY){key=K_AGW;t=&gwT;} else if(p.src==NODE_MOD_B){key=K_AB;t=&peerT;} else return R_UNKNOWN;
  if(!verify(p,key)) return R_SIG;
  if(linkNeedsFreshness(p.type) && p.dstBoot!=MY_BOOT) return R_STALE;
  if(t->accept(p)==TR_REPLAY) return R_REPLAY;
  return ACCEPT;
}
int main(){
  printf("Packet size %zu bytes (ESP-NOW max 250)\n\n", sizeof(LinkPacket));
  CHECK(sizeof(LinkPacket)<=250, "Packet fits in one ESP-NOW frame");

  printf("\n-- structure --\n");
  LinkPacket s=mk(NODE_GATEWAY,NODE_MOD_A,L_ACK,G1,1,0,K_AGW);
  CHECK(linkWellFormed(s,sizeof(s)), "Good packet is well-formed");
  CHECK(!linkWellFormed(s,sizeof(s)-1), "Wrong length rejected");
  LinkPacket v=s; v.version=2; CHECK(!linkWellFormed(v,sizeof(v)), "Old protocol version (v4 boards) rejected");
  v=s; v.type=0; CHECK(!linkWellFormed(v,sizeof(v)), "Unknown type 0 rejected");
  v=s; v.type=L_TYPE_MAX+1; CHECK(!linkWellFormed(v,sizeof(v)), "Unknown type 9 rejected");
  v=s; v.textLen=LINK_TEXT_MAX+1; CHECK(!linkWellFormed(v,sizeof(v)), "Text length over 160 rejected");

  printf("\n-- signatures (one key per link) --\n");
  LinkPacket c=mk(NODE_GATEWAY,NODE_MOD_A,L_CMD,G1,2,MY_BOOT,K_AGW,CMD_DISARM,R_OPERATOR);
  CHECK(verify(c,K_AGW), "Gateway->A command with A-GW key: accepted");
  CHECK(!verify(c,K_BGW), "Same packet checked with B-GW key: rejected");
  LinkPacket f=mk(NODE_GATEWAY,NODE_MOD_A,L_CMD,G1,2,MY_BOOT,K_BGW,CMD_DISARM,R_OPERATOR);
  CHECK(!verify(f,K_AGW), "Module B (or its stolen key) faking gateway->A: rejected");
  LinkPacket fab=mk(NODE_GATEWAY,NODE_MOD_A,L_CMD,G1,2,MY_BOOT,K_AB,CMD_DISARM,R_OPERATOR);
  CHECK(!verify(fab,K_AGW), "Peer-link key used to fake a gateway command: rejected");
  LinkPacket t=c; t.dst=NODE_MOD_B; CHECK(!verify(t,K_AGW), "Command redirected from A to B in transit: rejected");
  t=c; t.src=NODE_MOD_B; CHECK(!verify(t,K_AGW), "Sender changed in transit: rejected");
  t=c; t.role=R_MAINTENANCE; CHECK(!verify(t,K_AGW), "Role raised OPERATOR->MAINTENANCE in transit: rejected");
  t=c; t.code=CMD_MAINT_START; CHECK(!verify(t,K_AGW), "Command changed DISARM->MAINT in transit: rejected");
  t=c; t.arg=900; CHECK(!verify(t,K_AGW), "Argument changed in transit: rejected");
  t=c; t.dstBoot^=1; CHECK(!verify(t,K_AGW), "Boot binding changed in transit: rejected");
  t=c; t.text[0]='X'; CHECK(!verify(t,K_AGW), "User name changed in transit: rejected");

  printf("\n-- Module A's receive pipeline --\n");
  CHECK(moduleA(mk(NODE_GATEWAY,NODE_MOD_A,L_HELLO,G1,1,0,K_AGW))==ACCEPT, "Gateway HELLO: accepted (link syncs)");
  CHECK(moduleA(mk(NODE_GATEWAY,NODE_MOD_A,L_CMD,G1,2,MY_BOOT,K_AGW,CMD_ARM,R_OPERATOR))==ACCEPT, "Fresh signed ARM: accepted");
  CHECK(moduleA(mk(NODE_GATEWAY,NODE_MOD_A,L_CMD,G1,2,MY_BOOT,K_AGW,CMD_ARM,R_OPERATOR))==R_REPLAY, "Same ARM packet sent again: replay rejected");
  CHECK(moduleA(mk(NODE_GATEWAY,NODE_MOD_A,L_CMD,G1,3,0xDEAD,K_AGW,CMD_DISARM,R_OPERATOR))==R_STALE, "DISARM recorded before A restarted (old boot): rejected");
  CHECK(moduleA(mk(NODE_GATEWAY,NODE_MOD_A,L_CMD,G1,4,0,K_AGW,CMD_DISARM,R_OPERATOR))==R_STALE, "Command with unknown boot (0): rejected");
  CHECK(moduleA(mk(NODE_GATEWAY,NODE_MOD_A,L_ACK,G1,5,0,K_AGW))==ACCEPT, "Plain ACK needs no boot binding: accepted");
  CHECK(moduleA(mk(NODE_GATEWAY,NODE_MOD_B,L_CMD,G1,6,MY_BOOT,K_BGW,CMD_DISARM,R_OPERATOR))==IGNORE, "Packet for Module B: ignored by A");
  CHECK(moduleA(mk(NODE_DONGLE,NODE_MOD_A,L_CMD,5,1,MY_BOOT,K_AGW,CMD_DISARM,R_OPERATOR))==R_UNKNOWN, "PC dongle talking to A directly: unknown sender");
  CHECK(moduleA(mk(NODE_MOD_B,NODE_MOD_A,L_PEER_EVENT,BB1,1,MY_BOOT,K_AB,ZONE_WALL))==ACCEPT, "Peer WALL event from B: accepted");
  CHECK(moduleA(mk(NODE_MOD_B,NODE_MOD_A,L_PEER_EVENT,BB1,1,MY_BOOT,K_AB,ZONE_WALL))==R_REPLAY, "Replayed peer event (fake corroboration): rejected");
  CHECK(moduleA(mk(NODE_MOD_B,NODE_MOD_A,L_PEER_ALARM,BB1,2,0x1234,K_AB))==R_STALE, "Old peer alarm from before A restarted: rejected");
  CHECK(moduleA(mk(NODE_MOD_B,NODE_MOD_A,L_PEER_ALARM,BB1,3,MY_BOOT,K_BGW))==R_SIG, "Peer alarm signed with wrong key: rejected");
  CHECK(moduleA(mk(NODE_GATEWAY,NODE_MOD_A,L_STATUS,G2,1,0,K_AGW))==R_REPLAY, "Gateway new boot without HELLO: rejected");
  CHECK(moduleA(mk(NODE_GATEWAY,NODE_MOD_A,L_HELLO,G2,1,0,K_AGW))==ACCEPT, "Gateway restart announced by HELLO: accepted");
  CHECK(moduleA(mk(NODE_GATEWAY,NODE_MOD_A,L_CMD,G2,2,MY_BOOT,K_AGW,CMD_ARM,R_OPERATOR))==ACCEPT, "Command after gateway restart: accepted");
  CHECK(moduleA(mk(NODE_GATEWAY,NODE_MOD_A,L_HELLO,G1,1,0,K_AGW))==R_REPLAY, "Recorded HELLO from the OLD gateway boot: rejected");
  CHECK(moduleA(mk(NODE_GATEWAY,NODE_MOD_A,L_CMD,G1,40,MY_BOOT,K_AGW,CMD_DISARM,R_OPERATOR))==R_REPLAY, "...so a recorded DISARM from that boot stays rejected");
  CHECK(moduleA(mk(NODE_GATEWAY,NODE_MOD_A,L_CMD,G2,3,MY_BOOT,K_AGW,CMD_ARM,R_OPERATOR))==ACCEPT, "Real gateway traffic still accepted after that attack");
  CHECK(bootIsNewer(makeBootId(1,0),makeBootId(65535,0)), "Boot counter wrap-around (65535 -> 1) handled");

  printf("\n-- ESP-NOW encryption keys --\n");
  uint8_t a[16],b[16],x[16]; linkLmk(K_AGW,32,a); linkLmk(K_AGW,32,b); linkLmk(K_BGW,32,x);
  CHECK(memcmp(a,b,16)==0, "Both ends derive the same encryption key from a link key");
  CHECK(memcmp(a,x,16)!=0, "Different links get different encryption keys");
  printf("\n%s (%d failed)\n", fails?"SOME TESTS FAILED":"ALL TESTS PASSED", fails);
  return fails;
}
