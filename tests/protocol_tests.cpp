#include <openssl/evp.h>
#include <cstdio>
#include "link_protocol.h"
#include "mesh.h"
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
  TrackResult tr=t->accept(p); if(tr==TR_REPLAY||tr==TR_DUP||tr==TR_OLD_BOOT||tr==TR_UNSYNCED) return R_REPLAY;
  return ACCEPT;
}
int main(){
  printf("Packet size %zu bytes (ESP-NOW max 250)\n\n", sizeof(LinkPacket));
  CHECK(sizeof(LinkPacket)<=250, "Packet fits in one ESP-NOW frame");

  printf("\n-- structure --\n");
  LinkPacket s=mk(NODE_GATEWAY,NODE_MOD_A,L_ACK,G1,1,0,K_AGW);
  CHECK(linkWellFormed(s,sizeof(s)), "Good packet is well-formed");
  CHECK(!linkWellFormed(s,sizeof(s)-1), "Wrong length rejected");
  LinkPacket v=s; v.version=3; CHECK(!linkWellFormed(v,sizeof(v)), "Old protocol version (v5 boards) rejected");
  v=s; v.type=0; CHECK(!linkWellFormed(v,sizeof(v)), "Unknown type 0 rejected");
  v=s; v.type=L_TYPE_MAX+1; CHECK(!linkWellFormed(v,sizeof(v)), "Unknown type 14 rejected");
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
  CHECK(moduleA(mk(NODE_SERVER,NODE_MOD_A,L_CMD,5,1,MY_BOOT,K_AGW,CMD_DISARM,R_OPERATOR))==R_UNKNOWN, "server talking to A directly: unknown sender");
  CHECK(moduleA(mk(NODE_MOD_B,NODE_MOD_A,L_PEER_EVENT,BB1,1,MY_BOOT,K_AB,2))==R_REPLAY, "Peer event before B's HELLO: waits (not acted on)");
  CHECK(moduleA(mk(NODE_MOD_B,NODE_MOD_A,L_HELLO,BB1,2,0,K_AB))==ACCEPT, "Module B HELLO: link syncs");
  CHECK(moduleA(mk(NODE_MOD_B,NODE_MOD_A,L_PEER_EVENT,BB1,3,MY_BOOT,K_AB,2))==ACCEPT, "Peer zone-2 event from B: accepted");
  CHECK(moduleA(mk(NODE_MOD_B,NODE_MOD_A,L_PEER_EVENT,BB1,3,MY_BOOT,K_AB,2))==R_REPLAY, "Replayed peer event (fake corroboration): rejected");
  CHECK(moduleA(mk(NODE_MOD_B,NODE_MOD_A,L_PEER_ALARM,BB1,4,0x1234,K_AB))==R_STALE, "Old peer alarm from before A restarted: rejected");
  CHECK(moduleA(mk(NODE_MOD_B,NODE_MOD_A,L_PEER_ALARM,BB1,5,MY_BOOT,K_BGW))==R_SIG, "Peer alarm signed with wrong key: rejected");
  CHECK(moduleA(mk(NODE_GATEWAY,NODE_MOD_A,L_STATUS,G2,1,0,K_AGW))==R_REPLAY, "Gateway new boot without HELLO: rejected");
  CHECK(moduleA(mk(NODE_GATEWAY,NODE_MOD_A,L_HELLO,G2,1,0,K_AGW))==ACCEPT, "Gateway restart announced by HELLO: accepted");
  CHECK(moduleA(mk(NODE_GATEWAY,NODE_MOD_A,L_CMD,G2,2,MY_BOOT,K_AGW,CMD_ARM,R_OPERATOR))==ACCEPT, "Command after gateway restart: accepted");
  CHECK(moduleA(mk(NODE_GATEWAY,NODE_MOD_A,L_HELLO,G1,1,0,K_AGW))==R_REPLAY, "Recorded HELLO from the OLD gateway boot: rejected");
  CHECK(moduleA(mk(NODE_GATEWAY,NODE_MOD_A,L_CMD,G1,40,MY_BOOT,K_AGW,CMD_DISARM,R_OPERATOR))==R_REPLAY, "...so a recorded DISARM from that boot stays rejected");
  CHECK(moduleA(mk(NODE_GATEWAY,NODE_MOD_A,L_CMD,G2,3,MY_BOOT,K_AGW,CMD_ARM,R_OPERATOR))==ACCEPT, "Real gateway traffic still accepted after that attack");
  CHECK(bootIsNewer(makeBootId(1,0),makeBootId(65535,0)), "Boot counter wrap-around (65535 -> 1) handled");
  { PeerTracker fresh;                              // we just restarted
    CHECK(fresh.accept(mk(NODE_GATEWAY,NODE_MOD_A,L_STATUS,G2,50,0,K_AGW))==TR_UNSYNCED, "After OUR restart: plain packets wait for the sender's HELLO");
    CHECK(fresh.accept(mk(NODE_GATEWAY,NODE_MOD_A,L_HELLO,G2,51,0,K_AGW))==TR_SYNCED, "...the HELLO syncs the link");
    CHECK(fresh.accept(mk(NODE_GATEWAY,NODE_MOD_A,L_HELLO,G1,52,0,K_AGW))==TR_OLD_BOOT, "...a recorded HELLO from an older boot is refused (told apart in the log)");
    CHECK(fresh.accept(mk(NODE_GATEWAY,NODE_MOD_A,L_STATUS,G2,53,0,K_AGW))==TR_OK, "...and real traffic carries on"); }


  printf("\n-- out-of-order and duplicate packets (relay copies) --\n");
  { PeerTracker w; const uint32_t B = makeBootId(3, 0x77);
    CHECK(w.accept(mk(NODE_MOD_C,NODE_MOD_A,L_HELLO,B,10,0,K_AB))==TR_SYNCED, "HELLO syncs");
    CHECK(w.accept(mk(NODE_MOD_C,NODE_MOD_A,L_STATUS,B,14,0,K_AB))==TR_OK, "Packet 14 (13..11 lost or still on the relay)");
    CHECK(w.accept(mk(NODE_MOD_C,NODE_MOD_A,L_STATUS,B,12,0,K_AB))==TR_LATE, "Packet 12 arrives late through the relay: accepted once");
    CHECK(w.accept(mk(NODE_MOD_C,NODE_MOD_A,L_STATUS,B,12,0,K_AB))==TR_DUP, "...its second copy is a duplicate: dropped quietly");
    CHECK(w.accept(mk(NODE_MOD_C,NODE_MOD_A,L_STATUS,B,14,0,K_AB))==TR_DUP, "Newest packet again (straight + relayed copy): dropped");
    CHECK(w.accept(mk(NODE_MOD_C,NODE_MOD_A,L_STATUS,B,60,0,K_AB))==TR_OK, "Jump ahead to 60");
    CHECK(w.accept(mk(NODE_MOD_C,NODE_MOD_A,L_STATUS,B,29,0,K_AB))==TR_LATE, "29 is 31 back: still inside the 32-packet window");
    CHECK(w.accept(mk(NODE_MOD_C,NODE_MOD_A,L_STATUS,B,28,0,K_AB))==TR_REPLAY, "28 is 32 back: too old, refused as a replay");
    CHECK(w.accept(mk(NODE_MOD_C,NODE_MOD_A,L_STATUS,B,14,0,K_AB))==TR_REPLAY, "An old recorded packet: refused"); }

  printf("\n-- the site: zones and walls --\n");
  CHECK(zonePartner(1,NODE_MOD_A)==NODE_MOD_D && zonePartner(1,NODE_MOD_D)==NODE_MOD_A, "Zone 1 = wall A-D");
  CHECK(zonePartner(2,NODE_MOD_A)==NODE_MOD_B && zonePartner(2,NODE_MOD_B)==NODE_MOD_A, "Zone 2 = wall A-B");
  CHECK(zonePartner(3,NODE_MOD_B)==NODE_MOD_C && zonePartner(3,NODE_MOD_C)==NODE_MOD_B, "Zone 3 = wall B-C");
  CHECK(zonePartner(3,NODE_MOD_A)==NODE_NONE && zonePartner(4,NODE_MOD_C)==NODE_NONE, "A is not on wall B-C; there is no zone 4 (wall C-D)");
  CHECK(zonesOf(NODE_MOD_A)==0b011 && zonesOf(NODE_MOD_B)==0b110, "A stands on zones 1+2, B on zones 2+3");
  CHECK(zonesOf(NODE_MOD_C)==0b100 && zonesOf(NODE_MOD_D)==0b001, "C on zone 3, D on zone 1");
  CHECK((zonesOf(NODE_MOD_A)&zoneBit(1)) && !(zonesOf(NODE_MOD_B)&zoneBit(1)), "Buzzers: zone 1 alarm sounds A, not B");
  CHECK((zonesOf(NODE_MOD_B)&zoneBit(3)) && !(zonesOf(NODE_MOD_A)&zoneBit(3)), "Buzzers: zone 3 alarm sounds B, not A");
  CHECK((zonesOf(NODE_MOD_A)&zoneBit(2)) && (zonesOf(NODE_MOD_B)&zoneBit(2)), "Buzzers: zone 2 alarm sounds A and B");

  printf("\n-- the mesh: routes and relays --\n");
  { static const uint8_t K_AC[32]={0xAC}, K_CG[32]={0xC9}, K_AD[32]={0xAD}, K_BG2[32]={0xB9};
    static const uint8_t MA[6]={2,0,0,0,0,1}, MB[6]={2,0,0,0,0,2}, MC[6]={2,0,0,0,0,3}, MD[6]={2,0,0,0,0,4}, MG[6]={2,0,0,0,0,9};
    // Module A's view
    MeshPeer aG(NODE_GATEWAY,"Gateway",MG,K_AGW), aB(NODE_MOD_B,"Module B",MB,K_AB), aC(NODE_MOD_C,"Module C",MC,K_AC), aD(NODE_MOD_D,"Module D",MD,K_AD);
    MeshPeer* aPeers[]={&aG,&aB,&aC,&aD}; Mesh meshA(NODE_MOD_A,aPeers,4);
    // The gateway's view
    MeshPeer gA(NODE_MOD_A,"Module A",MA,K_AGW), gB(NODE_MOD_B,"Module B",MB,K_BG2), gC(NODE_MOD_C,"Module C",MC,K_CG), gD(NODE_MOD_D,"Module D",MD,K_AD);
    MeshPeer* gPeers[]={&gA,&gB,&gC,&gD}; Mesh meshG(NODE_GATEWAY,gPeers,4);
    for (MeshPeer* P : gPeers) P->macSet = true;
    g_millis = 100000;
    // A hears G, B, D straight and they hear A; A and C can't hear each other.
    for (MeshPeer* P : {&aG,&aB,&aD}) { P->directAt=g_millis; P->trk.online=true; P->rssi=-60; }
    aG.theirMesh = meshBit(NODE_MOD_A)|meshBit(NODE_MOD_B)|meshBit(NODE_MOD_C)|meshBit(NODE_MOD_D);
    aB.theirMesh = meshBit(NODE_MOD_A)|meshBit(NODE_GATEWAY)|meshBit(NODE_MOD_C);
    aD.theirMesh = meshBit(NODE_MOD_A)|meshBit(NODE_GATEWAY);
    aC.theirMesh = meshBit(NODE_MOD_B)|meshBit(NODE_MOD_D)|meshBit(NODE_GATEWAY); aC.trk.online=true;
    CHECK(meshA.mask()==(meshBit(NODE_GATEWAY)|meshBit(NODE_MOD_B)|meshBit(NODE_MOD_D)), "A's mesh byte: hears G, B and D directly");
    CHECK(meshA.directOk(aB) && !meshA.directOk(aC), "A-B works both ways; A-C does not");
    CHECK(meshA.chooseRoute(aB)==0, "Packets for B go straight");
    CHECK(meshA.chooseRoute(aC)==NODE_GATEWAY, "Packets for C go through the gateway (hears both, in the middle)");
    aG.theirMesh &= ~meshBit(NODE_MOD_C);
    CHECK(meshA.chooseRoute(aC)==NODE_MOD_B, "Gateway loses C too: through B instead");
    aG.theirMesh |= meshBit(NODE_MOD_C);
    CHECK(meshA.chooseRoute(aC)==NODE_MOD_B, "Gateway hears C again: stays with B while B works (no flapping)");
    char net[6]; meshA.netText(net);
    CHECK(strcmp(net,"*DbDD")==0, "A's status NET field: *DbDD (C relayed through b)");
    aD.theirMesh = meshBit(NODE_GATEWAY);           // D stopped hearing A
    CHECK(!meshA.directOk(aD), "One-way link (D no longer hears A): not used straight");
    CHECK(meshA.chooseRoute(aD)==NODE_GATEWAY, "...relayed until both ways work");
    aD.theirMesh |= meshBit(NODE_MOD_A);
    CHECK(meshA.chooseRoute(aD)==0, "Both ways again: straight");
    aB.cutUntil = g_millis + 60000;
    CHECK(!meshA.hears(aB) && meshA.chooseRoute(aB)==NODE_GATEWAY, "Relay test: A-B cut for 60 s -> through the gateway");
    g_millis += 61000; for (MeshPeer* P : {&aG,&aB,&aD}) P->directAt=g_millis;
    CHECK(!meshA.isCut(aB) && meshA.chooseRoute(aB)==0, "Test over: straight again");
    g_millis += 3000;
    CHECK(meshA.mask()==0, "Nothing heard straight for 3 s: every direct link counts as down");

    // A -> C through G: signed with the A-C key, which G does not hold
    LinkPacket ac=mk(NODE_MOD_A,NODE_MOD_C,L_PEER_ALARM,BB1,7,0x5555,K_AC,0b010,0,3,"A-Z2 + B-Z2");
    ac.via=NODE_GATEWAY; linkSign(K_AC,32,ac,ac.sig);
    CHECK(meshG.forwardTo(ac,MA)==&gC, "Gateway passes A's packet on to C");
    CHECK(verify(ac,K_AC), "C checks it with the A-C key: genuine, end to end");
    LinkPacket t2=ac; t2.code=0; CHECK(!verify(t2,K_AC), "Relay changes the zones in transit: C rejects it");
    t2=ac; t2.via=0; CHECK(!verify(t2,K_AC), "Relay pretends it came straight from A: C rejects it");
    LinkPacket forged=mk(NODE_MOD_A,NODE_MOD_C,L_PEER_ALARM,BB1,8,0x5555,K_CG,0b001); forged.via=NODE_GATEWAY; linkSign(K_CG,32,forged,forged.sig);
    CHECK(!verify(forged,K_AC), "Relay makes up an alarm 'from A' with its own key: C rejects it");
    CHECK(meshG.forwardTo(ac,MB)==nullptr, "Copy that didn't come straight from A (MAC of B): not passed on");
    LinkPacket other=ac; other.via=NODE_MOD_B; CHECK(meshG.forwardTo(other,MA)==nullptr, "Packet naming another relay: not passed on");
    other=ac; other.dst=NODE_SERVER; CHECK(meshG.forwardTo(other,MA)==nullptr, "Relay to a board outside the mesh: refused");
    other=ac; other.dst=NODE_MOD_A; CHECK(meshG.forwardTo(other,MA)==nullptr, "Sender = receiver: refused");
    gC.cutUntil = g_millis + 10000; CHECK(meshG.forwardTo(ac,MA)==nullptr, "Relay test cuts G-C: G doesn't relay to C either"); gC.cutUntil = 0;
    int passed=0; for (int i=0;i<100;i++) if (meshG.forwardTo(ac,MA)) passed++;
    CHECK(passed>=39 && passed<=41, "Flood of 100 relay requests at once: only 40 passed on (rate limit)");
    g_millis += 1000; CHECK(meshG.forwardTo(ac,MA)==&gC, "A second later: relaying again");
    CHECK(sizeof(LinkPacket)==206, "Packet is 206 bytes (fits ESP-NOW's 250)"); }

  printf("\n-- PC link (gateway <-> server) --\n");
  static const uint8_t K_PC[32] = {5,5,5};
  LinkPacket pc=mk(NODE_SERVER,NODE_GATEWAY,L_PC_CMD,BB1,1,0x6060,K_PC,CMD_DISARM,R_NONE);
  pc.session=0x1234; pc.target=TARGET_ALL; linkSign(K_PC,32,pc,pc.sig);
  CHECK(linkWellFormed(pc,sizeof(pc)), "PC command packet (type 13) is well-formed");
  v=pc; v.type=L_TYPE_MAX+1; CHECK(!linkWellFormed(v,sizeof(v)), "Type 14 rejected");
  CHECK(linkNeedsFreshness(L_PC_CMD) && linkNeedsFreshness(L_LOGIN_RESP), "PC commands and login answers are tied to the gateway's boot");
  CHECK(!linkNeedsFreshness(L_LOGIN_REQ), "Login request needs no boot binding (answered with a fresh challenge)");
  t=pc; t.session=0x1235; CHECK(!verify(t,K_PC), "Session ID changed in transit: rejected");
  t=pc; t.target=NODE_MOD_A; CHECK(!verify(t,K_PC), "Target changed in transit (all -> A only): rejected");
  CHECK(!verify(pc,K_AGW), "PC packet checked with a module key: rejected");

  printf("\n-- PC login (challenge-response) --\n");
  uint8_t h[32]; PKCS5_PBKDF2_HMAC("admin123",8,(const unsigned char*)"p13-pc:admin",12,100000,EVP_sha256(),32,h);
  CHECK(strcmp(toHex(h,32).c_str(),"7493b37e4df180c408885fd146df4792281b6b15d66e213397c9bcc8132f5e2e")==0, "Stored admin hash (gateway secrets.h) = PBKDF2(admin123, 100000 rounds)");
  uint8_t nonce[16]; for(int i=0;i<16;i++) nonce[i]=i;
  uint8_t msg[21]; memcpy(msg,nonce,16); memcpy(msg+16,"admin",5);
  uint8_t r[32]; hmacSha256(h,32,msg,21,r);
  CHECK(strcmp(toHex(r,32).c_str(),"a2b6c14afdbb735e3a3e7bb323dfca377f28d1ecbeab6f0c1a2a842b5dccf092")==0, "Gateway's expected answer matches the PC-side reference (Python)");
  uint8_t back[32]; CHECK(fromHex(String("a2b6c14afdbb735e3a3e7bb323dfca377f28d1ecbeab6f0c1a2a842b5dccf092"),back,32) && memcmp(back,r,32)==0, "Hex round trip");
  CHECK(!fromHex(String("abc"),back,32), "Hex of the wrong length rejected");
  CHECK(!fromHex(String("zzb6c14afdbb735e3a3e7bb323dfca377f28d1ecbeab6f0c1a2a842b5dccf092"),back,32), "Hex with a bad character rejected");
  uint8_t r2[32]; nonce[0]^=1; memcpy(msg,nonce,16); hmacSha256(h,32,msg,21,r2);
  CHECK(memcmp(r,r2,32)!=0, "A different challenge needs a different answer (old answers useless)");
  CHECK(strcmp(modStateShort(MS_INTRUSION),"ALM")==0 && strcmp(modStateShort(99),"?? ")==0, "Module state names for the gateway LCD");
  printf("\n-- ESP-NOW encryption keys --\n");
  uint8_t a[16],b[16],x[16]; linkLmk(K_AGW,32,a); linkLmk(K_AGW,32,b); linkLmk(K_BGW,32,x);
  CHECK(memcmp(a,b,16)==0, "Both ends derive the same encryption key from a link key");
  CHECK(memcmp(a,x,16)!=0, "Different links get different encryption keys");
  printf("\n%s (%d failed)\n", fails?"SOME TESTS FAILED":"ALL TESTS PASSED", fails);
  return fails;
}
