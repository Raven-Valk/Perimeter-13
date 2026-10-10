// =====================================================================
//  mesh.h  —  the radio mesh (firmware 6.0). IDENTICAL in Gateway/ and SensorModule/.
//
//  Five radios: modules A, B, C, D and the gateway. Each one talks straight to
//  the other four (a full mesh: 10 links, each with its own key).
//
//  Every packet carries the sender's "mesh" byte: which boards it hears
//  directly right now. From that each board knows, for every link, whether it
//  works BOTH ways. When the direct link to a board fails, packets for it also
//  go through a third board (a relay) that hears both ends:
//
//      A --x-- C        A sends to C straight (in case it comes back) AND
//       \     /         through G with via = G. G passes it on unchanged.
//        \   /          C accepts whichever copy arrives first and drops the
//          G            other (each sequence number is accepted once).
//
//  The relay can't read or fake what it carries: the packet is signed with the
//  A<->C key, which G doesn't have, and the radio hops are encrypted per link
//  (A->G with the A<->G key, G->C with the G<->C key). One hop only: a board
//  only passes on packets that name it as `via` and come straight from the sender.
// =====================================================================
#pragma once
#include "link_protocol.h"

// The "mesh" byte: bit 0..3 = modules A..D, bit 4 = gateway.
inline uint8_t meshBit(uint8_t node) {
  return isModule(node) ? 1 << (node - 1) : node == NODE_GATEWAY ? 1 << 4 : 0;
}
const uint8_t MESH_SIZE = 5;
const uint8_t MESH_ORDER[MESH_SIZE] = { NODE_MOD_A, NODE_MOD_B, NODE_MOD_C, NODE_MOD_D, NODE_GATEWAY };

// One link: what this board knows about one other board.
struct MeshPeer {
  uint8_t        node;
  const char*    name;
  const uint8_t* mac;
  const uint8_t* key;              // the signing key of this link
  PeerTracker    trk;              // replay protection; trk.online = heard (any way) recently
  bool           macSet = false;
  bool           encrypted = false;
  uint32_t       beats = 0;
  uint32_t       lastKick = 0;     // last HELLO sent to nudge it after a restart
  int8_t         rssi = 0;         // signal of its last packet that came straight from it
  uint32_t       directAt = 0;     // when a good packet last came straight from it
  uint8_t        theirMesh = 0;    // who IT hears directly (from its newest packet)
  uint8_t        state = 0xFF;     // its state and priority (from its newest packet)
  uint8_t        prio = 0;
  uint8_t        route = 0;        // how our packets reach it: 0 = straight, else the relay's node
  uint8_t        loggedRoute = 0;  // the route last written to the log
  uint32_t       routeSince = 0;   // when the route last changed (logged once it has held 2 s)
  uint32_t       cutUntil = 0;     // relay test: direct link treated as broken until then (0 = no test)
  MeshPeer(uint8_t n, const char* nm, const uint8_t* m, const uint8_t* k) : node(n), name(nm), mac(m), key(k) {}
};

class Mesh {
public:
  Mesh(uint8_t me_, MeshPeer* const* peers_, uint8_t count_) : me(me_), peers(peers_), count(count_) {}

  uint32_t directTimeout = 2500;   // no packet straight from a board for this long: direct link down
  uint32_t forwarded = 0;          // packets passed on for other boards
  uint32_t forwardDropped = 0;     // ... and refused by the rate limit

  MeshPeer* find(uint8_t node) const {
    for (uint8_t i = 0; i < count; i++) if (peers[i]->node == node) return peers[i];
    return nullptr;
  }
  bool isCut(const MeshPeer& P) const { return P.cutUntil && notYet(P.cutUntil); }

  // We hear P directly (and the link isn't cut for a test).
  bool hears(const MeshPeer& P) const {
    return !isCut(P) && P.directAt && millis() - P.directAt <= directTimeout;
  }
  // The direct link works both ways: we hear P, and P's newest packet says it hears us.
  bool directOk(const MeshPeer& P) const { return hears(P) && (P.theirMesh & meshBit(me)); }

  uint8_t mask() const {                                   // our "mesh" byte
    uint8_t m = 0;
    for (uint8_t i = 0; i < count; i++) if (hears(*peers[i])) m |= meshBit(peers[i]->node);
    return m;
  }

  // Picks how packets for T travel. 0 = straight; else a board that we and T
  // both reach directly. Keeps the current relay while it works, then prefers
  // the gateway (in the middle of the site), then the strongest signal.
  uint8_t chooseRoute(MeshPeer& T) {
    if (directOk(T)) { T.route = 0; return 0; }
    uint8_t best = 0;
    int bestScore = -10000;
    for (uint8_t i = 0; i < count; i++) {
      MeshPeer& R = *peers[i];
      if (&R == &T || !directOk(R) || !(R.theirMesh & meshBit(T.node))) continue;
      int score = R.rssi ? R.rssi : -90;
      if (R.node == T.route)      score += 15;
      if (R.node == NODE_GATEWAY) score += 5;
      if (score > bestScore) { bestScore = score; best = R.node; }
    }
    T.route = best;
    return best;
  }

  // After a packet from P passed every check: remember what it tells us.
  void heard(MeshPeer& P, const LinkPacket& p, TrackResult tr, int8_t rssi) {
    if (p.via == 0) {                                      // came straight from P
      P.directAt = millis() ? millis() : 1;
      if (rssi) P.rssi = rssi;
    }
    if (tr != TR_LATE) { P.theirMesh = p.mesh; P.state = p.state; P.prio = p.priority; }
  }

  // A packet not addressed to us: should we pass it on, and to whom?
  // Only when it names us as `via`, came straight from its sender (fromMac,
  // real boards), and both ends are boards of this mesh. Rate-limited.
  MeshPeer* forwardTo(const LinkPacket& p, const uint8_t* fromMac) {
    if (p.via != me || p.dst == me || p.src == me || p.src == p.dst) return nullptr;
    MeshPeer* S = find(p.src);
    MeshPeer* D = find(p.dst);
    if (!S || !D || isCut(*S) || isCut(*D)) return nullptr;
    if (fromMac && S->macSet && memcmp(fromMac, S->mac, 6) != 0) return nullptr;
    uint32_t now = millis(), el = now - tokenAt;           // token bucket: 40 packets, one more every 25 ms
    if (el >= 1000)    { tokens = 40; tokenAt = now; }
    else if (el >= 25) { tokens += el / 25; if (tokens > 40) tokens = 40; tokenAt += el / 25 * 25; }
    if (tokens < 1) { forwardDropped++; return nullptr; }
    tokens--;
    forwarded++;
    return D;
  }

  // One character per board, in the order A B C D G, for the status line:
  //   '*' this board   'D' direct both ways   'a'..'d','g' relayed through that board
  //   '?' heard, but no working route back yet   '-' not heard at all
  char netChar(uint8_t node) const {
    if (node == me) return '*';
    const MeshPeer* P = find(node);
    if (!P || !P->trk.online) return '-';
    if (directOk(*P)) return 'D';
    if (P->route) return (char)(nodeLetter(P->route) - 'A' + 'a');
    return '?';
  }
  void netText(char out[MESH_SIZE + 1]) const {
    for (uint8_t i = 0; i < MESH_SIZE; i++) out[i] = netChar(MESH_ORDER[i]);
    out[MESH_SIZE] = 0;
  }

  const uint8_t me;
private:
  MeshPeer* const* peers;
  const uint8_t count;
  uint32_t tokens = 40, tokenAt = 0;    // relay rate limit
};
