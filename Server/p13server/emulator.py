"""A stand-in for the gateway and both sensor modules, for working on the
dashboard without hardware. It speaks the real protocol: signed packets,
replay protection, challenge-response login with the demo accounts, roles,
command results, log numbering and re-sends.

Run in-process:   python -m p13server --emulate
Run over MQTT:    python tools/gateway_emulator.py   (connects to Mosquitto as the gateway)

The dashboard says "emulated gateway" while this is in use. It is a test tool:
the module behaviour is simplified (no PIR timing, no keypads).
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import os
import random
import time
from dataclasses import dataclass, field
from typing import Callable

from .protocol import (TARGET_BOTH, Cmd, Node, Packet, PacketError, PeerTracker, Result, Role, Track,
                       Type, decode, make_boot_id, needs_freshness, verify)

# Gateway/secrets.h demo accounts: PBKDF2-HMAC-SHA256(password, "p13-pc:" + user, 100000)
DEMO_USERS = {
    "operator": ("cb2517ca1d99b7b0997600a15363346a1edbce5213da77ca8da4be00a0135a6b", Role.OPERATOR),
    "admin": ("7493b37e4df180c408885fd146df4792281b6b15d66e213397c9bcc8132f5e2e", Role.MAINTENANCE),
}
ROLE_NEEDED = {Cmd.ARM: Role.OPERATOR, Cmd.DISARM: Role.OPERATOR, Cmd.ACK_ALARM: Role.OPERATOR,
               Cmd.MAINT_END: Role.OPERATOR, Cmd.MAINT_START: Role.MAINTENANCE, Cmd.CLEAR_FAULT: Role.MAINTENANCE,
               Cmd.SET_TIME: Role.NONE, Cmd.RESEND_LOG: Role.NONE}
CMD_NAMES = {Cmd.ARM: "ARM", Cmd.DISARM: "DISARM", Cmd.MAINT_START: "MAINT", Cmd.MAINT_END: "MAINT_END",
             Cmd.ACK_ALARM: "ACK_ALARM", Cmd.CLEAR_FAULT: "CLEAR_FAULT", Cmd.SET_TIME: "SET_TIME",
             Cmd.RESEND_LOG: "RESEND_LOG", Cmd.LOGOUT: "LOGOUT"}
SESSION_IDLE, SESSION_MAX = 300, 1800
# For demos and tests: how often something moves (seconds) and how often a wall
# trigger is confirmed by the other module (0..1).
SCENE_EVERY = float(os.environ.get("P13_EMULATOR_INTERVAL", "45"))
CONFIRM_CHANCE = float(os.environ.get("P13_EMULATOR_CONFIRM", "0.35"))


def _prio(state: str) -> int:
    return {"INTRUSION": 2, "TAMPER_FAULT": 3}.get(state, 0)


@dataclass
class EmuModule:
    letter: str
    gw: "EmulatedGateway"
    state: str = "BOOT"
    log_no: int = 0
    armed_mode: bool = False
    warning_until: float = 0.0
    maint_until: float = 0.0
    lid_open: bool = False
    rssi: int = field(default_factory=lambda: random.randint(-62, -48))

    @property
    def peer(self) -> str:
        return "B" if self.letter == "A" else "A"

    @property
    def priority(self) -> int:
        p = _prio(self.state)
        return 1 if p == 0 and time.time() < self.warning_until else p

    def log(self, typ: str, event: str, zone: str = "-", result: str = "-", prio: int | None = None,
            user: str = "-", at: float | None = None) -> None:
        self.log_no += 1
        unix = int(at) if at else self.gw.unix()
        uptime = int((time.monotonic() - self.gw.started) * 1000) if not at else 0
        p = self.priority if prio is None else prio
        line = (f"{self.log_no},{self.gw.boot_no},{uptime},{unix},{self.letter},P{p},{self.state},{typ},"
                f"{event.replace(',', ';')},{zone},{user},{result}")
        self.gw.store_line(line)

    def go(self, state: str, reason: str) -> None:
        old, self.state = self.state, state
        self.log("STATE", f"{old}->{state} ({reason})")

    def status_text(self) -> str:
        wall = "WARMUP" if self.state == "BOOT" else "OK"
        return (f"{self.letter},{self.state},P{self.priority},WALL:{wall},SIDE:{wall},"
                f"LID:{'OPEN' if self.lid_open else 'SHUT'},LCD:OK,PEER:UP,LOCK:0,LOGNO:{self.log_no},"
                f"CH:{self.gw.channel},RSSI:{self.rssi + random.randint(-2, 2)}")

    def apply(self, cmd: int, role: int, who: str, arg: int) -> tuple[int, str]:
        """Module-side checks, as SensorModule.ino applyCommand()."""
        need = ROLE_NEEDED.get(cmd)
        if need is None:
            return Result.BAD, "Unknown command"
        if role < need:
            why = f"Needs {Role(need).name}"
            self.log("CMD", f"{CMD_NAMES[cmd]} denied: {why}", result="DENIED", user=who)
            return Result.DENIED, why
        res, why = Result.OK, ""
        s = self.state
        if cmd == Cmd.ARM:
            if s == "ARMED":
                why = "Already armed"
            elif s != "DISARMED":
                res, why = Result.REFUSED, f"Not possible in {s}"
            elif self.lid_open:
                res, why = Result.REFUSED, "Lid open"
            else:
                self.armed_mode = True
                self.go("ARMED", f"armed by {who}")
        elif cmd == Cmd.DISARM:
            if s == "DISARMED":
                why = "Already disarmed"
            elif s == "TAMPER_FAULT":
                res, why = Result.REFUSED, "Clear the fault first"
            elif s == "MAINTENANCE":
                res, why = Result.REFUSED, "End maintenance first"
            else:
                self.armed_mode = False
                if s == "INTRUSION":
                    self.log("ALERT", "Intrusion acknowledged by disarm", result="ACK", prio=2, user=who)
                self.go("DISARMED", f"disarmed by {who}")
        elif cmd == Cmd.MAINT_START:
            secs = max(30, min(arg or 300, 900))
            if s == "MAINTENANCE":
                self.maint_until, why = time.time() + secs, "Extended"
            elif s not in ("ARMED", "DISARMED", "TAMPER_FAULT"):
                res, why = Result.REFUSED, f"Not possible in {s}"
            else:
                self.maint_until = time.time() + secs
                self.go("MAINTENANCE", f"maintenance {secs} s by {who}")
        elif cmd == Cmd.MAINT_END:
            if s != "MAINTENANCE":
                res, why = Result.REFUSED, "Not in maintenance"
            else:
                self.go("RECOVERY", f"maintenance ended by {who}")
        elif cmd == Cmd.ACK_ALARM:
            if s != "INTRUSION":
                res, why = Result.REFUSED, "No alarm to acknowledge"
            else:
                self.log("ALERT", "Intrusion acknowledged", result="ACK", prio=2, user=who)
                self.go("RECOVERY", f"acknowledged by {who}")
        elif cmd == Cmd.CLEAR_FAULT:
            if s != "TAMPER_FAULT":
                res, why = Result.REFUSED, "No fault to clear"
            elif self.lid_open:
                res, why = Result.REFUSED, "Lid open"
            else:
                self.go("RECOVERY", f"fault cleared by {who}")
        msg = CMD_NAMES[cmd] + (f": {why}" if why else "")
        self.log("CMD", msg, result=Result(res).name, user=who)
        return res, why

    def tick(self) -> None:
        now = time.time()
        if self.state == "BOOT" and time.monotonic() - self.gw.started > 4:
            self.log("TEST", "Self-test OK", result="PASS")
            self.go("ARMED" if self.armed_mode else "DISARMED", "warm-up done")
        elif self.state == "RECOVERY":
            self.log("TEST", "Recovery self-test OK", result="PASS")
            self.go("ARMED" if self.armed_mode else "DISARMED", "recovered")
        elif self.state == "MAINTENANCE" and now > self.maint_until:
            self.log("MAINT", "Session timed out")
            self.go("RECOVERY", "maintenance timeout")


class EmulatedGateway:
    """Gateway.ino, reduced to what the server can observe."""

    def __init__(self, key: bytes, send: Callable[[bytes], None], *, scenario: bool = True, history: bool = True):
        self.key = key
        self.send_bytes = send
        self.scenario = scenario
        self.boot_no = (int(time.time()) // 10) & 0xFFFF     # goes up on every start, like the gateway's counter
        self.boot_id = make_boot_id(self.boot_no, random.getrandbits(16))
        self.seq = 0
        self.beats = 0
        self.started = time.monotonic()
        self.channel = 11
        self.server = PeerTracker()
        self.server_heard = 0.0
        self.server_online = False
        self.gw_no = 0
        self.lines: dict[int, str] = {}
        self.queue: list[int] = []
        self.resend: list[int] = []
        self.time_base: float | None = None
        self.chal: tuple[str, bytes, float] | None = None
        self.last_chal = 0.0
        self.session: dict | None = None
        self.fails = 0
        self.locked_until = 0.0
        self.mods = {"A": EmuModule("A", self), "B": EmuModule("B", self)}
        self.next_scene = time.monotonic() + min(12, SCENE_EVERY)
        if history:
            self._history()
        self.glog("SYSTEM", f"Boot #{self.boot_no} reason=POWER_ON")
        self.glog("TEST", "Gateway self-test OK", result="PASS")
        for m in self.mods.values():
            m.log("SYSTEM", f"Boot #{self.boot_no} reason=POWER_ON saved=DISARMED disarmed")

    # ---------------- log ----------------
    def unix(self) -> int:
        return int(time.time()) if self.time_base else 0

    def store_line(self, line: str) -> None:
        self.gw_no += 1
        self.lines[self.gw_no] = line
        self.queue.append(self.gw_no)
        if len(self.queue) > 32:            # the gateway's queue: oldest dropped, the server asks again
            self.queue.pop(0)

    def glog(self, typ: str, event: str, zone: str = "-", result: str = "-", prio: int = 0, user: str = "-",
             at: float | None = None) -> None:
        no = self.gw_no + 1
        unix = int(at) if at else self.unix()
        uptime = 0 if at else int((time.monotonic() - self.started) * 1000)
        self.store_line(f"{no},{self.boot_no},{uptime},{unix},G,P{prio},READY,{typ},{event.replace(',', ';')},"
                        f"{zone},{user},{result}")

    def _history(self) -> None:
        """A plausible past day, so a fresh dashboard has something to show."""
        t = time.time() - 26 * 3600
        a, b = self.mods["A"], self.mods["B"]
        steps = [
            (0, lambda at: self.glog("SYSTEM", "Boot #40 reason=POWER_ON", at=at)),
            (40, lambda at: self.glog("COMM", "Server link connected (TLS)", at=at)),
            (900, lambda at: self.glog("AUTH", "Card + PIN accepted", result="SUCCESS", user="Operator1@GW **:BE:EF", at=at)),
            (905, lambda at: self.glog("CMD", "ARM sent to A+B", result="SENT", user="Operator1@GW", at=at)),
            (906, lambda at: a.log("STATE", "DISARMED->ARMED (armed by Operator1@GW)", at=at)),
            (906, lambda at: b.log("STATE", "DISARMED->ARMED (armed by Operator1@GW)", at=at)),
            (907, lambda at: self.glog("CMD", "ARM: A:OK B:OK", result="OK", user="Operator1@GW", at=at)),
            (14400, lambda at: a.log("ALERT", "Motion warning 1/3", zone="A-SIDE", prio=1, at=at)),
            (31000, lambda at: b.log("ALERT", "Motion warning 1/3", zone="B-WALL", prio=1, at=at)),
            (31002, lambda at: a.log("ALERT", "Motion seen by Module B", zone="B-WALL", prio=1, at=at)),
            (31009, lambda at: a.log("ALERT", "Intrusion: B-WALL + A-WALL", zone="A-WALL", prio=2, at=at)),
            (31009, lambda at: b.log("ALERT", "Module A confirmed: B-WALL + A-WALL", prio=2, at=at)),
            (31120, lambda at: self.glog("AUTH", "Dashboard login (OPERATOR)", result="SUCCESS", user="operator@web", at=at)),
            (31131, lambda at: self.glog("CMD", "ACK_ALARM: A:OK B:OK", result="OK", user="operator@web", at=at)),
            (52000, lambda at: self.glog("AUTH", "Card + PIN refused", result="FAIL", user="card **:9A:01@GW", at=at)),
            (52010, lambda at: self.glog("AUTH", "Card + PIN refused", result="FAIL", user="card **:9A:01@GW", at=at)),
            (61200, lambda at: self.glog("CMD", "DISARM: A:OK B:OK", result="OK", user="Operator1@GW", at=at)),
            (61200, lambda at: a.log("STATE", "ARMED->DISARMED (disarmed by Operator1@GW)", at=at)),
            (61200, lambda at: b.log("STATE", "ARMED->DISARMED (disarmed by Operator1@GW)", at=at)),
            (88000, lambda at: self.glog("SYSTEM", "Power off", at=at)),
        ]
        for offset, fn in steps:
            fn(t + offset)
        self.queue.clear()          # old lines: the server fetches them with RESEND_LOG

    # ---------------- packets ----------------
    def send(self, ptype: int, *, code: int = 0, arg: int = 0, result: int = 0, role: int = 0, session: int = 0,
             text: str = "", log_no: int = 0, state: int = 1) -> None:
        self.seq += 1
        p = Packet(Node.GATEWAY, Node.SERVER, ptype, boot_id=self.boot_id, seq=self.seq,
                   dst_boot=self.server.boot_id if self.server.synced else 0, log_no=log_no, state=state,
                   priority=self.system_priority(), code=code, role=role, result=result, arg=arg & 0xFFFFFFFF,
                   session=session, text=text)
        self.send_bytes(p.encode(self.key))

    def on_bytes(self, data: bytes) -> None:
        try:
            p, body = decode(data)
        except PacketError:
            return
        if p.dst != Node.GATEWAY or p.src != Node.SERVER or not verify(self.key, body, p.sig):
            return
        if p.dst_boot != self.boot_id:
            self.server.send_hello = True
        if needs_freshness(p.type) and p.dst_boot != self.boot_id:
            return
        tr = self.server.accept(p)
        if tr in (Track.UNSYNCED, Track.REPLAY, Track.OLD_BOOT):
            return
        if tr == Track.NEW_BOOT:
            self.end_session("server restarted", notify=True)
        self.server_heard = time.monotonic()
        if not self.server_online:
            self.server_online = True
            self.glog("COMM", "Server link UP")
        if p.type == Type.LOGIN_REQ:
            self.on_login_req(p.text)
        elif p.type == Type.LOGIN_RESP:
            self.on_login_resp(p.text)
        elif p.type == Type.PC_CMD:
            self.on_command(p)

    # ---------------- login ----------------
    def on_login_req(self, user: str) -> None:
        now = time.monotonic()
        if now - self.last_chal < 1:
            return
        self.last_chal = now
        if now < self.locked_until:
            self.send(Type.LOGIN_RESULT, result=Result.DENIED, text=f"Locked {int(self.locked_until - now)} s")
            return
        nonce = os.urandom(16)
        self.chal = (user.strip()[:31], nonce, now + 30)
        self.send(Type.LOGIN_CHAL, text=nonce.hex())

    def on_login_resp(self, text: str) -> None:
        user, _, answer = text.rpartition(":")
        now = time.monotonic()
        if now < self.locked_until:
            self.send(Type.LOGIN_RESULT, result=Result.DENIED, text=f"Locked {int(self.locked_until - now)} s")
            return
        ok, role = False, Role.NONE
        if self.chal and self.chal[0] == user and now < self.chal[2] and user in DEMO_USERS:
            pw_hex, role = DEMO_USERS[user]
            expect = hmac.new(bytes.fromhex(pw_hex), self.chal[1] + user.encode()[:32], hashlib.sha256).hexdigest()
            ok = hmac.compare_digest(expect, answer)
        self.chal = None
        who = f"{user or '?'}@web"
        if ok:
            self.fails = 0
            if self.session:
                self.end_session("new login", notify=False)
            self.session = {"id": random.getrandbits(32) | 1, "user": user, "role": role, "last": now, "start": now}
            self.glog("AUTH", f"Dashboard login ({Role(role).name})", result="SUCCESS", user=who)
            self.send(Type.LOGIN_RESULT, result=Result.OK, role=role, session=self.session["id"], text=f"Welcome {user}")
            return
        self.fails += 1
        self.glog("AUTH", "Dashboard login failed", result="FAIL", user=who)
        if self.fails >= 3:
            self.fails = 0
            self.locked_until = now + 60
            self.glog("AUTH", "Dashboard login locked 60 s", result="LOCKED", prio=1)
            self.send(Type.LOGIN_RESULT, result=Result.DENIED, text="Locked 60 s")
        else:
            self.send(Type.LOGIN_RESULT, result=Result.DENIED, text=f"Wrong user or password, {3 - self.fails} tries left")

    def end_session(self, why: str, notify: bool) -> None:
        if not self.session:
            return
        self.glog("AUTH", f"Dashboard session ended ({why})", user=f"{self.session['user']}@web")
        self.session = None
        if notify and self.server_online:
            self.send(Type.LOGIN_RESULT, result=Result.DENIED, text=f"Session ended: {why}")

    # ---------------- commands ----------------
    def on_command(self, p: Packet) -> None:
        cmd, seq = p.code, p.seq
        if cmd == Cmd.LOGOUT:
            mine = bool(self.session and self.session["id"] == p.session)
            if mine:
                self.end_session("logout", notify=False)
            self.send(Type.CMD_RESULT, code=cmd, arg=seq, result=Result.OK if mine else Result.REFUSED,
                      text="Logged out" if mine else "No session")
            return
        if cmd == Cmd.SET_TIME:
            first = self.time_base is None
            self.time_base = p.arg
            if first:
                self.glog("SYSTEM", "Real time received from server")
            self.send(Type.CMD_RESULT, code=cmd, arg=seq, result=Result.OK, text="Time set")
            return
        if cmd == Cmd.RESEND_LOG:
            self.resend = [n for n in sorted(self.lines) if n >= p.arg][:3000]
            self.send(Type.CMD_RESULT, code=cmd, arg=seq, result=Result.OK, text="Resending")
            return
        if not self.session or self.session["id"] != p.session:
            self.glog("CMD", f"{CMD_NAMES.get(cmd, '?')} from dashboard refused: not logged in", result="DENIED",
                      user="?@web")
            self.send(Type.CMD_RESULT, code=cmd, arg=seq, result=Result.DENIED, text="Not logged in")
            return
        self.session["last"] = time.monotonic()
        role, who = self.session["role"], f"{self.session['user']}@web"
        need = ROLE_NEEDED.get(cmd)
        if need is None:
            self.report(cmd, seq, Result.BAD, "Unknown command", who)
            return
        if role < need:
            self.report(cmd, seq, Result.DENIED, f"Needs {Role(need).name}", who)
            return
        if p.target == Node.GATEWAY:
            self.report(cmd, seq, Result.REFUSED if cmd == Cmd.CLEAR_FAULT else Result.BAD,
                        "No gateway tamper" if cmd == Cmd.CLEAR_FAULT else "Not a gateway command", who)
            return
        letters = {TARGET_BOTH: "AB", Node.MOD_A: "A", Node.MOD_B: "B"}.get(p.target)
        if not letters:
            self.report(cmd, seq, Result.BAD, "Unknown target", who)
            return
        self.glog("CMD", f"{CMD_NAMES[cmd]} sent to {'A+B' if len(letters) == 2 else letters}", result="SENT", user=who)
        overall, parts = Result.OK, []
        for ch in letters:
            res, why = self.mods[ch].apply(cmd, role, who, p.arg)
            parts.append(f"{ch}:{'OK' if res == Result.OK else (why or Result(res).name)}")
            if res != Result.OK and overall == Result.OK:
                overall = res
        self.report(cmd, seq, overall, " ".join(parts), who)

    def report(self, cmd: int, seq: int, res: int, text: str, who: str) -> None:
        self.glog("CMD", f"{CMD_NAMES.get(cmd, '?')}: {text}", result=Result(res).name, user=who)
        self.send(Type.CMD_RESULT, code=cmd, arg=seq, result=res, text=text)

    # ---------------- the running box ----------------
    def system_priority(self) -> int:
        return max((m.priority for m in self.mods.values()), default=0)

    def scene(self) -> None:
        """Now and then something moves along the wall."""
        armed = [m for m in self.mods.values() if m.state == "ARMED"]
        if not armed:
            return
        m = random.choice(armed)
        zone = random.choice(["WALL", "WALL", "SIDE"]) if CONFIRM_CHANCE < 1 else "WALL"
        m.warning_until = time.time() + 20
        m.log("ALERT", "Motion warning 1/3", zone=f"{m.letter}-{zone}", prio=1)
        if zone == "WALL":
            other = self.mods[m.peer]
            if other.state == "ARMED":
                other.warning_until = time.time() + 20
                other.log("ALERT", f"Motion seen by Module {m.letter}", zone=f"{m.letter}-WALL", prio=1)
            if random.random() < CONFIRM_CHANCE and other.state == "ARMED":
                why = f"{m.letter}-WALL + {other.letter}-WALL"
                other.log("ALERT", f"Intrusion: {why}", zone=f"{other.letter}-WALL", prio=2)
                other.go("INTRUSION", why)
                m.log("ALERT", f"Module {other.letter} confirmed: {why}", prio=2)
                m.go("INTRUSION", f"Module {other.letter} alarm")

    async def run(self) -> None:
        tick = 0
        while True:
            await asyncio.sleep(0.02)
            tick += 1
            now = time.monotonic()
            if self.server_online and now - self.server_heard > 8:
                self.server_online = False
                self.end_session("server link lost", notify=False)
                self.glog("COMM", "Server link DOWN")
            if self.session and (now - self.session["last"] > SESSION_IDLE or now - self.session["start"] > SESSION_MAX):
                self.end_session("idle 5 min" if now - self.session["last"] > SESSION_IDLE else "30 min limit", notify=True)
            if tick % 50 == 0:                              # every second: three status packets
                for m in self.mods.values():
                    m.tick()
                if self.scenario and now > self.next_scene:
                    self.next_scene = now + random.uniform(SCENE_EVERY * 0.6, SCENE_EVERY * 1.4)
                    self.scene()
                self.beats += 1
                hello = self.beats % 10 == 1 or self.server.send_hello
                self.server.send_hello = False
                kind = Type.HELLO if hello else Type.STATUS
                sess = self.session["user"] if self.session else "-"
                g = (f"G,READY,P{self.system_priority()},RFID:OK,LCD:OK,LID:SHUT,USER:{sess},"
                     f"TIME:{'Y' if self.time_base else 'N'},KPLOCK:0,PCLOCK:{max(0, int(self.locked_until - now))},"
                     f"LOGNO:{self.gw_no},WIFI:-51,CH:{self.channel},FW:5.4 (emulated)")
                self.send(kind, code=Node.GATEWAY, arg=self.unix(), text=g)
                for node, m in ((Node.MOD_A, self.mods["A"]), (Node.MOD_B, self.mods["B"])):
                    self.send(kind, code=node, arg=self.unix(), text=m.status_text())
            elif self.server_online:
                if self.queue:
                    n = self.queue.pop(0)
                    self.send(Type.LOG, log_no=n, text=self.lines[n])
                elif self.resend:
                    n = self.resend.pop(0)
                    self.send(Type.LOG, code=1, log_no=n, text=self.lines[n])

