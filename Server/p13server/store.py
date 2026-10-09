"""Everything the server keeps on disk: the system event log, its own audit
trail, and a few counters. One SQLite file, data/p13.db."""

from __future__ import annotations

import csv
import hashlib
import hmac
import io
import os
import sqlite3
import time
from pathlib import Path

from .protocol import parse_log_line

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    series      INTEGER NOT NULL,           -- +1 when the gateway's numbering restarts (flash erased)
    gw_no       INTEGER NOT NULL,           -- the gateway's line number
    log_no      INTEGER, boot INTEGER, uptime_ms INTEGER, unix_time INTEGER,
    module      TEXT, priority INTEGER, state TEXT, type TEXT, event TEXT,
    zone        TEXT, user TEXT, result TEXT,
    received_at REAL NOT NULL,
    resent      INTEGER NOT NULL DEFAULT 0,
    raw         TEXT NOT NULL,
    PRIMARY KEY (series, gw_no)
);
CREATE INDEX IF NOT EXISTS events_received ON events(received_at);
CREATE TABLE IF NOT EXISTS lost (series INTEGER, first INTEGER, last INTEGER, noted_at REAL);
CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT, at REAL NOT NULL,
    actor TEXT, ip TEXT, action TEXT NOT NULL, detail TEXT, outcome TEXT
);
CREATE TABLE IF NOT EXISTS viewers (               -- for signing in to view while the gateway is offline
    user TEXT PRIMARY KEY, role INTEGER NOT NULL, salt BLOB NOT NULL, verifier BLOB NOT NULL, updated REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT NOT NULL);
"""

EVENT_COLUMNS = ("gw_no", "log_no", "boot", "uptime_ms", "unix_time", "module", "priority", "state",
                 "type", "event", "zone", "user", "result", "received_at", "resent")


def _int(v: str | None, default: int = 0) -> int:
    try:
        return int(v)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default


class Store:
    def __init__(self, data_dir: Path):
        data_dir.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(data_dir / "p13.db", isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=NORMAL")
        self.db.executescript(SCHEMA)
        self.series = int(self.get("series", "1"))

    # ---------------- small key/value settings ----------------
    def get(self, k: str, default: str | None = None) -> str | None:
        row = self.db.execute("SELECT v FROM kv WHERE k=?", (k,)).fetchone()
        return row["v"] if row else default

    def put(self, k: str, v: str) -> None:
        self.db.execute("INSERT INTO kv(k, v) VALUES(?, ?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", (k, v))

    def next_boot_no(self) -> int:
        """The server's own restart counter: part of its boot ID, only ever goes up."""
        n = int(self.get("boot_no", "0")) + 1
        self.put("boot_no", str(n))
        return n

    # ---------------- the event log ----------------
    def new_series(self) -> None:
        self.series += 1
        self.put("series", str(self.series))

    def max_gw_no(self) -> int:
        row = self.db.execute("SELECT MAX(gw_no) AS m FROM events WHERE series=?", (self.series,)).fetchone()
        return row["m"] or 0

    def add_line(self, gw_no: int, line: str, resent: bool) -> dict | None:
        """Store one line. Returns it as a dict if it is new, None if we already had it."""
        f = parse_log_line(line) or {}
        row = {
            "gw_no": gw_no, "log_no": _int(f.get("log_no")), "boot": _int(f.get("boot")),
            "uptime_ms": _int(f.get("uptime_ms")), "unix_time": _int(f.get("unix_time")),
            "module": f.get("module", "?"), "priority": _int((f.get("priority") or "P0")[1:]),
            "state": f.get("state", ""), "type": f.get("type", ""), "event": f.get("event", line),
            "zone": f.get("zone", "-"), "user": f.get("user", "-"), "result": f.get("result", "-"),
            "received_at": time.time(), "resent": int(resent),
        }
        cur = self.db.execute(
            "INSERT OR IGNORE INTO events(series, gw_no, log_no, boot, uptime_ms, unix_time, module, priority,"
            " state, type, event, zone, user, result, received_at, resent, raw)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (self.series, gw_no, row["log_no"], row["boot"], row["uptime_ms"], row["unix_time"], row["module"],
             row["priority"], row["state"], row["type"], row["event"], row["zone"], row["user"], row["result"],
             row["received_at"], row["resent"], line))
        return row if cur.rowcount else None

    def have_numbers(self, low: int, high: int) -> set[int]:
        rows = self.db.execute("SELECT gw_no FROM events WHERE series=? AND gw_no BETWEEN ? AND ?",
                               (self.series, low, high))
        have = {r[0] for r in rows}
        for r in self.db.execute("SELECT first, last FROM lost WHERE series=? AND last>=? AND first<=?",
                                 (self.series, low, high)):
            have.update(range(max(r[0], low), min(r[1], high) + 1))
        return have

    def mark_lost(self, first: int, last: int) -> None:
        self.db.execute("INSERT INTO lost(series, first, last, noted_at) VALUES(?,?,?,?)",
                        (self.series, first, last, time.time()))

    def events(self, *, before: int | None = None, limit: int = 200, module: str | None = None,
               min_priority: int = 0, text: str | None = None, types: list[str] | None = None) -> list[dict]:
        sql = ["SELECT", ", ".join(EVENT_COLUMNS), "FROM events WHERE series=?"]
        args: list = [self.series]
        if before:
            sql.append("AND gw_no < ?"); args.append(before)
        if module:
            sql.append("AND module = ?"); args.append(module)
        if min_priority:
            sql.append("AND priority >= ?"); args.append(min_priority)
        if types:
            sql.append(f"AND type IN ({','.join('?' * len(types))})"); args += types
        if text:
            sql.append("AND (event LIKE ? ESCAPE '\\' OR user LIKE ? ESCAPE '\\' OR type LIKE ? ESCAPE '\\')")
            like = "%" + text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
            args += [like, like, like]
        sql.append("ORDER BY gw_no DESC LIMIT ?"); args.append(max(1, min(limit, 1000)))
        return [dict(r) for r in self.db.execute(" ".join(sql), args)]

    def events_csv(self) -> str:
        out = io.StringIO()
        w = csv.writer(out)
        w.writerow(("gw_no", "log_no", "boot", "uptime_ms", "unix_time", "module", "priority", "state",
                    "type", "event", "zone", "user", "result", "received_at_utc", "resent"))
        for r in self.db.execute("SELECT " + ", ".join(EVENT_COLUMNS) + " FROM events WHERE series=? ORDER BY gw_no",
                                 (self.series,)):
            row = list(r)
            row[13] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(row[13]))
            w.writerow(row)
        return out.getvalue()

    # ---------------- the server's own audit trail ----------------
    def audit(self, action: str, *, actor: str = "-", ip: str = "-", detail: str = "", outcome: str = "") -> dict:
        at = time.time()
        cur = self.db.execute("INSERT INTO audit(at, actor, ip, action, detail, outcome) VALUES(?,?,?,?,?,?)",
                              (at, actor, ip, action, detail, outcome))
        return {"id": cur.lastrowid, "at": at, "actor": actor, "ip": ip, "action": action,
                "detail": detail, "outcome": outcome}

    def audit_rows(self, limit: int = 100) -> list[dict]:
        return [dict(r) for r in self.db.execute("SELECT * FROM audit ORDER BY id DESC LIMIT ?", (limit,))]

    # ---------------- view-only sign-in while the gateway is offline ----------------
    # After the gateway accepts a password, the server keeps a salted hash OF the
    # gateway's password hash. That lets the same person sign in to *view* while
    # the gateway is unreachable. It cannot be used to log in to the gateway.
    def remember_viewer(self, user: str, role: int, pw_hash: bytes) -> None:
        salt = os.urandom(16)
        self.db.execute(
            "INSERT INTO viewers(user, role, salt, verifier, updated) VALUES(?,?,?,?,?)"
            " ON CONFLICT(user) DO UPDATE SET role=excluded.role, salt=excluded.salt,"
            " verifier=excluded.verifier, updated=excluded.updated",
            (user, role, salt, self._verifier(salt, pw_hash), time.time()))

    def check_viewer(self, user: str, pw_hash: bytes) -> int | None:
        row = self.db.execute("SELECT role, salt, verifier FROM viewers WHERE user=?", (user,)).fetchone()
        if row and hmac.compare_digest(self._verifier(row["salt"], pw_hash), row["verifier"]):
            return row["role"]
        return None

    @staticmethod
    def _verifier(salt: bytes, pw_hash: bytes) -> bytes:
        return hashlib.sha256(b"p13-view:" + salt + pw_hash).digest()
