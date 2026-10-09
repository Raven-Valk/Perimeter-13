"""The server's Python packet code against the firmware's C++ link_protocol.h.

Run by run_tests.sh. Each check builds or verifies the same packet both ways.
"""
import os
import random
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "Server"))
from p13server import protocol as P  # noqa: E402

HELPER = os.path.join(HERE, "interop_helper")
fails = 0


def check(ok, msg):
    global fails
    print(f"{msg:<64} {'PASS' if ok else 'FAIL'}")
    if not ok:
        fails += 1


def run(*args, stdin=None):
    out = subprocess.run([HELPER, *map(str, args)], input=stdin, capture_output=True, text=True, check=True).stdout
    return out.rstrip("\n")


rng = random.Random(13)
key = bytes(rng.randrange(256) for _ in range(32))
texts = ["", "A,ARMED,P0,WALL:OK,SIDE:OK,LID:SHUT,LCD:OK,PEER:UP,LOCK:0,LOGNO:55,CH:11",
         "1042,7,183220,1760000000,A,P2,ARMED,ALERT,Intrusion: B-WALL + A-WALL,A-WALL,-,-", "x" * 200]

# 1. C++ signs, Python decodes and verifies
for i, text in enumerate(texts):
    f = [10, 9, rng.randrange(1, 14), rng.getrandbits(32), rng.getrandbits(32), rng.getrandbits(32),
         rng.getrandbits(32), rng.randrange(256), rng.randrange(4), rng.randrange(256), rng.randrange(256),
         rng.randrange(3), rng.randrange(4), rng.getrandbits(32), rng.getrandbits(32), rng.randrange(256)]
    raw = bytes.fromhex(run("sign", key.hex(), *f, text))
    p, body = P.decode(raw)
    ok = P.verify(key, body, p.sig) and [p.src, p.dst, p.type, p.boot_id, p.seq, p.dst_boot, p.log_no, p.state,
                                         p.priority, p.reset_reason, p.code, p.role, p.result, p.arg, p.session,
                                         p.target] == f and p.text == text[:160]
    check(ok, f"C++ packet {i} decodes and verifies in Python")
    check(not P.verify(bytes(32), body, p.sig), f"C++ packet {i} fails with the wrong key")

# 2. Python signs, C++ verifies
for i, text in enumerate(texts):
    p = P.Packet(P.Node.SERVER, P.Node.GATEWAY, P.Type.PC_CMD, boot_id=rng.getrandbits(32), seq=i + 1,
                 dst_boot=rng.getrandbits(32), code=P.Cmd.ARM, target=P.TARGET_BOTH, session=rng.getrandbits(32),
                 arg=rng.getrandbits(32), text=text)
    raw = p.encode(key)
    out = run("verify", key.hex(), raw.hex())
    fields = out.split(" ", 18)
    got_text = fields[18] if len(fields) > 18 else ""
    ok = (fields[0] == "OK" and int(fields[1]) == P.Node.SERVER and int(fields[3]) == P.Type.PC_CMD
          and int(fields[4]) == p.boot_id and int(fields[15]) == p.session and int(fields[17]) == len(text[:160])
          and got_text == text[:160])
    check(ok, f"Python packet {i} verifies in C++")
    tampered = bytearray(raw); tampered[30] ^= 1
    check(run("verify", key.hex(), tampered.hex()) == "BAD sig", f"Python packet {i}, one bit flipped: C++ rejects")

# 3. Login answer: what the server sends equals what the gateway computes
for user in ["admin", "operator", "u" * 40]:
    pw = P.password_hash(user, "correct horse")
    nonce = os.urandom(16)
    check(P.login_response(pw, nonce, user) == run("login", pw.hex(), nonce.hex(), user), f"login answer matches the gateway ({user[:12]})")

# 4. Replay tracker: same decisions on a long random sequence (incl. boot counter wrap)
seq_lines, py = [], P.PeerTracker()
boots = [P.make_boot_id(n, rng.getrandbits(16)) for n in (1, 2, 2, 3, 65535, 0, 1)]
decisions = []
for _ in range(3000):
    t = rng.choice([1, 2, 2, 2, 3])
    b = rng.choice(boots)
    s = rng.randrange(1, 60)
    seq_lines.append(f"{t} {b} {s}")
    decisions.append(int(py.accept(P.Packet(10, 9, t, boot_id=b, seq=s))))
cpp = [int(x) for x in run("track", stdin="\n".join(seq_lines)).split()]
check(cpp == decisions, "replay tracker: 3000 random packets, identical decisions")

print("ALL TESTS PASSED (0 failed)" if not fails else f"{fails} FAILED")
sys.exit(1 if fails else 0)
