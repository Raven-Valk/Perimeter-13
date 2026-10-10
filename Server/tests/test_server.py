"""Server tests: the gateway link and the web API, against the emulated gateway.

    cd Server && python3 -m unittest -v tests.test_server

No broker or hardware needed: packets go straight between the server's link
and the emulator, the same bytes they would carry over MQTT.
"""

from __future__ import annotations

import asyncio
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aiohttp.test_utils import TestClient, TestServer  # noqa: E402

from p13server.__main__ import DEMO_KEY  # noqa: E402
from p13server.config import Config  # noqa: E402
from p13server.emulator import EmulatedGateway  # noqa: E402
from p13server.gateway import GatewayLink  # noqa: E402
from p13server.hub import Hub  # noqa: E402
from p13server.protocol import Node, Packet, Type, decode  # noqa: E402
from p13server.store import Store  # noqa: E402
from p13server.web import Dashboard  # noqa: E402


def config(tmp: str) -> Config:
    return Config(site_id="test", mode="emulator", gateway_key=DEMO_KEY, mqtt_host="", mqtt_port=0,
                  mqtt_user="", mqtt_password="", web_host="127.0.0.1", web_port=0, tls_cert=None, tls_key=None,
                  session_hours=1, data_dir=Path(tmp))


class Rig:
    """Server link + emulator joined back to back, with a tap to drop or copy packets."""

    def __init__(self, tmp: str):
        self.cfg = config(tmp)
        self.store = Store(self.cfg.data_dir)
        self.hub = Hub()
        self.link = GatewayLink(self.cfg, self.store, self.hub)
        self.to_server: list[bytes] = []          # every packet the "gateway" sent
        self.drop_logs = False
        self.cut = False                          # True: nothing gets through either way
        loop = asyncio.get_running_loop()

        def gateway_sends(b: bytes) -> None:
            self.to_server.append(b)
            if self.cut:
                return
            p, _ = decode(b)
            if self.drop_logs and p.type == Type.LOG and p.code == 0:
                return
            loop.call_soon(self.link.on_bytes, b)

        self.emu = EmulatedGateway(self.cfg.gateway_key, send=gateway_sends, scenario=False)
        self.link.send_hook = lambda b: None if self.cut else loop.call_soon(self.emu.on_bytes, b)
        self.link.transport_up = True
        self.tasks = [asyncio.create_task(self.link.run()), asyncio.create_task(self.emu.run())]

    async def until(self, test, timeout: float = 10.0) -> None:
        for _ in range(int(timeout / 0.05)):
            if test():
                return
            await asyncio.sleep(0.05)
        raise AssertionError("timed out")

    def stop(self) -> None:
        for t in self.tasks:
            t.cancel()


class ServerTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.rig = Rig(self.tmp.name)
        await self.rig.until(lambda: self.rig.link.online)
        self.origin = None
        self.client = TestClient(TestServer(Dashboard(self.rig.cfg, self.rig.store, self.rig.hub, self.rig.link).app()))
        await self.client.start_server()
        self.origin = f"http://{self.client.server.host}:{self.client.server.port}"

    async def asyncTearDown(self):
        await self.client.close()
        self.rig.stop()
        self.tmp.cleanup()

    async def post(self, path, body, origin=True):
        headers = {"Origin": self.origin} if origin else {}
        r = await self.client.post(path, json=body, headers=headers)
        return r.status, await r.json()

    async def sign_in(self, user="admin", password="admin123"):
        await asyncio.sleep(1.1)                      # the gateway gives one challenge per second
        return await self.post("/api/session", {"user": user, "password": password})

    # ---------------- sign-in and roles ----------------
    async def test_wrong_password_is_refused_by_the_gateway(self):
        status, body = await self.sign_in("admin", "nope")
        self.assertEqual(status, 401)
        self.assertIn("tries left", body["error"])
        self.assertIsNone(self.rig.link.control)

    async def test_sign_in_then_arm_and_role_check(self):
        status, s = await self.sign_in("operator", "operator123")
        self.assertEqual(status, 200)
        self.assertTrue(s["control"])
        await self.rig.until(lambda: all(m.state == "DISARMED" for m in self.rig.emu.mods.values()))
        status, r = await self.post("/api/commands", {"command": "arm", "target": "all"})
        self.assertEqual((status, r["result"], r["text"]), (200, "OK", "A:OK B:OK C:OK D:OK"))
        self.assertEqual(self.rig.emu.mods["D"].state, "ARMED")
        status, r = await self.post("/api/commands", {"command": "maint_start", "target": "A", "seconds": 60})
        self.assertEqual(status, 403)                    # operators can't start maintenance

    async def test_requests_from_another_site_are_refused(self):
        await self.sign_in()
        status, _ = await self.post("/api/commands", {"command": "disarm"}, origin=False)
        self.assertEqual(status, 403)

    async def test_two_wrong_passwords_from_one_address_then_wait(self):
        await self.sign_in("admin", "nope")
        await self.sign_in("admin", "nope-again")
        status, body = await self.sign_in("admin", "admin123")
        self.assertEqual(status, 429)                    # this address can't use up the gateway's 3rd try
        self.assertGreater(self.rig.emu.fails, 0)
        self.assertEqual(self.rig.emu.locked_until, 0)   # and the gateway never locked

    async def test_link_drop_during_a_command_gives_a_clean_answer(self):
        await self.sign_in()
        self.rig.cut = True
        task = asyncio.create_task(self.post("/api/commands", {"command": "arm"}))
        await asyncio.sleep(0.3)
        self.rig.link._set_online(False, "test")
        status, r = await task
        self.assertEqual((status, r["result"]), (200, "OFFLINE"))

    async def test_sign_out_without_a_session(self):
        r = await self.client.delete("/api/session", headers={"Origin": self.origin})
        self.assertEqual(r.status, 401)

    async def test_api_needs_sign_in(self):
        r = await self.client.get("/api/events")
        self.assertEqual(r.status, 401)

    async def test_released_control_is_view_only(self):
        await self.sign_in()
        r = await self.client.delete("/api/control", headers={"Origin": self.origin})
        self.assertFalse((await r.json())["control"])
        status, _ = await self.post("/api/commands", {"command": "arm"})
        self.assertEqual(status, 409)
        await self.rig.until(lambda: self.rig.emu.session is None)

    async def test_session_ended_on_the_gateway_reaches_the_server(self):
        await self.sign_in()
        self.rig.emu.end_session("idle 5 min", notify=True)
        await self.rig.until(lambda: self.rig.link.control is None)

    async def test_view_only_sign_in_while_the_gateway_is_offline(self):
        await self.sign_in()                             # the server learns this account
        self.rig.cut = True
        self.rig.link._set_online(False, "test")
        status, s = await self.post("/api/session", {"user": "admin", "password": "admin123"})
        self.assertEqual(status, 200)
        self.assertFalse(s["control"])
        status, _ = await self.post("/api/session", {"user": "operator", "password": "operator123"})
        self.assertEqual(status, 503)                    # never signed in before: can't be checked

    # ---------------- four modules, zones, mesh ----------------
    async def test_status_of_all_five_boards_reaches_the_dashboard(self):
        await self.rig.until(lambda: all(self.rig.link.nodes[n].get("NET") for n in "GABCD")
                             and self.rig.link.nodes["D"].get("state") == "DISARMED")
        nodes = self.rig.link.nodes
        self.assertEqual(nodes["C"]["LID"], "NONE")                 # C and D: no tamper switch fitted
        self.assertEqual((nodes["A"].get("Z1"), nodes["A"].get("Z2"), nodes["D"].get("Z1")), ("OK", "OK", "OK"))
        self.assertEqual(nodes["A"]["NET"], "*DDDD")
        self.assertEqual(nodes["G"]["NET"], "DDDD*")

    async def test_relay_test_cuts_one_link_and_it_gets_relayed(self):
        await self.sign_in()
        await self.rig.until(lambda: self.rig.link.nodes["A"].get("NET"))
        status, r = await self.post("/api/commands", {"command": "test_cut", "link": "A-C", "seconds": 60})
        self.assertEqual((status, r["result"]), (200, "OK"), r)
        await self.rig.until(lambda: self.rig.link.nodes["A"].get("NET", "")[2:3] == "g")   # A -> C through G
        self.assertEqual(self.rig.link.nodes["C"]["NET"][0], "g")
        self.assertEqual(self.rig.link.nodes["A"].get("CUT"), "C")
        status, r = await self.post("/api/commands", {"command": "test_cut", "link": "D-G", "seconds": 30})
        self.assertEqual((status, r["result"]), (200, "OK"), r)
        self.assertIn("G-D cut", r["text"])
        status, _ = await self.post("/api/commands", {"command": "test_cut", "link": "A-A"})
        self.assertEqual(status, 400)
        status, _ = await self.post("/api/commands", {"command": "test_cut", "link": "A-C", "seconds": 999})
        self.assertEqual(status, 400)

    async def test_relay_test_needs_maintenance(self):
        await self.sign_in("operator", "operator123")
        status, _ = await self.post("/api/commands", {"command": "test_cut", "link": "A-B"})
        self.assertEqual(status, 403)

    async def test_wall_pair_confirms_then_any_pir_escalates(self):
        emu = self.rig.emu
        await self.rig.until(lambda: all(m.state == "DISARMED" for m in emu.mods.values()))
        for m in emu.mods.values():
            m.apply(1, 2, "test", 0)                                 # ARM
        emu.trigger(emu.mods["B"], 2)                                # B-Z2 alone: a warning
        self.assertEqual(emu.mods["B"].priority, 1)
        self.assertEqual(emu.mods["A"].state, "ARMED")
        emu.trigger(emu.mods["A"], 2)                                # A-Z2 within 20 s: intrusion, zone 2
        self.assertTrue(all(m.state == "INTRUSION" for m in emu.mods.values()))
        self.assertEqual(emu.mods["D"].alarm_zones, {2})
        emu.trigger(emu.mods["C"], 3)                                # one hit on wall B-C: escalates at once
        self.assertEqual(emu.mods["B"].alarm_zones, {2, 3})
        await self.rig.until(lambda: self.rig.link.nodes["B"].get("ALM") == "2+3")
        for m in emu.mods.values():
            m.apply(5, 1, "test", 0)                                 # ACK_ALARM
        for m in emu.mods.values():
            m.tick()
        self.assertTrue(all(m.state == "ARMED" for m in emu.mods.values()))
        emu.trigger(emu.mods["D"], 1)                                # after the ack: back to the normal rules
        self.assertEqual(emu.mods["D"].state, "ARMED")

    # ---------------- packets ----------------
    async def test_replayed_packet_is_refused(self):
        await asyncio.sleep(1.5)
        old = self.rig.to_server[-1]
        self.rig.link.on_bytes(old)
        self.assertEqual(self.rig.link.rejects["replay"], 1)

    async def test_forged_packet_is_refused(self):
        p = Packet(Node.GATEWAY, Node.SERVER, Type.STATUS, boot_id=self.rig.emu.boot_id, seq=10 ** 6,
                   dst_boot=self.rig.link.boot_id, code=Node.MOD_A, text="A,DISARMED,P0")
        self.rig.link.on_bytes(p.encode(bytes(32)))
        self.assertEqual(self.rig.link.rejects["signature"], 1)

    async def test_stale_answer_is_refused(self):
        p = Packet(Node.GATEWAY, Node.SERVER, Type.LOGIN_RESULT, boot_id=self.rig.emu.boot_id, seq=10 ** 6,
                   dst_boot=self.rig.link.boot_id ^ 1, result=0, session=5, text="Welcome")
        self.rig.link.on_bytes(p.encode(DEMO_KEY))
        self.assertEqual(self.rig.link.rejects["stale"], 1)
        self.assertIsNone(self.rig.link.control)

    async def test_lost_log_lines_are_fetched_again(self):
        await self.rig.until(lambda: self.rig.store.max_gw_no() >= self.rig.emu.gw_no)   # history arrives
        self.rig.drop_logs = True
        for i in range(10):
            self.rig.emu.glog("TEST", f"line {i}")
        await asyncio.sleep(1)
        self.rig.drop_logs = False
        top = self.rig.emu.gw_no
        await self.rig.until(lambda: len(self.rig.store.have_numbers(1, top)) == top, timeout=15)
        resent = self.rig.store.db.execute("SELECT COUNT(*) FROM events WHERE resent=1").fetchone()[0]
        self.assertGreaterEqual(resent, 10)


if __name__ == "__main__":
    unittest.main()
