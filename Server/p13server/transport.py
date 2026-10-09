"""MQTT between the server and the gateway.

hardware: the server's own Mosquitto (the server logs in on the local listener;
          the gateway reaches the TLS listener from the Wi-Fi network)
wokwi:    the public broker the Wokwi projects use (no login, no encryption:
          the packets are still signed, but anyone can read them)
"""

from __future__ import annotations

import asyncio
import logging

import aiomqtt

from .config import Config
from .gateway import GatewayLink

log = logging.getLogger("p13.mqtt")


class MqttTransport:
    def __init__(self, cfg: Config, link: GatewayLink):
        self.cfg = cfg
        self.link = link
        base = cfg.topic_base
        self.topic_in = f"{base}/to/P"
        self.topic_out = f"{base}/to/G"
        self.topic_state = f"{base}/state/G"
        self._out: asyncio.Queue[bytes] = asyncio.Queue(256)
        link.send_hook = self._enqueue

    def _enqueue(self, data: bytes) -> None:
        if not self.link.transport_up:
            return
        try:
            self._out.put_nowait(data)
        except asyncio.QueueFull:
            pass      # the broker is stalled: beats repeat, commands time out and say so

    async def run(self) -> None:
        delay = 1.0
        ident = f"p13-server-{self.cfg.site_id}-{self.link.boot_id:08x}"
        while True:
            try:
                async with aiomqtt.Client(self.cfg.mqtt_host, self.cfg.mqtt_port,
                                          username=self.cfg.mqtt_user or None,
                                          password=self.cfg.mqtt_password or None,
                                          identifier=ident, keepalive=15) as client:
                    await client.subscribe(self.topic_in)
                    if self.cfg.mode == "hardware":
                        await client.subscribe(self.topic_state)
                    while not self._out.empty():
                        self._out.get_nowait()
                    self.link.set_transport(True, f"{self.cfg.mqtt_host}:{self.cfg.mqtt_port}")
                    delay = 1.0
                    sender = asyncio.create_task(self._send_loop(client))
                    try:
                        async for msg in client.messages:
                            topic = str(msg.topic)
                            payload = bytes(msg.payload) if isinstance(msg.payload, (bytes, bytearray)) else b""
                            if topic == self.topic_in:
                                self.link.on_bytes(payload)
                            elif topic == self.topic_state:
                                self.link.set_presence(payload.decode("ascii", "replace"))
                    finally:
                        sender.cancel()
            except aiomqtt.MqttError as e:
                self.link.set_transport(False, str(e))
                log.warning("broker: %s (retrying in %.0f s)", e, delay)
            await asyncio.sleep(delay)
            delay = min(delay * 2, 30.0)

    async def _send_loop(self, client: aiomqtt.Client) -> None:
        while True:
            data = await self._out.get()
            await client.publish(self.topic_out, data, qos=0)
