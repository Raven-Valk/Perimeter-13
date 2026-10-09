"""Fan-out of live updates to every open dashboard."""

from __future__ import annotations

import asyncio
from typing import Any


class Hub:
    def __init__(self, queue_size: int = 512):
        self._subs: set[asyncio.Queue] = set()
        self._size = queue_size

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(self._size)
        self._subs.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        self._subs.discard(q)

    def publish(self, kind: str, data: Any) -> None:
        msg = {"type": kind, "data": data}
        for q in self._subs:
            try:
                q.put_nowait(msg)
            except asyncio.QueueFull:
                # A client this far behind gets a fresh snapshot instead of a gap.
                while not q.empty():
                    q.get_nowait()
                q.put_nowait({"type": "resync", "data": None})

    @property
    def listeners(self) -> int:
        return len(self._subs)
