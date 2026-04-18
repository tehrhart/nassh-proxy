"""Event bus: fan out structured session events to multiple sinks without blocking."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Iterable, Protocol, runtime_checkable

log = logging.getLogger("ssh_relay.events")


@runtime_checkable
class Sink(Protocol):
    name: str

    async def emit(self, event: dict) -> None: ...

    async def close(self) -> None: ...


class EventBus:
    def __init__(self, sinks: Iterable[Sink], queue_size: int = 10_000):
        self._sinks = list(sinks)
        self._queues: list[tuple[Sink, asyncio.Queue]] = []
        self._tasks: list[asyncio.Task] = []
        self._queue_size = queue_size

    async def start(self) -> None:
        for sink in self._sinks:
            q: asyncio.Queue = asyncio.Queue(maxsize=self._queue_size)
            self._queues.append((sink, q))
            self._tasks.append(asyncio.create_task(self._drain(sink, q), name=f"sink-{sink.name}"))

    def emit(self, event: dict) -> None:
        """Non-blocking: if a sink's queue is full, drop and warn."""
        for sink, q in self._queues:
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                log.warning("sink %s queue full, dropping event %s", sink.name, event.get("event"))

    async def _drain(self, sink: Sink, q: asyncio.Queue) -> None:
        while True:
            event = await q.get()
            try:
                await sink.emit(event)
            except Exception as e:
                log.warning("sink %s emit failed: %s", sink.name, e)

    async def stop(self) -> None:
        for t in self._tasks:
            t.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        for sink in self._sinks:
            with contextlib.suppress(Exception):
                await sink.close()


def now() -> tuple[str, float]:
    t = time.time()
    return datetime.fromtimestamp(t, tz=timezone.utc).isoformat(), t


def new_event_id() -> str:
    return uuid.uuid4().hex
