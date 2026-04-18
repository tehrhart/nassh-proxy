from __future__ import annotations

import asyncio


class PortPoolExhausted(RuntimeError):
    pass


class PortPool:
    """Fixed range of source ports, one-at-a-time acquisition. Usable outside the OS ephemeral range."""

    def __init__(self, port_min: int, port_max: int):
        if port_min < 1 or port_max > 65535 or port_min > port_max:
            raise ValueError(f"invalid port range {port_min}-{port_max}")
        self._free: list[int] = list(range(port_min, port_max + 1))
        self._free.reverse()
        self._lock = asyncio.Lock()

    @property
    def available(self) -> int:
        return len(self._free)

    async def acquire(self) -> int:
        async with self._lock:
            if not self._free:
                raise PortPoolExhausted("source port pool exhausted")
            return self._free.pop()

    async def release(self, port: int) -> None:
        async with self._lock:
            self._free.append(port)


class NoPool:
    """Stand-in when port binding is disabled."""

    available = -1

    async def acquire(self) -> int | None:
        return None

    async def release(self, port: int | None) -> None:
        pass
