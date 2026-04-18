from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Awaitable, Callable

from fastapi import WebSocket, WebSocketDisconnect
from starlette.websockets import WebSocketState

from .events import now
from .protocol import (
    TAG_ACK,
    TAG_DATA,
    decode,
    encode_ack,
    encode_connect_success,
    encode_data,
    encode_reconnect_success,
)

log = logging.getLogger("ssh_relay.session")


@dataclass
class SessionLimits:
    read_chunk_bytes: int = 64 * 1024
    max_replay_buffer: int = 4 * 1024 * 1024
    max_frame_bytes: int = 1 * 1024 * 1024
    grace_seconds: int = 120


class SessionGone(Exception):
    pass


class Session:
    def __init__(
        self,
        sid: str,
        identity_key: str | None,
        tcp_reader: asyncio.StreamReader,
        tcp_writer: asyncio.StreamWriter,
        limits: SessionLimits,
        meta: dict,
        emit: Callable[[dict], None],
        on_close: Callable[[], Awaitable[None]] | None = None,
    ):
        self.sid = sid
        self.identity_key = identity_key
        self.limits = limits
        self.meta = meta
        self._emit = emit
        self._on_close = on_close
        self._r = tcp_reader
        self._w = tcp_writer
        self._out_buf = bytearray()
        self._out_base = 0
        self._sent_pos = 0
        self._recv_pos = 0
        self._eof = False
        self._closed = False
        self._data_event = asyncio.Event()
        self._lock = asyncio.Lock()
        self._grace_task: asyncio.Task | None = None
        self._pump_task = asyncio.create_task(self._pump(), name=f"pump-{sid}")
        self._reconnect_count = 0
        self._close_emitted = False
        _, self._started_unix = now()
        self._client_banner: bytes | None = None
        self._target_banner: bytes | None = None
        self._client_peek = bytearray()
        self._target_peek = bytearray()

    @property
    def closed(self) -> bool:
        return self._closed

    def emit_start(self) -> None:
        ts, ts_unix = now()
        self._emit({
            "event": "session.start",
            "ts": ts,
            "ts_unix": ts_unix,
            "session_id": self.sid,
            **self.meta,
        })

    def note_reconnect(self, source_ip: str | None, user_agent: str | None, resume_ack: int) -> None:
        self._reconnect_count += 1
        ts, ts_unix = now()
        self._emit({
            "event": "session.reconnect",
            "ts": ts,
            "ts_unix": ts_unix,
            "session_id": self.sid,
            "source_ip": source_ip,
            "user_agent": user_agent,
            "resume_ack": resume_ack,
            "reconnect_count": self._reconnect_count,
        })

    def _emit_close(self, reason: str, error: str | None = None) -> None:
        if self._close_emitted:
            return
        self._close_emitted = True
        ts, ts_unix = now()
        self._emit({
            "event": "session.close",
            "ts": ts,
            "ts_unix": ts_unix,
            "session_id": self.sid,
            "reason": reason,
            "error": error,
            "duration_seconds": round(ts_unix - self._started_unix, 3),
            "bytes_to_target": self._recv_pos,
            "bytes_from_target": self._sent_pos,
            "reconnect_count": self._reconnect_count,
            "client_ssh_banner": _banner(self._client_banner),
            "target_ssh_banner": _banner(self._target_banner),
            "identity": self.meta.get("identity"),
            "source_port": self.meta.get("source_port"),
            "target_host": self.meta.get("target_host"),
            "target_port": self.meta.get("target_port"),
        })

    async def _pump(self) -> None:
        try:
            while not self._closed:
                chunk = await self._r.read(self.limits.read_chunk_bytes)
                if not chunk:
                    self._eof = True
                    self._data_event.set()
                    return
                if self._target_banner is None:
                    self._target_peek.extend(chunk[: 256 - len(self._target_peek)])
                    self._target_banner = _extract_banner(self._target_peek)
                async with self._lock:
                    self._out_buf.extend(chunk)
                    self._sent_pos += len(chunk)
                    over = len(self._out_buf) - self.limits.max_replay_buffer
                    if over > 0:
                        del self._out_buf[:over]
                        self._out_base += over
                self._data_event.set()
        except asyncio.CancelledError:
            raise
        except Exception as e:
            log.warning("sid=%s tcp pump error: %s", self.sid, e)
            self._eof = True
            self._data_event.set()

    async def handle(self, ws: WebSocket, resume_from: int | None) -> None:
        if resume_from is None:
            await ws.send_bytes(encode_connect_success(self.sid))
            start_pos = 0
        else:
            async with self._lock:
                if resume_from < self._out_base or resume_from > self._sent_pos:
                    raise SessionGone(
                        f"resume_from={resume_from} outside buffer "
                        f"[{self._out_base},{self._sent_pos}]"
                    )
            await ws.send_bytes(encode_reconnect_success(self._recv_pos))
            start_pos = resume_from

        sender = asyncio.create_task(self._sender(ws, start_pos))
        receiver = asyncio.create_task(self._receiver(ws))
        done, pending = await asyncio.wait({sender, receiver}, return_when=asyncio.FIRST_COMPLETED)
        for t in pending:
            t.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
        for t in done:
            exc = t.exception()
            if exc and not isinstance(exc, (WebSocketDisconnect, ConnectionError)):
                log.warning("sid=%s task error: %s", self.sid, exc)
        if self._eof:
            self._closed = True

    async def _sender(self, ws: WebSocket, start_pos: int) -> None:
        pos = start_pos
        cap = self.limits.max_frame_bytes - 6
        try:
            while True:
                async with self._lock:
                    if pos < self._out_base:
                        raise SessionGone("sender fell behind trim base")
                    if pos < self._sent_pos:
                        offset = pos - self._out_base
                        chunk = bytes(self._out_buf[offset:])
                    elif self._eof:
                        if ws.client_state != WebSocketState.DISCONNECTED:
                            await ws.close()
                        return
                    else:
                        self._data_event.clear()
                        chunk = None
                if chunk is None:
                    await self._data_event.wait()
                    continue
                for i in range(0, len(chunk), cap):
                    sub = chunk[i : i + cap]
                    await ws.send_bytes(encode_data(sub))
                    pos += len(sub)
        except (WebSocketDisconnect, ConnectionError, RuntimeError):
            return

    async def _receiver(self, ws: WebSocket) -> None:
        try:
            while True:
                try:
                    msg = await ws.receive_bytes()
                except WebSocketDisconnect:
                    return
                if len(msg) > self.limits.max_frame_bytes:
                    await ws.close(code=1009)
                    return
                frame = decode(msg)
                if frame.tag == TAG_DATA and frame.data:
                    if self._client_banner is None:
                        self._client_peek.extend(frame.data[: 256 - len(self._client_peek)])
                        self._client_banner = _extract_banner(self._client_peek)
                    self._w.write(frame.data)
                    await self._w.drain()
                    self._recv_pos += len(frame.data)
                    await ws.send_bytes(encode_ack(self._recv_pos))
                elif frame.tag == TAG_ACK:
                    async with self._lock:
                        drop = frame.ack - self._out_base
                        if drop > 0:
                            if drop > len(self._out_buf):
                                drop = len(self._out_buf)
                            del self._out_buf[:drop]
                            self._out_base += drop
        except (WebSocketDisconnect, ConnectionError, RuntimeError):
            return

    def arm_grace(self, sessions: "dict[str, Session]") -> None:
        self.cancel_grace()

        async def expire():
            try:
                await asyncio.sleep(self.limits.grace_seconds)
            except asyncio.CancelledError:
                return
            sessions.pop(self.sid, None)
            await self.close(reason="grace_expired")

        self._grace_task = asyncio.create_task(expire(), name=f"grace-{self.sid}")

    def cancel_grace(self) -> None:
        if self._grace_task and not self._grace_task.done():
            self._grace_task.cancel()
        self._grace_task = None

    async def close(self, reason: str = "closed", error: str | None = None) -> None:
        if self._closed and self._close_emitted:
            return
        self._closed = True
        self._emit_close(reason, error)
        self._data_event.set()
        self.cancel_grace()
        self._pump_task.cancel()
        try:
            await self._pump_task
        except BaseException:
            pass
        try:
            self._w.close()
            await self._w.wait_closed()
        except Exception:
            pass
        if self._on_close is not None:
            try:
                await self._on_close()
            except Exception as e:
                log.warning("sid=%s on_close hook error: %s", self.sid, e)
            finally:
                self._on_close = None


def _extract_banner(buf: bytearray) -> bytes | None:
    nl = buf.find(b"\n")
    if nl == -1:
        return None
    line = bytes(buf[:nl]).rstrip(b"\r")
    return line if line else None


def _banner(b: bytes | None) -> str | None:
    if b is None:
        return None
    try:
        return b.decode("ascii", errors="replace")[:128]
    except Exception:
        return None
