"""Integration tests for /v4/reconnect session resumption."""

from __future__ import annotations

import asyncio
import os

import pytest
import pytest_asyncio
import uvicorn
from websockets.asyncio.client import connect

os.environ.setdefault("RELAY_PUBLIC_HOST", "localhost")
os.environ.setdefault("RELAY_PUBLIC_PORT", "8080")
os.environ.setdefault("RELAY_IDENTITY_PROVIDER", "none")
os.environ.setdefault("RELAY_AUTH_REQUIRED", "false")
os.environ.setdefault("RELAY_LOG_SINKS", "stderr")
os.environ.setdefault("RELAY_GRACE_SECONDS", "5")

from ssh_relay.app import app  # noqa: E402
from ssh_relay.protocol import (  # noqa: E402
    TAG_CONNECT_SUCCESS,
    TAG_DATA,
    TAG_RECONNECT_SUCCESS,
    decode,
    encode_data,
)


async def _echo_handler(reader, writer):
    try:
        while True:
            data = await reader.read(4096)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    finally:
        writer.close()


def _make_triggered_handler(trigger: asyncio.Event, payload: bytes):
    async def handler(reader, writer):
        await trigger.wait()
        writer.write(payload)
        await writer.drain()
        try:
            while await reader.read(4096):
                pass
        except Exception:
            pass
    return handler


@pytest_asyncio.fixture
async def echo_server():
    server = await asyncio.start_server(_echo_handler, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    task = asyncio.create_task(server.serve_forever())
    try:
        yield port
    finally:
        server.close()
        await server.wait_closed()
        task.cancel()


@pytest_asyncio.fixture
async def relay_server():
    config = uvicorn.Config(app, host="127.0.0.1", port=0, log_level="warning", lifespan="on")
    server = uvicorn.Server(config)
    task = asyncio.create_task(server.serve())
    while not server.started:
        await asyncio.sleep(0.05)
    port = server.servers[0].sockets[0].getsockname()[1]
    try:
        yield port
    finally:
        server.should_exit = True
        await task


async def _read_data_until(ws, needle: bytes, timeout=2.0) -> tuple[bytes, int]:
    """Return (accumulated_data, bytes_received_from_server)."""
    got = b""
    recv = 0
    while needle not in got:
        msg = await asyncio.wait_for(ws.recv(), timeout=timeout)
        f = decode(bytes(msg))
        if f.tag == TAG_DATA:
            got += f.data
            recv += len(f.data)
    return got, recv


@pytest.mark.asyncio
async def test_reconnect_resumes_session(echo_server, relay_server):
    url = f"ws://127.0.0.1:{relay_server}/v4/connect?host=127.0.0.1&port={echo_server}"

    async with connect(url, subprotocols=["ssh"]) as ws:
        first = decode(bytes(await ws.recv()))
        assert first.tag == TAG_CONNECT_SUCCESS
        sid = first.sid
        assert len(sid) == 32

        await ws.send(encode_data(b"hello"))
        got, recv_pos = await _read_data_until(ws, b"hello")
        assert got == b"hello"

    # First WS closed. Relay should be holding the session open within grace period.
    rc_url = f"ws://127.0.0.1:{relay_server}/v4/reconnect?sid={sid}&ack={recv_pos}"
    async with connect(rc_url, subprotocols=["ssh"]) as ws2:
        first = decode(bytes(await ws2.recv()))
        assert first.tag == TAG_RECONNECT_SUCCESS

        await ws2.send(encode_data(b"world"))
        got, _ = await _read_data_until(ws2, b"world")
        assert got == b"world"


@pytest.mark.asyncio
async def test_reconnect_replays_data_buffered_while_disconnected(relay_server):
    trigger = asyncio.Event()
    payload = b"sent-while-disconnected"
    server = await asyncio.start_server(
        _make_triggered_handler(trigger, payload), "127.0.0.1", 0
    )
    tcp_port = server.sockets[0].getsockname()[1]
    server_task = asyncio.create_task(server.serve_forever())

    try:
        url = f"ws://127.0.0.1:{relay_server}/v4/connect?host=127.0.0.1&port={tcp_port}"
        async with connect(url, subprotocols=["ssh"]) as ws:
            first = decode(bytes(await ws.recv()))
            assert first.tag == TAG_CONNECT_SUCCESS
            sid = first.sid
            # Disconnect before the TCP server has sent anything.

        # Now let the TCP server send data. It accumulates in the relay's replay buffer.
        trigger.set()
        await asyncio.sleep(0.2)

        rc_url = f"ws://127.0.0.1:{relay_server}/v4/reconnect?sid={sid}&ack=0"
        async with connect(rc_url, subprotocols=["ssh"]) as ws2:
            first = decode(bytes(await ws2.recv()))
            assert first.tag == TAG_RECONNECT_SUCCESS
            got, _ = await _read_data_until(ws2, payload)
            assert got.startswith(payload)
    finally:
        server.close()
        server_task.cancel()
        try:
            await asyncio.wait_for(server_task, timeout=1.0)
        except (asyncio.CancelledError, asyncio.TimeoutError):
            pass


@pytest.mark.asyncio
async def test_reconnect_with_unknown_sid_is_rejected(relay_server):
    rc_url = f"ws://127.0.0.1:{relay_server}/v4/reconnect?sid={'0' * 32}&ack=0"
    # websockets raises on close codes >= 4000 during handshake? No — 4xxx are app-level closes;
    # the server accepts then closes. The client sees a close.
    async with connect(rc_url, subprotocols=["ssh"]) as ws:
        with pytest.raises(Exception):
            await asyncio.wait_for(ws.recv(), timeout=2.0)
