"""End-to-end relay test: FastAPI + real TCP echo server + real WebSocket client."""

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

from ssh_relay.app import app  # noqa: E402
from ssh_relay.protocol import (  # noqa: E402
    TAG_CONNECT_SUCCESS,
    TAG_DATA,
    decode,
    encode_data,
)


async def _echo_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    try:
        while True:
            data = await reader.read(4096)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    finally:
        writer.close()


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


@pytest.mark.asyncio
async def test_echo_roundtrip(echo_server, relay_server):
    url = f"ws://127.0.0.1:{relay_server}/v4/connect?host=127.0.0.1&port={echo_server}"
    async with connect(url, subprotocols=["ssh"]) as ws:
        first = await ws.recv()
        assert isinstance(first, (bytes, bytearray))
        frame = decode(first)
        assert frame.tag == TAG_CONNECT_SUCCESS

        await ws.send(encode_data(b"ping"))

        # Expect a DATA frame echoed back (may arrive before or after our server ACK).
        got = b""
        while b"ping" not in got:
            msg = await asyncio.wait_for(ws.recv(), timeout=2.0)
            f = decode(bytes(msg))
            if f.tag == TAG_DATA:
                got += f.data
        assert got == b"ping"
