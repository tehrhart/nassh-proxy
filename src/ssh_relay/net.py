"""TCP dial helper that optionally binds to a specific source port before connect()."""

from __future__ import annotations

import asyncio
import socket


async def open_tcp(
    host: str, port: int, *, source_port: int | None = None
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter, int | None]:
    """Open a TCP connection, returning (reader, writer, actual_source_port).

    If source_port is None, let the kernel pick and try to read the port back from the socket.
    """
    if source_port is None:
        reader, writer = await asyncio.open_connection(host, port)
        sock = writer.get_extra_info("socket")
        actual = sock.getsockname()[1] if sock else None
        return reader, writer, actual

    loop = asyncio.get_running_loop()
    addrinfo = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    last_err: Exception | None = None
    for family, sock_type, proto, _, sockaddr in addrinfo:
        sock = None
        try:
            sock = socket.socket(family, sock_type, proto)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            bind_addr = ("", source_port) if family == socket.AF_INET else ("::", source_port, 0, 0)
            sock.bind(bind_addr)
            sock.setblocking(False)
            await loop.sock_connect(sock, sockaddr)
            reader, writer = await asyncio.open_connection(sock=sock)
            return reader, writer, source_port
        except OSError as e:
            last_err = e
            if sock is not None:
                sock.close()
    raise last_err or OSError(f"cannot connect to {host}:{port} from source port {source_port}")
