"""nassh corp-relay-v4@google.com wire format.

Spec: https://chromium.googlesource.com/apps/libapps/+/master/nassh/doc/relay-protocol.md
All integers big-endian; arrays prefixed by a 32-bit length.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

TAG_CONNECT_SUCCESS = 0x0001
TAG_RECONNECT_SUCCESS = 0x0002
TAG_DATA = 0x0004
TAG_ACK = 0x0007

_ACK_MASK = (1 << 64) - 1


@dataclass(frozen=True)
class Frame:
    tag: int
    data: bytes = b""
    ack: int = 0
    sid: str = ""


def encode_connect_success(sid: str) -> bytes:
    sid_bytes = sid.encode("ascii")
    return struct.pack(">HI", TAG_CONNECT_SUCCESS, len(sid_bytes)) + sid_bytes


def encode_reconnect_success(ack: int) -> bytes:
    return struct.pack(">HQ", TAG_RECONNECT_SUCCESS, ack & _ACK_MASK)


def encode_data(data: bytes) -> bytes:
    return struct.pack(">HI", TAG_DATA, len(data)) + data


def encode_ack(ack: int) -> bytes:
    return struct.pack(">HQ", TAG_ACK, ack & _ACK_MASK)


def decode(msg: bytes) -> Frame:
    if len(msg) < 2:
        raise ValueError("frame shorter than tag")
    (tag,) = struct.unpack_from(">H", msg, 0)
    if tag == TAG_DATA:
        if len(msg) < 6:
            raise ValueError("DATA frame missing length")
        (length,) = struct.unpack_from(">I", msg, 2)
        if len(msg) < 6 + length:
            raise ValueError("DATA frame truncated")
        return Frame(tag=tag, data=bytes(msg[6 : 6 + length]))
    if tag == TAG_ACK or tag == TAG_RECONNECT_SUCCESS:
        if len(msg) < 10:
            raise ValueError("u64-payload frame truncated")
        (ack,) = struct.unpack_from(">Q", msg, 2)
        return Frame(tag=tag, ack=ack)
    if tag == TAG_CONNECT_SUCCESS:
        if len(msg) < 6:
            raise ValueError("CONNECT_SUCCESS missing length")
        (length,) = struct.unpack_from(">I", msg, 2)
        if len(msg) < 6 + length:
            raise ValueError("CONNECT_SUCCESS truncated")
        return Frame(tag=tag, sid=bytes(msg[6 : 6 + length]).decode("ascii"))
    # Unknown tags MUST be ignored per spec.
    return Frame(tag=tag)
