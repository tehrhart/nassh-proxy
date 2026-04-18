import struct

import pytest

from ssh_relay.protocol import (
    TAG_ACK,
    TAG_CONNECT_SUCCESS,
    TAG_DATA,
    decode,
    encode_ack,
    encode_connect_success,
    encode_data,
)


def test_connect_success_layout():
    frame = encode_connect_success("abc123")
    assert frame[:2] == struct.pack(">H", TAG_CONNECT_SUCCESS)
    assert frame[2:6] == struct.pack(">I", 6)
    assert frame[6:] == b"abc123"


def test_data_layout_and_roundtrip():
    payload = b"hello\x00world"
    frame = encode_data(payload)
    assert frame[:2] == struct.pack(">H", TAG_DATA)
    assert frame[2:6] == struct.pack(">I", len(payload))
    assert frame[6:] == payload
    decoded = decode(frame)
    assert decoded.tag == TAG_DATA
    assert decoded.data == payload


def test_ack_layout_and_roundtrip():
    frame = encode_ack(2**40 + 17)
    assert frame[:2] == struct.pack(">H", TAG_ACK)
    assert frame[2:10] == struct.pack(">Q", 2**40 + 17)
    decoded = decode(frame)
    assert decoded.tag == TAG_ACK
    assert decoded.ack == 2**40 + 17


def test_unknown_tag_is_ignored_not_raised():
    frame = struct.pack(">H", 0x00FF) + b"garbage"
    decoded = decode(frame)
    assert decoded.tag == 0x00FF
    assert decoded.data == b""


def test_truncated_data_raises():
    bad = struct.pack(">HI", TAG_DATA, 100) + b"short"
    with pytest.raises(ValueError):
        decode(bad)


def test_ack_wraps_at_64_bits():
    frame = encode_ack(2**64 + 5)
    assert frame[2:10] == struct.pack(">Q", 5)
