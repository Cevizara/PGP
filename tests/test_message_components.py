import struct

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from pgp import cryptoPrimitives as cp
from pgp import messageComponents as mc


def _new_private_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def test_pack_field_roundtrip_basic():
    data = b"\x00abc\xff"
    packed = mc.packField(data)
    out, off = mc.unpackField(packed, 0)
    assert out == data
    assert off == len(packed)


def test_unpack_field_from_nonzero_offset():
    first = mc.packField(b"one")
    second = mc.packField(b"two")
    blob = first + second
    _, off1 = mc.unpackField(blob, 0)
    out2, off2 = mc.unpackField(blob, off1)
    assert out2 == b"two"
    assert off2 == len(blob)


def test_unpack_field_empty_payload():
    packed = mc.packField(b"")
    out, off = mc.unpackField(packed, 0)
    assert out == b""
    assert off == 4


def test_unpack_field_short_header_raises():
    with pytest.raises(struct.error):
        mc.unpackField(b"\x00\x00\x00", 0)


def test_unpack_field_declared_length_larger_than_available_truncates():
    # Current implementation slices and returns shorter bytes, no raise.
    blob = struct.pack(">I", 10) + b"abc"
    out, off = mc.unpackField(blob, 0)
    assert out == b"abc"
    assert off == 14


def test_pack_int_unpack_int_roundtrip_1_8_bytes():
    for nbytes in range(1, 9):
        value = (1 << (8 * nbytes)) - 1
        packed = mc.packInt(value, nbytes)
        out, off = mc.unpackInt(packed, 0, nbytes)
        assert out == value
        assert off == nbytes


def test_pack_int_negative_raises():
    with pytest.raises(OverflowError):
        mc.packInt(-1, 2)


def test_pack_int_value_too_large_raises():
    with pytest.raises(OverflowError):
        mc.packInt(256, 1)


def test_build_and_parse_message_component_roundtrip(monkeypatch):
    monkeypatch.setattr(cp, "currentTimestamp", lambda: 1234567890)
    blob = mc.buildMessageComponent(b"hello", "f.txt")
    comp, remaining = mc.parseMessageComponent(blob)

    assert remaining == b""
    assert comp["filename"] == "f.txt"
    assert comp["creationTime"] == 1234567890
    assert comp["message"] == b"hello"


def test_parse_message_component_preserves_remaining_bytes(monkeypatch):
    monkeypatch.setattr(cp, "currentTimestamp", lambda: 1)
    blob = mc.buildMessageComponent(b"m", "x.bin") + b"TAIL"
    comp, remaining = mc.parseMessageComponent(blob)
    assert comp["filename"] == "x.bin"
    assert comp["message"] == b"m"
    assert remaining == b"TAIL"


def test_parse_message_component_invalid_filename_decode_raises():
    # Build a valid component but with invalid UTF-8 filename bytes.
    block = b""
    block += mc.packField(b"\xff\xfe")
    block += mc.packInt(1, 8)
    block += mc.packField(b"msg")
    data = mc.packField(block)

    with pytest.raises(UnicodeDecodeError):
        mc.parseMessageComponent(data)


def test_parse_message_component_short_input_raises():
    with pytest.raises(struct.error):
        mc.parseMessageComponent(b"\x00")


def test_build_and_parse_signature_component_roundtrip(monkeypatch):
    private_key = _new_private_key()
    monkeypatch.setattr(cp, "currentTimestamp", lambda: 4242)

    blob = mc.buildSignature(b"payload", private_key, senderKeyId=777)
    comp, remaining = mc.parseSignatureComponent(blob)

    assert remaining == b""
    assert comp["timestamp"] == 4242
    assert comp["senderKeyId"] == 777
    assert isinstance(comp["leadingTwoOctets"], bytes)
    assert len(comp["leadingTwoOctets"]) == 2
    assert isinstance(comp["signature"], bytes)
    assert len(comp["signature"]) > 0


def test_parse_signature_component_preserves_remaining_bytes(monkeypatch):
    private_key = _new_private_key()
    monkeypatch.setattr(cp, "currentTimestamp", lambda: 9)
    blob = mc.buildSignature(b"x", private_key, senderKeyId=1) + b"REST"
    comp, remaining = mc.parseSignatureComponent(blob)

    assert comp["timestamp"] == 9
    assert comp["senderKeyId"] == 1
    assert remaining == b"REST"


def test_parse_signature_component_short_input_raises():
    with pytest.raises(struct.error):
        mc.parseSignatureComponent(b"\x00")


@pytest.mark.parametrize("algorithm", ["AES128", "TripleDES"])
def test_build_and_parse_session_key_component_roundtrip(algorithm):
    blob = mc.buildSessionKeyComponent(b"\x01\x02\x03", recipientKeyId=55, algorithm=algorithm)
    comp, remaining = mc.parseSessionKeyComponent(blob)

    assert remaining == b""
    assert comp["recipientKeyId"] == 55
    assert comp["algorithm"] == algorithm
    assert comp["encryptedSessionKey"] == b"\x01\x02\x03"


def test_build_session_key_component_invalid_algorithm_raises():
    with pytest.raises(ValueError):
        mc.buildSessionKeyComponent(b"k", recipientKeyId=1, algorithm="BAD")


def test_parse_session_key_component_invalid_algorithm_id_raises():
    # recipient(8) + algorithm(1 invalid) + encryptedSessionKey(field)
    block = b""
    block += mc.packInt(99, 8)
    block += mc.packInt(255, 1)
    block += mc.packField(b"k")
    data = mc.packField(block)

    with pytest.raises(ValueError):
        mc.parseSessionKeyComponent(data)


def test_parse_session_key_component_short_input_raises():
    with pytest.raises(struct.error):
        mc.parseSessionKeyComponent(b"\x00")


def test_parse_session_key_component_preserves_remaining_bytes():
    blob = mc.buildSessionKeyComponent(b"k", recipientKeyId=7, algorithm="AES128") + b"XYZ"
    comp, remaining = mc.parseSessionKeyComponent(blob)

    assert comp["recipientKeyId"] == 7
    assert comp["algorithm"] == "AES128"
    assert comp["encryptedSessionKey"] == b"k"
    assert remaining == b"XYZ"