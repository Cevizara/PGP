# tests/test_message_components_and_serializer_exhaustive.py
import struct

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from pgp import cryptoPrimitives as cp
from pgp import fileSerializer as fs
from pgp import messageComponents as mc


def _rsa_pair():
    pr = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return pr, pr.public_key()


def test_pack_unpack_field_roundtrip():
    original = b"abc\x00\xff"
    packed = mc.packField(original)
    field, off = mc.unpackField(packed, 0)
    assert field == original
    assert off == len(packed)


def test_pack_unpack_int_roundtrip():
    v = 2**63 + 123
    packed = mc.packInt(v, 8)
    out, off = mc.unpackInt(packed, 0, 8)
    assert out == v
    assert off == 8


def test_build_parse_message_component(monkeypatch):
    monkeypatch.setattr(cp, "currentTimestamp", lambda: 123456789)
    data = mc.buildMessageComponent(b"payload", "file.txt")
    comp, rest = mc.parseMessageComponent(data)
    assert rest == b""
    assert comp["filename"] == "file.txt"
    assert comp["creationTime"] == 123456789
    assert comp["message"] == b"payload"


def test_build_parse_signature_component(monkeypatch):
    pr, _ = _rsa_pair()
    monkeypatch.setattr(cp, "currentTimestamp", lambda: 42)
    blob = mc.buildSignature(b"hello", pr, senderKeyId=777)
    comp, rest = mc.parseSignatureComponent(blob)
    assert rest == b""
    assert comp["timestamp"] == 42
    assert comp["senderKeyId"] == 777
    assert len(comp["leadingTwoOctets"]) == 2
    assert len(comp["signature"]) > 0


@pytest.mark.parametrize("algo", ["AES128", "TripleDES"])
def test_build_parse_session_key_component(algo):
    enc_ks = b"abc123"
    blob = mc.buildSessionKeyComponent(enc_ks, recipientKeyId=999, algorithm=algo)
    comp, rest = mc.parseSessionKeyComponent(blob)
    assert rest == b""
    assert comp["recipientKeyId"] == 999
    assert comp["algorithm"] == algo
    assert comp["encryptedSessionKey"] == enc_ks


def test_parse_session_key_component_invalid_algorithm_id_raises():
    block = b""
    block += mc.packInt(5, 8)
    block += mc.packInt(99, 1)
    block += mc.packField(b"ks")
    data = mc.packField(block)
    with pytest.raises(ValueError):
        mc.parseSessionKeyComponent(data)


@pytest.mark.parametrize("signed,encrypted,compressed,radix64,algo_id", [
    (False, False, False, False, 0),
    (True, False, False, False, 0),
    (False, True, False, False, 1),
    (False, False, True, False, 0),
    (False, False, False, True, 0),
    (True, True, True, True, 2),
])
def test_header_encode_decode_flags(signed, encrypted, compressed, radix64, algo_id):
    payload = b"payload"
    raw = fs.encodeHeader(signed, encrypted, compressed, radix64, algo_id) + payload
    flags, out_payload = fs.decodeHeader(raw)
    assert out_payload == payload
    assert flags["signed"] is signed
    assert flags["encrypted"] is encrypted
    assert flags["compressed"] is compressed
    assert flags["radix64"] is radix64
    assert flags["algorithmId"] == algo_id


def test_decode_header_invalid_magic_raises():
    with pytest.raises(ValueError):
        fs.decodeHeader(b"NOPE\x00\x00payload")


def test_decode_header_too_short_raises():
    with pytest.raises(Exception):
        fs.decodeHeader(b"PGP1")


def test_serialize_and_read_file_roundtrip(tmp_path):
    p = tmp_path / "x.pgp"
    header = fs.encodeHeader(False, False, False, False, 0)
    fs.serializeToFile(b"abc", header, str(p))
    raw = fs.readFile(str(p))
    assert raw == header + b"abc"


def test_verify_sender_leading_two_octets_fast_fail():
    from pgp.pgpReceive import verifySender

    pr, pu = _rsa_pair()
    digest_input = b"m" + mc.packInt(123, 8)
    digest = cp.sha1Hash(digest_input)
    sig = cp.rsaSign(pr, digest)

    signature_component = {
        "timestamp": 123,
        "senderKeyId": 1,
        "leadingTwoOctets": b"\x00\x00",
        "signature": sig,
    }
    message_component = {"message": b"m"}
    assert verifySender(pu, signature_component, message_component) is False