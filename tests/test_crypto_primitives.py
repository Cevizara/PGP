import os
import time
import zlib

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from pgp import cryptoPrimitives as cp


def _rsa_pair():
    pr = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return pr, pr.public_key()


def test_sha1_known_vector():
    assert cp.sha1Hash(b"abc").hex() == "a9993e364706816aba3e25717850c26c9cd0d89d"


def test_rsa_sign_and_verify_true():
    pr, pu = _rsa_pair()
    digest = cp.sha1Hash(b"hello")
    sig = cp.rsaSign(pr, digest)
    assert cp.rsaVerify(pu, sig, digest) is True


def test_rsa_verify_false_for_tampered_digest():
    pr, pu = _rsa_pair()
    digest = cp.sha1Hash(b"hello")
    sig = cp.rsaSign(pr, digest)
    bad_digest = cp.sha1Hash(b"hello2")
    assert cp.rsaVerify(pu, sig, bad_digest) is False


def test_rsa_encrypt_decrypt_roundtrip():
    pr, pu = _rsa_pair()
    session_key = os.urandom(16)
    enc = cp.rsaEncrypt(pu, session_key)
    dec = cp.rsaDecrypt(pr, enc)
    assert dec == session_key


def test_rsa_decrypt_with_wrong_key_raises():
    pr1, pu1 = _rsa_pair()
    pr2, _ = _rsa_pair()
    enc = cp.rsaEncrypt(pu1, os.urandom(16))
    with pytest.raises(Exception):
        cp.rsaDecrypt(pr2, enc)


@pytest.mark.parametrize("algo,key_len,block_size", [
    ("AES128", 16, 16),
    ("TripleDES", 24, 8),
])
def test_generate_session_key_lengths(algo, key_len, block_size):
    key = cp.generateSessionKey(algo)
    assert len(key) == key_len
    assert cp.getBlockSize(algo) == block_size


def test_generate_session_key_is_random():
    a = cp.generateSessionKey("AES128")
    b = cp.generateSessionKey("AES128")
    assert a != b


@pytest.mark.parametrize("algo", ["AES128", "TripleDES"])
@pytest.mark.parametrize("payload_len", [0, 1, 7, 8, 15, 16, 17, 31, 64, 1024])
def test_symmetric_roundtrip_all_sizes(algo, payload_len):
    key = cp.generateSessionKey(algo)
    payload = os.urandom(payload_len)
    encrypted = cp.symmetricEncrypt(algo, key, payload)
    decrypted = cp.symmetricDecrypt(algo, key, encrypted)
    assert decrypted == payload


@pytest.mark.parametrize("algo", ["AES128", "TripleDES"])
def test_symmetric_encrypt_prepends_iv_and_randomizes(algo):
    key = cp.generateSessionKey(algo)
    data = b"same plaintext"
    e1 = cp.symmetricEncrypt(algo, key, data)
    e2 = cp.symmetricEncrypt(algo, key, data)
    assert len(e1) >= cp.getBlockSize(algo)
    assert len(e2) >= cp.getBlockSize(algo)
    assert e1 != e2


@pytest.mark.parametrize("algo", ["AES128", "TripleDES"])
def test_symmetric_decrypt_short_input_raises(algo):
    key = cp.generateSessionKey(algo)
    with pytest.raises(Exception):
        cp.symmetricDecrypt(algo, key, b"\x00")


@pytest.mark.parametrize("data", [
    b"",
    b"a",
    b"a" * 1000,
    os.urandom(256),
])
def test_compress_decompress_roundtrip(data):
    assert cp.decompress(cp.compress(data)) == data


def test_decompress_invalid_raises():
    with pytest.raises(zlib.error):
        cp.decompress(b"not-zlib-data")


@pytest.mark.parametrize("data", [
    b"",
    b"\x00\xff\x10text",
    os.urandom(257),
])
def test_radix64_roundtrip(data):
    assert cp.radix64Decode(cp.radix64Encode(data)) == data


def test_radix64_decode_invalid_raises():
    with pytest.raises(Exception):
        cp.radix64Decode(b"%%%not_base64%%%")


def test_algorithm_mapping_roundtrip():
    for algo in ("AES128", "TripleDES"):
        assert cp.idToAlgorithm(cp.algorithmToId(algo)) == algo


def test_algorithm_to_id_invalid_raises():
    with pytest.raises(ValueError):
        cp.algorithmToId("AES256")


def test_id_to_algorithm_invalid_raises():
    with pytest.raises(ValueError):
        cp.idToAlgorithm(99)


def test_build_cipher_algorithm_invalid_raises():
    with pytest.raises(ValueError):
        cp.buildCipherAlgorithm("NOPE", os.urandom(16))


def test_get_block_size_invalid_raises():
    with pytest.raises(ValueError):
        cp.getBlockSize("NOPE")


def test_current_timestamp_is_close_to_now():
    now = int(time.time())
    ts = cp.currentTimestamp()
    assert now - 5 <= ts <= now + 5