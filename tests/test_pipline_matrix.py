# tests/test_pipeline_matrix_exhaustive.py
from itertools import product

import pytest

from pgp import keyGeneration as kg
from pgp import keyRing as kr
from pgp import pgpReceive as receiver
from pgp import pgpSend as sender


def _setup_keys(tmp_path):
    km = kr.KeyManager(
        privateRingPath=str(tmp_path / "priv.json"),
        publicRingPath=str(tmp_path / "pub.json"),
    )
    alice_id = kg.generateKeyPair(km, "Alice", "alice@example.com", 2048, "alicepw")
    bob_id = kg.generateKeyPair(km, "Bob", "bob@example.com", 2048, "bobpw")
    return km, alice_id, bob_id


_CASES = [
    (sign, encrypt, compress, radix64, algo)
    for sign, encrypt, compress, radix64 in product([False, True], repeat=4)
    for algo in (["AES128", "TripleDES"] if encrypt else [None])
]


@pytest.mark.parametrize("sign,encrypt,compress,radix64,algo", _CASES)
def test_full_pipeline_all_flag_combinations(tmp_path, sign, encrypt, compress, radix64, algo):
    km, alice_id, bob_id = _setup_keys(tmp_path)
    out_file = tmp_path / "msg.pgp"
    message = b"matrix test payload \x00\x01"

    options = {
        "sign": sign,
        "encrypt": encrypt,
        "compress": compress,
        "radix64": radix64,
    }
    if sign:
        options["senderKeyId"] = alice_id
        options["passphrase"] = "alicepw"
    if encrypt:
        options["recipientKeyId"] = bob_id
        options["algorithm"] = algo

    sender.pgpSend(km, message, "matrix.txt", str(out_file), options)
    result = receiver.pgpReceive(km, str(out_file), "bobpw" if encrypt else "")

    assert result["error"] is None
    assert result["message"] == message
    assert result["filename"] == "matrix.txt"
    if sign:
        assert result["verified"] is True
        assert "Alice" in result["author"]
    else:
        assert result["verified"] is None
        assert result["author"] is None


def test_send_missing_sign_fields_raises(tmp_path):
    km, _, bob_id = _setup_keys(tmp_path)
    out_file = tmp_path / "x.pgp"
    options = {
        "sign": True,
        "encrypt": True,
        "compress": False,
        "radix64": False,
        "recipientKeyId": bob_id,
        "algorithm": "AES128",
    }
    with pytest.raises(KeyError):
        sender.pgpSend(km, b"x", "x.txt", str(out_file), options)


def test_send_missing_encrypt_fields_raises(tmp_path):
    km, alice_id, _ = _setup_keys(tmp_path)
    out_file = tmp_path / "x.pgp"
    options = {
        "sign": True,
        "encrypt": True,
        "compress": False,
        "radix64": False,
        "senderKeyId": alice_id,
        "passphrase": "alicepw",
    }
    with pytest.raises(KeyError):
        sender.pgpSend(km, b"x", "x.txt", str(out_file), options)


def test_receive_wrong_passphrase_sets_error(tmp_path):
    km, _, bob_id = _setup_keys(tmp_path)
    out_file = tmp_path / "badpw.pgp"

    options = {
        "sign": False,
        "encrypt": True,
        "compress": False,
        "radix64": False,
        "recipientKeyId": bob_id,
        "algorithm": "AES128",
    }
    sender.pgpSend(km, b"secret", "s.txt", str(out_file), options)
    result = receiver.pgpReceive(km, str(out_file), "wrong")
    assert result["error"] is not None
    assert result["message"] is None


def test_receive_invalid_magic_sets_error(tmp_path):
    km, _, _ = _setup_keys(tmp_path)
    bad = tmp_path / "garbage.pgp"
    bad.write_bytes(b"not a pgp")
    result = receiver.pgpReceive(km, str(bad), "x")
    assert result["error"] is not None


def test_receive_unknown_signer_key_sets_error(tmp_path):
    km, alice_id, _ = _setup_keys(tmp_path)
    out_file = tmp_path / "signed_only.pgp"

    options = {
        "sign": True,
        "encrypt": False,
        "compress": False,
        "radix64": False,
        "senderKeyId": alice_id,
        "passphrase": "alicepw",
    }
    sender.pgpSend(km, b"msg", "m.txt", str(out_file), options)

    km.privateRing.remove(alice_id)
    km.saveRings()

    result = receiver.pgpReceive(km, str(out_file), "")
    assert result["error"] is not None