import os
import tempfile

from pgp import keyRing as kr
from pgp import keyGeneration as kg
from pgp import pgpSend as sender
from pgp import pgpReceive as receiver


def setupKeys():
    tmpDir = tempfile.mkdtemp()
    km = kr.KeyManager(
        privateRingPath=os.path.join(tmpDir, "priv.json"),
        publicRingPath=os.path.join(tmpDir, "pub.json"),
    )
    aliceId = kg.generateKeyPair(km, "Alice", "alice@x.com", 2048, "alicepw")
    bobId = kg.generateKeyPair(km, "Bob", "bob@x.com", 2048, "bobpw")
    return km, aliceId, bobId, tmpDir


def test_full_roundtrip():
    km, aliceId, bobId, tmpDir = setupKeys()
    outFile = os.path.join(tmpDir, "msg.pgp")

    message = b"test message round trip"
    options = {
        "sign": True, "encrypt": True, "compress": True, "radix64": True,
        "signKeyId": aliceId, "password": "alicepw",
        "recipientKeyId": bobId, "algorithm": "AES128",
    }

    sender.pgpSend(km, message, "test.txt", outFile, options)
    result = receiver.pgpReceive(km, outFile, "bobpw")

    assert result["error"] is None
    assert result["message"] == message
    assert result["verified"] is True
    assert result["author"] == "Alice <alice@x.com>"


def test_encrypt_only_no_sign():
    km, aliceId, bobId, tmpDir = setupKeys()
    outFile = os.path.join(tmpDir, "msg.pgp")

    message = b"encrypted but not signed"
    options = {
        "sign": False, "encrypt": True, "compress": False, "radix64": False,
        "recipientKeyId": bobId, "algorithm": "AES128",
    }

    sender.pgpSend(km, message, "test.txt", outFile, options)
    result = receiver.pgpReceive(km, outFile, "bobpw")

    assert result["message"] == message
    assert result["verified"] is None