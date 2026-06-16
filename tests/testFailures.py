import os
import tempfile

from pgp import keyRing as kr
from pgp import keyGeneration as kg
from pgp import pgpSend as sender
from pgp import pgpReceive as receiver


def test_wrong_password():
    tmpDir = tempfile.mkdtemp()
    km = kr.KeyManager(
        privateRingPath=os.path.join(tmpDir, "priv.json"),
        publicRingPath=os.path.join(tmpDir, "pub.json"),
    )
    bobId = kg.generateKeyPair(km, "Bob", "bob@x.com", 2048, "bobpw")
    outFile = os.path.join(tmpDir, "msg.pgp")

    options = {
        "sign": False, "encrypt": True, "compress": False, "radix64": False,
        "recipientKeyId": bobId, "algorithm": "AES128",
    }
    sender.pgpSend(km, b"secret", "f.txt", outFile, options)

    result = receiver.pgpReceive(km, outFile, "wrongpassword")
    assert result["error"] is not None
    assert result["message"] is None


def test_invalid_file():
    tmpDir = tempfile.mkdtemp()
    km = kr.KeyManager(
        privateRingPath=os.path.join(tmpDir, "priv.json"),
        publicRingPath=os.path.join(tmpDir, "pub.json"),
    )
    badFile = os.path.join(tmpDir, "garbage.pgp")
    with open(badFile, "wb") as f:
        f.write(b"this is not a pgp file")

    result = receiver.pgpReceive(km, badFile, "anypw")
    assert result["error"] is not None