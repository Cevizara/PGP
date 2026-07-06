"""Send orchestrator — build a PGP message file from a message + chosen services.

The body reads as the pipeline itself: one optional step per `if`, in the
textbook order, each step calling a small named helper elsewhere:

    sign  ->  compress  ->  encrypt  ->  radix-64

This file only decides *which* steps run and in what order; the actual work
lives in messageComponents / fileSerializer / cryptoPrimitives.
"""

from . import keys as K
from . import cryptoPrimitives as cp
from . import messageComponents as mc
from . import fileSerializer as fs
from .errors import KeyNotFound


def _recipientPublicKey(km, keyId):
    """PUb — recipient's public key from the public ring (or our own keys)."""
    entry = km.public_ring.get(keyId) or km.private_ring.get(keyId)
    if not entry:
        raise KeyNotFound(f"Recipient key {keyId} is not in your keyring.")
    return K.loadPublicKeyFromPem(entry.public_key.encode("utf-8"))


def pgpSend(km, message: bytes, filename: str, *,
            signRequired=False, signerKeyId=None, passphrase=None,
            confidentialityRequired=False, recipientKeyId=None, symAlgo="AES-128",
            compressRequired=False, radix64Required=False) -> bytes:
    """Build a PGP message file from `message`. Returns the file bytes."""

    # message packet (+ signature packet if signing)
    signature = None
    if signRequired:
        privateKey = km.get_private_key(signerKeyId, passphrase)     # asks the passphrase
        signature = mc.buildSignature(message, privateKey, signerKeyId)
    payload = mc.packInner(mc.buildMessageComponent(message, filename), signature)

    # compress
    if compressRequired:
        payload = cp.compressData(payload)

    # encrypt: payload -> ciphertext, and wrap the session key for the recipient
    iv = None
    sessionKeyComponent = None
    if confidentialityRequired:
        sessionKey = cp.generateSessionKey(symAlgo)
        iv, payload = cp.symmetricEncrypt(symAlgo, sessionKey, payload)
        encryptedSessionKey = cp.rsaEncrypt(_recipientPublicKey(km, recipientKeyId), sessionKey)
        sessionKeyComponent = mc.buildSessionKeyComponent(encryptedSessionKey, recipientKeyId)

    # wrap everything in the file container
    container = fs.assembleContainer(
        signed=signRequired, compressed=compressRequired, encrypted=confidentialityRequired,
        radix64=radix64Required, symAlgo=symAlgo, iv=iv,
        sessionKeyComponent=sessionKeyComponent, payload=payload)

    # radix-64 armor
    if radix64Required:
        container = fs.armor(container)
    return container
