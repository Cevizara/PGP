"""
    sign  ->  compress  ->  encrypt  ->  radix-64
"""

from . import keys as Keys
from . import cryptoPrimitives as CryptoPrimitives
from . import messageComponents as MessageComponents
from . import fileSerializer as FileSerializer
from .errors import KeyNotFound


def _recipientPublicKey(km, keyId):
    """PUb — recipient's public key from the public ring (or our own keys)."""
    entry = km.public_ring.get(keyId) or km.private_ring.get(keyId)
    if not entry:
        raise KeyNotFound(f"Recipient key {keyId} is not in your keyring.")
    return Keys.loadPublicKeyFromPem(entry.public_key.encode("utf-8"))


def pgpSend(km, message: bytes, filename: str, *,
            signRequired=False, signerKeyId=None, passphrase=None,
            confidentialityRequired=False, recipientKeyId=None, symAlgo="AES-128",
            compressRequired=False, radix64Required=False) -> bytes:

    print(message)
    # message packet (+ signature packet if signing)
    signature = None
    if signRequired:
        privateKey = km.get_private_key(signerKeyId, passphrase)     # asks the passphrase
        signature = MessageComponents.buildSignature(message, privateKey, signerKeyId)
    payload = MessageComponents.packInner(MessageComponents.buildMessageComponent(message, filename), signature)
    print(payload)

    # compress
    if compressRequired:
        payload = CryptoPrimitives.compressData(payload)

    # encrypt: payload -> ciphertext, and wrap the session key for the recipient
    iv = None
    sessionKeyComponent = None
    if confidentialityRequired:
        sessionKey = CryptoPrimitives.generateSessionKey(symAlgo)
        iv, payload = CryptoPrimitives.symmetricEncrypt(symAlgo, sessionKey, payload)
        encryptedSessionKey = CryptoPrimitives.rsaEncrypt(_recipientPublicKey(km, recipientKeyId), sessionKey)
        sessionKeyComponent = MessageComponents.buildSessionKeyComponent(encryptedSessionKey, recipientKeyId)

    # wrap everything in the file container
    container = FileSerializer.assembleContainer(
        signed=signRequired, compressed=compressRequired, encrypted=confidentialityRequired,
        radix64=radix64Required, symAlgo=symAlgo, iv=iv,
        sessionKeyComponent=sessionKeyComponent, payload=payload)

    # radix-64 armor
    if radix64Required:
        container = FileSerializer.armor(container)
    return container
