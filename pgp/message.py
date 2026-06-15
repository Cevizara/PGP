"""The PGP message engine.

Read this file top-to-bottom like the slide diagrams:
  - the SEND substeps, then `pgpSend` (the send orchestrator),
  - the RECEIVE substeps, then `pgpReceive` (the receive orchestrator).

Each substep is one small, clearly named function; the orchestrators just call
them in order. The on-disk file is a JSON "outer container" (UTF-8); binary
fields are Base64 so they fit in JSON. When radix-64 is on, the whole container
is Base64-armored.

  Outer:  version, flags (signed/compressed/encrypted/radix64), sym_algo, iv,
          session_key {recipient_key_id, enc_session_key}, payload
  Inner:  message {filename, timestamp, data}
          signature {timestamp, signer_key_id, leading_two_octets, signature}

ORDER (send):     sign -> compress -> encrypt -> radix64
ORDER (receive):  un-radix64 -> decrypt -> decompress -> verify
"""

import json
import base64
import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone

from pgp.keymanager import KeyManager

from . import keys as K
from . import ciphers
from . import compression
from . import radix64
from .errors import KeyNotFound, MessageError, NeedPassphrase

VERSION = "PGP-ZP/1.0"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.b64decode(text)


# =========================================================================== #
# SEND substeps                                                               #
# =========================================================================== #

@dataclass
class HeaderOptions:
    sign: bool=False
    signerKeyId: str=""
    passphrase: str=""
    encrypt: bool=False
    recipientKeyId: str="" 
    symAlgo: str="AES-128"
    compress: bool=False
    radix64: bool=False
    iv: bytes | None = None
    sessionKeyComponent: dict | None = None

def getPrivateKey(km: KeyManager, key_id: str, passphrase: str):
    """Decrypt our private key from the private ring (asks the passphrase)."""
    key = km.get_private_key(key_id, passphrase)
    print(f"Using private key {key_id} for signing.")
    return key


def buildMessageComponent(message: bytes, filename: str) -> dict:
    """The message component: the data itself + its name + a timestamp."""
    msgComponent = {"filename": filename, "timestamp": _now(), "data": _b64(message)}
    print(f"Built message component with filename '{filename}' and timestamp {msgComponent['timestamp']}.")
    print(f"Message data (Base64-encoded): {msgComponent['data'][:60]}... (truncated)")
    return msgComponent


def hashMessage(message: bytes, timestamp: str) -> bytes:
    """H(M || timestamp) -> 160-bit SHA-1 digest (timestamp bound in for anti-replay)."""
    hash = hashlib.sha1(message + timestamp.encode("utf-8")).digest()
    print(f"Computed hash of message + timestamp: {hash.hex()}")
    return hash


def buildSignature(message: bytes, privateKey, signerKeyId: str) -> dict:
    """The signature component: sign H(M||ts) with the sender's private key."""
    timestamp = _now()
    digest = hashMessage(message, timestamp)
    signature = K.rsaSign(privateKey, message + timestamp.encode("utf-8"))
    print(f"Signature: {_b64(signature)}")
    return {
        "timestamp": timestamp,
        "signerKeyId": signerKeyId,
        "leadingTwoOctets": digest[:2].hex().upper(),
        "signature": _b64(signature),
    }


def concat(signatureComponent, messageComponent) -> bytes:
    """The '||' block: signature (optional) + message, serialized to bytes."""
    inner = {"message": messageComponent}
    if signatureComponent is not None:
        inner["signature"] = signatureComponent
    print(f"Concatenated inner block with message and {'signature' if signatureComponent else 'no signature'}.")
    return json.dumps(inner).encode("utf-8")


def compress(data: bytes) -> bytes:
    """Z(data) — ZIP compression."""
    return compression.compressData(data)


def generateSessionKey(algo: str) -> bytes:
    """A fresh random one-time session key Ks for this message."""
    Ks = ciphers.generateSessionKey(algo)
    print(f"Generated session key: {_b64(Ks)}")
    return Ks


def encryptMessage(algorithm: str, sessionKey: bytes, data: bytes):
    """EC(Ks, data) — symmetric encrypt. Returns (iv, ciphertext)."""
    return ciphers.symmetricEncrypt(algorithm, sessionKey, data)


def getRecipientPublicKey(km, key_id):
    """PUb — recipient's public key from the public ring (or our own keys)."""
    entry = km.public_ring.get(key_id) or km.private_ring.get(key_id)
    if not entry:
        raise KeyNotFound(f"Recipient key {key_id} is not in your keyring.")
    PUb = K.loadPublicKeyFromPem(entry.public_key.encode("utf-8"))
    print(f"PUb for recipient {key_id} loaded.")
    return PUb


def encryptSessionKey(public_key, session_key: bytes) -> bytes:
    """EP(PUb, Ks) — encrypt the session key with the recipient's public key."""
    return K.rsaEncrypt(public_key, session_key)


def buildSessionKeyComponent(encryptedSessionKey: bytes, recipientKeyId: str) -> dict:
    """The session-key component: recipient's Key ID + E[PUb, Ks]."""
    return {"recipientKeyId": recipientKeyId,
            "encryptedSessionKey": _b64(encryptedSessionKey)}


def assembleOutput(payload, options: HeaderOptions) -> bytes:
    """The final outer container (JSON) describing what was applied + the payload."""
    outer = {
        "version": VERSION,
        "signed": bool(options.sign),
        "compressed": bool(options.compress),
        "encrypted": bool(options.encrypt),
        "radix64": bool(options.radix64),
        "symAlgo": options.symAlgo if options.encrypt else None,
        "iv": _b64(options.iv) if options.encrypt and options.iv is not None else None,
        "sessionKeyComponent": options.sessionKeyComponent if options.encrypt else None,
        "payload": _b64(payload),
    }
    return json.dumps(outer, indent=2).encode("utf-8")


def radix64encode(data: bytes) -> bytes:
    """R64(data) — Base64-armor the whole block into ASCII."""
    return radix64.radix64encode(data).encode("ascii")


# --------------------------------------------------------------------------- #
# Send orchestrator                                                           #
# --------------------------------------------------------------------------- #
def pgpSend(keyManager: KeyManager, message: bytes, filename: str, destPath: str, options: dict) -> bool:
    """Build a PGP message file from `message`. Returns the file bytes."""
    sign = options.get("sign", False)
    encrypt = options.get("encrypt", False)
    compress = options.get("compress", False)
    radix64 = options.get("radix64", False)
    algorithmId = 0
    
    X = concat(None, buildMessageComponent(message, filename))

    if sign:
        PRa = keyManager.getPrivateKey(options["signerKeyId"], options["passphrase"])
        signatureBlock = buildSignature(message, PRa, options["signerKeyId"])
        X = concat(signatureBlock, X)

    if compress:
        X = compress(X)

    if encrypt:
        algorithm = options["algorithm"]
        
        Ks = generateSessionKey(algorithm)
        iv, X = encryptMessage(algorithm, Ks, X)
        
        PUb = keyManager.getRecipientPublicKey(options["recipientKeyId"])
        enc_Ks = encryptSessionKey(PUb, Ks)
        
        sessionKeyBlock = buildSessionKeyComponent(enc_Ks, options["recipientKeyId"], algorithm)
        X = concat(sessionKeyBlock, X)
        
        algorithmId = getAlgorithmId(algorithm)

    if radix64:
        X = radix64encode(X)
        
        
    headerBytes = fs.encodeHeader(
        signed = sign,
        encrypted = encrypt,
        compressed = compress,
        radix64 = radix64,
        algorithmId = algorithmId,
    )
    fs.serializeToFIle(X, headerBytes, destPath)
    return True


# =========================================================================== #
# RECEIVE                                                                     #
# =========================================================================== #
@dataclass
class MessageInfo:
    """What the file declares about itself — readable without any passphrase."""
    radix64: bool = False
    encrypted: bool = False
    signed: bool = False
    compressed: bool = False
    sym_algo: str | None = None
    recipient_key_id: str | None = None
    _outer: dict = None


@dataclass
class MessageResult:
    message_bytes: bytes = b""
    filename: str = "message"
    msg_timestamp: str = ""
    was_encrypted: bool = False
    was_compressed: bool = False
    was_signed: bool = False
    sym_algo: str | None = None
    recipient_key_id: str | None = None
    # signature outcome: True = valid, False = invalid, None = could not check
    signature_valid: object = None
    signer_key_id: str | None = None
    signer_user_id: str | None = None
    sig_timestamp: str = ""
    signer_note: str = ""


def radix64decode(text: str) -> bytes:
    """R64_inv — Base64 ASCII back to binary."""
    return radix64.radix64decode(text)


def inspectMessage(raw: bytes) -> MessageInfo:
    """Read only the outer header so the GUI knows what services were applied
    (and which key it is encrypted to) before asking for a passphrase."""
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise MessageError("Not a valid PGP message file (bad encoding).")

    try:
        # A non-armored file is raw JSON; an armored file is Base64 of that JSON.
        try:
            outer = json.loads(text)
            is_armored = False
        except json.JSONDecodeError:
            outer = json.loads(radix64decode(text))
            is_armored = True
    except (ValueError, json.JSONDecodeError) as exc:
        raise MessageError(f"Not a valid PGP message file.\n({exc})")

    if "payload" not in outer:
        raise MessageError("Not a valid PGP message file (missing payload).")

    session = outer.get("session_key") or {}
    return MessageInfo(
        radix64=is_armored or bool(outer.get("radix64")),
        encrypted=bool(outer.get("encrypted")),
        signed=bool(outer.get("signed")),
        compressed=bool(outer.get("compressed")),
        sym_algo=outer.get("sym_algo"),
        recipient_key_id=session.get("recipient_key_id"),
        _outer=outer,
    )


# --------------------------------------------------------------------------- #
# Receive substeps                                                            #
# --------------------------------------------------------------------------- #

def parseSessionKeyComponent(outer: dict):
    """Extract recipient Key ID, encrypted Ks, IV and algorithm from the header."""
    session = outer.get("session_key") or {}
    return (session.get("recipient_key_id"),
            _unb64(session["enc_session_key"]),
            _unb64(outer["iv"]),
            outer["sym_algo"])


def decryptSessionKey(private_key, encrypted_session_key: bytes) -> bytes:
    """DP(PRb, E[PUb, Ks]) -> Ks."""
    return K.rsaDecrypt(private_key, encrypted_session_key)


def decryptMessage(session_key: bytes, iv: bytes, ciphertext: bytes, algo: str) -> bytes:
    """DC(Ks, ciphertext) -> compressed signature+message."""
    return ciphers.symmetricDecrypt(algo, session_key, iv, ciphertext)


def decompress(data: bytes) -> bytes:
    """Z_inv(data) — ZIP decompression."""
    return compression.decompressData(data)


def parseSignedMessage(inner_bytes: bytes):
    """Split the inner block into (messageComponent, signatureComponent or None)."""
    inner = json.loads(inner_bytes)
    return inner["message"], inner.get("signature")


def getSenderPublicKey(km, key_id):
    """PUa — sender's public key (from contacts, or our own). Returns (key, user_id)
    or (None, None) if not found."""
    entry = km.public_ring.get(key_id) or km.private_ring.get(key_id)
    if not entry:
        return None, None
    return K.loadPublicKeyFromPem(entry.public_key.encode("utf-8")), entry.user_id


def verifySignature(public_key, signatureComponent: dict, message: bytes) -> bool:
    """Recompute H(M||ts) and check it against the signature with the sender's PUa."""
    timestamp = signatureComponent.get("timestamp", "")
    digest = hashMessage(message, timestamp)
    if digest[:2].hex().upper() != signatureComponent.get("leading_two_octets"):
        return False
    return K.rsaVerify(public_key, _unb64(signatureComponent["signature"]),
                        message + timestamp.encode("utf-8"))


# --------------------------------------------------------------------------- #
# Receive orchestrator                                                        #
# --------------------------------------------------------------------------- #
def pgpReceive(km, raw: bytes, passphrase: str | None = None) -> MessageResult:
    """Reverse every applied stage and verify the signature.

    Raises NeedPassphrase if encrypted to a key we hold but no passphrase given,
    WrongPassphrase on a bad passphrase, MessageError on missing keys / corruption.
    A bad/unverifiable signature is reported via MessageResult.signature_valid."""

    info = inspectMessage(raw)
    outer = info._outer
    X = _unb64(outer["payload"])

    result = MessageResult(was_encrypted=info.encrypted, was_compressed=info.compressed,
                           was_signed=info.signed, sym_algo=info.sym_algo,
                           recipient_key_id=info.recipient_key_id)

    # 1. decrypt (optional)
    if info.encrypted:
        recipient_key_id, encrypted_Ks, iv, algo = parseSessionKeyComponent(outer)
        priv_entry = km.private_ring.get(recipient_key_id)
        if not priv_entry:
            raise MessageError(f"This message is encrypted to key {recipient_key_id}, "
                               "which is not in your private key ring.")
        if passphrase is None:
            raise NeedPassphrase(recipient_key_id, priv_entry.user_id)
        PRb = loadPrivateKey(km, recipient_key_id, passphrase)     # may raise WrongPassphrase
        Ks = decryptSessionKey(PRb, encrypted_Ks)
        try:
            X = decryptMessage(Ks, iv, X, algo)
        except Exception as exc:
            raise MessageError(f"Decryption failed.\n({exc})")

    # 2. decompress (optional)
    if info.compressed:
        try:
            X = decompress(X)
        except Exception:
            raise MessageError("Decompression failed — the file is corrupt or was "
                               "not decrypted correctly.")

    # 3. parse the inner block
    try:
        messageComponent, signatureComponent = parseSignedMessage(X)
        message = _unb64(messageComponent["data"])
    except Exception as exc:
        raise MessageError(f"Could not read the message body.\n({exc})")

    result.message_bytes = message
    result.filename = messageComponent.get("filename", "message")
    result.msg_timestamp = messageComponent.get("timestamp", "")

    # 4. verify signature (optional)
    if info.signed and signatureComponent:
        signer_key_id = signatureComponent.get("signer_key_id")
        result.signer_key_id = signer_key_id
        result.sig_timestamp = signatureComponent.get("timestamp", "")
        PUa, signer_user_id = getSenderPublicKey(km, signer_key_id)
        if PUa is None:
            result.signature_valid = None
            result.signer_note = (f"Signer key {signer_key_id} is not in your keyring, "
                                  "so the signature could not be verified.")
        else:
            result.signature_valid = verifySignature(PUa, signatureComponent, message)
            result.signer_user_id = signer_user_id

    return result
