"""The PGP message *components* (packets): how each piece is built and parsed.

  message   packet : {filename, timestamp, data}
  signature packet : {timestamp, signer_key_id, leading_two_octets, signature}
  session-key packet: {recipient_key_id, enc_session_key}

Binary fields are Base64 so they fit inside the JSON container. This module has
no notion of files or orchestration — it just turns bytes into packets and back.
"""

import json
import base64
from datetime import datetime, timezone

from . import cryptoPrimitives as cp


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def unb64(text: str) -> bytes:
    return base64.b64decode(text)


# ------------------------------------------------------------------ #
# message packet                                                     #
# ------------------------------------------------------------------ #
def buildMessageComponent(message: bytes, filename: str) -> dict:
    """The data itself + its name + a timestamp."""
    return {"filename": filename, "timestamp": now(), "data": b64(message)}


# ------------------------------------------------------------------ #
# signature packet                                                   #
# ------------------------------------------------------------------ #
def hashMessage(message: bytes, timestamp: str) -> bytes:
    """H(M || timestamp) -> SHA-1 digest (timestamp bound in for anti-replay)."""
    return cp.sha1(message + timestamp.encode("utf-8"))


def buildSignature(message: bytes, privateKey, signerKeyId: str) -> dict:
    """Sign H(M||ts) with the sender's private key."""
    timestamp = now()
    digest = hashMessage(message, timestamp)
    signature = cp.rsaSign(privateKey, message + timestamp.encode("utf-8"))
    return {
        "timestamp": timestamp,
        "signer_key_id": signerKeyId,
        "leading_two_octets": digest[:2].hex().upper(),
        "signature": b64(signature),
    }


def verifySignature(publicKey, signatureComponent: dict, message: bytes) -> bool:
    """Recompute H(M||ts) and check it against the signature with the sender's key."""
    timestamp = signatureComponent.get("timestamp", "")
    digest = hashMessage(message, timestamp)
    if digest[:2].hex().upper() != signatureComponent.get("leading_two_octets"):
        return False
    return cp.rsaVerify(publicKey, unb64(signatureComponent["signature"]),
                        message + timestamp.encode("utf-8"))


# ------------------------------------------------------------------ #
# inner block  (message packet [+ signature packet])                 #
# ------------------------------------------------------------------ #
def packInner(messageComponent: dict, signatureComponent: dict | None = None) -> bytes:
    """Serialize the signature (optional) + message block to bytes."""
    inner = {"message": messageComponent}
    if signatureComponent is not None:
        inner["signature"] = signatureComponent
    return json.dumps(inner).encode("utf-8")


def unpackInner(inner_bytes: bytes):
    """Split the inner block into (messageComponent, signatureComponent or None)."""
    inner = json.loads(inner_bytes)
    return inner["message"], inner.get("signature")


# ------------------------------------------------------------------ #
# session-key packet                                                 #
# ------------------------------------------------------------------ #
def buildSessionKeyComponent(encryptedSessionKey: bytes, recipientKeyId: str) -> dict:
    """Recipient's Key ID + E[PUb, Ks]."""
    return {"recipient_key_id": recipientKeyId,
            "enc_session_key": b64(encryptedSessionKey)}


def parseSessionKeyComponent(outer: dict):
    """Extract (recipientKeyId, encryptedKs, iv, algorithm) from the container."""
    session = outer.get("session_key") or {}
    return (session.get("recipient_key_id"),
            unb64(session["enc_session_key"]),
            unb64(outer["iv"]),
            outer["sym_algo"])
