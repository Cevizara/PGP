import json
import base64
from datetime import datetime, timezone

from . import cryptoPrimitives as CryptoPrimitives


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def unb64(text: str) -> bytes:
    return base64.b64decode(text)


#message packet
def buildMessageComponent(message: bytes, filename: str) -> dict:
    #the data itself + its name + a timestamp
    return {"filename": filename, "timestamp": now(), "data": b64(message)}


#signature packet
def hashMessage(message: bytes, timestamp: str) -> bytes:
    #hash(M || timestamp) -> SHA-1 digest (anti replay zbog timestampa)
    return CryptoPrimitives.sha1(message + timestamp.encode("utf-8"))


def buildSignature(message: bytes, privateKey, signerKeyId: str) -> dict:
    #sign hash(M || timestamp) with the sender private key
    timestamp = now()
    digest = hashMessage(message, timestamp)
    signature = CryptoPrimitives.rsaSign(privateKey, message + timestamp.encode("utf-8"))
    first_two_bytes = digest[:2]                     # prva dva bajta
    leading_two_octets = first_two_bytes.hex().upper() 
    return {
        "timestamp": timestamp,
        "signer_key_id": signerKeyId,
        "leading_two_octets": leading_two_octets,
        "signature": b64(signature),
    }


def verifySignature(publicKey, signatureComponent: dict, message: bytes) -> bool:
    #recompute hash(M || timestamp) and check it against the signature with the sender's key
    timestamp = signatureComponent.get("timestamp", "")
    digest = hashMessage(message, timestamp)
    first_two_bytes = digest[:2]                     # prva dva bajta ponovo izracunatog hash-a
    leading_two_octets = first_two_bytes.hex().upper()
    if leading_two_octets != signatureComponent.get("leading_two_octets"):
        return False
    return CryptoPrimitives.rsaVerify(publicKey, unb64(signatureComponent["signature"]),
                        message + timestamp.encode("utf-8"))


#inner block  (message packet [+ signature packet])
def packInner(messageComponent: dict, signatureComponent: dict | None = None) -> bytes:
    #serialize the signature (optional) + message block to bytes
    inner = {"message": messageComponent}
    if signatureComponent is not None:
        inner["signature"] = signatureComponent
    return json.dumps(inner).encode("utf-8")


def unpackInner(inner_bytes: bytes):
    #split the inner block into (messageComponent, signatureComponent or None)
    inner = json.loads(inner_bytes)
    return inner["message"], inner.get("signature")


#session-key packet
def buildSessionKeyComponent(encryptedSessionKey: bytes, recipientKeyId: str) -> dict:
    #recipient's Key ID + E[PUb, Ks]
    return {"recipient_key_id": recipientKeyId,
            "enc_session_key": b64(encryptedSessionKey)}


def parseSessionKeyComponent(outer: dict):
    #extract (recipientKeyId, encryptedKs, iv, algorithm) from the container
    session = outer.get("session_key") or {}
    return (session.get("recipient_key_id"),
            unb64(session["enc_session_key"]),
            unb64(outer["iv"]),
            outer["sym_algo"])
