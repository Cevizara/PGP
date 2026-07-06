"""Receive orchestrator — reverse the applied services and verify the signature.

The body reads as the reverse pipeline: one optional step per `if`:

    un-radix-64  ->  decrypt  ->  decompress  ->  verify

(De-armoring + reading the flags happens in fileSerializer.inspectMessage.)
"""

from dataclasses import dataclass

from . import keys as K
from . import cryptoPrimitives as cp
from . import messageComponents as mc
from . import fileSerializer as fs
from .errors import MessageError, NeedPassphrase


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


def _senderPublicKey(km, keyId):
    """PUa — sender's public key (contacts or our own). (key, user_id) or (None, None)."""
    entry = km.public_ring.get(keyId) or km.private_ring.get(keyId)
    if not entry:
        return None, None
    return K.loadPublicKeyFromPem(entry.public_key.encode("utf-8")), entry.user_id


def pgpReceive(km, raw: bytes, passphrase: str | None = None) -> MessageResult:
    """Reverse every applied stage and verify the signature.

    Raises NeedPassphrase if encrypted to a key we hold but no passphrase given,
    WrongPassphrase on a bad passphrase, MessageError on missing keys / corruption.
    A bad/unverifiable signature is reported via MessageResult.signature_valid."""

    info = fs.inspectMessage(raw)          # de-armors + reads the flags
    payload = fs.payloadBytes(info)
    result = MessageResult(was_encrypted=info.encrypted, was_compressed=info.compressed,
                           was_signed=info.signed, sym_algo=info.sym_algo,
                           recipient_key_id=info.recipient_key_id)

    # decrypt
    if info.encrypted:
        recipientKeyId, encryptedKs, iv, algo = mc.parseSessionKeyComponent(info.outer)
        privEntry = km.private_ring.get(recipientKeyId)
        if not privEntry:
            raise MessageError(f"This message is encrypted to key {recipientKeyId}, "
                               "which is not in your private key ring.")
        if passphrase is None:
            raise NeedPassphrase(recipientKeyId, privEntry.user_id)
        privateKey = km.get_private_key(recipientKeyId, passphrase)     # may raise WrongPassphrase
        sessionKey = cp.rsaDecrypt(privateKey, encryptedKs)
        try:
            payload = cp.symmetricDecrypt(algo, sessionKey, iv, payload)
        except Exception as exc:
            raise MessageError(f"Decryption failed.\n({exc})")

    # decompress
    if info.compressed:
        try:
            payload = cp.decompressData(payload)
        except Exception:
            raise MessageError("Decompression failed — the file is corrupt or was "
                               "not decrypted correctly.")

    # read the inner block
    try:
        messageComponent, signatureComponent = mc.unpackInner(payload)
        message = mc.unb64(messageComponent["data"])
    except Exception as exc:
        raise MessageError(f"Could not read the message body.\n({exc})")

    result.message_bytes = message
    result.filename = messageComponent.get("filename", "message")
    result.msg_timestamp = messageComponent.get("timestamp", "")

    # verify
    if info.signed and signatureComponent:
        signerKeyId = signatureComponent.get("signer_key_id")
        result.signer_key_id = signerKeyId
        result.sig_timestamp = signatureComponent.get("timestamp", "")
        publicKey, userId = _senderPublicKey(km, signerKeyId)
        if publicKey is None:
            result.signature_valid = None
            result.signer_note = (f"Signer key {signerKeyId} is not in your keyring, "
                                  "so the signature could not be verified.")
        else:
            result.signature_valid = mc.verifySignature(publicKey, signatureComponent, message)
            result.signer_user_id = userId

    return result
