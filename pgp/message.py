"""The PGP message engine: build a message file (send) and process one (receive).

FILE FORMAT (our own, but faithful to the slide "struktura poruke")
-------------------------------------------------------------------
The on-disk file is a JSON "outer container" (UTF-8). When radix-64 is enabled
the whole container is additionally ASCII-armored (see radix64.py). Binary
fields are Base64 strings so they fit in JSON.

Outer container:
    {
      "version": "...",
      "signed": bool, "compressed": bool, "encrypted": bool, "radix64": bool,
      "sym_algo": "AES-128" | "3DES" | null,
      "iv": <base64> | null,                       # symmetric IV, if encrypted
      "session_key": {                             # present iff encrypted
          "recipient_key_id": "....",
          "enc_session_key": <base64 of EP(PUb, Ks)>
      },
      "payload": <base64>                          # the processed inner block
    }

The "payload" holds the inner block AFTER the chosen transforms:
    inner JSON  --(optional ZIP)-->  --(optional EC(Ks))-->  payload bytes

Inner block (the signature + message components):
    {
      "message":  { "filename": ..., "timestamp": ..., "data": <base64> },
      "signature":{                                # present iff signed
          "timestamp": ...,
          "signer_key_id": "....",
          "leading_two_octets": "ABCD",            # first 2 bytes of SHA-1 digest
          "signature": <base64 of E(PRa, H(data||sig_ts))>
      }
    }

ORDER (send):  sign -> compress -> encrypt -> radix64
ORDER (recv):  un-radix64 -> decrypt -> decompress -> verify
Every stage is optional and independent; the receiver reads the flags and the
structure to decide what to reverse.
"""

import json
import base64
import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone

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


def _find_public_key(km, key_id):
    """Look up a public key by Key ID: first in Contacts, then among own keys."""
    entry = km.public_ring.get(key_id)
    if entry:
        return entry
    return km.private_ring.get(key_id)   # own public part (PrivateKeyEntry also has .public_key)


# --------------------------------------------------------------------------- #
# SEND                                                                        #
# --------------------------------------------------------------------------- #
def create_message(km, message_bytes: bytes, filename: str, *,
                   sign=False, signer_key_id=None, signer_passphrase=None,
                   encrypt=False, recipient_key_id=None, sym_algo="AES-128",
                   compress=False, radix64_armor=False) -> bytes:
    """Build a PGP message file and return its bytes. Raises WrongPassphrase if
    signing and the signer passphrase is wrong, KeyNotFound for missing keys."""

    # --- message component ------------------------------------------------- #
    inner = {
        "message": {
            "filename": filename,
            "timestamp": _now(),
            "data": _b64(message_bytes),
        }
    }

    # --- signature component (sign the UNcompressed data) ------------------ #
    if sign:
        if not km.private_ring.get(signer_key_id):
            raise KeyNotFound(f"Signing key {signer_key_id} is not in your private ring.")
        private_key = km.get_private_key(signer_key_id, signer_passphrase)  # may raise WrongPassphrase
        sig_ts = _now()
        signed_data = message_bytes + sig_ts.encode("utf-8")   # bind timestamp (anti-replay)
        digest = hashlib.sha1(signed_data).digest()
        inner["signature"] = {
            "timestamp": sig_ts,
            "signer_key_id": signer_key_id,
            "leading_two_octets": digest[:2].hex().upper(),
            "signature": _b64(K.rsa_sign(private_key, signed_data)),
        }

    payload = json.dumps(inner).encode("utf-8")

    # --- compression ------------------------------------------------------- #
    if compress:
        payload = compression.compress(payload)

    # --- encryption (+ session-key component) ------------------------------ #
    iv_b64 = None
    session_component = None
    if encrypt:
        pub_entry = _find_public_key(km, recipient_key_id)
        if not pub_entry:
            raise KeyNotFound(f"Recipient key {recipient_key_id} is not in your keyring.")
        public_key = K.load_public_key_from_pem(pub_entry.public_key.encode("utf-8"))
        session_key = ciphers.generate_session_key(sym_algo)
        iv, payload = ciphers.symmetric_encrypt(sym_algo, session_key, payload)
        iv_b64 = _b64(iv)
        session_component = {
            "recipient_key_id": recipient_key_id,
            "enc_session_key": _b64(K.rsa_encrypt(public_key, session_key)),
        }

    # --- outer container --------------------------------------------------- #
    outer = {
        "version": VERSION,
        "signed": bool(sign),
        "compressed": bool(compress),
        "encrypted": bool(encrypt),
        "radix64": bool(radix64_armor),
        "sym_algo": sym_algo if encrypt else None,
        "iv": iv_b64,
        "session_key": session_component,
        "payload": _b64(payload),
    }
    outer_bytes = json.dumps(outer, indent=2).encode("utf-8")

    # --- radix-64 ---------------------------------------------------------- #
    if radix64_armor:
        return radix64.armor(outer_bytes).encode("ascii")
    return outer_bytes


# --------------------------------------------------------------------------- #
# RECEIVE                                                                     #
# --------------------------------------------------------------------------- #
@dataclass
class MessageInfo:
    """What the file declares about itself — readable without any passphrase."""
    radix64: bool = False
    encrypted: bool = False
    signed: bool = False
    compressed: bool = False
    sym_algo: str | None = None
    recipient_key_id: str | None = None
    _outer: dict = field(default_factory=dict, repr=False)


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
    # signature outcome: True=valid, False=invalid, None=could not check
    signature_valid: object = None
    signer_key_id: str | None = None
    signer_user_id: str | None = None
    sig_timestamp: str = ""
    signer_note: str = ""


def inspect_message(raw: bytes) -> MessageInfo:
    """Parse only the outer header so the GUI knows what services were applied
    (and which key it is encrypted to) before asking for a passphrase."""
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise MessageError("Not a valid PGP message file (bad encoding).")

    is_armored = radix64.is_armored(text)
    try:
        outer_bytes = radix64.dearmor(text) if is_armored else raw
        outer = json.loads(outer_bytes)
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


def process_message(km, raw: bytes, passphrase: str | None = None) -> MessageResult:
    """Reverse every applied stage and verify the signature.

    Raises NeedPassphrase if the message is encrypted to a key we hold but no
    passphrase was supplied. Raises WrongPassphrase on a bad passphrase, and
    MessageError on missing keys / corrupt data. A bad or unverifiable signature
    is NOT an exception — it is reported via MessageResult.signature_valid."""

    info = inspect_message(raw)
    outer = info._outer
    payload = _unb64(outer["payload"])

    result = MessageResult(
        was_encrypted=info.encrypted,
        was_compressed=info.compressed,
        was_signed=info.signed,
        sym_algo=info.sym_algo,
        recipient_key_id=info.recipient_key_id,
    )

    # --- decrypt ----------------------------------------------------------- #
    if info.encrypted:
        session = outer.get("session_key") or {}
        rid = session.get("recipient_key_id")
        priv_entry = km.private_ring.get(rid)
        if not priv_entry:
            raise MessageError(
                f"This message is encrypted to key {rid}, which is not in your "
                "private key ring. You cannot decrypt it.")
        if passphrase is None:
            raise NeedPassphrase(rid, priv_entry.user_id)
        private_key = km.get_private_key(rid, passphrase)        # may raise WrongPassphrase
        session_key = K.rsa_decrypt(private_key, _unb64(session["enc_session_key"]))
        iv = _unb64(outer["iv"])
        try:
            payload = ciphers.symmetric_decrypt(outer["sym_algo"], session_key, iv, payload)
        except Exception as exc:
            raise MessageError(f"Decryption failed.\n({exc})")

    # --- decompress -------------------------------------------------------- #
    if info.compressed:
        try:
            payload = compression.decompress(payload)
        except Exception:
            raise MessageError("Decompression failed — the file is corrupt or was "
                               "not decrypted correctly.")

    # --- parse inner block ------------------------------------------------- #
    try:
        inner = json.loads(payload)
        msg = inner["message"]
        data = _unb64(msg["data"])
    except Exception as exc:
        raise MessageError(f"Could not read the message body.\n({exc})")

    result.message_bytes = data
    result.filename = msg.get("filename", "message")
    result.msg_timestamp = msg.get("timestamp", "")

    # --- verify signature -------------------------------------------------- #
    if info.signed and "signature" in inner:
        sig = inner["signature"]
        signer_id = sig.get("signer_key_id")
        result.signer_key_id = signer_id
        result.sig_timestamp = sig.get("timestamp", "")
        signed_data = data + sig.get("timestamp", "").encode("utf-8")
        digest = hashlib.sha1(signed_data).digest()
        leading_ok = digest[:2].hex().upper() == sig.get("leading_two_octets")

        pub_entry = _find_public_key(km, signer_id)
        if pub_entry is None:
            result.signature_valid = None
            result.signer_note = (f"Signer key {signer_id} is not in your keyring, "
                                  "so the signature could not be verified.")
        else:
            public_key = K.load_public_key_from_pem(pub_entry.public_key.encode("utf-8"))
            valid = leading_ok and K.rsa_verify(public_key, _unb64(sig["signature"]), signed_data)
            result.signature_valid = bool(valid)
            result.signer_user_id = pub_entry.user_id

    return result
