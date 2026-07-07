"""The on-disk file format: the outer JSON container and how to read it.

  Outer: flags (signed/compressed/encrypted/radix64), sym_algo, iv,
         session_key {recipient_key_id, enc_session_key}, payload

`assembleContainer` writes it, `inspectMessage` reads the header back (without
any passphrase), and `armor`/inspect handle the optional radix-64 wrapping of
the whole container.
"""

import json
from dataclasses import dataclass

from . import messageComponents as MessageComponents
from . import cryptoPrimitives as CryptoPrimitives
from .errors import MessageError


@dataclass
class MessageInfo:
    """What the file declares about itself — readable without any passphrase."""
    radix64: bool = False
    encrypted: bool = False
    signed: bool = False
    compressed: bool = False
    sym_algo: str | None = None
    recipient_key_id: str | None = None
    outer: dict = None


def assembleContainer(*, signed, compressed, encrypted, radix64,
                      symAlgo, iv, sessionKeyComponent, payload) -> bytes:
    """The final outer container (JSON) describing what was applied + the payload."""
    outer = {
        "signed": bool(signed),
        "compressed": bool(compressed),
        "encrypted": bool(encrypted),
        "radix64": bool(radix64),
        "sym_algo": symAlgo if encrypted else None,
        "iv": MessageComponents.b64(iv) if iv is not None else None,
        "session_key": sessionKeyComponent,
        "payload": MessageComponents.b64(payload),
    }
    return json.dumps(outer, indent=2).encode("utf-8")


def armor(container: bytes) -> bytes:
    """R64 — Base64-armor the whole container into ASCII."""
    return CryptoPrimitives.radix64encode(container).encode("ascii")


def inspectMessage(raw: bytes) -> MessageInfo:
    """Read only the outer header so the caller knows what services were applied
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
            outer = json.loads(CryptoPrimitives.radix64decode(text))
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
        outer=outer,
    )


def payloadBytes(info: MessageInfo) -> bytes:
    """The raw payload bytes carried by the container."""
    return MessageComponents.unb64(info.outer["payload"])
