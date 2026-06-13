"""Radix-64 (ASCII armor) — the slide's R64 / R64^-1.

Converts the raw binary message block into printable ASCII so it survives plain
email/chat. This mirrors OpenPGP's ASCII armor: Base64 of the data, wrapped in
BEGIN/END lines, with a trailing CRC-24 checksum (=XXXX) for error detection —
exactly the "radix-64 adds a CRC" point from the slides.
"""

import base64

HEADER = "-----BEGIN PGP MESSAGE-----"
FOOTER = "-----END PGP MESSAGE-----"


def _crc24(data: bytes) -> int:
    """CRC-24 as defined for OpenPGP (RFC 4880 §6.1)."""
    crc = 0x00B704CE
    for byte in data:
        crc ^= byte << 16
        for _ in range(8):
            crc <<= 1
            if crc & 0x01000000:
                crc ^= 0x01864CFB
    return crc & 0x00FFFFFF


def armor(data: bytes) -> str:
    """Binary block -> armored ASCII text."""
    b64 = base64.b64encode(data).decode("ascii")
    lines = [b64[i:i + 64] for i in range(0, len(b64), 64)]
    crc = _crc24(data).to_bytes(3, "big")
    crc_b64 = base64.b64encode(crc).decode("ascii")
    body = "\n".join(lines)
    return f"{HEADER}\n\n{body}\n={crc_b64}\n{FOOTER}\n"


def is_armored(text: str) -> bool:
    return HEADER in text


def dearmor(text: str) -> bytes:
    """Armored ASCII text -> binary block. Verifies the CRC-24 if present."""
    lines = text.splitlines()
    try:
        start = next(i for i, l in enumerate(lines) if HEADER in l)
        end = next(i for i, l in enumerate(lines) if FOOTER in l)
    except StopIteration:
        raise ValueError("Radix-64 armor header/footer not found.")

    payload_parts = []
    crc_value = None
    for line in lines[start + 1:end]:
        s = line.strip()
        if not s:
            continue
        if s.startswith("="):           # the CRC line
            crc_value = s[1:]
            continue
        payload_parts.append(s)

    data = base64.b64decode("".join(payload_parts))
    if crc_value is not None:
        expected = int.from_bytes(base64.b64decode(crc_value), "big")
        if _crc24(data) != expected:
            raise ValueError("Radix-64 CRC check failed — the file is corrupted.")
    return data
