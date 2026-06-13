"""Symmetric (session-key) encryption for the message body.

The project requires supporting two of {TripleDES, AES128, Cast5, IDEA}.
We chose AES-128 and 3DES (TripleDES) because both are clean and well supported
by the `cryptography` library. The slides specify CFB mode for PGP confidentiality,
so we use CFB — a stream-style mode that needs no padding. A fresh random IV is
generated per message and travels (in the clear, it is not secret) with the file.
"""

import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
# TripleDES and CFB live in the "decrepit" module in modern cryptography versions
# (they are legacy primitives). PGP/the slides use exactly these, so we import
# them from their current location to avoid deprecation warnings.
from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
from cryptography.hazmat.decrepit.ciphers.modes import CFB

# Public registry — the GUI offers these names; the engine looks up the spec.
ALGORITHMS = {
    "AES-128": {"key_size": 16, "iv_size": 16, "cipher": algorithms.AES},
    "3DES":    {"key_size": 24, "iv_size": 8,  "cipher": TripleDES},
}

ALGORITHM_NAMES = list(ALGORITHMS.keys())


def generate_session_key(algo: str) -> bytes:
    """Random one-time key for this message (the slide's Ks)."""
    return os.urandom(ALGORITHMS[algo]["key_size"])


def symmetric_encrypt(algo: str, key: bytes, data: bytes):
    """EC(Ks, data). Returns (iv, ciphertext)."""
    spec = ALGORITHMS[algo]
    iv = os.urandom(spec["iv_size"])
    encryptor = Cipher(spec["cipher"](key), CFB(iv)).encryptor()
    return iv, encryptor.update(data) + encryptor.finalize()


def symmetric_decrypt(algo: str, key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """DC(Ks, ciphertext)."""
    spec = ALGORITHMS[algo]
    decryptor = Cipher(spec["cipher"](key), CFB(iv)).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()
