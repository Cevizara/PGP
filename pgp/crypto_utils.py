"""Protecting the private key at rest with the user's passphrase.

This implements the slide "prsten privatnih ključeva":
  - derive a symmetric key from the passphrase,
  - symmetric-encrypt the private key with it.

We use a salted SHA-1 string-to-key (RFC 4880 §3.7.1.2 style) producing a
128-bit key, then AES-128-CBC. AES-128 is one of the two symmetric algorithms
this project supports, and 128 bits matches the slide's "128-bit hash code".
"""

import os
import base64
import hashlib

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

from .errors import WrongPassphrase


def deriveKey(passphrase: str, salt: bytes) -> bytes:
    """Salted S2K: SHA-1(salt || passphrase) truncated to 128 bits."""
    digest = hashlib.sha1(salt + passphrase.encode("utf-8")).digest()
    return digest[:16]


def encryptPrivateKey(private_pem: bytes, passphrase: str) -> dict:
    """Encrypt the PEM bytes of a private key. Returns a JSON-serializable blob."""
    salt = os.urandom(16)
    iv = os.urandom(16)
    key = deriveKey(passphrase, salt)

    padder = PKCS7(128).padder()
    padded = padder.update(private_pem) + padder.finalize()

    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    return {
        "algo": "AES-128-CBC",
        "s2k": "salted-sha1",
        "salt": base64.b64encode(salt).decode("ascii"),
        "iv": base64.b64encode(iv).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }


def decryptPrivateKey(blob: dict, passphrase: str) -> bytes:
    """Reverse of `encrypt_private_key`. Raises WrongPassphrase on bad password."""
    salt = base64.b64decode(blob["salt"])
    iv = base64.b64decode(blob["iv"])
    ciphertext = base64.b64decode(blob["ciphertext"])
    key = deriveKey(passphrase, salt)

    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    try:
        padded = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = PKCS7(128).unpadder()
        data = unpadder.update(padded) + unpadder.finalize()
    except ValueError:
        # padding check failed -> wrong key -> wrong passphrase
        raise WrongPassphrase("Incorrect passphrase.")

    # Second sanity check: a correct decryption yields a PEM private key.
    if b"PRIVATE KEY" not in data:
        raise WrongPassphrase("Incorrect passphrase.")
    return data
