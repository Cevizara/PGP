"""RSA key operations: generation, PEM import/export, Key ID and fingerprint.

We use the `cryptography` library for the RSA primitive (allowed by the task
rules). Everything here is stateless — it only deals with key objects and PEM
bytes; storage and passphrase protection live in other modules.
"""

import hashlib

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    PrivateFormat,
    NoEncryption,
    BestAvailableEncryption,
    load_pem_public_key,
    load_pem_private_key,
)

ALLOWED_KEY_SIZES = (1024, 2048)


def generate_rsa_keypair(key_size: int):
    """Generate a fresh RSA key pair. Returns (private_key, public_key)."""
    if key_size not in ALLOWED_KEY_SIZES:
        raise ValueError("Key size must be 1024 or 2048 bits.")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    return private_key, private_key.public_key()


def compute_key_id(public_key) -> str:
    """Key ID = low-order 64 bits of the RSA modulus n  (PU mod 2**64).

    This is the definition used in the course material (Stallings PGP).
    RFC 4880 V4 keys instead take the low 64 bits of the SHA-1 fingerprint;
    we follow the course definition and keep the fingerprint separately.
    Returned as 16 uppercase hex digits.
    """
    n = public_key.public_numbers().n
    return format(n & 0xFFFFFFFFFFFFFFFF, "016X")


def compute_fingerprint(public_key) -> str:
    """SHA-1 hash over the DER-encoded public key, shown as uppercase hex.

    Inspired by RFC 4880's fingerprint idea; used here only for display so a
    user can compare keys out-of-band (e.g. over the phone).
    """
    der = public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha1(der).hexdigest().upper()


def key_size_of(public_key) -> int:
    return public_key.key_size


# --- PEM serialization -------------------------------------------------------

def public_key_to_pem(public_key) -> str:
    return public_key.public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
    ).decode("ascii")


def private_key_to_pem(private_key, password: str | None = None) -> bytes:
    """Serialize a private key to PEM. If `password` is given, the PEM itself is
    encrypted (used when exporting a whole pair to a file)."""
    encryption = (
        BestAvailableEncryption(password.encode("utf-8")) if password else NoEncryption()
    )
    return private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, encryption)


def load_public_key_from_pem(data: bytes):
    return load_pem_public_key(data)


def load_private_key_from_pem(data: bytes, password: str | None = None):
    return load_pem_private_key(data, password=password.encode("utf-8") if password else None)


# --- RSA operations used by the message engine ------------------------------
# Used both for the "session-key component" (EP/DP) and the signature (sign/verify).

def rsa_encrypt(public_key, data: bytes) -> bytes:
    """EP(PU, data) — encrypt a small payload (the session key) with a public key."""
    return public_key.encrypt(
        data,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None),
    )


def rsa_decrypt(private_key, data: bytes) -> bytes:
    """DP(PR, data) — recover the session key with the matching private key."""
    return private_key.decrypt(
        data,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None),
    )


def rsa_sign(private_key, data: bytes) -> bytes:
    """Signature = E(PR, H(data)). cryptography hashes with SHA-1 internally and
    applies the RSA private-key operation (PKCS#1 v1.5), which is exactly the
    'encrypt the digest with the private key' idea from the slides."""
    return private_key.sign(data, padding.PKCS1v15(), hashes.SHA1())


def rsa_verify(public_key, signature: bytes, data: bytes) -> bool:
    """True iff `signature` is a valid SHA-1/RSA signature over `data`."""
    try:
        public_key.verify(signature, data, padding.PKCS1v15(), hashes.SHA1())
        return True
    except Exception:
        return False
