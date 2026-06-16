import base64
from datetime import datetime, timezone
import hashlib
import os
import zlib

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.decrepit.ciphers.modes import CFB
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

# ------------------------------------------------------
# Hashing
# ------------------------------------------------------
def sha1Hash(data: bytes) -> bytes:
    """SHA-1 -> 20 byte (160-bit) digest."""
    return hashlib.sha1(data).digest()

# ------------------------------------------------------
# RSA
# ------------------------------------------------------
def rsaSign(privateKey, digest: bytes) -> bytes:
    """Sign a prehashed SHA-1 digest with RSA private key."""
    return privateKey.sign(
        digest,
        padding.PKCS1v15(),
        Prehashed(hashes.SHA1())
    )

def rsaEncrypt(publicKey, sessionKey: bytes) -> bytes:
    """Encrypt a session key with recipient's public key."""
    return publicKey.encrypt(
        sessionKey,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
    )

# ------------------------------------------------------
# Symmetric encryption
# ------------------------------------------------------
def buildCipherAlgorithm(algorithm: str, sessionKey: bytes):
    """Map algorithm name -> cryptography cipher algorithm object."""
    if algorithm == "AES128":
        return algorithms.AES(sessionKey)
    elif algorithm == "TripleDES":
        return algorithms.TripleDES(sessionKey)
    else:
        raise ValueError(f"Unsupported algorithm {algorithm}")

def getBlockSize(algorithm: str) -> int:
    """Block size in bytes (used for IV length)."""
    if algorithm == "AES128":
        return 16
    elif algorithm == "TripleDES":
        return 8
    else:
        raise ValueError(f"Unsupported algorithm {algorithm}")

def symmetricEncrypt(algorithm: str, sessionKey: bytes, data: bytes) -> bytes:
    """EC -- CFB mode. Prepends IV to ciphertext."""
    blockSize = getBlockSize(algorithm)
    iv = os.urandom(blockSize)
    
    cipherAlg = buildCipherAlgorithm(algorithm, sessionKey)
    cipher = Cipher(cipherAlg, CFB(iv))
    encryptor = cipher.encryptor()
    
    cipherText = encryptor.update(data) + encryptor.finalize()
    return iv + cipherText

# ------------------------------------------------------
# Session key generation
# ------------------------------------------------------
def generateSessionKey(algorithm: str) -> bytes:
    """Generate random session key sized per algorithm."""
    if algorithm == "AES128":
        return os.urandom(16)
    elif algorithm == "TripleDES":
        return os.urandom(24)
    else:
        raise ValueError("Unsupported algorithm")

# ------------------------------------------------------
# Compression
# ------------------------------------------------------
def compress(data: bytes) -> bytes:
    """ZIP compression."""
    return zlib.compress(data)

# ------------------------------------------------------
# Radix64 encoding
# ------------------------------------------------------
def radix64Encode(data: bytes) -> bytes:
    """Base64 encode (R64) -> ASCII bytes."""
    return base64.b64encode(data)


# ------------------------------------------------------
# Algorithm Id mapping
# ------------------------------------------------------
def algorithmToId(algorithm: str) -> int:
    """Map algorithm name -> algorithm ID."""
    mapping = {
        "AES128": 1,
        "TripleDES": 2
    }
    if algorithm not in mapping:
        raise ValueError(f"Unsupported algorithm {algorithm}")
    return mapping[algorithm]


# ------------------------------------------------------
# Utility
# ------------------------------------------------------
def currentTimestamp() -> int:
    """Unix timestamp (seconds)."""
    return int(datetime.now(timezone.utc).timestamp())

