import base64
from datetime import datetime, timezone
import hashlib
import os
import zlib

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.decrepit.ciphers import algorithms as decrepit_algorithms
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
    
def rsaDecrypt(privateKey, encryptedSessionKey: bytes) -> bytes:
    """Decrypt session key with recipient's private key."""
    return privateKey.decrypt(
        encryptedSessionKey,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
    )
    
def rsaVerify(publicKey, signature: bytes, digest: bytes) -> bool:
    """Verify a prehashed SHA-1 digest signature."""
    from cryptography.exceptions import InvalidSignature
    try:
        publicKey.verify(
            signature,
            digest,
            padding.PKCS1v15(),
            Prehashed(hashes.SHA1())
        )
        return True
    except InvalidSignature:
        return False

# ------------------------------------------------------
# Symmetric encryption
# ------------------------------------------------------
def buildCipherAlgorithm(algorithm: str, sessionKey: bytes):
    """Map algorithm name -> cryptography cipher algorithm object."""
    if algorithm == "AES128":
        return algorithms.AES(sessionKey)
    elif algorithm == "TripleDES":
        return decrepit_algorithms.TripleDES(sessionKey)
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

def symmetricDecrypt(algorithm: str, sessionKey: bytes, data: bytes) -> bytes:
    """DC -- CFB mode. IV is prepended to data."""
    blockSize = getBlockSize(algorithm)
    iv = data[:blockSize]
    cipherText = data[blockSize:]
    
    cipherAlg = buildCipherAlgorithm(algorithm, sessionKey)
    cipher = Cipher(cipherAlg, CFB(iv))
    decryptor = cipher.decryptor()
    
    return decryptor.update(cipherText) + decryptor.finalize()


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

def decompress(data: bytes) -> bytes:
    """ZIP decompression."""
    return zlib.decompress(data)

# ------------------------------------------------------
# Radix64
# ------------------------------------------------------
def radix64Encode(data: bytes) -> bytes:
    """Base64 encode into ASCII bytes."""
    return base64.b64encode(data)

def radix64Decode(data: bytes) -> bytes:
    """Base64 decode into binary."""
    return base64.b64decode(data)

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

def idToAlgorithm(algorithmId: int) -> str:
    """Map algorithm ID -> algorithm name."""
    mapping = {
        1: "AES128",
        2: "TripleDES"
    }
    if algorithmId not in mapping:
        raise ValueError(f"Unsupported algorithmId {algorithmId}")
    return mapping[algorithmId]


# ------------------------------------------------------
# Utility
# ------------------------------------------------------
def currentTimestamp() -> int:
    """Unix timestamp (seconds)."""
    return int(datetime.now(timezone.utc).timestamp())

