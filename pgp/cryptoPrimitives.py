import hashlib
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
from cryptography.hazmat.decrepit.ciphers.modes import CFB

import zlib
import base64


#hashing
def sha1(data: bytes) -> bytes:
    #SHA-1 160 bits digest
    return hashlib.sha1(data).digest()


#RSA operations
def rsaEncrypt(publicKey, data: bytes) -> bytes:
    """EP(PU, data) — used to protect the session key (OAEP/SHA-256)."""
    return publicKey.encrypt(
        data,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None),
    )


def rsaDecrypt(privateKey, data: bytes) -> bytes:
    #DP(PR, data)
    return privateKey.decrypt(
        data,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None),
    )


def rsaSign(privateKey, data: bytes) -> bytes:
    #E(PR, H(M)) — signature over the data, PKCS#1 v1.5 with SHA-1
    return privateKey.sign(data, padding.PKCS1v15(), hashes.SHA1())


def rsaVerify(publicKey, signature: bytes, data: bytes) -> bool:
    try:
        publicKey.verify(signature, data, padding.PKCS1v15(), hashes.SHA1())
        return True
    except Exception:
        return False


#symmetric ciphers (CFB mode)
ALGORITHMS = {
    "AES-128": {"key_size": 16, "iv_size": 16, "cipher": algorithms.AES},
    "3DES":    {"key_size": 24, "iv_size": 8,  "cipher": TripleDES},
}
ALGORITHM_NAMES = list(ALGORITHMS.keys())


def generateSessionKey(algo: str) -> bytes:
    return os.urandom(ALGORITHMS[algo]["key_size"])


def symmetricEncrypt(algo: str, key: bytes, data: bytes):
    #EC(Ks, data) — returns (iv, ciphertext)
    spec = ALGORITHMS[algo]
    iv = os.urandom(spec["iv_size"])
    encryptor = Cipher(spec["cipher"](key), CFB(iv)).encryptor()
    return iv, encryptor.update(data) + encryptor.finalize()


def symmetricDecrypt(algo: str, key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    #DC(Ks, ciphertext)
    spec = ALGORITHMS[algo]
    decryptor = Cipher(spec["cipher"](key), CFB(iv)).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


#compression (Z)
def compressData(data: bytes) -> bytes:
    return zlib.compress(data, level=9)


def decompressData(data: bytes) -> bytes:
    return zlib.decompress(data)


#radix-64 (ASCII armor)
def radix64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def radix64decode(text: str) -> bytes:
    return base64.b64decode(text)
