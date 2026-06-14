import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
from cryptography.hazmat.decrepit.ciphers.modes import CFB

ALGORITHMS = {
    "AES-128": {"key_size": 16, "iv_size": 16, "cipher": algorithms.AES},
    "3DES":    {"key_size": 24, "iv_size": 8,  "cipher": TripleDES},
}

ALGORITHM_NAMES = list(ALGORITHMS.keys())

def generateSessionKey(algo: str) -> bytes:
    return os.urandom(ALGORITHMS[algo]["key_size"])


def symmetricEncrypt(algo: str, key: bytes, data: bytes):
    spec = ALGORITHMS[algo]
    iv = os.urandom(spec["iv_size"])
    encryptor = Cipher(spec["cipher"](key), CFB(iv)).encryptor()
    return iv, encryptor.update(data) + encryptor.finalize()


def symmetricDecrypt(algo: str, key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    spec = ALGORITHMS[algo]
    decryptor = Cipher(spec["cipher"](key), CFB(iv)).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()
