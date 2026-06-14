"""RSA key operations: generation, PEM import/export, Key ID.

We use the `cryptography` library for the RSA primitive (allowed by the task
rules). Everything here is stateless — it only deals with key objects and PEM
bytes; storage and passphrase protection live in other modules.
"""

import cryptography

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



# Generate a fresh RSA key pair. Returns (private_key, public_key)
# e is default value for public_exponent
def generateRsaPairOfKeys(size: int):
    if size != 1024 and size != 2048:
        raise ValueError("Key size must be 1024 or 2048 bits.")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=size)
    public_key = private_key.public_key()
    return private_key, public_key


# Compute the key ID of a public key (Low 64 bits of the RSA modulus n)
def computeKeyId(publicKey) -> str:
    n = publicKey.public_numbers().n
    return f"{n % (1 << 64):016X}"



#PEM serialization
def publicKeyToPem(publicKey) -> str:
    return publicKey.public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
    ).decode("ascii")


def privateKeyToPem(privateKey, pw: str | None = None) -> bytes:
    encryption = (
        BestAvailableEncryption(pw.encode("utf-8")) if pw else NoEncryption()
    )
    return privateKey.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, encryption)


def loadPublicKeyFromPem(data: bytes):
    return load_pem_public_key(data)


def loadPrivateKeyFromPem(data: bytes, pw: str | None = None):
    return load_pem_private_key(data, password=pw.encode("utf-8") if pw else None)


#RSA operations
#Session key/message encryption/decryption
def rsaEncrypt(publicKey, data: bytes) -> bytes:
    return publicKey.encrypt(
        data,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None),
    )


def rsaDecrypt(private_key, data: bytes) -> bytes:
    return private_key.decrypt(
        data,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None),
    )


#Signature generation
def rsaSign(privateKey, data: bytes) -> bytes:
    return privateKey.sign(data, padding.PKCS1v15(), hashes.SHA1())

#Signature verification
def rsaVerify(publicKey, signature: bytes, data: bytes) -> bool:
    try:
        publicKey.verify(signature, data, padding.PKCS1v15(), hashes.SHA1())
        return True
    except Exception:
        return False
