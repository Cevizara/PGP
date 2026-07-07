from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    PrivateFormat,
    NoEncryption,
    BestAvailableEncryption,
    load_pem_public_key,
    load_pem_private_key,
)



#generate a fresh RSA key pair. Returns (private_key, public_key)
#e is default value for public_exponent (65537)
def generateRsaPairOfKeys(size: int):
    if size != 1024 and size != 2048:
        raise ValueError("Key size must be 1024 or 2048 bits.")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=size)
    public_key = private_key.public_key()
    return private_key, public_key


#compute the key ID of a public key (Low 64 bits of the RSA modulus n)
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
    if pw:
        password_bytes = pw.encode("utf-8")
    else:
        password_bytes = None
    return load_pem_private_key(data, password=password_bytes)
