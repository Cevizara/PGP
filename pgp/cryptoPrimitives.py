import hashlib

def sha1Hash(data: bytes) -> bytes:
    """SHA-1 -> 20 byte (160-bit) digest."""
    return hashlib.sha1(data).digest()

