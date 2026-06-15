import base64
import json

from cryptography.hazmat.primitives import serialization

from . import cryptoPrimitives as cp
from .keyRing import KeyRing

class KeyManager:
    def __init__(self, privateRingPath="private_ring.json", publicRingPath="public_ring.json"):
        self.privateRing = KeyRing()
        self.publicRing = KeyRing()
        self.privateRingPath = privateRingPath
        self.publicRingPath = publicRingPath
        self.loadRings()
        
    @staticmethod
    def computeKeyId(publicKey) -> int:
        """keyId = PU mod 2^64 (least significant 8 bytes of the public key)."""
        n = publicKey.public_numbers().n
        return n % (2**64)
        
    
    def unlockPrivateKey(self, keyId, passphrase):
        """"Decrypt stored private key using password-derived key."""
        entry = self.privateRing.getById(keyId)
        if entry is None:
            raise KeyError(f"Private key for {keyId} not found")
        
        pwdHash = cp.sha1Hash(passphrase.encode())
        decKey = pwdHash[:16] 
        
        try:
            encryptedPr = base64.b64decode(entry["encryptedPrivateKey"])
            prBytes = symmetricDecryptForKeys(decKey, encryptedPr)
            privateKey = serialization.load_pem_private_key(prBytes, password=None)
        except Exception:
            raise ValueError("Wrong password")
        
        return privateKey
    
    
    def getPublicKey(self, keyId: int):
        entry = self.publicRing.getById(keyId)
        if entry is None:
            entry = self.privateRing.getById(keyId)
        if entry is None:
            raise KeyError(f"Public key for {keyId} not found")
        return deserializePublicKey(entry["publicKey"])
    

    def loadRings(self):
        """Load key rings from disk, or initialize empty if not found."""
        try:
            with open(self.publicRingPath, "r") as f:
                self.publicRing.entries = json.load(f)
        except FileNotFoundError:
            self.publicRing.entries = []
            
        try:
            with open(self.privateRingPath, "r") as f:
                self.privateRing.entries = json.load(f)
        except FileNotFoundError:
            self.privateRing.entries = []
            
    def saveRings(self):
        with open(self.publicRingPath, "w") as f:
            json.dump(self.publicRing.entries, f, indent=2)
        with open(self.privateRingPath, "w") as f:
            json.dump(self.privateRing.entries, f, indent=2)
            
            
            
def symmetricDecryptForKeys(key: bytes, ciphertext: bytes) -> bytes:
    """AES128-CFB decryption for private-key storage (IV prepended)."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    iv = ciphertext[:16]
    cipherText = ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(cipherText) + decryptor.finalize()

def deserializePublicKey(pemString: str):
    """PEM string -> public key object."""
    return serialization.load_pem_public_key(pemString.encode())

def serializePublicKey(publicKey) -> str:
    """Public key object -> PEM string (for ring storage)."""
    pemBytes = publicKey.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pemBytes.decode()