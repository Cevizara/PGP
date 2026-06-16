import base64

from . import cryptoPrimitives as cp
from . import keyRing as kr

import cryptography.hazmat.primitives.asymmetric.rsa as rsa
import cryptography.hazmat.primitives.serialization as serialization
from cryptography.hazmat.decrepit.ciphers.modes import CFB

def generateKeyPair(keyManager: kr.KeyManager, name: str, email: str, keySize: int, passphrase: str) -> int:
   """Generate RSA pair, encrypt private key, store in ring."""
   if keySize not in (1024, 2048):
      raise ValueError("Key size must be 1024 or 2048")
   
   privateKey = rsa.generate_private_key(public_exponent=65537, key_size=keySize)
   publicKey = privateKey.public_key()
   keyId = keyManager.computeKeyId(publicKey)
   
   pwdHash = cp.sha1Hash(passphrase.encode())
   encKey = pwdHash[:16]
   
   prBytes = privateKey.private_bytes(
      encoding=serialization.Encoding.PEM,
      format=serialization.PrivateFormat.PKCS8,
      encryption_algorithm=serialization.NoEncryption()
   )
   encryptedPr = symmetricEncryptForKeys(encKey, prBytes)
   
   userId = f"{name} <{email}>"
   entry = {
      "timestamp": cp.currentTimestamp(),
      "keyId": keyId,
      "publicKey": kr.serializePublicKey(publicKey),
      "encryptedPrivateKey": base64.b64encode(encryptedPr).decode(),
      "userId": userId,
   }
   keyManager.privateRing.add(entry)
   keyManager.saveRings()
   return keyId

def symmetricEncryptForKeys(key: bytes, data: bytes) -> bytes:
   """AES128-CFB encrypt for private-key storage (IV prepended)."""
   import os
   from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
   iv = os.urandom(16)
   cipher = Cipher(algorithms.AES(key), CFB(iv))
   encryptor = cipher.encryptor()
   cipherText = encryptor.update(data) + encryptor.finalize()
   return iv + cipherText