import struct

from . import cryptoPrimitives as cp

def packField(data: bytes) -> bytes:
   """Prefix a byte field with its 4-byte length."""
   return struct.pack('>I', len(data)) + data

def packInt(value: int, numBytes: int) -> bytes:
   """Pack an integer into fixed number of bytes (big-endian)."""
   return value.to_bytes(numBytes, byteorder='big')

def buildSignature(message: bytes, privateKey, signerKeyId: int) -> bytes:
   """
   Build signature component. Format:
   timestamp | senderKeyId | leadingTwoOctets | signature
   """
   timestamp = cp.currentTimestamp()
   
   digestInput = message + packInt(timestamp, 8)
   digest = cp.sha1Hash(digestInput)
   
   signature = cp.rsaSign(privateKey, digest)
   leadingTwoOctets = signature[:2]
   
   component = b""
   component += packInt(timestamp, 8)
   component += packInt(signerKeyId, 8)
   component += packField(leadingTwoOctets)
   component += packField(signature)
   
   return packField(component)

def buildMessageComponent(message: bytes, filename: str) -> bytes:
   """
   Build message component. Format:
   filename | creationTime | message
   """
   creationTime = cp.currentTimestamp()
   component = b""
   component += packField(filename.encode())
   component += packInt(creationTime, 8)
   component += packField(message)
   
   return packField(component)

def buildSessionKeyComponent(encryptedSessionKey: bytes, recipientKeyId: int, algorithm: str) -> bytes:
   """
   Build session key component. Format:
   recipientKeyId | algorithmId | encryptedSessionKey
   """
   algorithmId = cp.algorithmToId(algorithm)
   
   component = b""
   component += packInt(recipientKeyId, 8)
   component += packInt(algorithmId, 1)
   component += packField(encryptedSessionKey)
   
   return packField(component)