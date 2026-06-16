import struct

from . import cryptoPrimitives as cp

def packField(data: bytes) -> bytes:
   """Prefix a byte field with its 4-byte length."""
   return struct.pack('>I', len(data)) + data

def unpackField(data: bytes, offset: int):
   """Read a 4-byte-length-prefixed field. Returns (field, newOffset)."""
   length = struct.unpack('>I', data[offset:offset+4])[0]
   offset += 4
   field = data[offset:offset+length]
   offset += length
   return field, offset

def packInt(value: int, numBytes: int) -> bytes:
   """Pack an integer into fixed number of bytes (big-endian)."""
   return value.to_bytes(numBytes, byteorder='big')

def unpackInt(data: bytes, offset: int, numBytes: int):
   """Read a fixed size big-endian integer. Returns (value, newOffset)."""
   value = int.from_bytes(data[offset:offset+numBytes], byteorder='big')
   offset += numBytes
   return value, offset

def buildSignature(message: bytes, privateKey, senderKeyId: int) -> bytes:
   """
   Build signature component. Format:
   timestamp | senderKeyId | leadingTwoOctets | signature
   """
   timestamp = cp.currentTimestamp()
   
   digestInput = message + packInt(timestamp, 8)
   digest = cp.sha1Hash(digestInput)
   
   signature = cp.rsaSign(privateKey, digest)
   leadingTwoOctets = digest[:2]
   
   component = b""
   component += packInt(timestamp, 8)
   component += packInt(senderKeyId, 8)
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

def parseSessionKeyComponent(data: bytes):
   """
   Reverse of buildSessionKeyComponent:
   recipientKeyId | algorithmId | encryptedSessionKey
   Parse session key component. Returns (component dict, remaining bytes).
   """
   block, remaining = unpackField(data, 0)
   
   offset = 0
   recipientKeyId, offset = unpackInt(block, offset, 8)
   algorithmId, offset = unpackInt(block, offset, 1)
   encryptedSessionKey, offset = unpackField(block, offset)
   
   component = {
      "recipientKeyId": recipientKeyId,
      "algorithm": cp.idToAlgorithm(algorithmId),
      "encryptedSessionKey": encryptedSessionKey
   }
   
   return component, data[remaining:]

def parseSignatureComponent(data: bytes):
   """
   Reverse of buildSignature:
   timestamp | senderKeyId | leadingTwoOctets | signature
   Returns (component dict, remaining bytes).
   """
   block, remaining = unpackField(data, 0)
   offset = 0
   timestamp, offset = unpackInt(block, offset, 8)
   senderKeyId, offset = unpackInt(block, offset, 8)
   leadingTwoOctets, offset = unpackField(block, offset)
   signature, offset = unpackField(block, offset)
   
   component = {
      "timestamp": timestamp,
      "senderKeyId": senderKeyId,
      "leadingTwoOctets": leadingTwoOctets,
      "signature": signature
   }
   
   return component, data[remaining:]

def parseMessageComponent(data: bytes):
   """
   Reverse of buildMessageComponent:
      filename | creationTime | message
   Returns (component dict, remaining bytes).
   """
   block, remaining = unpackField(data, 0)
   
   offset = 0
   filename, offset = unpackField(block, offset)
   creationTime, offset = unpackInt(block, offset, 8)
   messageData, offset = unpackField(block, offset)
   
   component = {
      "filename": filename.decode(),
      "creationTime": creationTime,
      "message": messageData
   }
   
   return component, data[remaining:]