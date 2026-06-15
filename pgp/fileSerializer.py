MAGIC = b'PGP1'
FLAG_SIGNED = 0b0001
FLAG_ENCRYPTED = 0b0010
FLAG_COMPRESSED = 0b0100
FLAG_RADIX64 = 0b1000

def encodeHeader(signed: bool, encrypted: bool, compressed: bool, radix64: bool, algorithmId: int) -> bytes:
   """Header layout:
   [4 bytes MAGIC][1 byte flags][1 byte algorithmId]
   Receiver reads flags to know which packets are present.
   """
   flagsByte = 0
   if signed:
      flagsByte |= FLAG_SIGNED
   if encrypted:
      flagsByte |= FLAG_ENCRYPTED
   if compressed:
      flagsByte |= FLAG_COMPRESSED
   if radix64:
      flagsByte |= FLAG_RADIX64
   
   return MAGIC + bytes([flagsByte]) + bytes([algorithmId])

def serializeToFile(payload: bytes, headerBytes: bytes, filePath: str):
   """Write header + payload to file."""
   with open(filePath, 'wb') as f:
      f.write(headerBytes + payload)