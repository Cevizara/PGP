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
      
def readFile(filePath: str) -> bytes:
   """Read the whole file."""
   with open(filePath, 'rb') as f:
      return f.read()
   
def decodeHeader(headerBytes: bytes):
   """
   Read header and split it from the payload
   Returns (flagsDict, payload).
   This is how receiver recognizes which packets are present.
   """
   magic = headerBytes[:4]
   if magic != MAGIC:
      raise ValueError("Not a valid PGP file")
   
   flagsByte = headerBytes[4]
   algorithmId = headerBytes[5]
   payload = headerBytes[6:]
   
   flags = {
      'signed': bool(flagsByte & FLAG_SIGNED),
      'encrypted': bool(flagsByte & FLAG_ENCRYPTED),
      'compressed': bool(flagsByte & FLAG_COMPRESSED),
      'radix64': bool(flagsByte & FLAG_RADIX64),
      "algorithmId": algorithmId
   }
   
   
   return flags, payload