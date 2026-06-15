import zlib

#Compress the message and signature
def compressData(messageAndSignature: bytes) -> bytes:
    return zlib.compress(messageAndSignature, level=9)

#Decompress the compressed data
def decompressData(compressedData: bytes) -> bytes:
    return zlib.decompress(compressedData)
