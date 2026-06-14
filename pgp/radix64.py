import base64

# binaryData to ASCII string
def radix64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")

# ASCII string to binary data
def radix64decode(text: str) -> bytes:
    return base64.b64decode(text)
