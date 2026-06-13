"""ZIP (DEFLATE) compression service — the slide's Z / Z^-1.

PGP compresses after signing and before encryption. We use Python's built-in
zlib, which implements the DEFLATE algorithm used by ZIP.
"""

import zlib


def compress(data: bytes) -> bytes:
    return zlib.compress(data, level=9)


def decompress(data: bytes) -> bytes:
    return zlib.decompress(data)
