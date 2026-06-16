from pgp import cryptoPrimitives as cp


def test_symmetric_roundtrip():
    key = cp.generateSessionKey("AES128")
    data = b"hello world"
    encrypted = cp.symmetricEncrypt("AES128", key, data)
    decrypted = cp.symmetricDecrypt("AES128", key, encrypted)
    assert decrypted == data


def test_compress_roundtrip():
    data = b"aaaaaaaaaaaaaaaaaaaa"   # compresses well
    assert cp.decompress(cp.compress(data)) == data


def test_radix64_roundtrip():
    data = b"\x00\x01\x02\xff binary stuff"
    assert cp.radix64Decode(cp.radix64Encode(data)) == data


def test_algorithm_id_mapping():
    assert cp.idToAlgorithm(cp.algorithmToId("AES128")) == "AES128"
    assert cp.idToAlgorithm(cp.algorithmToId("TripleDES")) == "TripleDES"