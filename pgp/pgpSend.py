from pgp.keyManager import KeyManager
import fileSerializer as fs
import messageComponents as mc
import cryptoPrimitives as cp


def pgpSend(keyManager: KeyManager, message: bytes, filename: str, destPath: str, options: dict) -> bool:
    """
    Send orchestrator. Flow: 
        sign -> compress -> encrypt -> radix64
    options = {
        "sign": bool,
        "encrypt": bool,
        "compress": bool,
        "radix64": bool,
        "signerKeyId": int, # required if sign
        "passphrase": str, # required if sign
        "recipientKeyId": int, # required if encrypt
        "algorithm": str, # required if encrypt ("AES128" | "TripleDES")
    }
    """
    sign = options.get("sign", False)
    encrypt = options.get("encrypt", False)
    compress = options.get("compress", False)
    radix64 = options.get("radix64", False)
    algorithmId = 0
    
    x = mc.buildMessageComponent(message, filename)

    if sign:
        PRa = keyManager.unlockPrivateKey(options["signerKeyId"], options["passphrase"])
        signatureBlock = mc.buildSignature(message, PRa, options["signerKeyId"])
        x = signatureBlock + x

    if compress:
        x = cp.compress(x)

    if encrypt:
        algorithm = options["algorithm"]
        
        Ks = cp.generateSessionKey(algorithm)
        x = cp.symmetricEncrypt(algorithm, Ks, x)
        
        PUb = keyManager.getPublicKey(options["recipientKeyId"])
        enc_Ks = cp.rsaEncrypt(PUb, Ks)
        
        sessionKeyBlock = mc.buildSessionKeyComponent(enc_Ks, options["recipientKeyId"], algorithm)
        X = sessionKeyBlock + x
        
        algorithmId = cp.algorithmToId(algorithm)

    if radix64:
        x = cp.radix64Encode(x)
        
    headerBytes = fs.encodeHeader(
        signed = sign,
        encrypted = encrypt,
        compressed = compress,
        radix64 = radix64,
        algorithmId = algorithmId,
    )
    fs.serializeToFile(x, headerBytes, destPath)
    
    return True