from . import cryptoPrimitives as cp
from . import messageComponents as mc
from . import fileSerializer as fs

def verifySender(publicKey, signatureComponent: dict, messageComponent: dict) -> bool:
   """Hash gotten message and verify against signature
   Mirrors how the sender build it (message + timestamp)
   """
   message = messageComponent["message"]
   digestInput = message + mc.packInt(signatureComponent["timestamp"], 8)
   computedDigest = cp.sha1Hash(digestInput)
   
   if(computedDigest[:2] != signatureComponent["leadingTwoOctets"]):
      return False

   return cp.rsaVerify(publicKey, signatureComponent["signature"], computedDigest)
   
   
def pgpReceive(keyManager, filePath: str, passphrase: str) -> dict:
   """
   Receive orchestrator. Flow:
         radix64 -> decrypt -> decompress -> verify
   Returns a result dict:
      {
         "message": bytes,
         "filename": str,
         "verified": True | False | None # None if not signed
         "author": str | None # None if not signed
         "error": str | None
      }
   """
   result = {
      "message": None,
      "filename": None,
      "verified": None or True or False,
      "author": None,
      "error": None
   }
   
   try:
      rawData = fs.readFile(filePath)
      flags, x = fs.decodeHeader(rawData)
      
      if flags["radix64"]:
         x = cp.radix64Decode(x)
      
      if flags["encrypted"]:
         sessionKeyComponent, rest = mc.parseSessionKeyComponent(x)
         
         privateKey = keyManager.unlockPrivateKey(sessionKeyComponent["recipientKeyId"], passphrase)
         Ks = cp.rsaDecrypt(privateKey, sessionKeyComponent["encryptedSessionKey"])
         x = cp.symmetricDecrypt(sessionKeyComponent["algorithm"], Ks, rest)
         
      if flags["compressed"]:
         x = cp.decompress(x)
         
      if flags["signed"]:
         signatureComponent, rest = mc.parseSignatureComponent(x)
         messageComponent, _ = mc.parseMessageComponent(rest)
         
         publicKey = keyManager.getPublicKey(signatureComponent["senderKeyId"])
         result["verified"] = verifySender(publicKey, signatureComponent, messageComponent)
         result["author"] = keyManager.getUserId(signatureComponent["senderKeyId"])
         result["message"] = messageComponent["message"]
         result["filename"] = messageComponent["filename"]
      else:
         messageComponent, _ = mc.parseMessageComponent(x)
         result["message"] = messageComponent["message"]
         result["filename"] = messageComponent["filename"]
         result["verified"] = None
         
      return result
   except ValueError as e:
      result["error"] = str(e)
      return result
   except KeyError as e:
      result["error"] = f"Key not found: {str(e)}."
      return result
   except Exception as e:
      result["error"] = f"Error processing message: {str(e)}."
      return result
   
   
def saveMessage(messageData: bytes, destPath: str):
   """Save message to file."""
   with open(destPath, "wb") as f:
      f.write(messageData)