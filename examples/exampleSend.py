import os
from pgp import keyRing as kr
from pgp import keyGeneration as kg
from pgp import pgpSend as sender

OUTPUT_DIR = "output/"
os.makedirs(OUTPUT_DIR, exist_ok=True)

def main():
   keyManager = kr.KeyManager()

   senderKeyId = kg.generateKeyPair(
      keyManager,
      name="Alice",
      email="alice@example.com",
      keySize=2048,
      passphrase="alicePassword123"
   )
   print(f"Sender key ID: {senderKeyId}")

   recipientKeyId = kg.generateKeyPair(
      keyManager,
      name="Bob",
      email="bob@example.com",
      keySize=2048,
      passphrase="bobPassword456"
   )
   print(f"Recipient key ID: {recipientKeyId}")

   message = b"Hello Bob, this is a confidential and signed message!"
   filename = "secret.txt"

   options = {
      "sign": True,
      "encrypt": True,
      "compress": True,
      "radix64": True,
      "signerKeyId": senderKeyId,
      "passphrase": "alicePassword123",
      "recipientKeyId": recipientKeyId,
      "algorithm": "AES128"
   }

   sender.pgpSend(
      keyManager,
      message=message,
      filename=filename,
      destPath=OUTPUT_DIR + "outputMessage.pgp",
      options=options
   )
   print("Message sent -> " + OUTPUT_DIR + "outputMessage.pgp")


if __name__ == "__main__":
   main()