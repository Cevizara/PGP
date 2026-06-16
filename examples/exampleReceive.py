import os
from pgp import keyRing as kr
from pgp import keyGeneration as kg
from pgp import pgpSend as sender
from pgp import pgpReceive as receiver

OUTPUTDIR = "output/"
os.makedirs(OUTPUTDIR, exist_ok=True)

def main():
    keyManager = kr.KeyManager()

    senderKeyId = kg.generateKeyPair(
        keyManager, "Alice", "alice@example.com", 2048, "alicePassword123"
    )
    recipientKeyId = kg.generateKeyPair(
        keyManager, "Bob", "bob@example.com", 2048, "bobPassword456"
    )

    message = b"Hello Bob, this is a confidential and signed message!"
    options = {
        "sign": True,
        "encrypt": True,
        "compress": True,
        "radix64": True,
        "senderKeyId": senderKeyId,
        "passphrase": "alicePassword123",
        "recipientKeyId": recipientKeyId,
        "algorithm": "AES128",
    }
    sender.pgpSend(keyManager, message, "secret.txt", OUTPUTDIR + "outputMessage.pgp", options)
    print("Sent -> " + OUTPUTDIR + "outputMessage.pgp")

    result = receiver.pgpReceive(keyManager, OUTPUTDIR + "outputMessage.pgp", "bobPassword456")

    if result["error"]:
        print("ERROR:", result["error"])
        return

    print("Filename:  ", result["filename"])
    print("Message:   ", result["message"].decode())

    if result["verified"] is True:
        print("Signature: VALID")
        print("Author:    ", result["author"])
    elif result["verified"] is False:
        print("Signature: INVALID")
    else:
        print("Signature: (not signed)")

    # 6. Save the original message
    receiver.saveMessage(result["message"], OUTPUTDIR + "received_" + result["filename"])
    print("Saved -> " + OUTPUTDIR + "received_" + result["filename"])


if __name__ == "__main__":
    main()