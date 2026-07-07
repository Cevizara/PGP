"""KeyManager — the single facade the GUI uses.

It coordinates the two rings, RSA operations and passphrase protection so the
GUI never has to touch the crypto directly. New project features (sending and
receiving messages) will add methods here or sit alongside it, but the
key-management surface stays stable.
"""

import os
from datetime import datetime, timezone

from . import keys as K
from .crypto_utils import encrypt_private_key, decrypt_private_key
from .keyrings import PrivateKeyRing, PublicKeyRing
from .models import PrivateKeyEntry, PublicKeyEntry
from .errors import WrongPassphrase, KeyNotFound, InvalidKeyFile


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class KeyManager:
    def __init__(self, storage_dir: str):
        self.storage_dir = storage_dir
        self.private_ring = PrivateKeyRing(storage_dir)
        self.public_ring = PublicKeyRing(storage_dir)

    # ------------------------------------------------------------------ #
    # Requirement 1: generate / delete RSA key pairs                     #
    # ------------------------------------------------------------------ #
    def generateKeyPair(self, name, email, key_size, passphrase) -> PrivateKeyEntry:
        private_key, public_key = K.generateRsaPairOfKeys(key_size)
        entry = PrivateKeyEntry(
            key_id=K.computeKeyId(public_key),
            name=name,
            email=email,
            key_size=key_size,
            public_key=K.publicKeyToPem(public_key),
            enc_private_key=encrypt_private_key(K.privateKeyToPem(private_key), passphrase),
            timestamp=now(),
        )
        self.private_ring.add(entry)
        return entry

    def deletePrivateKey(self, key_id) -> None:
        if not self.private_ring.get(key_id):
            raise KeyNotFound(key_id)
        self.private_ring.remove(key_id)

    def deletePublicKey(self, key_id) -> None:
        if not self.public_ring.get(key_id):
            raise KeyNotFound(key_id)
        self.public_ring.remove(key_id)

    # ------------------------------------------------------------------ #
    # Accessing a private key always requires the passphrase             #
    # ------------------------------------------------------------------ #
    def getPrivateKey(self, key_id, passphrase):
        entry = self.private_ring.get(key_id)
        if not entry:
            raise KeyNotFound(key_id)
        pem = decrypt_private_key(entry.enc_private_key, passphrase)  # may raise WrongPassphrase
        return K.loadPrivateKeyFromPem(pem)

    def verifyPassphrase(self, key_id, passphrase) -> bool:
        try:
            self.get_private_key(key_id, passphrase)
            return True
        except WrongPassphrase:
            return False

    # ------------------------------------------------------------------ #
    # Requirement 2: import / export (.pem)                              #
    # ------------------------------------------------------------------ #
    def importPublicKey(self, path, name, email) -> PublicKeyEntry:
        with open(path, "rb") as f:
            data = f.read()
        try:
            public_key = K.loadPublicKeyFromPem(data)
        except Exception as exc:
            raise InvalidKeyFile(f"Not a valid public-key PEM file.\n({exc})")
        entry = PublicKeyEntry(
            key_id=K.computeKeyId(public_key),
            name=name,
            email=email,
            key_size=public_key.key_size,
            public_key=K.publicKeyToPem(public_key),
            timestamp=now(),
        )
        self.public_ring.add(entry)
        return entry

    def importKeyPair(self, path, pem_password, name, email, keyring_passphrase) -> PrivateKeyEntry:
        with open(path, "rb") as f:
            data = f.read()
        try:
            private_key = K.loadPrivateKeyFromPem(data, pem_password or None)
        except (TypeError, ValueError) as exc:
            raise InvalidKeyFile(
                "Could not load the private key. The file may not be a private-key "
                f"PEM, or the file password is wrong.\n({exc})"
            )
        public_key = private_key.public_key()
        entry = PrivateKeyEntry(
            key_id=K.computeKeyId(public_key),
            name=name,
            email=email,
            key_size=public_key.key_size,
            public_key=K.publicKeyToPem(public_key),
            enc_private_key=encrypt_private_key(K.privateKeyToPem(private_key), keyring_passphrase),
            timestamp=now(),
        )
        self.private_ring.add(entry)
        return entry

    def exportPublicKey(self, key_id, path) -> None:
        """Export the public key from either ring — checks private ring first."""
        entry = self.private_ring.get(key_id) or self.public_ring.get(key_id)
        if not entry:
            raise KeyNotFound(key_id)
        with open(path, "w", encoding="utf-8") as f:
            f.write(entry.public_key)

    def exportKeyPair(self, key_id, keyring_passphrase, path, export_password=None) -> None:
        # Unlocking the private key here enforces "every access needs a passphrase".
        private_key = self.getPrivateKey(key_id, keyring_passphrase)  # may raise WrongPassphrase
        pem = K.privateKeyToPem(private_key, export_password or None)
        with open(path, "wb") as f:
            f.write(pem)
