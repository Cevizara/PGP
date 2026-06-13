"""The two key rings and their persistence.

Each ring is a list of entries saved as a JSON file in the keystore directory.
JSON is chosen for transparency (you can open the file and inspect the
structure) — the private key field inside is still encrypted, so it is safe.
"""

import os
import json

from .models import PrivateKeyEntry, PublicKeyEntry


class _Ring:
    entry_cls = None
    filename = None

    def __init__(self, storage_dir: str):
        self.path = os.path.join(storage_dir, self.filename)
        self.entries: list = []
        self.load()

    def load(self) -> None:
        if os.path.exists(self.path):
            with open(self.path, "r", encoding="utf-8") as f:
                raw = json.load(f)
            self.entries = [self.entry_cls.from_dict(d) for d in raw]
        else:
            self.entries = []

    def save(self) -> None:
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump([e.to_dict() for e in self.entries], f, indent=2)

    def get(self, key_id: str):
        for e in self.entries:
            if e.key_id == key_id:
                return e
        return None

    def add(self, entry) -> None:
        # Replace any existing entry with the same Key ID (re-import / regenerate).
        if self.get(entry.key_id):
            self.entries = [e for e in self.entries if e.key_id != entry.key_id]
        self.entries.append(entry)
        self.save()

    def remove(self, key_id: str) -> None:
        self.entries = [e for e in self.entries if e.key_id != key_id]
        self.save()

    def __iter__(self):
        return iter(self.entries)

    def __len__(self):
        return len(self.entries)


class PrivateKeyRing(_Ring):
    entry_cls = PrivateKeyEntry
    filename = "private_keyring.json"


class PublicKeyRing(_Ring):
    entry_cls = PublicKeyEntry
    filename = "public_keyring.json"
