"""Row structures for the two key rings.

These mirror the tables from the slides:
  Private Key Ring: Timestamp, Key ID, Public Key, Encrypted Private Key, User ID
  Public  Key Ring: Timestamp, Key ID, Public Key, Owner Trust, User ID,
                    Key Legitimacy, Signatures, Signature Trust
The trust-related fields on PublicKeyEntry are present but unused for now;
they are reserved for the later key-management / trust requirement.
"""

from dataclasses import dataclass, field, asdict


@dataclass
class PrivateKeyEntry:
    key_id: str
    name: str
    email: str
    key_size: int
    public_key: str            # PEM, stored in the clear
    enc_private_key: dict      # passphrase-encrypted blob (see crypto_utils)
    timestamp: str
    fingerprint: str = ""

    @property
    def user_id(self) -> str:
        return f"{self.name} <{self.email}>"

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "PrivateKeyEntry":
        return cls(**d)


@dataclass
class PublicKeyEntry:
    key_id: str
    name: str
    email: str
    key_size: int
    public_key: str            # PEM
    timestamp: str
    fingerprint: str = ""
    # --- reserved for the later trust model ---
    owner_trust: str = "unknown"
    key_legitimacy: str = "unknown"
    signatures: list = field(default_factory=list)

    @property
    def user_id(self) -> str:
        return f"{self.name} <{self.email}>"

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "PublicKeyEntry":
        return cls(**d)
