from dataclasses import dataclass, asdict


@dataclass(kw_only=True)
class KeyEntry:
    key_id: str
    name: str
    email: str
    key_size: int
    public_key: str            
    timestamp: str

    @property
    def user_id(self) -> str:
        return f"{self.name} <{self.email}>"

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "KeyEntry":
        return cls(**d)


@dataclass(kw_only=True)
class PrivateKeyEntry(KeyEntry):
    enc_private_key: dict      


@dataclass(kw_only=True)
class PublicKeyEntry(KeyEntry):
    pass
