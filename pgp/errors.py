"""Custom exceptions for the PGP core, so the GUI can react to specific cases."""


class PGPError(Exception):
    """Base class for all PGP-core errors."""


class WrongPassphrase(PGPError):
    """Raised when a passphrase fails to unlock a protected private key."""


class KeyNotFound(PGPError):
    """Raised when a key id is not present in the requested ring."""


class InvalidKeyFile(PGPError):
    """Raised when an imported .pem file cannot be parsed as the expected key."""


class MessageError(PGPError):
    """Raised when a PGP message file is malformed, corrupt, or cannot be processed."""


class NeedPassphrase(PGPError):
    """Raised while receiving when the message is encrypted to a key we hold but
    no passphrase was supplied yet. The GUI catches this, prompts the user, and
    retries. Carries the key id (and user id if known) so the prompt is specific."""

    def __init__(self, key_id, user_id=None):
        self.key_id = key_id
        self.user_id = user_id
        super().__init__(f"Passphrase required for key {key_id}")
