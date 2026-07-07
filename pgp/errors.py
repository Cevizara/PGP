class PGPError(Exception):
    #base class for all errors
    pass

class KeyNotFound(PGPError):
    pass

class InvalidKeyFile(PGPError):
    pass

class WrongPassphrase(PGPError):
    pass


class MessageError(PGPError):
    pass

class NeedPassphrase(PGPError):
    #raised while receiving when the message is encrypted to a key we hold but no passphrase was supplied yet
    def __init__(self, key_id, user_id=None):
        self.key_id = key_id
        self.user_id = user_id
        super().__init__(f"Passphrase required for key {key_id}")
