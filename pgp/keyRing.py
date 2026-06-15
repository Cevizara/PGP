class KeyRing:
    def __init__(self):
        self.entries: list = []

    def add(self, entry: dict) -> None:
        self.entries.append(entry)

    def remove(self, keyId: int) -> None:
        self.entries = [entry for entry in self.entries if entry["keyId"] != keyId]

    def getById(self, keyId: int):
        for entry in self.entries:
            if entry["keyId"] == keyId:
                return entry
        return None
    
    def all(self):
        return self.entries

