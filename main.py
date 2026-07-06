import os
import sys

from gui.app import App

DEFAULT_STORAGE_DIR = "./keystore"


def main():
    # Keystore folder: first CLI argument, else PGP_KEYSTORE, else the default.
    # This lets two instances run side by side as separate users (Alice / Bob).
    storage_dir = (sys.argv[1] if len(sys.argv) > 1
                   else os.environ.get("PGP_KEYSTORE", DEFAULT_STORAGE_DIR))
    app = App(storage_dir=storage_dir)
    app.mainloop()


if __name__ == "__main__":
    main()
