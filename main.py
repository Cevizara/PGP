"""Entry point for the PGP application.

Run with the project virtual environment:
    .venv\\Scripts\\python.exe main.py                  (default ./keystore)
    .venv\\Scripts\\python.exe main.py keystore_alice    (separate keystore)

The keystore folder can be given as the first argument or via the PGP_KEYSTORE
environment variable. This lets you run two instances side by side (e.g. Alice
and Bob) with independent key rings for a realistic send/receive demo.
"""

import os
import sys

from gui.app import App


def main():
    storage_dir = None
    if len(sys.argv) > 1:
        storage_dir = sys.argv[1]
    elif os.environ.get("PGP_KEYSTORE"):
        storage_dir = os.environ["PGP_KEYSTORE"]

    app = App(storage_dir=storage_dir)
    app.mainloop()


if __name__ == "__main__":
    main()
