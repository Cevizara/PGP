"""Entry point for the PGP application.

Run with the project virtual environment:
    .venv\\Scripts\\python.exe main.py
or just double-click run.bat on Windows.
"""

from gui.app import App


def main():
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
