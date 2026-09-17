# PGP Desktop Application

A Python desktop application that implements the PGP message-protection workflow without using a ready-made PGP library. It supports key management and secure message exchange through a `customtkinter` GUI.

The application creates protected `.pgp` message files that can be sent through any existing channel, including email, messaging apps, or cloud storage. The recipient opens the file with this application and decrypts it using their private key. After both users exchange and verify their public keys, they can communicate with message confidentiality, integrity, and sender authentication, even when the delivery channel itself is not trusted.

## Features

- Generate, import, export, and delete RSA key pairs
- Manage private and public key rings
- Sign and verify messages
- Encrypt and decrypt messages with AES-128 or 3DES session keys
- Optional compression and Radix-64 encoding
- Run separate application instances with independent keystores

## Quick start

Requires Windows and Python 3.10 or newer.

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe main.py
```

After setup, the application can also be launched with `run.bat`.

## Documentation

- [Detailed project guide](docs/DETAILED_GUIDE.md)
- [Send and receive message flow](MESSAGE_FLOW.md)

> This is an academic implementation of the course-specified PGP scheme. Some required algorithms, including SHA-1, are not suitable for modern production use.
