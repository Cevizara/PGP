"""PGP core package — pure crypto/logic, independent of any GUI.

The GUI talks to this package only through `pgp.keymanager.KeyManager`.
Later project requirements (message send/receive, compression, radix-64) are
added here as new modules without changing the existing key-management code.
"""
