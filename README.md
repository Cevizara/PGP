# PGP — Zaštita podataka 2025/26

A desktop application that implements the **PGP scheme** for protecting e-mail
messages: RSA key management, and sending/receiving messages with
**confidentiality (encryption)**, **authenticity (digital signature)**,
**compression**, and **radix-64** ASCII armoring — in any combination.

Built with Python + `cryptography` (for the crypto primitives) and
`customtkinter` (for the GUI). It does **not** use any ready-made PGP module
(`pgpy`, `python-gnupg`, …) — the PGP scheme itself is assembled by hand, which
is the point of the assignment.

> This README is written so a new teammate can understand the **whole** project
> from zero. Read it top to bottom once; after that the section headings are a
> quick reference.

---

## 1. What it does (and which requirements it covers)

The assignment lists five required functionalities. All are implemented:

| # | Requirement | Where in the UI |
|---|-------------|-----------------|
| 1 | Generate / delete RSA key pairs | **My Keys** tab → *Generate* / *Delete* |
| 2 | Import / export public key or whole pair (`.pem`) | **My Keys** / **Contacts** → *Import* / *Export* |
| 3 | Display the public & private key rings with all info | **My Keys** / **Contacts** tables + *Details* |
| 4 | Send a message (encryption + signing + …) | **Send** tab |
| 5 | Receive a message (decryption + verification) | **Receive** tab |

Each protection service on **Send** is an independent checkbox: *Sign*,
*Encrypt*, *Compress*, *Radix-64*. The receiver auto-detects which were applied.

---

## 2. Quick start

### Requirements
- Windows (developed on Win 11), Python 3.13 (3.10+ should work).
- Packages in `requirements.txt`: `cryptography`, `customtkinter`, `pillow`.

### Setup (already done on this machine — repeat on a new one)
```powershell
# from the project folder
py -3.13 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```
> On this machine the bare `python` / `py` names are shadowed by the Windows
> Store stub. The real interpreter lives at
> `C:\Users\<user>\AppData\Local\Programs\Python\Python313\python.exe`.
> The `.venv` already points at the right one.

### Run
```powershell
.\.venv\Scripts\python.exe main.py
```
or just double-click **`run.bat`**.

Key rings are created on first use under **`keystore/`** (see §7).

---

## 3. Architecture

The golden rule: **the GUI never does crypto.** All cryptography and PGP logic
live in the `pgp/` package; the GUI (`gui/`) only calls into it. This keeps the
logic testable without a screen and lets two people work without colliding.

```
Projekat/
├── main.py                 # entry point: builds the App and runs the loop
├── run.bat                 # launches main.py with the venv Python
├── requirements.txt
│
├── pgp/                    # ── PURE LOGIC, no GUI imports ──
│   ├── keys.py             # RSA: generate, PEM I/O, Key ID, fingerprint,
│   │                       #      rsa_encrypt/decrypt (EP/DP) & sign/verify
│   ├── crypto_utils.py     # protect the private key at rest (passphrase → AES)
│   ├── ciphers.py          # symmetric session ciphers: AES-128 & 3DES (CFB)
│   ├── compression.py      # ZIP (zlib) compress/decompress
│   ├── radix64.py          # ASCII armor (Base64 + CRC-24), like OpenPGP
│   ├── models.py           # PrivateKeyEntry / PublicKeyEntry (ring rows)
│   ├── keyrings.py         # the two rings + JSON persistence
│   ├── keymanager.py       # FACADE used by the GUI for all key operations
│   ├── message.py          # the message engine: create / inspect / process
│   └── errors.py           # typed exceptions the GUI reacts to
│
├── gui/                    # ── customtkinter UI ──
│   ├── app.py              # main window, tabs, key-management wiring
│   ├── send_view.py        # Send tab
│   ├── receive_view.py     # Receive tab
│   ├── dialogs.py          # all modal dialogs (generate, passphrase, details…)
│   └── widgets.py          # the dark-themed table helper
│
└── keystore/               # created at runtime: private_keyring.json + public_keyring.json
```

**Dependency direction:** `gui/*` → `pgp.keymanager` / `pgp.message` → the rest
of `pgp/*`. Nothing in `pgp/` imports from `gui/`.

---

## 4. How the PGP scheme works here

### Two kinds of keys (the core idea)
- **RSA key pair** (slow, asymmetric): used to sign, and to protect the session key.
- **Session key** (fast, symmetric — AES-128 or 3DES): used to encrypt the actual
  message. A fresh random session key is made for **every** message (one-time key).

This is the "digital envelope": encrypt the big message with a fast one-time key,
then encrypt just that little key with the recipient's RSA public key.

### Send pipeline (order matters!) — `pgp/message.py::create_message`
```
M (message)
  → SIGN      : digest = SHA-1(data ‖ sig_timestamp); signature = RSA_sign(PR_sender, …)
  → COMPRESS  : ZIP(signature ‖ message)
  → ENCRYPT   : Ks = random; body = AES/3DES_CFB(Ks, …);  encKs = RSA_encrypt(PU_recipient, Ks)
  → RADIX-64  : ASCII-armor the whole container
```
The textbook order is **sign → compress → encrypt → radix-64**, and we follow it
exactly. (Sign before compress so we can store/verify the original; encrypt after
compress so there's less redundancy to attack.)

### Receive pipeline (the mirror) — `pgp/message.py::process_message`
```
file
  → un-RADIX-64 : if armored, de-armor (and check CRC-24)
  → DECRYPT     : find our private key by recipient Key ID → ask passphrase →
                  Ks = RSA_decrypt(PR_us, encKs) → AES/3DES_CFB decrypt body
  → DECOMPRESS  : un-ZIP
  → VERIFY      : find sender's public key by signer Key ID → check SHA-1 + RSA
```

### When is the passphrase asked?
Only when a **private key** is touched:
- **Signing** (Send) — to unlock the signer's private key.
- **Decrypting** (Receive) — to unlock the recipient's private key.

Encrypting *to* someone uses their **public** key (no passphrase), and verifying
a signature uses the sender's **public** key (no passphrase).

---

## 5. Message file format

Our own format, but faithful to the slide *"struktura poruke"* (session-key /
signature / message components). The file is a JSON **outer container** (UTF-8);
binary fields are Base64 so they fit in JSON. If radix-64 is on, the whole
container is additionally ASCII-armored.

**Outer container**
```jsonc
{
  "version": "PGP-ZP/1.0",
  "signed": true, "compressed": true, "encrypted": true, "radix64": true,
  "sym_algo": "AES-128" | "3DES" | null,
  "iv": "<base64>" | null,                 // symmetric IV (only if encrypted)
  "session_key": {                         // present iff encrypted
     "recipient_key_id": "....",           //   → which private key decrypts it
     "enc_session_key": "<base64 EP(PUb, Ks)>"
  },
  "payload": "<base64>"                    // inner block after the chosen transforms
}
```

**Inner block** (inside `payload`, *before* compression/encryption):
```jsonc
{
  "message":  { "filename": "...", "timestamp": "...", "data": "<base64>" },
  "signature":{                            // present iff signed
     "timestamp": "...",
     "signer_key_id": "....",              //   → which public key verifies it
     "leading_two_octets": "ABCD",         //   first 2 bytes of SHA-1 digest (quick check)
     "signature": "<base64 E(PRa, H(data‖ts))>"
  }
}
```

The receiver reads `signed/compressed/encrypted/radix64` (+ the structure) to
decide what to reverse. The two **Key IDs** are what let it pick the right keys
from the rings.

---

## 6. Key ring storage

Two JSON files in `keystore/` (created on first use):

**`private_keyring.json`** — your own pairs. Fields per the slide *Private Key Ring*:
```jsonc
{
  "key_id": "5E586EC780847F77",   // low 64 bits of the RSA modulus (PU mod 2^64)
  "name": "...", "email": "...",  // the User ID
  "key_size": 2048,
  "public_key": "-----BEGIN PUBLIC KEY-----\n...",   // PEM, in the clear
  "enc_private_key": {            // the private key, ENCRYPTED:
     "algo": "AES-128-CBC", "s2k": "salted-sha1",
     "salt": "<b64>", "iv": "<b64>", "ciphertext": "<b64>"
  },
  "timestamp": "...", "fingerprint": "<SHA-1 of public key>"
}
```
The private key is **never** stored in the clear — it is AES-encrypted with a key
derived from the passphrase (see §8).

**`public_keyring.json`** — contacts' public keys. Same shape minus the private
key, plus `owner_trust` / `key_legitimacy` / `signatures` fields that are
**reserved for a future trust model** (not part of the 5 required features).

> Note: the folder is inside OneDrive on this machine, so the rings sync to the
> cloud. The private key is encrypted, so this is acceptable — but security then
> rests entirely on passphrase strength. Moving `keystore/` out of OneDrive (or
> to `%APPDATA%`) is a reasonable hardening step.

---

## 7. Cryptographic choices & rationale (know these for the defense)

| Decision | What we do | Why |
|----------|-----------|-----|
| **Key ID** | low 64 bits of the RSA modulus `n` (`PU mod 2^64`) | Matches the course slides / Stallings. (RFC 4880 V4 uses the low 64 bits of the SHA-1 *fingerprint* instead — we don't.) |
| **Fingerprint** | SHA-1 over the DER public key | For out-of-band human verification (read it over the phone). Display only. |
| **Private key at rest** | salted SHA-1 → 128-bit key → AES-128-CBC | Slide says "SHA-1 of passphrase → 128-bit key → symmetric encrypt"; salt follows RFC 4880 S2K advice; AES-128 is one of our two algorithms. |
| **Symmetric algorithms** | **AES-128** and **3DES** (two of the four allowed) | Both are clean in `cryptography`. Cast5/IDEA would add library pain for no extra credit. |
| **Cipher mode** | **CFB** | The slide specifies 64-bit CFB for PGP confidentiality. CFB is stream-style → no padding. |
| **Session-key encryption** | RSA-OAEP (SHA-256) | Modern, secure padding for `EP(PUb, Ks)`. Session keys (16/24 B) fit even in RSA-1024. |
| **Signature** | RSA PKCS#1 v1.5 over SHA-1 | This is exactly "encrypt the digest with the private key" (`E(PRa, H(M))`). SHA-1 is required by the assignment. |
| **Compression** | `zlib` (DEFLATE) | The DEFLATE algorithm used by ZIP, which the slide names. |
| **Radix-64** | Base64 + CRC-24 + BEGIN/END armor | Mirrors OpenPGP ASCII armor; the CRC is the slide's "radix-64 adds a CRC". |

**Academic caveats to mention if asked:** 1024-bit RSA and SHA-1 are weak by
modern standards but are required by the course; a single-pass salted SHA-1 S2K
is weaker than an iterated KDF (PBKDF2/Argon2). These are deliberate, to follow
the textbook PGP.

---

## 8. Where each requirement lives in the code

- **Generate / delete** → `pgp/keymanager.py::generate_keypair` / `delete_private_key`;
  UI in `gui/app.py::on_generate` / `on_delete_private`.
- **Import / export** → `pgp/keymanager.py::import_public_key` / `import_keypair` /
  `export_public_key` / `export_keypair`; UI handlers `on_import_*` / `on_export_*`.
- **Display rings** → tables in `gui/app.py` (`refresh_private`/`refresh_public`),
  full details in `gui/dialogs.py::KeyDetailsDialog`.
- **Send** → `pgp/message.py::create_message`; UI in `gui/send_view.py`.
- **Receive** → `pgp/message.py::inspect_message` + `process_message`;
  UI in `gui/receive_view.py`.

---

## 9. Suggested two-person split

The rules forbid "one does logic, the other does GUI". Split by **feature
vertical** instead — each person owns the logic *and* its UI:

- **Person A — Keys & Send:** `pgp/keys.py`, `crypto_utils.py`, `keyrings.py`,
  `keymanager.py`, the build half of `message.py`, `gui/app.py` (key tabs),
  `gui/send_view.py`.
- **Person B — Ciphers & Receive:** `pgp/ciphers.py`, `compression.py`,
  `radix64.py`, the receive half of `message.py`, `gui/receive_view.py`,
  `gui/dialogs.py`.

Both share `models.py` / `errors.py` and review each other's `message.py` half
(it's the seam where send and receive meet).

---

## 10. How to test / verify by hand

Two-person round trip on one machine:
1. **My Keys → Generate** two pairs, e.g. "Alice" and "Bob" (give each a passphrase).
2. **My Keys → Export public** for Alice; **Contacts → Import public** it back as
   a contact (in a real demo you'd do this on the other person's machine).
3. **Send:** type a message, tick *Sign* (Alice's key) + *Encrypt* (for Bob) +
   *Compress* + *Radix-64*, click *Create message file* → save `*.pgp`.
4. **Receive:** *Open message file* → that `.pgp`. It detects the services, asks
   Bob's passphrase, decrypts, and shows **"Signature VALID — signed by Alice"**.
5. **Save message** to confirm the original came back byte-for-byte.

The crypto engine has been exercised across **all 16 combinations** of the four
services (plus wrong-passphrase and corruption cases) during development.

---

## 11. Roadmap / not yet done

- **Trust model** (owner trust, key legitimacy, signatures on keys) — the data
  structures already have the fields; the logic/UI are future work. Not among
  the 5 required features.
- **Segmentation** of very large messages — described in the slides, optional here.
