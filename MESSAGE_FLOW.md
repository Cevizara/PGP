# PGP message flow — Send & Receive

> Diagrams use **Mermaid**. They render on GitHub automatically, and in VS Code with the
> *“Markdown Preview Mermaid Support”* extension (then `Ctrl+Shift+V` to preview).

---

## 1. SEND — timeline (who calls what, in order)

This is the sequence when **all four options are ON** (sign + encrypt + compress + radix-64).

```mermaid
sequenceDiagram
    actor User
    participant GUI as gui/send_view.py
    participant ORCH as pgp/message.py<br/>pgpSend()
    participant KM as pgp/keymanager.py
    participant Keys as pgp/keys.py
    participant Ciph as pgp/ciphers.py
    participant Zip as pgp/compression.py
    participant R64 as pgp/radix64.py

    User->>GUI: click "Create message file"
    GUI->>GUI: _message_source() → (message, filename)
    GUI-->>User: PassphraseDialog (only if signing)
    GUI->>ORCH: pgpSend(message, filename, options, keyIds, passphrase)

    Note over ORCH: STEP 1 — message component
    ORCH->>ORCH: buildMessageComponent()

    Note over ORCH,Keys: STEP 2 — SIGN
    ORCH->>KM: loadPrivateKey(signerKeyId, passphrase)
    KM->>Keys: loadPrivateKeyFromPem()
    KM-->>ORCH: PRa (your private key)
    ORCH->>ORCH: hashMessage() → SHA-1 digest
    ORCH->>Keys: rsaSign(PRa, M‖ts) → signature
    ORCH->>ORCH: concat(signature, message) → X

    Note over ORCH,Zip: STEP 3 — COMPRESS
    ORCH->>Zip: compressData(X) → X

    Note over ORCH,Keys: STEP 4 — ENCRYPT
    ORCH->>Ciph: generateSessionKey() → Ks
    ORCH->>Ciph: symmetricEncrypt(Ks, X) → (iv, X)
    ORCH->>Keys: loadPublicKeyFromPem() → PUb
    ORCH->>Keys: rsaEncrypt(PUb, Ks) → enc_Ks
    ORCH->>ORCH: buildSessionKeyComponent(enc_Ks)

    Note over ORCH: STEP 5 — assemble outer container
    ORCH->>ORCH: assembleOutput() → X (outer JSON)

    Note over ORCH,R64: STEP 6 — RADIX-64
    ORCH->>R64: radix64encode(X) → ASCII

    ORCH-->>GUI: final file bytes
    GUI->>GUI: asksaveasfilename() → write msg.pgp
    GUI-->>User: "Message created"
```

---

## 2. SEND — pipeline (each step is optional)

```mermaid
flowchart TD
    M([message M]) --> S1[buildMessageComponent]
    S1 --> Q2{Sign?}
    Q2 -- yes --> SG[loadPrivateKey · hashMessage · rsaSign · concat]
    Q2 -- no --> Q3
    SG --> Q3{Compress?}
    Q3 -- yes --> CP[compressData = Z]
    Q3 -- no --> Q4
    CP --> Q4{Encrypt?}
    Q4 -- yes --> EN[generateSessionKey · symmetricEncrypt · rsaEncrypt Ks]
    Q4 -- no --> AS
    EN --> AS[assembleOutput = outer JSON + flags]
    AS --> Q6{Radix-64?}
    Q6 -- yes --> R[radix64encode = R64]
    Q6 -- no --> F
    R --> F([msg.pgp file])

    style M fill:#1f6feb,color:#fff
    style F fill:#238636,color:#fff
    style SG fill:#30363d,color:#fff
    style CP fill:#30363d,color:#fff
    style EN fill:#30363d,color:#fff
    style AS fill:#30363d,color:#fff
    style R fill:#30363d,color:#fff
```

---

## 3. SEND — how the data `X` transforms

| After step | `X` becomes | by |
|---|---|---|
| 1. message component | `{ message }` (JSON) | `buildMessageComponent` |
| 2. sign | `{ signature + message }` | `buildSignature`, `concat` |
| 3. compress | `«zlib blob»` | `compressData` |
| 4. encrypt | `«AES/3DES ciphertext»` (+ `enc_Ks`) | `symmetricEncrypt`, `rsaEncrypt` |
| 5. assemble | `{ header + session_key + payload }` | `assembleOutput` |
| 6. radix-64 | `"LS0tLS1CRUdJ...."` ASCII | `radix64encode` |

**Key rule:** the keys used —
`rsaSign` uses **your private** key · `rsaEncrypt` uses **recipient's public** key.

---

## 4. RECEIVE — timeline (the mirror)

```mermaid
sequenceDiagram
    actor User
    participant GUI as gui/receive_view.py
    participant ORCH as pgp/message.py<br/>pgpReceive()
    participant KM as pgp/keymanager.py
    participant Keys as pgp/keys.py
    participant Ciph as pgp/ciphers.py
    participant Zip as pgp/compression.py
    participant R64 as pgp/radix64.py

    User->>GUI: open msg.pgp
    GUI->>ORCH: inspectMessage(raw)
    ORCH-->>GUI: what's inside (encrypted? signed? ...)
    GUI-->>User: PassphraseDialog (if encrypted)
    GUI->>ORCH: pgpReceive(raw, passphrase)

    Note over ORCH,R64: un-RADIX-64
    ORCH->>R64: radix64decode() → outer JSON

    Note over ORCH,Keys: DECRYPT
    ORCH->>ORCH: parseSessionKeyComponent()
    ORCH->>KM: loadPrivateKey(recipientKeyId, passphrase)
    KM-->>ORCH: PRb (your private key)
    ORCH->>Keys: rsaDecrypt(PRb, enc_Ks) → Ks
    ORCH->>Ciph: symmetricDecrypt(Ks, iv, X) → X

    Note over ORCH,Zip: DECOMPRESS
    ORCH->>Zip: decompressData(X) → X

    Note over ORCH,Keys: VERIFY
    ORCH->>ORCH: parseSignedMessage(X) → message + signature
    ORCH->>Keys: loadPublicKeyFromPem() → PUa (sender)
    ORCH->>Keys: rsaVerify(PUa, signature, M) → valid?
    ORCH-->>GUI: { message, signature_valid, signer }
    GUI-->>User: shows message + "Signature VALID — signed by ..."
```

**Receive key rule:** `rsaDecrypt` uses **your private** key · `rsaVerify` uses **sender's public** key.

---

## 5. Files and their roles

| File | Role |
|---|---|
| `gui/send_view.py` / `gui/receive_view.py` | collect input, ask passphrase, save files |
| `pgp/message.py` | **orchestrators** `pgpSend` / `pgpReceive` + all substeps |
| `pgp/keymanager.py` | unlock private keys (passphrase) |
| `pgp/crypto_utils.py` | encrypt/decrypt the private key at rest |
| `pgp/keys.py` | RSA: `rsaSign`, `rsaVerify`, `rsaEncrypt`, `rsaDecrypt`, PEM I/O, Key ID |
| `pgp/ciphers.py` | symmetric: `generateSessionKey`, `symmetricEncrypt/Decrypt` |
| `pgp/compression.py` | `compressData` / `decompressData` (ZIP) |
| `pgp/radix64.py` | `radix64encode` / `radix64decode` (Base64) |
| `pgp/keyrings.py` | load/save the two key-ring JSON files |
| `pgp/models.py` | the entry data structures |
```
