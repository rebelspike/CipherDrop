# CipherDrop

Zero-knowledge-inspired encrypted file vault and controlled sharing platform.

## Current status — v0.2 vertical slice
Working path: **Register → Login → Unlock Vault → Encrypt Locally → Store Ciphertext → Download → Decrypt Locally**.

### Security implemented now
- Account passwords hashed server-side with Argon2id (`argon2-cffi`).
- Opaque random session tokens; only SHA-256 token digests are stored in the database.
- Random 256-bit vault master key generated in the browser.
- Vault master key is wrapped client-side with AES-256-GCM using a KEK derived from the vault passphrase.
- Random 256-bit DEK for every file.
- File contents encrypted client-side with AES-256-GCM.
- File DEKs wrapped client-side by the vault master key.
- Original filenames encrypted client-side too.
- Server stores ciphertext blobs only in `data/encrypted/`.
- Ownership is checked server-side before metadata/blob access.

### Important current limitations
This is an early security build, **not production ready**. TLS, rate limiting, CSRF hardening, sharing, RBAC, session management UI, audit chaining, device trust, notifications, passkeys, and browser Argon2id vault KDF are upcoming. Server mode is development-only until TLS is added.

## Quick start
Requirements: Python 3.11+ and Node.js 20+.

macOS/Linux:
```bash
./start.sh
```

Windows PowerShell:
```powershell
.\start.ps1
```

On first run, CipherDrop creates a Python virtual environment and installs backend/frontend dependencies. Choose **Standalone** for the easiest local run, then open `http://localhost:5173`.

## Key rule
The account password authenticates the account. The vault passphrase unlocks client-side encryption material. They serve different purposes and should be treated as separate secrets.
