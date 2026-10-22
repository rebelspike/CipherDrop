# CipherDrop

Zero-knowledge-inspired encrypted file vault and controlled sharing platform.

## Current status — v0.4 sharing controls
CipherDrop now supports the end-to-end path **Register → Login → Unlock Vault → Encrypt Locally → Store Ciphertext → Share Cryptographically → Enforce Permissions/Expiration → Revoke Access → Decrypt Locally**.

### Security implemented now
- Account passwords are hashed server-side with Argon2id (`argon2-cffi`).
- Opaque random session tokens are issued to the browser; only SHA-256 token digests are stored in the database.
- A random 256-bit vault master key is generated in the browser.
- The vault master key is wrapped client-side with AES-256-GCM using a KEK derived from the vault passphrase.
- Every uploaded/replaced file gets a fresh random 256-bit DEK and fresh AES-GCM nonces.
- File contents and original filenames are encrypted client-side with AES-256-GCM.
- File DEKs are wrapped client-side; the server stores ciphertext and wrapped key material rather than raw DEKs/plaintext.
- Each user has a P-256 ECDH sharing key pair. The public key is server-visible; the private key is encrypted client-side under the vault key before storage.
- Recipient-specific sharing keys are derived client-side with ECDH + HKDF-SHA-256, then used with AES-256-GCM to protect the file DEK and filename for that recipient.
- Server-side ownership/recipient checks protect file and share endpoints against simple IDOR/BOLA attacks.
- Owners can replace and delete encrypted files. Replacement generates new client-side key material and revokes existing shares.

### v0.4 — permissions, expiration, reshare, and revocation
- Share grants support **View listing**, **Download**, and **Reshare** permissions.
- Share expiration supports never, 1 hour, 24 hours, 7 days, or a custom date/time.
- Expired grants are excluded from the recipient's active Shared view and cannot download ciphertext.
- Owners get **Manage Access** for each file and can revoke individual grants.
- Revocation is enforced by the backend, not just hidden in the UI.
- A recipient with Reshare permission can re-wrap the file DEK in the browser for another recipient without exposing the raw DEK to the server.
- Reshared grants cannot outlive their parent grant and cannot gain permissions the parent did not have.
- Revoking a grant recursively revokes downstream grants created through it.
- Existing pre-v0.4 development shares are migrated on SQLite startup with View + Download enabled, Reshare disabled, and no expiration.

## Security behavior already exercised manually
Development testing has included ciphertext tampering, wrapped-DEK tampering, wrong vault passphrases, unauthorized file GET/PUT/DELETE requests, and unauthorized access to another recipient's share. AES-GCM integrity failures were rejected and tested cross-user object-ID requests were denied.

## Important security boundaries and limitations
CipherDrop is a course-project security build, **not production ready**. “Zero-knowledge-inspired” is intentionally narrower than claiming complete zero knowledge: stored server-side data alone is designed to be insufficient to decrypt user files, but the web server delivers the JavaScript that performs cryptography. A compromised server could therefore attempt to serve malicious client code.

A **View listing** permission means the recipient may see/decrypt shared-file metadata in the CipherDrop UI; it does not give plaintext file access. **Download** controls retrieval of the encrypted blob needed for normal client-side file decryption. Once a recipient legitimately decrypts/downloads plaintext, later revocation cannot erase copies they already saved. Revocation prevents future access through CipherDrop.

TLS, rate limiting, CSRF hardening, richer session management, tamper-evident audit chaining, device trust, notifications, passkeys, and a memory-hard browser-side vault KDF remain planned. Server mode should be treated as development-only until TLS is added.

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

## Key model
The **account password** authenticates the account. The **vault passphrase** unlocks client-side encryption material. They serve different purposes and should be treated as separate secrets.

For sharing, the server may store public keys, encrypted private-key blobs, wrapped DEKs, encrypted filenames, permissions, expiration times, and relationship metadata such as owner/recipient IDs. It should not receive the raw file DEK, plaintext sharing private key, plaintext filename, or plaintext file as part of the normal encryption/sharing flow.
