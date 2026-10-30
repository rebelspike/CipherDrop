# CipherDrop

Zero-knowledge-inspired encrypted file vault and controlled sharing platform.

## Current status — v0.7 development batch (sessions, audit, secure links)
CipherDrop supports the end-to-end path **Register → Login → Unlock Vault → Encrypt Locally → Store Ciphertext → Share Cryptographically → Enforce Permissions/Expiration → Revoke Access → Decrypt Locally**.

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

### v0.5 — Security sessions
- **Security** page lists the account's active sessions with user-agent, IP, creation, expiration, and current-session identification.
- Revoke an individual session or revoke all other sessions. Revocation removes server-side session records immediately.
- Cookie `Secure` flag is controlled by `CIPHERDROP_COOKIE_SECURE=true` for HTTPS deployments; local HTTP remains the development default.

### v0.6 — Security activity and tamper-evident audit
- Backend emits audit events for session creation/logout/revocation, file upload/replace/delete, share creation/resharing/revocation, and secure-link events.
- **Activity** displays the latest 150 events for the signed-in user.
- **Security → Verify chain** checks an HMAC-SHA-256-linked sequence for database-only tampering.
- Audit HMAC key is generated at `data/audit_hmac.key` (outside the DB) and MUST be backed up separately, protected from source control, and kept secret. Deleting it makes previously recorded events unverifiable.
- This is a **single-process development implementation**; concurrency across multiple server workers and key compromise are not solved. Do not claim the audit chain protects against full host compromise or log truncation without external checkpoints.

### v0.7 — Secure encrypted links
- File owner can create a bearer download link with expiration and a maximum download count (1–100), list links, and revoke them.
- Browser generates a random 256-bit link key, re-wraps the file DEK and encrypts the filename with AES-256-GCM. The key lives in the URL `#fragment` and is not sent as part of ordinary HTTP requests.
- Backend stores only a SHA-256 hash of the random link token, encrypted metadata, and counters. A public visitor can decrypt locally without an account.
- Download counter increments using an atomic conditional database update. The counter counts **ciphertext downloads**, not successful human consumption of plaintext; a failed client-side decrypt still consumes a download.
- Bearer links are transferable: anyone who obtains the full link can download until it expires or is exhausted. Link revocation does not erase already saved copies.
- Links to a file are removed when the file is replaced or deleted.

## Security behavior already exercised manually
Development testing has included ciphertext tampering, wrapped-DEK tampering, wrong vault passphrases, unauthorized file GET/PUT/DELETE requests, and unauthorized access to another recipient's share. AES-GCM integrity failures were rejected and tested cross-user object-ID requests were denied.

## Important security boundaries and limitations
CipherDrop is a course-project security build, **not production ready**. “Zero-knowledge-inspired” is intentionally narrower than claiming complete zero knowledge: stored server-side data alone is designed to be insufficient to decrypt user files, but the web server delivers the JavaScript that performs cryptography. A compromised server could therefore attempt to serve malicious client code.

A **View listing** permission means the recipient may see/decrypt shared-file metadata in the CipherDrop UI; it does not give plaintext file access. **Download** controls retrieval of the encrypted blob needed for normal client-side file decryption. Once a recipient legitimately decrypts/downloads plaintext, later revocation cannot erase copies they already saved. Revocation prevents future access through CipherDrop.

TLS, rate limiting, CSRF hardening, robust multi-process audit coordination, device trust, notifications, passkeys, and a memory-hard browser-side vault KDF remain planned. Server mode should be treated as development-only until TLS is added.

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

## v0.7 developer test checklist (manual)
1. Open CipherDrop in two independent browser profiles and sign in to the same account. Security page should show both sessions; revoke one and confirm it receives HTTP 401 on the next authenticated request.
2. Click **Revoke all other sessions** and confirm only the current session survives.
3. Upload, share, and revoke a test file. Confirm Activity lists events and Security verifies the chain. For tamper tests, use a **backup copy** of the database, not your real data.
4. Generate a one-download link. Open it in a private window; decrypt and download. A second download should fail.
5. Generate a longer-lived link and revoke it before downloading. Confirm it becomes unavailable.
6. Test expiration with a short expiry and verify download is rejected after expiry.
7. Run `python -m compileall backend/app` and `cd frontend && npm run build` on the Mac. Do not commit if the frontend build fails.

**Academic integrity:** Threat model, security analysis, and AI reflection must be written by the students, not copied from generated documentation.
