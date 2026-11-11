# CipherDrop

**Your files. Your keys.** A browser-based encrypted file vault with cryptographic sharing, account security controls, and tamper-evident activity logging.

CipherDrop is a **standalone, localhost-only course project**. The browser encrypts file contents and filenames before upload; the Python backend stores ciphertext and enforces access controls. It is designed to demonstrate multiple security properties, **not** to serve as a production-ready password manager or cloud storage service.

## Quick start (macOS/Linux)

**Prerequisites:** Python **3.11+**, Node.js **20.19+** (including npm), GNU Make, a modern browser, and an internet connection for the initial dependency download. On macOS, Make is available with Apple's Command Line Tools.

In the project folder:

```bash
make          # Install dependencies and build the frontend
make run      # Start CipherDrop in standalone mode (no menu)
```

Open **http://localhost:5173**. Press **Ctrl+C** in the launch terminal to stop the application. `make run` checks/builds missing dependencies on a fresh checkout, so it also works as the initial command, though `make` followed by `make run` is recommended for grading.

**Normal user commands**

| Command | Description |
| --- | --- |
| `make` | Install Python/Node dependencies as necessary and build the React frontend |
| `make run` | Start the localhost-only frontend and API automatically |
| `make clean` | Remove compiled frontend and caches; **preserve user accounts and encrypted files** |

**Developer-only commands:** `make test` runs backend regression tests; `make audit` checks Python/npm dependencies against vulnerability advisories; `make help` lists available targets. `make clean-all` also removes the virtual environment and Node packages, but **not** application data. These developer targets are optional for someone just running CipherDrop.

The standalone launcher runs a Vite development frontend on `localhost:5173` and FastAPI on `127.0.0.1:8000`. The `make` production build is used by the optional Caddy-based HTTPS setup, **not** by the ordinary standalone Vite server. Do not expose either standalone service to an untrusted network.

For more installation/troubleshooting detail, see [SETUP.md](SETUP.md).

## Features at a glance

| Area | Implemented functionality |
| --- | --- |
| Accounts | Registration, Argon2id password hashing, login/logout, passkey login with password fallback |
| Vault | Separate vault passphrase, browser-side AES-256-GCM encryption/decryption, encrypted filenames |
| File management | Multi-file picker, drag-and-drop uploads, staged progress feedback, download, replace, delete |
| Sharing | Recipient-specific cryptographic sharing, permissions, expiration, resharing, recursive revocation |
| Secure links | Client-decrypted bearer links, download limits, expiration and revocation |
| Security Center | Session listing/revocation, password reauthentication, passkey management, trusted browsers, notifications |
| Activity | Event history and HMAC-SHA-256 audit-chain verification |
| Network protection | Session-bound CSRF tokens, origin checks, persistent login throttling, production secure-cookie/HTTPS configuration |

## Getting started with the application

1. **Register** an account. The account password is used for authentication and is hashed on the server.
2. **Create/unlock the vault** with a separate vault passphrase. This unlocks encryption key material in the browser.
3. **Upload files** with the picker or drag-and-drop area. Multiple files are supported, subject to a **100 MB per-file limit**. The UI reports encryption/upload stages rather than exact network-byte percentages.
4. **Download** an owned file using **Decrypt & Download**. Decryption takes place in the browser.
5. **Share** an owned file with another registered user. Configure permissions and expiration; the recipient finds it under **Shared**.
6. **Manage Access** to revoke grants, or create **Secure download links** for people without accounts.
7. Visit **Security** and **Activity** to manage sessions and credentials, inspect notifications, and verify the audit chain.

### Account passwords, passkeys, and the vault passphrase

These are **different security mechanisms**:

- **Account password** authenticates a user. The backend stores an Argon2id password hash rather than the original password.
- **Passkey (WebAuthn)** can authenticate an account using a device authenticator, security key, or supported passkey provider. Password sign-in remains available.
- **Vault passphrase** unlocks client-side encryption material. **A passkey login does not automatically decrypt or unlock the vault**; enter the vault passphrase afterward.

To add a passkey: log in with your password, unlock the vault, open **Security**, use **Confirm password** (a five-minute reauthentication window), then select **Add passkey**. Registered passkeys can be listed and removed there; sensitive changes require recent password confirmation. To sign in later, supply your username and select **Sign in with a passkey**.

**Local passkey origin:** Use **http://localhost:5173**, *not* `http://127.0.0.1:5173`. The application also supports the configured HTTPS origin for WebAuthn. Browser and device support for passkeys is required.

## Encryption and key management

- Files and original filenames are encrypted **in the browser** using **AES-256-GCM** and fresh random nonces.
- Each new/replaced file uses a random **256-bit data-encryption key (DEK)**. Replacing a file rotates key material and removes existing sharing grants/links.
- The browser generates a random **vault master key**. File DEKs are wrapped under that key; the vault master key is itself wrapped using a key derived from the user's vault passphrase (PBKDF2-SHA-256).
- CipherDrop stores ciphertext, encrypted metadata, and wrapped keys rather than intentionally sending plaintext files or unwrapped DEKs to the backend.
- Per-user **P-256 ECDH** sharing key pairs support recipient-specific access. The encrypted private sharing key is stored server-side; the browser uses **ECDH + HKDF-SHA-256 + AES-GCM** to wrap material for an authorized recipient.
- AES-GCM authentication causes decryption to fail when the ciphertext or authentication tag is modified.

**Security model:** CipherDrop is *zero-knowledge-inspired*, not a proven zero-knowledge system. The server serves the JavaScript that performs encryption, so a compromised server could distribute malicious code. The server also sees account, ownership, share, event, and timing metadata. Browser-side key derivation and memory handling have not been independently audited.

## File permissions and sharing

**Owned files:** Upload, list, decrypt/download, replace, delete, share and manage grants.

**Recipient permissions:**

- **View:** See the authorized file listing and decrypt associated filename metadata in the UI.
- **Download:** Retrieve ciphertext and decrypt the shared file in the browser.
- **Reshare:** Re-wrap the file key for another recipient, subject to the original grant's limits.

Grant expiration options include **1 hour, 24 hours, 7 days, a custom date/time, or no expiration**. Child grants cannot exceed parent permissions or expiration. Owners can revoke grants, including downstream grants created through resharing. Backend authorization checks protect file/blob and shared-file endpoints; access must not depend on simply hiding UI buttons.

**Limits of revocation:** Revoking a grant prevents *future access through CipherDrop*; it cannot erase copies previously downloaded or decrypted by a recipient.

### Secure download links

Owners may create a link with an expiration and **1–100 maximum ciphertext downloads**, inspect existing links, and revoke them. The browser generates the decryption secret and places it in the URL **fragment** (`#...`), which is not sent as part of a normal HTTP request. A visitor with the full URL can decrypt locally without an account.

These are **bearer links**: anyone possessing the complete link may use it until it expires, is revoked, or reaches its limit. A failed client-side decrypt can still consume a counted ciphertext download. Revocation cannot undo prior downloads.

## Security Center, authentication, and auditing

- **Sessions:** View current/other logins with readable browser/OS labels, IP information and expiry. Revoke individual sessions or all other sessions.
- **Password step-up:** Confirm the account password for a **five-minute** authorization window before higher-impact account actions. This does not log out the user after five minutes.
- **Trusted browsers:** Mark or remove browsers; this is a recognition feature and **does not bypass authentication**.
- **Passkeys:** Register, list and remove WebAuthn credentials; password login remains the fallback.
- **Notifications:** In-app login/device/security alerts with a read/unread state.
- **Activity timeline:** Inspect recorded login, file, sharing, session and link operations.
- **Audit verification:** Events form an **HMAC-SHA-256-linked audit chain**. Verification detects certain database-only changes if the signing key is kept separately secret.
- **Login throttling:** Login attempt counters persist in SQLite across standalone server restarts.
- **CSRF/origin checks:** Session-bound CSRF tokens and same-origin validation protect state-changing authenticated API operations.
- **Cookies:** Auth cookies are `HttpOnly` and `SameSite=Strict`. Production configuration requires `Secure` cookies over HTTPS; local HTTP standalone mode does not set `Secure`.

### Audit signing key — important

`data/audit_hmac.key` is a **secret**, generated locally, and must never be committed to Git or included in shared source archives. Preserve and back it up securely *alongside* the associated database. Deleting or replacing it can make existing audit records impossible to verify.

The current audit append mechanism uses a process-local lock and is intended for a **single backend process**. The chain does not provide independent proof against full host compromise, signing-key theft or undetected log truncation; multiple-worker concurrency remains a limitation.

## Architecture

```text
Browser (React + TypeScript + Web Crypto API)
  ├─ Registration, login, passkey ceremonies, vault UI
  ├─ Encrypt/decrypt contents and filenames locally
  └─ Wrap/unwrap vault, file and sharing keys
                 │ localhost HTTP (standalone)
                 ▼
FastAPI (Python, SQLAlchemy, Pydantic)
  ├─ Authentication, session management, CSRF, throttling
  ├─ Ownership, permission, sharing and download-limit enforcement
  ├─ WebAuthn verification, security notifications, audit chain
  ├─ SQLite: users, sessions, keys-as-ciphertext, grants, audit events
  └─ Local filesystem: data/encrypted/ ciphertext blobs
```

**Stack:** React, TypeScript, Vite, Web Crypto API; Python 3.11+, FastAPI, SQLAlchemy, Pydantic, Argon2, `webauthn`; SQLite; optional Caddy reverse proxy.

**Where data lives:** SQLite and encrypted blobs are stored locally under `data/`, with configuration in `.env`. Each fresh standalone installation starts with its own local data. Never commit `.env`, `data/cipherdrop.db`, `data/audit_hmac.key`, local credentials or encrypted user files.

## Testing and vulnerability checks (optional, for development)

```bash
make test    # Python regression tests using isolated temporary data
make audit   # Python pip-audit + npm audit (network access required)
```

The automated suite covers AES-GCM primitive tampering; account/file isolation; CSRF/origin enforcement; persistent rate limiting; shared-file expiry, permission and revocation paths; encrypted file storage/download; one-time link behavior; audit tampering; production configuration/cookie settings; and passkey challenge/access-control checks. **It does not replace manual end-to-end testing with a real authenticator or browser Web Crypto.**

Recommended manual regression: create an account → unlock vault → upload/download → test altered ciphertext → share with another account → revoke access → verify audit chain → register/login with a passkey → try drag-and-drop → inspect cookies under HTTPS.

`make audit` checks currently known advisories, not application logic, and should not be treated as proof of complete security. The frontend currently pins **Vite 8.3.6**; review new advisories before future deployments.

## HTTPS and deployment

**Normal usage is localhost-only, with no hosting/menu option.** A previously added **optional** production configuration lives in `deploy/` with instructions in [PHASE1_SECURITY.md](PHASE1_SECURITY.md). It uses Caddy to serve the built frontend and proxy `/api/*` to a local FastAPI process over a TLS-protected public origin. Local testing can use `deploy/Caddyfile.local` and Caddy's locally trusted CA.

Standalone `make run` **does not start Caddy** and is not an HTTPS production deployment. A public deployment would still require DNS, a valid TLS configuration, secure cookie verification, proper process management and an independent security review. Do **not** expose the Vite dev server or API port directly to the internet.

## Known limitations

- This is a teaching/research implementation and has **not received an independent production security audit**.
- Local SQLite authentication throttling and the HMAC audit append implementation target one backend process; neither is designed for distributed hosting.
- Browser-served cryptographic JavaScript remains a trust boundary. Vault passphrase derivation currently uses PBKDF2 rather than a memory-hard browser-side KDF.
- Passkeys authenticate the account but don't replace vault unlocking; WebAuthn support varies by device/browser/origin.
- Upload progress is **stage-based**, not exact percentage of network bytes.
- Secure links and authorized recipient downloads cannot revoke plaintext that someone has already saved.
- `make run` serves a development frontend on localhost. Production HTTPS is an **optional, separately configured deployment**.

## Course project note

CipherDrop demonstrates encryption, account security, access controls, network security configuration, and audit logging. The course's threat model, security evaluation, and AI-use reflection are separate **student-authored** submissions and are not provided by this README.
