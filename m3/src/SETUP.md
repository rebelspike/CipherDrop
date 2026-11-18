# CipherDrop — Quick Start (macOS/Linux)

## Requirements
- Python 3.11 or newer (`python3`)
- Node.js **20.19+** with `npm`
- `make` (available with macOS Command Line Tools or Linux build tools)
- Internet connection **on first installation** to download dependencies
- Modern browser with Web Crypto support

## Start from a clean submission ZIP

Extract the project and open Terminal inside the folder containing `Makefile`.

```bash
make
make run
```

CipherDrop starts directly in **Standalone** mode. Open `http://localhost:5173` in your browser. Press `Ctrl+C` to stop.

`make` creates a local `.venv`, installs the backend and frontend dependencies, locks Vite to patched version **8.3.6** if the lockfile is older, and builds the frontend. No pre-existing accounts or database are needed. Running `make` again is safe.

## Additional commands (optional)

```bash
make test     # install test dependencies and run security regression tests
make audit    # check Python/npm dependencies against known advisories
make clean    # clear generated build artifacts; KEEP user data and packages
make help
```

`make audit` needs internet access and can return a nonzero exit status if a vulnerability is found. A passing audit is **not** proof that the application has no vulnerabilities.

## Troubleshooting
- **`make: command not found`** on macOS: install Apple's Command Line Tools (`xcode-select --install`).
- **Node.js version error:** install Node.js 20.19+ (or a recent supported LTS).
- **Network/npm error:** verify internet access and rerun `make`.
- **Ports 5173/8000 in use:** stop the other app process and rerun `make run`.
- **Python dependency install fails:** verify Python 3.11+ and internet access.
- **Application data persists after `make clean`:** intentional. Cleanup never deletes encrypted blobs, the SQLite database, `.env`, or the audit HMAC key.

## Important security notes
Standalone mode binds to localhost. Do **not** expose the Vite development server or the Standalone HTTP endpoints directly to the internet. Remote deployment requires a proper HTTPS reverse proxy and production security configuration; see `PHASE1_SECURITY.md`.

Windows uses `start.ps1` (GNU Make instructions above target macOS/Linux).

## Simple grading setup (macOS/Linux)

Prerequisites: Python 3.11+, Node.js 20.19+, npm, and GNU Make. Internet connection required on first run.

```bash
make
make run
```

It starts directly in **Standalone** mode. Open `http://localhost:5173` (use **localhost**, not 127.0.0.1, for passkeys). `make run` also performs initial setup automatically if required. `make clean` removes only build artifacts and caches, **not accounts, encrypted files, or audit secrets**.

To test a passkey: sign in with your password, unlock the vault, open Security, click Confirm password, then Add passkey. Log out, enter your username and choose Sign in with a passkey. After passkey authentication enter your separate vault passphrase.

A Mac or PC must have platform passkey support (Touch ID/Windows Hello/security key or paired phone). Browser WebAuthn requires a trustworthy origin (localhost or HTTPS). Development over `http://127.0.0.1:5173` is not supported for passkey registration by this implementation; use `http://localhost:5173`.
