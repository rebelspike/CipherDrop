# CipherDrop

Zero-knowledge-inspired encrypted file vault and controlled sharing platform.

## Current status
Milestone 0 bootstrap: portable setup launcher and project skeleton.

## Quick start
macOS/Linux: `./start.sh`
Windows PowerShell: `.\\start.ps1`

The launcher supports Standalone, Server, and Development modes from one codebase.

## Planned security architecture
- Client-side AES-256-GCM file encryption
- Per-file random data encryption keys
- Wrapped user/file keys; server should not require plaintext file contents
- Argon2id account password hashing
- Opaque revocable sessions
- RBAC + per-file authorization
- Step-up authentication
- Device trust and passkeys
- Security activity timeline and notifications
- Tamper-evident audit logging
