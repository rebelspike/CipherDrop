# [Your Application Name]

**CSCI 4531/6531 — Course Project**
**Team:** [Name 1, Name 2, Name 3]

## What This Application Does

[1–2 paragraph description of your application: what it does, who it is for, and
what security problem it solves.]

## Security Properties Implemented

| Property | Implementation | Key files |
|---|---|---|
| Encryption | AES-256-GCM via Python `cryptography` library | `src/crypto.py` |
| Accounts | Registration + Argon2id password hashing + session management | `src/auth.py` |
| [Property] | [How] | [Where in code] |

## Quick Start

See [SETUP.md](SETUP.md) for full environment and run instructions.

```bash
# Short version (assumes dependencies installed):
python app.py
# Then open http://localhost:5000
```

## Project Structure

```
src/
├── app.py          ← main application entry point
├── auth.py         ← authentication and session management
├── crypto.py       ← encryption/decryption operations
├── models.py       ← database models
├── routes/         ← HTTP route handlers
└── templates/      ← HTML templates
```

## Security Architecture Notes

[Brief notes on where security is enforced and any important design decisions.
Reference specific files and functions.]
