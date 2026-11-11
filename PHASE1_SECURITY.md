# CipherDrop Phase 1 hardening — implementation notes

## What's changed

- Optional production HTTPS reverse proxy using Caddy and a public DNS name.
- Production startup refuses insecure session cookies or a non-HTTPS public origin.
- CORS is limited to the configured production origin; CSRF tokens remain session-bound.
- Same-origin checks reject supplied foreign Origin and cross-site fetch metadata.
- HTTP security headers and no-store API responses.
- Authentication attempt counters stored in SQLite (rather than being reset at every restart), with both IP-wide and account-specific limits. IP address comes from the direct socket; do not expose the backend directly.
- On a new login, any existing session cookie is invalidated (session rotation).
- Larger request fields have limits and login input has bounded lengths.
- Isolated automated API regression tests, including access isolation, CSRF, resharing revocation, expiry, audit tampering, one-time links and AES-GCM primitive tamper detection.
- Optional local dependency scanning commands; network advisories must be checked on a machine with internet access.

## Production deployment (DNS name + public certificate required)

Do **not** expose Vite dev server on the internet. Do **not** use the standalone/server menu to claim an HTTPS deployment.

1. Point a DNS A/AAAA record for `vault.example.com` to your deployment host; open TCP ports 80 and 443.
2. Install Caddy from https://caddyserver.com/docs/install and Python/Node dependencies.
3. From the project root, use `python3 -m venv .venv` and `.venv/bin/python -m pip install -r backend/requirements.txt`.
4. Run `cd frontend && npm ci && npm run build && cd ..`.
5. Run `export CIPHERDROP_DOMAIN=vault.example.com` (replace with your real hostname).
6. Run `./deploy/start_production.sh`. Access `https://vault.example.com`.
7. Store `data/` securely and back up `data/audit_hmac.key` together with the database. Never commit the key. The Caddy process must be able to write certificate storage.

`deploy/start_production.sh` starts the application bound to localhost; Caddy handles TLS and serves the compiled frontend. Use a trusted supervisor/service manager for restarts in real production. Cookie `Secure` mode only works over HTTPS. Verify browser cookies are Secure, HttpOnly and SameSite=Strict.

## Validation

```
python3 -m venv .venv
.venv/bin/python -m pip install -r backend/requirements.txt -r backend/requirements-test.txt
.venv/bin/python -m pytest -q tests
cd frontend && npm ci && npm run build && npm audit --audit-level=high && cd ..
.venv/bin/python -m pip install pip-audit
.venv/bin/python -m pip_audit -r backend/requirements.txt
```

The tests use a separate temporary directory (`CIPHERDROP_DATA_DIR`) and do not touch your actual vault. `pip-audit` and `npm audit` require online advisory access. Review results; do not indiscriminately force dependency upgrades.

## Known limitations to evaluate

- Per-IP/account SQLite throttling is designed for one backend instance. Multi-node deployments need a shared centralized limiter and proper proxy IP handling.
- Audit append uses a process-local lock; multiple API processes can still race. Run **one uvicorn worker**, and evaluate audit-chain concurrency and race conditions during your own security audit.
- Browser Web Crypto, unlike the Python AES-GCM test, needs manual browser testing for actual file upload/decrypt and ciphertext corruption.
- HTTP TLS termination assumes Caddy is correctly configured and internet-reachable; no publicly trusted certificate was provisioned by this package.
- Download-link limits are atomic in SQLite, but already downloaded plaintext cannot be revoked.
- Keep the backend private behind Caddy; never run an insecure API on an untrusted network.
- Security testing is not a guarantee that the application is vulnerability-free.

Do not ask AI to draft your course's threat model, security evaluation or reflection if prohibited by the rubric.
