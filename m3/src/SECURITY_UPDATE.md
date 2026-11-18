# CipherDrop security-center batch (v0.8–v0.9 + hardening preview)

## Implemented

- **Security Center** overview and clearer audit-chain verification display.
- **Password step-up**: confirm account password for five-minute approval before "Revoke all other sessions" or managing trusted devices.
- **Trusted browser records**: browser receives a random, HttpOnly cookie; only its SHA-256 hash is stored in the database. Device trust never bypasses login, vault unlock, or file permissions.
- **In-app notifications**: new login from trusted/untrusted browser, session revocation, device trust changes. No email delivery.
- **CSRF defense**: session-bound HMAC token on authenticated state-changing API calls and Origin checks. Frontend automatically sends the token.
- **Basic login/step-up/registration throttling**: 8 attempts per 5 minutes per client IP + username. In-memory **single-process only**, not a distributed production rate limiter.
- **Deployment guardrails**: `CIPHERDROP_ENV=production` disables interactive API docs and refuses to start without `CIPHERDROP_COOKIE_SECURE=true`. You must configure a genuine HTTPS reverse proxy separately.

## Not implemented in this batch

**Passkeys/WebAuthn are NOT implemented.** Secure WebAuthn needs a challenge store, correct RP ID/origin validation, signature and counter verification, credential lifecycle and tested browser flows. Do not claim it is present. The password-based login and step-up remain in use. Production TLS proxy setup, distributed rate limiting, external audit-chain anchoring, and full multi-worker audit synchronization also remain open.

## Installation / verification

1. Back up your local `data/` directory (especially `audit_hmac.key`) before starting the upgraded backend.
2. Apply the package with `bash ../CipherDrop_security_update/apply_update.sh "$PWD"` from the CipherDrop project root.
3. Run `./start.sh` in standalone mode; the existing SQLite database is migrated with the `sessions.step_up_until` column and two new tables.
4. In another terminal run `cd frontend && npm run build` (requires dependencies installed locally).
5. Open Security; confirm account password, trust current browser, revoke it, mark notifications read, and verify the audit chain.
6. Test a login in a second browser. Confirm the notification and session revocation.
7. Verify CSRF: an authenticated POST without `X-CSRF-Token` should return 403; the UI should continue working normally.
8. Confirm the original upload, download, sharing, and secure-link flows still work.

**Security limitations:** In-process rate limits reset on restart and do not coordinate multiple workers; HTTPS requires deployment configuration; compromised web-delivered JavaScript can steal browser keys; audit-chain verification is not an independent external attestation.
