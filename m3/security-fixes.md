# Security Fixes from the Milestone 3 Audit

The audit found 12 vulnerabilities: 5 from our attack scenarios and 7 from the AI red team. We fixed 9 and accepted 3. Every fix was retested on an isolated copy of the merged v1.0 code.

**Fixes:**

| # | Source | Finding | Fix | Where |
|---|---|---|---|---|
| S1 | Scenario | No login rate limiting | Engineer's database-backed limiter: 8 attempts per account and 40 failed attempts per IP in 5 min, then HTTP 429 | `check_login_limit()`, [main.py:217](../backend/app/main.py#L217) |
| S3 | Scenario | Failed logins and downloads not audited | `LOGIN_FAILED`, `FILE_DOWNLOADED`, `SHARE_DOWNLOADED` events | [main.py:256](../backend/app/main.py#L256), [main.py:395](../backend/app/main.py#L395), [main.py:581](../backend/app/main.py#L581) |
| S5 | Scenario | Timezone-less expiry crashed the server (500) | Engineer's `timezone_required` validator; returns 422 | [schemas.py:24](../backend/app/schemas.py#L24), [main.py:637](../backend/app/main.py#L637) |
| R1 | Red team | One shared IP could lock out every user | Successful attempts no longer count toward the IP limit; the Vite proxy forwards the real client IP | `clear_login_limit()`, [main.py:231](../backend/app/main.py#L231); [vite.config.ts:13](../frontend/vite.config.ts#L13) |
| R2 | Red team | `X-Forwarded-For` spoofing through Vite | `xfwd: true`: Vite appends the real IP, and uvicorn uses the right-most untrusted entry | [vite.config.ts:13](../frontend/vite.config.ts#L13) |
| R3 | Red team | Password could equal the vault passphrase | Register form rejects it | `auth()`, [main.tsx:263](../frontend/src/main.tsx#L263) |
| R4 | Red team | Step-up bypass by revoking sessions one at a time | Revoking another session now requires step-up | `revoke_session()`, [main.py:593](../backend/app/main.py#L593) |
| R6 | Red team | Failed step-up not audited | `STEP_UP_FAILED` event | [main.py:728](../backend/app/main.py#L728) |
| R7 | Red team | Audit verify revealed the system-wide event count | `checked` removed from the response and the UI | `audit_integrity()`, [main.py:625](../backend/app/main.py#L625); [main.tsx:305](../frontend/src/main.tsx#L305) |

**Accepted:**

| # | Finding | Why |
|---|---|---|
| S2 | Ciphertext can be swapped (no AES-GCM AAD) | Requires full server compromise, which can already serve malicious JavaScript |
| S4 | Audit tail truncation and forgery with the HMAC key | Requires direct database access, plus the key file for forgery; a single-host hash chain can't prevent this |
| R5 | Username enumeration (login timing and the register "username unavailable" error) | Username sign-up has to say when a name is taken; the timing gap only confirms what register already reveals |

---

## Scenario fixes (S1, S3, S5)

**S1: Login rate limiting.**
- **How it works:** `check_login_limit()` runs before the password check. Under a lock, it counts recent attempts for the account and for the client IP, and records the new attempt in the same step, so concurrent requests can't slip past the limit.
- **Storage:** attempts are stored in the `AuthAttempt` table as HMAC keys, so they survive restarts and raw usernames and IPs aren't stored.
- **Coverage:** the same limiter protects login, register, step-up, and passkey login.

**S3: Missing audit events.** `login()` handles an unknown username exactly like a wrong password: both write `LOGIN_FAILED` and return 401.
- The attempted username is not stored, because people sometimes type their password into that box.
- Owner downloads write `FILE_DOWNLOADED`.
- Shared downloads write `SHARE_DOWNLOADED` under the recipient.

**S5: Timezone-less expiry.** `expires_at` must include a timezone offset in `ShareRequest` (which `ReshareRequest` inherits) and in `LinkCreate`. The frontend already sends `toISOString()` values, so the normal UI isn't affected.

## Red-team fixes (R1–R4, R6, R7)

**R1 and R2: IP-based limiting behind the Vite proxy.**

The problem was that every request reached FastAPI from `127.0.0.1`, so all users shared one 40-attempt IP budget. Successful logins also used up that budget, so 40 failed logins from anyone locked out everyone. On top of that, uvicorn trusts `X-Forwarded-For` from `127.0.0.1`, and Vite passed the client's header through untouched, so anyone could fake their IP.

The fix has two parts:
- **The real IP is forwarded.** `xfwd: true` in `vite.config.ts` makes Vite append the real client address. A client that sends `X-Forwarded-For: 203.0.113.50` now arrives as `203.0.113.50,<real IP>`, and uvicorn takes the right-most address that isn't a trusted proxy, which is the real one.
- **Only failures count.** `clear_login_limit()` now refunds the IP slot when the password is correct, so the IP budget counts only failed attempts.

Known limits:
- **On the server machine itself:** a client there connects from `127.0.0.1`, which uvicorn trusts. That client can still spoof its IP and shares one IP budget with everyone else on that machine. This only affects people with access to the host itself.
- **Production:** Caddy sets `X-Forwarded-For` from the real client address. This setup was not tested.
- **Targeted lockout:** 8 bad passwords still lock a specific account for 5 minutes.

**R3: Password equal to the vault passphrase.** The register form now refuses to submit if the two are identical and explains why: the server sees the account password at every login. This has to be a frontend check, because the server never sees the vault passphrase. A modified client could skip it, but the check exists to protect users from a mistake, not from themselves.

**R4: Step-up bypass.** `revoke_session()` now requires a recent step-up to revoke any session other than the current one, the same as "revoke all others". The ownership check runs first, so another user's session IDs still return 404, not 403.

**R6: Failed step-up auditing.** A wrong step-up password now writes `STEP_UP_FAILED` with `result="failure"`. It appears in the user's Activity log and is part of the HMAC chain.

**R7: Audit count leak.** `/api/security/audit/verify` no longer returns `checked`, and the Security page shows "✓ VERIFIED · HMAC-SHA-256" without a count. One limit remains: event, file, and share IDs are sequential across all users, so someone could still roughly estimate overall activity from the gaps between IDs.

---

## Retest results (merged v1.0 code)

| Finding | Before | After |
|---|---|---|
| S1 Brute force | 1,000 attempts, never blocked | 8 failures, then 429; correct password blocked during lockout; other users unaffected |
| S3 Missing events | 0 new audit rows | `LOGIN_FAILED`, `FILE_DOWNLOADED`, `SHARE_DOWNLOADED` recorded; chain valid |
| S5 Timezone-less expiry | 500 | 422 (a date with a timezone still returns 201) |
| R1 Shared-IP lockout | 45 failures for fake usernames locked out a real user with the correct password | 50 successful logins from one IP: all 200. Attacker IP blocked after 40 failures; users on other IPs and on localhost still log in |
| R2 IP spoofing | Spoofed IP accepted; 100-account spray never blocked | LAN client's real IP recorded; spray blocked after 40 |
| R3 Password = passphrase | Registration accepted | Register form blocks it (code review plus production build; not exercised in a browser) |
| R4 Step-up bypass | Other sessions revoked without step-up (204) | 403 without step-up; 204 after step-up |
| R6 Failed step-up | 0 audit rows | `STEP_UP_FAILED` recorded and shown in Activity |
| R7 Audit count leak | `checked=195` shown to a user with 1 event | Response is just `{"valid": true}` |

All 11 original scenarios were re-run afterward. The 8 that passed still pass, and the server logged no 500 errors. LAN clients were simulated by sending the backend the exact `X-Forwarded-For` chain Vite produces, which was confirmed with a header-echo server.

**To check it yourself:**
1. Run `python -m compileall backend/app` and `cd frontend && npm run build`.
2. Register with the same account password and vault passphrase. The form should refuse.
3. On the Security page, revoke another session without confirming your password. It should ask for reauthentication.
