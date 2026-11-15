# Security Fixes from the Milestone 3 Audit

Three audit findings were fixed in the backend. Only `backend/app/main.py` and `backend/app/schemas.py` changed; there are no frontend or database schema changes. The fixes are not committed yet, so `git diff backend/` shows the full change.

| # | Finding | Fix |
|---|---|---|
| 1 | No login rate limiting | 5 failed attempts per username in 15 minutes, then HTTP 429 |
| 3 | Failed logins and downloads not audited | New `LOGIN_FAILED`, `FILE_DOWNLOADED`, and `SHARE_DOWNLOADED` events |
| 5 | Expiration date without a timezone crashed the server (HTTP 500) | Timezone now required; returns HTTP 422 instead |

Findings 2 (no AES-GCM AAD) and 4 (audit tail truncation / key on the same host) were **accepted**, not fixed. Both require full server compromise.

---

## Fix 1: Login rate limiting

**Problem:** 1,000 login guesses went through in 12.7 seconds with no 429 response, and the correct password still worked on attempt #1000.

**Change:** [main.py:137-170](../../backend/app/main.py#L137-L170) adds an in-memory limiter, and `login()` ([main.py:196](../../backend/app/main.py#L196)) calls it first.
- `reserve_login_attempt(username)` checks and records the attempt in one locked step, **before** the Argon2 verify.
- A successful login clears that username's record.
- Once a username has 5 attempts in the 15-minute window, the endpoint returns `429` with a `Retry-After` header.

**Design choices to review:**
- **Check and record happen together, before verifying.** The first version checked first and recorded the failure after Argon2. 10 concurrent requests all passed the check before any failure was saved, so 11 guesses got through instead of 5. Recording up front closes that race.
- **Keyed by username, not IP.** The Vite dev server proxies `/api`, so every request reaches FastAPI from `127.0.0.1`. An IP limit would lock out every user at once.
  - The same proxy issue means `sessions.ip_address` is always `127.0.0.1`.
- **Unknown usernames are limited too**, so the 429 doesn't reveal whether an account exists.
- **Blocked (429) attempts are not audited**, so flooding the endpoint can't flood the audit log.

**Known limits:**
- **Targeted lockout:** anyone can lock a specific user out for 15 minutes by sending 5 bad passwords for that username. This is the usual tradeoff of per-account lockout.
- **Memory only:** the counter lives in memory, so it resets when the server restarts and isn't shared across multiple workers. This is the same scope limit as `_audit_lock`. Production would need Redis or a database table.
- **Timing still differs:** unknown usernames still skip Argon2, so the timing difference between real and fake usernames remains. This wasn't in scope.

## Fix 3: Audit missing events

**Problem:** a failed login, an owner download, and a shared download all added 0 audit rows.

**Change:**
- `login()` now writes `LOGIN_FAILED` with `result="failure"` before returning 401 ([main.py:209](../../backend/app/main.py#L209)).
  - `user_id` is the account's ID if the username exists, otherwise `NULL`.
  - The attempted username is deliberately **not** stored, because people sometimes type their password into the username box.
- `download_blob()` writes `FILE_DOWNLOADED` ([main.py:340](../../backend/app/main.py#L340)).
- `download_shared_blob()` writes `SHARE_DOWNLOADED` under the recipient ([main.py:526](../../backend/app/main.py#L526)).

These events use the existing `audit()` helper, so they're part of the HMAC chain, and Verify Chain still passes. Users see their own `LOGIN_FAILED` events on the Activity page.

## Fix 5: Timezone-less expiration date

**Problem:** sending `expires_at: "2030-01-01T00:00:00"` (no timezone) to create a share or link raised `TypeError: can't compare offset-naive and offset-aware datetimes`, which returned HTTP 500.

**Change:** `expires_at` is now `pydantic.AwareDatetime` in `ShareRequest` ([schemas.py:31](../../backend/app/schemas.py#L31)), which `ReshareRequest` inherits, and in `LinkCreate` ([main.py:574](../../backend/app/main.py#L574)). A date without a timezone now gets a clean `422`. The frontend already sends `toISOString()` values ending in `Z`, so the normal UI is unaffected.

---

## Retest results

The full audit script was re-run against the patched code on a fresh, isolated database:

| Scenario | Before | After |
|---|---|---|
| Brute force (1,000 attempts) | 1,000 × 401/200, never blocked | 5 failures total, then 429 (`Retry-After: 900`); correct password also blocked during lockout; a different user could still log in |
| Missing events | 0 new audit rows | `LOGIN_FAILED`, `FILE_DOWNLOADED`, `SHARE_DOWNLOADED` recorded; Verify Chain valid |
| Timezone-less expiry | 500 on shares and links | 422 on both; zero 500s in the server log |
| Other 8 scenarios | Passed | Still pass (no regressions) |

**To check it yourself:**
1. Run `python -m compileall backend/app`.
2. Start the app and try 6 wrong passwords for one account. The 6th should say "Too many failed login attempts."
3. Download a file, then confirm `FILE_DOWNLOADED` appears on the Activity page.
