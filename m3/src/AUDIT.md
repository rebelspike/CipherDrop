# Security Audit Instructions
## CipherDrop

This document lets someone unfamiliar with the project reproduce our security audit independently. Every test is automated in `m3/src/audit/`, and one command runs all of them against a **throwaway copy** of CipherDrop's data. Your own accounts and files are never touched.

---

## Prerequisites

* macOS or Linux with Python 3.11+, Node.js 20.19+, `make`, and `curl` (the same requirements as SETUP.md).
* Run `make` once from the project root. This creates `.venv` and installs the frontend packages.
* Ports **8000** and **5173** must be free. Stop CipherDrop (`Ctrl+C` on `make run`) before auditing.
* Internet access on the first run. The audit installs `backend/requirements-test.txt` (`httpx`, `cryptography`) into `.venv`.
* **No test accounts need to be created.** The scripts register their own users (alice, bob, carol, mallory, and so on, with a random suffix).

**Audit files** (in `m3/src/audit/`):

| File | What it does |
|---|---|
| `run_audit.sh` | One-command runner: starts the backend and Vite dev server with a temporary data folder, runs both scripts, saves logs, cleans up |
| `audit_tests.py` | The 11 attack scenarios from our audit plan, plus the extra checks |
| `redteam_tests.py` | Reproduces the AI red-team findings and checks |
| `results/` | Logs and JSON from the latest run (overwritten each run) |

The scripts act as a CipherDrop browser: they do the same Web Crypto steps as `frontend/src/main.tsx` (PBKDF2 → AES-256-GCM vault key, a fresh AES-256-GCM key per file, ECDH P-256 + HKDF for sharing), send the CSRF token, and talk to the real API. Tamper tests edit the throwaway SQLite database directly, as an attacker with database access would.

---

## Running the Audit

From the project root:

```bash
make                         # first time only
./m3/src/audit/run_audit.sh
```

It takes about 2 minutes and ends with a summary.

### Expected Output (submitted build)

```
[A-2] Password storage -> DEFENDED
[S-1] Stolen token hash replayed as cookie -> DEFENDED
[C-1] Tampered ciphertext (1 byte flipped in .enc file) -> DEFENDED
[C-2] Swapped files (malicious server / DB write access) -> VULNERABLE      ← accepted risk
[R-1] IDOR: accessing another user's files by ID -> DEFENDED
[R-2] Reshare privilege escalation -> DEFENDED
[L-1] Download-limit race (50 simultaneous downloads, limit 1) -> DEFENDED
[L-2] Reusing a dead link (revoked / expired / exhausted) -> DEFENDED
[G-2] Missing events (failed login + downloads) -> DEFENDED
[G-1] Editing or deleting an audit entry -> DEFENDED
[X-1] [Extra] Expiration date without a timezone -> OK
[A-1] Brute-force login (1,000 rapid attempts) -> DEFENDED
[RT-1] Global login lockout through a shared IP -> DEFENDED
[RT-2] X-Forwarded-For spoofing -> DEFENDED
[RT-3] Step-up bypass by revoking sessions one at a time -> DEFENDED
[RT-4] Username enumeration (accepted risk) -> VULNERABLE                   ← accepted risk
[RT-5] Failed step-up attempts audited -> DEFENDED
[RT-6] Audit verify reveals system-wide event count -> DEFENDED
[RT-7] CSRF on state-changing requests -> DEFENDED
[RT-8] Session fixation -> DEFENDED
[RT-9] Account password equal to vault passphrase -> MANUAL                 ← check in browser (see RT-9)
[RT-10] Oversized upload metadata (DoS) -> DEFENDED
HTTP 500 responses in backend log: 0
```

Timings, IDs, and event counts vary between runs. The verdicts should match. Each line in `results/audit_tests.log` and `results/redteam_tests.log` is followed by the detailed observations quoted in the "Actual Result" sections below.

### Running pieces by hand (optional)

To run a script on its own, start the servers yourself with a temporary data folder:

```bash
.venv/bin/python -m pip install -r backend/requirements-test.txt   # httpx, cryptography
export CIPHERDROP_DATA_DIR="$(mktemp -d)"                       # throwaway data
.venv/bin/python -m uvicorn app.main:app --app-dir backend --port 8000 &
(cd frontend && node_modules/.bin/vite --host 127.0.0.1 --port 5173) &
.venv/bin/python m3/src/audit/audit_tests.py   http://127.0.0.1:8000 "$CIPHERDROP_DATA_DIR"
.venv/bin/python m3/src/audit/redteam_tests.py http://127.0.0.1:5173 http://127.0.0.1:8000 "$CIPHERDROP_DATA_DIR"
```

Never point the scripts at your real `data/` folder: the tamper tests modify the database.

---

## Audit Scenario 1 — Brute-Force Login

**Security property tested:** Accounts  
**Expected result:** Rate limiting activates; the correct password is refused during lockout.

### Steps

`audit_tests.py` → `t_bruteforce` (output line `[A-1]`). It sends 1,000 login attempts for one account from 10 threads, with the correct password as attempt #1000. Then it logs in as a different user.

To try it by hand (with the servers running):

```bash
for i in $(seq 1 12); do
  curl -s -o /dev/null -w "%{http_code}\n" -X POST http://127.0.0.1:8000/api/auth/login \
    -H 'Content-Type: application/json' -d '{"username":"alice_test","password":"wrong-password"}'
done
```

### Expected Output (defended)

```
401  (x8)
429  ← "Too many authentication attempts; retry in five minutes"
```

### Actual Result

Before the fix (v0.7): all 1,000 attempts went through in 12.7 s (999 × 401, then 200 for the correct password).

After:
```
Status codes: {429: 993, 401: 7}. Correct password on attempt #1000 returned 429.
Different user (bob) logging in during alice's lockout -> 200.
```
(The test made 1 earlier failed login for alice, so 8 failures in total before the lockout.)

### Response

**Fixed.** Logins are limited to 8 attempts per account and 40 failed attempts per IP in 5 minutes (`check_login_limit()` in `backend/app/main.py`).

---

## Audit Scenario 2 — Password Storage

**Security property tested:** Accounts  
**Expected result:** Only Argon2id hashes are stored; no plaintext secrets in the database.

### Steps

`t_password_storage` (`[A-2]`) reads `users.password_hash` with sqlite3 and searches the raw database bytes for every test password and vault passphrase. By hand: `sqlite3 "$CIPHERDROP_DATA_DIR/cipherdrop.db" "select username, password_hash from users"`.

### Expected Output (defended)

Every hash starts with `$argon2id$`, salts are unique, and no secrets are found.

### Actual Result

```
4 users; all $argon2id$: True; unique salts: True; plaintext password/passphrase found in raw DB bytes for: none
(parameters: m=65536, t=3, p=4)
```

### Response

No change needed.

---

## Audit Scenario 3 — Stolen Session Token Hash

**Security property tested:** Sessions  
**Expected result:** A token hash copied from the database is useless as a cookie.

### Steps

`t_stolen_token` (`[S-1]`) logs in, reads `sessions.token_hash` from the database, and sends it as the `cipherdrop_session` cookie to `GET /api/auth/me`.

### Expected Output (defended)

```
real cookie -> 200; stolen hash -> 401
```

### Actual Result

```
real cookie -> 200; DB token_hash used as cookie -> 401; sha256(cookie)==stored hash: True; raw token in DB: False
```

### Response

No change needed.

---

## Audit Scenario 4 — Tampered Ciphertext

**Security property tested:** Encryption  
**Expected result:** AES-GCM rejects any modification.

### Steps

`t_tamper` (`[C-1]`) uploads a file, flips 1 byte in its `.enc` file on disk, downloads, and decrypts it like the browser. It then restores the file, flips 1 bit of the wrapped file key in the database, and tries again.

### Expected Output (defended)

```
integrity_error (cryptography.exceptions.InvalidTag) in both cases
```

### Actual Result

```
untampered -> ok; 1-byte flip in .enc -> integrity_error; 1-bit flip in wrapped DEK (DB) -> integrity_error
```

### Response

No change needed.

---

## Audit Scenario 5 — Swapped Files (Malicious Server)

**Security property tested:** Encryption  
**Expected result:** The app detects that one file's encrypted data was replaced with another's.

### Steps

`t_swap` (`[C-2]`) uploads two files for one user. In the database it (1) swaps only their stored ciphertext, then (2) swaps the ciphertext, IV, and wrapped key together, decrypting file A after each change.

### Expected Output (defended)

Both variants fail to decrypt.

### Actual Result

```
Variant 1 (swap ciphertext only) -> integrity_error.
Variant 2 (swap ciphertext + IV + wrapped DEK) -> decrypted with NO error:
file shown as 'Q3-salary-report.txt' but contents are b'Contents of file B: vacation notes'
```

### Response

**Accepted** (see Known Residual Risks). AES-GCM is used without associated data (AAD), so a ciphertext isn't tied to its file ID.

---

## Audit Scenario 6 — IDOR (Accessing Another User's Files)

**Security property tested:** Access control  
**Expected result:** Every cross-user request returns 404; the victim's data is unchanged.

### Steps

`t_idor` (`[R-1]`) logs in as mallory and calls download, replace, delete, list/create shares, list/create links, shared download, revoke share, and revoke session for IDs 1–40, including alice's. It compares SHA-256 hashes of alice's `.enc` files before and after.

### Expected Output (defended)

```
all endpoints -> [404]; Alice's files/shares unchanged: True
```

### Actual Result

```
322 requests ... {'GET blob': [404], 'PUT replace': [404], 'DELETE': [404], 'GET shares': [404], 'GET links': [404],
'POST link': [404], 'GET shared blob': [404], 'DELETE share': [404], 'DELETE alice session': [404]}.
Alice's files/shares unchanged: True
```

### Response

No change needed.

---

## Audit Scenario 7 — Reshare Privilege Escalation

**Security property tested:** Access control  
**Expected result:** A reshare can't exceed the parent share's permissions or expiration, and revocation cascades.

### Steps

`t_reshare` (`[R-2]`):
1. alice shares a file with bob **without** Reshare permission. bob tries to reshare it.
2. alice shares another file with bob with Reshare but **without** Download, expiring in 1 hour. bob reshares it to carol, asking for Download, Reshare, and no expiration.
3. alice revokes bob's share.

### Expected Output (defended)

The first reshare returns 404. carol's grant has no Download and is capped at bob's expiration. After revocation, carol loses access.

### Actual Result

```
(a) reshare without Reshare permission -> HTTP 404.
(b) ... -> HTTP 201; carol's grant: can_download=False, can_reshare=True, expiry capped to parent's: True;
    carol blob download -> 404; bob direct blob download (view-only bypass) -> 404.
(c) after alice revoked bob: carol download -> 404, carol still lists file: False
```

### Response

No change needed.

---

## Audit Scenario 8 — Download-Limit Race

**Security property tested:** Secure links  
**Expected result:** A 1-use link can be downloaded only once, even with simultaneous requests.

### Steps

`t_link_race` (`[L-1]`) creates a link with `max_downloads=1` and releases 50 download requests at the same moment (`threading.Barrier`).

### Expected Output (defended)

```
{200: 1, 404: 49}; download_count == 1
```

### Actual Result

```
responses: {200: 1, 404: 49}; download_count in DB: 1
```

### Response

No change needed.

---

## Audit Scenario 9 — Reusing a Dead Link

**Security property tested:** Secure links  
**Expected result:** Revoked, expired, used-up, and deleted-file links all stop working.

### Steps

`t_dead_links` (`[L-2]`) calls the public metadata and download endpoints after revoking a link, after a 3-second expiry passes, after a 1-use link is used, and after the file is deleted.

### Expected Output (defended)

```
(metadata 404, download 404) in all four cases
```

### Actual Result

```
revoked -> (404, 404); expired -> (404, 404); exhausted -> (404, 404); file deleted -> (404, 404)
```

### Response

No change needed.

---

## Audit Scenario 10 — Editing or Deleting Audit Entries

**Security property tested:** Audit log  
**Expected result:** Verify Chain detects edits and deletions.

### Steps

`t_audit_tamper` (`[G-1]`) uses the database: it edits one event's type, deletes one event, and (extra checks) deletes the newest 10 events, then rewrites an event while recomputing every HMAC using `audit_hmac.key`. It calls `GET /api/security/audit/verify` after each change (the same call as the **Verify chain** button) and restores the database in between.

### Expected Output (defended)

Edit and deletion → `valid: False` with the failing event's ID.

### Actual Result

```
edited event 19 -> {'valid': False, 'failed_event_id': 19}
deleted event 19 -> {'valid': False, 'failed_event_id': 20}
[extra] deleted last 10 rows -> {'valid': True}                       ← not detected
[extra] rewrote entry 19 and recomputed HMACs with the key file -> {'valid': True}   ← not detected
```

### Response

The main scenario needs no change. The two extra cases are **accepted** (see Known Residual Risks).

---

## Audit Scenario 11 — Missing Audit Events

**Security property tested:** Audit log  
**Expected result:** Failed logins and downloads are recorded.

### Steps

`t_missing_events` (`[G-2]`) does a failed login, an owner download, and a shared download, and counts new `audit_events` rows.

### Expected Output (defended)

Three new events.

### Actual Result

Before the fix: 0 new rows. After:
```
Audit rows before/after: 34/37; new events: ['SHARE_DOWNLOADED', 'FILE_DOWNLOADED', 'LOGIN_FAILED']
```

### Response

**Fixed.** `login()`, `download_blob()`, and `download_shared_blob()` now write audit events.

---

## Audit Scenario 12 — Expiration Date Without a Timezone (extra finding)

**Security property tested:** Access control / input handling  
**Expected result:** Bad input is rejected cleanly (4xx), not with a server error.

### Steps

`t_extra_naive_expiry` (`[X-1]`) creates a share and a link with `expires_at: "2030-01-01T00:00:00"` (no timezone).

### Expected Output (defended)

```
422 for both
```

### Actual Result

Before the fix: HTTP 500 (`TypeError: can't compare offset-naive and offset-aware datetimes`). After:
```
share -> HTTP 422; link -> HTTP 422
```

### Response

**Fixed.** `expires_at` must include a timezone (`timezone_required` validator).

---

## AI Red-Team Findings

### AI Tool Used

Claude (Anthropic), run inside the project folder so it could read the code and run tests on an isolated copy of the app. We had planned to cross-check with ChatGPT and Gemini, but used only Claude. Because the same tool generated and triaged the suggestions, and had already seen the code, the rounds weren't fully independent.

### Prompt Used

```
Round 1 (description only):
"You are a penetration tester. CipherDrop is a client-side-encrypted file vault with sharing,
secure links, sessions, passkeys, and an HMAC-chained audit log. [endpoint list] For each
security property, propose attacks. For each, give what the attacker needs, what they'd do,
and how we'd know it worked."

Round 2 (code review):
"Review backend/app/main.py for IDOR, race conditions, missing rate limits, info leaks, and
authorization gaps. Review frontend/src/main.tsx for crypto mistakes like reused IVs, weak key
derivation, or trusting server values. Cite specific lines."

Round 3 (attacker roles):
"Act as each attacker from our threat model: an outside attacker, a logged-in user, someone
with a leaked database backup, and a malicious server. What can each one actually get or change?"
```

Of 24 distinct candidates, 7 were confirmed, 6 duplicated our scenarios, 9 were already defended, and 2 were hallucinations (they target JWTs and password reset tokens, which CipherDrop doesn't have).

### Findings Summary

| # | Finding | Property | Tested | Result | Status |
|---|---|---|---|---|---|
| 1 | Global login lockout through a shared proxy IP | Accounts | Yes (RT-1) | Vulnerable | Fixed |
| 2 | X-Forwarded-For spoofing bypasses the IP limit | Accounts | Yes (RT-2) | Vulnerable | Fixed |
| 3 | Account password can equal the vault passphrase | Encryption | Yes (RT-9, manual) | Vulnerable | Fixed |
| 4 | Step-up bypass by revoking sessions one at a time | Sessions | Yes (RT-3) | Vulnerable | Fixed |
| 5 | Username enumeration (login timing, register error) | Accounts | Yes (RT-4) | Vulnerable | Accepted |
| 6 | Failed step-up attempts not audited | Audit log | Yes (RT-5) | Vulnerable | Fixed |
| 7 | Audit verify reveals system-wide event count | Audit log | Yes (RT-6) | Vulnerable | Fixed |
| 8 | CSRF on state-changing requests | Sessions | Yes (RT-7) | Defended | No change |
| 9 | Session fixation | Sessions | Yes (RT-8) | Defended | No change |
| 10 | Oversized upload metadata (DoS) | Availability | Yes (RT-10) | Defended | No change |
| 11 | SQL injection in usernames or IDs | Access control | Code review | Defended | No change |
| 12 | Path traversal through file names | Access control | Code review | Defended | No change |
| 13 | XSS through filenames or User-Agent | Sessions | Code review | Defended | No change |
| 14 | AES-GCM IV reuse | Encryption | Code review | Defended | No change |
| 15 | Link key leaking to the server | Secure links | Code review | Defended | No change |
| 16 | Passkey challenge replay | Accounts | Code review | Defended | No change |
| 17 | JWT algorithm confusion | Accounts | No | Hallucination | Discarded |
| 18 | Predictable password reset tokens | Accounts | No | Hallucination | Discarded |

### Reproducing the Red-Team Findings

All checks are in `redteam_tests.py` and run through the real Vite dev server, so they use `frontend/vite.config.ts`. A LAN client is simulated by sending the backend the exact `X-Forwarded-For` chain Vite produces with `xfwd: true`: `<whatever the client sent>,<real client IP>`. "Before" results were recorded on the merged v1.0 build before our fixes.

| ID | Steps | Before fixes | Actual result (submitted build) |
|---|---|---|---|
| RT-1 | 50 successful logins from one IP; an attacker IP sends 45 failed logins for fake users; then victims on localhost and on another IP log in | Victim with the correct password got 429 (everyone shared `127.0.0.1`) | `50 successful logins -> [200]. Attacker: 40x401 then 5x429. Victim on localhost -> 200; victim on another LAN IP -> 200.` |
| RT-2 | A LAN client sends a fake `X-Forwarded-For`; spray of 100 accounts with a new fake IP each | Fake IP recorded; spray never blocked | `session IP recorded as '10.0.0.88'` (the real one). Spray: `40x401, 60x429`. |
| RT-3 | Without step-up, revoke one of your other sessions; then step up and retry | 204 (bypass) | `revoke all others -> 403, revoke one other session -> 403. After step-up (200) -> 204.` |
| RT-4 | Time failed logins for real vs. fake usernames; register a taken name | Same | `real users 24.0 ms vs non-existent 4.2 ms`; register → `409 'Username is unavailable'` (accepted risk) |
| RT-5 | Wrong step-up password; count `STEP_UP_FAILED` events | 0 events | `STEP_UP_FAILED rows 0 -> 1; shown in the user's Activity log: True` |
| RT-6 | New user calls `GET /api/security/audit/verify` | `checked=195` (everyone's events) | `{'valid': True}` |
| RT-7 | `DELETE /api/files/{id}` without CSRF token / with `Origin: evil.example` / with `Sec-Fetch-Site: cross-site` | Defended | `403 / 403 / 403; file survived: True; legitimate DELETE -> 204` |
| RT-8 | Log in with a planted session cookie; log in again while holding a valid session | Defended | New random token issued; planted value → `401`; old token → `401` |
| RT-10 | Upload with a 5 MiB `encrypted_filename` | Defended | `400 "Part exceeded maximum size of 1024KB."` |

**RT-9 — manual check.** The server never sees the vault passphrase, so this check lives in the register form:
1. Start CipherDrop with `make run` and open `http://localhost:5173`.
2. Choose **Create account**.
3. Enter the same value for **Account password** and **Vault passphrase**.
4. **Expected:** the form refuses with "Your vault passphrase must be different from your account password…", and no account is created. Before the fix, the account was created.

---

## Known Residual Risks

| Risk | Severity | Justification for Accepting |
|---|---|---|
| Files can be swapped without detection (no AES-GCM AAD) — Scenario 5 | Low | Requires write access to both the database and file storage, meaning control of the server, which could already serve malicious JavaScript. Only works between one user's own files; no new content can be inserted without the vault key. We would add AAD before production. |
| Deleting the newest audit entries isn't detected; anyone with the HMAC key can rewrite the log — Scenario 10 | Low | Requires direct database access, plus the key file for rewriting: full host compromise, which a hash chain on one server can't prevent. External checkpoints are out of scope. |
| Username enumeration — RT-4 | Low | Username sign-up must say when a name is taken; the timing gap only confirms what register already shows. |
| Targeted account lockout (side effect of Scenario 1's fix) | Low | 8 wrong passwords block one account for 5 minutes. This is the normal tradeoff of per-account lockout and better than unlimited guessing. |
| IP spoofing by clients on the server machine itself — RT-2 | Low | Uvicorn trusts loopback as a proxy, so only someone already on the host can fake an IP. |
| Sequential IDs reveal rough system activity | Low | Event, file, and share IDs count up across users; no contents or names are exposed. |
