"""CipherDrop AI red-team checks (Milestone 3).

Reproduces the 7 confirmed red-team findings and the main "defended" checks against the
submitted code. Browser-like requests go through the real Vite dev server (frontend/vite.config.ts);
LAN clients are simulated by sending the backend the exact X-Forwarded-For chain that Vite
produces with xfwd:true ("<whatever the client sent>,<real client IP>").
Needs a backend with a THROWAWAY data folder. Reuses the crypto client from audit_tests.py.
Usage: python redteam_tests.py <vite_url> <backend_url> <data_dir> [results.json]
"""
import importlib.util, json, secrets, sqlite3, statistics, sys, time
from pathlib import Path

import httpx

VITE, DIRECT, DATA = sys.argv[1], sys.argv[2], Path(sys.argv[3])
OUT = Path(sys.argv[4]) if len(sys.argv) > 4 else DATA / "redteam_results.json"
HERE = Path(__file__).resolve().parent
sys.argv = [sys.argv[0], VITE, str(DATA)]
spec = importlib.util.spec_from_file_location("audit_tests", HERE / "audit_tests.py")
t = importlib.util.module_from_spec(spec); spec.loader.exec_module(t)

DB = DATA / "cipherdrop.db"
RESULTS = []
tag = secrets.token_hex(2)
_ip = iter(range(10, 250))


def fresh_ip():
    return f"198.51.100.{next(_ip)}"


def record(rid, name, verdict, observed):
    RESULTS.append(dict(id=rid, name=name, verdict=verdict, observed=observed))
    print(f"\n[{rid}] {name} -> {verdict}\n  {observed}")


def make_user(name, ip=None, password=None, vault=None):
    u = t.User(f"{name}_{tag}", password or f"{name.title()}-Correct-Pw-2026", vault or f"{name} vault passphrase 42")
    if ip:
        u.c.headers["X-Forwarded-For"] = ip
    return u.register()


def login(base, username, password, xff=None, cookies=None):
    return httpx.post(base + "/api/auth/login", json={"username": username, "password": password},
                      headers={"X-Forwarded-For": xff} if xff else {}, cookies=cookies, timeout=60)


def current_session_ip(cookies):
    return next(s["ip_address"] for s in httpx.get(DIRECT + "/api/security/sessions", cookies=cookies).json() if s["current"])


def audit_rows(event=None):
    with sqlite3.connect(DB) as con:
        if event:
            return con.execute("select count(*) from audit_events where event_type=?", (event,)).fetchone()[0]
        return con.execute("select count(*) from audit_events").fetchone()[0]


# RT-1: one shared IP must not lock out every user
def rt1_shared_ip_lockout():
    victim = make_user("victim")
    ok = [login(VITE, victim.name, victim.password).status_code for _ in range(50)]
    attacker = [login(DIRECT, f"nobody{i}_{tag}", "wrong-password-123", xff=f"203.0.113.{i},10.0.0.66").status_code for i in range(45)]
    local_victim = login(VITE, victim.name, victim.password).status_code
    lan_victim = login(DIRECT, victim.name, victim.password, xff="10.0.0.77").status_code
    defended = all(c == 200 for c in ok) and 429 in attacker and local_victim == 200 and lan_victim == 200
    record("RT-1", "Global login lockout through a shared IP", "DEFENDED" if defended else "VULNERABLE",
           f"50 successful logins from one IP -> {sorted(set(ok))}. Attacker at 10.0.0.66, 45 failed logins for fake users: "
           f"{attacker.count(401)}x401 then {attacker.count(429)}x429. Victim on localhost -> {local_victim}; victim on another LAN IP -> {lan_victim}.")


# RT-2: a client-supplied X-Forwarded-For must not change the recorded IP
def rt2_xff_spoofing():
    victim = make_user("spoofvictim", ip=fresh_ip())
    r = login(DIRECT, victim.name, victim.password, xff="203.0.113.50,10.0.0.88")
    shown = current_session_ip(r.cookies)
    spray = [login(DIRECT, f"spray{i}_{tag}", "Password123!", xff=f"198.51.100.{i},10.0.0.99").status_code for i in range(100)]
    local = login(VITE, victim.name, victim.password, xff="203.0.113.51")
    local_shown = current_session_ip(local.cookies)
    defended = shown == "10.0.0.88" and 429 in spray
    record("RT-2", "X-Forwarded-For spoofing", "DEFENDED" if defended else "VULNERABLE",
           f"LAN client 10.0.0.88 sending a fake 'X-Forwarded-For: 203.0.113.50' -> session IP recorded as '{shown}'. "
           f"Spray of 100 accounts from one LAN IP, new fake IP each: {spray.count(401)}x401, {spray.count(429)}x429. "
           f"[Known limit] A client on the server machine itself can still spoof: session shows '{local_shown}'.")


# RT-3: revoking other sessions must require step-up
def rt3_stepup_bypass():
    alice = make_user("alice", ip=fresh_ip())
    for i in range(2):
        assert login(VITE, alice.name, alice.password, xff=f"10.0.1.{i}").status_code == 200
    others = [s for s in alice.c.get("/api/security/sessions").json() if not s["current"]]
    bulk = alice.c.post("/api/security/sessions/revoke-others").status_code
    single = alice.c.delete(f"/api/security/sessions/{others[0]['id']}").status_code
    step = alice.c.post("/api/security/step-up", json={"password": alice.password}).status_code
    after = alice.c.delete(f"/api/security/sessions/{others[0]['id']}").status_code
    defended = bulk == 403 and single == 403 and after == 204
    record("RT-3", "Step-up bypass by revoking sessions one at a time", "DEFENDED" if defended else "VULNERABLE",
           f"Without step-up: revoke all others -> {bulk}, revoke one other session -> {single}. After step-up ({step}) -> {after}.")


# RT-4: username enumeration (ACCEPTED RISK: expected to still show)
def rt4_enumeration():
    real = [make_user(f"timing{i}", ip=fresh_ip()) for i in range(3)]
    exist, missing = [], []
    for u in real:
        for _ in range(7):  # stay under the 8-per-account limit
            s = time.perf_counter(); login(DIRECT, u.name, "wrong-password-123", xff=fresh_ip()); exist.append(time.perf_counter() - s)
    for i in range(21):
        s = time.perf_counter(); login(DIRECT, f"ghost{i}_{tag}", "wrong-password-123", xff=fresh_ip()); missing.append(time.perf_counter() - s)
    me, mm = statistics.median(exist) * 1000, statistics.median(missing) * 1000
    dup = httpx.post(DIRECT + "/api/auth/register", headers={"X-Forwarded-For": fresh_ip()}, json=dict(
        username=real[0].name, password="Another-Pw-2026", vault_salt="x", vault_wrap_iv="x", wrapped_vault_key="x", kdf_iterations=600000))
    record("RT-4", "Username enumeration (accepted risk)", "VULNERABLE" if me > 3 * mm or dup.status_code == 409 else "DEFENDED",
           f"Median failed login: real users {me:.1f} ms vs non-existent {mm:.1f} ms (21 samples each). "
           f"Register with a taken username -> {dup.status_code} {dup.json().get('detail')!r}.")


# RT-5: failed step-up must be audited
def rt5_stepup_audit():
    bob = make_user("bob", ip=fresh_ip())
    before = audit_rows("STEP_UP_FAILED")
    code = bob.c.post("/api/security/step-up", json={"password": "not-my-password"}).status_code
    after = audit_rows("STEP_UP_FAILED")
    shown = any(e["event_type"] == "STEP_UP_FAILED" for e in bob.c.get("/api/security/activity").json())
    record("RT-5", "Failed step-up attempts audited", "DEFENDED" if after == before + 1 and shown else "VULNERABLE",
           f"Wrong step-up password -> {code}; STEP_UP_FAILED rows {before} -> {after}; shown in the user's Activity log: {shown}.")


# RT-6: audit verify must not reveal the system-wide event count
def rt6_audit_count():
    mallory = make_user("mallory", ip=fresh_ip())
    v = mallory.c.get("/api/security/audit/verify").json()
    record("RT-6", "Audit verify reveals system-wide event count", "DEFENDED" if "checked" not in v and v.get("valid") else "VULNERABLE",
           f"New user calls /api/security/audit/verify -> {v} (system holds {audit_rows()} events).")


# RT-7: CSRF protection
def rt7_csrf():
    carol = make_user("carol", ip=fresh_ip())
    fid = carol.upload("csrf.txt", b"csrf test")
    token = carol.c.headers["X-CSRF-Token"]
    no_token = httpx.delete(f"{VITE}/api/files/{fid}", cookies=carol.c.cookies).status_code
    evil = httpx.delete(f"{VITE}/api/files/{fid}", cookies=carol.c.cookies, headers={"Origin": "http://evil.example", "X-CSRF-Token": token}).status_code
    cross = httpx.delete(f"{VITE}/api/files/{fid}", cookies=carol.c.cookies, headers={"Sec-Fetch-Site": "cross-site", "X-CSRF-Token": token}).status_code
    survived = any(f["id"] == fid for f in carol.c.get("/api/files").json())
    legit = carol.c.delete(f"/api/files/{fid}").status_code
    record("RT-7", "CSRF on state-changing requests", "DEFENDED" if no_token == evil == cross == 403 and survived and legit == 204 else "VULNERABLE",
           f"DELETE without X-CSRF-Token -> {no_token}; Origin: evil.example -> {evil}; Sec-Fetch-Site: cross-site -> {cross}; "
           f"file survived: {survived}; legitimate DELETE -> {legit}.")


# RT-8: session fixation
def rt8_fixation():
    dave = make_user("dave", ip=fresh_ip())
    planted = "attacker-chosen-session-value"
    r = login(VITE, dave.name, dave.password, xff=fresh_ip(), cookies={"cipherdrop_session": planted})
    issued = r.cookies.get("cipherdrop_session")
    planted_code = httpx.get(VITE + "/api/auth/me", cookies={"cipherdrop_session": planted}).status_code
    old = dave.c.cookies.get("cipherdrop_session")
    login(VITE, dave.name, dave.password, xff=fresh_ip(), cookies={"cipherdrop_session": old})
    old_code = httpx.get(VITE + "/api/auth/me", cookies={"cipherdrop_session": old}).status_code
    record("RT-8", "Session fixation", "DEFENDED" if issued and issued != planted and planted_code == 401 and old_code == 401 else "VULNERABLE",
           f"Login with a planted cookie issued a new random token: {issued != planted}; planted value -> {planted_code}. "
           f"Logging in again while holding a valid session -> old token -> {old_code}.")


# RT-9: password == vault passphrase (frontend-only check: verify by hand in the browser)
def rt9_same_secret():
    record("RT-9", "Account password equal to vault passphrase", "MANUAL",
           "The server never sees the vault passphrase, so this check lives in the register form and can't be tested "
           "over the API. Open http://localhost:5173, choose Create account, and enter the same value for "
           "'Account password' and 'Vault passphrase'. Expected: the form refuses with 'Your vault passphrase must be "
           "different from your account password...'")


# RT-10: oversized upload metadata
def rt10_metadata():
    erin = make_user("erin", ip=fresh_ip())
    c = httpx.Client(base_url=DIRECT, cookies=erin.c.cookies, headers=erin.c.headers, timeout=60)
    meta = dict(filename_iv="x" * 12, file_iv="x" * 12, wrapped_dek="x" * 20, dek_wrap_iv="x" * 12)
    big = c.post("/api/files", files={"blob": ("b", b"x")}, data=meta | {"encrypted_filename": "A" * (5 * 1024 * 1024)})
    record("RT-10", "Oversized upload metadata (DoS)", "DEFENDED" if big.status_code in (400, 413, 422) else "VULNERABLE",
           f"Upload with a 5 MiB encrypted_filename -> {big.status_code} {big.text[:60]!r}")


if __name__ == "__main__":
    for test in (rt1_shared_ip_lockout, rt2_xff_spoofing, rt3_stepup_bypass, rt4_enumeration, rt5_stepup_audit,
                 rt6_audit_count, rt7_csrf, rt8_fixation, rt9_same_secret, rt10_metadata):
        test()
    OUT.write_text(json.dumps(RESULTS, indent=2))
    print(f"\nSaved {len(RESULTS)} results to {OUT}")
