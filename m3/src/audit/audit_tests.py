"""CipherDrop attack-scenario audit (Milestone 3).

Runs the threat scenarios from our audit plan against a CipherDrop backend that uses a
THROWAWAY data folder (CIPHERDROP_DATA_DIR). The client mimics the browser's Web Crypto
flow (PBKDF2 -> AES-256-GCM vault key, per-file DEKs, ECDH + HKDF sharing) and edits the
database directly for the tamper tests, so never point it at real data.
Usage: python audit_tests.py <backend_url> <data_dir>   (run_audit.sh does this for you)
"""
import base64, hashlib, json, os, secrets, shutil, sqlite3, sys, threading, time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

BASE = sys.argv[1]
DATA = Path(sys.argv[2])
DB = DATA / "cipherdrop.db"
STORE = DATA / "encrypted"
RESULTS = []

b64 = lambda b: base64.b64encode(b).decode()
unb64 = base64.b64decode
b64u = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
unb64u = lambda s: base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
iso = lambda dt: dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
now = lambda: datetime.now(timezone.utc)


def record(sid, prop, name, expected, observed, verdict, evidence):
    RESULTS.append(dict(id=sid, property=prop, scenario=name, expected=expected,
                        observed=observed, verdict=verdict, evidence=evidence))
    print(f"\n[{sid}] {name} -> {verdict}\n  observed: {observed}")
    for line in evidence:
        print("   ", line)


def db():
    return sqlite3.connect(DB)


# ---------- client-side crypto, mirroring frontend/src/main.tsx ----------
def gcm_enc(key, data):
    iv = os.urandom(12)
    return AESGCM(key).encrypt(iv, data, None), iv


def gcm_dec(key, iv, data):
    return AESGCM(key).decrypt(iv, data, None)


def derive_kek(passphrase, salt, iterations):
    return PBKDF2HMAC(hashes.SHA256(), 32, salt, iterations).derive(passphrase.encode())


def ec_pub_jwk(pub):
    n = pub.public_numbers()
    return {"kty": "EC", "crv": "P-256", "x": b64u(n.x.to_bytes(32, "big")), "y": b64u(n.y.to_bytes(32, "big")), "ext": True}


def ec_pub_from_jwk(text):
    j = json.loads(text)
    return ec.EllipticCurvePublicNumbers(int.from_bytes(unb64u(j["x"]), "big"),
                                         int.from_bytes(unb64u(j["y"]), "big"), ec.SECP256R1()).public_key()


def share_key(priv, pub, salt):
    secret = priv.exchange(ec.ECDH(), pub)
    return HKDF(hashes.SHA256(), 32, salt, b"CipherDrop file share v1").derive(secret)


class User:
    def __init__(self, name, password, vault):
        self.name, self.password, self.vault = name, password, vault
        self.c = httpx.Client(base_url=BASE, timeout=60)
        self.vault_key = None
        self.priv = None

    def register(self):
        salt, iters = os.urandom(16), 600000
        kek = derive_kek(self.vault, salt, iters)
        self.vault_key = os.urandom(32)
        wrapped, iv = gcm_enc(kek, self.vault_key)
        r = self.c.post("/api/auth/register", json=dict(username=self.name, password=self.password,
                        vault_salt=b64(salt), vault_wrap_iv=b64(iv), wrapped_vault_key=b64(wrapped), kdf_iterations=iters))
        assert r.status_code == 201, r.text
        self.load_csrf()
        self.priv = ec.generate_private_key(ec.SECP256R1())
        priv_jwk = ec_pub_jwk(self.priv.public_key()) | {"d": b64u(self.priv.private_numbers().private_value.to_bytes(32, "big"))}
        enc_priv, piv = gcm_enc(self.vault_key, json.dumps(priv_jwk).encode())
        r = self.c.post("/api/sharing/profile", json=dict(public_key_jwk=json.dumps(ec_pub_jwk(self.priv.public_key())),
                        encrypted_private_key=b64(enc_priv), private_key_iv=b64(piv)))
        assert r.status_code == 201, r.text
        return self

    def load_csrf(self):
        # v1.0 requires a session-bound X-CSRF-Token on state-changing requests (as the frontend sends).
        r = self.c.get("/api/auth/csrf")
        if r.status_code == 200:
            self.c.headers["X-CSRF-Token"] = r.json()["token"]

    def upload(self, filename, content):
        dek = os.urandom(32)
        ct, fiv = gcm_enc(dek, content)
        wdek, wiv = gcm_enc(self.vault_key, dek)
        ename, niv = gcm_enc(self.vault_key, filename.encode())
        r = self.c.post("/api/files", files={"blob": ("blob", ct)}, data=dict(encrypted_filename=b64(ename),
                        filename_iv=b64(niv), file_iv=b64(fiv), wrapped_dek=b64(wdek), dek_wrap_iv=b64(wiv)))
        assert r.status_code == 201, r.text
        return r.json()["id"]

    def file_row(self, fid):
        return next(f for f in self.c.get("/api/files").json() if f["id"] == fid)

    def download_and_decrypt(self, fid):
        """Exactly what the browser does: fetch row + blob, unwrap DEK, decrypt name and contents."""
        row = self.file_row(fid)
        r = self.c.get(f"/api/files/{fid}/blob")
        if r.status_code != 200:
            return ("http", r.status_code)
        try:
            dek = gcm_dec(self.vault_key, unb64(row["dek_wrap_iv"]), unb64(row["wrapped_dek"]))
            name = gcm_dec(self.vault_key, unb64(row["filename_iv"]), unb64(row["encrypted_filename"])).decode()
            plain = gcm_dec(dek, unb64(row["file_iv"]), r.content)
            return ("ok", name, plain)
        except InvalidTag:
            return ("integrity_error",)

    def build_share(self, fid, recipient):
        row = self.file_row(fid)
        dek = gcm_dec(self.vault_key, unb64(row["dek_wrap_iv"]), unb64(row["wrapped_dek"]))
        name = gcm_dec(self.vault_key, unb64(row["filename_iv"]), unb64(row["encrypted_filename"]))
        pub = ec_pub_from_jwk(self.c.get(f"/api/users/{recipient}/public-key").json()["public_key_jwk"])
        salt = os.urandom(32)
        k = share_key(self.priv, pub, salt)
        wdek, wiv = gcm_enc(k, dek)
        ename, niv = gcm_enc(k, name)
        return dict(recipient_username=recipient, wrapped_dek=b64(wdek), dek_wrap_iv=b64(wiv),
                    encrypted_filename=b64(ename), filename_iv=b64(niv), hkdf_salt=b64(salt))

    def build_reshare(self, share_row, recipient):
        k_in = share_key(self.priv, ec_pub_from_jwk(share_row["sender_public_key_jwk"]), unb64(share_row["hkdf_salt"]))
        dek = gcm_dec(k_in, unb64(share_row["dek_wrap_iv"]), unb64(share_row["wrapped_dek"]))
        name = gcm_dec(k_in, unb64(share_row["filename_iv"]), unb64(share_row["encrypted_filename"]))
        pub = ec_pub_from_jwk(self.c.get(f"/api/users/{recipient}/public-key").json()["public_key_jwk"])
        salt = os.urandom(32)
        k = share_key(self.priv, pub, salt)
        wdek, wiv = gcm_enc(k, dek)
        ename, niv = gcm_enc(k, name)
        return dict(recipient_username=recipient, wrapped_dek=b64(wdek), dek_wrap_iv=b64(wiv),
                    encrypted_filename=b64(ename), filename_iv=b64(niv), hkdf_salt=b64(salt))

    def make_link(self, fid, max_downloads=1, expires_at=None):
        row = self.file_row(fid)
        dek = gcm_dec(self.vault_key, unb64(row["dek_wrap_iv"]), unb64(row["wrapped_dek"]))
        name = gcm_dec(self.vault_key, unb64(row["filename_iv"]), unb64(row["encrypted_filename"]))
        link_key = os.urandom(32)
        wdek, wiv = gcm_enc(link_key, dek)
        ename, niv = gcm_enc(link_key, name)
        r = self.c.post(f"/api/files/{fid}/links", json=dict(wrapped_dek=b64(wdek), dek_wrap_iv=b64(wiv),
                        encrypted_filename=b64(ename), filename_iv=b64(niv), max_downloads=max_downloads, expires_at=expires_at))
        return r


def snapshot_db(tag):
    # Use SQLite's backup API (not a raw file copy) so the running server's page cache is invalidated correctly.
    dst = DATA.parent / f"db_backup_{tag}.db"
    with db() as src, sqlite3.connect(dst) as out:
        src.backup(out)
    return dst


def restore_db(src):
    with sqlite3.connect(src) as backup, db() as live:
        backup.backup(live)


# ============================== scenarios ==============================
def t_bruteforce(alice, bob):
    guesses = [f"wrongguess{i:04d}" for i in range(999)] + [alice.password]
    codes, lock = {}, threading.Lock()
    def attempt(pw):
        r = httpx.post(BASE + "/api/auth/login", json={"username": alice.name, "password": pw}, timeout=60)
        with lock:
            codes[r.status_code] = codes.get(r.status_code, 0) + 1
        return r.status_code
    t0 = time.time()
    with ThreadPoolExecutor(10) as ex:
        statuses = list(ex.map(attempt, guesses))
    dt = time.time() - t0
    blocked = codes.get(429, 0) + codes.get(423, 0)
    last = statuses[-1]
    other_user = httpx.post(BASE + "/api/auth/login", json={"username": bob.name, "password": bob.password}).status_code
    record("A-1", "Accounts", "Brute-force login (1,000 rapid attempts)",
           "Rate limiting / lockout (HTTP 429) kicks in",
           f"{len(guesses)} attempts in {dt:.1f}s ({len(guesses)/dt:.1f}/s, 10 threads). Status codes: {codes}. "
           f"Correct password on attempt #1000 returned {last}. "
           f"Different user (bob) logging in during alice's lockout -> {other_user}.",
           "VULNERABLE" if blocked == 0 else "DEFENDED",
           [f"status code histogram: {codes}", f"attempt #1000 (correct password) -> HTTP {last}"])


def t_password_storage(users):
    con = db()
    rows = con.execute("select username, password_hash from users").fetchall()
    con.close()
    all_argon2id = all(h.startswith("$argon2id$") for _, h in rows)
    salts = [h.split("$")[4] for _, h in rows]
    raw = DB.read_bytes()
    leaked = [u.name for u in users if u.password.encode() in raw or u.vault.encode() in raw]
    record("A-2", "Accounts", "Password storage",
           "Every password is an Argon2id hash; no plaintext passwords in DB",
           f"{len(rows)} users; all $argon2id$: {all_argon2id}; unique salts: {len(set(salts)) == len(salts)}; "
           f"plaintext password/passphrase found in raw DB bytes for: {leaked or 'none'}",
           "DEFENDED" if all_argon2id and not leaked else "VULNERABLE",
           [f"{u}: {h[:40]}..." for u, h in rows[:2]] + ["param string: " + rows[0][1].split("$")[3]])


def t_stolen_token(alice):
    c = httpx.Client(base_url=BASE)
    c.post("/api/auth/login", json={"username": alice.name, "password": alice.password})
    raw = c.cookies.get("cipherdrop_session")
    con = db()
    stored = con.execute("select token_hash from sessions order by id desc limit 1").fetchone()[0]
    con.close()
    real = c.get("/api/auth/me").status_code
    forged = httpx.get(BASE + "/api/auth/me", cookies={"cipherdrop_session": stored}).status_code
    record("S-1", "Sessions", "Stolen token hash replayed as cookie",
           "Hash from DB is useless as a cookie (401)",
           f"real cookie -> {real}; DB token_hash used as cookie -> {forged}; "
           f"sha256(cookie)==stored hash: {hashlib.sha256(raw.encode()).hexdigest() == stored}; raw token in DB: {raw.encode() in DB.read_bytes()}",
           "DEFENDED" if forged == 401 and real == 200 else "VULNERABLE",
           [f"GET /api/auth/me with stolen hash -> HTTP {forged}"])


def t_tamper(alice):
    fid = alice.upload("tamper-test.txt", b"CANARY-7f3a9c original contents")
    base = alice.download_and_decrypt(fid)
    con = db()
    obj = con.execute("select object_name from files where id=?", (fid,)).fetchone()[0]
    con.close()
    p = STORE / obj
    data = bytearray(p.read_bytes()); orig = bytes(data)
    data[5] ^= 0x01; p.write_bytes(bytes(data))
    flipped = alice.download_and_decrypt(fid)
    p.write_bytes(orig)
    bk = snapshot_db("tamper")
    con = db()
    w = bytearray(unb64(con.execute("select wrapped_dek from files where id=?", (fid,)).fetchone()[0])); w[0] ^= 0x01
    con.execute("update files set wrapped_dek=? where id=?", (b64(bytes(w)), fid)); con.commit(); con.close()
    wdek = alice.download_and_decrypt(fid)
    restore_db(bk)
    ok = base[0] == "ok" and flipped == ("integrity_error",) and wdek == ("integrity_error",)
    record("C-1", "Encryption", "Tampered ciphertext (1 byte flipped in .enc file)",
           "AES-GCM tag check fails; download rejected with integrity error",
           f"untampered -> {base[0]}; 1-byte flip in .enc -> {flipped[0]}; 1-bit flip in wrapped DEK (DB) -> {wdek[0]}",
           "DEFENDED" if ok else "VULNERABLE",
           [f"file {fid} object {obj}, flipped byte offset 5", "decrypt raised cryptography.exceptions.InvalidTag" if ok else ""])


def t_swap(alice):
    a = alice.upload("Q3-salary-report.txt", b"Contents of file A: salaries")
    b = alice.upload("vacation-photo-notes.txt", b"Contents of file B: vacation notes")
    bk = snapshot_db("swap")
    con = db()
    cols = "object_name, file_iv, wrapped_dek, dek_wrap_iv"
    ra = con.execute(f"select {cols} from files where id=?", (a,)).fetchone()
    rb = con.execute(f"select {cols} from files where id=?", (b,)).fetchone()
    # Variant 1: swap only the stored ciphertext object.
    con.execute("update files set object_name='tmpswap' where id=?", (a,))
    con.execute("update files set object_name=? where id=?", (ra[0], b))
    con.execute("update files set object_name=? where id=?", (rb[0], a)); con.commit()
    v1 = alice.download_and_decrypt(a)
    restore_db(bk)
    # Variant 2: swap the whole crypto tuple (ciphertext + IV + wrapped DEK), leave the encrypted filename.
    con = db()
    con.execute("update files set object_name='tmpswap' where id=?", (a,))
    con.execute(f"update files set object_name=?, file_iv=?, wrapped_dek=?, dek_wrap_iv=? where id=?", (*ra, b))
    con.execute(f"update files set object_name=?, file_iv=?, wrapped_dek=?, dek_wrap_iv=? where id=?", (*rb, a)); con.commit(); con.close()
    v2 = alice.download_and_decrypt(a)
    restore_db(bk)
    silent = v2[0] == "ok"
    record("C-2", "Encryption", "Swapped files (malicious server / DB write access)",
           "App detects that file A's ciphertext was replaced",
           f"Variant 1 (swap ciphertext only) -> {v1[0]}. "
           + (f"Variant 2 (swap ciphertext + IV + wrapped DEK) -> decrypted with NO error: file shown as '{v2[1]}' but contents are {v2[2]!r}"
              if silent else f"Variant 2 -> {v2[0]}"),
           "VULNERABLE" if silent else "DEFENDED",
           ["ciphertext-only swap fails because each file has its own DEK",
            "full-tuple swap succeeds because AES-GCM is used with no AAD binding ciphertext/DEK to file ID or filename"])


def t_idor(alice, mallory, bob):
    fids = [alice.upload(f"private-{i}.txt", f"alice secret {i}".encode()) for i in range(3)]
    sid = alice.c.post(f"/api/files/{fids[0]}/shares", json=alice.build_share(fids[0], bob.name)).json()["id"]
    con = db()
    before = {r[0]: hashlib.sha256((STORE / r[1]).read_bytes()).hexdigest() for r in con.execute("select id, object_name from files where owner_id=(select id from users where username=?)", (alice.name,))}
    alice_sessions = [r[0] for r in con.execute("select id from sessions where user_id=(select id from users where username=?)", (alice.name,))]
    con.close()
    fake = dict(encrypted_filename="x" * 20, filename_iv="x" * 12, file_iv="x" * 12, wrapped_dek="x" * 20, dek_wrap_iv="x" * 12)
    results = {}
    def hit(label, resp):
        results.setdefault(label, []).append(resp.status_code)
    for fid in range(1, 41):
        hit("GET blob", mallory.c.get(f"/api/files/{fid}/blob"))
        hit("PUT replace", mallory.c.put(f"/api/files/{fid}", files={"blob": ("b", b"evil")}, data=fake))
        hit("DELETE", mallory.c.delete(f"/api/files/{fid}"))
        hit("GET shares", mallory.c.get(f"/api/files/{fid}/shares"))
        hit("GET links", mallory.c.get(f"/api/files/{fid}/links"))
        hit("POST link", mallory.c.post(f"/api/files/{fid}/links", json=dict(wrapped_dek="x" * 20, dek_wrap_iv="x" * 12, encrypted_filename="x", filename_iv="x" * 12, max_downloads=5)))
    for s in range(1, 41):
        hit("GET shared blob", mallory.c.get(f"/api/shared/{s}/blob"))
        hit("DELETE share", mallory.c.delete(f"/api/files/{fids[0]}/shares/{s}"))
    for s in alice_sessions:
        hit("DELETE alice session", mallory.c.delete(f"/api/security/sessions/{s}"))
    con = db()
    after = {r[0]: hashlib.sha256((STORE / r[1]).read_bytes()).hexdigest() for r in con.execute("select id, object_name from files where owner_id=(select id from users where username=?)", (alice.name,))}
    share_alive = con.execute("select count(*) from file_shares where id=?", (sid,)).fetchone()[0]
    con.close()
    summary = {k: sorted(set(v)) for k, v in results.items()}
    non404 = {k: v for k, v in summary.items() if v != [404]}
    unchanged = before == after and share_alive == 1
    total = sum(len(v) for v in results.values())
    record("R-1", "Access Control", "IDOR: accessing another user's files by ID",
           "Every cross-user request returns 404; victim's data unchanged",
           f"{total} requests from mallory across file IDs 1-40, share IDs 1-40 and alice's session IDs. "
           f"Distinct status codes per endpoint: {summary}. Alice's files/shares unchanged: {unchanged}",
           "DEFENDED" if not non404 and unchanged else "VULNERABLE",
           [f"non-404 responses: {non404 or 'none'}", f"alice .enc SHA-256 before == after: {before == after}"])


def t_reshare(alice, bob, carol):
    # (a) bob has View+Download but no Reshare
    f1 = alice.upload("no-reshare.txt", b"file 1")
    alice.c.post(f"/api/files/{f1}/shares", json=alice.build_share(f1, bob.name) | dict(can_view=True, can_download=True, can_reshare=False))
    s1 = next(s for s in bob.c.get("/api/shared").json() if s["file_id"] == f1)
    ra = bob.c.post(f"/api/shared/{s1['id']}/reshare", json=bob.build_reshare(s1, carol.name) | dict(can_view=True, can_download=True, can_reshare=True))
    # (b) bob has Reshare but NOT Download, 1h expiry; asks for download+reshare+no expiry for carol
    f2 = alice.upload("view-and-reshare-only.txt", b"file 2")
    parent_exp = now() + timedelta(hours=1)
    alice.c.post(f"/api/files/{f2}/shares", json=alice.build_share(f2, bob.name) | dict(can_view=True, can_download=False, can_reshare=True, expires_at=iso(parent_exp)))
    s2 = next(s for s in bob.c.get("/api/shared").json() if s["file_id"] == f2)
    bob_dl = bob.c.get(f"/api/shared/{s2['id']}/blob").status_code
    rb = bob.c.post(f"/api/shared/{s2['id']}/reshare", json=bob.build_reshare(s2, carol.name) | dict(can_view=True, can_download=True, can_reshare=True, expires_at=None))
    child = next(s for s in carol.c.get("/api/shared").json() if s["file_id"] == f2)
    carol_dl = carol.c.get(f"/api/shared/{child['id']}/blob").status_code
    child_exp = datetime.fromisoformat(str(child["expires_at"]).replace("Z", "+00:00"))
    if child_exp.tzinfo is None:
        child_exp = child_exp.replace(tzinfo=timezone.utc)
    capped = abs((child_exp - parent_exp).total_seconds()) < 2
    # (c) recursive revocation: alice revokes bob -> carol's grant must disappear
    alice.c.delete(f"/api/files/{f2}/shares/{s2['id']}")
    carol_after = carol.c.get(f"/api/shared/{child['id']}/blob").status_code
    carol_listed = any(s["file_id"] == f2 for s in carol.c.get("/api/shared").json())
    ok = ra.status_code == 404 and rb.status_code == 201 and not child["can_download"] and capped and carol_dl == 404 and bob_dl == 404 and carol_after == 404 and not carol_listed
    record("R-2", "Access Control", "Reshare privilege escalation",
           "Reshare blocked without Reshare permission; child grant can't exceed parent's permissions or expiry",
           f"(a) reshare without Reshare permission -> HTTP {ra.status_code}. "
           f"(b) bob (no Download) reshared asking for Download+Reshare+no-expiry -> HTTP {rb.status_code}; carol's grant: "
           f"can_download={child['can_download']}, can_reshare={child['can_reshare']}, expiry capped to parent's: {capped}; "
           f"carol blob download -> {carol_dl}; bob direct blob download (view-only bypass) -> {bob_dl}. "
           f"(c) after alice revoked bob: carol download -> {carol_after}, carol still lists file: {carol_listed}",
           "DEFENDED" if ok else "VULNERABLE",
           ["requested can_download=true was downgraded to false", "requested expires_at=null was capped to parent expiry"])


def t_link_race(alice):
    fid = alice.upload("race.txt", b"race contents")
    token = alice.make_link(fid, max_downloads=1).json()["token"]
    barrier = threading.Barrier(50)
    def go(_):
        barrier.wait()
        return httpx.post(f"{BASE}/api/public/links/{token}/download", timeout=60).status_code
    with ThreadPoolExecutor(50) as ex:
        codes = list(ex.map(go, range(50)))
    con = db()
    count = con.execute("select download_count from secure_links where token_hash=?", (hashlib.sha256(token.encode()).hexdigest(),)).fetchone()[0]
    con.close()
    hist = {c: codes.count(c) for c in set(codes)}
    record("L-1", "Secure Links", "Download-limit race (50 simultaneous downloads, limit 1)",
           "Exactly 1 request succeeds; download_count == 1",
           f"responses: {hist}; download_count in DB: {count}",
           "DEFENDED" if hist.get(200) == 1 and count == 1 else "VULNERABLE",
           ["50 threads released together with a threading.Barrier"])


def t_dead_links(alice):
    out = {}
    def probe(tok):
        return (httpx.get(f"{BASE}/api/public/links/{tok}").status_code,
                httpx.post(f"{BASE}/api/public/links/{tok}/download").status_code)
    fid = alice.upload("dead-links.txt", b"dead link contents")
    r = alice.make_link(fid, max_downloads=5).json()
    before = probe(r["token"])  # note: this consumes one download
    alice.c.delete(f"/api/files/{fid}/links/{r['id']}")
    out["revoked"] = probe(r["token"])
    tok = alice.make_link(fid, max_downloads=5, expires_at=iso(now() + timedelta(seconds=3))).json()["token"]
    pre_exp = httpx.get(f"{BASE}/api/public/links/{tok}").status_code
    time.sleep(4)
    out["expired"] = probe(tok)
    tok = alice.make_link(fid, max_downloads=1).json()["token"]
    first = httpx.post(f"{BASE}/api/public/links/{tok}/download").status_code
    out["exhausted"] = probe(tok)
    tok = alice.make_link(fid, max_downloads=5).json()["token"]
    alice.c.delete(f"/api/files/{fid}")
    out["file deleted"] = probe(tok)
    dead = all(v == (404, 404) for v in out.values())
    record("L-2", "Secure Links", "Reusing a dead link (revoked / expired / exhausted)",
           "All three return 404 on metadata and download",
           f"live link before revoke -> {before}; before-expiry metadata -> {pre_exp}; first download of 1-use link -> {first}; "
           f"after: " + "; ".join(f"{k} -> (metadata {v[0]}, download {v[1]})" for k, v in out.items()),
           "DEFENDED" if dead else "VULNERABLE", [])


def t_audit_tamper(alice):
    verify = lambda: alice.c.get("/api/security/audit/verify").json()
    base = verify()
    con = db()
    ids = [r[0] for r in con.execute("select id from audit_events order by id")]
    mid = ids[len(ids) // 2]
    con.close()
    bk = snapshot_db("audit")
    con = db(); orig = con.execute("select event_type from audit_events where id=?", (mid,)).fetchone()[0]
    con.execute("update audit_events set event_type='FILE_UPLOAD' where id=?", (mid,)) if orig != "FILE_UPLOAD" else con.execute("update audit_events set event_type='LOGOUT' where id=?", (mid,))
    con.commit(); con.close()
    edited = verify(); restore_db(bk)
    con = db(); con.execute("delete from audit_events where id=?", (mid,)); con.commit(); con.close()
    deleted = verify(); restore_db(bk)
    con = db(); con.execute("delete from audit_events where id > ?", (ids[-1] - 10,)); con.commit(); con.close()
    tail = verify(); restore_db(bk)
    key = (DATA / "audit_hmac.key").read_bytes()
    con = db()
    rows = con.execute("select id,user_id,event_type,resource_id,result,created_at,previous_hash,event_hash from audit_events order by id").fetchall()
    target = rows[len(rows) // 2][0]
    prev = rows[0][6]
    for (i, uid, et, rid, res, ca, ph, eh) in rows:
        et2 = "LOGOUT" if i == target else et
        created = datetime.fromisoformat(ca).isoformat()
        payload = json.dumps([i, uid, et2, rid, res, created, prev], separators=(",", ":"))
        h = __import__("hmac").new(key, payload.encode(), hashlib.sha256).hexdigest()
        con.execute("update audit_events set event_type=?, previous_hash=?, event_hash=? where id=?", (et2, prev, h, i))
        prev = h
    con.commit(); con.close()
    forged = verify(); restore_db(bk)
    final = verify()
    ok = base["valid"] and not edited["valid"] and not deleted["valid"]
    record("G-1", "Audit Log", "Editing or deleting an audit entry",
           "Verify Chain reports the tampered entry",
           f"baseline -> {base}; edited event {mid} -> {edited}; deleted event {mid} -> {deleted}; "
           f"[extra] deleted last 10 rows -> {tail}; [extra] rewrote entry {target} and recomputed HMACs with the key file -> {forged}; restored -> {final}",
           "DEFENDED" if ok else "VULNERABLE",
           [f"tail truncation detected: {not tail['valid']}", f"forgery with key detected: {not forged['valid']}"])
    return tail, forged


def t_missing_events(alice, bob):
    def types():
        return [e["event_type"] for e in alice.c.get("/api/security/activity").json()]
    fid = alice.upload("events.txt", b"event contents")
    alice.c.post(f"/api/files/{fid}/shares", json=alice.build_share(fid, bob.name))
    sid = next(s for s in bob.c.get("/api/shared").json() if s["file_id"] == fid)["id"]
    before = types()
    con = db(); n_before = con.execute("select count(*) from audit_events").fetchone()[0]; con.close()
    fail = httpx.post(BASE + "/api/auth/login", json={"username": alice.name, "password": "definitely-wrong"}).status_code
    own = alice.c.get(f"/api/files/{fid}/blob").status_code
    shared = bob.c.get(f"/api/shared/{sid}/blob").status_code
    after = types()
    con = db(); n_after = con.execute("select count(*) from audit_events").fetchone()[0]
    new = con.execute("select event_type from audit_events order by id desc limit ?", (max(n_after - n_before, 0),)).fetchall() if n_after > n_before else []
    con.close()
    missing = n_after == n_before
    record("G-2", "Audit Log", "Missing events (failed login + downloads)",
           "Failed login and downloads appear in the Activity log",
           f"failed login -> HTTP {fail}; owner download -> HTTP {own}; shared download -> HTTP {shared}. "
           f"Audit rows before/after: {n_before}/{n_after}; new events: {[r[0] for r in new] or 'none'}; "
           f"alice Activity view unchanged: {before == after}",
           "VULNERABLE" if missing else "DEFENDED",
           ["none of the three actions produced an audit event" if missing else ""])


def t_extra_naive_expiry(alice, bob):
    fid = alice.upload("tz.txt", b"tz")
    body = alice.build_share(fid, bob.name) | {"expires_at": "2030-01-01T00:00:00"}
    try:
        code = alice.c.post(f"/api/files/{fid}/shares", json=body).status_code
    except Exception as e:
        code = f"exception {e}"
    # A 500 drops the keep-alive connection, so continue on a fresh client with the same cookie.
    alice.c = httpx.Client(base_url=BASE, timeout=60, cookies=alice.c.cookies, headers=alice.c.headers)
    link = alice.make_link(fid, max_downloads=1, expires_at="2030-01-01T00:00:00").status_code
    record("X-1", "Access Control", "[Extra] Expiration date without a timezone",
           "Request is accepted or rejected cleanly (2xx/4xx)",
           f"share with expires_at '2030-01-01T00:00:00' -> HTTP {code}; link with same -> HTTP {link}",
           "BUG" if code == 500 or link == 500 else "OK", [])


if __name__ == "__main__":
    tag = secrets.token_hex(2)
    print("Registering test users (PBKDF2 600k each)...")
    alice = User(f"alice_{tag}", "Alice-Correct-Pw-2026", "alice vault passphrase 42").register()
    bob = User(f"bob_{tag}", "Bob-Correct-Pw-2026", "bob vault passphrase 42").register()
    carol = User(f"carol_{tag}", "Carol-Correct-Pw-2026", "carol vault passphrase 42").register()
    mallory = User(f"mallory_{tag}", "Mallory-Pw-2026!!", "mallory vault passphrase").register()
    t_password_storage([alice, bob, carol, mallory])
    t_stolen_token(alice)
    t_tamper(alice)
    t_swap(alice)
    t_idor(alice, mallory, bob)
    t_reshare(alice, bob, carol)
    t_link_race(alice)
    t_dead_links(alice)
    t_missing_events(alice, bob)
    t_audit_tamper(alice)
    t_extra_naive_expiry(alice, bob)
    t_bruteforce(alice, bob)
    out = Path(sys.argv[3]) if len(sys.argv) > 3 else DATA / "audit_results.json"
    out.write_text(json.dumps(RESULTS, indent=2, default=str))
    print(f"\nSaved {len(RESULTS)} results to {out}")
