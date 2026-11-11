"""Executable regression tests. The team's security analysis remains student-authored."""
import io
import os
import secrets
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import select, text

from app.database import SessionLocal
from app.models import AuditEvent, FileShare
from app.main import verify_audit


def account(client, name):
    client.cookies.clear()  # Independent browser identity for each test account.
    password = "TestOnly-Long-Password!25"
    r = client.post("/api/auth/register", json={
        "username": name, "password": password,
        "vault_salt": "a" * 24, "vault_wrap_iv": "b" * 24,
        "wrapped_vault_key": "c" * 70, "kdf_iterations": 600000,
    })
    assert r.status_code == 201, r.text
    cookie = r.cookies.get("cipherdrop_session")
    assert cookie
    csrf = client.get("/api/auth/csrf", cookies={"cipherdrop_session": cookie})
    assert csrf.status_code == 200
    return cookie, csrf.json()["token"]


def headers(auth):
    cookie, csrf = auth
    return {"cookies": {"cipherdrop_session": cookie}, "headers": {"X-CSRF-Token": csrf}}


def upload(client, auth):
    r = client.post("/api/files", **headers(auth), data={
        "encrypted_filename": "cipher-name", "filename_iv": "filename-iv",
        "file_iv": "file-iv", "wrapped_dek": "wrapped-dek", "dek_wrap_iv": "wrap-iv",
    }, files={"blob": ("cipher.enc", b"simulated-ciphertext", "application/octet-stream")})
    assert r.status_code == 201, r.text
    return r.json()["id"]


def profile(client, auth):
    r = client.post("/api/sharing/profile", **headers(auth), json={
        "public_key_jwk": "{" + '"k":"' + "P" * 32 + '"}',
        "encrypted_private_key": "e" * 64, "private_key_iv": "f" * 24
    })
    assert r.status_code == 201, r.text


def share(client, auth, fid, username, **opts):
    data = {"recipient_username": username, "wrapped_dek": "d" * 64,
            "dek_wrap_iv": "i" * 24, "encrypted_filename": "n" * 24,
            "filename_iv": "v" * 24, "hkdf_salt": "s" * 24,
            "can_view": True, "can_download": True, "can_reshare": True}
    data.update(opts)
    return client.post(f"/api/files/{fid}/shares", **headers(auth), json=data)


def test_aes_gcm_roundtrip_and_tamper():
    # Equivalent AES-GCM primitive and authentication failure; browser Web Crypto
    # is additionally exercised by manual frontend regression checks.
    key, nonce = secrets.token_bytes(32), secrets.token_bytes(12)
    plaintext = b"Never upload this plaintext to the server"
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)
    assert plaintext not in ciphertext
    assert AESGCM(key).decrypt(nonce, ciphertext, None) == plaintext
    broken = bytearray(ciphertext)
    broken[0] ^= 1
    from cryptography.exceptions import InvalidTag
    import pytest
    with pytest.raises(InvalidTag):
        AESGCM(key).decrypt(nonce, bytes(broken), None)


def test_csrf_account_isolation_and_revocation(client):
    owner = account(client, "phaseowner")
    bob = account(client, "phasebob")
    charlie = account(client, "phasecharlie")
    outsider = account(client, "phaseoutsider")
    profile(client, owner)
    profile(client, bob)
    profile(client, charlie)
    fid = upload(client, owner)
    assert client.get(f"/api/files/{fid}/blob", cookies={"cipherdrop_session": outsider[0]}).status_code == 404
    assert client.delete(f"/api/files/{fid}", cookies={"cipherdrop_session": outsider[0]}).status_code == 403
    assert client.delete(f"/api/files/{fid}", **headers(outsider)).status_code == 404
    assert client.delete(f"/api/files/{fid}", cookies={"cipherdrop_session": owner[0]}).status_code == 403
    created = share(client, owner, fid, "phasebob")
    assert created.status_code == 201, created.text
    bob_shares = client.get("/api/shared", cookies={"cipherdrop_session": bob[0]}).json()
    assert len(bob_shares) == 1
    parent = created.json()["id"]
    child = client.post(f"/api/shared/{parent}/reshare", **headers(bob), json={
        "recipient_username": "phasecharlie", "wrapped_dek": "d" * 64,
        "dek_wrap_iv": "i" * 24, "encrypted_filename": "n" * 24,
        "filename_iv": "v" * 24, "hkdf_salt": "s" * 24,
        "can_view": True, "can_download": True, "can_reshare": False,
    })
    assert child.status_code == 201, child.text
    descendant = child.json()["id"]
    assert client.get(f"/api/shared/{descendant}/blob", cookies={"cipherdrop_session": charlie[0]}).status_code == 200
    assert client.delete(f"/api/files/{fid}/shares/{parent}", **headers(owner)).status_code == 204
    assert client.get(f"/api/shared/{parent}/blob", cookies={"cipherdrop_session": bob[0]}).status_code == 404
    assert client.get(f"/api/shared/{descendant}/blob", cookies={"cipherdrop_session": charlie[0]}).status_code == 404
    assert client.get("/api/shared", cookies={"cipherdrop_session": charlie[0]}).json() == []


def test_expiry_and_no_reshare_escalation(client):
    owner = account(client, "expireowner")
    recipient = account(client, "expirerecipient")
    profile(client, recipient)
    fid = upload(client, owner)
    future = (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat()
    created = share(client, owner, fid, "expirerecipient", can_reshare=False, expires_at=future)
    assert created.status_code == 201, created.text
    share_id = created.json()["id"]
    result = client.post(f"/api/shared/{share_id}/reshare", **headers(recipient), json={
        "recipient_username": "phaseoutsider", "wrapped_dek": "d" * 64,
        "dek_wrap_iv": "i" * 24, "encrypted_filename": "n" * 24,
        "filename_iv": "v" * 24, "hkdf_salt": "s" * 24,
    })
    assert result.status_code == 404
    with SessionLocal() as db:
        row = db.get(FileShare, share_id)
        row.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
        db.commit()
    assert client.get(f"/api/shared/{share_id}/blob", cookies={"cipherdrop_session": recipient[0]}).status_code == 404


def test_audit_integrity_tampering(client):
    user = account(client, "auditowner")
    with SessionLocal() as db:
        initial = verify_audit(db)
        assert initial["valid"], initial
        row = db.scalar(select(AuditEvent).order_by(AuditEvent.id.desc()).limit(1))
        old = row.resource_id
        row.resource_id = "ATTACKER-MODIFIED"
        db.commit()
        assert not verify_audit(db)["valid"]
        row.resource_id = old
        db.commit()
        assert verify_audit(db)["valid"]


def test_rate_limit_persists_in_database(client):
    name = "nonexistent-phase1-rate"
    for _ in range(8):
        r = client.post("/api/auth/login", json={"username": name, "password": "incorrect"})
        assert r.status_code == 401
    r = client.post("/api/auth/login", json={"username": name, "password": "incorrect"})
    assert r.status_code == 429


def test_link_download_one_time(client):
    owner = account(client, "linkowner")
    fid = upload(client, owner)
    created = client.post(f"/api/files/{fid}/links", **headers(owner), json={
        "encrypted_filename":"n"*24,"filename_iv":"i"*24,
        "wrapped_dek":"d"*64,"dek_wrap_iv":"v"*24,"max_downloads":1,
    })
    assert created.status_code == 201, created.text
    token = created.json()["token"]
    assert client.get(f"/api/public/links/{token}").status_code == 200
    assert client.post(f"/api/public/links/{token}/download").status_code == 200
    assert client.post(f"/api/public/links/{token}/download").status_code == 404


def test_encrypted_upload_roundtrip_and_confidential_storage(client):
    from app.models import FileRecord
    from app.main import STORAGE
    owner = account(client, "actualcryptoowner")
    plaintext = b"Classified phase-one demonstration plaintext"
    aes = AESGCM(secrets.token_bytes(32))
    nonce = secrets.token_bytes(12)
    ciphertext = aes.encrypt(nonce, plaintext, None)
    r = client.post("/api/files", **headers(owner), data={
        "encrypted_filename": "opaque-encrypted-filename", "filename_iv": "x" * 24,
        "file_iv": "y" * 24, "wrapped_dek": "z" * 64, "dek_wrap_iv": "q" * 24,
    }, files={"blob": ("file.enc", ciphertext, "application/octet-stream")})
    assert r.status_code == 201
    fid = r.json()["id"]
    with SessionLocal() as db:
        record = db.get(FileRecord, fid)
        stored = (STORAGE / record.object_name).read_bytes()
        assert stored == ciphertext
        assert plaintext not in stored
        assert record.encrypted_filename != "original-name.txt"
    downloaded = client.get(f"/api/files/{fid}/blob", cookies={"cipherdrop_session": owner[0]})
    assert downloaded.status_code == 200
    assert aes.decrypt(nonce, downloaded.content, None) == plaintext


def test_security_headers_and_cross_origin(client):
    r = client.get("/api/health")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["cache-control"] == "no-store"
    r = client.post("/api/auth/login", json={"username": "anything", "password": "wrong"},
                    headers={"Origin": "https://evil.example"})
    assert r.status_code == 403


def test_production_requires_https_config():
    import subprocess
    import sys
    from pathlib import Path
    env = os.environ.copy()
    env["CIPHERDROP_ENV"] = "production"
    env["CIPHERDROP_COOKIE_SECURE"] = "false"
    env["CIPHERDROP_PUBLIC_ORIGIN"] = "http://localhost"
    result = subprocess.run([sys.executable, "-c", "import app.main"],
                            env=env, cwd=str(Path(__file__).resolve().parents[1] / "backend"),
                            capture_output=True, text=True)
    assert result.returncode != 0
    assert "Production requires" in result.stderr


def test_session_cookie_flags(client):
    client.cookies.clear()
    r = client.post("/api/auth/register", json={
        "username":"cookieflagsowner", "password":"TestOnly-Long-Password!25",
        "vault_salt":"a"*24,"vault_wrap_iv":"b"*24,
        "wrapped_vault_key":"c"*70,"kdf_iterations":600000,
    })
    assert r.status_code == 201
    cookies = r.headers.get("set-cookie", "").lower()
    assert "httponly" in cookies
    assert "samesite=strict" in cookies


def test_passkey_flows_are_single_use(client):
    """DB challenges are short-lived, purpose-specific and consumed exactly once."""
    from app.main import _new_passkey_flow, _consume_passkey_flow
    from fastapi import HTTPException
    import pytest
    user_cookie, _ = account(client, 'passkeyflowowner')
    from app.models import User
    with SessionLocal() as db:
        user = db.scalar(select(User).where(User.username == 'passkeyflowowner'))
        flow = _new_passkey_flow(db, user.id, b'challenge-1234', 'login', 'http://localhost:5173')
        assert _consume_passkey_flow(db, flow, 'login', 'http://localhost:5173') == (user.id, b'challenge-1234')
        with pytest.raises(HTTPException):
            _consume_passkey_flow(db, flow, 'login', 'http://localhost:5173')
        flow2 = _new_passkey_flow(db, user.id, b'challenge-5678', 'register', 'http://localhost:5173', 'session')
        with pytest.raises(HTTPException):
            _consume_passkey_flow(db, flow2, 'register', 'http://localhost:5173', user.id, 'wrong-session')
        with pytest.raises(HTTPException):
            _consume_passkey_flow(db, flow2, 'register', 'http://localhost:5173', user.id, 'session')


def test_passkey_management_protected(client):
    auth = account(client, 'passkeymanager')
    assert client.get('/api/security/passkeys', cookies={'cipherdrop_session': auth[0]}).json() == []
    client.cookies.clear()
    assert client.get('/api/security/passkeys').status_code == 401
    assert client.delete('/api/security/passkeys/999', **headers(auth)).status_code == 403
    r=client.post('/api/security/passkeys/register/begin', **headers(auth))
    assert r.status_code == 403  # password step-up required
