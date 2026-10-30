import hashlib
import os
import json
import hmac
import threading
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import Depends, FastAPI, HTTPException, Request, Response, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from sqlalchemy import select, text, update
from sqlalchemy.orm import Session as DBSession

from .database import Base, engine, get_db
from .models import User, Session, FileRecord, UserCryptoProfile, FileShare, AuditEvent, SecureLink
from .schemas import RegisterRequest, LoginRequest, CryptoProfileRequest, ShareRequest, ReshareRequest

ROOT = Path(__file__).resolve().parents[2]
STORAGE = ROOT / "data" / "encrypted"
STORAGE.mkdir(parents=True, exist_ok=True)
SESSION_COOKIE = "cipherdrop_session"
SESSION_HOURS = 12
COOKIE_SECURE = os.getenv("CIPHERDROP_COOKIE_SECURE", "false").lower() == "true"
MAX_FILE_BYTES = 100 * 1024 * 1024
ph = PasswordHasher()

app = FastAPI(title="CipherDrop API", version="0.7.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Content-Type"],
)

@app.on_event("startup")
def startup():
    Base.metadata.create_all(bind=engine)
    # Lightweight SQLite migration for pre-v0.4 development databases.
    # SQLAlchemy create_all() creates new tables but does not add columns to existing ones.
    if engine.dialect.name == "sqlite":
        with engine.begin() as conn:
            cols = {row[1] for row in conn.execute(text("PRAGMA table_info(file_shares)"))}
            additions = {
                "grantor_id": "INTEGER",
                "parent_share_id": "INTEGER",
                "can_view": "BOOLEAN NOT NULL DEFAULT 1",
                "can_download": "BOOLEAN NOT NULL DEFAULT 1",
                "can_reshare": "BOOLEAN NOT NULL DEFAULT 0",
                "expires_at": "DATETIME",
            }
            for name, ddl in additions.items():
                if name not in cols:
                    conn.execute(text(f"ALTER TABLE file_shares ADD COLUMN {name} {ddl}"))
            conn.execute(text("UPDATE file_shares SET grantor_id = owner_id WHERE grantor_id IS NULL"))
            session_cols = {row[1] for row in conn.execute(text("PRAGMA table_info(sessions)"))}
            for name, ddl in {"user_agent":"VARCHAR(300) DEFAULT 'Unknown'", "ip_address":"VARCHAR(100) DEFAULT 'Unknown'", "last_seen_at":"DATETIME"}.items():
                if name not in session_cols:
                    conn.execute(text(f"ALTER TABLE sessions ADD COLUMN {name} {ddl}"))
            conn.execute(text("UPDATE sessions SET last_seen_at = created_at WHERE last_seen_at IS NULL"))

def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()

def current_user(request: Request, db: DBSession = Depends(get_db)) -> User:
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        raise HTTPException(401, "Authentication required")
    row = db.scalar(select(Session).where(Session.token_hash == hash_token(token)))
    if not row or row.expires_at.replace(tzinfo=timezone.utc) <= datetime.now(timezone.utc):
        if row:
            db.delete(row)
            db.commit()
        raise HTTPException(401, "Session expired or invalid")
    user = db.get(User, row.user_id)
    if not user:
        raise HTTPException(401, "Authentication required")
    request.state.session_id = row.id
    return user

def create_session(response: Response, user: User, db: DBSession, request: Request):
    raw = secrets.token_urlsafe(32)
    expires = datetime.now(timezone.utc) + timedelta(hours=SESSION_HOURS)
    db.add(Session(user_id=user.id, token_hash=hash_token(raw), expires_at=expires, user_agent=request.headers.get("user-agent", "Unknown")[:300], ip_address=request.client.host if request.client else "Unknown", last_seen_at=datetime.now(timezone.utc)))
    db.commit()
    response.set_cookie(
        SESSION_COOKIE, raw, httponly=True, samesite="lax", secure=COOKIE_SECURE,
        max_age=SESSION_HOURS * 3600, path="/"
    )


AUDIT_KEY_FILE = ROOT / "data" / "audit_hmac.key"
AUDIT_KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
if not AUDIT_KEY_FILE.exists():
    try:
        with AUDIT_KEY_FILE.open("xb") as fh:
            fh.write(secrets.token_bytes(32))
        os.chmod(AUDIT_KEY_FILE, 0o600)
    except FileExistsError:
        pass
AUDIT_KEY = AUDIT_KEY_FILE.read_bytes()
_audit_lock = threading.RLock()

def audit(db: DBSession, user_id: int | None, event: str, resource: str = "", result: str = "success"):
    # Call only for authoritative server-side events; commit atomically with business operation.
    with _audit_lock:
        last = db.scalar(select(AuditEvent).order_by(AuditEvent.id.desc()).limit(1))
        prev = last.event_hash if last else "0" * 64
        row = AuditEvent(user_id=user_id, event_type=event, resource_id=str(resource), result=result,
                         previous_hash=prev, event_hash="", created_at=datetime.now(timezone.utc).replace(tzinfo=None))
        db.add(row)
        db.flush()
        payload = json.dumps([row.id, row.user_id, row.event_type, row.resource_id, row.result,
                              row.created_at.isoformat(), row.previous_hash], separators=(",", ":"))
        row.event_hash = hmac.new(AUDIT_KEY, payload.encode(), hashlib.sha256).hexdigest()
        db.flush()

def verify_audit(db: DBSession):
    prev = "0" * 64
    events = db.scalars(select(AuditEvent).order_by(AuditEvent.id)).all()
    for row in events:
        payload = json.dumps([row.id, row.user_id, row.event_type, row.resource_id, row.result,
                              row.created_at.isoformat(), row.previous_hash], separators=(",", ":"))
        expected = hmac.new(AUDIT_KEY, payload.encode(), hashlib.sha256).hexdigest()
        if row.previous_hash != prev or not hmac.compare_digest(expected, row.event_hash):
            return {"valid": False, "checked": len(events), "failed_event_id": row.id}
        prev = row.event_hash
    return {"valid": True, "checked": len(events)}

@app.get("/api/health")
def health():
    return {"status": "ok", "version": "0.7.0"}

@app.post("/api/auth/register", status_code=201)
def register(body: RegisterRequest, response: Response, request: Request, db: DBSession = Depends(get_db)):
    username = body.username.strip().lower()
    if db.scalar(select(User).where(User.username == username)):
        raise HTTPException(409, "Username is unavailable")
    user = User(
        username=username,
        password_hash=ph.hash(body.password),
        vault_salt=body.vault_salt,
        vault_wrap_iv=body.vault_wrap_iv,
        wrapped_vault_key=body.wrapped_vault_key,
        kdf_iterations=body.kdf_iterations,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    create_session(response, user, db, request)
    audit(db, user.id, "SESSION_CREATED"); db.commit()
    return {"id": user.id, "username": user.username}

@app.post("/api/auth/login")
def login(body: LoginRequest, response: Response, request: Request, db: DBSession = Depends(get_db)):
    user = db.scalar(select(User).where(User.username == body.username.strip().lower()))
    if not user:
        raise HTTPException(401, "Invalid username or password")
    try:
        ph.verify(user.password_hash, body.password)
    except VerifyMismatchError:
        raise HTTPException(401, "Invalid username or password")
    if ph.check_needs_rehash(user.password_hash):
        user.password_hash = ph.hash(body.password)
    create_session(response, user, db, request)
    audit(db, user.id, "SESSION_CREATED"); db.commit()
    return {"id": user.id, "username": user.username}

@app.post("/api/auth/logout", status_code=204)
def logout(request: Request, response: Response, db: DBSession = Depends(get_db)):
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        row = db.scalar(select(Session).where(Session.token_hash == hash_token(token)))
        if row:
            audit(db, row.user_id, "LOGOUT", str(row.id))
            db.delete(row)
            db.commit()
    response.delete_cookie(SESSION_COOKIE, path="/")

@app.get("/api/auth/me")
def me(user: User = Depends(current_user)):
    return {"id": user.id, "username": user.username}

@app.get("/api/vault/material")
def vault_material(user: User = Depends(current_user)):
    return {
        "vault_salt": user.vault_salt,
        "vault_wrap_iv": user.vault_wrap_iv,
        "wrapped_vault_key": user.wrapped_vault_key,
        "kdf_iterations": user.kdf_iterations,
    }

@app.get("/api/files")
def list_files(user: User = Depends(current_user), db: DBSession = Depends(get_db)):
    rows = db.scalars(select(FileRecord).where(FileRecord.owner_id == user.id).order_by(FileRecord.created_at.desc())).all()
    return [{
        "id": r.id, "encrypted_filename": r.encrypted_filename, "filename_iv": r.filename_iv,
        "file_iv": r.file_iv, "wrapped_dek": r.wrapped_dek, "dek_wrap_iv": r.dek_wrap_iv,
        "size_bytes": r.size_bytes, "created_at": r.created_at,
    } for r in rows]

@app.post("/api/files", status_code=201)
async def upload_file(
    blob: UploadFile = File(...), encrypted_filename: str = Form(...), filename_iv: str = Form(...),
    file_iv: str = Form(...), wrapped_dek: str = Form(...), dek_wrap_iv: str = Form(...),
    user: User = Depends(current_user), db: DBSession = Depends(get_db),
):
    data = await blob.read(MAX_FILE_BYTES + 1)
    if len(data) > MAX_FILE_BYTES:
        raise HTTPException(413, "Encrypted file exceeds 100 MiB demo limit")
    object_name = f"{uuid.uuid4().hex}.enc"
    path = STORAGE / object_name
    path.write_bytes(data)
    row = FileRecord(
        owner_id=user.id, object_name=object_name, encrypted_filename=encrypted_filename,
        filename_iv=filename_iv, file_iv=file_iv, wrapped_dek=wrapped_dek,
        dek_wrap_iv=dek_wrap_iv, size_bytes=len(data),
    )
    db.add(row)
    try:
        db.flush()
        audit(db, user.id, "FILE_UPLOAD", str(row.id))
        db.commit()
        db.refresh(row)
    except Exception:
        path.unlink(missing_ok=True)
        raise
    return {"id": row.id}

@app.put("/api/files/{file_id}")
async def replace_file(
    file_id: int, blob: UploadFile = File(...), encrypted_filename: str = Form(...), filename_iv: str = Form(...),
    file_iv: str = Form(...), wrapped_dek: str = Form(...), dek_wrap_iv: str = Form(...),
    user: User = Depends(current_user), db: DBSession = Depends(get_db),
):
    row = db.scalar(select(FileRecord).where(FileRecord.id == file_id, FileRecord.owner_id == user.id))
    if not row:
        raise HTTPException(404, "File not found")
    data = await blob.read(MAX_FILE_BYTES + 1)
    if len(data) > MAX_FILE_BYTES:
        raise HTTPException(413, "Encrypted file exceeds 100 MiB demo limit")

    # Replacement uses fresh client-generated key material. Existing recipient grants
    # are revoked because their wrapped DEKs refer to the old encrypted object.
    new_object_name = f"{uuid.uuid4().hex}.enc"
    new_path = STORAGE / new_object_name
    old_path = STORAGE / row.object_name
    new_path.write_bytes(data)
    try:
        for link in db.scalars(select(SecureLink).where(SecureLink.file_id == row.id)).all():
            db.delete(link)
        for share in list(row.shares):
            db.delete(share)
        row.object_name = new_object_name
        row.encrypted_filename = encrypted_filename
        row.filename_iv = filename_iv
        row.file_iv = file_iv
        row.wrapped_dek = wrapped_dek
        row.dek_wrap_iv = dek_wrap_iv
        row.size_bytes = len(data)
        audit(db, user.id, "FILE_REPLACED", str(row.id))
        db.commit()
    except Exception:
        db.rollback()
        new_path.unlink(missing_ok=True)
        raise
    old_path.unlink(missing_ok=True)
    return {"id": row.id, "shares_revoked": True}

@app.delete("/api/files/{file_id}", status_code=204)
def delete_file(file_id: int, user: User = Depends(current_user), db: DBSession = Depends(get_db)):
    row = db.scalar(select(FileRecord).where(FileRecord.id == file_id, FileRecord.owner_id == user.id))
    if not row:
        raise HTTPException(404, "File not found")
    path = STORAGE / row.object_name
    audit(db, user.id, "FILE_DELETED", str(row.id))
    for link in db.scalars(select(SecureLink).where(SecureLink.file_id == row.id)).all():
        db.delete(link)
    db.delete(row)  # FileShare rows are removed by the relationship cascade.
    db.commit()
    path.unlink(missing_ok=True)

@app.get("/api/files/{file_id}/blob")
def download_blob(file_id: int, user: User = Depends(current_user), db: DBSession = Depends(get_db)):
    row = db.scalar(select(FileRecord).where(FileRecord.id == file_id, FileRecord.owner_id == user.id))
    if not row:
        raise HTTPException(404, "File not found")
    path = STORAGE / row.object_name
    if not path.exists():
        raise HTTPException(410, "Encrypted object is missing")
    return FileResponse(path, media_type="application/octet-stream", filename=f"{file_id}.enc")


@app.get("/api/sharing/profile")
def get_crypto_profile(user: User = Depends(current_user), db: DBSession = Depends(get_db)):
    profile = db.scalar(select(UserCryptoProfile).where(UserCryptoProfile.user_id == user.id))
    if not profile:
        return {"configured": False}
    return {
        "configured": True,
        "public_key_jwk": profile.public_key_jwk,
        "encrypted_private_key": profile.encrypted_private_key,
        "private_key_iv": profile.private_key_iv,
    }

@app.post("/api/sharing/profile", status_code=201)
def create_crypto_profile(body: CryptoProfileRequest, user: User = Depends(current_user), db: DBSession = Depends(get_db)):
    existing = db.scalar(select(UserCryptoProfile).where(UserCryptoProfile.user_id == user.id))
    if existing:
        raise HTTPException(409, "Sharing keys are already configured")
    profile = UserCryptoProfile(
        user_id=user.id,
        public_key_jwk=body.public_key_jwk,
        encrypted_private_key=body.encrypted_private_key,
        private_key_iv=body.private_key_iv,
    )
    db.add(profile)
    db.commit()
    return {"configured": True}

@app.get("/api/users/{username}/public-key")
def recipient_public_key(username: str, user: User = Depends(current_user), db: DBSession = Depends(get_db)):
    target = db.scalar(select(User).where(User.username == username.strip().lower()))
    if not target or target.id == user.id:
        raise HTTPException(404, "Recipient not found")
    profile = db.scalar(select(UserCryptoProfile).where(UserCryptoProfile.user_id == target.id))
    if not profile:
        raise HTTPException(409, "Recipient has not initialized encrypted sharing")
    return {"username": target.username, "public_key_jwk": profile.public_key_jwk}

def _is_expired(share: FileShare) -> bool:
    if not share.expires_at:
        return False
    expiry = share.expires_at
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)
    return expiry <= datetime.now(timezone.utc)

def _delete_share_tree(db: DBSession, share: FileShare):
    children = db.scalars(select(FileShare).where(FileShare.parent_share_id == share.id)).all()
    for child in children:
        _delete_share_tree(db, child)
    db.delete(share)

def _share_payload(share: FileShare, db: DBSession):
    file_row = db.get(FileRecord, share.file_id)
    owner = db.get(User, share.owner_id)
    grantor = db.get(User, share.grantor_id or share.owner_id)
    grantor_profile = db.scalar(select(UserCryptoProfile).where(UserCryptoProfile.user_id == (share.grantor_id or share.owner_id)))
    if not file_row or not owner or not grantor or not grantor_profile:
        return None
    return {
        "id": share.id, "file_id": file_row.id,
        "owner_username": owner.username, "grantor_username": grantor.username,
        "sender_public_key_jwk": grantor_profile.public_key_jwk,
        "encrypted_filename": share.encrypted_filename, "filename_iv": share.filename_iv,
        "file_iv": file_row.file_iv, "wrapped_dek": share.wrapped_dek,
        "dek_wrap_iv": share.dek_wrap_iv, "hkdf_salt": share.hkdf_salt,
        "size_bytes": file_row.size_bytes, "created_at": share.created_at,
        "can_view": bool(share.can_view), "can_download": bool(share.can_download),
        "can_reshare": bool(share.can_reshare), "expires_at": share.expires_at,
    }

@app.post("/api/files/{file_id}/shares", status_code=201)
def create_share(file_id: int, body: ShareRequest, user: User = Depends(current_user), db: DBSession = Depends(get_db)):
    file_row = db.scalar(select(FileRecord).where(FileRecord.id == file_id, FileRecord.owner_id == user.id))
    if not file_row:
        raise HTTPException(404, "File not found")
    recipient = db.scalar(select(User).where(User.username == body.recipient_username.strip().lower()))
    if not recipient or recipient.id == user.id:
        raise HTTPException(404, "Recipient not found")
    profile = db.scalar(select(UserCryptoProfile).where(UserCryptoProfile.user_id == recipient.id))
    if not profile:
        raise HTTPException(409, "Recipient has not initialized encrypted sharing")
    existing = db.scalar(select(FileShare).where(FileShare.file_id == file_id, FileShare.recipient_id == recipient.id))
    if existing:
        raise HTTPException(409, "File is already shared with this user")
    if body.expires_at and body.expires_at <= datetime.now(timezone.utc):
        raise HTTPException(400, "Expiration must be in the future")
    share = FileShare(
        file_id=file_id, owner_id=user.id, recipient_id=recipient.id, grantor_id=user.id,
        wrapped_dek=body.wrapped_dek, dek_wrap_iv=body.dek_wrap_iv,
        encrypted_filename=body.encrypted_filename, filename_iv=body.filename_iv,
        hkdf_salt=body.hkdf_salt, can_view=body.can_view, can_download=body.can_download,
        can_reshare=body.can_reshare, expires_at=body.expires_at,
    )
    db.add(share); db.flush(); audit(db, user.id, "SHARE_CREATED", str(share.id)); db.commit(); db.refresh(share)
    return {"id": share.id, "recipient": recipient.username}

@app.get("/api/files/{file_id}/shares")
def manage_file_shares(file_id: int, user: User = Depends(current_user), db: DBSession = Depends(get_db)):
    file_row = db.scalar(select(FileRecord).where(FileRecord.id == file_id, FileRecord.owner_id == user.id))
    if not file_row:
        raise HTTPException(404, "File not found")
    shares = db.scalars(select(FileShare).where(FileShare.file_id == file_id, FileShare.owner_id == user.id).order_by(FileShare.created_at.desc())).all()
    result = []
    for share in shares:
        recipient = db.get(User, share.recipient_id)
        grantor = db.get(User, share.grantor_id or share.owner_id)
        if recipient and grantor:
            result.append({
                "id": share.id, "recipient_username": recipient.username,
                "grantor_username": grantor.username, "can_view": bool(share.can_view),
                "can_download": bool(share.can_download), "can_reshare": bool(share.can_reshare),
                "expires_at": share.expires_at, "expired": _is_expired(share),
                "created_at": share.created_at, "is_direct": share.parent_share_id is None,
            })
    return result

@app.delete("/api/files/{file_id}/shares/{share_id}", status_code=204)
def revoke_share(file_id: int, share_id: int, user: User = Depends(current_user), db: DBSession = Depends(get_db)):
    file_row = db.scalar(select(FileRecord).where(FileRecord.id == file_id, FileRecord.owner_id == user.id))
    if not file_row:
        raise HTTPException(404, "File not found")
    share = db.scalar(select(FileShare).where(FileShare.id == share_id, FileShare.file_id == file_id, FileShare.owner_id == user.id))
    if not share:
        raise HTTPException(404, "Share not found")
    audit(db, user.id, "SHARE_REVOKED", str(share.id))
    _delete_share_tree(db, share)
    db.commit()

@app.get("/api/shared")
def shared_with_me(user: User = Depends(current_user), db: DBSession = Depends(get_db)):
    shares = db.scalars(select(FileShare).where(FileShare.recipient_id == user.id, FileShare.can_view == True).order_by(FileShare.created_at.desc())).all()
    result = []
    for share in shares:
        if _is_expired(share):
            continue
        payload = _share_payload(share, db)
        if payload:
            result.append(payload)
    return result

@app.post("/api/shared/{share_id}/reshare", status_code=201)
def reshare_file(share_id: int, body: ReshareRequest, user: User = Depends(current_user), db: DBSession = Depends(get_db)):
    parent = db.scalar(select(FileShare).where(FileShare.id == share_id, FileShare.recipient_id == user.id))
    if not parent or _is_expired(parent) or not parent.can_reshare:
        raise HTTPException(404, "Share not found")
    recipient = db.scalar(select(User).where(User.username == body.recipient_username.strip().lower()))
    if not recipient or recipient.id in {user.id, parent.owner_id}:
        raise HTTPException(404, "Recipient not found")
    profile = db.scalar(select(UserCryptoProfile).where(UserCryptoProfile.user_id == recipient.id))
    if not profile:
        raise HTTPException(409, "Recipient has not initialized encrypted sharing")
    existing = db.scalar(select(FileShare).where(FileShare.file_id == parent.file_id, FileShare.recipient_id == recipient.id))
    if existing:
        raise HTTPException(409, "File is already shared with this user")
    expires_at = body.expires_at
    if parent.expires_at and (expires_at is None or expires_at > parent.expires_at.replace(tzinfo=timezone.utc)):
        expires_at = parent.expires_at.replace(tzinfo=timezone.utc)
    if expires_at and expires_at <= datetime.now(timezone.utc):
        raise HTTPException(400, "Expiration must be in the future")
    child = FileShare(
        file_id=parent.file_id, owner_id=parent.owner_id, recipient_id=recipient.id,
        grantor_id=user.id, parent_share_id=parent.id,
        wrapped_dek=body.wrapped_dek, dek_wrap_iv=body.dek_wrap_iv,
        encrypted_filename=body.encrypted_filename, filename_iv=body.filename_iv,
        hkdf_salt=body.hkdf_salt, can_view=body.can_view,
        can_download=body.can_download and parent.can_download,
        can_reshare=body.can_reshare and parent.can_reshare, expires_at=expires_at,
    )
    db.add(child); db.flush(); audit(db, user.id, "SHARE_RESHARED", str(child.id)); db.commit(); db.refresh(child)
    return {"id": child.id, "recipient": recipient.username}

@app.get("/api/shared/{share_id}/blob")
def download_shared_blob(share_id: int, user: User = Depends(current_user), db: DBSession = Depends(get_db)):
    share = db.scalar(select(FileShare).where(FileShare.id == share_id, FileShare.recipient_id == user.id))
    if not share or _is_expired(share) or not share.can_download:
        raise HTTPException(404, "Shared file not found")
    file_row = db.get(FileRecord, share.file_id)
    if not file_row:
        raise HTTPException(410, "Shared file record is missing")
    path = STORAGE / file_row.object_name
    if not path.exists():
        raise HTTPException(410, "Encrypted object is missing")
    return FileResponse(path, media_type="application/octet-stream", filename=f"shared-{share_id}.enc")

# v0.5 — authenticated session management
@app.get('/api/security/sessions')
def list_sessions(request: Request, user: User = Depends(current_user), db: DBSession = Depends(get_db)):
    rows = db.scalars(select(Session).where(Session.user_id == user.id).order_by(Session.created_at.desc())).all()
    return [{'id': r.id, 'created_at': r.created_at, 'last_seen_at': r.last_seen_at,
             'expires_at': r.expires_at, 'user_agent': r.user_agent, 'ip_address': r.ip_address,
             'current': r.id == request.state.session_id} for r in rows]

@app.delete('/api/security/sessions/{session_id}', status_code=204)
def revoke_session(session_id: int, request: Request, user: User = Depends(current_user), db: DBSession = Depends(get_db)):
    row = db.scalar(select(Session).where(Session.id == session_id, Session.user_id == user.id))
    if not row:
        raise HTTPException(404, 'Session not found')
    audit(db, user.id, 'SESSION_REVOKED', str(row.id))
    db.delete(row)
    db.commit()

@app.post('/api/security/sessions/revoke-others')
def revoke_other_sessions(request: Request, user: User = Depends(current_user), db: DBSession = Depends(get_db)):
    rows = db.scalars(select(Session).where(Session.user_id == user.id, Session.id != request.state.session_id)).all()
    for row in rows:
        db.delete(row)
    audit(db, user.id, 'OTHER_SESSIONS_REVOKED', str(len(rows)))
    db.commit()
    return {'revoked': len(rows)}

# v0.6 — read-only user activity + chain verification
@app.get('/api/security/activity')
def security_activity(user: User = Depends(current_user), db: DBSession = Depends(get_db)):
    rows = db.scalars(select(AuditEvent).where(AuditEvent.user_id == user.id).order_by(AuditEvent.id.desc()).limit(150)).all()
    return [{'id': r.id, 'created_at': r.created_at, 'event_type': r.event_type,
             'resource_id': r.resource_id, 'result': r.result} for r in rows]

@app.get('/api/security/audit/verify')
def audit_integrity(user: User = Depends(current_user), db: DBSession = Depends(get_db)):
    return verify_audit(db)

# v0.7 — encrypted links. Secret is only in browser URL fragment, never server request.
from pydantic import BaseModel, Field

class LinkCreate(BaseModel):
    encrypted_filename: str
    filename_iv: str
    wrapped_dek: str
    dek_wrap_iv: str
    expires_at: datetime | None = None
    max_downloads: int = Field(ge=1, le=100)

@app.post('/api/files/{file_id}/links', status_code=201)
def create_link(file_id: int, body: LinkCreate, user: User = Depends(current_user), db: DBSession = Depends(get_db)):
    file_row = db.scalar(select(FileRecord).where(FileRecord.id == file_id, FileRecord.owner_id == user.id))
    if not file_row:
        raise HTTPException(404, 'File not found')
    if body.expires_at and body.expires_at <= datetime.now(timezone.utc):
        raise HTTPException(400, 'Expiration must be in the future')
    raw = secrets.token_urlsafe(32)
    link = SecureLink(file_id=file_id, owner_id=user.id, token_hash=hash_token(raw),
                      encrypted_filename=body.encrypted_filename, filename_iv=body.filename_iv,
                      wrapped_dek=body.wrapped_dek, dek_wrap_iv=body.dek_wrap_iv,
                      expires_at=body.expires_at, max_downloads=body.max_downloads)
    db.add(link); db.flush(); audit(db, user.id, 'LINK_CREATED', str(link.id)); db.commit()
    return {'id': link.id, 'token': raw}

@app.get('/api/files/{file_id}/links')
def list_links(file_id: int, user: User = Depends(current_user), db: DBSession = Depends(get_db)):
    if not db.scalar(select(FileRecord).where(FileRecord.id == file_id, FileRecord.owner_id == user.id)):
        raise HTTPException(404, 'File not found')
    rows = db.scalars(select(SecureLink).where(SecureLink.file_id == file_id, SecureLink.owner_id == user.id)).all()
    return [{'id': r.id, 'expires_at': r.expires_at, 'download_count': r.download_count,
             'max_downloads': r.max_downloads} for r in rows]

@app.delete('/api/files/{file_id}/links/{link_id}', status_code=204)
def revoke_link(file_id: int, link_id: int, user: User = Depends(current_user), db: DBSession = Depends(get_db)):
    row = db.scalar(select(SecureLink).where(SecureLink.id == link_id, SecureLink.file_id == file_id, SecureLink.owner_id == user.id))
    if not row:
        raise HTTPException(404, 'Link not found')
    audit(db, user.id, 'LINK_REVOKED', str(row.id)); db.delete(row); db.commit()

def _public_link(db, token):
    link = db.scalar(select(SecureLink).where(SecureLink.token_hash == hash_token(token)))
    if not link or (link.expires_at and link.expires_at.replace(tzinfo=timezone.utc) <= datetime.now(timezone.utc)) or link.download_count >= link.max_downloads:
        raise HTTPException(404, 'Link unavailable')
    row = db.get(FileRecord, link.file_id)
    if not row:
        raise HTTPException(404, 'Link unavailable')
    return link, row

@app.get('/api/public/links/{token}')
def public_link_metadata(token: str, db: DBSession = Depends(get_db)):
    link, row = _public_link(db, token)
    return {'encrypted_filename': link.encrypted_filename, 'filename_iv': link.filename_iv,
            'wrapped_dek': link.wrapped_dek, 'dek_wrap_iv': link.dek_wrap_iv,
            'file_iv': row.file_iv, 'size_bytes': row.size_bytes}

@app.post('/api/public/links/{token}/download')
def public_link_download(token: str, db: DBSession = Depends(get_db)):
    link, row = _public_link(db, token)
    path = STORAGE / row.object_name
    if not path.exists():
        raise HTTPException(404, 'Link unavailable')
    # Atomic conditional update prevents concurrent requests from exceeding the limit.
    result = db.execute(update(SecureLink).where(SecureLink.id == link.id,
                        SecureLink.download_count < SecureLink.max_downloads).values(
                        download_count=SecureLink.download_count + 1))
    if result.rowcount != 1:
        db.rollback(); raise HTTPException(404, 'Link unavailable')
    audit(db, link.owner_id, 'LINK_DOWNLOADED', str(link.id)); db.commit()
    return FileResponse(path, media_type='application/octet-stream', filename='encrypted-file.enc')
