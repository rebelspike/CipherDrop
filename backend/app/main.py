import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import Depends, FastAPI, HTTPException, Request, Response, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.orm import Session as DBSession

from .database import Base, engine, get_db
from .models import User, Session, FileRecord, UserCryptoProfile, FileShare
from .schemas import RegisterRequest, LoginRequest, CryptoProfileRequest, ShareRequest

ROOT = Path(__file__).resolve().parents[2]
STORAGE = ROOT / "data" / "encrypted"
STORAGE.mkdir(parents=True, exist_ok=True)
SESSION_COOKIE = "cipherdrop_session"
SESSION_HOURS = 12
MAX_FILE_BYTES = 100 * 1024 * 1024
ph = PasswordHasher()

app = FastAPI(title="CipherDrop API", version="0.3.0")
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
    return user

def create_session(response: Response, user: User, db: DBSession):
    raw = secrets.token_urlsafe(32)
    expires = datetime.now(timezone.utc) + timedelta(hours=SESSION_HOURS)
    db.add(Session(user_id=user.id, token_hash=hash_token(raw), expires_at=expires))
    db.commit()
    response.set_cookie(
        SESSION_COOKIE, raw, httponly=True, samesite="lax", secure=False,
        max_age=SESSION_HOURS * 3600, path="/"
    )

@app.get("/api/health")
def health():
    return {"status": "ok", "version": "0.3.0"}

@app.post("/api/auth/register", status_code=201)
def register(body: RegisterRequest, response: Response, db: DBSession = Depends(get_db)):
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
    create_session(response, user, db)
    return {"id": user.id, "username": user.username}

@app.post("/api/auth/login")
def login(body: LoginRequest, response: Response, db: DBSession = Depends(get_db)):
    user = db.scalar(select(User).where(User.username == body.username.strip().lower()))
    if not user:
        raise HTTPException(401, "Invalid username or password")
    try:
        ph.verify(user.password_hash, body.password)
    except VerifyMismatchError:
        raise HTTPException(401, "Invalid username or password")
    if ph.check_needs_rehash(user.password_hash):
        user.password_hash = ph.hash(body.password)
    create_session(response, user, db)
    return {"id": user.id, "username": user.username}

@app.post("/api/auth/logout", status_code=204)
def logout(request: Request, response: Response, db: DBSession = Depends(get_db)):
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        row = db.scalar(select(Session).where(Session.token_hash == hash_token(token)))
        if row:
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
        for share in list(row.shares):
            db.delete(share)
        row.object_name = new_object_name
        row.encrypted_filename = encrypted_filename
        row.filename_iv = filename_iv
        row.file_iv = file_iv
        row.wrapped_dek = wrapped_dek
        row.dek_wrap_iv = dek_wrap_iv
        row.size_bytes = len(data)
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
    share = FileShare(
        file_id=file_id, owner_id=user.id, recipient_id=recipient.id,
        wrapped_dek=body.wrapped_dek, dek_wrap_iv=body.dek_wrap_iv,
        encrypted_filename=body.encrypted_filename, filename_iv=body.filename_iv,
        hkdf_salt=body.hkdf_salt,
    )
    db.add(share)
    db.commit()
    db.refresh(share)
    return {"id": share.id, "recipient": recipient.username}

@app.get("/api/shared")
def shared_with_me(user: User = Depends(current_user), db: DBSession = Depends(get_db)):
    shares = db.scalars(select(FileShare).where(FileShare.recipient_id == user.id).order_by(FileShare.created_at.desc())).all()
    result = []
    for share in shares:
        file_row = db.get(FileRecord, share.file_id)
        owner = db.get(User, share.owner_id)
        owner_profile = db.scalar(select(UserCryptoProfile).where(UserCryptoProfile.user_id == share.owner_id))
        if not file_row or not owner or not owner_profile:
            continue
        result.append({
            "id": share.id,
            "file_id": file_row.id,
            "owner_username": owner.username,
            "sender_public_key_jwk": owner_profile.public_key_jwk,
            "encrypted_filename": share.encrypted_filename,
            "filename_iv": share.filename_iv,
            "file_iv": file_row.file_iv,
            "wrapped_dek": share.wrapped_dek,
            "dek_wrap_iv": share.dek_wrap_iv,
            "hkdf_salt": share.hkdf_salt,
            "size_bytes": file_row.size_bytes,
            "created_at": share.created_at,
        })
    return result

@app.get("/api/shared/{share_id}/blob")
def download_shared_blob(share_id: int, user: User = Depends(current_user), db: DBSession = Depends(get_db)):
    share = db.scalar(select(FileShare).where(FileShare.id == share_id, FileShare.recipient_id == user.id))
    if not share:
        raise HTTPException(404, "Shared file not found")
    file_row = db.get(FileRecord, share.file_id)
    if not file_row:
        raise HTTPException(410, "Shared file record is missing")
    path = STORAGE / file_row.object_name
    if not path.exists():
        raise HTTPException(410, "Encrypted object is missing")
    return FileResponse(path, media_type="application/octet-stream", filename=f"shared-{share_id}.enc")
