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
from .models import User, Session, FileRecord
from .schemas import RegisterRequest, LoginRequest

ROOT = Path(__file__).resolve().parents[2]
STORAGE = ROOT / "data" / "encrypted"
STORAGE.mkdir(parents=True, exist_ok=True)
SESSION_COOKIE = "cipherdrop_session"
SESSION_HOURS = 12
MAX_FILE_BYTES = 100 * 1024 * 1024
ph = PasswordHasher()

app = FastAPI(title="CipherDrop API", version="0.2.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE"],
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
    return {"status": "ok", "version": "0.2.0"}

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

@app.get("/api/files/{file_id}/blob")
def download_blob(file_id: int, user: User = Depends(current_user), db: DBSession = Depends(get_db)):
    row = db.scalar(select(FileRecord).where(FileRecord.id == file_id, FileRecord.owner_id == user.id))
    if not row:
        raise HTTPException(404, "File not found")
    path = STORAGE / row.object_name
    if not path.exists():
        raise HTTPException(410, "Encrypted object is missing")
    return FileResponse(path, media_type="application/octet-stream", filename=f"{file_id}.enc")
