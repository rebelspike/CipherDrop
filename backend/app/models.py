from datetime import datetime, timezone
from sqlalchemy import String, Integer, DateTime, ForeignKey, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from .database import Base

def now_utc():
    return datetime.now(timezone.utc)

class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(Text)
    vault_salt: Mapped[str] = mapped_column(Text)
    vault_wrap_iv: Mapped[str] = mapped_column(Text)
    wrapped_vault_key: Mapped[str] = mapped_column(Text)
    kdf_iterations: Mapped[int] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    sessions = relationship("Session", cascade="all, delete-orphan")
    files = relationship("FileRecord", cascade="all, delete-orphan")

class Session(Base):
    __tablename__ = "sessions"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))

class FileRecord(Base):
    __tablename__ = "files"
    id: Mapped[int] = mapped_column(primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    object_name: Mapped[str] = mapped_column(String(100), unique=True)
    encrypted_filename: Mapped[str] = mapped_column(Text)
    filename_iv: Mapped[str] = mapped_column(Text)
    file_iv: Mapped[str] = mapped_column(Text)
    wrapped_dek: Mapped[str] = mapped_column(Text)
    dek_wrap_iv: Mapped[str] = mapped_column(Text)
    size_bytes: Mapped[int] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
