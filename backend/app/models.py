from datetime import datetime, timezone
from sqlalchemy import String, Integer, DateTime, ForeignKey, Text, UniqueConstraint, Boolean
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
    crypto_profile = relationship("UserCryptoProfile", cascade="all, delete-orphan", uselist=False)

class Session(Base):
    __tablename__ = "sessions"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    user_agent: Mapped[str] = mapped_column(String(300), default="Unknown")
    ip_address: Mapped[str] = mapped_column(String(100), default="Unknown")
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)

class UserCryptoProfile(Base):
    __tablename__ = "user_crypto_profiles"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), unique=True, index=True)
    public_key_jwk: Mapped[str] = mapped_column(Text)
    encrypted_private_key: Mapped[str] = mapped_column(Text)
    private_key_iv: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)

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
    shares = relationship("FileShare", cascade="all, delete-orphan")

class FileShare(Base):
    __tablename__ = "file_shares"
    __table_args__ = (UniqueConstraint("file_id", "recipient_id", name="uq_file_recipient"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    file_id: Mapped[int] = mapped_column(ForeignKey("files.id"), index=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    recipient_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    wrapped_dek: Mapped[str] = mapped_column(Text)
    dek_wrap_iv: Mapped[str] = mapped_column(Text)
    encrypted_filename: Mapped[str] = mapped_column(Text)
    filename_iv: Mapped[str] = mapped_column(Text)
    hkdf_salt: Mapped[str] = mapped_column(Text)
    grantor_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    parent_share_id: Mapped[int | None] = mapped_column(ForeignKey("file_shares.id"), nullable=True, index=True)
    can_view: Mapped[bool] = mapped_column(Boolean, default=True)
    can_download: Mapped[bool] = mapped_column(Boolean, default=True)
    can_reshare: Mapped[bool] = mapped_column(Boolean, default=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)

class AuditEvent(Base):
    __tablename__ = "audit_events"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    event_type: Mapped[str] = mapped_column(String(80))
    resource_id: Mapped[str] = mapped_column(String(100), default="")
    result: Mapped[str] = mapped_column(String(20), default="success")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    previous_hash: Mapped[str] = mapped_column(String(64))
    event_hash: Mapped[str] = mapped_column(String(64))

class SecureLink(Base):
    __tablename__ = "secure_links"
    id: Mapped[int] = mapped_column(primary_key=True)
    file_id: Mapped[int] = mapped_column(ForeignKey("files.id"), index=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    encrypted_filename: Mapped[str] = mapped_column(Text)
    filename_iv: Mapped[str] = mapped_column(Text)
    wrapped_dek: Mapped[str] = mapped_column(Text)
    dek_wrap_iv: Mapped[str] = mapped_column(Text)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    max_downloads: Mapped[int] = mapped_column(Integer, default=1)
    download_count: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
