from pydantic import BaseModel, Field

class RegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")
    password: str = Field(min_length=10, max_length=256)
    vault_salt: str
    vault_wrap_iv: str
    wrapped_vault_key: str
    kdf_iterations: int = Field(ge=100_000, le=2_000_000)

class LoginRequest(BaseModel):
    username: str
    password: str

class FileMetadata(BaseModel):
    encrypted_filename: str
    filename_iv: str
    file_iv: str
    wrapped_dek: str
    dek_wrap_iv: str
