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

class CryptoProfileRequest(BaseModel):
    public_key_jwk: str = Field(min_length=20, max_length=4096)
    encrypted_private_key: str = Field(min_length=20, max_length=8192)
    private_key_iv: str = Field(min_length=8, max_length=128)

class ShareRequest(BaseModel):
    recipient_username: str = Field(min_length=3, max_length=64)
    wrapped_dek: str = Field(min_length=20, max_length=8192)
    dek_wrap_iv: str = Field(min_length=8, max_length=128)
    encrypted_filename: str = Field(min_length=1, max_length=8192)
    filename_iv: str = Field(min_length=8, max_length=128)
    hkdf_salt: str = Field(min_length=8, max_length=128)
