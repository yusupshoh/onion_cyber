from pydantic import BaseModel, EmailStr, field_validator


class LoginRequest(BaseModel):
    email: EmailStr
    password: str

    @field_validator("password")
    @classmethod
    def password_length(cls, v: str) -> str:
        if len(v) < 8: raise ValueError("Parol kamida 8 belgidan iborat bo'lishi kerak")
        if len(v) > 256: raise ValueError("Parol juda uzun")
        return v

    model_config = {"str_max_length": 320}  # email uchun RFC chegarasi


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    @field_validator("password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        if len(v) < 8: raise ValueError("Parol kamida 8 belgidan iborat bo'lishi kerak")
        if len(v) > 256: raise ValueError("Parol juda uzun")
        if v.isdigit() or v.isalpha(): raise ValueError("Parol harf va raqamlar aralashmasidan iborat bo'lishi tavsiya etiladi")
        return v


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
