"""
CHEGARA XIZMATI (Border service) - foydalanuvchi bilan bevosita gaplashadigan
yagona nuqta. E'TIBOR: bu yerda HECH QANDAY kalit, HECH QANDAY shifrni ochish
mantig'i yo'q - hammasi Vault xizmatida (vault/service.py), alohida jarayonda.
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings, validate_settings
from app.middleware.security_headers import SecurityHeadersMiddleware
from app.middleware.cors_guard import BodySizeLimitMiddleware
from app.routes.auth import router as auth_router

validate_settings()

app = FastAPI(title="Muallim - Chegara xizmati (Auth API)")

# 1-qatlam
app.add_middleware(SecurityHeadersMiddleware)

# 2-qatlam
app.add_middleware(BodySizeLimitMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["POST"],
    allow_headers=["Content-Type"],
)

app.include_router(auth_router, prefix="/auth", tags=["auth"])


@app.get("/health")
async def health():
    return {"status": "ok"}
