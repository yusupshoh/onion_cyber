"""
VAULT XIZMATI - alohida jarayon (faqat 127.0.0.1).

Bu xizmat quyidagilarni BAJARADI va Chegara xizmatiga HECH QACHON bermaydi:
  - parolni tekshirish (Argon2id + pepper)
  - access tokenni Ed25519 bilan IMZOLASH (maxfiy kalit shu yerda)
  - refresh tokenlarni saqlash/aylantirish/bekor qilish
Chegara xizmati faqat natijani (token satrlarini) oladi va public kalitni biladi.

Ichki so'rovlar HMAC bilan imzolanadi; imzoga metod va yo'l ham kiradi (bir
endpoint uchun imzolangan so'rovni boshqasiga ko'chirib bo'lmaydi). Imzo
tekshirilGUNCHA body'ga tegilmaydi (validatsiya imzodan KEYIN).

Foydalanuvchi yaratish HTTP orqali MUMKIN EMAS - u faqat scripts/create_user.py
orqali, Vault to'xtatilgan holda, administrator tomonidan qilinadi.
"""
import asyncio
import hashlib
import hmac
import os
import time
from collections import deque
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel, Field, ValidationError

from vault import tokens
from vault.hardening import harden_process
from vault.passphrase import get_admin_passphrase
from vault import user_store
from vault.login_throttle import LoginThrottle
from vault.vault_core import (
    unlock_vault, persist_vault, rotate_data_key, check_runtime_integrity, alert,
    UnlockedVault,
)

_vault: UnlockedVault | None = None
_throttle = LoginThrottle()
# Argon2 (64 MB) bir vaqtda ko'p ishlamasligi uchun (xotira DoS'ga qarshi)
_argon_slots = asyncio.Semaphore(int(os.environ.get("ARGON_CONCURRENCY", 4)))
_signing_key = None
_watchdog_task: asyncio.Task | None = None

INTEGRITY_CHECK_INTERVAL = float(os.environ.get("INTEGRITY_CHECK_INTERVAL_SECONDS", 30))

# Imzosi noto'g'ri so'rovlar: bu "kimdir Vault'ga bevosita kirmoqchi" signali.
# MUHIM: bu kalit OSHKOR BO'LGANINI bildirmaydi (HMAC kaliti taxmin qilib
# bo'lmaydi), shuning uchun kalit ALMASHTIRILMAYDI - faqat alert beriladi.
_bad_signature_log: deque[float] = deque()
BAD_SIGNATURE_WINDOW = 60
BAD_SIGNATURE_THRESHOLD = 3

REPLAY_WINDOW_SECONDS = 10
_seen_nonces: dict[str, float] = {}


def _internal_signing_key() -> bytes:
    key = os.environ.get("INTERNAL_SIGNING_KEY")
    if not key:
        raise RuntimeError("INTERNAL_SIGNING_KEY o'rnatilmagan")
    return key.encode("utf-8")


def _record_bad_signature() -> None:
    now = time.time()
    _bad_signature_log.append(now)
    while _bad_signature_log and now - _bad_signature_log[0] > BAD_SIGNATURE_WINDOW:
        _bad_signature_log.popleft()
    if len(_bad_signature_log) >= BAD_SIGNATURE_THRESHOLD:
        alert(f"Vault'ga imzosiz/xato so'rovlar ko'paydi ({len(_bad_signature_log)} ta "
              f"{BAD_SIGNATURE_WINDOW}s ichida) - Chegara xizmatini chetlab o'tishga urinish ehtimoli.")
        _bad_signature_log.clear()


def _verify_internal_signature(request: Request, body: bytes) -> None:
    timestamp = request.headers.get("X-Timestamp")
    nonce = request.headers.get("X-Nonce")
    signature = request.headers.get("X-Signature")

    if not (timestamp and nonce and signature):
        _record_bad_signature()
        raise HTTPException(status_code=401, detail="Ichki autentifikatsiya sarlavhalari yo'q")

    now = time.time()
    try:
        ts = float(timestamp)
    except ValueError:
        _record_bad_signature()
        raise HTTPException(status_code=401, detail="Noto'g'ri vaqt tamg'asi")

    if abs(now - ts) > REPLAY_WINDOW_SECONDS:
        _record_bad_signature()
        raise HTTPException(status_code=401, detail="So'rov eskirgan (replay ehtimoli)")

    for n, t in list(_seen_nonces.items()):
        if now - t > REPLAY_WINDOW_SECONDS * 2:
            del _seen_nonces[n]

    if nonce in _seen_nonces:
        _record_bad_signature()
        raise HTTPException(status_code=401, detail="Nonce takrorlangan (replay hujumi)")

    message = f"{timestamp}.{nonce}.{request.method}.{request.url.path}.".encode() + body
    expected = hmac.new(_internal_signing_key(), message, hashlib.sha256).hexdigest()

    if not hmac.compare_digest(expected, signature):
        _record_bad_signature()
        raise HTTPException(status_code=401, detail="Imzo mos kelmadi")

    _seen_nonces[nonce] = now


async def _integrity_watchdog() -> None:
    """
    Ishlab turgan Vault fayllarni RAM'dagi haqiqiy nusxa bilan solishtiradi.
    Farq topilsa: alert + DK almashtirish + fayllarni RAM'dan qayta yozish.
    (Bu haqiqiy avtomatik javob; ishga tushishdagi tamper'da esa Vault
    ochilmaydi, chunki RAM'da hali nusxa yo'q.)
    """
    global _vault
    while True:
        await asyncio.sleep(INTEGRITY_CHECK_INTERVAL)
        if _vault is None:
            continue
        try:
            fixable, warn_only = check_runtime_integrity(_vault)
            for w in warn_only:
                alert(f"Statik fayl muammosi: {w}")
            if fixable:
                alert("Runtime yaxlitlik buzilishi: " + "; ".join(fixable))
                _vault = rotate_data_key(_vault, reason="runtime tamper: " + "; ".join(fixable), force=True)
        except Exception as exc:  # watchdog hech qachon jimgina o'lmasligi kerak
            alert(f"Integrity watchdog xatosi: {exc!r}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _vault, _signing_key, _watchdog_task
    _internal_signing_key()  # yo'q bo'lsa, darhol yiqilsin
    harden_process()
    passphrase = get_admin_passphrase()
    _vault = unlock_vault(passphrase)
    del passphrase

    _signing_key, created = tokens.load_or_create_signing_key(_vault.conn)
    if created:
        persist_vault(_vault)
        print("[VAULT] Yangi JWT imzolash kaliti yaratildi (Ed25519).")
    await asyncio.to_thread(user_store.dummy_hash)  # timing tenglashtirish uchun oldindan hisoblab qo'yamiz

    _watchdog_task = asyncio.create_task(_integrity_watchdog())
    print("[VAULT] Xizmat tayyor - baza RAM'da ochildi.")
    try:
        yield
    finally:
        if _watchdog_task:
            _watchdog_task.cancel()


app = FastAPI(title="Muallim Vault (ichki xizmat)", lifespan=lifespan)


class LoginPayload(BaseModel):
    email: str = Field(max_length=320)
    password: str = Field(max_length=256)
    source: str = Field(default="unknown", max_length=64)  # mijoz IP (chegara xizmati aniqlaydi)


class RefreshPayload(BaseModel):
    refresh_token: str = Field(max_length=256)


def _parse(model, body: bytes):
    try:
        return model.model_validate_json(body)
    except ValidationError:
        raise HTTPException(status_code=422, detail="Noto'g'ri so'rov formati")


def _ready() -> UnlockedVault:
    if _vault is None or _signing_key is None:
        raise HTTPException(status_code=503, detail="Vault hali tayyor emas")
    return _vault


def _persist() -> None:
    """HAR DOIM global _vault'ni saqlaydi: handler await'dan keyin watchdog DK'ni
    almashtirgan bo'lishi mumkin, eski obyekt bilan yozish bazani buzardi."""
    persist_vault(_ready())


def _token_bundle(user_id: int, email: str, refresh_raw: str) -> dict:
    access, expires_in = tokens.create_access_token(_signing_key, user_id, email)
    return {
        "result": "ok",
        "access_token": access,
        "expires_in": expires_in,
        "refresh_token": refresh_raw,
        "refresh_expires_in": tokens.REFRESH_TTL,
    }


@app.post("/internal/login")
async def internal_login(request: Request):
    body = await request.body()
    _verify_internal_signature(request, body)
    _ready()
    payload = _parse(LoginPayload, body)

    email = payload.email.strip().lower()
    src_hash = user_store.source_hash(payload.source)
    row = user_store.get_user_row(_vault.conn, email)
    known = row is not None and user_store.is_known_source(_vault.conn, row[0], src_hash)

    retry = _throttle.check(email, src_hash, known)
    if retry is not None:
        # Mavjud va mavjud bo'lmagan email uchun BIR XIL javob (enumeration yo'q)
        return {"result": "locked", "retry_after": retry}

    # Mavjud bo'lmagan email uchun ham aynan bitta Argon2 verify (soxta hash bilan)
    stored_hash = row[1] if row else user_store.dummy_hash()
    async with _argon_slots:
        ok = await asyncio.to_thread(user_store.check_password, stored_hash, payload.password)
    ok = ok and row is not None

    if not ok:
        _throttle.record_failure(email, src_hash)
        return {"result": "invalid"}

    user_id = row[0]
    if user_store.needs_rehash(stored_hash):
        async with _argon_slots:
            new_hash = await asyncio.to_thread(user_store.hash_password, payload.password)
        user_store.update_password_hash(_ready().conn, user_id, new_hash)

    _throttle.record_success(email, src_hash)
    conn = _ready().conn
    user_store.remember_source(conn, user_id, src_hash)
    refresh_raw = tokens.issue_refresh_token(conn, user_id)
    _persist()
    return _token_bundle(user_id, email, refresh_raw)


@app.post("/internal/refresh")
async def internal_refresh(request: Request):
    body = await request.body()
    _verify_internal_signature(request, body)
    vault = _ready()
    payload = _parse(RefreshPayload, body)

    try:
        user_id, email, new_raw = tokens.rotate_refresh_token(vault.conn, payload.refresh_token)
    except tokens.RefreshTokenTheftDetected as exc:
        _persist()
        alert(f"Refresh token qayta ishlatildi (o'g'irlik signali): user_id={exc}; barcha sessiyalar bekor qilindi.")
        return {"result": "theft"}
    except tokens.RefreshTokenInvalid:
        return {"result": "invalid"}

    _persist()
    return _token_bundle(user_id, email, new_raw)


@app.post("/internal/logout")
async def internal_logout(request: Request):
    body = await request.body()
    _verify_internal_signature(request, body)
    vault = _ready()
    payload = _parse(RefreshPayload, body)
    tokens.revoke_refresh_token(vault.conn, payload.refresh_token)
    _persist()
    return {"result": "ok"}


@app.get("/internal/public-key")
async def public_key():
    """Public kalit maxfiy emas - Chegara xizmati access tokenni tekshirishi uchun."""
    _ready()
    return {"alg": "EdDSA", "public_key_pem": tokens.public_key_pem(_signing_key)}


@app.get("/internal/health")
async def health():
    return {"status": "ok", "vault_unlocked": _vault is not None}
