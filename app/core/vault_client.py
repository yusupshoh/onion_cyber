"""
5-6 QATLAM: VAULT BILAN IMZOLANGAN ALOQA

Chegara xizmati parolni ham, tokenni ham O'ZI tekshirmaydi/yaratmaydi.
U so'rovni Vault'ga uzatadi (HMAC bilan imzolab: vaqt tamg'asi + nonce +
metod + yo'l + body) va Vault qaytargan natijani foydalanuvchiga yetkazadi.

Chegara xizmati buzilgan taqdirda hujumchi:
  + kelayotgan parollarni ko'ra oladi (bu muqarrar - parol shu yerdan o'tadi)
  + Vault'dan "login"/"refresh" so'ray oladi, lekin FAQAT parolni bilgan yoki
    amaldagi refresh tokenga ega foydalanuvchi uchun
  - istalgan email uchun token YASAY OLMAYDI (imzolash kaliti Vault'da)
  - foydalanuvchi YARATA OLMAYDI (bunday endpoint yo'q)
"""
import hashlib
import hmac
import json
import time
import uuid

import httpx

from app.config import settings


class VaultUnavailable(Exception): pass


def _sign(method: str, path: str, body: bytes) -> dict[str, str]:
    timestamp = str(time.time())
    nonce = uuid.uuid4().hex
    message = f"{timestamp}.{nonce}.{method}.{path}.".encode() + body
    signature = hmac.new(settings.INTERNAL_SIGNING_KEY.encode("utf-8"), message, hashlib.sha256).hexdigest()
    return {"X-Timestamp": timestamp, "X-Nonce": nonce, "X-Signature": signature}


async def _post(path: str, payload: dict) -> dict:
    body = json.dumps(payload).encode("utf-8")
    headers = _sign("POST", path, body)
    headers["Content-Type"] = "application/json"
    try:
        async with httpx.AsyncClient(timeout=5.0) as client: resp = await client.post(f"{settings.VAULT_URL}{path}", content=body, headers=headers)
        resp.raise_for_status()
        return resp.json()
    except httpx.HTTPError as exc: raise VaultUnavailable(f"Vault xizmati bilan aloqa yo'q: {exc}") from exc


async def login(email: str, password: str, source: str = "unknown") -> dict: return await _post("/internal/login", {"email": email, "password": password, "source": source})
async def refresh(refresh_token: str) -> dict: return await _post("/internal/refresh", {"refresh_token": refresh_token})
async def logout(refresh_token: str) -> None: await _post("/internal/logout", {"refresh_token": refresh_token})
async def fetch_public_key() -> str:
    try:
        async with httpx.AsyncClient(timeout=5.0) as client: resp = await client.get(f"{settings.VAULT_URL}/internal/public-key")
        resp.raise_for_status()
        return resp.json()["public_key_pem"]
    except (httpx.HTTPError, KeyError) as exc: raise VaultUnavailable(f"Public kalitni olib bo'lmadi: {exc}") from exc
