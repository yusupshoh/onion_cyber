"""
TOKENLAR - FAQAT VAULT ICHIDA.

Avvalgi dizaynda JWT sirlari va refresh-token bazasi Chegara xizmatida edi.
Chegara xizmatini egallagan hujumchi istalgan email uchun token yasay olardi.

Endi:
  - Access token Ed25519 (EdDSA) bilan Vault'da IMZOLANADI. Maxfiy kalit
    shifrlangan baza ichida turadi (server_keys jadvali) va hech qachon
    Vault'dan chiqmaydi. Chegara xizmatida faqat PUBLIC kalit bor - u token'ni
    tekshira oladi, lekin yarata olmaydi.
  - Refresh tokenlar ham Vault'ning shifrlangan bazasida (refresh_tokens).
    Chegara xizmati parolni to'g'ri kiritgan yoki amaldagi refresh tokenni
    ko'rsatgan foydalanuvchi uchungina token ola oladi - "istalgan email uchun"
    token so'rash imkoni yo'q.
"""
import hashlib
import os
import secrets
import sqlite3
import time
import uuid

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ACCESS_TTL = int(os.environ.get("ACCESS_TOKEN_TTL_SECONDS", 15 * 60))
REFRESH_TTL = int(os.environ.get("REFRESH_TOKEN_TTL_SECONDS", 7 * 24 * 60 * 60))
# Parallel so'rov (masalan, ikki brauzer tabi bir vaqtda refresh qilsa) o'g'irlik
# deb hisoblanmasligi uchun: yaqinda AYLANTIRILGAN token shu muddat ichida qayta
# ko'rsatilsa, yangi token beriladi (barcha sessiyalar bekor qilinmaydi).
# Kompromiss: o'g'ri token'ni aynan shu soniyalarda ishlatsa ham o'tadi.
REFRESH_GRACE_SECONDS = int(os.environ.get("REFRESH_GRACE_SECONDS", 10))
_SIGNING_KEY_NAME = "jwt_ed25519_private"


class RefreshTokenInvalid(Exception):
    pass


class RefreshTokenTheftDetected(Exception):
    pass


def load_or_create_signing_key(conn: sqlite3.Connection) -> tuple[Ed25519PrivateKey, bool]:
    """Qaytaradi: (kalit, yangi_yaratildimi). Yangi bo'lsa chaqiruvchi persist qilishi kerak."""
    row = conn.execute("SELECT value FROM server_keys WHERE name = ?", (_SIGNING_KEY_NAME,)).fetchone()
    if row:
        return serialization.load_pem_private_key(bytes(row[0]), password=None), False
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    conn.execute("INSERT INTO server_keys (name, value) VALUES (?, ?)", (_SIGNING_KEY_NAME, pem))
    conn.commit()
    return key, True


def public_key_pem(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


def create_access_token(key: Ed25519PrivateKey, user_id: int, email: str) -> tuple[str, int]:
    now = int(time.time())
    payload = {
        "sub": str(user_id), "email": email, "iat": now, "exp": now + ACCESS_TTL,
        "type": "access", "jti": uuid.uuid4().hex,
    }
    return jwt.encode(payload, key, algorithm="EdDSA"), ACCESS_TTL


def _hash(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def issue_refresh_token(conn: sqlite3.Connection, user_id: int) -> str:
    raw = secrets.token_urlsafe(48)
    conn.execute(
        "INSERT INTO refresh_tokens (token_hash, user_id, expires_at, revoked) VALUES (?, ?, ?, 0)",
        (_hash(raw), user_id, time.time() + REFRESH_TTL),
    )
    # eskirgan yozuvlarni vaqti-vaqti bilan tozalash (bazani shishirmaslik uchun)
    conn.execute("DELETE FROM refresh_tokens WHERE expires_at < ?", (time.time() - 86400,))
    conn.commit()
    return raw


def rotate_refresh_token(conn: sqlite3.Connection, raw: str) -> tuple[int, str, str]:
    """
    Qaytaradi: (user_id, email, yangi_raw_refresh). Eski token bekor qilinadi.
    Allaqachon bekor qilingan token qayta ko'rsatilsa - o'g'irlik signali:
    shu foydalanuvchining BARCHA refresh tokenlari bekor qilinadi.

    Atomiklik: Vault so'rovlari bitta event-loop oqimida, await'siz bajariladi,
    shuning uchun SELECT->UPDATE orasida boshqa so'rov aralasha olmaydi.
    """
    h = _hash(raw)
    row = conn.execute(
        "SELECT user_id, expires_at, revoked, revoked_at FROM refresh_tokens WHERE token_hash = ?", (h,)
    ).fetchone()
    if row is None:
        raise RefreshTokenInvalid("Token topilmadi")
    user_id, expires_at, revoked, revoked_at = row
    now = time.time()

    within_grace = False
    if revoked:
        if revoked == 2 and revoked_at and now - revoked_at <= REFRESH_GRACE_SECONDS and now <= expires_at:
            within_grace = True  # parallel so'rov, o'g'irlik emas
        else:
            conn.execute("UPDATE refresh_tokens SET revoked = 1, revoked_at = ? WHERE user_id = ?", (now, user_id))
            conn.commit()
            raise RefreshTokenTheftDetected(str(user_id))

    if now > expires_at:
        raise RefreshTokenInvalid("Token muddati tugagan")

    user = conn.execute("SELECT email FROM users WHERE id = ?", (user_id,)).fetchone()
    if user is None:
        raise RefreshTokenInvalid("Foydalanuvchi topilmadi")

    if not within_grace:
        conn.execute("UPDATE refresh_tokens SET revoked = 2, revoked_at = ? WHERE token_hash = ?", (now, h))
    new_raw = issue_refresh_token(conn, user_id)  # commit shu yerda
    return user_id, user[0], new_raw


def revoke_refresh_token(conn: sqlite3.Connection, raw: str) -> None:
    conn.execute("UPDATE refresh_tokens SET revoked = 1, revoked_at = ? WHERE token_hash = ?", (time.time(), _hash(raw)))
    conn.commit()
