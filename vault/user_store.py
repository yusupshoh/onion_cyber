"""
Foydalanuvchi bilan ishlash: yaratish, parolni tekshirish.

Parollar Argon2id bilan hash qilinadi + "pepper" (server tomonidagi qo'shimcha
maxfiy qiymat, bazada saqlanmaydi) - baza sizib chiqsa ham pepper'siz hash'larni
offline buzib bo'lmaydi.

TUZILISH (event loop'ni bloklamaslik uchun):
  - get_user_row / known-source so'rovlari  -> SQLite, event-loop oqimida (tez)
  - check_password / hash_password          -> sof funksiyalar (DB'ga tegmaydi),
                                               thread-pool'da chaqiriladi
Bloklash (lockout) mantig'i login_throttle.py'da.
"""
import hashlib
import os
import sqlite3
import threading
import time

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHash, VerificationError

_ph = PasswordHasher(
    time_cost=3,
    memory_cost=65536,  # 64 MB
    parallelism=2,
    hash_len=32,
)

MAX_KNOWN_SOURCES_PER_USER = 10


def _pepper() -> str:
    pepper = os.environ.get("PASSWORD_PEPPER", "")
    if not pepper:
        raise RuntimeError("PASSWORD_PEPPER muhit o'zgaruvchisi o'rnatilmagan")
    return pepper


def hash_password(plain_password: str) -> str:
    return _ph.hash(plain_password + _pepper())


def check_password(password_hash: str, plain_password: str) -> bool:
    """Sof funksiya (thread-safe): DB'ga tegmaydi."""
    try:
        return _ph.verify(password_hash, plain_password + _pepper())
    except (VerifyMismatchError, InvalidHash, VerificationError):
        return False


def needs_rehash(password_hash: str) -> bool:
    try:
        return _ph.check_needs_rehash(password_hash)
    except InvalidHash:
        return False


# --- Timing/enumeration himoyasi: mavjud bo'lmagan email uchun ham AYNAN BIR XIL
# ish (bitta Argon2 verify) bajariladi. Soxta hash bir marta hisoblanadi.
_dummy_lock = threading.Lock()
_dummy_hash: str | None = None


def dummy_hash() -> str:
    global _dummy_hash
    with _dummy_lock:
        if _dummy_hash is None:
            _dummy_hash = hash_password("dummy-password-for-timing-equalization")
        return _dummy_hash


def create_user(conn: sqlite3.Connection, email: str, plain_password: str) -> None:
    email = email.strip().lower()
    now = time.time()
    conn.execute(
        "INSERT INTO users (email, password_hash, created_at, updated_at) VALUES (?, ?, ?, ?)",
        (email, hash_password(plain_password), now, now),
    )
    conn.commit()


def get_user_row(conn: sqlite3.Connection, email: str) -> tuple[int, str] | None:
    row = conn.execute("SELECT id, password_hash FROM users WHERE email = ?", (email.strip().lower(),)).fetchone()
    return (row[0], row[1]) if row else None


def update_password_hash(conn: sqlite3.Connection, user_id: int, new_hash: str) -> None:
    conn.execute("UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?", (new_hash, time.time(), user_id))
    conn.commit()


# --- Ma'lum manbalar (IP xeshi) ---------------------------------------------
def source_hash(source: str) -> str:
    return hashlib.sha256((_pepper() + "|src|" + source).encode()).hexdigest()[:32]


def is_known_source(conn: sqlite3.Connection, user_id: int, src_hash: str) -> bool:
    return conn.execute(
        "SELECT 1 FROM known_sources WHERE user_id = ? AND source_hash = ?", (user_id, src_hash)
    ).fetchone() is not None


def remember_source(conn: sqlite3.Connection, user_id: int, src_hash: str) -> None:
    now = time.time()
    conn.execute(
        "INSERT INTO known_sources (user_id, source_hash, last_seen) VALUES (?, ?, ?) "
        "ON CONFLICT(user_id, source_hash) DO UPDATE SET last_seen = excluded.last_seen",
        (user_id, src_hash, now),
    )
    conn.execute(
        "DELETE FROM known_sources WHERE user_id = ? AND source_hash NOT IN "
        "(SELECT source_hash FROM known_sources WHERE user_id = ? ORDER BY last_seen DESC LIMIT ?)",
        (user_id, user_id, MAX_KNOWN_SOURCES_PER_USER),
    )
    conn.commit()
