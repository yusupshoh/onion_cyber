"""
Konvert shifrlash (envelope encryption):

  secrets.db.enc  <-- Data Key (DK) bilan shifrlangan
  keyfile.enc     <-- DK ni Key Encryption Key (KEK) bilan shifrlangan holda saqlaydi
  KEK             <-- hech qayerda saqlanmaydi, har safar 4 mustaqil manbadan
                       qayta hosil qilinadi (key_sources.py'ga qarang)

Barcha shifrlash AES-256-GCM bilan (autentifikatsiyalangan shifrlash -
ma'lumot ham maxfiy, ham o'zgartirib bo'lmaydigan bo'ladi; fayl birror
bit o'zgartirilsa, ochishda xato chiqadi - bu HMAC yaxlitlik
tekshiruvi bilan bog'liq).
"""
import os
import struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_LEN = 12  # AES-GCM uchun tavsiya etilgan nonce uzunligi


def generate_key(length: int = 32) -> bytes:
    """256-bitli tasodifiy kalit generatsiya qilish (AES-256 uchun)."""
    return os.urandom(length)


def encrypt_bytes(plaintext: bytes, key: bytes, associated_data: bytes = b"") -> bytes:
    """
    plaintext -> [4 bayt versiya][12 bayt nonce][shifrlangan ma'lumot + 16 bayt GCM tag]

    associated_data - shifrlanmaydi, lekin yaxlitlik tekshiruviga kiradi
    (masalan, fayl nomi yoki maqsadi - noto'g'ri joyga "ko'chirib qo'yilgan"
    shifr matnni ochishga yo'l qo'ymaslik uchun).
    """
    aesgcm = AESGCM(key)
    nonce = os.urandom(NONCE_LEN)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
    version = struct.pack(">I", 1)
    return version + nonce + ciphertext


def decrypt_bytes(blob: bytes, key: bytes, associated_data: bytes = b"") -> bytes:
    if len(blob) < 4 + NONCE_LEN:
        raise ValueError("Shifrlangan blok juda qisqa - buzilgan yoki noto'g'ri fayl")
    version = struct.unpack(">I", blob[:4])[0]
    if version != 1:
        raise ValueError(f"Noma'lum shifrlash versiyasi: {version}")
    nonce = blob[4:4 + NONCE_LEN]
    ciphertext = blob[4 + NONCE_LEN:]
    aesgcm = AESGCM(key)
    try:
        return aesgcm.decrypt(nonce, ciphertext, associated_data)
    except Exception as exc:
        # MUHIM: bu yerda "kalit noto'g'ri" (oddiy, kutilishi mumkin bo'lgan holat -
        # masalan administrator parolni xato kiritdi) va "fayl buzilgan" (haqiqiy
        # yaxlitlik hujumi) FARQLANMAYDI - AES-GCM ikkalasida ham bir xil xato
        # beradi. Shu sabab bu DecryptionError - "tamper" degan xulosa faqat
        # alohida HMAC tekshiruvidan (key_sources.verify_file_integrity) kelishi
        # kerak, bu yerdan emas.
        raise DecryptionError("Shifrni ochib bo'lmadi - kalit noto'g'ri yoki ma'lumot buzilgan") from exc


class DecryptionError(Exception):
    """AEAD shifrni ochishda xato (noto'g'ri kalit YOKI buzilgan ma'lumot - farqlanmaydi)."""
    pass
