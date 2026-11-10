"""
Foydalanuvchi yaratish - ADMINISTRATIV, OFFLAYN amal.

Vault'ning HTTP API'sida foydalanuvchi yaratish endpoint'i yo'q (chegara xizmati
buzilsa, hujumchi o'ziga akkaunt ochib ololmasligi uchun). Shuning uchun bu
skript Vault xizmati TO'XTATILGAN holda ishga tushiriladi: u bazani ochadi,
foydalanuvchini qo'shadi va qayta shifrlab saqlaydi. Xizmat ishlab turgan
bo'lsa, skript rad etadi (aks holda xizmatning RAM nusxasi o'zgarishni
ustidan yozib yuborardi).

Ishlatish: python scripts/create_user.py email@example.uz
(parol terminalda so'raladi - buyruq qatori/tarixida qolmaydi)
"""
import getpass
import os
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vault.passphrase import get_admin_passphrase, PassphraseUnavailable
from vault.vault_core import unlock_vault, persist_vault, VaultError
from vault.user_store import create_user


def _vault_service_running() -> bool:
    url = os.environ.get("VAULT_URL", "http://127.0.0.1:8500") + "/internal/health"
    try:
        urllib.request.urlopen(url, timeout=1)
        return True
    except Exception:
        return False


def main():
    if len(sys.argv) < 2:
        print("Ishlatish: python scripts/create_user.py email@example.uz")
        sys.exit(1)
    email = sys.argv[1]

    if _vault_service_running():
        print("XATO: Vault xizmati ishlab turibdi. Avval uni to'xtating, so'ng qayta urining.")
        sys.exit(1)

    password = getpass.getpass(f"{email} uchun parol (kamida 8 belgi): ")
    if len(password) < 8 or password != getpass.getpass("Parolni tasdiqlang: "):
        print("XATO: parol juda qisqa yoki mos kelmadi.")
        sys.exit(1)

    try:
        vault = unlock_vault(get_admin_passphrase())
        create_user(vault.conn, email, password)
        persist_vault(vault)
    except (PassphraseUnavailable, VaultError) as exc:
        print(f"XATO: {exc}")
        sys.exit(1)
    print(f"Foydalanuvchi yaratildi: {email.strip().lower()}")


if __name__ == "__main__":
    main()
