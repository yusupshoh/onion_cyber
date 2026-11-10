"""
ADMIN PASSPHRASE MANBASI

Muammo: passphrase VAULT_ENV_SECRET bilan bir xil muhitda (.env) tursa,
ikkalasi ham bitta joydan o'g'irlanadi va "ikki mustaqil manba" amalda bitta
bo'lib qoladi.

Shuning uchun tartib (birinchi topilgani ishlatiladi):

  1. ADMIN_PASSPHRASE_FILE - sir menejeri/tmpfs/Docker secret yo'li
     (fayl ruxsati 0600/0400 bo'lishi shart).
  2. ADMIN_PASSPHRASE env - FAQAT ALLOW_ENV_PASSPHRASE=1 bo'lsa (dev uchun),
     har safar ogohlantirish chiqadi.
  3. Interaktiv kiritish (getpass) - production uchun tavsiya etilgan:
     passphrase hech qayerda (diskda ham, muhitda ham) saqlanmaydi.
"""
import getpass
import os
import stat
import sys
from pathlib import Path


class PassphraseUnavailable(Exception):
    pass


def get_admin_passphrase(confirm: bool = False) -> str:
    file_path = os.environ.get("ADMIN_PASSPHRASE_FILE")
    if file_path:
        p = Path(file_path)
        if not p.is_file():
            raise PassphraseUnavailable(f"ADMIN_PASSPHRASE_FILE topilmadi: {p}")
        mode = stat.S_IMODE(p.stat().st_mode)
        if mode & 0o077:
            raise PassphraseUnavailable(f"{p} ruxsati juda ochiq ({oct(mode)}); 'chmod 600' qiling.")
        value = p.read_text().rstrip("\r\n")
        if not value:
            raise PassphraseUnavailable(f"{p} bo'sh.")
        return value

    env_value = os.environ.get("ADMIN_PASSPHRASE")
    if env_value and os.environ.get("ALLOW_ENV_PASSPHRASE") == "1":
        print("[PASSPHRASE][OGOHLANTIRISH] Passphrase muhit o'zgaruvchisidan olinmoqda - "
              "bu FAQAT development uchun. Production'da ADMIN_PASSPHRASE_FILE yoki "
              "interaktiv kiritishdan foydalaning.", file=sys.stderr)
        return env_value

    if sys.stdin is not None and sys.stdin.isatty():
        value = getpass.getpass("Vault administrator parolini kiriting: ")
        if confirm:
            if value != getpass.getpass("Parolni tasdiqlang: "):
                raise PassphraseUnavailable("Parollar mos kelmadi.")
        if not value:
            raise PassphraseUnavailable("Bo'sh parol qabul qilinmaydi.")
        return value

    raise PassphraseUnavailable(
        "Administrator passphrase berilmadi: terminal yo'q, ADMIN_PASSPHRASE_FILE o'rnatilmagan "
        "(dev uchun: ALLOW_ENV_PASSPHRASE=1 va ADMIN_PASSPHRASE)."
    )
