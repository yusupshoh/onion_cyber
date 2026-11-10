"""
Vault'ni noldan sozlash - FAQAT BIR MARTA, deploy paytida.

Production (tavsiya etilgan):
  python scripts/init_vault.py --share-dirs /mnt/usb1/s /mnt/usb2/s /srv/admin2/s /srv/admin3/s /srv/admin4/s
  (5 ta alohida joy: turli USB / server / administrator; hech biri secrets/ ichida emas)

Faqat dev/demo (Shamir foydasi YO'Q, hammasi bitta papkada):
  python scripts/init_vault.py --insecure-colocated-shares

Passphrase: ADMIN_PASSPHRASE_FILE, yoki (dev) ALLOW_ENV_PASSPHRASE=1 + ADMIN_PASSPHRASE,
yoki terminalda interaktiv so'raladi.
"""
import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vault.passphrase import get_admin_passphrase, PassphraseUnavailable
from vault.vault_core import initialize_vault, VaultError


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--share-dirs", nargs="+", type=Path, help="5 ta alohida papka (har biriga 1 ta Shamir bo'lagi)")
    ap.add_argument("--insecure-colocated-shares", action="store_true",
                    help="FAQAT dev: barcha bo'laklar secrets/shamir_shares/ ichida")
    args = ap.parse_args()

    if "VAULT_ENV_SECRET" not in os.environ:
        print("XATO: VAULT_ENV_SECRET muhit o'zgaruvchisi o'rnatilmagan.")
        print("Masalan: export VAULT_ENV_SECRET=$(python3 -c \"import secrets;print(secrets.token_hex(32))\")")
        sys.exit(1)

    try:
        passphrase = get_admin_passphrase(confirm=True)
        initialize_vault(
            passphrase,
            share_dirs=args.share_dirs,
            allow_colocated_shares=args.insecure_colocated_shares,
        )
    except (PassphraseUnavailable, VaultError) as exc:
        print(f"XATO: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
