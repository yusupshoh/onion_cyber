"""
ESKI vault'dagi Shamir bo'laklarini secrets/shamir_shares/ dan 5 ta alohida
joyga KO'CHIRADI (migratsiya). Vault xizmati to'xtatilgan bo'lishi kerak.

Ishlatish: python scripts/distribute_shares.py D1 D2 D3 D4 D5
Bo'lak i -> Di papkasiga ko'chiriladi, nusxa to'g'riligi tekshiriladi, keyin
asl fayl o'chiriladi. So'ng ishga tushirishda SHAMIR_SHARE_PATHS ni bering.
"""
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vault import immutability as imm
from vault.vault_core import SHAMIR_DIR, SHAMIR_TOTAL, _validate_share_dirs, VaultError


def main():
    dirs = [Path(a) for a in sys.argv[1:]]
    try:
        dirs = _validate_share_dirs(dirs)
    except VaultError as exc:
        print(f"XATO: {exc}")
        sys.exit(1)

    sources = [SHAMIR_DIR / f"share_{i}.json" for i in range(1, SHAMIR_TOTAL + 1)]
    missing = [str(s) for s in sources if not s.exists()]
    if missing:
        print(f"XATO: bo'laklar topilmadi: {missing}")
        sys.exit(1)

    for src, d in zip(sources, dirs):
        d.mkdir(parents=True, exist_ok=True)
        os.chmod(d, 0o700)
        dst = d / src.name
        data = src.read_bytes()
        dst.write_bytes(data)
        os.chmod(dst, 0o600)
        if json.loads(dst.read_text()) != json.loads(data):
            print(f"XATO: {dst} nusxasi mos kelmadi, to'xtatildi (asl fayllar saqlanib qoldi).")
            sys.exit(1)
        imm.make_immutable(dst)
        if imm.is_immutable(src):
            imm._run_chattr(["-i"], src)
        src.unlink()
        print(f"  {src.name} -> {dst}")

    try:
        SHAMIR_DIR.rmdir()
    except OSError:
        pass
    print("Tayyor. Endi Vault'ni ishga tushirishda SHAMIR_SHARE_PATHS ni bering "
          f"(kamida 3 ta joy, ajratgich '{os.pathsep}').")


if __name__ == "__main__":
    main()
