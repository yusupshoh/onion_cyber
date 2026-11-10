"""
FAYLLARNI O'CHIRISHDAN/O'ZGARTIRISHDAN HIMOYA QILISH (immutable atribut)

MUHIM FARQ oldingi himoyalardan: HMAC/imzo yaxlitlik BUZILGANINI ANIQLAYDI
(tamper detection) - lekin buzilishning o'zini TO'XTATMAYDI (prevention).
Bu modul esa OS darajasida - hatto root foydalanuvchi ham, avval atributni
maxsus buyruq bilan olib tashlamasdan turib, faylni o'CHIRA yoki
O'ZGARTIRA OLMAYDI. Bu Linux ext2/3/4 fayl tizimlarida `chattr +i`
("immutable") atributi orqali amalga oshiriladi.

IKKI TOIFA:
  1. STATIK fayllar - sozlashdan keyin HECH QACHON o'zgarmaydi (keyring,
     passphrase tuzi, Shamir bo'laklari, integrity kaliti). Bular BIR
     MARTA immutable qilinadi va boshqa hech qachon tegilmaydi.
  2. DINAMIK fayllar - ishlash paytida o'zgarishi kerak (keyfile,
     secrets.db, attempt/rotation holat fayllari). Bular uchun
     `mutable_window()` context manager ishlatiladi: atribut vaqtincha
     olib tashlanadi, yozish amalga oshiriladi, atribut qayta o'rnatiladi.
     Bu oyna HAR DOIM log qilinadi - chunki himoyani vaqtincha
     "o'chirish" o'zi nozik operatsiya.

CHEKLOV (halol eslatma): bu FAQAT ext2/3/4 kabi fayl tizimlarida va
CAP_LINUX_IMMUTABLE huquqi (odatda root) borida ishlaydi. Docker'ning
overlay2 fayl tizimi, ba'zi tarmoq disklari (NFS) yoki boshqa OS'lar
(masalan, ba'zi bulut fayl tizimlari) buni qo'llab-quvvatlamasligi
mumkin. Shuning uchun bu funksiyalar xato chiqsa DARHOL, ANIQ
ogohlantirish beradi - jimgina "ishlamay qolish" emas.
"""
import subprocess
import sys
import time
from contextlib import contextmanager
from pathlib import Path


class ImmutabilityUnsupported(Exception):
    """Fayl tizimi yoki huquqlar immutable atributni qo'llab-quvvatlamaganda."""
    pass


def _run_chattr(args: list[str], path: Path) -> None:
    try:
        result = subprocess.run(
            ["chattr", *args, str(path)],
            capture_output=True, text=True, timeout=5,
        )
    except FileNotFoundError:
        raise ImmutabilityUnsupported(
            "'chattr' buyrug'i topilmadi - bu tizimda immutable himoya ISHLATIB BO'LMAYDI. "
            "Buning o'rniga papka darajasidagi ruxsat ajratishdan foydalaning (README'ga qarang)."
        )
    if result.returncode != 0:
        raise ImmutabilityUnsupported(
            f"chattr {' '.join(args)} {path} muvaffaqiyatsiz: {result.stderr.strip()}. "
            f"Fayl tizimi (masalan, overlay2/NFS) buni qo'llab-quvvatlamasligi mumkin."
        )


def is_immutable(path: Path) -> bool:
    return bool(immutable_set([path]))


def immutable_set(paths: list[Path]) -> set[Path]:
    """Berilgan fayllardan qaysilari immutable ekanini BITTA lsattr chaqiruvi bilan aniqlaydi."""
    existing = [p for p in paths if p.exists()]
    if not existing:
        return set()
    try:
        result = subprocess.run(["lsattr", "-d", *map(str, existing)], capture_output=True, text=True, timeout=5)
    except FileNotFoundError:
        return set()
    out: set[Path] = set()
    for line in result.stdout.splitlines():
        parts = line.split(None, 1)
        if len(parts) == 2 and "i" in parts[0]:
            out.add(Path(parts[1].strip()))
    return out


def make_immutable(path: Path, *, quiet: bool = False) -> bool:
    """
    True = muvaffaqiyatli o'rnatildi. False = tizim qo'llab-quvvatlamaydi
    (ogohlantirish chiqariladi, lekin dastur ishlashda davom etadi - chunki
    bu QO'SHIMCHA qatlam, yagona himoya emas: HMAC/imzo baribir ishlaydi).
    """
    try:
        _run_chattr(["+i"], path)
        return True
    except ImmutabilityUnsupported as exc:
        if not quiet:
            print(f"[OGOHLANTIRISH] Immutable himoya o'rnatilmadi ({path}): {exc}", file=sys.stderr)
        return False


@contextmanager
def mutable_window(paths, reason: str):
    """
    Immutable fayl(lar)ni VAQTINCHA yozish uchun ochadi, keyin qayta yopadi.
    Bir nechta fayl berilsa ham tizim chaqiruvlari soni o'zgarmaydi (lsattr 1 ta,
    chattr -i 1 ta, chattr +i 1 ta). Har bir oyna LOG QILINADI.
    """
    plist = [Path(paths)] if isinstance(paths, (str, Path)) else [Path(p) for p in paths]
    was = sorted(immutable_set(plist))
    if was:
        print(f"[IMMUTABLE] Vaqtincha ochilmoqda: {', '.join(p.name for p in was)} (sabab: {reason})")
        subprocess.run(["chattr", "-i", *map(str, was)], capture_output=True, timeout=5, check=True)
    try:
        yield
    finally:
        existing = [p for p in plist if p.exists()]
        ok = True
        if existing:
            try:
                r = subprocess.run(["chattr", "+i", *map(str, existing)], capture_output=True, timeout=5)
                ok = r.returncode == 0
            except FileNotFoundError:
                ok = False
        if was and ok:
            print(f"[IMMUTABLE] Qayta yopildi: {', '.join(p.name for p in was)}")
        elif was and not ok:
            print(f"[OGOHLANTIRISH] {', '.join(p.name for p in was)} qayta immutable qilinmadi!", file=sys.stderr)


def harden_all(paths: list[Path]) -> dict[str, bool]:
    """Fayllar ro'yxatini immutable qilishga urinadi, natijalarni qaytaradi."""
    results = {}
    for p in paths:
        if not p.exists():
            continue
        results[str(p)] = make_immutable(p)
    return results
