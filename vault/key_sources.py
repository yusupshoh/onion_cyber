"""
7 MUSTAQIL MANBA - Key Encryption Key (KEK) shu yerda hosil bo'ladi.

To'rttasi - HAQIQIY KALIT MATERIALI (birlashtirilib KEK hosil qiladi):
  1. Muhit o'zgaruvchisi (.env, repo'da yo'q, deploy vaqtida beriladi)
  2. "OS keyring" - mahalliy, qattiq ruxsatli, alohida faylda saqlangan sir
     (production'da haqiqiy OS keyring/HSM/AWS KMS bilan almashtiriladi)
  3. Administrator parolidan Argon2id orqali hosil qilingan kalit
  4. Shamir bo'laklaridan tiklangan sir (3-of-5 threshold)

Uchtasi - GATE (o'tish shartlari, o'zi kalit material EMAS, lekin
ULARSIZ jarayon davom etmaydi):
  5. Fayl ruxsati/egaligi tekshiruvi (faqat xizmat foydalanuvchisi o'qiy oladi)
  6. HMAC yaxlitlik tekshiruvi (fayllar tashqi tomondan o'zgartirilmaganmi)
  7. Urinishlar sonini cheklash (KEK yig'ishga cheksiz urinib bo'lmaydi)

MUHIM: bitta manba (masalan, fayl o'g'irlash) sizib chiqishi YETARLI EMAS -
KEK faqat barcha to'rtta material bir joyga yig'ilgandagina hosil bo'ladi.
"""
import hashlib
import hmac
import json
import os
import stat
import time
from pathlib import Path

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from vault.shamir import reconstruct_secret
from vault import immutability as imm
from vault.fsutil import atomic_write


class GateError(Exception):
    """Gate (o'tish sharti) bajarilmaganda ko'tariladi."""
    pass


class TamperDetected(Exception):
    """
    HMAC imzosi mos kelmaganda ko'tariladi - bu FAQAT fayl tashqi tomondan
    o'zgartirilganda yuz beradi (HMAC kaliti parol/KEK'dan mustaqil, shuning
    uchun "noto'g'ri parol" bilan aralashmaydi). Bu haqiqiy hujum signali.
    """
    pass


# ---------------------------------------------------------------------------
# GATE 5: fayl ruxsati va egaligi tekshiruvi
# ---------------------------------------------------------------------------
_WARNED_WINDOWS = False


def check_file_permissions(path: Path, require_mode: int = 0o600) -> None:
    """
    Faylning (yoki papkaning) ruxsatlari juda keng bo'lsa - ya'ni guruh
    yoki boshqalar uchun HAR QANDAY ruxsat berilgan bo'lsa - jarayon
    to'xtaydi. Egasi uchun ruxsat require_mode orqali belgilanadi (fayllar
    uchun odatda 0o600, papkalar uchun 0o700 - execute bit kerak).
    Bu noto'g'ri konfiguratsiya qilingan serverda maxfiy fayllarning
    tasodifan oshkor bo'lishidan himoya qiladi.
    """
    if not path.exists():
        raise GateError(f"Fayl topilmadi: {path}")
    if os.name == "nt":
        # Windows'da POSIX ruxsat bitlari ma'noga ega emas (os.stat doim 0o666 kabi
        # qiymat beradi) - tekshiruv imkonsiz. Himoya uchun NTFS ACL'larni qo'lda
        # sozlang. Bu yerda faqat ogohlantirish beramiz va davom etamiz.
        global _WARNED_WINDOWS
        if not _WARNED_WINDOWS:
            print("[OGOHLANTIRISH] Windows: fayl ruxsati gate'i o'chirilgan (faqat dev uchun).")
            _WARNED_WINDOWS = True
        return
    mode = stat.S_IMODE(os.stat(path).st_mode)
    if mode & 0o077:  # guruh yoki boshqalar uchun har qanday ruxsat - har doim taqiqlanadi
        raise GateError(
            f"{path} juda ochiq ruxsatlarga ega ({oct(mode)}). "
            f"'chmod {oct(require_mode)[2:]} {path}' bajaring."
        )
    if mode & ~require_mode & 0o700:  # egasi uchun kutilmagan qo'shimcha bit (masalan execute fayl uchun)
        raise GateError(f"{path} egasi uchun kutilmagan ruxsat bitlari mavjud ({oct(mode)}).")


# ---------------------------------------------------------------------------
# GATE 7: urinishlar sonini cheklash (KEK yig'ish uchun brute-force'dan himoya)
#
# MUHIM TUZATISH: holat fayli (attempt_state.json) endi HMAC bilan
# imzolanadi VA uning yo'qligi "toza holat" (0 ta urinish) emas, balki
# SHUBHALI holat deb qaraladi. Shu bilan quyidagi zaiflik yopiladi:
#
#   Avvalgi variantda - agar hujumchi fayl tizimiga yozish huquqini
#   (5-qatlamni) allaqachon qandaydir yo'l bilan chetlab o'tgan bo'lsa,
#   u shunchaki attempt_state.json'ni O'CHIRIB, hisoblagichni nolga
#   tushirib qo'yishi mumkin edi - ya'ni 7-qatlam o'zi mustaqil emas,
#   5-qatlamga to'liq qaram edi.
#
#   Endi: fayl yo'q YOKI imzosi mos kelmasa (qo'lda tahrirlangan) -
#   tizim buni "0 ta urinish" deb EMAS, balki "standart uzoq bloklash"
#   deb talqin qiladi. Ya'ni faylni o'chirish endi hech qanday foyda
#   bermaydi - aksincha, eng qattiq bloklashni keltirib chiqaradi.
# ---------------------------------------------------------------------------
class AttemptThrottle:
    def __init__(
        self,
        state_file: Path,
        integrity_key: bytes,
        max_attempts: int = 5,
        lockout_seconds: int = 300,
        missing_or_tampered_lockout_seconds: int = 3600,
    ):
        self.state_file = state_file
        self.integrity_key = integrity_key
        self.max_attempts = max_attempts
        self.lockout_seconds = lockout_seconds
        self.missing_or_tampered_lockout_seconds = missing_or_tampered_lockout_seconds

    def _sign(self, failures: int, locked_until: float) -> str:
        payload = f"{failures}:{locked_until}".encode()
        return hmac.new(self.integrity_key, payload, hashlib.sha256).hexdigest()

    def _read_state(self) -> tuple[dict, bool]:
        """
        Qaytaradi: (state, suspicious)
        suspicious=True bo'lsa - fayl yo'q yoki imzosi mos kelmagan degani.
        """
        if not self.state_file.exists():
            return {"failures": 0, "locked_until": 0}, True

        try:
            raw = json.loads(self.state_file.read_text())
            failures = raw["failures"]
            locked_until = raw["locked_until"]
            sig = raw["sig"]
        except (json.JSONDecodeError, OSError, KeyError):
            return {"failures": 0, "locked_until": 0}, True

        expected_sig = self._sign(failures, locked_until)
        if not hmac.compare_digest(expected_sig, sig):
            return {"failures": 0, "locked_until": 0}, True

        return {"failures": failures, "locked_until": locked_until}, False

    def _write_state(self, state: dict) -> None:
        sig = self._sign(state["failures"], state["locked_until"])
        with imm.mutable_window(self.state_file, reason="urinishlar hisoblagichi yangilanmoqda"):
            self.state_file.write_text(json.dumps({**state, "sig": sig}))
            os.chmod(self.state_file, 0o600)

    def check(self) -> None:
        state, suspicious = self._read_state()
        if suspicious:
            # Fayl yo'q yoki imzosi mos kelmadi - bu "0 ta urinish" DEGANI EMAS.
            # Buni darhol jazolaymiz (uzoq standart bloklash) va yuqoriga
            # signal beramiz - chaqiruvchi kod buni tamper sifatida ko'rib,
            # favqulodda kalit almashtirishni ko'rib chiqishi mumkin.
            self._write_state({
                "failures": 0,
                "locked_until": time.time() + self.missing_or_tampered_lockout_seconds,
            })
            raise TamperDetected(
                f"{self.state_file} topilmadi yoki imzosi mos kelmadi - "
                f"tashqi aralashuv shubhasi. {self.missing_or_tampered_lockout_seconds}s bloklandi."
            )
        if time.time() < state.get("locked_until", 0):
            remaining = int(state["locked_until"] - time.time())
            raise GateError(f"Juda ko'p muvaffaqiyatsiz urinish. {remaining} soniyadan keyin qayta urining.")

    def record_failure(self) -> None:
        state, suspicious = self._read_state()
        if suspicious:
            # check() allaqachon bloklagan bo'lishi kerak, lekin har ehtimolga
            # qarshi shu yerda ham xavfsiz (punitive) holatni yozib qo'yamiz.
            self._write_state({
                "failures": 0,
                "locked_until": time.time() + self.missing_or_tampered_lockout_seconds,
            })
            return
        state["failures"] = state.get("failures", 0) + 1
        if state["failures"] >= self.max_attempts:
            state["locked_until"] = time.time() + self.lockout_seconds
            state["failures"] = 0
        self._write_state(state)

    def record_success(self) -> None:
        self._write_state({"failures": 0, "locked_until": 0})

    def initialize_clean_state(self) -> None:
        """Faqat `initialize_vault()` paytida, birinchi marta imzolangan 'toza' holatni yozish uchun."""
        self._write_state({"failures": 0, "locked_until": 0})


# ---------------------------------------------------------------------------
# GATE 6: HMAC yaxlitlik tekshiruvi
# ---------------------------------------------------------------------------
def compute_hmac(data: bytes, hmac_key: bytes) -> str:
    return hmac.new(hmac_key, data, hashlib.sha256).hexdigest()


def _hmac_path(path: Path) -> Path:
    return path.with_suffix(path.suffix + ".hmac")


def read_integrity_lines(path: Path) -> list[str]:
    hp = _hmac_path(path)
    if not hp.exists():
        return []
    return [l.strip() for l in hp.read_text().splitlines() if l.strip()]


def verify_file_integrity(path: Path, hmac_key: bytes) -> None:
    """
    <fayl>.hmac ichidagi imzo(lar) bilan solishtiradi. Fayl 1 YOKI 2 imzo
    saqlashi mumkin: yozish paytida (stage_integrity) yangi va eski imzo
    birga turadi, shuning uchun yozish o'rtasida jarayon to'xtasa ham fayl
    "buzilgan" deb qaralmaydi (crash-safe).
    """
    hp = _hmac_path(path)
    lines = read_integrity_lines(path)
    if not lines:
        raise GateError(f"{hp} topilmadi yoki bo'sh - yaxlitlik imzosi mavjud emas")
    actual = compute_hmac(path.read_bytes(), hmac_key)
    if not any(hmac.compare_digest(l, actual) for l in lines):
        raise TamperDetected(f"{path} yaxlitligi BUZILGAN - fayl kutilmagan tarzda o'zgargan!")


def stage_integrity(path: Path, hmac_key: bytes, new_data: bytes) -> None:
    """Faylni YOZISHDAN OLDIN chaqiring: yangi imzoni eskisi bilan birga yozadi."""
    old = read_integrity_lines(path)[:1]
    new = compute_hmac(new_data, hmac_key)
    lines = [new] + [o for o in old if o != new]
    atomic_write(_hmac_path(path), ("\n".join(lines)).encode())


def write_file_integrity(path: Path, hmac_key: bytes) -> None:
    """Fayl yozilgandan KEYIN chaqiring: faqat joriy fayl imzosini qoldiradi."""
    atomic_write(_hmac_path(path), compute_hmac(path.read_bytes(), hmac_key).encode())


# ---------------------------------------------------------------------------
# KALIT MATERIALI MANBALARI (1, 2, 3, 4)
# ---------------------------------------------------------------------------
def source_env_secret() -> bytes:
    """1-manba: muhit o'zgaruvchisi."""
    val = os.environ.get("VAULT_ENV_SECRET")
    if not val:
        raise GateError("VAULT_ENV_SECRET muhit o'zgaruvchisi topilmadi")
    return val.encode("utf-8")


def source_os_keyring(keyring_file: Path) -> bytes:
    """
    2-manba: "OS keyring" o'rnini bosuvchi. Production'da bu yerda haqiqiy
    OS keyring (`keyring` python paketi) yoki KMS/HSM chaqiruvi bo'ladi.
    """
    check_file_permissions(keyring_file)
    return keyring_file.read_bytes()


def source_passphrase_kdf(passphrase: str, salt: bytes) -> bytes:
    """
    3-manba: administrator parolidan Argon2id orqali 32 baytli kalit hosil
    qilish. Parolning o'zi hech qayerda saqlanmaydi - faqat runtime'da
    kiritiladi (yoki avtomatlashtirilgan muhitda ADMIN_PASSPHRASE env orqali).
    """
    if not passphrase:
        raise GateError("Administrator parol (passphrase) berilmadi")
    return hash_secret_raw(
        secret=passphrase.encode("utf-8"),
        salt=salt,
        time_cost=3,
        memory_cost=65536,  # 64 MB
        parallelism=2,
        hash_len=32,
        type=Type.ID,
    )


def source_shamir_shares(locations: list[Path], threshold: int = 3) -> bytes:
    """
    4-manba: Shamir bo'laklaridan tiklangan sir.

    `locations` - papkalar (ichida share_*.json) yoki to'g'ridan-to'g'ri
    share fayllari ro'yxati. Production'da bo'laklar TURLI joylarda
    (alohida USB/mount, boshqa server, boshqa administrator) turishi kerak -
    aks holda 3-of-5 sxemasi hech narsa bermaydi. Mavjud bo'lmagan joy
    (masalan, ulanmagan USB) jim o'tkazib yuboriladi; yetarli bo'lak
    yig'ilmasagina xato beriladi.
    """
    found: dict[int, bytes] = {}
    missing: list[str] = []
    for loc in locations:
        if loc.is_dir():
            check_file_permissions(loc, require_mode=0o700)
            files = sorted(loc.glob("share_*.json"))
        elif loc.is_file():
            files = [loc]
        else:
            missing.append(str(loc))
            continue
        for f in files:
            check_file_permissions(f)
            obj = json.loads(f.read_text())
            found.setdefault(int(obj["index"]), bytes.fromhex(obj["value"]))

    if len(found) < threshold:
        raise GateError(
            f"Shamir bo'laklari yetarli emas: {len(found)} ta topildi, kamida {threshold} ta kerak"
            + (f" (topilmagan joylar: {', '.join(missing)})" if missing else "")
        )
    return reconstruct_secret(sorted(found.items())[:threshold])


# ---------------------------------------------------------------------------
# HAMMASINI BIRLASHTIRISH -> KEK
# ---------------------------------------------------------------------------
def derive_kek(env_secret: bytes, keyring_secret: bytes, passphrase_key: bytes, shamir_secret: bytes) -> bytes:
    """
    To'rtta mustaqil kalit materialini HKDF orqali bitta 256-bitli
    Key Encryption Key'ga birlashtiradi. HKDF - bu ko'p manbali kalit
    materialini xavfsiz "aralashtirish" uchun standart usul (RFC 5869).
    """
    combined = env_secret + b"|" + keyring_secret + b"|" + passphrase_key + b"|" + shamir_secret
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"muallim-vault-kek-v1",
        info=b"key-encryption-key",
    )
    return hkdf.derive(combined)
