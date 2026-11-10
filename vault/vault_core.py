"""
Vault yadrosi: KEK yig'ish -> keyfile.enc'ni ochish -> Data Key (DK) olish ->
secrets.db.enc'ni RAM'dagi sqlite bazaga ochish.

Baza HECH QACHON diskka ochiq (shifrlanmagan) holda yozilmaydi - faqat
sqlite3'ning `:memory:` bazasida turadi, `serialize()/deserialize()` orqali
xotira <-> shifrlangan fayl orasida o'giriladi.

HIMOYA MODELI (halol):
  * Diskdagi `secrets/` papkasi (yoki uning zaxira nusxasi) o'g'irlansa -
    KEK 4 ta mustaqil manbasiz tiklanmaydi (bu sxemaning haqiqiy kuchi).
  * Jarayon ishlab turganda hujumchi RAM'ga yetib borsa - KEK/DK u yerda,
    shuning uchun harden_process() (hardening.py) bunga to'siq qo'yadi, lekin
    root'ga qarshi kafolat bermaydi.
  * Ishlab turgan Vault fayllarning ruxsatsiz o'zgartirilganini RAM'dagi
    haqiqiy nusxa bilan solishtirib topadi va fayllarni RAM'dan qayta
    yozib TIKLAYDI (check_runtime_integrity / rotate_data_key).
"""
import hashlib
import json
import os
import sqlite3
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from vault import key_sources as ks
from vault import immutability as imm
from vault.fsutil import atomic_write
from vault.envelope import encrypt_bytes, decrypt_bytes, generate_key, DecryptionError

BASE_DIR = Path(__file__).resolve().parent.parent
SECRETS_DIR = Path(os.environ.get("VAULT_SECRETS_DIR") or (BASE_DIR / "secrets"))

KEYRING_FILE = SECRETS_DIR / "keyring.key"
PASSPHRASE_SALT_FILE = SECRETS_DIR / "passphrase.salt"
SHAMIR_DIR = SECRETS_DIR / "shamir_shares"  # FAQAT demo/dev rejimi uchun (colocated)
KEYFILE = SECRETS_DIR / "keyfile.enc"
SECRETS_DB = SECRETS_DIR / "secrets.db.enc"
INTEGRITY_KEY_FILE = SECRETS_DIR / "integrity.key"
ATTEMPT_STATE_FILE = SECRETS_DIR / "attempt_state.json"
ROTATION_STATE_FILE = SECRETS_DIR / "rotation_state.json"
KEYFILE_NEXT = SECRETS_DIR / "keyfile.enc.next"  # kalit almashtirish jurnali (crash-safe)
ALERT_LOG = SECRETS_DIR / "alerts.log"

SHAMIR_THRESHOLD = 3
SHAMIR_TOTAL = 5
ROTATION_MIN_INTERVAL_SECONDS = 60 * 60  # majburiy bo'lmagan almashtirish uchun


class VaultError(Exception):
    pass


@dataclass
class UnlockedVault:
    kek: bytes
    dk: bytes
    conn: sqlite3.Connection
    # Vault O'ZI oxirgi marta yozgan fayllarning SHA-256 izi (faqat RAM'da).
    # Diskdagi fayl bundan farq qilsa - kimdir tashqaridan o'zgartirgan.
    # Bu integrity.key'ga bog'liq emas (u ham shu papkada turadi).
    file_digests: dict = field(default_factory=dict)
    static_digests: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Yordamchilar
# ---------------------------------------------------------------------------
def alert(message: str) -> None:
    """Jiddiy hodisa: stderr'ga va alerts.log'ga yoziladi (monitoring shu faylni kuzatsin)."""
    line = f"[VAULT][ALERT] {message}"
    print(line, file=sys.stderr)
    try:
        with open(ALERT_LOG, "a") as f:
            f.write(f"{time.strftime('%Y-%m-%dT%H:%M:%S')} {message}\n")
        os.chmod(ALERT_LOG, 0o600)
    except OSError:
        pass


def shamir_locations() -> list[Path]:
    """SHAMIR_SHARE_PATHS (os.pathsep bilan ajratilgan) bo'lmasa - demo papka."""
    raw = os.environ.get("SHAMIR_SHARE_PATHS", "")
    paths = [Path(p) for p in raw.split(os.pathsep) if p.strip()]
    return paths or [SHAMIR_DIR]


_atomic_write = atomic_write


def _digest(path: Path) -> str | None:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def _hmac_path(p: Path) -> Path:
    return p.with_suffix(p.suffix + ".hmac")


def _dynamic_files() -> list[Path]:
    return [KEYFILE, SECRETS_DB, _hmac_path(KEYFILE), _hmac_path(SECRETS_DB)]


def _static_files() -> list[Path]:
    return [KEYRING_FILE, PASSPHRASE_SALT_FILE, INTEGRITY_KEY_FILE]


def _record_digests(vault: UnlockedVault) -> None:
    vault.file_digests = {p.name: _digest(p) for p in _dynamic_files()}


def ensure_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            failed_attempts INTEGER NOT NULL DEFAULT 0,
            locked_until REAL NOT NULL DEFAULT 0,
            created_at REAL NOT NULL,
            updated_at REAL NOT NULL
        );
        -- revoked: 0 = amalda, 1 = qat'iy bekor (logout/o'g'irlik), 2 = aylantirilgan
        -- (qisqa grace davrida qayta ko'rsatilsa - parallel tab, o'g'irlik emas)
        CREATE TABLE IF NOT EXISTS refresh_tokens (
            token_hash TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            expires_at REAL NOT NULL,
            revoked INTEGER NOT NULL DEFAULT 0,
            revoked_at REAL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS server_keys (
            name TEXT PRIMARY KEY,
            value BLOB NOT NULL
        );
        -- foydalanuvchi muvaffaqiyatli kirgan manbalar (IP xeshi): hisob-bo'yicha
        -- bloklash faqat NOMA'LUM manbalarga qo'llanadi (lockout-DoS'ga qarshi)
        CREATE TABLE IF NOT EXISTS known_sources (
            user_id INTEGER NOT NULL,
            source_hash TEXT NOT NULL,
            last_seen REAL NOT NULL,
            PRIMARY KEY (user_id, source_hash)
        );
        """
    )
    cols = [r[1] for r in conn.execute("PRAGMA table_info(refresh_tokens)")]
    if "revoked_at" not in cols:  # eski vault'dan migratsiya
        conn.execute("ALTER TABLE refresh_tokens ADD COLUMN revoked_at REAL")
    conn.commit()


# ---------------------------------------------------------------------------
# BOSHLANG'ICH SOZLASH (bir marta, o'rnatishda ishlaydi)
# ---------------------------------------------------------------------------
def _validate_share_dirs(share_dirs: list[Path]) -> list[Path]:
    if len(share_dirs) != SHAMIR_TOTAL:
        raise VaultError(f"Aynan {SHAMIR_TOTAL} ta alohida papka kerak (har bir Shamir bo'lagi uchun bittadan).")
    resolved = [Path(d).resolve() for d in share_dirs]
    if len(set(resolved)) != len(resolved):
        raise VaultError("Bo'lak papkalari bir-biridan farq qilishi kerak.")
    secrets_resolved = SECRETS_DIR.resolve()
    for d in resolved:
        if d == secrets_resolved or secrets_resolved in d.parents:
            raise VaultError(f"{d} secrets/ ichida - bo'laklar secrets/ papkasidan TASHQARIDA bo'lishi shart.")
    return resolved


def initialize_vault(
    admin_passphrase: str,
    share_dirs: list[Path] | None = None,
    allow_colocated_shares: bool = False,
) -> None:
    """
    Vault'ni "noldan" sozlaydi.

    Shamir bo'laklari: yo `share_dirs` (5 ta alohida papka - turli mount/USB/
    server) beriladi, yo `allow_colocated_shares=True` (FAQAT dev: barcha
    bo'laklar bitta papkada - xavfsizlik foydasi yo'q). Ikkalasi ham
    berilmasa - sozlash rad etiladi.
    """
    if KEYFILE.exists():
        raise VaultError("Vault allaqachon ishga tushirilgan (keyfile.enc mavjud). Avval eskisini tozalang.")

    if share_dirs:
        share_dirs = _validate_share_dirs(share_dirs)
    elif not allow_colocated_shares:
        raise VaultError(
            "Shamir bo'laklari uchun joy ko'rsatilmadi. Production: 5 ta alohida papka bering "
            "(--share-dirs). Faqat dev/demo: --insecure-colocated-shares."
        )

    SECRETS_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(SECRETS_DIR, 0o700)

    env_secret = ks.source_env_secret()

    keyring_secret = generate_key(32)
    KEYRING_FILE.write_bytes(keyring_secret)
    os.chmod(KEYRING_FILE, 0o600)

    salt = os.urandom(16)
    PASSPHRASE_SALT_FILE.write_bytes(salt)
    os.chmod(PASSPHRASE_SALT_FILE, 0o600)
    passphrase_key = ks.source_passphrase_kdf(admin_passphrase, salt)

    shamir_secret = generate_key(32)
    from vault.shamir import split_secret
    shares = split_secret(shamir_secret, threshold=SHAMIR_THRESHOLD, total_shares=SHAMIR_TOTAL)

    share_paths: list[Path] = []
    if share_dirs:
        targets = share_dirs
    else:
        SHAMIR_DIR.mkdir(exist_ok=True)
        os.chmod(SHAMIR_DIR, 0o700)
        targets = [SHAMIR_DIR] * SHAMIR_TOTAL
        alert("OGOHLANTIRISH: Shamir bo'laklari bitta papkada (dev rejimi) - bu sxema xavfsizlik BERMAYDI.")
    for (idx, value), d in zip(shares, targets):
        d.mkdir(parents=True, exist_ok=True)
        os.chmod(d, 0o700)
        share_path = d / f"share_{idx}.json"
        share_path.write_text(json.dumps({"index": idx, "value": value.hex()}))
        os.chmod(share_path, 0o600)
        share_paths.append(share_path)

    integrity_key = generate_key(32)
    INTEGRITY_KEY_FILE.write_bytes(integrity_key)
    os.chmod(INTEGRITY_KEY_FILE, 0o600)

    kek = ks.derive_kek(env_secret, keyring_secret, passphrase_key, shamir_secret)
    dk = generate_key(32)

    _atomic_write(KEYFILE, encrypt_bytes(dk, kek, associated_data=b"keyfile"))

    conn = sqlite3.connect(":memory:")
    ensure_schema(conn)
    plaintext_db = conn.serialize()
    conn.close()
    _atomic_write(SECRETS_DB, encrypt_bytes(bytes(plaintext_db), dk, associated_data=b"secrets.db"))

    ks.write_file_integrity(KEYFILE, integrity_key)
    ks.write_file_integrity(SECRETS_DB, integrity_key)

    ks.AttemptThrottle(ATTEMPT_STATE_FILE, integrity_key).initialize_clean_state()

    ROTATION_STATE_FILE.write_text(json.dumps({"last_rotation": 0}))
    os.chmod(ROTATION_STATE_FILE, 0o600)

    static_files = _static_files() + share_paths
    dynamic_files = _dynamic_files() + [ATTEMPT_STATE_FILE, ROTATION_STATE_FILE]
    imm_results = imm.harden_all(static_files + dynamic_files)
    supported = sum(1 for ok in imm_results.values() if ok)
    print(f"[IMMUTABLE] {supported}/{len(imm_results)} fayl OS darajasida himoyalandi (chattr +i).")
    if supported < len(imm_results):
        print("[OGOHLANTIRISH] Ba'zi fayllar immutable qilinmadi - fayl tizimi buni "
              "qo'llab-quvvatlamasligi mumkin (masalan, Docker overlay2).")

    print("Vault muvaffaqiyatli ishga tushirildi.")
    print(f"  - Keyring:   {KEYRING_FILE}")
    print(f"  - Keyfile:   {KEYFILE}")
    print(f"  - Secrets DB:{SECRETS_DB}")
    if share_dirs:
        print("  - Shamir bo'laklari (har biri alohida joyda):")
        for p in share_paths:
            print(f"      {p}")
        print("    Ishga tushirishda kamida 3 tasini SHAMIR_SHARE_PATHS orqali bering "
              f"(ajratgich: '{os.pathsep}').")


# ---------------------------------------------------------------------------
# OCHISH (har safar Vault xizmati ishga tushganda)
# ---------------------------------------------------------------------------
def unlock_vault(admin_passphrase: str) -> UnlockedVault:
    """
    Manba/gate'lar orqali KEK yig'adi, DK'ni ochadi, bazani RAM'ga yuklaydi.
    Har qanday bosqichda xato bo'lsa - muvaffaqiyatsizlik hisoblagichi oshadi
    va butun jarayon bekor qilinadi (qisman muvaffaqiyat holati bo'lmaydi).
    """
    thr = None
    try:
        if not INTEGRITY_KEY_FILE.exists():
            raise ks.GateError(f"{INTEGRITY_KEY_FILE} topilmadi - Vault sozlanmagan")
        ks.check_file_permissions(INTEGRITY_KEY_FILE)
        integrity_key = INTEGRITY_KEY_FILE.read_bytes()

        thr = ks.AttemptThrottle(ATTEMPT_STATE_FILE, integrity_key, max_attempts=5, lockout_seconds=300)
        thr.check()

        for p in [KEYRING_FILE, PASSPHRASE_SALT_FILE, KEYFILE, SECRETS_DB]:
            ks.check_file_permissions(p)

        ks.verify_file_integrity(KEYFILE, integrity_key)
        ks.verify_file_integrity(SECRETS_DB, integrity_key)

        env_secret = ks.source_env_secret()
        keyring_secret = ks.source_os_keyring(KEYRING_FILE)
        salt = PASSPHRASE_SALT_FILE.read_bytes()
        passphrase_key = ks.source_passphrase_kdf(admin_passphrase, salt)
        shamir_secret = ks.source_shamir_shares(shamir_locations(), threshold=SHAMIR_THRESHOLD)

        kek = ks.derive_kek(env_secret, keyring_secret, passphrase_key, shamir_secret)

        dk = decrypt_bytes(KEYFILE.read_bytes(), kek, associated_data=b"keyfile")
        db_blob = SECRETS_DB.read_bytes()
        recovered_from_next = False
        try:
            plaintext_db = decrypt_bytes(db_blob, dk, associated_data=b"secrets.db")
        except DecryptionError:
            # Kalit almashtirish paytida jarayon to'xtagan bo'lishi mumkin: baza YANGI DK
            # bilan yozilgan, keyfile hali eski. Jurnal (keyfile.enc.next) shuni hal qiladi.
            if not KEYFILE_NEXT.exists():
                raise
            dk = decrypt_bytes(KEYFILE_NEXT.read_bytes(), kek, associated_data=b"keyfile")
            plaintext_db = decrypt_bytes(db_blob, dk, associated_data=b"secrets.db")
            recovered_from_next = True

        conn = sqlite3.connect(":memory:")
        conn.deserialize(plaintext_db)
        ensure_schema(conn)  # eski vault'larni yangi sxemaga o'tkazadi (server_keys)

    except ks.TamperDetected as exc:
        if thr is not None:
            thr.record_failure()
        _alert_startup_tamper(reason=str(exc))
        raise VaultError(f"Vault'ni ochib bo'lmadi (yaxlitlik buzilgan): {exc}") from exc
    except (ks.GateError, DecryptionError, Exception) as exc:
        if thr is not None:
            thr.record_failure()
        raise VaultError(f"Vault'ni ochib bo'lmadi: {exc}") from exc

    thr.record_success()
    _finish_interrupted_rotation(kek, integrity_key, recovered_from_next)
    vault = UnlockedVault(kek=kek, dk=dk, conn=conn)
    _record_digests(vault)
    vault.static_digests = {p.name: _digest(p) for p in _static_files()}
    return vault


# ---------------------------------------------------------------------------
# BAZANI SAQLASH
# ---------------------------------------------------------------------------
def _write_with_integrity(path: Path, blob: bytes, integrity_key: bytes, reason: str) -> None:
    """Fayl + uning .hmac'i uchun crash-safe ketma-ketlik: yangi+eski imzo -> fayl -> yangi imzo."""
    with imm.mutable_window([path, _hmac_path(path)], reason=reason):
        ks.stage_integrity(path, integrity_key, blob)
        _atomic_write(path, blob)
        ks.write_file_integrity(path, integrity_key)


def _finish_interrupted_rotation(kek: bytes, integrity_key: bytes, recovered_from_next: bool) -> None:
    """Ochilgandan keyin: yarim qolgan kalit almashtirishni tugatadi, qoldiq imzolarni tozalaydi."""
    if recovered_from_next:
        alert("Kalit almashtirish yarim qolgan edi (jurnaldan tiklandi): keyfile yangilandi.")
        _write_with_integrity(KEYFILE, KEYFILE_NEXT.read_bytes(), integrity_key, "yarim qolgan almashtirishni tugatish")
    KEYFILE_NEXT.unlink(missing_ok=True)
    for p in (KEYFILE, SECRETS_DB):
        if len(ks.read_integrity_lines(p)) > 1:  # yozish paytida to'xtagan: bitta imzoga keltiramiz
            with imm.mutable_window(_hmac_path(p), reason="qoldiq imzoni tozalash"):
                ks.write_file_integrity(p, integrity_key)


def persist_vault(vault: UnlockedVault) -> None:
    plaintext_db = vault.conn.serialize()
    blob = encrypt_bytes(bytes(plaintext_db), vault.dk, associated_data=b"secrets.db")
    _write_with_integrity(SECRETS_DB, blob, INTEGRITY_KEY_FILE.read_bytes(), "persist_vault: baza yangilanmoqda")
    _record_digests(vault)


# ---------------------------------------------------------------------------
# RUNTIME YAXLITLIK NAZORATI (Vault ishlab turganda)
# ---------------------------------------------------------------------------
def check_runtime_integrity(vault: UnlockedVault) -> tuple[list[str], list[str]]:
    """
    Qaytaradi: (tiklash_mumkin_muammolar, faqat_ogohlantirish_muammolari).

    1-ro'yxat: keyfile/secrets.db/.hmac fayllari Vault yozganidan farq qiladi
    yoki yo'q. Haqiqiy nusxa RAM'da, shuning uchun TIKLASH mumkin.
    2-ro'yxat: statik fayllar (keyring, salt, integrity.key) o'zgargan -
    ularni RAM'dan tiklab bo'lmaydi, faqat alert beriladi (admin aralashishi kerak).
    """
    fixable = []
    for p in _dynamic_files():
        d = _digest(p)
        if d is None:
            fixable.append(f"{p.name} yo'q yoki o'qib bo'lmaydi")
        elif d != vault.file_digests.get(p.name):
            fixable.append(f"{p.name} tashqaridan o'zgartirilgan")
    warn_only = []
    for p in _static_files():
        d = _digest(p)
        if d != vault.static_digests.get(p.name):
            warn_only.append(f"{p.name} o'zgartirilgan yoki yo'q (statik fayl, RAM'dan tiklab bo'lmaydi)")
    return fixable, warn_only


# ---------------------------------------------------------------------------
# KALIT ALMASHTIRISH
# ---------------------------------------------------------------------------
def _rotation_allowed() -> bool:
    if not ROTATION_STATE_FILE.exists():
        return True
    try:
        state = json.loads(ROTATION_STATE_FILE.read_text())
    except (json.JSONDecodeError, OSError):
        return True
    return time.time() - state.get("last_rotation", 0) > ROTATION_MIN_INTERVAL_SECONDS


def _mark_rotated() -> None:
    with imm.mutable_window(ROTATION_STATE_FILE, reason="kalit almashtirish vaqti belgilanmoqda"):
        ROTATION_STATE_FILE.write_text(json.dumps({"last_rotation": time.time()}))
        os.chmod(ROTATION_STATE_FILE, 0o600)


def rotate_data_key(vault: UnlockedVault, reason: str, force: bool = False) -> UnlockedVault:
    """
    Data Key'ni almashtiradi VA diskdagi hamma dinamik faylni RAM'dagi
    haqiqiy nusxadan qayta yozadi (shu sababli tashqaridan buzilgan fayllar
    ham tiklanadi).

    NIMA BERADI: eski DK bilan shifrlangan bironta eski nusxa/zaxira endi
    joriy keyfile bilan mos kelmaydi. NIMA BERMAYDI: KEK oshkor bo'lgan bo'lsa,
    DK almashtirish uni qaytarmaydi (KEK manbalarini almashtirish kerak).

    force=False bo'lsa chastota cheklanadi (soatiga 1 marta). force=True -
    runtime tamper aniqlanganda (tekshiruv oralig'i bilan o'zi chegaralangan).
    """
    if not force and not _rotation_allowed():
        print(f"[VAULT] Kalit almashtirish so'raldi ({reason}), lekin chastota chegarasi "
              f"tufayli kechiktirildi.")
        return vault

    print(f"[VAULT] KALIT ALMASHTIRILMOQDA. Sabab: {reason}")

    new_dk = generate_key(32)
    plaintext_db = vault.conn.serialize()

    db_blob = encrypt_bytes(bytes(plaintext_db), new_dk, associated_data=b"secrets.db")
    keyfile_blob = encrypt_bytes(new_dk, vault.kek, associated_data=b"keyfile")
    integrity_key = INTEGRITY_KEY_FILE.read_bytes()

    # CRASH-SAFE TARTIB (har bir qadam orasida to'xtash mumkin, unlock_vault tiklay oladi):
    #   1) yangi DK jurnalga (keyfile.enc.next)  2) baza yangi DK bilan  3) keyfile  4) jurnalni o'chirish
    _atomic_write(KEYFILE_NEXT, keyfile_blob)
    _write_with_integrity(SECRETS_DB, db_blob, integrity_key, "rotate_data_key: baza yangi DK bilan qayta shifrlanmoqda")
    _write_with_integrity(KEYFILE, keyfile_blob, integrity_key, "rotate_data_key: keyfile yangi DK bilan yangilanmoqda")
    KEYFILE_NEXT.unlink(missing_ok=True)

    _mark_rotated()

    new_vault = UnlockedVault(kek=vault.kek, dk=new_dk, conn=vault.conn,
                              static_digests=vault.static_digests)
    _record_digests(new_vault)
    print("[VAULT] Kalit muvaffaqiyatli almashtirildi, fayllar RAM'dan qayta yozildi.")
    return new_vault


def _alert_startup_tamper(reason: str) -> None:
    """
    Vault'ni OCHISH paytida yaxlitlik buzilishi aniqlanganda chaqiriladi.
    Bu yerda Vault hali ochilmagan (DK yo'q), shuning uchun KALIT ALMASHTIRISH
    IMKONSIZ va qilinmaydi - faqat alert yoziladi va ishga tushish to'xtaydi.
    Fayllarni qo'lda tekshirib, zaxiradan tiklash kerak. (Ishlab turgan
    Vault'dagi tamper boshqacha: u RAM'dan tiklanadi, yuqoridagi
    check_runtime_integrity + rotate_data_key.)
    """
    alert(f"Ishga tushish paytida yaxlitlik buzilishi: {reason}. Vault OCHILMADI. "
          f"Administrator fayllarni tekshirib, zaxiradan tiklashi kerak.")
