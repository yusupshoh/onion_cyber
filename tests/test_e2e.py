import base64
import hashlib
import hmac as hmaclib
import json
import subprocess
import sys
import time
import uuid
from pathlib import Path

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tests.conftest import USERS, ROOT

PW = "KuchliParol123"


def login(stack, email, password, ip):
    return httpx.post(stack.border + "/auth/login", json={"email": email, "password": password},
                      headers={"X-Forwarded-For": ip}, timeout=30)


def vault_sign(stack, method, path, body, key=None):
    ts, n = str(time.time()), uuid.uuid4().hex
    sig = hmaclib.new((key or stack.signing_key).encode(), f"{ts}.{n}.{method}.{path}.".encode() + body, hashlib.sha256).hexdigest()
    return {"X-Timestamp": ts, "X-Nonce": n, "X-Signature": sig, "Content-Type": "application/json"}


def vault_post(stack, path, payload, sign_path=None):
    body = json.dumps(payload).encode()
    return httpx.post(stack.vault + path, content=body, headers=vault_sign(stack, "POST", sign_path or path, body), timeout=30)


def verify_with_border_code(stack, token) -> str:
    """Chegara xizmatining HAQIQIY token_manager kodi bilan tekshiradi (alohida jarayonda)."""
    code = ("import asyncio,sys;from app.core import token_manager as t;"
            "print(asyncio.run(t.verify_access_token(sys.argv[1]))['email'])")
    r = subprocess.run([sys.executable, "-c", code, token], cwd=ROOT, capture_output=True, text=True,
                       env={**stack.border_env})
    return r.stdout.strip() if r.returncode == 0 else "REJECTED"


# ---------------------------------------------------------------- oddiy oqim
def test_login_and_cookie_flags(stack, ip):
    r = login(stack, "main@muallim.uz", PW, ip)
    assert r.status_code == 200
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie and "path=/auth" in cookie
    assert login(stack, "main@muallim.uz", "boshqa-parol-1", ip).status_code == 401


def test_malformed_bodies_never_500(stack, ip):
    h = {"content-type": "application/json", "X-Forwarded-For": ip}
    for body in (b"{bad", b"[]", b'"str"', b"null", b'{"email": 5, "password": []}'):
        assert httpx.post(stack.border + "/auth/login", content=body, headers=h).status_code == 422, body


def test_body_limits_including_chunked(stack, ip):
    h = {"content-type": "application/json", "X-Forwarded-For": ip}
    assert httpx.post(stack.border + "/auth/login", content=b"{" + b"a" * 20000 + b"}", headers=h).status_code == 413

    def chunks():  # Content-Length YO'Q - Transfer-Encoding: chunked
        for _ in range(40):
            yield b"x" * 1024
    assert httpx.post(stack.border + "/auth/login", content=chunks(), headers=h).status_code == 413
    h2 = {"content-type": "text/plain", "X-Forwarded-For": ip}
    assert httpx.post(stack.border + "/auth/login", content=chunks(), headers=h2).status_code == 415


# ---------------------------------------------------------------- tokenlar
def test_tokens_are_signed_only_by_vault(stack, ip):
    tok = login(stack, "main@muallim.uz", PW, ip).json()["access_token"]
    assert verify_with_border_code(stack, tok) == "main@muallim.uz"

    forged = jwt.encode({"sub": "1", "email": "admin@x.uz", "exp": int(time.time()) + 999, "type": "access"},
                        Ed25519PrivateKey.generate(), algorithm="EdDSA")
    assert verify_with_border_code(stack, forged) == "REJECTED"

    pub = httpx.get(stack.vault + "/internal/public-key").json()["public_key_pem"]
    b64 = lambda d: base64.urlsafe_b64encode(d).rstrip(b"=").decode()
    head = b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()) + "." + b64(
        json.dumps({"sub": "1", "email": "x@x.uz", "exp": int(time.time()) + 999, "type": "access"}).encode())
    hs = head + "." + b64(hmaclib.new(pub.encode(), head.encode(), hashlib.sha256).digest())
    assert verify_with_border_code(stack, hs) == "REJECTED"   # alg-confusion


def test_refresh_rotation_theft_and_grace(stack, ip):
    c = httpx.Client(base_url=stack.border, headers={"X-Forwarded-For": ip})
    assert c.post("/auth/login", json={"email": "grace@muallim.uz", "password": PW}).status_code == 200
    r0 = c.cookies.get("refresh_token")
    r1 = c.post("/auth/refresh"); assert r1.status_code == 200
    # parallel tab: eski token QISQA grace ichida qayta ko'rsatildi - o'g'irlik EMAS
    again = httpx.post(stack.border + "/auth/refresh", cookies={"refresh_token": r0}, headers={"X-Forwarded-For": ip})
    assert again.status_code == 200
    time.sleep(3)  # grace (test muhitida 2s) tugadi
    late = httpx.post(stack.border + "/auth/refresh", cookies={"refresh_token": r0}, headers={"X-Forwarded-For": ip})
    assert late.status_code == 401 and "bekor qilindi" in late.text      # o'g'irlik signali
    newest = c.cookies.get("refresh_token")
    assert httpx.post(stack.border + "/auth/refresh", cookies={"refresh_token": newest}, headers={"X-Forwarded-For": ip}).status_code == 401


def test_logout_revokes(stack, ip):
    c = httpx.Client(base_url=stack.border, headers={"X-Forwarded-For": ip})
    c.post("/auth/login", json={"email": "main@muallim.uz", "password": PW})
    tok = c.cookies.get("refresh_token")
    assert c.post("/auth/logout").status_code == 200
    assert httpx.post(stack.border + "/auth/refresh", cookies={"refresh_token": tok}, headers={"X-Forwarded-For": ip}).status_code == 401


# ---------------------------------------------------------------- Chegara xizmati buzilgan stsenariy
def test_compromised_border_cannot_mint_or_create(stack):
    body = b"{}"
    r = httpx.post(stack.vault + "/internal/create-user", content=body, headers=vault_sign(stack, "POST", "/internal/create-user", body))
    assert r.status_code in (404, 405)
    assert vault_post(stack, "/internal/login", {"email": "main@muallim.uz", "password": "boshqa-parol-1", "source": "1.1.1.1"}).json()["result"] == "invalid"
    assert vault_post(stack, "/internal/login", {"email": "yangi@hujumchi.uz", "password": "HujumchiParol1"}).json()["result"] == "invalid"
    assert vault_post(stack, "/internal/refresh", {"refresh_token": "x" * 40}).json()["result"] == "invalid"
    # imzo boshqa endpoint'ga ko'chirilsa
    assert vault_post(stack, "/internal/login", {"email": "a@b.c", "password": "x"}, sign_path="/internal/refresh").status_code == 401
    # imzosiz / noto'g'ri imzo / buzuq body: 401 (validatsiya imzodan keyin)
    assert httpx.post(stack.vault + "/internal/login", content=b"{{{").status_code == 401
    bad = vault_sign(stack, "POST", "/internal/login", b"{{{", key="noto'g'ri-kalit")
    assert httpx.post(stack.vault + "/internal/login", content=b"{{{", headers=bad).status_code == 401


def test_bad_signatures_alert_but_do_not_rotate_key(stack):
    kf = (stack.secrets / "keyfile.enc").read_bytes()
    for _ in range(4):
        httpx.post(stack.vault + "/internal/login", content=b"{}")
    time.sleep(0.5)
    assert "imzosiz/xato so'rovlar ko'paydi" in stack.vault_log_text()
    assert (stack.secrets / "keyfile.enc").read_bytes() == kf


# ---------------------------------------------------------------- throttle / enumeration / lockout-DoS
def test_enumeration_uniform_and_lockout_dos_prevented(stack):
    attacker, owner = "172.16.1.1", "172.16.2.2"
    existing, ghost = "enum@muallim.uz", "ghost-user@muallim.uz"
    for email in (existing, ghost):
        codes = [login(stack, email, "xato-parol-123", attacker).status_code for _ in range(6)]
        assert codes == [401] * 5 + [423], (email, codes)           # mavjud va mavjud emas BIR XIL
    # hujumchi bloklandi, lekin HAQIQIY EGA o'z manbasidan kira oladi
    assert login(stack, existing, PW, owner).status_code == 200


def test_distributed_bruteforce_locks_unknown_sources_but_not_owner(stack):
    victim, home = "dist@muallim.uz", "172.16.9.9"
    assert login(stack, victim, PW, home).status_code == 200        # 'home' ma'lum manbaga aylandi
    for i in range(30):                                              # 30 ta turli IP'dan bittadan xato
        assert login(stack, victim, "xato-parol-123", f"172.17.{i}.1").status_code == 401
    assert login(stack, victim, PW, "172.18.0.1").status_code == 423  # noma'lum manba: hatto to'g'ri parol bilan ham
    assert login(stack, victim, PW, home).status_code == 200          # ega bloklanmadi


def test_credential_stuffing_by_distinct_emails(stack, ip):
    codes = [login(stack, f"{uuid.uuid4().hex[:10]}@{uuid.uuid4().hex[:6]}.example", "Parol12345", ip).status_code for _ in range(12)]
    assert 429 in codes and codes.index(429) <= 10


def test_x_device_id_cannot_evade_ip_limit(stack):
    """X-Device-Id endi limit kalitiga kirmaydi: har so'rovda almashtirish IP chegarasidan qutqarmaydi."""
    ip = "172.20.0.5"
    for i in range(10):
        httpx.post(stack.border + "/auth/login", json={"email": f"{uuid.uuid4().hex[:9]}@{uuid.uuid4().hex[:5]}.example", "password": "Parol12345"},
                   headers={"X-Forwarded-For": ip, "X-Device-Id": f"dev-{i}"})
    r = httpx.post(stack.border + "/auth/login", json={"email": "main@muallim.uz", "password": PW},
                   headers={"X-Forwarded-For": ip, "X-Device-Id": "fresh-device"})
    assert r.status_code == 429


# ---------------------------------------------------------------- fayl buzilishi va restart (OXIRIDA: Vault'ni qayta ishga tushiradi)
def _digest(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def _unlock(p: Path):
    subprocess.run(["chattr", "-i", str(p)], capture_output=True)


def test_zz_runtime_tamper_is_repaired_and_vault_restarts(stack, ip):
    db, kf = stack.secrets / "secrets.db.enc", stack.secrets / "keyfile.enc"
    kf_before = _digest(kf)
    _unlock(db); db.write_bytes(b"HUJUMCHI CHIQINDISI" * 50)
    time.sleep(4)
    assert db.read_bytes()[:4] == b"\x00\x00\x00\x01"                  # RAM'dan qayta yozildi
    assert _digest(kf) != kf_before                                   # DK almashtirildi
    assert login(stack, "tamper@muallim.uz", PW, ip).status_code == 200

    kf_before = _digest(kf); _unlock(kf); kf.unlink()
    time.sleep(4)
    assert kf.exists() and _digest(kf) != kf_before                   # o'chirilgan keyfile tiklandi
    assert "runtime yaxlitlik buzilishi" in (stack.secrets / "alerts.log").read_text().lower()

    salt = stack.secrets / "passphrase.salt"; orig = salt.read_bytes()
    _unlock(salt); salt.write_bytes(b"X" * 16); time.sleep(3)
    assert "passphrase.salt o'zgartirilgan" in (stack.secrets / "alerts.log").read_text()  # statik: faqat alert
    salt.write_bytes(orig); subprocess.run(["chattr", "+i", str(salt)], capture_output=True)

    stack.stop_vault(); stack.start_vault()                           # yangi DK bilan qayta ochilishi kerak
    assert "Yangi JWT imzolash kaliti" not in stack.vault_log_text().split("Xizmat tayyor")[-2] if stack.vault_log_text().count("Xizmat tayyor") > 1 else True
    assert login(stack, "tamper@muallim.uz", PW, ip).status_code == 200
