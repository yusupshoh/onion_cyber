import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("INTERNAL_SIGNING_KEY", "x" * 32)


def test_shamir_any_3_of_5():
    from itertools import combinations
    from vault.shamir import split_secret, reconstruct_secret
    secret = os.urandom(32)
    shares = split_secret(secret, threshold=3, total_shares=5)
    for combo in combinations(shares, 3):
        assert reconstruct_secret(list(combo)) == secret
    assert reconstruct_secret(shares[:2]) != secret  # 2 ta bo'lak yetmaydi


def test_login_throttle_source_scoped_and_enumeration_uniform():
    from vault.login_throttle import LoginThrottle, SOURCE_MAX_FAILS
    t = [1000.0]
    th = LoginThrottle(clock=lambda: t[0])
    for _ in range(SOURCE_MAX_FAILS):
        th.record_failure("a@x.uz", "srcA")
    assert th.check("a@x.uz", "srcA", known_source=False) is not None   # hujumchi manbasi bloklandi
    assert th.check("a@x.uz", "srcB", known_source=False) is None       # boshqa manba (ega) bloklanmagan
    # mavjud bo'lmagan email ham AYNAN shunday (enumeration yo'q)
    for _ in range(SOURCE_MAX_FAILS):
        th.record_failure("ghost@x.uz", "srcA")
    assert th.check("ghost@x.uz", "srcA", False) is not None
    t[0] += 16 * 60
    assert th.check("a@x.uz", "srcA", False) is None                    # blok tugadi


def test_login_throttle_account_wide_exempts_known_sources():
    from vault.login_throttle import LoginThrottle, ACCOUNT_MAX_FAILS
    th = LoginThrottle(clock=lambda: 5000.0)
    for i in range(ACCOUNT_MAX_FAILS):
        th.record_failure("v@x.uz", f"src{i}")
    assert th.check("v@x.uz", "new-src", known_source=False) is not None
    assert th.check("v@x.uz", "home-src", known_source=True) is None    # egasi bloklanmaydi


def test_login_throttle_memory_bounded(monkeypatch):
    from vault import login_throttle as lt
    monkeypatch.setattr(lt, "MAX_ENTRIES", 100)
    th = lt.LoginThrottle()
    for i in range(1000):
        th.record_failure(f"u{i}@x.uz", f"s{i}")
    assert len(th._src) <= 100 and len(th._acct) <= 100


def _request(headers, client=("9.9.9.9", 1)):
    from starlette.requests import Request
    return Request({"type": "http", "method": "POST", "path": "/", "query_string": b"",
                    "headers": [(k.encode(), v.encode()) for k, v in headers.items()], "client": client})


def test_rate_limit_key_ignores_x_device_id():
    from app.core.client_ip import get_client_ip
    a = get_client_ip(_request({"x-device-id": "aaa"}))
    b = get_client_ip(_request({"x-device-id": "bbb"}))
    assert a == b == "9.9.9.9"


def test_rate_limiter_distinct_email_stuffing_and_bounded_memory(monkeypatch):
    from app.middleware import rate_limiter as rl
    from app.config import settings
    rl._clients.clear()
    for i in range(settings.DISTINCT_EMAIL_FAILS_THRESHOLD):
        rl.record_attempt("1.2.3.4", f"zq{i}{'k'*i}@host{i*7}.example", success=False)
    assert rl._clients["1.2.3.4"].suspicious_until > 0
    monkeypatch.setattr(settings, "MAX_TRACKED_CLIENTS", 50)
    for i in range(500):
        rl.record_attempt(f"ip{i}", "a@b.c", success=True)
    assert len(rl._clients) <= 50 + 1


def test_same_email_repeated_is_not_suspicious_but_similar_variants_are():
    from app.middleware import rate_limiter as rl
    rl._clients.clear()
    for _ in range(7):                                   # parolni unutgan odam
        rl.record_attempt("5.5.5.5", "teacher@school.uz", success=False)
    assert rl._clients["5.5.5.5"].suspicious_until == 0
    for e in ("teacher1@school.uz", "teacher2@school.uz", "teacher3@school.uz"):   # ketma-ket generatsiya
        rl.record_attempt("6.6.6.6", e, success=False)
    assert rl._clients["6.6.6.6"].suspicious_until > 0


def test_client_ip_trusted_proxy_chain(monkeypatch):
    import ipaddress
    from app.core import client_ip as ci
    monkeypatch.setattr(ci, "_NETS", [ipaddress.ip_network("10.0.0.0/8")])
    # hujumchi chapga soxta IP qo'shadi; o'ngdagi haqiqiy yozuvni proxy qo'shgan
    r = _request({"x-forwarded-for": "6.6.6.6, 203.0.113.7, 10.0.0.2"}, client=("10.0.0.1", 1))
    assert ci.get_client_ip(r) == "203.0.113.7"
    # ishonchsiz peer: X-Forwarded-For e'tiborga olinmaydi
    r = _request({"x-forwarded-for": "6.6.6.6"}, client=("8.8.8.8", 1))
    assert ci.get_client_ip(r) == "8.8.8.8"


# --- CRASH-SAFETY: yozish paytida jarayon istalgan nuqtada to'xtasa ham vault ochiladi --------
CRASH_SIM = textwrap.dedent('''
    import os, sys
    from pathlib import Path
    sys.path.insert(0, os.environ["PYTHONPATH"])
    from vault import fsutil, vault_core, key_sources
    from vault.vault_core import initialize_vault, unlock_vault, persist_vault, rotate_data_key
    from vault.user_store import create_user, get_user_row

    mode, k = sys.argv[1], int(sys.argv[2])
    pw = os.environ["ADMIN_PASSPHRASE"]
    shares = [Path(os.environ["SIM_DIR"]) / f"sh{i}" for i in range(5)]
    initialize_vault(pw, share_dirs=shares)
    os.environ["SHAMIR_SHARE_PATHS"] = os.pathsep.join(str(p) for p in shares[:3])
    v = unlock_vault(pw)
    create_user(v.conn, "first@x.uz", "ParolParol1"); persist_vault(v)

    class Crash(BaseException): pass
    calls = {"n": 0}
    real = fsutil.atomic_write
    def flaky(path, data, mode=0o600):
        calls["n"] += 1
        if calls["n"] == k:
            raise Crash()
        return real(path, data, mode)
    vault_core._atomic_write = flaky; key_sources.atomic_write = flaky

    create_user(v.conn, "second@x.uz", "ParolParol2")
    try:
        if mode == "rotate": rotate_data_key(v, "sim", force=True)
        else: persist_vault(v)
        print("NO_CRASH", calls["n"])
    except Crash:
        print("CRASHED_AT", k)

    vault_core._atomic_write = real; key_sources.atomic_write = real
    v2 = unlock_vault(pw)                       # tiklanishi SHART
    assert get_user_row(v2.conn, "first@x.uz") is not None
    print("RECOVERED", get_user_row(v2.conn, "second@x.uz") is not None)
    persist_vault(v2); v3 = unlock_vault(pw)    # tiklangandan keyin ham normal ishlaydi
    assert get_user_row(v3.conn, "first@x.uz") is not None
''')


@pytest.mark.parametrize("mode,k", [("rotate", i) for i in range(1, 9)] + [("persist", i) for i in range(1, 5)])
def test_crash_at_every_write_point_is_recoverable(tmp_path, mode, k):
    import secrets as sec
    env = {**os.environ, "PYTHONPATH": str(ROOT), "VAULT_SECRETS_DIR": str(tmp_path / "secrets"),
           "SIM_DIR": str(tmp_path), "VAULT_ENV_SECRET": sec.token_hex(32), "PASSWORD_PEPPER": sec.token_hex(32),
           "ALLOW_ENV_PASSPHRASE": "1", "ADMIN_PASSPHRASE": "sim-passphrase-1"}
    try:
        r = subprocess.run([sys.executable, "-c", CRASH_SIM, mode, str(k)], env=env, capture_output=True, text=True, timeout=120)
        assert r.returncode == 0, f"{mode} k={k}\n{r.stdout}\n{r.stderr[-2000:]}"
        assert "RECOVERED" in r.stdout
    finally:
        subprocess.run(["chattr", "-R", "-i", str(tmp_path)], capture_output=True)
