"""
Test infratuzilmasi: HAQIQIY ikkita jarayon (Vault + Chegara xizmati), vaqtinchalik
secrets papkasi, 5 ta alohida Shamir papkasi bilan. Linux/WSL, Python 3.10+.
"""
import os
import secrets
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest

ROOT = Path(__file__).resolve().parent.parent
PASSPHRASE = "test-passphrase-123"
USERS = {
    "main@muallim.uz": "KuchliParol123",
    "enum@muallim.uz": "KuchliParol123",
    "dos@muallim.uz": "KuchliParol123",
    "dist@muallim.uz": "KuchliParol123",
    "grace@muallim.uz": "KuchliParol123",
    "tamper@muallim.uz": "KuchliParol123",
}


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_http(url: str, timeout: float = 40) -> None:
    end = time.time() + timeout
    while time.time() < end:
        try:
            httpx.get(url, timeout=1)
            return
        except httpx.HTTPError:
            time.sleep(0.3)
    raise RuntimeError(f"{url} ko'tarilmadi")


class Stack:
    def __init__(self, tmp: Path):
        self.tmp = tmp
        self.secrets = tmp / "secrets"
        self.shares = [tmp / "shares" / str(i) for i in range(1, 6)]
        self.vault_port, self.border_port = free_port(), free_port()
        self.signing_key = secrets.token_hex(32)
        self.vault_env = {
            **os.environ,
            "VAULT_SECRETS_DIR": str(self.secrets),
            "VAULT_ENV_SECRET": secrets.token_hex(32),
            "PASSWORD_PEPPER": secrets.token_hex(32),
            "INTERNAL_SIGNING_KEY": self.signing_key,
            "ALLOW_ENV_PASSPHRASE": "1",
            "ADMIN_PASSPHRASE": PASSPHRASE,
            "INTEGRITY_CHECK_INTERVAL_SECONDS": "1",
            "REFRESH_GRACE_SECONDS": "2",
            # faqat 3/5 bo'lak ulangan: Shamir chegarasi ham sinaladi
            "SHAMIR_SHARE_PATHS": os.pathsep.join(str(self.shares[i]) for i in (0, 2, 4)),
            "PYTHONPATH": str(ROOT),
        }
        self.border_env = {
            "PATH": os.environ["PATH"], "PYTHONPATH": str(ROOT),
            "INTERNAL_SIGNING_KEY": self.signing_key,
            "VAULT_URL": f"http://127.0.0.1:{self.vault_port}",
            "TRUSTED_PROXIES": "127.0.0.1",
            "RATE_LIMIT_MAX_ATTEMPTS": "1000",
            "NODE_ENV": "development",
            "ALLOWED_ORIGINS": "http://localhost:3000",
        }
        self.vault_proc = self.border_proc = None

    @property
    def vault(self): return f"http://127.0.0.1:{self.vault_port}"
    @property
    def border(self): return f"http://127.0.0.1:{self.border_port}"

    def init(self):
        code = (
            "import os,sys;from pathlib import Path;"
            "from vault.vault_core import initialize_vault,unlock_vault,persist_vault;"
            "from vault.user_store import create_user;"
            f"initialize_vault(os.environ['ADMIN_PASSPHRASE'],share_dirs=[Path(p) for p in {[str(p) for p in self.shares]!r}]);"
            "v=unlock_vault(os.environ['ADMIN_PASSPHRASE']);"
            f"[create_user(v.conn,e,p) for e,p in {USERS!r}.items()];persist_vault(v)"
        )
        r = subprocess.run([sys.executable, "-c", code], env=self.vault_env, cwd=ROOT, capture_output=True, text=True)
        assert r.returncode == 0, r.stdout + r.stderr

    def start_vault(self):
        self.vault_log = open(self.tmp / "vault.log", "a")
        self.vault_proc = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "vault.service:app", "--host", "127.0.0.1", "--port", str(self.vault_port)],
            env=self.vault_env, cwd=ROOT, stdout=self.vault_log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
        wait_http(self.vault + "/internal/health")

    def stop_vault(self):
        if self.vault_proc:
            self.vault_proc.send_signal(signal.SIGTERM)
            self.vault_proc.wait(timeout=15)
            self.vault_proc = None

    def start_border(self):
        self.border_log = open(self.tmp / "border.log", "a")
        self.border_proc = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", str(self.border_port), "--no-server-header"],
            env=self.border_env, cwd=ROOT, stdout=self.border_log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
        wait_http(self.border + "/health")

    def vault_log_text(self) -> str:
        self.vault_log.flush()
        return (self.tmp / "vault.log").read_text()

    def stop(self):
        for p in (self.border_proc, self.vault_proc):
            if p:
                p.terminate()
                try: p.wait(timeout=10)
                except subprocess.TimeoutExpired: p.kill()
        # immutable fayllarni pytest tmp tozalashi o'chira olishi uchun
        subprocess.run(["chattr", "-R", "-i", str(self.tmp)], capture_output=True)


@pytest.fixture(scope="module")
def stack(tmp_path_factory):
    st = Stack(tmp_path_factory.mktemp("vt"))
    st.init(); st.start_vault(); st.start_border()
    yield st
    st.stop()


_ip_counter = iter(range(1, 250))


@pytest.fixture
def ip():
    """Har test uchun noyob 'mijoz IP' (ishonchli proxy orqali X-Forwarded-For bilan)."""
    return f"10.{next(_ip_counter)}.{secrets.randbelow(200)}.{secrets.randbelow(200) + 1}"
