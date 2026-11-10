"""
3-QATLAM: TRAFIK NAZORATI VA ANOMALIYA ANIQLASH

Oldingi variantdagi kamchiliklar tuzatildi:
  * Kalit endi FAQAT IP (X-Device-Id'ga ishonilmaydi: uni mijoz o'zi beradi va
    har so'rovda almashtirib limitdan qochardi). IP reverse proxy ortida ham
    to'g'ri aniqlanadi (app/core/client_ip.py).
  * Xotira CHEKLANGAN: bo'sh turgan yozuvlar tozalanadi, jami MAX_TRACKED_CLIENTS
    dan oshmaydi (cheksiz o'sib, xotirani to'ldirish DoS'i yo'q).
  * CREDENTIAL STUFFING: bitta IP'dan XILMA-XIL email'larga xato urinishlar soni
    sanaladi (oldingi "o'xshash email" tekshiruvi buni sezmasdi, chunki stuffing
    ro'yxatidagi email'lar bir-biriga o'xshamaydi). O'xshashlik tekshiruvi
    (lug'at/ketma-ket generatsiya) saqlab qolindi.
  * Hisob bo'yicha bloklash Vault'da (login_throttle.py) - u yerda manba va
    "ma'lum manba" ma'lum, shuning uchun haqiqiy egani bloklab qo'yib bo'lmaydi.

Production'da bu holat Redis kabi umumiy xotiraga ko'chirilishi kerak (bir nechta
jarayon/server bo'lsa, hisoblagichlar jarayonlar orasida bo'linib ketadi).
"""
import time
from collections import OrderedDict, deque
from dataclasses import dataclass, field

from fastapi import Request, HTTPException

from app.config import settings
from app.core.client_ip import get_client_ip

SIMILARITY_DISTANCE_THRESHOLD = 3
SIMILARITY_FAILURE_STREAK = 3
SUSPICIOUS_COOLDOWN_SECONDS = 5 * 60
DISTINCT_WINDOW_SECONDS = 10 * 60


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            curr[j] = min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost)
        prev = curr
    return prev[-1]


@dataclass
class ClientState:
    attempts: deque = field(default_factory=deque)
    recent_emails: deque = field(default_factory=lambda: deque(maxlen=5))   # (email, success, ts)
    failed_emails: deque = field(default_factory=deque)                      # (email, ts) - faqat xatolar
    suspicious_until: float = 0.0
    last_seen: float = 0.0


_clients: "OrderedDict[str, ClientState]" = OrderedDict()
_ops = 0


def _gc(now: float) -> None:
    """Idle yozuvlarni tozalaydi; chegaradan oshsa eng eskilarini chiqaradi."""
    idle = settings.RATE_LIMIT_WINDOW_SECONDS + DISTINCT_WINDOW_SECONDS
    for k in [k for k, v in _clients.items() if now - v.last_seen > idle and v.suspicious_until < now]:
        del _clients[k]
    while len(_clients) > settings.MAX_TRACKED_CLIENTS:
        _clients.popitem(last=False)


def _get_state(key: str, now: float) -> ClientState:
    global _ops
    st = _clients.pop(key, None)
    if st is None:
        st = ClientState()
    st.last_seen = now
    _clients[key] = st          # eng oxirga (LRU tartibi)
    _ops += 1
    if _ops % 500 == 0 or len(_clients) > settings.MAX_TRACKED_CLIENTS:
        _gc(now)
    return st


def enforce_rate_limit(request: Request) -> str:
    """FastAPI dependency. Qaytaradi: mijoz kaliti (IP) - record_attempt va Vault'ga 'source' uchun."""
    key = get_client_ip(request)
    now = time.time()
    state = _get_state(key, now)

    if now < state.suspicious_until:
        remaining = int(state.suspicious_until - now) + 1
        raise HTTPException(status_code=429, detail=f"Shubhali xatti-harakat aniqlandi. {remaining} soniyadan keyin qayta urining.")

    while state.attempts and now - state.attempts[0] > settings.RATE_LIMIT_WINDOW_SECONDS:
        state.attempts.popleft()
    if len(state.attempts) >= settings.RATE_LIMIT_MAX_ATTEMPTS:
        raise HTTPException(status_code=429, detail=f"Juda ko'p urinish. {settings.RATE_LIMIT_WINDOW_SECONDS} soniyadan keyin qayta urining.")

    state.attempts.append(now)
    return key


def record_attempt(client_key: str, email: str, success: bool) -> None:
    """Har urinishdan KEYIN: o'xshash-email naqshi va xilma-xil-email (stuffing) hisobi."""
    now = time.time()
    state = _get_state(client_key, now)
    email_norm = email.strip().lower()

    if success:
        state.failed_emails.clear()
        state.recent_emails.append((email_norm, True, now))
        return

    # (1) credential stuffing: oynada nechta XILMA-XIL email'ga xato bo'ldi
    state.failed_emails.append((email_norm, now))
    while state.failed_emails and now - state.failed_emails[0][1] > DISTINCT_WINDOW_SECONDS:
        state.failed_emails.popleft()
    distinct = {e for e, _ in state.failed_emails}
    if len(distinct) >= settings.DISTINCT_EMAIL_FAILS_THRESHOLD:
        state.suspicious_until = now + SUSPICIOUS_COOLDOWN_SECONDS
        state.failed_emails.clear()
        print(f"[RATE-LIMIT] Credential stuffing shubhasi (ip={client_key}): {len(distinct)} ta xilma-xil "
              f"email'ga xato urinish. {SUSPICIOUS_COOLDOWN_SECONDS}s ga cheklandi.")

    # (2) o'xshash, lekin TURLICHA email'lar ketma-ketligi (lug'at/ketma-ket generatsiya).
    # MUHIM: aynan bir xil email'ni qayta-qayta xato yozish (parolni unutgan odam)
    # shubhali EMAS - klaster to'plam bo'lgani uchun takroriy email bitta sanaladi.
    cluster = {email_norm}
    for prev_email, prev_success, _ in reversed(state.recent_emails):
        if prev_success:
            break
        if _levenshtein(email_norm, prev_email) <= SIMILARITY_DISTANCE_THRESHOLD:
            cluster.add(prev_email)
        else:
            break
    if len(cluster) >= SIMILARITY_FAILURE_STREAK:
        state.suspicious_until = now + SUSPICIOUS_COOLDOWN_SECONDS
        print(f"[RATE-LIMIT] Shubhali naqsh (ip={client_key}): {len(cluster)} ta turlicha, bir-biriga yaqin, "
              f"muvaffaqiyatsiz email. {SUSPICIOUS_COOLDOWN_SECONDS}s ga cheklandi.")

    state.recent_emails.append((email_norm, False, now))
