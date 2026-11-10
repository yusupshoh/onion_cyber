"""
LOGIN URINISHLARINI CHEKLASH (Vault, RAM'da).

Oldingi dizayndagi muammolar va ularning yechimi:

  * ENUMERATION: "mavjud email 5 xatodan keyin 423, mavjud emas 401" farqi.
    -> Hisob mavjudligidan QAT'I NAZAR, har qanday email satri uchun bir xil
       hisoblagich va bir xil "locked" javobi.
  * LOCKOUT-DoS: istalgan odam birovning emailini 5 marta xato kiritib
    bloklashi mumkin edi.
    -> Asosiy blok (email, MANBA) juftligi bo'yicha: hujumchi faqat O'Z
       manbasidan bloklanadi, haqiqiy egasi o'z IP'sidan kira oladi.
  * TARQOQ BRUTE-FORCE: ko'p IP'dan bitta hisobga urinish.
    -> Hisob bo'yicha umumiy oyna (ACCOUNT_MAX_FAILS / ACCOUNT_WINDOW). U
       FAQAT noma'lum manbalarga ta'sir qiladi: egasi ilgari kirgan manbalar
       (known_sources) bundan mustasno, shu sababli egasi bloklanmaydi.
  * Xotira o'sishi: yozuvlar soni MAX_ENTRIES bilan cheklangan, eskilari tozalanadi.

Holat RAM'da: Vault restarti uni nolga tushiradi (restart administrator
aralashuvini talab qiladi, hujumchi uni chaqira olmaydi) va har xato urinishda
shifrlangan bazani qayta yozish ham shart emas.
"""
import time
from collections import OrderedDict, deque

SOURCE_MAX_FAILS = 5
SOURCE_LOCK_SECONDS = 15 * 60
ACCOUNT_WINDOW_SECONDS = 15 * 60
ACCOUNT_MAX_FAILS = 30
ACCOUNT_LOCK_SECONDS = 15 * 60
MAX_ENTRIES = 50_000


class LoginThrottle:
    def __init__(self, clock=time.time):
        self._clock = clock
        # (email, source) -> [fails, locked_until, last_seen]
        self._src: "OrderedDict[tuple[str, str], list]" = OrderedDict()
        # email -> [deque[fail_times], locked_until]
        self._acct: "OrderedDict[str, list]" = OrderedDict()

    # -- tekshirish -----------------------------------------------------------
    def check(self, email: str, source: str, known_source: bool) -> int | None:
        """Bloklangan bo'lsa - qolgan soniyalar, aks holda None."""
        now = self._clock()
        s = self._src.get((email, source))
        if s and s[1] > now:
            return int(s[1] - now) + 1
        a = self._acct.get(email)
        if a and a[1] > now and not known_source:
            return int(a[1] - now) + 1
        return None

    # -- yozib borish ---------------------------------------------------------
    def record_failure(self, email: str, source: str) -> None:
        now = self._clock()
        key = (email, source)
        s = self._src.pop(key, None) or [0, 0.0, now]
        if s[1] and s[1] <= now:  # eski blok tugagan - qaytadan sanaymiz
            s = [0, 0.0, now]
        s[0] += 1
        s[2] = now
        if s[0] >= SOURCE_MAX_FAILS:
            s[1] = now + SOURCE_LOCK_SECONDS
            s[0] = 0
        self._src[key] = s

        a = self._acct.pop(email, None) or [deque(), 0.0]
        a[0].append(now)
        while a[0] and now - a[0][0] > ACCOUNT_WINDOW_SECONDS:
            a[0].popleft()
        if len(a[0]) >= ACCOUNT_MAX_FAILS and a[1] <= now:
            a[1] = now + ACCOUNT_LOCK_SECONDS
            a[0].clear()
        self._acct[email] = a
        self._gc()

    def record_success(self, email: str, source: str) -> None:
        self._src.pop((email, source), None)

    def account_locked(self, email: str) -> bool:
        a = self._acct.get(email)
        return bool(a and a[1] > self._clock())

    def _gc(self) -> None:
        if len(self._src) <= MAX_ENTRIES and len(self._acct) <= MAX_ENTRIES:
            return
        now = self._clock()
        for k in [k for k, v in self._src.items() if v[1] <= now and now - v[2] > SOURCE_LOCK_SECONDS]:
            del self._src[k]
        for k in [k for k, v in self._acct.items() if v[1] <= now and (not v[0] or now - v[0][-1] > ACCOUNT_WINDOW_SECONDS)]:
            del self._acct[k]
        while len(self._src) > MAX_ENTRIES:
            self._src.popitem(last=False)
        while len(self._acct) > MAX_ENTRIES:
            self._acct.popitem(last=False)
