"""
Shamir's Secret Sharing - GF(256) maydonida.

Maxfiy qiymat (masalan, 32 baytli kalit) N ta bo'lakka bo'linadi,
lekin ularning istalgan T tasi (T <= N) yig'ilsagina asl qiymat tiklanadi.
T-1 tasi yig'ilsa ham HECH QANDAY ma'lumot bermaydi (matematik jihatdan
mutlaqo tasodifiy ko'rinadi) - bu "ma'lumot-nazariy xavfsizlik" deb ataladi.

Bu yerda oddiy, ta'lim maqsadidagi implementatsiya. Production'da
kutubxona (masalan, `secretsharing` yoki HashiCorp Vault'ning o'zi)
ishlatilishi tavsiya etiladi - lekin algoritm printsipi bir xil.
"""
import secrets as _secrets

# GF(256) uchun AES bilan bir xil qaytarilmas polinom (Rijndael maydoni)
_EXP = [0] * 512
_LOG = [0] * 256


def _init_tables():
    # E'TIBOR: generator sifatida 3 ishlatiladi (0x02 GF(256)*da primitiv
    # element emas - uning tartibi 51, 255 emas; 0x03 esa haqiqiy primitiv
    # element va 255 ta barcha nolmas elementni hosil qiladi).
    x = 1
    for i in range(255):
        _EXP[i] = x
        _LOG[x] = i
        x ^= (x << 1) ^ (0x11B if (x & 0x80) else 0)
        x &= 0xFF
    for i in range(255, 512):
        _EXP[i] = _EXP[i - 255]


_init_tables()


def _gf_mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return _EXP[_LOG[a] + _LOG[b]]


def _gf_div(a: int, b: int) -> int:
    if a == 0:
        return 0
    if b == 0:
        raise ZeroDivisionError("GF(256) da nolga bo'lish")
    return _EXP[(_LOG[a] - _LOG[b]) % 255]


def _eval_poly(coeffs: list[int], x: int) -> int:
    """Polinomni x nuqtasida Horner usuli bilan hisoblash (GF(256) da)."""
    result = 0
    for coeff in reversed(coeffs):
        result = _gf_mul(result, x) ^ coeff
    return result


def split_secret(secret: bytes, threshold: int, total_shares: int) -> list[tuple[int, bytes]]:
    """
    Maxfiy baytlar ketma-ketligini `total_shares` ta bo'lakka bo'ladi,
    tiklash uchun kamida `threshold` ta bo'lak kerak bo'ladi.

    Qaytaradi: [(share_index, share_bytes), ...]
    """
    if threshold > total_shares:
        raise ValueError("threshold, total_shares dan katta bo'lishi mumkin emas")
    if threshold < 2:
        raise ValueError("threshold kamida 2 bo'lishi kerak (aks holda bo'lish ma'nosiz)")

    shares: list[list[int]] = [[] for _ in range(total_shares)]

    for byte_val in secret:
        # Har bir bayt uchun tasodifiy polinom yaratamiz:
        # P(x) = byte_val + c1*x + c2*x^2 + ... + c(t-1)*x^(t-1)
        # P(0) = byte_val - shu sir bo'ladi
        coeffs = [byte_val] + [_secrets.randbelow(256) for _ in range(threshold - 1)]
        for i in range(1, total_shares + 1):
            shares[i - 1].append(_eval_poly(coeffs, i))

    return [(i + 1, bytes(shares[i])) for i in range(total_shares)]


def reconstruct_secret(shares: list[tuple[int, bytes]]) -> bytes:
    """
    Kamida `threshold` ta (x, share_bytes) juftligidan asl sirni tiklaydi
    - Lagranj interpolyatsiyasi orqali, GF(256) da, x=0 nuqtasida baholanadi.
    """
    if len(shares) < 2:
        raise ValueError("Tiklash uchun kamida 2 ta bo'lak kerak")

    length = len(shares[0][1])
    secret = bytearray(length)

    for byte_idx in range(length):
        points = [(x, share[byte_idx]) for x, share in shares]
        # Lagranj interpolyatsiyasi x=0 nuqtasida
        result = 0
        for i, (xi, yi) in enumerate(points):
            numerator = 1
            denominator = 1
            for j, (xj, _) in enumerate(points):
                if i == j:
                    continue
                numerator = _gf_mul(numerator, xj)
                denominator = _gf_mul(denominator, xi ^ xj)
            term = _gf_mul(yi, _gf_div(numerator, denominator))
            result ^= term
        secret[byte_idx] = result

    return bytes(secret)
