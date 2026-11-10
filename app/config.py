import os


class Settings:
    """
    CHEGARA XIZMATI sozlamalari. Bu jarayonda ATAYLAB yo'q:
      JWT imzolash kaliti, parol pepper'i, admin passphrase, KEK manbalari.
    Faqat Vault bilan imzolangan aloqa uchun INTERNAL_SIGNING_KEY bor.
    (Token muddatlari endi Vault tomonidan belgilanadi.)
    """
    VAULT_URL: str = os.environ.get("VAULT_URL", "http://127.0.0.1:8500")
    INTERNAL_SIGNING_KEY: str = os.environ.get("INTERNAL_SIGNING_KEY", "")

    ALLOWED_ORIGINS: list[str] = [
        o.strip() for o in os.environ.get("ALLOWED_ORIGINS", "http://localhost:3000").split(",") if o.strip()
    ]

    # Reverse proxy ortida ishlasangiz: ishonchli proxy IP/CIDR'lari (vergul bilan).
    # X-Forwarded-For FAQAT shu manzillardan kelgan so'rovlarda hisobga olinadi.
    TRUSTED_PROXIES: list[str] = [
        p.strip() for p in os.environ.get("TRUSTED_PROXIES", "").split(",") if p.strip()
    ]

    # 3-qatlam: IP darajasidagi darajasidagi sirg'anuvchi oyna
    RATE_LIMIT_WINDOW_SECONDS: int = int(os.environ.get("RATE_LIMIT_WINDOW_SECONDS", 60))
    RATE_LIMIT_MAX_ATTEMPTS: int = int(os.environ.get("RATE_LIMIT_MAX_ATTEMPTS", 8))

    MAX_BODY_SIZE_BYTES: int = 16 * 1024
    # Bitta IP'dan shuncha XILMA-XIL email'ga xato urinish = credential stuffing
    DISTINCT_EMAIL_FAILS_THRESHOLD: int = int(os.environ.get("DISTINCT_EMAIL_FAILS_THRESHOLD", 10))
    MAX_TRACKED_CLIENTS: int = int(os.environ.get("MAX_TRACKED_CLIENTS", 100_000))

    COOKIE_SECURE: bool = os.environ.get("NODE_ENV", "production") != "development"


settings = Settings()


def validate_settings() -> None:
    if not settings.INTERNAL_SIGNING_KEY:
        raise RuntimeError("INTERNAL_SIGNING_KEY o'rnatilmagan")
