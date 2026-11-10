import sys

if sys.version_info < (3, 10):
    raise RuntimeError(
        f"Python 3.10+ kerak (hozir {sys.version_info.major}.{sys.version_info.minor}). "
        "Kod `str | None` kabi sintaksis va yangi kutubxona versiyalarini ishlatadi."
    )
