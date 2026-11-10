"""Fayl yozish yordamchilari (Vault ichki)."""
import os
from pathlib import Path


def atomic_write(path: Path, data: bytes, mode: int = 0o600) -> None:
    """tmp fayl -> fsync -> os.replace -> katalog fsync. Jarayon o'rtada to'xtasa
    fayl yo eski, yo to'liq yangi bo'ladi (yarim yozilgan holat bo'lmaydi)."""
    path = Path(path)
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    try:
        os.chmod(tmp, mode)
    except OSError:
        pass
    os.replace(tmp, path)
    try:
        dfd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    except OSError:  # Windows katalogni ochishga ruxsat bermaydi
        pass
