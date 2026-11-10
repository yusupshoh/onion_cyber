
import ipaddress

from fastapi import Request

from app.config import settings

_NETS = [ipaddress.ip_network(p, strict=False) for p in settings.TRUSTED_PROXIES]


def _trusted(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in n for n in _NETS)


def get_client_ip(request: Request) -> str:
    peer = request.client.host if request.client else "unknown"
    if not _NETS or not _trusted(peer):
        return peer
    xff = request.headers.get("x-forwarded-for", "")
    chain = [x.strip() for x in xff.split(",") if x.strip()]
    for hop in reversed(chain):
        if not _trusted(hop):
            return hop
    return peer
