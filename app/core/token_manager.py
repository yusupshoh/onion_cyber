
import jwt

from app.core import vault_client

_public_key_pem: str | None = None


async def _get_public_key() -> str:
    global _public_key_pem
    if _public_key_pem is None: _public_key_pem = await vault_client.fetch_public_key()
    return _public_key_pem


async def verify_access_token(token: str) -> dict:
    key = await _get_public_key()
    try: payload = jwt.decode(token, key, algorithms=["EdDSA"], options={"require": ["exp", "sub"]})
    except jwt.PyJWTError as exc: raise ValueError("Token yaroqsiz yoki muddati tugagan") from exc
    if payload.get("type") != "access": raise ValueError("Noto'g'ri token turi")
    return payload
