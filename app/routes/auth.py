from fastapi import APIRouter, Depends, HTTPException, Request, Response, Cookie
from pydantic import ValidationError

from app.config import settings
from app.core import vault_client
from app.core.vault_client import VaultUnavailable
from app.middleware.rate_limiter import enforce_rate_limit, record_attempt
from app.schemas.auth_schemas import LoginRequest, TokenResponse

router = APIRouter()

REFRESH_COOKIE_NAME = "refresh_token"


def _set_refresh_cookie(response: Response, raw_token: str, max_age: int) -> None:
    response.set_cookie(key=REFRESH_COOKIE_NAME, value=raw_token, httponly=True,
        secure=settings.COOKIE_SECURE, samesite="strict", max_age=max_age, path="/auth",)


def _unavailable() -> HTTPException: return HTTPException(status_code=503, detail="Xizmat vaqtincha ishlamayapti, birozdan keyin urining")


@router.post("/login", response_model=TokenResponse)
async def login(request: Request, response: Response, device_key: str = Depends(enforce_rate_limit)):
    try:
        raw_body = await request.json()
        payload = LoginRequest(**raw_body)
    except (ValueError, TypeError, ValidationError) as exc: raise HTTPException(status_code=422, detail="Email yoki parol formati noto'g'ri") from exc
    try:result = await vault_client.login(payload.email, payload.password, source=device_key)
    except VaultUnavailable:raise _unavailable()

    outcome = result.get("result")

    if outcome == "locked":
        record_attempt(device_key, payload.email, success=False)
        raise HTTPException(
            status_code=423,
            detail=f"Hisob vaqtincha bloklangan. {result.get('retry_after', 900)} soniyadan keyin urining.",)

    if outcome != "ok":
        record_attempt(device_key, payload.email, success=False)
        raise HTTPException(status_code=401, detail="Email yoki parol xato")
    record_attempt(device_key, payload.email, success=True)
    _set_refresh_cookie(response, result["refresh_token"], result["refresh_expires_in"])
    return TokenResponse(access_token=result["access_token"], expires_in=result["expires_in"])


@router.post("/refresh", response_model=TokenResponse)
async def refresh(response: Response, refresh_token: str | None = Cookie(default=None, alias=REFRESH_COOKIE_NAME)):
    if not refresh_token: raise HTTPException(status_code=401, detail="Refresh token topilmadi")
    try: result = await vault_client.refresh(refresh_token)
    except VaultUnavailable: raise _unavailable()
    outcome = result.get("result")
    if outcome == "theft":
        response.delete_cookie(REFRESH_COOKIE_NAME, path="/auth")
        raise HTTPException( status_code=401, detail="Xavfsizlik sababli barcha sessiyalar bekor qilindi. Qayta kiring.", )
    if outcome != "ok":
        response.delete_cookie(REFRESH_COOKIE_NAME, path="/auth")
        raise HTTPException(status_code=401, detail="Sessiya muddati tugagan, qayta kiring")
    _set_refresh_cookie(response, result["refresh_token"], result["refresh_expires_in"])
    return TokenResponse(access_token=result["access_token"], expires_in=result["expires_in"])


@router.post("/logout")
async def logout(response: Response, refresh_token: str | None = Cookie(default=None, alias=REFRESH_COOKIE_NAME)):
    if refresh_token:
        try: await vault_client.logout(refresh_token)
        except VaultUnavailable: raise _unavailable()
    response.delete_cookie(REFRESH_COOKIE_NAME, path="/auth")
    return {"result": "logged_out"}
