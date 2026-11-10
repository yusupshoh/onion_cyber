"""
2-QATLAM: CHEGARA NAZORATI (PERIMETER)

Sof ASGI middleware (BaseHTTPMiddleware EMAS), chunki kerak:
  - So'rov body'si OQIM bo'ylab hisoblanadi. Avvalgi variant faqat Content-Length
    sarlavhasiga qarardi; `Transfer-Encoding: chunked` bilan yuborilgan katta body
    to'liq o'qilib ketardi. Endi haqiqatda kelgan baytlar sanaladi va limitdan
    oshgan zahoti 413 qaytariladi.
  - Body bor har qanday POST/PUT/PATCH (chunked ham) faqat application/json bo'lishi shart.
"""
import json

from app.config import settings


class _BodyTooLarge(Exception):
    pass


async def _send_json(send, status: int, detail: str) -> None:
    body = json.dumps({"detail": detail}).encode()
    await send({"type": "http.response.start", "status": status,
                "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]})
    await send({"type": "http.response.body", "body": body})


class BodySizeLimitMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope["headers"]}
        limit = settings.MAX_BODY_SIZE_BYTES
        declared = headers.get("content-length")
        if declared is not None:
            try:
                length = int(declared)
            except ValueError:
                return await _send_json(send, 400, "Noto'g'ri Content-Length")
            if length < 0:
                return await _send_json(send, 400, "Noto'g'ri Content-Length")
            if length > limit:
                return await _send_json(send, 413, "So'rov hajmi juda katta")
        else:
            length = 0

        has_body = length > 0 or "transfer-encoding" in headers
        if scope["method"] in ("POST", "PUT", "PATCH") and has_body:
            if not headers.get("content-type", "").startswith("application/json"):
                return await _send_json(send, 415, "Faqat application/json qabul qilinadi")

        received = 0
        response_started = False

        async def limited_receive():
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    raise _BodyTooLarge()
            return message

        async def tracking_send(message):
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, limited_receive, tracking_send)
        except _BodyTooLarge:
            if not response_started:
                await _send_json(send, 413, "So'rov hajmi juda katta")
