"""
1-QATLAM: TRANSPORT/XAVFSIZLIK HEADER'LARI

Bir nechta hujum turiga qarshi bir vaqtda:
  - HSTS: protokolni pasaytirish (HTTPS -> HTTP) hujumiga qarshi
  - X-Content-Type-Options: MIME-sniffing orqali script bajarishga qarshi
  - X-Frame-Options / frame-ancestors: clickjacking'ga qarshi
  - Content-Security-Policy: XSS orqali tashqi resurs yuklashga qarshi
  - Referrer-Policy: URL orqali maxfiy ma'lumot sizib chiqishiga qarshi
  - Permissions-Policy: brauzer API'laridan ruxsatsiz foydalanishga qarshi

Sof ASGI middleware: BaseHTTPMiddleware so'rov body'sini o'z task-group'ida
o'qiydi va undagi istisnolarni ExceptionGroup'ga o'rab yuboradi (body limit
xatosi 413 o'rniga 500 bo'lib qolgan edi).

DIQQAT: uvicorn'ning "Server" sarlavhasini bu yerdan o'chirib BO'LMAYDI (uni
uvicorn o'zi qo'shadi). Uni o'chirish uchun: uvicorn ... --no-server-header
"""
_HEADERS = [
    (b"strict-transport-security", b"max-age=63072000; includeSubDomains; preload"),
    (b"x-content-type-options", b"nosniff"),
    (b"x-frame-options", b"DENY"),
    (b"content-security-policy", b"default-src 'none'; frame-ancestors 'none'"),
    (b"referrer-policy", b"no-referrer"),
    (b"permissions-policy", b"geolocation=(), microphone=(), camera=()"),
    (b"x-permitted-cross-domain-policies", b"none"),
]


class SecurityHeadersMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                present = {k.lower() for k, _ in message.get("headers", [])}
                message = dict(message)
                message["headers"] = list(message.get("headers", [])) + [
                    (k, v) for k, v in _HEADERS if k not in present
                ]
            await send(message)

        await self.app(scope, receive, send_with_headers)
