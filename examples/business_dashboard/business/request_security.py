"""Bound request bodies, enforce browser origin, and set response protections."""

from urllib.parse import urlsplit
from threading import BoundedSemaphore

import anyio
from starlette.responses import JSONResponse

MAX_BODY_BYTES = 32768
BODY_READ_TIMEOUT_SECONDS = 10.0
BODY_READ_CAPACITY = 32
SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cache-Control": "no-store",
}


def validate_origin(value):
    parts = urlsplit(value)
    if (parts.scheme not in ("http", "https") or not parts.hostname or parts.username or parts.password
            or parts.path or parts.query or parts.fragment or value != value.rstrip("/")):
        raise ValueError("Public origin must be scheme://hostname[:port] without a path.")
    if parts.scheme == "http" and parts.hostname not in ("localhost", "127.0.0.1", "::1"):
        raise ValueError("Public origins require HTTPS; HTTP is only for loopback demonstrations.")
    _ = parts.port  # Validate malformed port syntax now.
    return parts


class RequestSecurityMiddleware:
    def __init__(self, app, public_origin, challenge_required=False, on_event=None):
        self.app = app
        self.public_origin = public_origin
        self.secure = public_origin.startswith("https://")
        self.challenge_required = challenge_required
        self.body_slots = BoundedSemaphore(BODY_READ_CAPACITY)
        self.on_event = on_event

    def _record(self, event):
        if self.on_event is not None:
            self.on_event(event)

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def protected_send(message):
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                additions = dict(SECURITY_HEADERS)
                if self.challenge_required:
                    additions["Content-Security-Policy"] = (
                        additions["Content-Security-Policy"]
                        .replace("script-src 'self'", "script-src 'self' https://challenges.cloudflare.com")
                        .replace("connect-src 'self'", "connect-src 'self' https://challenges.cloudflare.com")
                        + "; frame-src https://challenges.cloudflare.com"
                    )
                if self.secure:
                    additions["Strict-Transport-Security"] = "max-age=31536000"
                headers += [(key.lower().encode(), value.encode()) for key, value in additions.items()]
                message["headers"] = headers
            await send(message)

        async def reject(status, detail, headers=None):
            await JSONResponse({"detail": detail}, status_code=status, headers=headers)(scope, receive, protected_send)

        if scope["method"] in ("POST", "PUT", "PATCH", "DELETE"):
            headers = {}
            for key, value in scope.get("headers", []):
                if key in headers and key in (b"origin", b"content-length", b"content-type"):
                    await reject(400, "Invalid request headers.")
                    return
                headers[key] = value
            if headers.get(b"origin", b"").decode("latin-1") != self.public_origin:
                await reject(403, "Requests must come from this dashboard's origin.")
                return
            if headers.get(b"sec-fetch-site", b"same-origin") not in (b"same-origin", b"none"):
                await reject(403, "Cross-site requests are not allowed.")
                return
            if headers.get(b"content-type", b"").split(b";", 1)[0].strip().lower() != b"application/json":
                await reject(415, "Use a JSON request body.")
                return
            try:
                length = int(headers.get(b"content-length", b"0"))
            except ValueError:
                await reject(400, "Invalid content length.")
                return
            if length < 0 or length > MAX_BODY_BYTES:
                self._record("body_oversized")
                await reject(413, "The request is too large.")
                return
            if not self.body_slots.acquire(blocking=False):
                self._record("body_capacity_denied")
                await reject(429, "Request intake is temporarily busy. Please try again shortly.", {"Retry-After": "1"})
                return
            body = bytearray()
            timed_out = oversized = False
            try:
                try:
                    # The deadline covers the whole body, including clients that
                    # keep sending tiny chunks. No slots wait in a reader queue.
                    with anyio.fail_after(BODY_READ_TIMEOUT_SECONDS):
                        while True:
                            # Already-buffered or empty chunks may make receive
                            # return immediately. Let deadlines and other requests
                            # run even when that transport call never suspends.
                            await anyio.lowlevel.checkpoint()
                            message = await receive()
                            if message["type"] == "http.disconnect":
                                return
                            chunk = message.get("body", b"")
                            if len(body) + len(chunk) > MAX_BODY_BYTES:
                                oversized = True
                                break
                            body.extend(chunk)
                            if not message.get("more_body", False):
                                break
                except TimeoutError:
                    timed_out = True
            finally:
                # A complete body releases intake before database, password,
                # provider or response work; cancellation releases it as well.
                self.body_slots.release()
            if timed_out:
                self._record("body_timeout")
                await reject(408, "The request body took too long. Please try again.")
                return
            if oversized:
                self._record("body_oversized")
                await reject(413, "The request is too large.")
                return
            sent = False

            async def bounded_receive():
                nonlocal sent
                if not sent:
                    sent = True
                    return {"type": "http.request", "body": bytes(body), "more_body": False}
                return await receive()

            await self.app(scope, bounded_receive, protected_send)
        else:
            await self.app(scope, receive, protected_send)
