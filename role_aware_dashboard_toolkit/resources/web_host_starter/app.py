"""Editable FastAPI HTTP boundary. Run with uvicorn app:create_app --factory."""
from __future__ import annotations

import json
import logging
import math
import os
from pathlib import Path
import sqlite3
from urllib.parse import urlsplit

from fastapi import Depends, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from role_aware_dashboard_toolkit.access import AccessDenied
from role_aware_dashboard_toolkit.access_store import FreezeConflict

from host.actions import ActionConflict, ActionDenied, ActionValidation
from host.auth import AuthenticationRequired
from host.service import WorkItems
from host.storage import StorageUnavailable


LOG = logging.getLogger(__name__)
STATIC = Path(__file__).resolve().parent / "static"
ASSETS = {"app.js", "app.css", "theme.css", "components.css", "components.js", "web-config.js"}
SECURITY_HEADERS = {
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "content-security-policy": "default-src 'self'; script-src 'self'; style-src 'self'; "
        "img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; "
        "frame-ancestors 'none'; form-action 'self'",
}


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON field.")
        result[key] = value
    return result


def _finite_number(value):
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("Nonfinite JSON number.")
    return number


def checked_origin(value: str) -> str:
    parsed = urlsplit(value)
    try:
        parsed.port
    except ValueError:
        raise ValueError("RADT_PUBLIC_ORIGIN requires a valid origin.") from None
    if (parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username
            or parsed.password or parsed.path or parsed.query or parsed.fragment
            or value != f"{parsed.scheme}://{parsed.netloc}" or not value.isascii()):
        raise ValueError("RADT_PUBLIC_ORIGIN requires a single origin without a path.")
    if parsed.scheme == "http" and parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
        raise ValueError("Non-loopback hosting requires an HTTPS public origin.")
    return value


class HTTPBoundary:
    """Bound request bodies and reject foreign hosts/origins before route parsing."""

    def __init__(self, app, origin: str):
        self.app, self.origin = app, origin
        self.url = urlsplit(origin)

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        async def secured_send(message):
            if message["type"] == "http.response.start":
                replaced = {name.encode("ascii") for name in SECURITY_HEADERS}
                headers = [(key, value) for key, value in message.get("headers", [])
                           if key.lower() not in replaced]
                headers.extend((name.encode("ascii"), value.encode("ascii"))
                               for name, value in SECURITY_HEADERS.items())
                message = {**message, "headers": headers}
            await send(message)

        async def reject(code, detail):
            await JSONResponse({"detail": detail}, status_code=code)(scope, receive, secured_send)

        hosts = [v.decode("latin1") for k, v in scope["headers"] if k.lower() == b"host"]
        origins = [v.decode("latin1") for k, v in scope["headers"] if k.lower() == b"origin"]
        if hosts != [self.url.netloc] or scope["scheme"] != self.url.scheme:
            return await reject(400, "This host or transport is not configured.")
        if origins and origins != [self.origin]:
            return await reject(403, "Cross-origin requests are not accepted.")
        if any(k.lower() == b"sec-fetch-site" and v == b"cross-site" for k, v in scope["headers"]):
            return await reject(403, "Cross-site requests are not accepted.")
        body = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            chunk = message.get("body", b"")
            if len(body) + len(chunk) > 16384:
                return await reject(413, "Request body is too large.")
            body.extend(chunk)
            if not message.get("more_body", False):
                break
        if body and scope["method"] == "POST" and scope["path"].startswith("/api/"):
            try:
                json.loads(body.decode("utf-8"), object_pairs_hook=_unique_object,
                           parse_constant=_finite_number, parse_float=_finite_number)
            except (ValueError, UnicodeError, RecursionError):
                return await reject(422, "Supply valid JSON with distinct fields and finite values.")
        delivered = False

        async def bounded_receive():
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return await receive()

        await self.app(scope, bounded_receive, secured_send)


class Input(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class NewItem(Input):
    label: str = Field(min_length=1, max_length=120)
    starts_at: str = Field(min_length=1, max_length=64)
    owner: str = Field(min_length=1, max_length=64)


class Change(Input):
    expected_revision: int = Field(ge=0, lt=9223372036854775807)
    reason: str = Field(default="", max_length=500)


class Reschedule(Change):
    starts_at: str = Field(min_length=1, max_length=64)


class StatusChange(Change):
    status: str = Field(min_length=1, max_length=20)


class FreezeChange(Input):
    expected_revision: int = Field(ge=0, lt=9223372036854775807)
    frozen: bool


def create_app(*, data_dir: str | Path | None = None, public_origin: str | None = None) -> FastAPI:
    service = WorkItems(data_dir if data_dir is not None else os.environ.get("RADT_DATA_DIR", ""))
    origin = checked_origin(public_origin or os.environ.get("RADT_PUBLIC_ORIGIN", "http://127.0.0.1:8093"))
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(HTTPBoundary, origin=origin)

    async def token(request: Request) -> str:
        headers = request.headers.getlist("authorization")
        if len(headers) != 1 or not headers[0].startswith("Bearer "):
            raise AuthenticationRequired()
        return headers[0][7:]

    async def authentication_error(request, exception):
        return JSONResponse({"detail": "A current access token is required."}, status_code=401,
                            headers={"WWW-Authenticate": "Bearer"})

    async def denied(request, exception):
        return JSONResponse({"detail": "This action is not permitted. Refresh your access and freeze state."},
                            status_code=403)

    async def conflict(request, exception):
        return JSONResponse({"detail": "This record or freeze state changed. Reload before trying again."},
                            status_code=409)

    async def invalid(request, exception):
        # Pydantic errors can echo user inputs; only expose the safe host message.
        detail = str(exception) if isinstance(exception, ActionValidation) else "Check the submitted fields."
        return JSONResponse({"detail": detail}, status_code=422)

    async def unavailable(request, exception):
        LOG.error("Host storage operation failed (%s)", type(exception).__name__)
        return JSONResponse({"detail": "Storage is unavailable. No successful change was recorded."},
                            status_code=503)

    app.add_exception_handler(AuthenticationRequired, authentication_error)
    for error in (AccessDenied, ActionDenied):
        app.add_exception_handler(error, denied)
    for error in (ActionConflict, FreezeConflict):
        app.add_exception_handler(error, conflict)
    for error in (ActionValidation, RequestValidationError):
        app.add_exception_handler(error, invalid)
    for error in (StorageUnavailable, sqlite3.Error, OSError):
        app.add_exception_handler(error, unavailable)

    @app.get("/")
    def index():
        return FileResponse(STATIC / "index.html")

    @app.get("/assets/{name}")
    def asset(name: str):
        if name not in ASSETS:
            return JSONResponse({"detail": "Asset not found."}, status_code=404)
        return FileResponse(STATIC / name)

    @app.get("/healthz")
    def health():
        with service.transaction():
            pass
        return {"status": "ok"}

    @app.get("/api/session")
    def session(access_token: str = Depends(token)):
        return service.session(access_token)

    @app.get("/api/items")
    def items(access_token: str = Depends(token)):
        return {"items": service.items(access_token)}

    @app.post("/api/items", status_code=201)
    def create(payload: NewItem, access_token: str = Depends(token)):
        return service.create(access_token, **payload.model_dump())

    @app.post("/api/items/{item_id}/reschedule")
    def reschedule(item_id: str, payload: Reschedule, access_token: str = Depends(token)):
        return service.change(access_token, item_id, expected_revision=payload.expected_revision,
                              action="rescheduled", value=payload.starts_at, reason=payload.reason)

    @app.post("/api/items/{item_id}/status")
    def change_status(item_id: str, payload: StatusChange, access_token: str = Depends(token)):
        return service.change(access_token, item_id, expected_revision=payload.expected_revision,
                              action="status_changed", value=payload.status, reason=payload.reason)

    @app.post("/api/freeze")
    def freeze(payload: FreezeChange, access_token: str = Depends(token)):
        return service.freeze(access_token, **payload.model_dump())

    @app.get("/api/history")
    def history(access_token: str = Depends(token)):
        return {"history": service.history(access_token)}

    return app
