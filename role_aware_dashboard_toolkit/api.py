# role_aware_dashboard_toolkit/api.py
# Optional REST API for Role-Aware Dashboard Toolkit dashboards.
#
# Exposes profile CRUD, control reads, and role info over HTTP with API-key
# authentication. From a reviewed toolkit source checkout, install the API extra:
#     python -m pip install ".[api]"
# Or install a reviewed local toolkit wheel with [api] appended to its filename.
#
# Usage:
#     from role_aware_dashboard_toolkit.api import create_app
#     app = create_app(registry=my_registry)
#     # uvicorn myapp:app --host 0.0.0.0 --port 8000
#     # (public bind is deployment-only behind trusted network controls)
#
# Set ROLE_AWARE_DASHBOARD_TOOLKIT_API_KEY env var before serving the API. Anonymous local/demo
# access requires explicit opt-in via create_app(..., allow_anonymous=True) or
# ROLE_AWARE_DASHBOARD_TOOLKIT_API_ALLOW_ANONYMOUS=true.

from __future__ import annotations

import os
import logging
import hmac
from typing import Any

from .audit import AuditLog
from ._record_projection import project_audit_events, project_record
from .controls import (
    ControlDef,
    ControlRegistry,
    _RejectedControlValue,
    _exact_control_value,
    _looks_like_hex_color,
)
from .profile_store import BaseProfileStore, FileProfileStore
from .profiles import (
    _InvalidProfileError,
    _contains_secret_fields,
    _public_profile_values as _profile_response_values,
    _require_profile_shape,
    _restore_profile_data,
    save_profile,
    load_profile_data,
    list_profiles,
    delete_profile,
)
from .security import (
    SecurityContext,
    make_security_context,
    get_role,
    has_perm,
    RoleDef,
    BUILTIN_ROLES,
)
from .sensitive_values import REDACTED_SECRET
from .store_diagnostics import StorePathSecurityError, store_read_error_total
from .version import ROLE_AWARE_DASHBOARD_TOOLKIT_VERSION

logger = logging.getLogger(__name__)
_OPTIONAL_API_DEPENDENCIES = {"fastapi", "pydantic"}
_FASTAPI_IMPORT_ERROR: ImportError | None = None


def _is_missing_optional_api_dependency(exc: ImportError) -> bool:
    if not isinstance(exc, ModuleNotFoundError):
        return False
    missing = str(getattr(exc, "name", "") or "").split(".", 1)[0]
    return missing in _OPTIONAL_API_DEPENDENCIES

try:
    from fastapi import FastAPI, HTTPException, Depends, Header, Request, Response
    from fastapi.exception_handlers import http_exception_handler
    from fastapi.exceptions import RequestValidationError
    from fastapi.responses import JSONResponse
    from starlette.exceptions import HTTPException as StarletteHTTPException
    from pydantic import BaseModel, Field
    FASTAPI_AVAILABLE = True
except ImportError as exc:
    _FASTAPI_IMPORT_ERROR = exc
    FastAPI = None  # type: ignore
    Depends = None  # type: ignore
    Header = None  # type: ignore
    Request = None  # type: ignore
    Response = None  # type: ignore
    JSONResponse = None  # type: ignore
    RequestValidationError = None  # type: ignore
    StarletteHTTPException = None  # type: ignore
    http_exception_handler = None  # type: ignore

    class HTTPException(Exception):  # type: ignore
        def __init__(self, status_code: int, detail: str) -> None:
            super().__init__(detail)
            self.status_code = status_code
            self.detail = detail

    class BaseModel:  # type: ignore
        def __init__(self, **data: Any) -> None:
            for key, value in data.items():
                setattr(self, key, value)

    def Field(default: Any = None, *, default_factory: Any = None, **_: Any) -> Any:  # type: ignore
        if default_factory is not None:
            return default_factory()
        return default

    FASTAPI_AVAILABLE = False

# Auth

_API_KEY_ENV = "ROLE_AWARE_DASHBOARD_TOOLKIT_API_KEY"
_API_ROLE_ENV = "ROLE_AWARE_DASHBOARD_TOOLKIT_API_ROLE"
_ALLOW_ANONYMOUS_ENV = "ROLE_AWARE_DASHBOARD_TOOLKIT_API_ALLOW_ANONYMOUS"
_ANONYMOUS_ROLE = "Anonymous"
_ANONYMOUS_PERMS = {"can_view_metrics": True}
_DEFAULT_AUTHENTICATED_ROLE = "Viewer"
_TRUE_VALUES = {"1", "true", "yes", "on"}


def _require_fastapi() -> None:
    if FASTAPI_AVAILABLE:
        return
    if _FASTAPI_IMPORT_ERROR is not None and not _is_missing_optional_api_dependency(_FASTAPI_IMPORT_ERROR):
        raise _FASTAPI_IMPORT_ERROR
    raise ImportError(
        "FastAPI is required for the Role-Aware Dashboard Toolkit API module. "
        'From your reviewed toolkit source checkout, run: python -m pip install ".[api]". '
        "Or install an absolute source path or reviewed local wheel filename "
        "with [api] appended. No package-index release is assumed. "
        "Help: python -m role_aware_dashboard_toolkit guide api"
    )




def _env_flag(name: str) -> bool:
    return os.getenv(name, "").strip().lower() in _TRUE_VALUES


def _context_for_role(role_name: str, custom_roles: dict[str, RoleDef] | None) -> SecurityContext:
    if role_name == _ANONYMOUS_ROLE:
        return make_security_context(_ANONYMOUS_ROLE, _ANONYMOUS_PERMS)
    role = get_role(role_name, custom_roles)
    if role is None:
        raise HTTPException(status_code=403, detail=f"Unknown API role '{role_name}'")
    return make_security_context(role.name, role.perms)


def _validate_role_config(role_name: str, custom_roles: dict[str, RoleDef] | None, *, field_name: str) -> None:
    if role_name == _ANONYMOUS_ROLE:
        return
    role = get_role(role_name, custom_roles)
    if role is None:
        raise ValueError(f"Unknown {field_name} '{role_name}'")


def _resolve_api_context(app_state: _AppState, x_api_key: str) -> SecurityContext:
    """Resolve the request's API-key role scope or reject the request."""
    expected = str(os.getenv(_API_KEY_ENV, "") or "")
    supplied = str(x_api_key or "")
    if expected:
        # String compare_digest accepts ASCII only. Reject malformed headers
        # and unsupported host keys without exposing either or enabling the
        # anonymous fallback; supported keys retain constant-time comparison.
        if not supplied.isascii() or not expected.isascii() or not hmac.compare_digest(supplied, expected):
            raise HTTPException(status_code=401, detail="Unauthorized")
        return _context_for_role(app_state.api_role or _DEFAULT_AUTHENTICATED_ROLE, app_state.custom_roles)
    if app_state.allow_anonymous:
        return _context_for_role(app_state.anonymous_role, app_state.custom_roles)
    if x_api_key:
        raise HTTPException(status_code=401, detail="Unauthorized")
    raise HTTPException(status_code=401, detail="API key required")


def _require_permission(ctx: SecurityContext, permission: str) -> None:
    # An empty or missing permission name denies, as the dashboard UI does.
    if not isinstance(permission, str) or not permission:
        raise HTTPException(status_code=403, detail="Forbidden: no permission is declared")
    if not has_perm(ctx, permission):
        raise HTTPException(status_code=403, detail=f"Forbidden: requires {permission}")


_DEFAULT_MAX_BODY_BYTES = 1024 * 1024
_MAX_JSON_DEPTH = 32


def _body_too_large(max_bytes: int) -> str:
    return f"Request body exceeds the API's limit of {max_bytes} bytes. Nothing was changed."


class _RequestBodyLimit:
    """Refuse a request body over the limit before a route stores or copies it.

    A declared Content-Length over the limit is refused without reading the
    body; a streamed body is counted as it arrives.
    """

    def __init__(self, app: Any, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        for name, value in scope.get("headers", ()):
            if name.lower() == b"content-length" and self._declares_too_much(value):
                response = JSONResponse({"detail": _body_too_large(self.max_bytes)}, status_code=413)
                await response(scope, receive, send)
                return
        received = 0

        async def limited_receive() -> Any:
            nonlocal received
            message = await receive()
            if message.get("type") == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    raise HTTPException(status_code=413, detail=_body_too_large(self.max_bytes))
            return message

        await self.app(scope, limited_receive, send)

    def _declares_too_much(self, value: bytes) -> bool:
        digits = value.strip().lstrip(b"0") or b"0"
        if not digits.isdigit():
            return False  # malformed: the streamed count below still applies
        # Compare lengths first: int() refuses very long digit strings.
        return len(digits) > len(str(self.max_bytes)) or int(digits) > self.max_bytes


def _validation_error_response(_request: Any, exc: Any) -> Any:
    """Report request validation errors without echoing the submitted values.

    FastAPI's default response includes each rejected ``input``: it repeats a
    client's secrets back and can fail to encode a deeply nested value.
    """
    return JSONResponse(status_code=422, content={"detail": [
        {"type": str(error.get("type", "")), "loc": list(error.get("loc", ())),
         "msg": str(error.get("msg", ""))}
        for error in exc.errors()
    ]})


_BODY_TOO_DEEP = (
    f"Request body JSON is nested too deeply to parse (a field allows {_MAX_JSON_DEPTH} levels). "
    "Nothing was changed."
)


async def _http_error_response(request: Any, exc: Any) -> Any:
    """Report JSON too deep for the parser as the depth refusal it is.

    FastAPI turns any body-parsing failure into a generic 400. Python's JSON
    parser stops at its recursion limit (about 1,000 levels before Python 3.12,
    deeper on later versions), so a body nested past it never reaches the
    field depth check; answer it with the same 422 on every version.
    """
    if exc.status_code == 400 and isinstance(exc.__cause__, RecursionError):
        return JSONResponse(status_code=422, content={"detail": _BODY_TOO_DEEP})
    return await http_exception_handler(request, exc)


def _require_json_depth(value: Any, field_name: str) -> None:
    """Refuse deeply nested JSON before profile copies or audit records recurse."""
    pending = [(value, 1)]
    while pending:
        item, depth = pending.pop()
        if not isinstance(item, (dict, list)):
            continue
        if depth > _MAX_JSON_DEPTH:
            raise HTTPException(
                status_code=422,
                detail=(
                    f"Field '{field_name}' is nested more than {_MAX_JSON_DEPTH} levels deep. "
                    "Nothing was changed."
                ),
            )
        children = item.values() if isinstance(item, dict) else item
        pending.extend((child, depth + 1) for child in children)


def _validated_body_limit(max_body_bytes: Any) -> int:
    if (isinstance(max_body_bytes, bool) or not isinstance(max_body_bytes, int)
            or max_body_bytes <= 0):
        raise ValueError("max_body_bytes must be a positive whole number of bytes")
    return max_body_bytes


_READ_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
_CROSS_SITE_REFUSAL = (
    "State-changing requests without an X-API-Key header must send "
    "Content-Type: application/json. This refuses requests that another web "
    "site could make a browser send."
)


def _is_json_media_type(content_type: str) -> bool:
    media_type = content_type.split(";", 1)[0].strip().lower()
    return media_type == "application/json" or (
        media_type.startswith("application/") and media_type.endswith("+json")
    )


def _require_preflighted_request(request: Any) -> None:
    """Refuse a state change that a browser could send cross-site unprompted.

    A cross-site form or no-cors fetch can send POST with no custom header and
    only a form, multipart or text/plain body, without a CORS preflight. Any
    X-API-Key header or a JSON Content-Type makes the request non-simple, so a
    browser must preflight it, and this API answers no preflight. Key-bearing
    clients are unaffected; anonymous demo clients send a JSON Content-Type.
    """
    if request.method in _READ_METHODS or "x-api-key" in request.headers:
        return
    if _is_json_media_type(request.headers.get("content-type", "")):
        return
    raise HTTPException(status_code=415, detail=_CROSS_SITE_REFUSAL)


def _canonical_api_profile_id(profile_id: str) -> str:
    """Return the identifier that the API will persist and clients can address.

    Normalize before saving so a file store's filename and payload agree. Avoid
    path separators, URL delimiters and encoded separators whose interpretation
    can change across clients/proxies. Unicode and ordinary spaces are retained;
    clients must URL-encode the returned identifier as one path segment.
    """
    canonical = profile_id.strip()
    if (
        not canonical
        or canonical in {".", ".."}
        or not profile_id.isprintable()
        or any(char in canonical for char in "/\\%?#")
    ):
        raise HTTPException(
            status_code=422,
            detail=(
                "Invalid profile_id: use a nonempty printable name without "
                "slash, backslash, percent, question mark or hash; '.' and '..' "
                "are reserved. Surrounding spaces are removed."
            ),
        )
    return canonical


# Request / response models

class ControlValue(BaseModel):
    key: str
    value: Any
    name: str = ""
    kind: str = ""
    group: str = ""
    sensitive: bool = False


class ControlUpdateRequest(BaseModel):
    # A missing wrapper or a misspelled field is refused, never a silent no-op.
    model_config = {"extra": "forbid"}

    values: dict[str, Any] = Field(
        ...,
        description="Map of control key -> new value",
    )


class ProfileRequest(BaseModel):
    # Profiles snapshot the API's live values; a "values" field would be ignored.
    model_config = {"extra": "forbid"}

    profile_id: str
    role: str = ""
    extra: dict[str, Any] = Field(default_factory=dict)


class ProfileResponse(BaseModel):
    profile_id: str
    saved_at: str = ""
    role: str = ""
    values: dict[str, Any] = Field(default_factory=dict)


class RoleResponse(BaseModel):
    name: str
    description: str = ""
    perms: dict[str, bool] = Field(default_factory=dict)


class HealthResponse(BaseModel):
    status: str = "ok"


# App state container

class _AppState:
    """Holds references shared across endpoints."""

    def __init__(
        self,
        registry: ControlRegistry,
        audit: AuditLog | None = None,
        custom_roles: dict[str, RoleDef] | None = None,
        profile_dir: str = "profiles",
        profile_store: BaseProfileStore | None = None,
        allow_anonymous: bool = False,
        anonymous_role: str = _ANONYMOUS_ROLE,
        api_role: str | None = None,
    ) -> None:
        self.registry = registry
        self.audit = audit if audit is not None else AuditLog()
        self.custom_roles = custom_roles
        self.profile_dir = profile_dir
        self.profile_store = profile_store
        self.allow_anonymous = bool(allow_anonymous)
        self.anonymous_role = str(anonymous_role or _ANONYMOUS_ROLE)
        self.api_role = str(api_role) if api_role else None
        # In-memory state mirror (since there's no Streamlit session)
        self.state: dict[str, Any] = {}
        self._init_defaults()

    def _init_defaults(self) -> None:
        for ctrl in self.registry.all():
            if ctrl.key not in self.state:
                self.state[ctrl.key] = ctrl.default


def _make_require_api_context(app_state: _AppState):
    def require_api_context(permission: str):
        def dependency(
            request: Request,
            x_api_key: str = Header(default="", alias="X-API-Key"),
        ) -> SecurityContext:
            ctx = _resolve_api_context(app_state, x_api_key)
            _require_preflighted_request(request)
            _require_permission(ctx, permission)
            return ctx

        return dependency

    return require_api_context


def _control_value(app_state: _AppState, key: str, *, can_read: bool = True) -> ControlValue:
    ctrl = app_state.registry.get(key)
    if ctrl is None:
        raise HTTPException(status_code=404, detail=f"Control '{key}' not found")
    return ControlValue(
        key=ctrl.key,
        value=REDACTED_SECRET if ctrl.sensitive or not can_read else project_record(
            {"controls": {ctrl.key: app_state.state.get(ctrl.key, ctrl.default)}},
            app_state.registry,
        )["controls"][ctrl.key],
        name=ctrl.name,
        kind=ctrl.kind,
        group=ctrl.group,
        sensitive=ctrl.sensitive,
    )


def _require_safe_api_coercion(ctrl: ControlDef, value: Any) -> None:
    """Reject public string conversion that would erase nested secret labels."""
    if ctrl.sensitive or ctrl.kind not in {"text", "color"}:
        return
    if ctrl.kind == "text":
        source = ctrl.default if value is None else value
    else:
        source = value or ctrl.default or "#3b82f6"
        # Invalid color input falls back to the configured default, which is
        # also stringified by the core sanitizer.
        if not _looks_like_hex_color(str(source).strip()):
            source = ctrl.default
    if _contains_secret_fields(source):
        raise HTTPException(
            status_code=422,
            detail="A public control cannot convert structured secret fields to text.",
        )


def _live_profile_response_values(app_state: _AppState, ctx: SecurityContext) -> dict[str, Any]:
    # A save/load grant authorizes the operation, not disclosure of its snapshot.
    if not has_perm(ctx, "can_view_metrics"):
        return {}
    return _profile_response_values(
        app_state.registry, app_state.registry.persistable_snapshot(app_state.state),
    )


def _register_health_route(app: FastAPI) -> None:
    @app.get("/health", response_model=HealthResponse)
    async def health_check():
        return HealthResponse(status="ok")


def _register_control_routes(app: FastAPI, app_state: _AppState, require_api_context: Any) -> None:
    @app.get("/controls", response_model=list[ControlValue])
    async def get_controls(_: SecurityContext = Depends(require_api_context("can_view_metrics"))):
        """Return all control keys and their current values."""
        return [_control_value(app_state, ctrl.key) for ctrl in app_state.registry.all()]

    @app.get("/controls/{key:path}")
    async def get_control(key: str, _: SecurityContext = Depends(require_api_context("can_view_metrics"))):
        """Return a single control's current value."""
        return _control_value(app_state, key)

    @app.patch("/controls", response_model=list[ControlValue])
    async def update_controls(
        req: ControlUpdateRequest,
        ctx: SecurityContext = Depends(require_api_context("can_edit_controls")),
    ):
        """Update one or more control values. Returns the updated controls."""
        pending_updates = []
        for key, value in req.values.items():
            _require_json_depth(value, key)
            ctrl = app_state.registry.get(key)
            if ctrl is None:
                raise HTTPException(
                    status_code=404,
                    detail=f"Control '{key}' not found",
                )
            _require_permission(ctx, ctrl.permission)
            old = app_state.state.get(key, ctrl.default)
            try:
                # Store exactly what was sent, or refuse: never record a
                # substituted default or a clamped value as the caller's change.
                stored = _exact_control_value(ctrl, value)
            except _RejectedControlValue as exc:
                raise HTTPException(
                    status_code=422, detail=f"{exc}. Nothing was changed.",
                ) from None
            pending_updates.append((ctrl, old, stored))

        updated = []
        for ctrl, old, stored in pending_updates:
            app_state.state[ctrl.key] = stored
            app_state.audit.log_control_change(
                ctrl.key,
                old,
                stored,
                role=ctx.role or "api",
                source="api",
                sensitive=ctrl.sensitive,
            )
            updated.append(_control_value(
                app_state, ctrl.key, can_read=has_perm(ctx, "can_view_metrics"),
            ))
        return updated


def _load_api_profile(
    profile_id: str, registry: ControlRegistry, session_state: dict[str, Any],
    *, profile_dir: str, store: BaseProfileStore | None = None, restore: bool = True,
) -> dict[str, Any] | None:
    try:
        data = load_profile_data(profile_id, profile_dir=profile_dir, store=store)
        if data is None:
            return None
        _require_profile_shape(data)
        # Project before restoration: coercing a mapping into a text control
        # would otherwise discard the field names that identify nested secrets.
        safe_data = {**data, "values": _profile_response_values(
            registry, data.get("values"), data.get("control_meta"),
        )}
        if not restore:
            return safe_data
        for ctrl in registry.all():
            value = safe_data["values"].get(ctrl.key, session_state.get(ctrl.key, ctrl.default))
            _require_safe_api_coercion(ctrl, value)
        return _restore_profile_data(safe_data, registry, session_state)
    except _InvalidProfileError:
        raise HTTPException(status_code=422, detail="Stored profile fields are invalid.") from None


class _ReadErrorWatch:
    """Count store read errors recorded during one request.

    File stores record unreadable records in ``read_errors`` and return None,
    which must not be reported as "not found" or overwritten. Compare the
    store's running error total, which keeps counting after the bounded
    ``read_errors`` window is full. Stores without ``read_errors`` keep their
    previous behavior.
    """

    def __init__(self, store: Any) -> None:
        self._store = store
        self._before = self._total()

    def _total(self) -> int | None:
        try:
            return store_read_error_total(self._store)
        except TypeError:  # a custom store whose read_errors has no length
            return None

    def new_errors(self) -> int:
        after = self._total()
        if self._before is None or after is None:
            return 0
        return max(0, after - self._before)


def _unreadable_profile(profile_id: str) -> str:
    # Fixed text: store diagnostics can contain paths and exception details.
    return (
        f"Profile '{profile_id}' exists but could not be read. Nothing was changed; "
        "repair or delete the stored record."
    )


def _api_profile_store(app_state: _AppState) -> BaseProfileStore:
    # One store per request, so a read error recorded by this request is visible.
    if app_state.profile_store is not None:
        return app_state.profile_store
    return FileProfileStore(app_state.profile_dir)


def _register_profile_routes(app: FastAPI, app_state: _AppState, require_api_context: Any) -> None:
    @app.get("/profiles", response_model=list[str])
    async def get_profiles(
        response: Response,
        _: SecurityContext = Depends(require_api_context("can_load_profiles")),
    ):
        store = _api_profile_store(app_state)
        watch = _ReadErrorWatch(store)
        profile_ids = list_profiles(app_state.profile_dir, store=store)
        unreadable = watch.new_errors()
        if unreadable:
            # The listing keeps readable records, as the dashboard does; the
            # header says it is incomplete instead of letting it look empty.
            response.headers["X-Unreadable-Records"] = str(unreadable)
            logger.warning("Profile listing skipped %d unreadable record(s); see read_errors.", unreadable)
        return profile_ids

    @app.get("/profiles/{profile_id}", response_model=ProfileResponse)
    async def get_profile(profile_id: str, ctx: SecurityContext = Depends(require_api_context("can_load_profiles"))):
        _require_permission(ctx, "can_view_metrics")
        store = _api_profile_store(app_state)
        watch = _ReadErrorWatch(store)
        data = _load_api_profile(
            profile_id,
            app_state.registry,
            {},  # read-only: don't mutate app state
            profile_dir=app_state.profile_dir,
            store=store,
            restore=False,
        )
        if data is None:
            if watch.new_errors():
                raise HTTPException(status_code=500, detail=_unreadable_profile(profile_id))
            raise HTTPException(status_code=404, detail=f"Profile '{profile_id}' not found")
        return ProfileResponse(
            profile_id=data.get("profile_id", profile_id),
            saved_at=data.get("saved_at", ""),
            role=data.get("role", ""),
            values=data.get("values", {}),
        )

    @app.post("/profiles", response_model=ProfileResponse)
    async def save_profile_endpoint(
        req: ProfileRequest,
        ctx: SecurityContext = Depends(require_api_context("can_save_profiles")),
    ):
        profile_id = _canonical_api_profile_id(req.profile_id)
        _require_json_depth(req.extra, "extra")
        store = _api_profile_store(app_state)
        watch = _ReadErrorWatch(store)
        existing = load_profile_data(profile_id, profile_dir=app_state.profile_dir, store=store)
        if existing is None and watch.new_errors():
            # An unreadable record is not permission to overwrite it.
            raise HTTPException(
                status_code=409,
                detail=(
                    f"Profile '{profile_id}' exists but could not be read, so it was not "
                    "replaced. Repair or delete the stored record first."
                ),
            )
        save_profile(
            profile_id,
            app_state.registry,
            app_state.state,
            role=req.role,
            extra=req.extra,
            source="api",
            profile_dir=app_state.profile_dir,
            store=store,
        )
        app_state.audit.log_profile_save(profile_id, role=ctx.role or req.role or "api", source="api")
        return ProfileResponse(
            profile_id=profile_id,
            role=req.role,
            values=_live_profile_response_values(app_state, ctx),
        )

    @app.post("/profiles/{profile_id}/activate", response_model=ProfileResponse)
    async def activate_profile(
        profile_id: str,
        ctx: SecurityContext = Depends(require_api_context("can_load_profiles")),
    ):
        staged_state = dict(app_state.state)
        store = _api_profile_store(app_state)
        watch = _ReadErrorWatch(store)
        data = _load_api_profile(
            profile_id,
            app_state.registry,
            staged_state,
            profile_dir=app_state.profile_dir,
            store=store,
        )
        if data is None:
            if watch.new_errors():
                raise HTTPException(status_code=500, detail=_unreadable_profile(profile_id))
            raise HTTPException(status_code=404, detail=f"Profile '{profile_id}' not found")
        profile_values = data.get("values", {})
        for ctrl in app_state.registry.all():
            restored = ctrl.key in profile_values and not ctrl.sensitive
            changed = (
                ctrl.key not in app_state.state
                or staged_state[ctrl.key] != app_state.state[ctrl.key]
            )
            if restored or changed:
                _require_permission(ctx, ctrl.permission)
        app_state.state.update(
            {ctrl.key: staged_state[ctrl.key] for ctrl in app_state.registry.all()}
        )
        app_state.audit.log_profile_load(profile_id, role=ctx.role or "api", source="api")
        return ProfileResponse(
            profile_id=data.get("profile_id", profile_id),
            saved_at=data.get("saved_at", ""),
            role=data.get("role", ""),
            values=_live_profile_response_values(app_state, ctx),
        )

    @app.delete("/profiles/{profile_id}")
    async def delete_profile_endpoint(
        profile_id: str,
        ctx: SecurityContext = Depends(require_api_context("can_save_profiles")),
    ):
        try:
            ok = delete_profile(profile_id, profile_dir=app_state.profile_dir, store=app_state.profile_store)
        except StorePathSecurityError:
            # The store refuses, for example, to delete a file that holds another
            # record's id. Fixed text: its diagnostic names local paths.
            raise HTTPException(
                status_code=409,
                detail=(
                    f"Profile '{profile_id}' was not deleted: its stored file failed a safety check "
                    "(for example, it holds a different record). Nothing was changed; repair the "
                    "stored record."
                ),
            ) from None
        if not ok:
            raise HTTPException(status_code=404, detail=f"Profile '{profile_id}' not found")
        app_state.audit.log("profile_delete", detail=profile_id, role=ctx.role or "api", source="api")
        return {"deleted": profile_id}


def _register_role_routes(app: FastAPI, app_state: _AppState, require_api_context: Any) -> None:
    @app.get("/roles", response_model=list[RoleResponse])
    async def get_roles(_: SecurityContext = Depends(require_api_context("can_view_metrics"))):
        all_roles = dict(BUILTIN_ROLES)
        if app_state.custom_roles:
            all_roles.update(app_state.custom_roles)
        return [
            RoleResponse(name=r.name, description=r.description, perms=r.perms)
            for r in all_roles.values()
        ]


def _register_audit_routes(app: FastAPI, app_state: _AppState, require_api_context: Any) -> None:
    @app.get("/audit")
    async def get_audit(
        n: int = 50,
        _: SecurityContext = Depends(require_api_context("can_view_audit")),
    ):
        return project_audit_events(
            app_state.audit.recent(max(0, min(n, 500))), app_state.registry,
        )


# App factory

def create_app(
    registry: ControlRegistry,
    *,
    audit: AuditLog | None = None,
    custom_roles: dict[str, RoleDef] | None = None,
    profile_dir: str = "profiles",
    profile_store: BaseProfileStore | None = None,
    title: str = "Role-Aware Dashboard Toolkit API",
    version: str = ROLE_AWARE_DASHBOARD_TOOLKIT_VERSION,
    api_role: str | None = None,
    allow_anonymous: bool | None = None,
    anonymous_role: str = _ANONYMOUS_ROLE,
    max_body_bytes: int = _DEFAULT_MAX_BODY_BYTES,
) -> FastAPI:
    """
    Create a FastAPI app exposing Role-Aware Dashboard Toolkit controls, profiles, and roles.

    Example::

        from role_aware_dashboard_toolkit.api import create_app
        from role_aware_dashboard_toolkit import ControlRegistry

        reg = ControlRegistry()
        reg.register("Refresh interval", kind="slider", key="refresh_seconds",
                     default=10, min_value=1, max_value=60, step=1)

        app = create_app(reg)
        # Run: uvicorn myapp:app --port 8000

    Request bodies over ``max_body_bytes`` (1 MiB by default) receive HTTP 413,
    and JSON nested more than 32 levels deep receives HTTP 422.
    """
    _require_fastapi()
    body_limit = _validated_body_limit(max_body_bytes)
    resolved_api_role = str(api_role or os.getenv(_API_ROLE_ENV, _DEFAULT_AUTHENTICATED_ROLE) or _DEFAULT_AUTHENTICATED_ROLE)

    app_state = _AppState(
        registry=registry,
        audit=audit,
        custom_roles=custom_roles,
        profile_dir=profile_dir,
        profile_store=profile_store,
        allow_anonymous=_env_flag(_ALLOW_ANONYMOUS_ENV) if allow_anonymous is None else allow_anonymous,
        anonymous_role=anonymous_role,
        api_role=resolved_api_role,
    )
    _validate_role_config(app_state.anonymous_role, app_state.custom_roles, field_name="anonymous_role")
    _validate_role_config(
        app_state.api_role or _DEFAULT_AUTHENTICATED_ROLE,
        app_state.custom_roles,
        field_name="api_role",
    )

    if not os.getenv(_API_KEY_ENV, "") and not app_state.allow_anonymous:
        # The key is read per request, so this is a warning, not an error: a
        # host may set it after creating the app. Never log the key itself.
        logger.warning(
            "%s is not set and anonymous access is off, so every protected route "
            "returns 401 until it is set in the server's environment. Set it, or "
            "pass allow_anonymous=True for a trusted local demo.",
            _API_KEY_ENV,
        )

    app = FastAPI(title=title, version=version)
    app.add_middleware(_RequestBodyLimit, max_bytes=body_limit)
    app.add_exception_handler(RequestValidationError, _validation_error_response)
    app.add_exception_handler(StarletteHTTPException, _http_error_response)
    require_api_context = _make_require_api_context(app_state)

    _register_health_route(app)
    _register_control_routes(app, app_state, require_api_context)
    _register_profile_routes(app, app_state, require_api_context)
    _register_role_routes(app, app_state, require_api_context)
    _register_audit_routes(app, app_state, require_api_context)

    return app


__all__ = ["FASTAPI_AVAILABLE", "create_app"]
