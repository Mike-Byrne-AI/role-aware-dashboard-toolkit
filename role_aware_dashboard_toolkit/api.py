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
from .controls import ControlDef, ControlRegistry, _looks_like_hex_color
from .profile_store import BaseProfileStore
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
    from fastapi import FastAPI, HTTPException, Depends, Header
    from pydantic import BaseModel, Field
    FASTAPI_AVAILABLE = True
except ImportError as exc:
    _FASTAPI_IMPORT_ERROR = exc
    FastAPI = None  # type: ignore
    Depends = None  # type: ignore
    Header = None  # type: ignore

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
    values: dict[str, Any] = Field(
        default_factory=dict,
        description="Map of control key -> new value",
    )


class ProfileRequest(BaseModel):
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
        def dependency(x_api_key: str = Header(default="", alias="X-API-Key")) -> SecurityContext:
            ctx = _resolve_api_context(app_state, x_api_key)
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
            ctrl = app_state.registry.get(key)
            if ctrl is None:
                raise HTTPException(
                    status_code=404,
                    detail=f"Control '{key}' not found",
                )
            _require_permission(ctx, ctrl.permission)
            old = app_state.state.get(key, ctrl.default)
            _require_safe_api_coercion(ctrl, value)
            stored = app_state.registry.sanitize_value(key, value)
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


def _register_profile_routes(app: FastAPI, app_state: _AppState, require_api_context: Any) -> None:
    @app.get("/profiles", response_model=list[str])
    async def get_profiles(_: SecurityContext = Depends(require_api_context("can_load_profiles"))):
        return list_profiles(app_state.profile_dir, store=app_state.profile_store)

    @app.get("/profiles/{profile_id}", response_model=ProfileResponse)
    async def get_profile(profile_id: str, ctx: SecurityContext = Depends(require_api_context("can_load_profiles"))):
        _require_permission(ctx, "can_view_metrics")
        data = _load_api_profile(
            profile_id,
            app_state.registry,
            {},  # read-only: don't mutate app state
            profile_dir=app_state.profile_dir,
            store=app_state.profile_store,
            restore=False,
        )
        if data is None:
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
        save_profile(
            profile_id,
            app_state.registry,
            app_state.state,
            role=req.role,
            extra=req.extra,
            source="api",
            profile_dir=app_state.profile_dir,
            store=app_state.profile_store,
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
        data = _load_api_profile(
            profile_id,
            app_state.registry,
            staged_state,
            profile_dir=app_state.profile_dir,
            store=app_state.profile_store,
        )
        if data is None:
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
        ok = delete_profile(profile_id, profile_dir=app_state.profile_dir, store=app_state.profile_store)
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
    """
    _require_fastapi()
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

    app = FastAPI(title=title, version=version)
    require_api_context = _make_require_api_context(app_state)

    _register_health_route(app)
    _register_control_routes(app, app_state, require_api_context)
    _register_profile_routes(app, app_state, require_api_context)
    _register_role_routes(app, app_state, require_api_context)
    _register_audit_routes(app, app_state, require_api_context)

    return app


__all__ = ["FASTAPI_AVAILABLE", "create_app"]
