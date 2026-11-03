"""Host-verified, per-request identity for one isolated API application."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from uuid import uuid4

from .access import AccessDenied, AccessPolicy, Identity
from .access_store import AccessStore
from .security import RoleDef, SecurityContext, get_role


@dataclass(frozen=True)
class APIAuthentication:
    """Bind a host credential verifier to this organization's access store.

    The resolver must verify credentials and return a current Identity, or None.
    It is called again at authorization boundaries; never trust request claims
    without verification. Give each organization a separate store and identity
    key, and mount a separately configured app. This is not a token verifier.
    """

    identity_resolver: Callable[[Any], Identity | None]
    store: AccessStore
    identity_key: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if not callable(self.identity_resolver):
            raise TypeError("identity_resolver must be callable")
        # Reuse the core key contract without resolving a request at startup.
        AccessPolicy(lambda: None, self.store, self.identity_key)

    def resolve(self, request: Any, custom_roles: dict[str, RoleDef] | None = None) -> SecurityContext:
        """Resolve a fresh principal and a selection among its current grants."""
        policy = AccessPolicy(lambda: self.identity_resolver(request), self.store, self.identity_key)
        principal = policy.identify()
        roles = policy.assigned_roles(principal)
        selected = request.headers.get("x-dashboard-role") or roles[0]
        if selected not in roles:
            raise AccessDenied()
        definition = get_role(selected, custom_roles)
        if definition is None:
            raise AccessDenied()
        return SecurityContext(
            role=selected, perms=dict(definition.perms), authenticated=True,
            user_id=principal, session_id=uuid4().hex,
            # The live policy checks freeze on writes. A frozen initial
            # snapshot must not prevent a later freshly authorized unfreeze.
            controls_writable=True,
            _authorize=lambda permission, write: policy.authorize(
                principal, selected, permission, custom_roles, write=write,
            ),
        )


__all__ = ["APIAuthentication"]
