"""Trusted identity and live server-side authorization, independent of UI.

The host must verify identities before returning them. This module neither
accepts passwords nor verifies tokens: constructing Identity is not proof of
authentication. Resolver, role definitions, stores, and the HMAC secret are
trusted server configuration, never session/profile or request input.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from .access_store import (  # noqa: F401 -- public module-level store API
    AccessStore,
    AccessStoreError,
    FreezeConflict,
    FreezeState,
    InMemoryAccessStore,
    SQLiteAccessStore,
)

if TYPE_CHECKING:
    from .security import RoleDef


class AccessDenied(RuntimeError):
    """A safe failure message with no identity, claims, or callback details."""

    def __init__(self) -> None:
        super().__init__("Access denied.")


@dataclass(frozen=True)
class Identity:
    """Minimal verified host identity; expiry is UTC Unix seconds.

    Raw identity stays in memory only and is excluded from repr. The host
    should use the provider's stable subject, never an email/display name.
    """

    issuer: str = field(repr=False)
    subject: str = field(repr=False)
    expires_at: float = field(repr=False)

    def __post_init__(self) -> None:
        if (
            not isinstance(self.issuer, str)
            or not 1 <= len(self.issuer) <= 2048
            or not isinstance(self.subject, str)
            or not 1 <= len(self.subject) <= 1024
            or type(self.expires_at) not in (int, float)
            or not 0 < self.expires_at < 253402300800
            or any(ord(char) < 32 for char in self.issuer + self.subject)
        ):
            raise AccessDenied()


def _validate_key(identity_key: bytes) -> None:
    if not isinstance(identity_key, bytes) or len(identity_key) < 32:
        raise ValueError("Identity key must contain at least 32 bytes.")


def principal_id(identity: Identity, identity_key: bytes) -> str:
    """Derive the opaque ID used by trusted grant provisioning.

    IDs are stable for a key plus issuer/subject, independent of expiry. Keep
    a cryptographically random application-specific key outside the store,
    repository, logs, and user sessions. Key rotation requires reprovisioning
    grants. Opaque IDs remain linkable pseudonymous data, not anonymization.
    """
    _validate_key(identity_key)
    if not isinstance(identity, Identity):
        raise AccessDenied()
    canonical = json.dumps(
        [identity.issuer, identity.subject], ensure_ascii=True, separators=(",", ":")
    ).encode("utf-8")
    return hmac.new(identity_key, canonical, hashlib.sha256).hexdigest()


@dataclass(frozen=True)
class AccessPolicy:
    """Resolve identity and fresh grants for every authorization decision.

    Revocation applies to the next check, including checks made from an old
    context. This is not cancellation of in-flight host work or an atomic
    transaction with external effects; hosts must enforce checks at their
    actual mutation boundary and design their own transaction semantics.
    """

    identity_resolver: Callable[[], Identity | None] = field(repr=False)
    store: AccessStore = field(repr=False)
    identity_key: bytes = field(repr=False)

    def __post_init__(self) -> None:
        _validate_key(self.identity_key)
        if not callable(self.identity_resolver):
            raise ValueError("Identity resolver must be callable.")

    def identify(self) -> str:
        """Return an opaque principal for a currently valid verified identity."""
        try:
            identity = self.identity_resolver()
            if not isinstance(identity, Identity) or identity.expires_at <= time.time():
                raise AccessDenied()
            return principal_id(identity, self.identity_key)
        except Exception:
            # Resolver failures can contain raw provider claims or secrets.
            raise AccessDenied() from None

    def assigned_roles(self, principal_id: str) -> tuple[str, ...]:
        """Read live assignments for this session's current identity only."""
        try:
            if not isinstance(principal_id, str) or not hmac.compare_digest(
                self.identify(), principal_id
            ):
                raise AccessDenied()
            roles = self.store.read_grants(principal_id)
            if (
                not isinstance(roles, tuple)
                or not 1 <= len(roles) <= 64
                or any(
                    not isinstance(role, str)
                    or not 1 <= len(role) <= 64
                    or role.casefold() == "unauthenticated"
                    for role in roles
                )
                or len(set(roles)) != len(roles)
            ):
                raise AccessDenied()
            return roles
        except Exception:
            raise AccessDenied() from None

    def authorize(
        self,
        principal_id: str,
        role: str,
        permission: str,
        custom_roles: dict[str, RoleDef] | None = None,
        *,
        write: bool = False,
    ) -> bool:
        """Check assigned role and host role definition; writes also check freeze."""
        from .security import get_role

        try:
            if role not in self.assigned_roles(principal_id):
                return False
            role_definition = get_role(role, custom_roles)
            if role_definition is None or role_definition.perms.get(permission) is not True:
                return False
            freeze = self.store.read_freeze()
            if not isinstance(freeze, FreezeState) or type(freeze.frozen) is not bool:
                return False
            return not write or not freeze.frozen
        except Exception:
            # Missing storage/authentication is a denied operation, not a
            # fallback to the mutable UI permission snapshot.
            return False

    def change_freeze(
        self,
        principal_id: str,
        role: str,
        frozen: bool,
        expected_revision: int,
        custom_roles: dict[str, RoleDef] | None = None,
    ) -> FreezeState:
        """Change the shared switch with fresh permission and stale-tab protection."""
        if not self.authorize(
            principal_id, role, "can_manage_freeze", custom_roles, write=False
        ):
            raise AccessDenied()
        try:
            return self.store.compare_and_set_freeze(frozen, expected_revision, principal_id)
        except FreezeConflict:
            raise
        except Exception:
            raise AccessDenied() from None
