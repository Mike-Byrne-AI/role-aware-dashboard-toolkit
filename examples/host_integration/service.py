"""Small host-owned service using the dependency-free access policy.

Identity resolvers and provisioning calls are trusted host code, not request
fields. This example deliberately supplies no login, HTTP server or persistence.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
import secrets
from threading import RLock
import time

from role_aware_dashboard_toolkit.access import AccessDenied, AccessPolicy, Identity, principal_id
from role_aware_dashboard_toolkit.access_store import FreezeState, InMemoryAccessStore
from role_aware_dashboard_toolkit.security import RoleDef


ROLES = {
    "Reader": RoleDef("Reader", {"can_read_notes": True}),
    "Writer": RoleDef("Writer", {"can_read_notes": True, "can_write_notes": True}),
    "Manager": RoleDef("Manager", {
        "can_read_notes": True, "can_write_notes": True, "can_manage_freeze": True,
    }),
}
PENDING_SECONDS = 300
MAX_PENDING = 8


@dataclass(frozen=True)
class _PendingNote:
    actor: str = field(repr=False)
    role: str
    text: str = field(repr=False)
    expires_at: float


class HostSession:
    """Server-owned session state; never reconstruct this object from a request.

    The host calls close before sign-out and discards the object. A new verified
    login gets a new HostSession, even when it belongs to the same account.
    """

    def __init__(self, owner: HostNotes, resolver: Callable[[], Identity | None]):
        self._owner = owner
        self._policy = AccessPolicy(resolver, owner._store, owner._identity_key)
        self._actor: str | None = None
        self._pending: dict[str, _PendingNote] = {}
        self._last_read: tuple[str, ...] = ()
        self._closed = False

    def _clear(self) -> None:
        self._actor = None
        self._pending.clear()
        self._last_read = ()

    def close(self) -> None:
        """Discard pending work before host logout; this session cannot reopen."""
        with self._owner._lock:
            self._clear()
            self._closed = True


class HostNotes:
    """Actor-scoped notes and deferred saves in one process.

    Every operation, grant update and freeze update in this service uses the
    same lock. This serializes this example's in-memory checks and effects; it
    is not a database transaction or an external-service cancellation mechanism.
    Keep the store private and do not bypass these methods in the host.
    """

    def __init__(self, *, identity_key: bytes):
        # AccessPolicy validates the key without resolving an identity.
        self._identity_key = identity_key
        self._store = InMemoryAccessStore(allowed_roles=ROLES)
        AccessPolicy(lambda: None, self._store, identity_key)
        self._lock = RLock()
        self._notes: dict[str, list[str]] = {}

    def provision(self, identity: Identity, roles: Iterable[str]) -> None:
        """Trusted operator boundary: replace grants for a verified account.

        Do not expose this method as a visitor-controlled endpoint. An empty
        role list revokes grants. Provisioning does not sign anyone in.
        """
        with self._lock:
            self._store.replace_grants(principal_id(identity, self._identity_key), roles)

    def open_session(self, resolver: Callable[[], Identity | None]) -> HostSession:
        """Use a resolver backed by the host's current verified authentication.

        Constructing Identity from browser claims does not verify those claims.
        The callback must return None after expiry, logout or failed verification.
        """
        return HostSession(self, resolver)

    def _identify(self, session: HostSession) -> str:
        if not isinstance(session, HostSession) or session._owner is not self:
            raise AccessDenied()
        if session._closed:
            session._clear()
            raise AccessDenied()
        try:
            actor = session._policy.identify()
        except AccessDenied:
            session._clear()
            raise
        if actor != session._actor:
            # A role name can stay unchanged when the underlying account changes.
            session._clear()
            session._actor = actor
        return actor

    def _authorize(
        self, session: HostSession, role: str, permission: str, *, write: bool = False,
    ) -> str:
        actor = self._identify(session)
        if not session._policy.authorize(actor, role, permission, ROLES, write=write):
            session._clear()
            raise AccessDenied()
        return actor

    def read_notes(self, session: HostSession, role: str) -> tuple[str, ...]:
        """Authorize before the actual read; a role selection supplies no grant."""
        with self._lock:
            actor = self._authorize(session, role, "can_read_notes")
            session._last_read = tuple(self._notes.get(actor, ()))
            return session._last_read

    def stage_note(self, session: HostSession, role: str, text: str) -> str:
        """Keep an actor-bound intent on the server; return only its opaque ID."""
        with self._lock:
            actor = self._authorize(session, role, "can_write_notes", write=True)
            if not isinstance(text, str) or not text.strip() or len(text) > 500:
                raise ValueError("A note must contain 1 to 500 characters.")
            now = time.monotonic()
            session._pending = {
                key: value for key, value in session._pending.items() if value.expires_at > now
            }
            if len(session._pending) >= MAX_PENDING:
                raise ValueError("Finish or discard pending notes before staging another.")
            ticket = secrets.token_urlsafe(32)
            session._pending[ticket] = _PendingNote(actor, role, text, now + PENDING_SECONDS)
            return ticket

    def commit_note(self, session: HostSession, role: str, ticket: str) -> None:
        """Reauthorize at completion; neither the ticket nor old UI state grants access."""
        with self._lock:
            actor = self._authorize(session, role, "can_write_notes", write=True)
            if not isinstance(ticket, str):
                raise AccessDenied()
            pending = session._pending.pop(ticket, None)
            if (
                pending is None or pending.actor != actor or pending.role != role
                or pending.expires_at <= time.monotonic()
            ):
                raise AccessDenied()
            # The side effect uses the checked actor and server-owned text, never
            # an actor/owner field from the browser or the deferred result.
            self._notes.setdefault(actor, []).append(pending.text)

    def freeze_state(self, session: HostSession, role: str) -> FreezeState:
        with self._lock:
            self._authorize(session, role, "can_read_notes")
            return self._store.read_freeze()

    def change_freeze(
        self, session: HostSession, role: str, frozen: bool, expected_revision: int,
    ) -> FreezeState:
        with self._lock:
            actor = self._authorize(session, role, "can_manage_freeze")
            return session._policy.change_freeze(actor, role, frozen, expected_revision, ROLES)
