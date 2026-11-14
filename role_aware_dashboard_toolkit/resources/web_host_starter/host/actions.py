"""Copy-and-adapt SQLite action recipe; this is not an installed toolkit API.

The host owns the surrounding BEGIN IMMEDIATE transaction, live authorization,
record repository and audit sink. Callbacks are trusted host code. They must use
this connection, must not commit, and must not perform external side effects.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from copy import deepcopy
from dataclasses import dataclass
import sqlite3
import uuid


class ActionDenied(RuntimeError):
    """The current actor no longer matches the actor who began the operation."""


class ActionConflict(ValueError):
    """The displayed revision no longer matches the current record."""


class ActionValidation(ValueError):
    """An action input or proposed change is invalid."""


@dataclass(frozen=True)
class ChangeResult:
    actor: str
    before: dict
    after: dict
    reason: str
    changed: bool


def normalize_reason(
    value: str | None, *, required: bool = False, max_length: int = 500,
) -> str:
    """Validate bounded human text without interpreting it as markup."""
    if value is None:
        value = ""
    if not isinstance(value, str) or len(value) > max_length:
        raise ActionValidation(f"A reason must contain at most {max_length} characters.")
    if any(ord(char) < 32 and char not in "\n\t" for char in value):
        raise ActionValidation("A reason contains unsupported control characters.")
    value = value.strip()
    if required and not value:
        raise ActionValidation("A reason is required.")
    return value


def execute_change(
    *,
    connection: sqlite3.Connection,
    expected_revision: int,
    authorize: Callable[[], str],
    load: Callable[[], Mapping],
    propose: Callable[[Mapping], Mapping],
    save: Callable[[Mapping, int], bool],
    audit: Callable[[ChangeResult], None],
    reason: str | None = None,
    require_reason: bool = False,
) -> ChangeResult:
    """Validate, reauthorize and save one revisioned record with its audit entry.

    ``authorize`` must resolve the current verified actor and check live grants
    and freeze every time; it returns the actor ID or raises. ``load`` returns
    an audit-safe record including an integer ``revision``. ``propose`` returns
    updates to existing fields, never ``revision``. ``save`` performs a compare
    and set and returns exactly True only when one record was written. ``audit``
    persists the result on the same connection. Load/propose must not write.

    A no-op checks current authority but does not save, increment or audit. An
    old revision conflicts even if its requested values now match. A savepoint
    rolls back the record and audit on any failure; the outer host transaction
    decides when to commit. This does not coordinate other connections, an
    external provider, emails or jobs. It cannot police trusted callback code.
    """
    if not connection.in_transaction:
        raise RuntimeError("The host must start a shared write transaction.")
    marker = "action_" + uuid.uuid4().hex
    connection.execute(f"SAVEPOINT {marker}")
    try:
        actor = authorize()
        if not isinstance(actor, str) or not actor:
            raise ActionDenied("Current authorization is required.")
        if type(expected_revision) is not int or not 0 <= expected_revision < 9223372036854775807:
            raise ActionValidation("A valid record revision is required.")
        checked_reason = normalize_reason(reason, required=require_reason)
        before = deepcopy(dict(load()))
        revision = before.get("revision")
        if type(revision) is not int or not 0 <= revision < 9223372036854775807:
            raise ActionValidation("The stored record revision is invalid.")
        if revision != expected_revision:
            raise ActionConflict("This record changed. Refresh before trying again.")
        changes = deepcopy(dict(propose(deepcopy(before))))
        if "revision" in changes or any(key not in before for key in changes):
            raise ActionValidation("The action proposed an unsupported field.")
        after = {**before, **changes}
        changed = after != before
        if changed:
            after["revision"] = revision + 1
        result = ChangeResult(actor, deepcopy(before), deepcopy(after), checked_reason, changed)
        # No callback that can load or validate business state sits between this
        # current-authority check and the actual write.
        if authorize() != actor:
            raise ActionDenied("The signed-in account changed. Refresh before trying again.")
        if changed:
            if save(deepcopy(after), revision) is not True:
                raise ActionConflict("This record changed. Refresh before trying again.")
            audit(result)
        connection.execute(f"RELEASE SAVEPOINT {marker}")
        return result
    except BaseException:
        connection.execute(f"ROLLBACK TO SAVEPOINT {marker}")
        connection.execute(f"RELEASE SAVEPOINT {marker}")
        raise
