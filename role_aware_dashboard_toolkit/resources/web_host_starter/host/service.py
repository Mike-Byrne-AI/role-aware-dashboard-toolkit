"""Editable record rules; current authority, records and history commit together."""
from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import uuid

from .actions import ActionValidation, execute_change, normalize_reason
from .auth import RequestActor, ROLES, grant, issue_token, revoke, subject_name
from .storage import data_path, read_key, transaction


def schedule(value: str) -> str:
    if not isinstance(value, str) or len(value) > 64:
        raise ActionValidation("Supply an ISO date and time with its UTC offset.")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError
        return parsed.astimezone(timezone.utc).isoformat(timespec="seconds")
    except (ValueError, OverflowError):
        raise ActionValidation("Supply an ISO date and time with its UTC offset.") from None


class WorkItems:
    def __init__(self, directory: str | Path):
        self.directory = data_path(directory)
        self.key = read_key(self.directory)
        with self.transaction():
            pass  # Validate schema/key at startup; never create or migrate.

    def transaction(self):
        return transaction(self.directory, self.key)

    def issue_token(self, subject: str, role: str, *, lifetime: int = 3600) -> str:
        with self.transaction() as connection:
            return issue_token(connection, self.key, subject, role, lifetime=lifetime)

    def grant(self, subject: str, role: str | None) -> None:
        with self.transaction() as connection:
            grant(connection, self.key, subject, role)

    def revoke(self, subject: str) -> None:
        with self.transaction() as connection:
            revoke(connection, self.key, subject)

    def session(self, token: str) -> dict:
        with self.transaction() as connection:
            actor = RequestActor(connection, self.key, token)
            actor.require("can_read_items")
            freeze = actor.store.read_freeze()
            return {"subject": actor.subject, "role": actor.role,
                    "can_edit": ROLES[actor.role].perms.get("can_edit_items") is True,
                    "can_manage": actor.role == "Manager",
                    "freeze": {"frozen": freeze.frozen, "revision": freeze.revision}}

    def items(self, token: str) -> list[dict]:
        with self.transaction() as connection:
            actor = RequestActor(connection, self.key, token)
            actor.require("can_read_items")
            query = "SELECT * FROM items"
            args = ()
            if actor.role == "Operator":
                query += " WHERE owner = ?"
                args = (actor.subject,)
            return [dict(row) for row in connection.execute(query + " ORDER BY starts_at, id", args)]

    @staticmethod
    def _history(connection, *, item_id, action, actor, reason, before, after):
        connection.execute(
            "INSERT INTO history (item_id, action, actor, reason, before_json, after_json) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (item_id, action, actor, reason, json.dumps(before, sort_keys=True),
             json.dumps(after, sort_keys=True)),
        )

    def create(self, token: str, *, label: str, starts_at: str, owner: str) -> dict:
        with self.transaction() as connection:
            actor = RequestActor(connection, self.key, token)
            actor.require("can_create_items", write=True)
            checked_label = normalize_reason(label, required=True, max_length=120)
            try:
                checked_owner = subject_name(owner)
            except ValueError:
                raise ActionValidation("Choose a valid account ID for the owner.") from None
            item = {"id": uuid.uuid4().hex, "label": checked_label, "starts_at": schedule(starts_at),
                    "status": "scheduled", "revision": 0, "owner": checked_owner}
            actor.require("can_create_items", write=True)
            connection.execute("INSERT INTO items VALUES (?, ?, ?, ?, ?, ?)", tuple(item.values()))
            self._history(connection, item_id=item["id"], action="created", actor=actor.principal,
                          reason="", before={}, after=item)
            return {"item": item, "changed": True}

    def change(self, token: str, item_id: str, *, expected_revision: int,
               action: str, value: str, reason: str = "") -> dict:
        with self.transaction() as connection:
            actor = RequestActor(connection, self.key, token)
            actor.require("can_edit_items", write=True)

            def load():
                row = connection.execute("SELECT * FROM items WHERE id = ?", (item_id,)).fetchone()
                if row is None:
                    raise ActionValidation("The requested item does not exist.")
                actor.require("can_edit_items", write=True, owner=row["owner"])
                return dict(row)

            def propose(record):
                if action == "rescheduled":
                    if record["status"] != "scheduled":
                        raise ActionValidation("Reopen this item before rescheduling it.")
                    return {"starts_at": schedule(value)}
                if action != "status_changed" or value not in {"scheduled", "completed", "cancelled"}:
                    raise ActionValidation("Choose a supported status.")
                if record["status"] != value and (record["status"], value) not in {
                    ("scheduled", "completed"), ("scheduled", "cancelled"),
                    ("completed", "scheduled"), ("cancelled", "scheduled"),
                }:
                    raise ActionValidation("Reopen this item before changing its status.")
                return {"status": value}

            def save(record, revision):
                return connection.execute(
                    "UPDATE items SET starts_at = ?, status = ?, revision = ? "
                    "WHERE id = ? AND revision = ?",
                    (record["starts_at"], record["status"], record["revision"], item_id, revision),
                ).rowcount == 1

            def audit(result):
                self._history(connection, item_id=item_id, action=action, actor=result.actor,
                              reason=result.reason, before=result.before, after=result.after)

            result = execute_change(
                connection=connection, expected_revision=expected_revision,
                authorize=lambda: actor.require("can_edit_items", write=True),
                load=load, propose=propose, save=save, audit=audit, reason=reason,
                require_reason=action == "status_changed" and value == "cancelled",
            )
            return {"item": result.after, "changed": result.changed}

    def freeze(self, token: str, *, frozen: bool, expected_revision: int) -> dict:
        with self.transaction() as connection:
            actor = RequestActor(connection, self.key, token)
            actor.require("can_manage_freeze")
            state = actor.policy.change_freeze(actor.principal, actor.role, frozen, expected_revision, ROLES)
            return {"freeze": {"frozen": state.frozen, "revision": state.revision}}

    def history(self, token: str) -> list[dict]:
        with self.transaction() as connection:
            actor = RequestActor(connection, self.key, token)
            actor.require("can_read_history")
            return [{"id": row["id"], "item_id": row["item_id"], "action": row["action"],
                     "actor": row["actor"], "reason": row["reason"],
                     "before": json.loads(row["before_json"]), "after": json.loads(row["after_json"])}
                    for row in connection.execute("SELECT * FROM history ORDER BY id")]
