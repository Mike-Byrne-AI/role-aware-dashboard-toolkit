"""Exercise durable changes using synthetic identities and a temporary database."""

from pathlib import Path
import secrets
from tempfile import TemporaryDirectory
import time

from role_aware_dashboard_toolkit.access import Identity

from .service import WorkItems


def main() -> None:
    # This is fixture data, never an authentication implementation.
    manager = Identity("synthetic-example", "manager", time.time() + 600)
    key = secrets.token_bytes(32)
    with TemporaryDirectory(prefix="record-workflows-") as directory:
        path = Path(directory) / "synthetic.sqlite3"
        service = WorkItems(path, identity_key=key)
        service.provision(manager, ["Manager"])
        session = service.open_session(lambda: manager)
        service.change_freeze(session, "Manager", False, 0)
        item = service.create_item(label="Example inspection", starts_at="2030-05-01T09:00:00+00:00")
        moved = service.reschedule(
            session, "Manager", item["id"], expected_revision=0,
            starts_at="2030-05-02T10:00:00+00:00", reason="Site available the next day",
        )
        service.change_status(
            session, "Manager", item["id"], expected_revision=moved.after["revision"],
            status="completed",
        )
        other = service.create_item(label="Example follow-up", starts_at="2030-05-03T09:00:00+00:00")
        service.change_status(
            session, "Manager", other["id"], expected_revision=0,
            status="cancelled", reason="No follow-up needed",
        )
        session.close()
        # A new service/connection reads the same committed records and history.
        reopened = WorkItems(path, identity_key=key)
        fresh = reopened.open_session(lambda: manager)
        saved = reopened.read(fresh, "Manager", item["id"])
        events = reopened.audit_events(fresh, "Manager")
        assert saved["status"] == "completed" and saved["revision"] == 2
        assert len(events) == 3
        print("Reschedule, completion and cancellation persisted with 3 audit records.")
        print("Synthetic temporary database removed when this example exits.")
        fresh.close()


if __name__ == "__main__":
    main()
