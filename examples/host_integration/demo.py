"""Run synthetic identities through a host service; this is not authentication."""

from __future__ import annotations

import secrets
import time

from role_aware_dashboard_toolkit.access import AccessDenied, Identity

from .service import HostNotes


def main() -> None:
    print("LOCAL SIMULATION: synthetic identities, in-memory data, no login or network.")
    service = HostNotes(identity_key=secrets.token_bytes(32))
    # ONLY this demonstration manufactures identities. A real host must obtain
    # them from its verified authentication adapter on every resolution.
    identities = {
        name: Identity("synthetic-host-integration", name, time.time() + 600)
        for name in ("manager", "writer-a", "writer-b", "reader")
    }
    for name, role in (("manager", "Manager"), ("writer-a", "Writer"),
                       ("writer-b", "Writer"), ("reader", "Reader")):
        service.provision(identities[name], (role,))
    manager = service.open_session(lambda: identities["manager"])
    current_account = [identities["writer-a"]]
    writer = service.open_session(lambda: current_account[0])
    reader = service.open_session(lambda: identities["reader"])

    freeze = service.freeze_state(manager, "Manager")
    service.change_freeze(manager, "Manager", False, freeze.revision)
    ticket = service.stage_note(writer, "Writer", "Synthetic note for writer A.")
    service.commit_note(writer, "Writer", ticket)
    print(f"Writer A saved {len(service.read_notes(writer, 'Writer'))} note.")
    print(f"Reader sees {len(service.read_notes(reader, 'Reader'))} own notes.")

    ticket = service.stage_note(writer, "Writer", "Deferred note that must not cross accounts.")
    current_account[0] = identities["writer-b"]  # Same role, different account.
    try:
        service.commit_note(writer, "Writer", ticket)
    except AccessDenied:
        print("Account switch: deferred save denied; writer B has no inherited notes.")
    assert service.read_notes(writer, "Writer") == ()

    ticket = service.stage_note(writer, "Writer", "Deferred note after revoked access.")
    service.provision(identities["writer-b"], ())
    try:
        service.commit_note(writer, "Writer", ticket)
    except AccessDenied:
        print("Live revocation: deferred save denied before the side effect.")

    current_account[0] = identities["writer-a"]
    ticket = service.stage_note(writer, "Writer", "Deferred note while frozen.")
    freeze = service.freeze_state(manager, "Manager")
    service.change_freeze(manager, "Manager", True, freeze.revision)
    try:
        service.commit_note(writer, "Writer", ticket)
    except AccessDenied:
        print("Shared freeze: deferred save denied; authorized reads still work.")
    assert len(service.read_notes(writer, "Writer")) == 1
    writer.close()
    print("Host sign-out: session closed and pending state discarded.")


if __name__ == "__main__":
    main()
