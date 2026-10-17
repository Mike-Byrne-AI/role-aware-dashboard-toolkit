"""Host integration behavior with synthetic identities and real in-memory effects."""

from copy import deepcopy
import os
from pathlib import Path
import subprocess
import sys
import time
from types import SimpleNamespace

import pytest

from examples.host_integration import service as example
from role_aware_dashboard_toolkit.access import AccessDenied, Identity
from role_aware_dashboard_toolkit.access_store import AccessStoreError, FreezeConflict


@pytest.fixture
def host():
    service = example.HostNotes(identity_key=b"synthetic-example-test-key-only!!")
    identities = {
        name: Identity("synthetic-host-test", name, time.time() + 600)
        for name in ("manager", "writer-a", "writer-b", "reader", "unassigned")
    }
    for name, role in (("manager", "Manager"), ("writer-a", "Writer"),
                       ("writer-b", "Writer"), ("reader", "Reader")):
        service.provision(identities[name], (role,))
    current = [identities["writer-a"]]
    session = service.open_session(lambda: current[0])
    manager = service.open_session(lambda: identities["manager"])
    state = service.freeze_state(manager, "Manager")
    service.change_freeze(manager, "Manager", False, state.revision)
    return SimpleNamespace(
        service=service, identities=identities, current=current, session=session, manager=manager,
    )


def test_actual_write_and_reads_are_scoped_to_current_actor(host):
    ticket = host.service.stage_note(host.session, "Writer", "Account A's synthetic note")
    host.service.commit_note(host.session, "Writer", ticket)
    assert host.service.read_notes(host.session, "Writer") == ("Account A's synthetic note",)
    host.current[0] = host.identities["writer-b"]
    assert host.service.read_notes(host.session, "Writer") == ()
    ticket = host.service.stage_note(host.session, "Writer", "Account B's note")
    host.service.commit_note(host.session, "Writer", ticket)
    assert host.service.read_notes(host.session, "Writer") == ("Account B's note",)
    host.current[0] = host.identities["writer-a"]
    assert host.service.read_notes(host.session, "Writer") == ("Account A's synthetic note",)


@pytest.mark.parametrize("account,role", (("reader", "Manager"), ("reader", "Writer"),
                                         ("unassigned", "Manager"), ("writer-a", "Manager")))
def test_role_input_cannot_grant_permissions_or_create_pending_work(host, account, role):
    session = host.service.open_session(lambda: host.identities[account])
    with pytest.raises(AccessDenied):
        host.service.read_notes(session, role)
    with pytest.raises(AccessDenied):
        host.service.stage_note(session, role, "Denied note")
    assert not session._pending
    assert not host.service._notes


def test_reader_can_read_but_cannot_stage_or_commit(host):
    session = host.service.open_session(lambda: host.identities["reader"])
    assert host.service.read_notes(session, "Reader") == ()
    with pytest.raises(AccessDenied):
        host.service.stage_note(session, "Reader", "Denied note")
    with pytest.raises(AccessDenied):
        host.service.commit_note(session, "Reader", "browser-manufactured-ticket")
    assert not host.service._notes


def test_ticket_is_server_owned_session_bound_and_single_use(host):
    ticket = host.service.stage_note(host.session, "Writer", "Saved once")
    other_session = host.service.open_session(lambda: host.identities["writer-a"])
    with pytest.raises(AccessDenied):
        host.service.commit_note(other_session, "Writer", ticket)
    with pytest.raises(AccessDenied):
        host.service.commit_note(host.session, "Writer", {"actor": "manager", "text": "forged"})
    host.service.commit_note(host.session, "Writer", ticket)
    with pytest.raises(AccessDenied):
        host.service.commit_note(host.session, "Writer", ticket)
    assert host.service.read_notes(host.session, "Writer") == ("Saved once",)


def test_same_role_account_switch_discards_cache_and_deferred_action(host):
    saved = host.service.stage_note(host.session, "Writer", "Prior account note")
    host.service.commit_note(host.session, "Writer", saved)
    assert host.service.read_notes(host.session, "Writer")
    ticket = host.service.stage_note(host.session, "Writer", "Old account's pending result")
    host.current[0] = host.identities["writer-b"]
    with pytest.raises(AccessDenied):
        host.service.commit_note(host.session, "Writer", ticket)
    assert host.session._last_read == ()
    assert host.session._pending == {}
    assert host.service.read_notes(host.session, "Writer") == ()
    host.current[0] = host.identities["writer-a"]
    with pytest.raises(AccessDenied):
        host.service.commit_note(host.session, "Writer", ticket)
    assert host.service.read_notes(host.session, "Writer") == ("Prior account note",)


@pytest.mark.parametrize("change", ("revoke", "freeze", "expire", "logout", "store_failure"))
def test_deferred_completion_rechecks_live_authority_before_effect(host, monkeypatch, change):
    first = host.service.stage_note(host.session, "Writer", "Existing note")
    host.service.commit_note(host.session, "Writer", first)
    host.service.read_notes(host.session, "Writer")
    ticket = host.service.stage_note(host.session, "Writer", "Must not be appended")
    before = deepcopy(host.service._notes)
    if change == "revoke":
        host.service.provision(host.identities["writer-a"], ())
    elif change == "freeze":
        state = host.service.freeze_state(host.manager, "Manager")
        host.service.change_freeze(host.manager, "Manager", True, state.revision)
    elif change == "expire":
        host.current[0] = Identity("synthetic-host-test", "writer-a", time.time() - 1)
    elif change == "logout":
        host.current[0] = None
    else:
        def failed_grants(_principal):
            raise AccessStoreError()
        monkeypatch.setattr(host.service._store, "read_grants", failed_grants)
    with pytest.raises(AccessDenied, match="^Access denied.$"):
        host.service.commit_note(host.session, "Writer", ticket)
    assert host.service._notes == before
    assert host.session._pending == {}
    assert host.session._last_read == ()
    if change == "freeze":
        assert host.service.read_notes(host.session, "Writer") == ("Existing note",)


def test_host_close_denies_old_session_even_after_same_account_signs_in_again(host):
    ticket = host.service.stage_note(host.session, "Writer", "Old session note")
    host.session.close()
    with pytest.raises(AccessDenied):
        host.service.commit_note(host.session, "Writer", ticket)
    fresh = host.service.open_session(lambda: host.identities["writer-a"])
    with pytest.raises(AccessDenied):
        host.service.commit_note(fresh, "Writer", ticket)
    assert host.service.read_notes(fresh, "Writer") == ()


def test_role_change_and_ticket_timeout_require_a_new_intent(host, monkeypatch):
    host.service.provision(host.identities["writer-a"], ("Writer", "Manager"))
    ticket = host.service.stage_note(host.session, "Writer", "Role-bound note")
    with pytest.raises(AccessDenied):
        host.service.commit_note(host.session, "Manager", ticket)
    with monkeypatch.context() as patch:
        patch.setattr(example.time, "monotonic", lambda: 100)
        ticket = host.service.stage_note(host.session, "Writer", "Expired intent")
        patch.setattr(example.time, "monotonic", lambda: 100 + example.PENDING_SECONDS)
        with pytest.raises(AccessDenied):
            host.service.commit_note(host.session, "Writer", ticket)
    assert host.service.read_notes(host.session, "Writer") == ()


def test_only_manager_can_change_freeze_and_stale_revision_is_rejected(host):
    state = host.service.freeze_state(host.session, "Writer")
    with pytest.raises(AccessDenied):
        host.service.change_freeze(host.session, "Writer", True, state.revision)
    changed = host.service.change_freeze(host.manager, "Manager", True, state.revision)
    with pytest.raises(FreezeConflict):
        host.service.change_freeze(host.manager, "Manager", False, state.revision)
    assert host.service.freeze_state(host.manager, "Manager") == changed


def test_example_runs_without_importing_optional_hosts():
    script = """
import sys
from examples.host_integration.demo import main
main()
assert not {'streamlit', 'fastapi', 'pandas'}.intersection(sys.modules)
"""
    result = subprocess.run(
        [sys.executable, "-c", script], cwd=Path(__file__).resolve().parents[1],
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        text=True, capture_output=True, check=True,
    )
    assert "LOCAL SIMULATION" in result.stdout
    assert "Live revocation: deferred save denied" in result.stdout
    assert "Shared freeze: deferred save denied" in result.stdout
