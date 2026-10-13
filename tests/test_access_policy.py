"""Authorization checks exercise stale callers and separate durable-store users."""

from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
import time
import traceback
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from dataclasses import FrozenInstanceError
from threading import Barrier

import pytest

from role_aware_dashboard_toolkit.access import (
    AccessDenied,
    AccessPolicy,
    AccessStoreError,
    FreezeConflict,
    FreezeState,
    Identity,
    InMemoryAccessStore,
    SQLiteAccessStore,
    principal_id,
)
from role_aware_dashboard_toolkit.security import RoleDef


KEY = b"synthetic-test-only-not-a-secret!" * 2
SUBJECT = "synthetic-private-provider-subject"
ISSUER = "https://synthetic.identity.invalid"
PID = "1" * 64
OTHER_PID = "2" * 64
FREEZE_ADMIN = {
    "Admin": RoleDef("Admin", {"can_manage_freeze": True, "can_edit_controls": True})
}


@pytest.fixture(params=["memory", "sqlite"])
def store(request, tmp_path):
    if request.param == "memory":
        return InMemoryAccessStore()
    return SQLiteAccessStore.create(tmp_path / "access.sqlite3")


@pytest.fixture
def identity():
    return Identity(ISSUER, SUBJECT, time.time() + 3600)


def policy_for(identity, store, roles=("Admin",)):
    policy = AccessPolicy(lambda: identity, store, KEY)
    pid = policy.identify()
    store.replace_grants(pid, roles)
    return policy, pid


def test_store_defaults_frozen_and_never_bootstraps_first_user(store, identity):
    assert store.read_freeze() == FreezeState(True, 0)
    policy = AccessPolicy(lambda: identity, store, KEY)
    pid = policy.identify()
    assert store.read_grants(pid) == ()
    with pytest.raises(AccessDenied, match="^Access denied[.]$"):
        policy.assigned_roles(pid)
    assert not policy.authorize(pid, "Admin", "can_edit_controls")


def test_server_assignments_limit_role_selection_and_revoke_immediately(store, identity):
    policy, pid = policy_for(identity, store, ("Viewer", "Operator"))
    assert policy.assigned_roles(pid) == ("Viewer", "Operator")
    assert policy.authorize(pid, "Viewer", "can_view_metrics")
    assert policy.authorize(pid, "Operator", "can_manage_runs")
    assert not policy.authorize(pid, "Viewer", "can_edit_controls")
    assert not policy.authorize(pid, "Admin", "can_edit_controls")
    store.replace_grants(pid, ("Viewer",))
    assert not policy.authorize(pid, "Operator", "can_manage_runs")
    store.replace_grants(pid, ())
    assert not policy.authorize(pid, "Viewer", "can_view_metrics")


def test_write_requires_unfrozen_server_state(store, identity):
    policy, pid = policy_for(identity, store)
    assert policy.authorize(pid, "Admin", "can_edit_controls")
    assert not policy.authorize(pid, "Admin", "can_edit_controls", write=True)
    updated = policy.change_freeze(pid, "Admin", False, 0, FREEZE_ADMIN)
    assert updated == FreezeState(False, 1, pid)
    assert policy.authorize(pid, "Admin", "can_edit_controls", write=True)
    policy.change_freeze(pid, "Admin", True, 1, FREEZE_ADMIN)
    assert not policy.authorize(pid, "Admin", "can_edit_controls", write=True)


@pytest.mark.parametrize("revision", [-1, True, "0", None, 0.0])
def test_malformed_custom_store_freeze_revision_denies_all_authorization(identity, revision, monkeypatch):
    store = InMemoryAccessStore()
    policy, pid = policy_for(identity, store)
    monkeypatch.setattr(store, "read_freeze", lambda: FreezeState(False, revision))
    assert not policy.authorize(pid, "Admin", "can_view_metrics")
    assert not policy.authorize(pid, "Admin", "can_edit_controls", write=True)
    with pytest.raises(AccessDenied):
        policy.change_freeze(pid, "Admin", False, 0)


def test_viewer_cannot_unfreeze_or_forge_admin(store, identity):
    policy, pid = policy_for(identity, store, ("Viewer",))
    for role in ("Viewer", "Admin"):
        with pytest.raises(AccessDenied):
            policy.change_freeze(pid, role, False, 0, FREEZE_ADMIN)
    assert store.read_freeze() == FreezeState(True, 0)


def test_stale_freeze_revision_cannot_override_another_session(store):
    assert store.compare_and_set_freeze(False, 0, PID) == FreezeState(False, 1, PID)
    with pytest.raises(FreezeConflict):
        store.compare_and_set_freeze(True, 0, OTHER_PID)
    assert store.read_freeze() == FreezeState(False, 1, PID)


def test_identity_switch_invalidates_old_context_even_for_same_role(store, identity):
    current = [identity]
    policy = AccessPolicy(lambda: current[0], store, KEY)
    old_pid = policy.identify()
    store.replace_grants(old_pid, ("Admin",))
    assert policy.authorize(old_pid, "Admin", "can_view_metrics")
    current[0] = Identity(ISSUER, "a-second-account", time.time() + 3600)
    store.replace_grants(policy.identify(), ("Admin",))
    assert not policy.authorize(old_pid, "Admin", "can_view_metrics")
    with pytest.raises(AccessDenied):
        policy.assigned_roles(old_pid)


def test_identity_expiry_invalidates_previously_authorized_context(store, monkeypatch):
    monkeypatch.setattr("role_aware_dashboard_toolkit.access.time.time", lambda: 1000)
    policy, pid = policy_for(Identity(ISSUER, SUBJECT, 1010), store)
    assert policy.authorize(pid, "Admin", "can_view_metrics")
    monkeypatch.setattr("role_aware_dashboard_toolkit.access.time.time", lambda: 1010)
    assert not policy.authorize(pid, "Admin", "can_view_metrics")
    with pytest.raises(AccessDenied):
        policy.identify()


@pytest.mark.parametrize("returned", [None, {}, "Admin", True])
def test_unverified_resolver_outputs_fail_closed(returned, store):
    policy = AccessPolicy(lambda: returned, store, KEY)
    with pytest.raises(AccessDenied):
        policy.identify()
    assert not policy.authorize(PID, "Admin", "can_view_metrics")


def test_resolver_exception_does_not_disclose_claims_or_secrets(store):
    def failing_resolver():
        raise RuntimeError(SUBJECT + KEY.decode())

    policy = AccessPolicy(failing_resolver, store, KEY)
    with pytest.raises(AccessDenied) as error:
        policy.identify()
    rendered = "".join(traceback.format_exception(error.value))
    assert SUBJECT not in rendered
    assert KEY.decode() not in rendered
    assert not policy.authorize(PID, "Admin", "can_view_metrics")


@pytest.mark.parametrize(
    "issuer,subject,expires",
    [
        ("", SUBJECT, 1000),
        (ISSUER, "", 1000),
        (None, SUBJECT, 1000),
        (ISSUER, 42, 1000),
        (ISSUER, "newline\nsubject", 1000),
        (ISSUER, SUBJECT, True),
        (ISSUER, SUBJECT, "1000"),
        (ISSUER, SUBJECT, float("nan")),
        (ISSUER, SUBJECT, float("inf")),
        (ISSUER, SUBJECT, 10 ** 1000),
        (ISSUER, SUBJECT, -1),
    ],
)
def test_malformed_identity_is_rejected_without_echo(issuer, subject, expires):
    with pytest.raises(AccessDenied, match="^Access denied[.]$"):
        Identity(issuer, subject, expires)


@pytest.mark.parametrize("key", [b"", b"x" * 31, "x" * 64, None])
def test_weak_or_wrong_type_identity_key_is_rejected(key, identity, store):
    with pytest.raises(ValueError, match="Identity key must contain at least 32 bytes"):
        AccessPolicy(lambda: identity, store, key)


def test_identity_is_immutable_and_repr_omits_raw_fields(identity, store):
    policy = AccessPolicy(lambda: identity, store, KEY)
    with pytest.raises(FrozenInstanceError):
        identity.subject = "changed"
    assert repr(identity) == "Identity()"
    assert repr(policy) == "AccessPolicy()"


def test_principal_hash_is_stable_unambiguous_keyed_and_issuer_scoped(identity):
    first = principal_id(identity, KEY)
    assert len(first) == 64
    assert first == principal_id(Identity(ISSUER, SUBJECT, 5000), KEY)
    assert first != principal_id(identity, b"another-synthetic-key" * 4)
    assert first != principal_id(Identity("https://other.invalid", SUBJECT, 5000), KEY)
    assert principal_id(Identity("ab", "c", 5000), KEY) != principal_id(
        Identity("a", "bc", 5000), KEY
    )


def test_secret_rotation_does_not_reuse_old_assignments(identity, store):
    policy_for(identity, store)
    rotated = AccessPolicy(lambda: identity, store, b"rotated-test-key" * 4)
    with pytest.raises(AccessDenied):
        rotated.assigned_roles(rotated.identify())


@pytest.mark.parametrize("roles", [("Unknown",), ("Admin", "Admin"), "Admin", [123]])
def test_invalid_grants_preserve_previous_assignment(store, roles):
    store.replace_grants(PID, ("Viewer",))
    with pytest.raises(AccessStoreError):
        store.replace_grants(PID, roles)
    assert store.read_grants(PID) == ("Viewer",)


@pytest.mark.parametrize("bad_pid", [SUBJECT, "A" * 64, "f" * 63, None, "' OR 1=1 --"])
def test_store_rejects_nonopaque_principal_identifiers(store, bad_pid):
    with pytest.raises(AccessStoreError, match="^Access storage is unavailable or invalid[.]$"):
        store.replace_grants(bad_pid, ("Admin",))


def test_custom_role_must_be_allowed_by_store_and_defined_by_host(identity):
    store = InMemoryAccessStore(allowed_roles=("Researcher",))
    policy, pid = policy_for(identity, store, ("Researcher",))
    assert not policy.authorize(pid, "Researcher", "can_view_metrics")
    custom = {"Researcher": RoleDef("Researcher", {"can_view_metrics": True})}
    assert policy.authorize(pid, "Researcher", "can_view_metrics", custom)
    custom["Researcher"].perms["can_view_metrics"] = "true"
    assert not policy.authorize(pid, "Researcher", "can_view_metrics", custom)


@pytest.mark.parametrize("frozen,revision", [("false", 0), (False, True), (False, -1)])
def test_invalid_freeze_inputs_do_not_mutate_state(store, frozen, revision):
    with pytest.raises(AccessStoreError):
        store.compare_and_set_freeze(frozen, revision, PID)
    assert store.read_freeze() == FreezeState(True, 0)


def test_separate_sqlite_instances_share_grants_freeze_and_revocation(tmp_path, identity):
    path = tmp_path / "access.sqlite3"
    first = SQLiteAccessStore.create(path)
    second = SQLiteAccessStore(path)
    policy, pid = policy_for(identity, first)
    assert second.read_grants(pid) == ("Admin",)
    second.compare_and_set_freeze(False, 0, PID)
    assert policy.authorize(pid, "Admin", "can_edit_controls", write=True)
    second.replace_grants(pid, ("Viewer",))
    assert not policy.authorize(pid, "Admin", "can_edit_controls", write=True)
    second.compare_and_set_freeze(True, 1, PID)
    assert first.read_freeze() == FreezeState(True, 2, PID)


def test_competing_sqlite_sessions_allow_exactly_one_freeze_update(tmp_path):
    path = tmp_path / "access.sqlite3"
    first = SQLiteAccessStore.create(path)
    second = SQLiteAccessStore(path)
    barrier = Barrier(2)

    def compete(store, desired):
        barrier.wait(timeout=5)
        try:
            return store.compare_and_set_freeze(desired, 0, PID)
        except FreezeConflict:
            return "conflict"

    with ThreadPoolExecutor(max_workers=2) as pool:
        calls = [pool.submit(compete, first, False), pool.submit(compete, second, True)]
        results = [call.result(timeout=10) for call in calls]
    assert results.count("conflict") == 1
    assert first.read_freeze().revision == 1


def test_separate_process_sees_and_updates_same_freeze(tmp_path):
    path = tmp_path / "access.sqlite3"
    store = SQLiteAccessStore.create(path)
    code = (
        "import sys; from role_aware_dashboard_toolkit.access import SQLiteAccessStore; "
        "store = SQLiteAccessStore(sys.argv[1]); "
        "store.compare_and_set_freeze(False, 0, '1' * 64)"
    )
    process = subprocess.run(
        [sys.executable, "-c", code, str(path)], capture_output=True, text=True, timeout=20
    )
    assert process.returncode == 0, process.stderr
    assert store.read_freeze() == FreezeState(False, 1, PID)


@pytest.mark.parametrize("contents", [None, b"", b"not a sqlite database"])
def test_opening_missing_or_invalid_database_never_creates_or_repairs(tmp_path, contents):
    path = tmp_path / "missing.sqlite3"
    if contents is not None:
        path.write_bytes(contents)
    with pytest.raises(AccessStoreError):
        SQLiteAccessStore(path)
    assert path.exists() is (contents is not None)
    if contents is not None:
        assert path.read_bytes() == contents


def test_explicit_creation_refuses_existing_database_and_preserves_policy(tmp_path):
    path = tmp_path / "access.sqlite3"
    store = SQLiteAccessStore.create(path)
    store.replace_grants(PID, ("Viewer",))
    store.compare_and_set_freeze(False, 0, PID)
    with pytest.raises(AccessStoreError):
        SQLiteAccessStore.create(path)
    assert store.read_grants(PID) == ("Viewer",)
    assert store.read_freeze() == FreezeState(False, 1, PID)


@pytest.mark.parametrize(
    "corrupt_sql",
    [
        "PRAGMA user_version = 2",
        "DELETE FROM freeze_state",
        "CREATE TABLE unexpected (extra TEXT)",
        "CREATE TABLE sqlitexunexpected (extra TEXT)",
        "UPDATE freeze_state SET changed_by = 'raw-user-data'",
        "CREATE TRIGGER unexpected AFTER INSERT ON grants BEGIN DELETE FROM grants; END",
    ],
)
def test_schema_and_freeze_corruption_fail_closed_on_already_open_store(
    tmp_path, identity, corrupt_sql
):
    path = tmp_path / "access.sqlite3"
    store = SQLiteAccessStore.create(path)
    policy, pid = policy_for(identity, store)
    with closing(sqlite3.connect(path)) as connection, connection:
        connection.execute(corrupt_sql)
    assert not policy.authorize(pid, "Admin", "can_view_metrics")
    with pytest.raises(AccessStoreError):
        store.read_freeze()


def test_database_disappearance_denies_old_policy_and_does_not_recreate(tmp_path, identity):
    path = tmp_path / "access.sqlite3"
    store = SQLiteAccessStore.create(path)
    policy, pid = policy_for(identity, store)
    path.unlink()
    assert not policy.authorize(pid, "Admin", "can_view_metrics")
    assert not path.exists()


def test_corrupt_role_rows_do_not_authorize(tmp_path, identity):
    path = tmp_path / "access.sqlite3"
    store = SQLiteAccessStore.create(path)
    policy, pid = policy_for(identity, store)
    with closing(sqlite3.connect(path)) as connection, connection:
        connection.execute("UPDATE grants SET position = 42")
    assert not policy.authorize(pid, "Admin", "can_view_metrics")


def test_persisted_database_excludes_raw_identity_and_hmac_key(tmp_path, identity):
    path = tmp_path / "access.sqlite3"
    store = SQLiteAccessStore.create(path)
    policy, pid = policy_for(identity, store)
    policy.change_freeze(pid, "Admin", False, 0, FREEZE_ADMIN)
    for file in tmp_path.iterdir():
        data = file.read_bytes()
        assert SUBJECT.encode() not in data
        assert ISSUER.encode() not in data
        assert KEY not in data
    with closing(sqlite3.connect(path)) as connection, connection:
        assert connection.execute("SELECT principal_id, role FROM grants").fetchall() == [
            (pid, "Admin")
        ]
    if os.name == "posix":
        assert path.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize(
    "allowed", [(), ("Unauthenticated",), ("unauthenticated",), ("Admin", "Admin"),
                ("A" * 65,), (" Role",), ("Role ",), tuple(f"Role{i}" for i in range(65))]
)
def test_invalid_allowlist_is_rejected_before_store_creation(tmp_path, allowed):
    with pytest.raises(AccessStoreError):
        InMemoryAccessStore(allowed_roles=allowed)
    path = tmp_path / "access.sqlite3"
    with pytest.raises(AccessStoreError):
        SQLiteAccessStore.create(path, allowed_roles=allowed)
    assert not path.exists()


def test_allowlist_and_grants_iterables_are_bounded(store):
    def never_ending():
        while True:
            yield "Admin"

    with pytest.raises(AccessStoreError):
        InMemoryAccessStore(allowed_roles=never_ending())
    with pytest.raises(AccessStoreError):
        store.replace_grants(PID, never_ending())


def test_custom_store_cannot_authorize_reserved_denial_role(identity):
    class BadStore:
        def read_grants(self, principal_id):
            return ("Unauthenticated",)

        def read_freeze(self):
            return FreezeState(False, 0)

    policy = AccessPolicy(lambda: identity, BadStore(), KEY)
    custom = {"Unauthenticated": RoleDef("Unauthenticated", {"can_view_metrics": True})}
    assert not policy.authorize(
        policy.identify(), "Unauthenticated", "can_view_metrics", custom
    )


def _report_owner(monkeypatch, path, uid):
    """Make os.stat and os.lstat report ``path`` as owned by ``uid``."""
    import stat as stat_module

    target = os.fspath(path)
    real_stat, real_lstat = os.stat, os.lstat

    def owned(real):
        def wrapper(candidate, *args, **kwargs):
            info = real(candidate, *args, **kwargs)
            if isinstance(candidate, (str, os.PathLike)) and os.fspath(candidate) == target:
                values = list(info)
                values[stat_module.ST_UID] = uid
                return os.stat_result(values)
            return info
        return wrapper

    monkeypatch.setattr(os, "stat", owned(real_stat))
    monkeypatch.setattr(os, "lstat", owned(real_lstat))


@pytest.mark.skipif(os.name != "posix", reason="POSIX ownership contract")
@pytest.mark.parametrize("owner", ["other", "root", "caller"])
def test_sqlite_store_refuses_a_database_owned_by_another_account(tmp_path, monkeypatch, owner):
    # Another account that can write the directory could replace the database
    # with its own 0600 file; the store reopens it by path on every call.
    path = tmp_path / "access.sqlite3"
    store = SQLiteAccessStore.create(path)
    store.replace_grants(PID, ("Viewer",))
    uid = {"other": os.geteuid() + 1, "root": 0, "caller": os.geteuid()}[owner]
    _report_owner(monkeypatch, path.absolute(), uid)
    if owner == "other":
        with pytest.raises(AccessStoreError):
            store.read_grants(PID)
        with pytest.raises(AccessStoreError):
            SQLiteAccessStore(path)
    else:
        assert store.read_grants(PID) == ("Viewer",)


@pytest.mark.skipif(sys.platform != "darwin", reason="macOS ACLs are read through ctypes")
def test_an_unusable_acl_library_fails_closed_as_a_store_error(tmp_path, monkeypatch):
    import role_aware_dashboard_toolkit.access_store as access_store

    store = SQLiteAccessStore.create(tmp_path / "access.sqlite3")

    def missing_library():
        raise ImportError("ctypes is unavailable")

    monkeypatch.setattr(access_store, "_darwin_acl_library", missing_library)
    with pytest.raises(AccessStoreError):
        store.read_freeze()
