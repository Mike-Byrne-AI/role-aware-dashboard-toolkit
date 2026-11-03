"""Real SQLite flow CAS, bounded tombstones, fixed horizons and rollback proofs."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path
import sqlite3
import sys
from threading import Barrier, Event, current_thread
from types import SimpleNamespace

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("cryptography")
from fastapi import HTTPException, Response  # noqa: E402
from starlette.requests import Request  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "examples/business_dashboard"))
from business import browser_flow as flow, db, security, session_state  # noqa: E402
from business.security_events import record_event  # noqa: E402

KEY = b"k" * 32
START = 2_000_000_000


def connect(path):
    connection = sqlite3.connect(path, timeout=5)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys=ON")
    return connection


@contextmanager
def transaction(connection):
    connection.execute("BEGIN IMMEDIATE")
    try:
        yield connection
        connection.commit()
    except BaseException:
        connection.rollback()
        raise


@pytest.fixture
def state(tmp_path, monkeypatch):
    clock = {"now": START}
    monkeypatch.setattr(flow, "current_time", lambda: clock["now"])
    path = tmp_path / "flow.sqlite3"
    connection = connect(path)
    connection.executescript(db.SCHEMA)
    with transaction(connection):
        connection.execute("UPDATE authentication_policy SET mode='transition'")
        for user in ("alice", "bob"):
            connection.execute("INSERT INTO users VALUES(?,?,?,?,?,1,?,0)",
                               (user, user, user, "!", "employee", security.principal_for_user(user, KEY)))
            connection.execute("INSERT INTO account_security VALUES(?,'legacy',0,NULL,NULL)", (user,))
        flow.checked_time(connection)
    yield SimpleNamespace(connection=connection, clock=clock, path=path)
    connection.close()


def bootstrap(state, cookie=None, **kwargs):
    with transaction(state.connection) as connection:
        return flow.bootstrap(connection, KEY, cookie, **kwargs)


def login(state, context, user="alice"):
    with transaction(state.connection) as connection:
        proof = flow.validate_context(connection, KEY, context.cookie, context.csrf)
        proof = flow.admit_login(connection, proof, user)
        token, expiry, auth = security.create_session(connection, user, KEY, flow_proof=proof, method="password")
        return token, expiry, auth.session_payload()


def authenticated(state, token):
    with transaction(state.connection) as connection:
        return security.authenticate(connection, token, KEY).session_payload()


def test_first_success_cas_and_next_generation_revoke_delayed_root(state):
    first = bootstrap(state)
    assert first.generation == 0
    assert state.connection.execute("SELECT COUNT(*) FROM browser_login_flows").fetchone()[0] == 0
    old, _, old_payload = login(state, first)
    with pytest.raises(HTTPException) as rejected:
        login(state, first, "bob")
    assert rejected.value.status_code == 409
    second = bootstrap(state, first.cookie)
    assert second.cookie == first.cookie and not second.set_cookie and second.generation == 1
    new, _, payload = login(state, second, "bob")
    assert payload["user"]["id"] == "bob" and payload["session_id"] != old_payload["session_id"]
    assert authenticated(state, new)["csrf"] == payload["csrf"]
    with pytest.raises(HTTPException) as invalid:
        authenticated(state, old)
    assert invalid.value.status_code == 401
    assert tuple(state.connection.execute("SELECT generation,closed FROM browser_login_flows").fetchone()) == (2, 0)
    assert state.connection.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 1


def test_concurrent_first_success_has_one_winner(state):
    context = bootstrap(state)
    barrier = Barrier(2)

    def attempt(user):
        connection = connect(state.path)
        try:
            barrier.wait()
            with transaction(connection):
                proof = flow.validate_context(connection, KEY, context.cookie, context.csrf)
                proof = flow.admit_login(connection, proof, user)
                security.create_session(connection, user, KEY, flow_proof=proof, method="password")
                return "accepted"
        except HTTPException as exc:
            return exc.status_code
        finally:
            connection.close()

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(attempt, ("alice", "bob")))
    assert sorted(outcomes, key=str) == [409, "accepted"]
    assert state.connection.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 1


def test_reauth_rotation_keeps_public_head_then_next_login_replaces_it(state):
    context = bootstrap(state)
    old, expiry, payload = login(state, context)
    with transaction(state.connection) as connection:
        rotated, rotated_expiry, rotated_payload = session_state.rotate_session(
            connection, security.token_hash(old), START, "password", KEY,
        )
    assert rotated_expiry == expiry and rotated_payload["session_id"] == payload["session_id"]
    next_context = bootstrap(state, context.cookie)
    new, _, _ = login(state, next_context, "bob")
    for obsolete in (old, rotated):
        with pytest.raises(HTTPException):
            authenticated(state, obsolete)
    assert authenticated(state, new)["user"]["id"] == "bob"


def test_legacy_live_session_bootstrap_exact_csrf_and_stale_refusal(state):
    token = "s" * 43
    hashed = security.token_hash(token)
    with transaction(state.connection) as connection:
        connection.execute("INSERT INTO sessions VALUES(?,?,?,?,?)", (hashed, "alice", START, START, START + 100))
        session_state.record_verification(connection, hashed, START, "password")
    assert authenticated(state, token)["user"]["id"] == "alice"
    with transaction(state.connection) as connection, pytest.raises(HTTPException):
        flow.require_bound_session(connection, hashed)
    with pytest.raises(HTTPException):
        bootstrap(state, authenticated=True, session_token=token, csrf="wrong")
    context = bootstrap(state, authenticated=True, session_token=token, csrf=security.csrf_for_token(token, KEY))
    assert context.generation == 1
    assert authenticated(state, token)["expires_at"] == START + 100
    winner, _, _ = login(state, context, "bob")
    with pytest.raises(HTTPException):
        bootstrap(state, authenticated=True, session_token=token, csrf=security.csrf_for_token(token, KEY))
    assert authenticated(state, winner)["user"]["id"] == "bob"


def test_live_session_cannot_bootstrap_anonymously_without_ordinary_csrf(state):
    context = bootstrap(state)
    token, _, _ = login(state, context)
    before = tuple(state.connection.execute("SELECT generation,closed FROM browser_login_flows").fetchone())
    for cookie in (None, context.cookie):
        with pytest.raises(HTTPException) as denied:
            bootstrap(state, cookie, session_token=token)
        assert denied.value.status_code == 403
    assert tuple(state.connection.execute("SELECT generation,closed FROM browser_login_flows").fetchone()) == before
    # A stale bearer cannot select its former descendant or prevent an explicit
    # anonymous bootstrap. Full credentials and a new context are still needed.
    anonymous = bootstrap(state, session_token="x" * 43)
    assert anonymous.generation == 0


def test_schema9_fractional_session_times_remain_live_and_never_move_backwards(state):
    token, hashed = "l" * 43, security.token_hash("l" * 43)
    state.clock["now"] = START + 0.75
    with transaction(state.connection) as connection:
        connection.execute("INSERT INTO sessions VALUES(?,?,?,?,?)", (hashed, "alice", START + 0.25, START + 0.5, START + 100.25))
        session_state.record_verification(connection, hashed, START + 0.25, "password")
    payload = authenticated(state, token)
    assert payload["expires_at"] == START + 100.25
    assert state.connection.execute("SELECT last_seen FROM sessions").fetchone()[0] == START + 0.75
    context = bootstrap(state, authenticated=True, session_token=token, csrf=payload["csrf"])
    assert context.flow_expires_at == START + flow.FLOW_SECONDS
    assert authenticated(state, token)["expires_at"] == START + 100
    assert state.connection.execute("SELECT created_at,last_seen FROM sessions").fetchone()[:] == (START + 0.25, START)


@pytest.mark.parametrize("expiry_kind", ["absolute", "idle"])
def test_bound_fractional_legacy_expiry_and_idle_cannot_revive_within_second(state, monkeypatch, expiry_kind):
    token, hashed = "f" * 43, security.token_hash("f" * 43)
    state.clock["now"] = START + 0.75
    absolute = START + (1.5 if expiry_kind == "absolute" else flow.FLOW_SECONDS)
    with transaction(state.connection) as connection:
        connection.execute("INSERT INTO sessions VALUES(?,?,?,?,?)", (hashed, "alice", START + 0.25, START + 0.5, absolute))
        session_state.record_verification(connection, hashed, START + 0.25, "password")
    bootstrap(state, authenticated=True, session_token=token, csrf=security.csrf_for_token(token, KEY))
    database = object.__new__(db.Database)
    database._initialized = True
    monkeypatch.setattr(database, "_connect", lambda **kwargs: connect(state.path))
    monkeypatch.setattr(database, "_require_current_key", lambda connection: None)
    boundary = START + (1 if expiry_kind == "absolute" else security.IDLE_SECONDS)
    state.clock["now"] = boundary + 0.25
    with pytest.raises(HTTPException):
        with database.transaction() as connection:
            security.authenticate(connection, token, KEY)
    assert state.connection.execute("SELECT rejection_time_floor FROM browser_flow_state").fetchone()[0] == boundary
    state.clock["now"] = boundary - 0.25
    with pytest.raises(HTTPException):
        with database.transaction():
            pytest.fail("Fractional rollback reopened expired bound authority")


def test_rolled_back_admission_leaves_stateless_context_reusable(state):
    context = bootstrap(state)
    with pytest.raises(RuntimeError):
        with transaction(state.connection) as connection:
            flow.admit_login(connection, flow.validate_context(connection, KEY, context.cookie, context.csrf), "alice")
            raise RuntimeError("factor failed after admission")
    assert state.connection.execute("SELECT COUNT(*) FROM browser_login_flows").fetchone()[0] == 0
    assert authenticated(state, login(state, context)[0])["user"]["id"] == "alice"


def test_structural_validation_accepts_future_floor_but_runtime_rejects(state):
    with transaction(state.connection) as connection:
        connection.execute("UPDATE browser_flow_state SET rejection_time_floor=?", (START + 50,))
        flow.validate_state(connection)
        assert not flow.clock_valid(connection)
    with pytest.raises(HTTPException):
        bootstrap(state)


@pytest.mark.parametrize("column,value", [("epoch", "not-an-epoch"), ("rejection_time_floor", "invalid"),
                                          ("rejection_time_floor", -1)])
def test_malformed_singleton_refuses_structural_and_runtime_work(state, column, value):
    # Model corrupted stored metadata without pretending SQL CHECK constraints
    # would permit these values during a normal application write.
    state.connection.execute("PRAGMA ignore_check_constraints=ON")
    with transaction(state.connection) as connection:
        connection.execute("DROP TRIGGER browser_flow_floor_monotonic")
        connection.execute(f"UPDATE browser_flow_state SET {column}=?", (value,))
    with pytest.raises(ValueError):
        flow.validate_state(state.connection)
    with pytest.raises(ValueError):
        bootstrap(state)


def test_rebootstrap_twice_from_same_exact_live_session_cancels_first_context(state):
    context = bootstrap(state)
    token, _, payload = login(state, context)
    first = bootstrap(state, authenticated=True, session_token=token, csrf=payload["csrf"])
    second = bootstrap(state, authenticated=True, session_token=token, csrf=payload["csrf"])
    assert first.cookie != second.cookie
    with pytest.raises(HTTPException):
        login(state, first)
    assert login(state, second)[2]["user"]["id"] == "alice"


def test_authenticated_rebootstrap_retires_only_exact_sessions_old_flow(state):
    first, unrelated = bootstrap(state), bootstrap(state)
    token, _, payload = login(state, first)
    other_token, _, _ = login(state, unrelated, "bob")
    replacement = bootstrap(state, unrelated.cookie, authenticated=True, session_token=token, csrf=payload["csrf"])
    assert replacement.cookie not in (first.cookie, unrelated.cookie)
    assert replacement.generation == 1
    assert authenticated(state, other_token)["user"]["id"] == "bob"
    with pytest.raises(HTTPException):
        login(state, first, "alice")
    with transaction(state.connection) as connection:
        assert connection.execute("SELECT COUNT(*) FROM browser_login_flows WHERE closed=1").fetchone()[0] == 1
        flow.validate_state(connection)


@pytest.mark.parametrize("deletion", ["session", "security", "binding", "user_sessions"])
def test_actual_sqlite_cascades_close_flow_and_cancel_pending_context(state, deletion):
    context = bootstrap(state)
    token, _, payload = login(state, context)
    pending = bootstrap(state, context.cookie)
    with transaction(state.connection) as connection:
        statements = {
            "session": ("DELETE FROM sessions WHERE token_hash=?", security.token_hash(token)),
            "security": ("DELETE FROM session_security WHERE public_id=?", payload["session_id"]),
            "binding": ("DELETE FROM session_browser_flow WHERE public_id=?", payload["session_id"]),
            "user_sessions": ("DELETE FROM sessions WHERE user_id=?", "alice"),
        }
        sql, value = statements[deletion]
        connection.execute(sql, (value,))
    assert state.connection.execute("SELECT closed FROM browser_login_flows").fetchone()[0] == 1
    with pytest.raises(HTTPException):
        login(state, pending)
    assert bootstrap(state, context.cookie).cookie != context.cookie


def test_required_event_failure_rolls_back_head_generation_and_caller_mutation(state):
    context = bootstrap(state)
    old, _, _ = login(state, context)
    pending = bootstrap(state, context.cookie)
    with transaction(state.connection) as connection:
        connection.execute("CREATE TRIGGER fail_event BEFORE INSERT ON security_events BEGIN SELECT RAISE(ABORT,'fault'); END")
    with pytest.raises(sqlite3.IntegrityError):
        with transaction(state.connection) as connection:
            proof = flow.admit_login(connection, flow.validate_context(connection, KEY, pending.cookie, pending.csrf), "bob")
            # This caller-owned mutation stands at the factor-consumption seam.
            connection.execute("UPDATE users SET revision=revision+1 WHERE id='bob'")
            security.create_session(connection, "bob", KEY, flow_proof=proof, method="password")
            record_event(connection, "login_succeeded", actor=security.principal_for_user("bob", KEY), method="password")
    assert authenticated(state, old)["user"]["id"] == "alice"
    assert state.connection.execute("SELECT generation FROM browser_login_flows").fetchone()[0] == 1
    assert state.connection.execute("SELECT revision FROM users WHERE id='bob'").fetchone()[0] == 0


def test_session_cap_cannot_close_winning_flow_when_creation_times_tie(state):
    tokens = []
    for _ in range(9):
        context = bootstrap(state)
        tokens.append(login(state, context)[0])
    assert authenticated(state, tokens[-1])["user"]["id"] == "alice"
    assert state.connection.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 8
    assert state.connection.execute("SELECT COUNT(*) FROM browser_login_flows WHERE closed=1").fetchone()[0] == 1
    with transaction(state.connection) as connection:
        flow.validate_state(connection)


def test_user_capacity_counts_unexpired_closed_tombstones_without_evicting_authority(state):
    for _ in range(flow.MAX_USER_FLOWS):
        login(state, bootstrap(state))
    before = list(state.connection.execute("SELECT token_hash FROM sessions ORDER BY token_hash"))
    with pytest.raises(HTTPException):
        login(state, bootstrap(state))
    assert before == list(state.connection.execute("SELECT token_hash FROM sessions ORDER BY token_hash"))
    assert state.connection.execute("SELECT COUNT(*) FROM browser_login_flows").fetchone()[0] == flow.MAX_USER_FLOWS


def test_global_capacity_and_generation_exhaustion_fail_closed(state, monkeypatch):
    monkeypatch.setattr(flow, "MAX_FLOWS", 1)
    context = bootstrap(state)
    old, _, _ = login(state, context)
    with pytest.raises(HTTPException):
        login(state, bootstrap(state), "bob")
    with transaction(state.connection) as connection:
        connection.execute("UPDATE browser_login_flows SET generation=?", (flow.MAX_GENERATION,))
    exhausted = bootstrap(state, context.cookie)
    with pytest.raises(HTTPException):
        login(state, exhausted)
    assert authenticated(state, old)["user"]["id"] == "alice"


@pytest.mark.parametrize("bound", ["MAX_USER_FLOWS", "MAX_FLOWS"])
def test_capacity_reclaims_only_heads_past_fixed_horizon_before_admission(state, monkeypatch, bound):
    monkeypatch.setattr(flow, bound, 1)
    first = bootstrap(state)
    old, _, _ = login(state, first)
    state.clock["now"] = first.flow_expires_at
    # No opportunistic request has physically removed the expired session.
    assert state.connection.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 1
    second = bootstrap(state, first.cookie)
    new, _, _ = login(state, second)
    assert authenticated(state, new)["user"]["id"] == "alice"
    with pytest.raises(HTTPException):
        authenticated(state, old)
    assert state.connection.execute("SELECT COUNT(*) FROM browser_login_flows").fetchone()[0] == 1
    assert state.connection.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 1


def test_fixed_horizon_caps_late_login_and_reauth_without_fractional_overhang(state):
    context = bootstrap(state)
    state.clock["now"] = START + flow.FLOW_SECONDS - 2.2
    late = bootstrap(state, context.cookie)
    token, expiry, _ = login(state, late)
    assert expiry == START + flow.FLOW_SECONDS
    with transaction(state.connection) as connection:
        rotated, rotated_expiry, _ = session_state.rotate_session(connection, security.token_hash(token), state.clock["now"], "password", KEY)
    assert rotated_expiry == expiry
    state.clock["now"] = expiry
    with pytest.raises(HTTPException):
        authenticated(state, rotated)
    fresh = bootstrap(state, context.cookie)
    assert fresh.cookie != context.cookie
    new, _, _ = login(state, fresh, "bob")
    assert authenticated(state, new)["user"]["id"] == "bob"
    with pytest.raises(HTTPException):
        authenticated(state, rotated)


def test_expired_tombstone_purge_and_restart_cannot_reopen_under_clock_rollback(state):
    context = bootstrap(state)
    token, _, _ = login(state, context)
    with transaction(state.connection) as connection:
        connection.execute("DELETE FROM sessions WHERE token_hash=?", (security.token_hash(token),))
    state.clock["now"] = context.flow_expires_at
    with transaction(state.connection) as connection:
        assert flow.purge_expired(connection) == 1
    state.connection.close()
    state.connection = connect(state.path)
    state.clock["now"] = START + 10
    with pytest.raises(HTTPException):
        bootstrap(state, context.cookie)
    assert state.connection.execute("SELECT COUNT(*) FROM browser_login_flows").fetchone()[0] == 0


def test_purge_and_clock_advance_are_atomic_on_transaction_failure(state):
    context = bootstrap(state)
    token, _, _ = login(state, context)
    with transaction(state.connection) as connection:
        connection.execute("DELETE FROM sessions WHERE token_hash=?", (security.token_hash(token),))
    state.clock["now"] = context.flow_expires_at
    with pytest.raises(RuntimeError):
        with transaction(state.connection) as connection:
            flow.purge_expired(connection)
            raise RuntimeError("Injected publication failure")
    assert state.connection.execute("SELECT COUNT(*) FROM browser_login_flows").fetchone()[0] == 1
    assert state.connection.execute("SELECT rejection_time_floor FROM browser_flow_state").fetchone()[0] == START


@pytest.mark.parametrize("clock", [-1, float("inf"), float("nan"), "2000000000", True])
def test_invalid_clock_refuses_without_state_mutation(state, clock):
    with pytest.raises(ValueError):
        bootstrap(state, now=clock)


@pytest.mark.parametrize("mutation", ["DELETE FROM browser_flow_state", "UPDATE browser_flow_state SET rejection_time_floor=2000000001"])
def test_missing_state_or_future_boundary_refuses_bootstrap(state, mutation):
    with transaction(state.connection) as connection:
        connection.execute(mutation)
    with pytest.raises((ValueError, HTTPException)):
        bootstrap(state)


@pytest.mark.parametrize("alter", [lambda value: value + ".x", lambda value: value.replace("v1.", "v2.", 1),
                                  lambda value: value.replace(".2000000000.", ".02000000000.", 1),
                                  lambda value: "é" + value, lambda value: value[:-1] + "="])
def test_malformed_cookie_and_context_are_not_login_authority(state, alter):
    context = bootstrap(state)
    with transaction(state.connection) as connection, pytest.raises(HTTPException):
        flow.validate_context(connection, KEY, alter(context.cookie), context.csrf)
    with transaction(state.connection) as connection, pytest.raises(HTTPException):
        flow.validate_context(connection, KEY, context.cookie, alter(context.csrf))


def test_context_expiry_and_cross_flow_purpose_binding(state):
    first, second = bootstrap(state), bootstrap(state)
    with transaction(state.connection) as connection, pytest.raises(HTTPException):
        flow.validate_context(connection, KEY, first.cookie, second.csrf)
    with transaction(state.connection) as connection:
        proof = flow.validate_context(connection, KEY, first.cookie, first.csrf)
        assert flow.binding_hash(proof) != security.token_hash(first.cookie)
        with pytest.raises(ValueError):
            flow.binding_hash(proof, "register")
    state.clock["now"] += flow.CONTEXT_SECONDS
    with pytest.raises(HTTPException):
        login(state, first)


def test_selected_cookie_is_host_scoped_and_duplicates_rejected(state):
    https = SimpleNamespace(scheme="https")
    http = SimpleNamespace(scheme="http")
    request = Request({"type": "http", "headers": [(b"cookie", b"westbridge_login_flow=wrong")]})
    assert flow.read_cookie(request, https) is None
    assert flow.read_cookie(request, http) == "wrong"
    duplicate = f"{flow.HTTPS_COOKIE_NAME}=a; {flow.HTTPS_COOKIE_NAME}=b".encode()
    with pytest.raises(HTTPException) as denied:
        flow.read_cookie(Request({"type": "http", "headers": [(b"cookie", duplicate)]}), https)
    assert denied.value.status_code == 400
    context = bootstrap(state)
    response = Response()
    flow.set_flow_cookie(response, https, context)
    cookie = response.headers["set-cookie"]
    assert "Secure" in cookie and "HttpOnly" in cookie and "SameSite=strict" in cookie and "Path=/" in cookie
    assert "Domain=" not in cookie and "Max-Age=28800" in cookie


def test_restore_epoch_uses_current_floor_and_closes_all_transient_authority(state):
    context = bootstrap(state)
    login(state, context)
    old_epoch = state.connection.execute("SELECT epoch FROM browser_flow_state").fetchone()[0]
    with transaction(state.connection) as connection:
        assert not flow.reset_after_restore(connection, START + 10)
        flow.validate_state(connection)
    assert state.connection.execute("SELECT epoch FROM browser_flow_state").fetchone()[0] != old_epoch
    assert state.connection.execute("SELECT rejection_time_floor FROM browser_flow_state").fetchone()[0] == START + 10
    assert state.connection.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 0
    with pytest.raises(HTTPException):
        bootstrap(state, context.cookie)
    state.clock["now"] = START + 10
    assert bootstrap(state, context.cookie).cookie != context.cookie


def test_schema9_explicit_migration_preserves_sessions_but_discards_challenges(tmp_path, monkeypatch):
    monkeypatch.setattr(flow, "current_time", lambda: START)
    connection = connect(tmp_path / "legacy.sqlite3")
    try:
        connection.executescript(db.SCHEMA_V9)
        with transaction(connection):
            connection.execute("INSERT INTO users VALUES('u','u','u','!','employee',1,'p',0)")
            connection.execute("INSERT INTO sessions VALUES('s','u',1,1,3000000000)")
            session_state.record_verification(connection, "s", 1, "password")
            connection.execute("INSERT INTO passkey_challenges VALUES('c','login',x'01','b',NULL,NULL,1)")
        with transaction(connection):
            db._require_schema(connection, 9)
            db._apply_browser_flow_migration(connection)
            db._require_schema(connection, 10)
        assert connection.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 1
        assert connection.execute("SELECT COUNT(*) FROM passkey_challenges").fetchone()[0] == 0
        with transaction(connection), pytest.raises(HTTPException):
            flow.require_bound_session(connection, "s")
    finally:
        connection.close()


def test_database_rejection_clock_commit_survives_denied_auth_rollback(state, monkeypatch):
    # Use Database.transaction itself while replacing only custody key checks.
    # Real SQLite commits, expired auth and subsequent rollback remain intact.
    database = object.__new__(db.Database)
    database._initialized = True
    monkeypatch.setattr(database, "_connect", lambda **kwargs: connect(state.path))
    monkeypatch.setattr(database, "_require_current_key", lambda connection: None)
    context = bootstrap(state)
    token, expiry, _ = login(state, context)
    state.clock["now"] = expiry
    with pytest.raises(HTTPException):
        with database.transaction() as connection:
            security.authenticate(connection, token, KEY)
    assert state.connection.execute("SELECT rejection_time_floor FROM browser_flow_state").fetchone()[0] == expiry
    # Leave the expired session physically present, then roll wall time back.
    assert state.connection.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 1
    state.clock["now"] = START + 1
    with pytest.raises(HTTPException):
        with database.transaction():
            pytest.fail("A backward clock entered an authority transaction")


def test_clock_advancing_past_horizon_inside_denied_transaction_cannot_revive(state, monkeypatch):
    context = bootstrap(state)
    horizon = context.flow_expires_at
    state.clock["now"] = horizon - 2
    token, _, _ = login(state, bootstrap(state, context.cookie))
    database = object.__new__(db.Database)
    database._initialized = True
    monkeypatch.setattr(database, "_connect", lambda **kwargs: connect(state.path))
    monkeypatch.setattr(database, "_require_current_key", lambda connection: None)
    observations = iter((horizon - 1, horizon))
    monkeypatch.setattr(flow, "current_time", lambda: next(observations))
    with pytest.raises(HTTPException):
        with database.transaction() as connection:
            security.authenticate(connection, token, KEY)
    assert state.connection.execute("SELECT rejection_time_floor FROM browser_flow_state").fetchone()[0] == horizon
    monkeypatch.setattr(flow, "current_time", lambda: horizon - 1)
    with pytest.raises(HTTPException):
        with database.transaction() as connection:
            security.authenticate(connection, token, KEY)


@pytest.mark.parametrize("fraction", [0, 0.75])
def test_later_freshness_expiry_observation_survives_denied_write(state, monkeypatch, fraction):
    context = bootstrap(state)
    token, _, _ = login(state, context)
    hashed = security.token_hash(token)
    with transaction(state.connection) as connection:
        connection.execute("UPDATE session_security SET verified_at=?", (START + fraction,))
    database = object.__new__(db.Database)
    database._initialized = True
    monkeypatch.setattr(database, "_connect", lambda **kwargs: connect(state.path))
    monkeypatch.setattr(database, "_require_current_key", lambda connection: None)
    boundary = START + session_state.VERIFICATION_SECONDS
    samples = iter((boundary - 1, boundary - 1, boundary - 1, boundary))
    monkeypatch.setattr(flow, "current_time", lambda: next(samples))
    with pytest.raises(HTTPException) as denied:
        with database.transaction() as connection:
            security.authenticate(connection, token, KEY)
            session_state.require_recent(connection, hashed)
    assert denied.value.status_code == 403
    assert state.connection.execute("SELECT rejection_time_floor FROM browser_flow_state").fetchone()[0] == boundary
    monkeypatch.setattr(flow, "current_time", lambda: boundary - 1)
    with pytest.raises(HTTPException):
        with database.transaction() as connection:
            security.authenticate(connection, token, KEY)
            session_state.require_recent(connection, hashed)


def test_clock_error_savepoint_keeps_writer_lock_until_boundary_commit(state, monkeypatch):
    context = bootstrap(state)
    horizon = context.flow_expires_at
    state.clock["now"] = horizon - 2
    token, _, _ = login(state, bootstrap(state, context.cookie))
    database = object.__new__(db.Database)
    database._initialized = True
    monkeypatch.setattr(database, "_connect", lambda **kwargs: connect(state.path))
    monkeypatch.setattr(database, "_require_current_key", lambda connection: None)
    owner_name = current_thread().name
    samples = iter((horizon - 1, horizon))
    monkeypatch.setattr(flow, "current_time", lambda: next(samples) if current_thread().name == owner_name else horizon - 1)
    rolled_back, probed, committed = Event(), Event(), Event()
    preserve = flow.preserve_observed_time

    def inspect_lock(connection, observations):
        rolled_back.set()
        assert probed.wait(5), "Competing writer did not attempt the retained lock"
        preserve(connection, observations)

    monkeypatch.setattr(flow, "preserve_observed_time", inspect_lock)

    def contender():
        assert rolled_back.wait(5)
        connection = connect(state.path)
        try:
            connection.execute("PRAGMA busy_timeout=0")
            with pytest.raises(sqlite3.OperationalError, match="locked"):
                connection.execute("BEGIN IMMEDIATE")
        finally:
            connection.close()
            probed.set()
        assert committed.wait(5)
        with pytest.raises(HTTPException) as denied:
            with database.transaction() as other:
                security.authenticate(other, token, KEY)
        return denied.value.status_code

    with ThreadPoolExecutor(max_workers=1, thread_name_prefix="flow-contender") as executor:
        pending = executor.submit(contender)
        try:
            with pytest.raises(HTTPException):
                with database.transaction() as connection:
                    security.authenticate(connection, token, KEY)
        finally:
            committed.set()
        assert pending.result(timeout=5) == 409
    assert state.connection.execute("SELECT rejection_time_floor FROM browser_flow_state").fetchone()[0] == horizon


def test_savepoint_preserves_only_trusted_clock_not_failed_authority_changes(state, monkeypatch):
    context = bootstrap(state)
    old, _, _ = login(state, context)
    pending = bootstrap(state, context.cookie)
    database = object.__new__(db.Database)
    database._initialized = True
    monkeypatch.setattr(database, "_connect", lambda **kwargs: connect(state.path))
    monkeypatch.setattr(database, "_require_current_key", lambda connection: None)
    state.clock["now"] = START + 10
    with pytest.raises(RuntimeError):
        with database.transaction() as connection:
            proof = flow.admit_login(connection, flow.validate_context(connection, KEY, pending.cookie, pending.csrf), "bob")
            security.create_session(connection, "bob", KEY, flow_proof=proof, method="password")
            connection.execute("UPDATE users SET revision=revision+1 WHERE id='bob'")
            # A caller-written value is not a validated clock observation.
            connection.execute("UPDATE browser_flow_state SET rejection_time_floor=?", (START + 100,))
            raise RuntimeError("Required publication failed")
    assert state.connection.execute("SELECT rejection_time_floor FROM browser_flow_state").fetchone()[0] == START + 10
    assert state.connection.execute("SELECT revision FROM users WHERE id='bob'").fetchone()[0] == 0
    assert state.connection.execute("SELECT generation FROM browser_login_flows").fetchone()[0] == 1
    assert authenticated(state, old)["user"]["id"] == "alice"


def test_clock_observer_is_connection_and_epoch_scoped_and_reset(state):
    other = connect(":memory:")
    other.executescript(db.SCHEMA)
    try:
        with transaction(state.connection) as connection:
            with flow.observe_clock(connection) as observations:
                flow.checked_time(connection)
                with transaction(other):
                    flow.checked_time(other, START + 100)
                assert set(observations.values()) == {START}
                old_epoch = connection.execute("SELECT epoch FROM browser_flow_state").fetchone()[0]
                connection.execute("SAVEPOINT reset_attempt")
                flow.reset_after_restore(connection, START + 100, now=START + 100)
                flow.checked_time(connection, START + 100)
                connection.execute("ROLLBACK TO SAVEPOINT reset_attempt")
                flow.preserve_observed_time(connection, observations)
                connection.execute("RELEASE SAVEPOINT reset_attempt")
                assert connection.execute("SELECT epoch FROM browser_flow_state").fetchone()[0] == old_epoch
                assert connection.execute("SELECT rejection_time_floor FROM browser_flow_state").fetchone()[0] == START
            assert flow._CLOCK_OBSERVER.get() is None
    finally:
        other.close()


def test_storage_auto_abort_supersedes_denial_without_publishing_authority(state, monkeypatch):
    context = bootstrap(state)
    horizon = context.flow_expires_at
    state.clock["now"] = horizon - 2
    token, _, _ = login(state, bootstrap(state, context.cookie))
    with transaction(state.connection) as connection:
        connection.execute(
            f"CREATE TRIGGER abort_clock BEFORE UPDATE OF rejection_time_floor ON browser_flow_state "
            f"WHEN NEW.rejection_time_floor={horizon} BEGIN SELECT RAISE(ROLLBACK,'clock storage fault'); END"
        )
    database = object.__new__(db.Database)
    database._initialized = True
    monkeypatch.setattr(database, "_connect", lambda **kwargs: connect(state.path))
    monkeypatch.setattr(database, "_require_current_key", lambda connection: None)
    samples = iter((horizon - 1, horizon))
    monkeypatch.setattr(flow, "current_time", lambda: next(samples))
    # RAISE(ROLLBACK) really aborts SQLite's entire outer transaction. The
    # missing savepoint is a storage error, not a claimed handled auth denial.
    with pytest.raises(sqlite3.Error, match="savepoint"):
        with database.transaction() as connection:
            connection.execute("UPDATE users SET revision=revision+1 WHERE id='alice'")
            security.authenticate(connection, token, KEY)
    assert state.connection.execute("SELECT revision FROM users WHERE id='alice'").fetchone()[0] == 0
    assert state.connection.execute("SELECT rejection_time_floor FROM browser_flow_state").fetchone()[0] == horizon - 2
    assert flow._CLOCK_OBSERVER.get() is None


@pytest.mark.parametrize("operation", ["expiry_denial", "new_authority"])
def test_commit_failure_supersedes_denial_or_success_and_rolls_back_mutations(state, monkeypatch, operation):
    context = bootstrap(state)
    old, _, _ = login(state, context)
    pending = bootstrap(state, context.cookie)

    class FailedCommit(sqlite3.Connection):
        def commit(self):
            raise sqlite3.OperationalError("Injected clock/authority commit failure")

    def broken_connection(**kwargs):
        connection = sqlite3.connect(state.path, factory=FailedCommit)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        return connection

    database = object.__new__(db.Database)
    database._initialized = True
    monkeypatch.setattr(database, "_connect", broken_connection)
    monkeypatch.setattr(database, "_require_current_key", lambda connection: None)
    state.clock["now"] = context.flow_expires_at if operation == "expiry_denial" else START + 1
    published = False
    with pytest.raises(sqlite3.OperationalError, match="commit failure"):
        with database.transaction() as connection:
            if operation == "expiry_denial":
                security.authenticate(connection, old, KEY)
            else:
                proof = flow.admit_login(connection, flow.validate_context(connection, KEY, pending.cookie, pending.csrf), "bob")
                security.create_session(connection, "bob", KEY, flow_proof=proof, method="password")
                record_event(connection, "login_succeeded", actor=security.principal_for_user("bob", KEY), method="password")
        published = True
    assert not published
    assert state.connection.execute("SELECT generation FROM browser_login_flows").fetchone()[0] == 1
    assert state.connection.execute("SELECT user_id FROM sessions").fetchone()[0] == "alice"
    assert state.connection.execute("SELECT COUNT(*) FROM security_events").fetchone()[0] == 0
    assert state.connection.execute("SELECT rejection_time_floor FROM browser_flow_state").fetchone()[0] == START
    assert flow._CLOCK_OBSERVER.get() is None
