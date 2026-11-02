"""Execute three bounded security demonstrations using disposable local data.

No existing data or remote target is accepted. The host scenarios exercise real
in-process HTTP authorization and backup reconciliation. The separate toolkit
scenario exercises local SQLite concurrency with a synthetic identity adapter;
it is not identity-provider, multi-host or hosted acceptance.
"""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
import hashlib
import json
from pathlib import Path
import secrets
import sys
import tempfile
from threading import Barrier
import time

if not __debug__:
    raise SystemExit("This evidence runner requires assertions. Rerun without -O, -OO or PYTHONOPTIMIZE.")

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples" / "business_dashboard"
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(EXAMPLE))

from business.evidence import CHECKS, finish_receipt, new_receipt, write_receipt  # noqa: E402

ORIGIN = "http://127.0.0.1:8091"


class Checks:
    def __init__(self, receipt):
        self.rows = {row["id"]: row for row in receipt["checks"]}

    def require(self, key, condition):
        self.rows[key]["status"] = "passed" if condition else "failed"
        if not condition:
            raise AssertionError("Security demonstration invariant failed.")


def _fixture(directory):
    from business.app import create_app
    from business.secret_store import create_key_file, default_key_path
    from business.seed import provision

    key = default_key_path(directory)
    create_key_file(directory, key)
    credentials = provision(directory, mfa_key_file=key)
    return create_app(directory, public_origin=ORIGIN, mfa_key_file=key), credentials, key


def _login(client, credentials, username="alex"):
    response = client.post("/api/login", json={"username": username, "password": credentials[username]},
                           headers={"Origin": ORIGIN})
    if response.status_code != 200:
        raise AssertionError("Disposable login failed.")
    return {"Origin": ORIGIN, "X-CSRF-Token": response.json()["csrf"]}


def _business_fingerprint(database):
    with database.transaction() as connection:
        rows = {table: [tuple(row) for row in connection.execute(f"SELECT * FROM {table} ORDER BY 1")]
                for table in ("messages", "events", "assignments", "contacts", "posts", "submissions", "revenue")}
    return hashlib.sha256(json.dumps(rows, sort_keys=True).encode()).hexdigest()


def session_revocation(directory, checks):
    from fastapi.testclient import TestClient

    app, credentials, _key = _fixture(directory / "host")
    with TestClient(app, base_url=ORIGIN) as first, TestClient(app, base_url=ORIGIN) as second:
        old_headers = _login(first, credentials)
        retained_headers = _login(second, credentials)
        checks.require("revoke_initial_access", first.get("/api/messages").status_code == 200)
        inventory = second.get("/api/security/sessions")
        if inventory.status_code != 200:
            raise AssertionError("Disposable session inventory failed.")
        other = [row for row in inventory.json()["sessions"] if not row["current"]]
        if len(other) != 1:
            raise AssertionError("Disposable session inventory was ambiguous.")
        response = second.post(f"/api/security/sessions/{other[0]['id']}/revoke", json={}, headers=retained_headers)
        checks.require("revoke_other_session", response.status_code == 200)
        before = _business_fingerprint(app.state.database)
        denied = first.post("/api/messages", json={"body": "Rejected disposable draft"}, headers=old_headers)
        checks.require("revoke_next_request", denied.status_code == 401)
        checks.require("revoke_no_business_change", _business_fingerprint(app.state.database) == before)
        accepted = second.post("/api/messages", json={"body": "Authorized disposable control"}, headers=retained_headers)
        checks.require("revoke_legitimate_control", accepted.status_code == 201
                       and _business_fingerprint(app.state.database) != before)


def stale_editor(directory, checks):
    from fastapi.testclient import TestClient
    from role_aware_dashboard_toolkit import AuditLog, ControlRegistry, InMemoryProfileStore
    from role_aware_dashboard_toolkit.access import Identity, InMemoryAccessStore, principal_id
    from role_aware_dashboard_toolkit.api import create_app
    from role_aware_dashboard_toolkit.api_access import APIAuthentication
    from role_aware_dashboard_toolkit.state_store import SQLiteStateStore

    path = directory / "state.sqlite3"
    first = SQLiteStateStore.create(path)
    second = SQLiteStateStore(path)
    barrier = Barrier(2)

    class RacingStore:
        def __init__(self, backend):
            self.backend = backend
            self.race = True

        def read(self):
            return self.backend.read()

        def compare_and_set(self, values, expected_revision):
            if self.race:
                barrier.wait(timeout=5)
            return self.backend.compare_and_set(values, expected_revision)

    key, token = secrets.token_bytes(32), secrets.token_urlsafe(24)
    identity = Identity("https://synthetic-demo.invalid", "disposable-editor", time.time() + 300)
    grants = InMemoryAccessStore()
    principal = principal_id(identity, key)
    grants.replace_grants(principal, ("Admin",))
    grants.compare_and_set_freeze(False, 0, principal)
    authentication = APIAuthentication(
        lambda request: identity if request.headers.get("authorization") == f"Bearer {token}" else None,
        grants, key,
    )
    stores, audits, clients = [], [], []
    headers = {"Authorization": f"Bearer {token}", "If-Match": '"0"'}
    with ExitStack() as stack:
        for backend in (first, second):
            registry = ControlRegistry()
            registry.register("Workers", key="workers", kind="number", default=1, min_value=1, max_value=40, step=1)
            store, audit = RacingStore(backend), AuditLog()
            app = create_app(registry, authentication=authentication, state_store=store,
                             audit=audit, profile_store=InMemoryProfileStore())
            stores.append(store)
            audits.append(audit)
            clients.append(stack.enter_context(TestClient(app)))
        reads = [client.get("/controls", headers=headers) for client in clients]
        checks.require("cas_shared_revision", all(reply.status_code == 200 and reply.headers["ETag"] == '"0"' for reply in reads))
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(client.patch, "/controls", headers=headers, json={"values": {"workers": value}})
                       for client, value in zip(clients, (10, 20))]
            responses = [future.result(timeout=15) for future in futures]
        checks.require("cas_one_winner", sorted(reply.status_code for reply in responses) == [200, 409])
        winner = next(reply for reply in responses if reply.status_code == 200)
        snapshot = first.read()
        events = [event for audit in audits for event in audit.all_events()]
        checks.require("cas_one_commit", snapshot.revision == 1 and snapshot.values["workers"] == winner.json()[0]["value"]
                       and len(events) == 1 and events[0]["type"] == "control_change")
        stores[0].race = False
        fresh = clients[0].patch("/controls", headers={**headers, "If-Match": '"1"'}, json={"values": {"workers": 30}})
        checks.require("cas_fresh_control", fresh.status_code == 200 and first.read().revision == 2
                       and first.read().values == {"workers": 30})


def recovery_authority(directory, checks):
    import backup
    from business.app import create_app
    from business.security import COOKIE_NAME
    from fastapi.testclient import TestClient

    current = directory / "current"
    app, credentials, key = _fixture(current)
    with TestClient(app, base_url=ORIGIN) as original:
        _login(original, credentials)
        old_cookie = original.cookies.get(COOKIE_NAME)
        with app.state.database.transaction() as connection:
            connection.execute("INSERT INTO messages VALUES(?,?,?,?)", ("security-demo-history", "alex", "Historical fictional record", "2026-01-01"))
        bundle = directory / "backup"
        backup.create_backup(current, bundle, mfa_key_file=key)
        with app.state.database.transaction() as connection:
            connection.execute("DELETE FROM messages WHERE id='security-demo-history'")
            connection.execute("UPDATE users SET active=0,revision=revision+1 WHERE id='blair'")
            connection.execute("DELETE FROM sessions WHERE user_id='alex'")
        restored = directory / "restored"
        backup.restore_backup(bundle, restored, mfa_key_file=key, security_source=current)
        restored_app = create_app(restored, public_origin=ORIGIN, mfa_key_file=key)
        with restored_app.state.database.transaction() as connection:
            historical = connection.execute("SELECT body FROM messages WHERE id='security-demo-history'").fetchone()
        checks.require("restore_historical_record", historical is not None and historical[0] == "Historical fictional record")
        with TestClient(restored_app, base_url=ORIGIN) as old, TestClient(restored_app, base_url=ORIGIN) as legitimate:
            rejected = old.get("/api/messages", headers={"Cookie": f"{COOKIE_NAME}={old_cookie}"})
            checks.require("restore_old_session_denied", rejected.status_code == 401)
            rejected = old.post("/api/login", json={"username": "blair", "password": credentials["blair"]}, headers={"Origin": ORIGIN})
            checks.require("restore_disabled_user_denied", rejected.status_code == 401)
            headers = _login(legitimate, credentials)
            checks.require("restore_current_access", legitimate.get("/api/messages").status_code == 200)
            before = _business_fingerprint(restored_app.state.database)
            rejected = legitimate.post("/api/messages", json={"body": "Frozen disposable control"}, headers=headers)
            checks.require("restore_remains_frozen", rejected.status_code == 403
                           and _business_fingerprint(restored_app.state.database) == before)


def run_demo(*, root=None):
    import role_aware_dashboard_toolkit as toolkit

    if Path(toolkit.__file__).resolve().parent != ROOT / "role_aware_dashboard_toolkit":
        raise ValueError("The security demonstration requires this checkout.")
    receipt = new_receipt("scenarios", CHECKS, root=root)
    checks = Checks(receipt)
    failure = None
    try:
        with tempfile.TemporaryDirectory(prefix="radt-security-demo-") as temporary:
            # Canonicalize only this newly created, runner-owned directory.
            # macOS temp roots can include the system /var -> /private/var alias;
            # private-storage validators still reject operator-supplied redirects.
            directory = Path(temporary).resolve(strict=True)
            for scenario in (session_revocation, stale_editor, recovery_authority):
                trial = directory / scenario.__name__
                trial.mkdir(mode=0o700)
                scenario(trial, checks)
    except (Exception, KeyboardInterrupt) as error:
        failure = error
    return finish_receipt(receipt, root=root, error=failure)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True, type=Path)
    options = parser.parse_args(argv)
    output = options.output_dir.resolve()
    if output == ROOT or ROOT in output.parents or (output.exists() and (not output.is_dir() or any(output.iterdir()))):
        parser.error("Evidence directory must be empty and outside the checkout.")
    output.mkdir(mode=0o700, parents=True, exist_ok=True)
    result = run_demo()
    write_receipt(output / "receipt.json", result)
    print(f"Security demonstration: {result['status']}; {sum(row['status'] == 'passed' for row in result['checks'])}/{len(result['checks'])} checks passed.")
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
