"""Explicit session-lineage migration preserves authority and rolls back faults."""

import hashlib
import sqlite3

import pytest

from tests.test_business_dashboard import (
    business as business, business_admin as business_admin, business_seed as business_seed,
    downgrade_enrollment_schema,
)
from business import db
from business.secret_store import default_key_path
from business.security import COOKIE_NAME, authenticate


def _schema_six(business):
    with business.raw_db() as connection:
        downgrade_enrollment_schema(connection)
        connection.execute("DROP TABLE session_predecessors")
        connection.execute("PRAGMA user_version=6")
        db._require_schema(connection, 6)


def _fingerprint(business):
    with business.raw_db() as connection:
        return hashlib.sha256("\n".join(connection.iterdump()).encode()).hexdigest()


def test_schema_six_requires_explicit_upgrade_and_preserves_existing_sessions(business, business_admin):
    employee = business.login("alex")
    _schema_six(business)
    with business.raw_db() as connection:
        tables = [row[0] for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
        )]
        before = {name: [tuple(row) for row in connection.execute(f"SELECT * FROM {name} ORDER BY 1")]
                  for name in tables}
    snapshot = _fingerprint(business)
    with pytest.raises(ValueError, match="explicit reviewed migration to schema ten"):
        db.Database(business.directory, mfa_key_file=default_key_path(business.directory))
    assert _fingerprint(business) == snapshot
    migrated = db.Database(business.directory, mfa_key_file=default_key_path(business.directory), migrate=True)
    with migrated.transaction() as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 10
        db._require_schema(connection, 10)
        assert connection.execute("SELECT * FROM session_predecessors").fetchall() == []
        after = {}
        for name in tables:
            query = ("SELECT event_id,attempts,next_attempt_at,acknowledged_at,last_error "
                     "FROM security_delivery_obligations WHERE destination_id='local-v1' ORDER BY event_id"
                     if name == "security_outbox" else
                     f"SELECT * FROM {'account_mfa' if name == 'admin_mfa' else name} ORDER BY 1")
            after[name] = [tuple(row) for row in connection.execute(query)]
        assert after == before
        for actor in (business_admin, employee):
            context = authenticate(connection, actor.client.cookies[COOKIE_NAME], migrated.identity_key)
            assert context.csrf == actor.csrf
            context.authorize("can_view_team")


def test_session_lineage_migration_fault_rolls_back_ddl_version_and_existing_state(business, monkeypatch):
    business.login("alex")
    _schema_six(business)
    before = _fingerprint(business)
    original = db._apply_session_predecessor_migration

    def fail_after_ddl(connection):
        original(connection)
        raise sqlite3.OperationalError("Synthetic session-lineage migration interruption")

    monkeypatch.setattr(db, "_apply_session_predecessor_migration", fail_after_ddl)
    with pytest.raises(ValueError, match="invalid or incomplete"):
        db.Database(business.directory, mfa_key_file=default_key_path(business.directory), migrate=True)
    assert _fingerprint(business) == before
    with business.raw_db() as connection:
        db._require_schema(connection, 6)
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 6


@pytest.mark.parametrize("damage", ["DROP INDEX security_outbox_pending", "CREATE TABLE unexpected(value TEXT)"])
def test_session_lineage_upgrade_validates_old_schema_before_ddl(business, monkeypatch, damage):
    _schema_six(business)
    with business.raw_db() as connection:
        connection.execute(damage)
    before = _fingerprint(business)
    monkeypatch.setattr(db, "_apply_session_predecessor_migration",
                        lambda connection: pytest.fail("Invalid schema reached migration"))
    with pytest.raises(ValueError, match="schema is incomplete or unsupported"):
        db.Database(business.directory, mfa_key_file=default_key_path(business.directory), migrate=True)
    assert _fingerprint(business) == before
