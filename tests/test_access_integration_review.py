"""Review regressions for actor binding and audit lifecycle across real reruns."""

import time

import pytest

from role_aware_dashboard_toolkit import (
    AuditLog,
    DashboardConfig,
    DashboardSections,
    InMemoryProfileStore,
    InMemoryRunStore,
)
from role_aware_dashboard_toolkit.access import (
    AccessPolicy,
    Identity,
    InMemoryAccessStore,
    principal_id,
)


AppTest = pytest.importorskip("streamlit.testing.v1").AppTest
KEY = b"synthetic-review-test-key" * 2
ISSUER = "synthetic-review"


def _resolve_test_account():
    import streamlit as st

    return Identity(ISSUER, st.session_state["synthetic_account"], time.time() + 3600)


def _render_shared_config(config, account):
    import streamlit as st
    from role_aware_dashboard_toolkit import render

    # Synthetic test-only identity adapter. Production never trusts a widget or
    # user-editable session key as identity; its provider adapter verifies login.
    st.session_state["synthetic_account"] = account
    render(config)


def _config(tmp_path):
    store = InMemoryAccessStore()
    principals = {
        account: principal_id(Identity(ISSUER, account, time.time() + 3600), KEY)
        for account in ("first", "second")
    }
    for pid in principals.values():
        store.replace_grants(pid, ("Admin",))
    store.compare_and_set_freeze(False, 0, principals["first"])
    audit = AuditLog()
    config = DashboardConfig(
        access=AccessPolicy(_resolve_test_account, store, KEY), audit=audit,
        audit_dir=str(tmp_path), profile_store=InMemoryProfileStore(),
        run_store=InMemoryRunStore(),
        sections=DashboardSections(profiles=False, controls=False, observability=False,
                                   audit_log=False, plugin_details=False),
    )
    return config, store, audit, principals


def _healthy(app):
    assert not app.exception, [error.message for error in app.exception]
    return app


def test_shared_config_freeze_callback_preserves_its_original_verified_actor(tmp_path):
    config, store, audit, principals = _config(tmp_path)
    first = _healthy(AppTest.from_function(
        _render_shared_config, args=(config, "first"), default_timeout=15
    ).run())
    second = _healthy(AppTest.from_function(
        _render_shared_config, args=(config, "second"), default_timeout=15
    ).run())
    assert config.audit is audit
    assert first.session_state["_radt_authenticated_principal"] == principals["first"]
    assert second.session_state["_radt_authenticated_principal"] == principals["second"]

    _healthy(first.toggle(key="_radt_shared_frozen").set_value(True).run())
    assert store.read_freeze().frozen is True
    assert store.read_freeze().changed_by == principals["first"]
    events = [event for event in audit.all_events() if event["type"] == "shared_freeze_changed"]
    assert len(events) == 1
    assert events[0]["user_id"] == principals["first"]
    assert events[0]["session_id"] == first.session_state["_radt_authenticated_session"]
    assert config.audit is audit


def test_authenticated_run_rerun_preserves_enabled_audit_writer_and_path(tmp_path):
    config, _store, audit, _principals = _config(tmp_path)
    app = _healthy(AppTest.from_function(
        _render_shared_config, args=(config, "first"), default_timeout=15
    ).run())
    path = str(tmp_path / "selected-audit.jsonl")
    try:
        _healthy(app.text_input(key="_radt_audit_path").set_value(path).run())
        _healthy(app.toggle(key="_radt_audit_writer").set_value(True).run())
        assert audit.writer_status()["writer_active"] is True
        _healthy(app.button(key="_radt_run_start").click().run())
        assert app.session_state["_radt_audit_writer"] is True
        assert app.session_state["_radt_audit_path"] == path
        assert audit.writer_status()["writer_active"] is True
        assert config.run_store.list_ids()
    finally:
        audit.stop_writer()
    assert path == app.session_state["_radt_audit_path"]
    assert (tmp_path / "selected-audit.jsonl").exists()
