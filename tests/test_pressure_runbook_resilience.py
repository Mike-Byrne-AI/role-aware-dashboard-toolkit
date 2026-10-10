"""Pressure regressions for records disappearing during native runbook reads."""

import pytest

from role_aware_dashboard_toolkit import InMemoryRunStore, build_run
from role_aware_dashboard_toolkit.runbook_panels import render_runbook_panel
from tests.test_runbook_contract import _FakeStreamlit, _admin_ctx, _runbook_config


class _VanishingRunStore(InMemoryRunStore):
    def list_ids(self):
        identifiers = super().list_ids()
        self.delete("vanishing")
        return identifiers


@pytest.mark.parametrize("keep_healthy", [False, True])
def test_runbook_handles_run_deleted_between_listing_and_loading(keep_healthy):
    store = _VanishingRunStore()
    store.save(build_run({}, run_id="vanishing"))
    if keep_healthy:
        store.save(build_run({}, run_id="healthy"))
    st = _FakeStreamlit(session_state={"_radt_selected_run_id": "vanishing"})

    render_runbook_panel(st, _runbook_config(store), _admin_ctx())

    assert not any(event[0] == "toast" for event in st.events)
    selections = [event for event in st.events if event[0] == "selectbox"]
    if keep_healthy:
        assert selections[0][2] == "healthy"
        assert store.load("healthy")["run_id"] == "healthy"
    else:
        assert not selections
        assert any(event[0] == "caption" and "available" in event[1].lower()
                   for event in st.events)


def _runbook_consumer(keep_healthy):
    import streamlit as st

    from role_aware_dashboard_toolkit import build_run
    from role_aware_dashboard_toolkit.runbook_panels import render_runbook_panel
    from tests.test_pressure_runbook_resilience import _VanishingRunStore
    from tests.test_runbook_contract import _admin_ctx, _runbook_config

    store = _VanishingRunStore()
    store.save(build_run({}, run_id="vanishing"))
    if keep_healthy:
        store.save(build_run({}, run_id="healthy"))
    render_runbook_panel(st, _runbook_config(store), _admin_ctx())


@pytest.mark.parametrize("keep_healthy", [False, True])
def test_vanishing_run_renders_in_streamlit(keep_healthy):
    AppTest = pytest.importorskip("streamlit.testing.v1").AppTest
    app = AppTest.from_function(_runbook_consumer, args=(keep_healthy,)).run(timeout=10)

    assert not app.exception
    if keep_healthy:
        assert app.selectbox(key="_radt_selected_run_id").value == "healthy"
    else:
        assert not app.selectbox
        assert any("available" in item.value.lower() for item in app.caption)
