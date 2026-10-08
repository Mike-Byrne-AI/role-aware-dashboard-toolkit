"""A queued freeze callback must not retain a role the same submission leaves."""

import pytest

from tests.test_authenticated_ui import _app, _healthy, _host


@pytest.mark.parametrize("next_role", ["Viewer", "Operator"])
@pytest.mark.parametrize("initial_frozen", [True, False])
def test_role_change_discards_previous_roles_freeze_submission(next_role, initial_frozen):
    host = _host(("Admin", next_role))
    if not initial_frozen:
        host.store.compare_and_set_freeze(False, 0, host.principal)
    app = _app(host)
    before = host.store.read_freeze()

    # Streamlit runs callbacks before rerendering the newly selected role. A
    # batched/stale browser submission can contain both changed widget values.
    app.selectbox(key="_radt_role").select(next_role)
    _healthy(app.toggle(key="_radt_shared_frozen").set_value(not initial_frozen).run())

    assert app.session_state["test_context"].role == next_role
    assert host.store.read_freeze() == before
    assert app.toggle(key="_radt_shared_frozen").disabled
    assert any("Freeze change denied" in item.value for item in app.warning)
    assert not any(
        event["type"] == "shared_freeze_changed" for event in host.audit.all_events()
    )
