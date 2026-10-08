"""An unreadable saved profile must never be mistaken for an unused name."""

from copy import deepcopy

import pytest

from tests.test_profile_menu_refresh import _consumer, _healthy, _profile_events


AppTest = pytest.importorskip("streamlit.testing.v1").AppTest


@pytest.mark.parametrize("listed", [True, False])
def test_unreadable_save_target_is_preserved_and_failure_is_sanitized(tmp_path, monkeypatch, listed):
    app = _healthy(AppTest.from_function(
        _consumer, args=(str(tmp_path / "audit"),), default_timeout=15,
    ).run())
    app.number_input(key="workers").set_value(18)
    _healthy(app.text_input(key="_radt_profile_name").set_value("  base  ").run())
    store = app.session_state["config"].profile_store
    original_load, original_save = store.load, store.save
    original = deepcopy(original_load("base"))
    saved_calls = []
    store.read_errors = []

    def unreadable(profile_id):
        if profile_id == "base":
            if not listed:
                store.read_errors.append({
                    "path": "C:/private/private-store-canary.json",
                    "error_type": "UnicodeDecodeError",
                    "message": "private-store-canary",
                })
            return None
        return original_load(profile_id)

    def record_save(profile):
        saved_calls.append(profile)
        return original_save(profile)

    monkeypatch.setattr(store, "load", unreadable)
    monkeypatch.setattr(store, "save", record_save)
    if not listed:
        monkeypatch.setattr(store, "list_ids", lambda: ["other"])

    _healthy(app.button(key="_radt_profile_save").click().run())

    assert not saved_calls
    assert original_load("base") == original
    assert not _profile_events(app)
    assert not app.get("toast")
    assert "RADT-PROFILE-IO" in " ".join(item.value for item in app.error)
    visible = "\n".join(str(element.proto) for element in app if hasattr(element, "proto"))
    assert "private-store-canary" not in visible
    assert app.number_input(key="workers").value == 18
    assert app.text_input(key="_radt_profile_name").value == "  base  "
    assert app.selectbox(key="_radt_profile_choice").value == "(none)"
