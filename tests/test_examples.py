from __future__ import annotations

import io
import json
import py_compile
import runpy
from contextlib import redirect_stdout
from pathlib import Path

import pytest

from role_aware_dashboard_toolkit import FileProfileStore


REPO_ROOT = Path(__file__).resolve().parents[1]
EXAMPLES_DIR = REPO_ROOT / "examples"
RETAINED_EXAMPLES = (
    "core_library.py",
    "dashboard_admin_controls_app.py",
    "plugin_template.py",
)


def _read(name: str) -> str:
    return (EXAMPLES_DIR / name).read_text(encoding="utf-8")


def test_all_retained_examples_compile(tmp_path):
    for name in RETAINED_EXAMPLES:
        py_compile.compile(
            str(EXAMPLES_DIR / name),
            cfile=str(tmp_path / f"{name}c"),
            doraise=True,
        )


def test_core_library_example_runs_and_exports_a_run_packet():
    stdout = io.StringIO()
    with redirect_stdout(stdout):
        runpy.run_path(str(EXAMPLES_DIR / "core_library.py"), run_name="__main__")

    packet = json.loads(stdout.getvalue())
    assert packet["packet_type"] == "run"
    assert packet["source_app"] == "role_aware_dashboard_toolkit"
    assert packet["meta"]["run_id"] == "example_run"
    assert packet["payload"]["source_profile_id"] == "baseline"
    assert packet["payload"]["initial_controls"] == {
        "maintenance_mode": False,
        "request_timeout_seconds": 30,
    }
    assert packet["payload"]["latest_controls"] == {
        "maintenance_mode": True,
        "request_timeout_seconds": 30,
    }


def test_dashboard_example_profile_and_role_workflow(tmp_path, monkeypatch):
    AppTest = pytest.importorskip("streamlit.testing.v1").AppTest
    monkeypatch.chdir(tmp_path)
    app = AppTest.from_file(
        str(EXAMPLES_DIR / "dashboard_admin_controls_app.py"), default_timeout=15,
    ).run()

    def healthy():
        assert not app.exception, [item.message for item in app.exception]
        assert not app.error, [item.value for item in app.error]

    control_types = {
        "request_timeout_seconds": "slider",
        "worker_limit": "number_input",
        "deployment_track": "selectbox",
        "maintenance_mode": "toggle",
    }

    def controls():
        # Read-only controls use separate widget keys to protect live values.
        return {
            key: next(widget for widget in app.get(kind)
                      if widget.key in (key, "_radt_read_only_control__" + key))
            for key, kind in control_types.items()
        }

    healthy()
    baseline = {
        "request_timeout_seconds": 30, "worker_limit": 8,
        "deployment_track": "Stable", "maintenance_mode": False,
    }
    assert {key: widget.value for key, widget in controls().items()} == baseline
    assert all(not widget.disabled for widget in controls().values())
    assert "Role=Admin; writable=True" in [item.value for item in app.info]
    snapshot = next(item for item in app.expander if item.label == "State snapshot")
    assert not snapshot.proto.expanded
    assert json.loads(snapshot.json[0].value)["plugin_count"] == 1
    resources = app.session_state["_radt_dashboard_admin_resources"]
    config, plugins = resources["config"], resources["plugins"]
    audit = config.audit

    app.text_input(key="_radt_profile_name").set_value("baseline").run()
    app.button(key="_radt_profile_save").click().run()
    healthy()
    # A fresh store must see the actual disk write, not an in-memory cache.
    profile_dir = tmp_path / "profiles"
    assert FileProfileStore(str(profile_dir)).load("baseline")["values"] == baseline
    assert "baseline" in app.selectbox(key="_radt_profile_choice").options

    app.slider(key="request_timeout_seconds").set_value(60)
    app.number_input(key="worker_limit").set_value(16)
    app.selectbox(key="deployment_track").select("Canary")
    app.toggle(key="maintenance_mode").set_value(True).run()
    healthy()
    edited = {
        "request_timeout_seconds": 60, "worker_limit": 16,
        "deployment_track": "Canary", "maintenance_mode": True,
    }
    assert {key: widget.value for key, widget in controls().items()} == edited
    app.selectbox(key="_radt_profile_choice").select("baseline").run()
    app.button(key="_radt_profile_load").click().run()
    healthy()
    assert {key: widget.value for key, widget in controls().items()} == baseline
    app.button(key="_radt_profile_delete").click().run()
    healthy()
    assert FileProfileStore(str(profile_dir)).load("baseline") is None
    assert FileProfileStore(str(profile_dir)).list_ids() == []
    assert "baseline" not in app.selectbox(key="_radt_profile_choice").options
    assert [event["type"] for event in audit.all_events()
            if event["type"].startswith("profile_")] == [
        "profile_save", "profile_load", "profile_delete",
    ]

    app.selectbox(key="_radt_role").select("Release Lead").run()
    healthy()
    assert all(not widget.disabled for widget in controls().values())
    assert not app.button(key="_radt_profile_save").disabled
    assert "Role=Release Lead; writable=True" in [item.value for item in app.info]
    app.selectbox(key="_radt_role").select("Viewer").run()
    healthy()
    assert all(widget.disabled for widget in controls().values())
    assert app.button(key="_radt_profile_save").disabled
    assert "Role=Viewer; writable=True" in [item.value for item in app.info]
    assert {key: widget.value for key, widget in controls().items()} == baseline

    events = audit.all_events()
    app.run()
    healthy()
    retained = app.session_state["_radt_dashboard_admin_resources"]
    assert retained["config"] is config
    assert retained["plugins"] is plugins
    assert config.plugins is plugins
    assert config.audit is audit
    assert audit.all_events() == events


def test_streamlit_example_guidance_uses_the_workbench_extra():
    readme = _read("README.md")
    install = 'python -m pip install -e ".[workbench,dev]"'
    run = "python -m streamlit run examples/dashboard_admin_controls_app.py"

    assert readme.index(install) < readme.index(run)
    assert "grouped controls" in readme
    assert "custom role" in readme
    assert "write-policy switch" in readme
    assert "profile and audit panels" in readme
    assert "trusted plugin panel" in readme
