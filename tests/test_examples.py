from __future__ import annotations

import io
import json
import py_compile
import runpy
from contextlib import redirect_stdout
from pathlib import Path


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


def test_dashboard_example_keeps_state_details_in_a_collapsed_expander():
    example = _read("dashboard_admin_controls_app.py")
    assert 'with st.expander("State snapshot", expanded=False):' in example
    assert '"plugin_count": len(plugins.describe())' in example
    assert '"controls_writable": ctx.controls_writable' in example


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
