from __future__ import annotations

import importlib.util
import re
from pathlib import Path

import role_aware_dashboard_toolkit as radt


REPO_ROOT = Path(__file__).resolve().parents[1]
EXAMPLES_DIR = REPO_ROOT / "examples"
RETAINED_EXAMPLES = {
    "core_library.py",
    "dashboard_admin_controls_app.py",
    "plugin_template.py",
}
RETIRED_EXAMPLE_NAMES = {
    "codex_builder_dashboard_app.py",
    "control_room_dashboard_app.py",
    "harness_dashboard_app.py",
    "model_control_panel.py",
    "repoos_dashboard_app.py",
    "semantic_review_cockpit_demo.py",
    "semantic_snapshot_auditor_demo.py",
    "semantic_snapshot_compare_demo.py",
    "semantic_snapshot_compare_minimal.py",
}


def _read(name: str) -> str:
    return (EXAMPLES_DIR / name).read_text(encoding="utf-8")


def test_example_surface_is_exactly_the_retained_oss_set():
    assert {path.name for path in EXAMPLES_DIR.glob("*.py")} == RETAINED_EXAMPLES

    corpus = "\n".join(
        [_read("README.md"), *(_read(name) for name in sorted(RETAINED_EXAMPLES))]
    ).lower()
    for retired_name in RETIRED_EXAMPLE_NAMES:
        assert retired_name not in corpus


def test_plugin_template_imports_and_builds_renderable_plugin():
    path = EXAMPLES_DIR / "plugin_template.py"
    spec = importlib.util.spec_from_file_location("role_aware_dashboard_toolkit_plugin_template_example", path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    plugin = module.build_plugin()
    assert isinstance(plugin, radt.DashboardPlugin)
    assert plugin.name == "example-plugin"
    assert plugin.capabilities == ["sidebar", "panel"]

    events: list[tuple[str, str]] = []

    class FakeStreamlit:
        def caption(self, value):
            events.append(("caption", value))

        def write(self, value):
            events.append(("write", value))

    context = {"st": FakeStreamlit()}
    assert plugin.render_sidebar is not None
    assert plugin.render_panel is not None
    plugin.render_sidebar(context)
    plugin.render_panel(context)

    assert events == [
        ("caption", "Example sidebar plugin loaded."),
        ("write", "Example panel plugin loaded."),
    ]


def test_examples_index_describes_only_the_retained_examples():
    text = _read("README.md")
    referenced_python_files = set(re.findall(r"\b[A-Za-z0-9_]+\.py\b", text))

    assert referenced_python_files == RETAINED_EXAMPLES | {"app.py", "demo.py"}
    assert "section_access/README.md" in text
    assert "examples/section_access/demo.py" in text
    assert "examples/operator_review/app.py" in text
    assert "operator_review/README.md" in text
    assert "## Dependency-free library example" in text
    assert "python -m examples.core_library" in text
    assert "## Streamlit dashboard" in text
    assert 'python -m pip install -e ".[workbench,dev]"' in text
    assert "python -m streamlit run examples/dashboard_admin_controls_app.py" in text
    assert "## Plugin template" in text
    assert "source-distribution material" in text
