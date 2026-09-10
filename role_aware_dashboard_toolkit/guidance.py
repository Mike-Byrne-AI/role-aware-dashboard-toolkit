"""Read version-matched offline guidance from the installed package.

These functions never import a consumer application or execute optional hosts.
Package guidance describes this library; user and project instructions retain
control over the work an assistant is authorized to perform.
"""
from __future__ import annotations

from dataclasses import asdict
from importlib import metadata, resources
from inspect import signature
from typing import Any

_GUIDE_TITLES = {
    "start": "Start an assistant-ready dashboard",
    "controls": "Add, change and remove controls",
    "appearance": "Customize page and card colors",
    "sections": "Choose panels and menus",
    "plugins": "Add custom panels and sidebar callbacks",
    "permissions": "Roles, permissions and frozen controls",
    "profiles": "Save and load profiles",
    "runs": "Runs, checkpoints and replay",
    "telemetry": "Sample and capture telemetry",
    "api": "Optional HTTP API",
    "troubleshooting": "Diagnose and verify changes",
}
_STARTER_FILES = {
    "app.py": "app.py",
    ".streamlit/config.toml": "config.toml",
    "AGENTS.md": "AGENTS.md",
    "README.md": "README.md",
}
_COMMAND = "python -m role_aware_dashboard_toolkit"


def list_guide_topics() -> list[dict[str, str]]:
    """Return the fixed topic catalog for this installed toolkit version."""
    return [{"id": topic, "title": title, "command": f"{_COMMAND} guide {topic}"}
            for topic, title in _GUIDE_TITLES.items()]


def read_guide(topic: str) -> dict[str, str]:
    """Read one known topic; arbitrary resource paths are never accepted."""
    if topic not in _GUIDE_TITLES:
        raise ValueError(f"Unknown guide topic: {topic}. Available topics: {', '.join(_GUIDE_TITLES)}")
    content = resources.files(__package__).joinpath("resources", "guides", f"{topic}.md").read_text(encoding="utf-8")
    return {"topic": topic, "title": _GUIDE_TITLES[topic], "content": content}


def read_starter() -> dict[str, str]:
    """Read the starter's fixed project files without writing or executing them."""
    root = resources.files(__package__).joinpath("resources", "starter")
    return {destination: root.joinpath(source).read_text(encoding="utf-8")
            for destination, source in _STARTER_FILES.items()}


def inspect_capabilities() -> dict[str, Any]:
    """Describe installed APIs; dependency metadata is not a compatibility test."""
    from .appearance import build_streamlit_theme_toml
    from .controls import ControlDef, ControlRegistry, VALID_KINDS
    from .dashboard import DashboardConfig
    from .diagnostics import list_diagnostics
    from .plugins import DashboardPlugin, PluginRegistry
    from .public_api import public_api_manifest
    from .sections import DashboardSections

    symbols = {
        "DashboardConfig": DashboardConfig,
        "DashboardSections": DashboardSections,
        "ControlDef": ControlDef,
        "ControlRegistry.register": ControlRegistry.register,
        "ControlRegistry.unregister": ControlRegistry.unregister,
        "DashboardPlugin": DashboardPlugin,
        "PluginRegistry.register": PluginRegistry.register,
        "PluginRegistry.unregister": PluginRegistry.unregister,
        "build_streamlit_theme_toml": build_streamlit_theme_toml,
    }
    dependencies = {}
    for name in ("streamlit", "pandas", "fastapi", "pydantic", "uvicorn"):
        try:
            version = metadata.version(name)
        except metadata.PackageNotFoundError:
            version = None
        dependencies[name] = {"installed": version is not None, "version": version,
                              "import_tested": False, "compatibility_tested": False}
    return {
        "api_manifest": public_api_manifest(),
        "diagnostics": list_diagnostics(),
        "control_kinds": list(VALID_KINDS),
        "supported_layouts": ["stacked", "columns"],
        "appearance_requirements": {
            "core_workbench": "Streamlit >=1.30",
            "group_fills": "Streamlit >=1.39 with st.container(key=...) and st.html()",
            "sidebar_theme": "Streamlit >=1.44",
            "note": "Documented API requirements, not certification of the installed runtime.",
        },
        "section_defaults": asdict(DashboardSections()),
        "signatures": {name: str(signature(value)) for name, value in symbols.items()},
        "optional_dependencies": dependencies,
        "dependency_note": "Distribution metadata only; optional hosts were not imported or tested for compatibility.",
        "guide_topics": list_guide_topics(),
        "examples": ["starter"],
    }


__all__ = ["list_guide_topics", "read_guide", "read_starter", "inspect_capabilities"]
