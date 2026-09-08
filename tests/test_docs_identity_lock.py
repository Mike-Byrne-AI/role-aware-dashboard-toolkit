import re
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
IDENTITY_DOCS = (
    "README.md",
    "ARCHITECTURE_SCOPE.md",
    "docs/what_role_aware_dashboard_toolkit_is_and_is_not.md",
)
DISPLAY_NAME = "Role-Aware Dashboard Toolkit"
DISTRIBUTION_NAME = "role-aware-dashboard-toolkit"
IMPORT_NAMESPACE = "role_aware_dashboard_toolkit"


def _read(path: str) -> str:
    return (REPO_ROOT / path).read_text(encoding="utf-8")


def test_front_door_docs_share_the_generic_dashboard_library_identity():
    normalized = {
        path: " ".join(_read(path).lower().split()) for path in IDENTITY_DOCS
    }

    for path, text in normalized.items():
        assert DISPLAY_NAME.lower() in text, path
        assert "dashboard" in text, path
        assert "library" in text or "toolbelt" in text, path

    combined = " ".join(normalized.values())
    for capability in (
        "controls",
        "profiles",
        "audit",
        "plugins",
        "checkpoints",
        "packets",
    ):
        assert capability in combined


def test_identity_docs_keep_authority_and_side_effect_boundaries_explicit():
    combined = " ".join(_read(path).lower() for path in IDENTITY_DOCS)

    assert "authentication" in combined
    assert "trusted code" in combined
    assert "external mutations" in combined or "external side effects" in combined
    assert "distributed" in combined
    assert "product-specific" in combined or "application-specific" in combined


def test_readme_distinguishes_distribution_and_import_names():
    readme = _read("README.md")
    assert f"python -m pip install {DISTRIBUTION_NAME}" in readme
    assert f'python -m pip install "{DISTRIBUTION_NAME}[workbench]"' in readme
    assert f"import {IMPORT_NAMESPACE} as radt" in readme
    assert f"pip install {IMPORT_NAMESPACE}" not in readme
    assert f'pip install "{IMPORT_NAMESPACE}[' not in readme


def test_readme_primary_paths_use_only_retained_generic_examples():
    readme = _read("README.md")
    referenced_examples = set(re.findall(r"(?:examples[/.][A-Za-z0-9_.-]+)", readme))

    assert referenced_examples == {
        "examples.core_library",
        "examples/dashboard_admin_controls_app.py",
    }
