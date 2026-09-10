from __future__ import annotations

import string
from collections.abc import Iterable
from typing import Any

from .distribution import (
    ROLE_AWARE_DASHBOARD_TOOLKIT_DISTRIBUTION_STRATEGY,
    list_distribution_artifacts,
)
from .public_api import list_public_api_families, public_api_manifest
from .version import ROLE_AWARE_DASHBOARD_TOOLKIT_VERSION


def build_release_manifest() -> dict[str, Any]:
    artifacts = list_distribution_artifacts()
    api_families = list_public_api_families()
    api_manifest = public_api_manifest()
    return {
        "version": ROLE_AWARE_DASHBOARD_TOOLKIT_VERSION,
        "distribution_strategy": ROLE_AWARE_DASHBOARD_TOOLKIT_DISTRIBUTION_STRATEGY,
        "artifact_ids": [artifact["artifact_id"] for artifact in artifacts],
        "family_ids": [family["family_id"] for family in api_families],
        "artifacts": artifacts,
        "api_families": api_families,
        "api_manifest": api_manifest,
    }


def build_release_audit_markdown() -> str:
    manifest = build_release_manifest()
    api = manifest["api_manifest"]
    counts = api["classification_counts"]
    lines = [
        "# Role-Aware Dashboard Toolkit release audit",
        "",
        f"- Version: `{manifest['version']}`",
        f"- Distribution strategy: `{manifest['distribution_strategy']}`",
        f"- Artifacts: {', '.join(f'`{item}`' for item in manifest['artifact_ids'])}",
        f"- Public API families: {', '.join(f'`{item}`' for item in manifest['family_ids'])}",
        f"- Root exports: `{api['export_count']}` / `{api['root_export_budget']['total']}`",
        f"- Stable root exports: `{counts.get('stable', 0)}`",
        f"- Undocumented root exports: `{api['undocumented_export_count']}`",
        "",
        "## Artifact summary",
        "",
    ]
    for artifact in manifest["artifacts"]:
        lines.extend(
            [
                f"### {artifact['display_name']}",
                "",
                f"- Artifact id: `{artifact['artifact_id']}`",
                f"- Install target: `{artifact['install_target']}`",
                "",
            ]
        )
    return "\n".join(lines)


RELEASE_ARTIFACT_BLOCKLIST = (
    ".coverage",
    "__pycache__/",
    ".pyc",
    ".pyo",
    ".DS_Store",
    "Thumbs.db",
    "tests/",
    ".repo_os/",
    ".codex/",
    "codex-lite/",
    "role_aware_dashboard_toolkit/_archive_review/",
    "role_aware_dashboard_toolkit/integrations/",
    "portable/",
    "snapshot_manifests/",
    "docs/history/",
)

# This is intentionally an exact list instead of a set of permissive prefixes.
# Hatch includes every file under the package directory, including untracked
# files in a local checkout. Keeping the retained package surface here makes an
# unexpected module a release failure rather than an accidental public API.
_PUBLIC_PACKAGE_MEMBERS = frozenset(
    {
        "role_aware_dashboard_toolkit/__init__.py",
        "role_aware_dashboard_toolkit/_exports.py",
        "role_aware_dashboard_toolkit/_json_safety.py",
        "role_aware_dashboard_toolkit/_optional_pandas.py",
        "role_aware_dashboard_toolkit/_record_utils.py",
        "role_aware_dashboard_toolkit/_ui_state.py",
        "role_aware_dashboard_toolkit/api.py",
        "role_aware_dashboard_toolkit/appearance.py",
        "role_aware_dashboard_toolkit/approvals.py",
        "role_aware_dashboard_toolkit/audit.py",
        "role_aware_dashboard_toolkit/audit_store.py",
        "role_aware_dashboard_toolkit/case_store.py",
        "role_aware_dashboard_toolkit/caseboard.py",
        "role_aware_dashboard_toolkit/checkpoints.py",
        "role_aware_dashboard_toolkit/compare.py",
        "role_aware_dashboard_toolkit/controls.py",
        "role_aware_dashboard_toolkit/dashboard.py",
        "role_aware_dashboard_toolkit/dashboard_context.py",
        "role_aware_dashboard_toolkit/dashboard_panels.py",
        "role_aware_dashboard_toolkit/decision_store.py",
        "role_aware_dashboard_toolkit/decisions.py",
        "role_aware_dashboard_toolkit/distribution.py",
        "role_aware_dashboard_toolkit/governance.py",
        "role_aware_dashboard_toolkit/governance_store.py",
        "role_aware_dashboard_toolkit/ledger.py",
        "role_aware_dashboard_toolkit/observability.py",
        "role_aware_dashboard_toolkit/operator_memory.py",
        "role_aware_dashboard_toolkit/operator_memory_normalization.py",
        "role_aware_dashboard_toolkit/operator_memory_store.py",
        "role_aware_dashboard_toolkit/packet_core.py",
        "role_aware_dashboard_toolkit/packets.py",
        "role_aware_dashboard_toolkit/path_redaction.py",
        "role_aware_dashboard_toolkit/plugins.py",
        "role_aware_dashboard_toolkit/profile_store.py",
        "role_aware_dashboard_toolkit/profiles.py",
        "role_aware_dashboard_toolkit/protocol/__init__.py",
        "role_aware_dashboard_toolkit/protocol/catalog.py",
        "role_aware_dashboard_toolkit/public_api.py",
        "role_aware_dashboard_toolkit/public_api_parts/__init__.py",
        "role_aware_dashboard_toolkit/public_api_parts/family_definitions.py",
        "role_aware_dashboard_toolkit/public_api_parts/family_registry.py",
        "role_aware_dashboard_toolkit/public_api_parts/manifest_tools.py",
        "role_aware_dashboard_toolkit/public_api_parts/reference_markdown.py",
        "role_aware_dashboard_toolkit/public_api_parts/usage_recipes.py",
        "role_aware_dashboard_toolkit/py.typed",
        "role_aware_dashboard_toolkit/release_audit.py",
        "role_aware_dashboard_toolkit/replay.py",
        "role_aware_dashboard_toolkit/run_store.py",
        "role_aware_dashboard_toolkit/runbook_panels.py",
        "role_aware_dashboard_toolkit/runbook_panels_parts/__init__.py",
        "role_aware_dashboard_toolkit/runbook_panels_parts/caseboard.py",
        "role_aware_dashboard_toolkit/runbook_panels_parts/decisions.py",
        "role_aware_dashboard_toolkit/runbook_panels_parts/governance.py",
        "role_aware_dashboard_toolkit/runbook_panels_parts/operator_memory.py",
        "role_aware_dashboard_toolkit/runbook_panels_parts/review_models.py",
        "role_aware_dashboard_toolkit/runbook_panels_parts/shared.py",
        "role_aware_dashboard_toolkit/runbook_panels_parts/team_ops.py",
        "role_aware_dashboard_toolkit/runs.py",
        "role_aware_dashboard_toolkit/runtime.py",
        "role_aware_dashboard_toolkit/security.py",
        "role_aware_dashboard_toolkit/sections.py",
        "role_aware_dashboard_toolkit/sensitive_values.py",
        "role_aware_dashboard_toolkit/sidebar.py",
        "role_aware_dashboard_toolkit/store_diagnostics.py",
        "role_aware_dashboard_toolkit/team_ops.py",
        "role_aware_dashboard_toolkit/team_store.py",
        "role_aware_dashboard_toolkit/ui_json.py",
        "role_aware_dashboard_toolkit/ui_text.py",
        "role_aware_dashboard_toolkit/validators.py",
        "role_aware_dashboard_toolkit/validators_parts/__init__.py",
        "role_aware_dashboard_toolkit/validators_parts/common.py",
        "role_aware_dashboard_toolkit/version.py",
    }
)

_PUBLIC_SDIST_MEMBERS = frozenset(
    {
        ".github/workflows/ci.yml",
        ".gitignore",
        "ARCHITECTURE_SCOPE.md",
        "CHANGELOG.md",
        "CODE_OF_CONDUCT.md",
        "CONTRIBUTING.md",
        "LICENSE",
        "PKG-INFO",
        "README.md",
        "SECURITY.md",
        "docs/README.md",
        "docs/api_security.md",
        "docs/assets/dashboard_admin_controls_app.png",
        "docs/caseboard.md",
        "docs/dashboard_tools.md",
        "docs/decision_model.md",
        "docs/distribution.md",
        "docs/governance.md",
        "docs/operator_memory.md",
        "docs/oss_boundary.md",
        "docs/plugins.md",
        "docs/protocol/ledger.md",
        "docs/protocol/overview.md",
        "docs/protocol/packets.md",
        "docs/public_api.md",
        "docs/quickstart.md",
        "docs/release_audit.md",
        "docs/release_checklist.md",
        "docs/release_runbook.md",
        "docs/release_strategy.md",
        "docs/replay.md",
        "docs/replay_contract.md",
        "docs/run_model.md",
        "docs/shared_store_patterns.md",
        "docs/team_ops.md",
        "docs/telemetry_contract.md",
        "docs/what_role_aware_dashboard_toolkit_is_and_is_not.md",
        "examples/README.md",
        "examples/core_library.py",
        "examples/dashboard_admin_controls_app.py",
        "examples/plugin_template.py",
        "pyproject.toml",
        "schemas/case.schema.json",
        "schemas/checkpoint.schema.json",
        "schemas/decision.schema.json",
        "schemas/governance.schema.json",
        "schemas/incident.schema.json",
        "schemas/incident_timeline.schema.json",
        "schemas/ledger.schema.json",
        "schemas/narrative_handoff.schema.json",
        "schemas/operator_note.schema.json",
        "schemas/packet.schema.json",
        "schemas/replay.schema.json",
        "schemas/run.schema.json",
        "tools/pre_release_check.py",
    }
)

_WHEEL_METADATA_MEMBERS = frozenset(
    {
        "METADATA",
        "RECORD",
        "WHEEL",
        "licenses/LICENSE",
    }
)
_SDIST_ROOT = f"role_aware_dashboard_toolkit-{ROLE_AWARE_DASHBOARD_TOOLKIT_VERSION}"
_WHEEL_METADATA_ROOT = f"role_aware_dashboard_toolkit-{ROLE_AWARE_DASHBOARD_TOOLKIT_VERSION}.dist-info"


def audit_release_artifact_members(members: Iterable[str]) -> dict[str, Any]:
    rejected: list[str] = []
    unexpected: list[str] = []
    for raw_member in members:
        member = str(raw_member or "").replace("\\", "/")
        if not member:
            continue
        logical = _strip_archive_root(member)
        if _is_unsafe_archive_member_name(member) or _is_unsafe_archive_member_name(logical):
            rejected.append(member)
            continue
        if _is_blocked_member(logical):
            rejected.append(member)
            continue
        if not _is_public_artifact_member(logical):
            rejected.append(member)
            unexpected.append(member)
    return {
        "ok": not rejected,
        "blocked_members": rejected,
        "unexpected_members": unexpected,
        "blocklist": list(RELEASE_ARTIFACT_BLOCKLIST),
    }


def _is_blocked_member(member: str) -> bool:
    normalized = str(member or "").strip("/")
    lowered = normalized.lower()
    if lowered == ".coverage" or lowered.endswith("/.coverage"):
        return True
    if "__pycache__/" in lowered or lowered.endswith((".pyc", ".pyo")):
        return True
    if lowered in {".ds_store", "thumbs.db"} or lowered.endswith(("/.ds_store", "/thumbs.db")):
        return True
    blocked_prefixes = (
        "tests/",
        ".repo_os/",
        ".codex/",
        "codex-lite/",
        "role_aware_dashboard_toolkit/_archive_review/",
        "role_aware_dashboard_toolkit/integrations/",
        "portable/",
        "snapshot_manifests/",
        "docs/history/",
    )
    return any(
        lowered == prefix.rstrip("/") or lowered.startswith(prefix)
        for prefix in blocked_prefixes
    )


def _strip_archive_root(member: str) -> str:
    normalized = str(member or "").replace("\\", "/").strip("/")
    if "/" not in normalized:
        return normalized
    root, rest = normalized.split("/", 1)
    if root == _SDIST_ROOT:
        return rest
    return normalized


def _is_public_artifact_member(member: str) -> bool:
    if member in _PUBLIC_PACKAGE_MEMBERS or member in _PUBLIC_SDIST_MEMBERS:
        return True
    root, separator, rest = member.partition("/")
    return bool(
        separator
        and root == _WHEEL_METADATA_ROOT
        and rest in _WHEEL_METADATA_MEMBERS
    )


def _is_unsafe_archive_member_name(member: str) -> bool:
    logical = str(member or "")
    if not logical or logical.startswith("/") or ":" in logical:
        return True
    if any(
        char in string.whitespace and char not in {" ", "\t"}
        for char in logical
    ):
        return True
    if any(ord(char) < 32 or ord(char) == 127 for char in logical):
        return True
    return any(part in {"", ".", ".."} for part in logical.split("/"))


__all__ = [
    "RELEASE_ARTIFACT_BLOCKLIST",
    "audit_release_artifact_members",
    "build_release_audit_markdown",
    "build_release_manifest",
]
