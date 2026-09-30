from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

VALID_ARTIFACT_FAMILIES: tuple[str, ...] = ("core", "ui", "extension", "full")
ROLE_AWARE_DASHBOARD_TOOLKIT_DISTRIBUTION_STRATEGY = "single-package-optional-extras"


@dataclass(frozen=True)
class DistributionArtifact:
    artifact_id: str
    display_name: str
    family: str
    package_name: str = "role-aware-dashboard-toolkit"
    extra_names: tuple[str, ...] = ()
    docs_paths: tuple[str, ...] = ()
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["extra_names"] = list(self.extra_names)
        payload["docs_paths"] = list(self.docs_paths)
        payload["install_target"] = build_install_target(
            self.package_name,
            self.extra_names,
        )
        return payload


def build_install_target(
    package_name: str,
    extra_names: tuple[str, ...] | list[str] = (),
) -> str:
    package = str(package_name or "role-aware-dashboard-toolkit").strip() or "role-aware-dashboard-toolkit"
    extras = tuple(
        str(item).strip()
        for item in extra_names
        if str(item).strip()
    )
    if not extras:
        return package
    return f"{package}[{','.join(extras)}]"


_ARTIFACTS: dict[str, DistributionArtifact] = {
    "core": DistributionArtifact(
        artifact_id="core",
        display_name="Role-Aware Dashboard Toolkit core",
        family="core",
        docs_paths=("README.md", "docs/public_api.md"),
        description="Dependency-free dashboard controls, profiles, audit, plugins, and records.",
    ),
    "workbench": DistributionArtifact(
        artifact_id="workbench",
        display_name="Role-Aware Dashboard Toolkit Streamlit UI",
        family="ui",
        extra_names=("workbench",),
        docs_paths=("README.md", "docs/dashboard_tools.md"),
        description="Optional Streamlit dashboard rendering.",
    ),
    "api": DistributionArtifact(
        artifact_id="api",
        display_name="Role-Aware Dashboard Toolkit API",
        family="extension",
        extra_names=("api",),
        docs_paths=("docs/api_security.md",),
        description="Optional FastAPI control, profile, role, and audit routes.",
    ),
    "auth": DistributionArtifact(
        artifact_id="auth",
        display_name="Role-Aware Dashboard Toolkit authenticated Streamlit UI",
        family="ui",
        extra_names=("auth",),
        docs_paths=("role_aware_dashboard_toolkit/resources/guides/authentication.md",),
        description="Optional OIDC login with server-owned role grants and shared freeze.",
    ),
    "pandas": DistributionArtifact(
        artifact_id="pandas",
        display_name="Role-Aware Dashboard Toolkit tabular views",
        family="extension",
        extra_names=("pandas",),
        docs_paths=("docs/dashboard_tools.md",),
        description="Optional pandas-backed audit and observability tables.",
    ),
    "full": DistributionArtifact(
        artifact_id="full",
        display_name="Role-Aware Dashboard Toolkit full",
        family="full",
        extra_names=("full",),
        docs_paths=("README.md", "docs/distribution.md"),
        description="All supported public Role-Aware Dashboard Toolkit runtime dependencies.",
    ),
}


def get_distribution_artifact(artifact_id: str) -> dict[str, Any]:
    return _ARTIFACTS[str(artifact_id or "")].to_dict()


def list_distribution_artifacts() -> list[dict[str, Any]]:
    return [
        artifact.to_dict()
        for _, artifact in sorted(_ARTIFACTS.items())
    ]


def distribution_artifact_map() -> dict[str, dict[str, Any]]:
    return {
        artifact_id: artifact.to_dict()
        for artifact_id, artifact in sorted(_ARTIFACTS.items())
    }


def build_distribution_reference_markdown() -> str:
    lines = [
        "# Role-Aware Dashboard Toolkit distribution reference",
        "",
        "Role-Aware Dashboard Toolkit defines one Python distribution with a dependency-free core and explicit optional extras.",
        "",
    ]
    for artifact in list_distribution_artifacts():
        lines.extend(
            [
                f"## {artifact['display_name']}",
                "",
                f"- Artifact id: `{artifact['artifact_id']}`",
                f"- Family: `{artifact['family']}`",
                f"- Install target: `{artifact['install_target']}`",
                (
                    "- Docs: "
                    + (
                        ", ".join(f"`{item}`" for item in artifact["docs_paths"])
                        if artifact["docs_paths"]
                        else "none"
                    )
                ),
                f"- Description: {artifact['description']}",
                "",
            ]
        )
    return "\n".join(lines)


def build_distribution_strategy_markdown() -> str:
    return "\n".join(
        [
            "# Role-Aware Dashboard Toolkit distribution strategy",
            "",
            f"- Strategy id: `{ROLE_AWARE_DASHBOARD_TOOLKIT_DISTRIBUTION_STRATEGY}`",
            "- `role-aware-dashboard-toolkit` is the single Python distribution; package-index publication is a separate release decision.",
            "- The core has no required third-party dependencies.",
            "- `workbench`, `api`, and `pandas` add isolated optional capabilities.",
            "- `full` installs every supported public runtime dependency.",
            "- Product-specific adapters and application integrations are not part of this distribution.",
            "",
        ]
    )


def build_release_gate_reference_markdown() -> str:
    lines = [
        "# Role-Aware Dashboard Toolkit artifact release gates",
        "",
        f"- Distribution strategy: `{ROLE_AWARE_DASHBOARD_TOOLKIT_DISTRIBUTION_STRATEGY}`",
        "- core imports without Streamlit, pandas, FastAPI, or product adapters",
        "- each optional extra is installed and smoke-tested independently",
        "- wheels and source distributions exclude tests, caches, and private maintenance data",
        "- built artifacts pass Twine validation and isolated-install smoke tests",
        "",
        "## Current artifacts",
        "",
    ]
    for artifact in list_distribution_artifacts():
        lines.append(f"- `{artifact['artifact_id']}` -> `{artifact['install_target']}`")
    lines.append("")
    return "\n".join(lines)


__all__ = [
    "ROLE_AWARE_DASHBOARD_TOOLKIT_DISTRIBUTION_STRATEGY",
    "VALID_ARTIFACT_FAMILIES",
    "DistributionArtifact",
    "build_distribution_reference_markdown",
    "build_distribution_strategy_markdown",
    "build_install_target",
    "build_release_gate_reference_markdown",
    "distribution_artifact_map",
    "get_distribution_artifact",
    "list_distribution_artifacts",
]
