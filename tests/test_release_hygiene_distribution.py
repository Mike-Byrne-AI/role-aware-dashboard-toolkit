from __future__ import annotations

import importlib.util
import os
import py_compile
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

from role_aware_dashboard_toolkit.release_audit import audit_release_artifact_members
from tests.release_hygiene_helpers import REPO_ROOT, load_pyproject


BLOCKED_PUBLIC_PREFIXES = (
    "role_aware_dashboard_toolkit/_archive_review/",
    "role_aware_dashboard_toolkit/integrations/",
    "portable/",
    "snapshot_manifests/",
    "examples/semantic_",
    "schemas/action_",
    "schemas/builder_",
    "schemas/semantic_",
)
BLOCKED_PUBLIC_DOC_FRAGMENTS = (
    "docs/codex_builder",
    "docs/federation",
    "docs/harness",
    "docs/pack_",
    "docs/portable_",
    "docs/repoos",
    "docs/semantic_",
)


def _archive_members(path: Path) -> list[str]:
    if path.suffix == ".whl":
        with zipfile.ZipFile(path) as archive:
            return archive.namelist()
    with tarfile.open(path, "r:gz") as archive:
        return archive.getnames()


def _archive_payloads(path: Path) -> list[tuple[str, bytes]]:
    if path.suffix == ".whl":
        with zipfile.ZipFile(path) as archive:
            return [
                (name, archive.read(name))
                for name in archive.namelist()
                if not name.endswith("/")
            ]
    with tarfile.open(path, "r:gz") as archive:
        payloads: list[tuple[str, bytes]] = []
        for member in archive.getmembers():
            if not member.isfile():
                continue
            extracted = archive.extractfile(member)
            assert extracted is not None
            payloads.append((member.name, extracted.read()))
        return payloads


def _logical_members(path: Path) -> set[str]:
    members = _archive_members(path)
    if path.suffix == ".whl":
        return {
            member.replace("\\", "/").strip("/")
            for member in members
        }
    return {
        normalized.split("/", 1)[1]
        for member in members
        if "/" in (normalized := member.replace("\\", "/").strip("/"))
    }


def test_release_artifact_fixture_surfaces_isolated_build_failures_as_diagnostic(
    built_release_artifacts,
):
    assert built_release_artifacts["build_mode"] in {
        "isolated",
        "no-isolation-diagnostic",
    }
    if built_release_artifacts["build_mode"] == "no-isolation-diagnostic":
        error_text = built_release_artifacts["isolated_build_error"]
        assert error_text.strip()
        assert "Creating isolated environment" in error_text


def test_wheel_and_sdist_contain_only_the_public_oss_boundary(
    built_release_artifacts,
):
    for artifact_key in ("wheel", "sdist"):
        artifact = built_release_artifacts[artifact_key]
        raw_members = _archive_members(artifact)
        members = _logical_members(artifact)

        audit = audit_release_artifact_members(raw_members)
        assert audit["ok"] is True, audit
        assert not any(
            member.startswith(prefix)
            for prefix in BLOCKED_PUBLIC_PREFIXES
            for member in members
        )
        assert not any(
            fragment in member
            for fragment in BLOCKED_PUBLIC_DOC_FRAGMENTS
            for member in members
        )
        assert not any(member.endswith(".py.txt") for member in members)

    wheel_members = _logical_members(built_release_artifacts["wheel"])
    assert "role_aware_dashboard_toolkit/py.typed" in wheel_members
    assert "role_aware_dashboard_toolkit/_record_utils.py" in wheel_members

    sdist_members = _logical_members(built_release_artifacts["sdist"])
    assert "examples/dashboard_admin_controls_app.py" in sdist_members
    assert "examples/plugin_template.py" in sdist_members
    assert "docs/quickstart.md" in sdist_members
    assert "schemas/run.schema.json" in sdist_members


def test_release_artifacts_do_not_embed_the_build_checkout_path(
    built_release_artifacts,
):
    checkout_markers = {
        str(REPO_ROOT.resolve()).lower().encode(),
        REPO_ROOT.resolve().as_posix().lower().encode(),
        str(REPO_ROOT.resolve())
        .replace("\\", "\\\\")
        .lower()
        .encode(),
    }
    leaked: list[str] = []

    for artifact_key in ("wheel", "sdist"):
        for member, payload in _archive_payloads(
            built_release_artifacts[artifact_key]
        ):
            lowered = payload.lower()
            if any(marker in lowered for marker in checkout_markers):
                leaked.append(f"{artifact_key}:{member}")

    assert leaked == []


def test_release_artifact_audit_rejects_archive_and_removed_lanes():
    audit = audit_release_artifact_members(
        [
            "role_aware_dashboard_toolkit-0.1.0/role_aware_dashboard_toolkit/__init__.py",
            "role_aware_dashboard_toolkit-0.1.0/role_aware_dashboard_toolkit/_archive_review/README.md",
            "role_aware_dashboard_toolkit-0.1.0/role_aware_dashboard_toolkit/integrations/product.py",
            "role_aware_dashboard_toolkit-0.1.0/portable/bundle.json",
            "role_aware_dashboard_toolkit-0.1.0/snapshot_manifests/release.json",
            "role_aware_dashboard_toolkit-0.1.0/tests/test_private.py",
            "role_aware_dashboard_toolkit-0.1.0/role_aware_dashboard_toolkit/action_receipts.py",
            "role_aware_dashboard_toolkit-0.1.0/role_aware_dashboard_toolkit/federation.py",
            "role_aware_dashboard_toolkit-0.1.0/role_aware_dashboard_toolkit/semantic_store.py",
            "role_aware_dashboard_toolkit-0.1.0/role_aware_dashboard_toolkit/review_cockpit.py",
            "role_aware_dashboard_toolkit-0.1.0/role_aware_dashboard_toolkit/customer_adapter.py",
            "role_aware_dashboard_toolkit-0.1.0/docs/private_launch.md",
            "role_aware_dashboard_toolkit-9.9.9/role_aware_dashboard_toolkit/__init__.py",
        ]
    )

    assert audit["ok"] is False
    assert set(audit["blocked_members"]) == {
        "role_aware_dashboard_toolkit-0.1.0/role_aware_dashboard_toolkit/_archive_review/README.md",
        "role_aware_dashboard_toolkit-0.1.0/role_aware_dashboard_toolkit/integrations/product.py",
        "role_aware_dashboard_toolkit-0.1.0/portable/bundle.json",
        "role_aware_dashboard_toolkit-0.1.0/snapshot_manifests/release.json",
        "role_aware_dashboard_toolkit-0.1.0/tests/test_private.py",
        "role_aware_dashboard_toolkit-0.1.0/role_aware_dashboard_toolkit/action_receipts.py",
        "role_aware_dashboard_toolkit-0.1.0/role_aware_dashboard_toolkit/federation.py",
        "role_aware_dashboard_toolkit-0.1.0/role_aware_dashboard_toolkit/semantic_store.py",
        "role_aware_dashboard_toolkit-0.1.0/role_aware_dashboard_toolkit/review_cockpit.py",
        "role_aware_dashboard_toolkit-0.1.0/role_aware_dashboard_toolkit/customer_adapter.py",
        "role_aware_dashboard_toolkit-0.1.0/docs/private_launch.md",
        "role_aware_dashboard_toolkit-9.9.9/role_aware_dashboard_toolkit/__init__.py",
    }
    assert set(audit["unexpected_members"]) == {
        "role_aware_dashboard_toolkit-0.1.0/role_aware_dashboard_toolkit/action_receipts.py",
        "role_aware_dashboard_toolkit-0.1.0/role_aware_dashboard_toolkit/federation.py",
        "role_aware_dashboard_toolkit-0.1.0/role_aware_dashboard_toolkit/semantic_store.py",
        "role_aware_dashboard_toolkit-0.1.0/role_aware_dashboard_toolkit/review_cockpit.py",
        "role_aware_dashboard_toolkit-0.1.0/role_aware_dashboard_toolkit/customer_adapter.py",
        "role_aware_dashboard_toolkit-0.1.0/docs/private_launch.md",
        "role_aware_dashboard_toolkit-9.9.9/role_aware_dashboard_toolkit/__init__.py",
    }


def test_release_artifact_audit_rejects_unsafe_archive_member_names():
    audit = audit_release_artifact_members(
        [
            "role_aware_dashboard_toolkit-0.1.0/role_aware_dashboard_toolkit/__init__.py",
            "role_aware_dashboard_toolkit-0.1.0/../evil.py",
            "role_aware_dashboard_toolkit-0.1.0//double/slash.py",
            "/absolute/path.py",
            "C:/outside/path.py",
            "role_aware_dashboard_toolkit-0.1.0/role_aware_dashboard_toolkit/\u0000nul.py",
        ]
    )

    assert audit["ok"] is False
    assert set(audit["blocked_members"]) == {
        "role_aware_dashboard_toolkit-0.1.0/../evil.py",
        "role_aware_dashboard_toolkit-0.1.0//double/slash.py",
        "/absolute/path.py",
        "C:/outside/path.py",
        "role_aware_dashboard_toolkit-0.1.0/role_aware_dashboard_toolkit/\u0000nul.py",
    }


def test_wheel_installed_core_imports_without_optional_dependencies(
    tmp_path,
    built_release_artifacts,
):
    target = tmp_path / "wheel_site"
    install_result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "install",
            "--no-deps",
            "--target",
            str(target),
            str(built_release_artifacts["wheel"]),
        ],
        cwd=str(tmp_path),
        text=True,
        capture_output=True,
        check=False,
    )
    assert install_result.returncode == 0, install_result.stderr

    env = os.environ.copy()
    env["PYTHONPATH"] = str(target)
    env["PYTHONNOUSERSITE"] = "1"
    script = """
import importlib.util
import pathlib
import sys

import role_aware_dashboard_toolkit as radt

assert "wheel_site" in str(pathlib.Path(radt.__file__).resolve())
assert importlib.util.find_spec("streamlit") is None
assert importlib.util.find_spec("pandas") is None
assert importlib.util.find_spec("fastapi") is None
assert "streamlit" not in sys.modules
config = radt.DashboardConfig(icon="Core", layout="columns", run_store=None)
run = radt.build_run({"temperature": 0.2}, actor="wheel-smoke")
packet = radt.build_run_packet(run)
assert config.icon == "Core"
assert packet["packet_type"] == "run"
assert packet["payload"]["run_id"] == run["run_id"]
print("ok")
"""
    result = subprocess.run(
        [sys.executable, "-S", "-c", script],
        cwd=str(tmp_path),
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "ok"


def test_sdist_shipped_examples_compile_from_extracted_artifact(
    tmp_path,
    built_release_artifacts,
):
    extract_dir = tmp_path / "sdist_extract"
    extract_dir.mkdir()

    with tarfile.open(
        built_release_artifacts["sdist"],
        "r:gz",
    ) as archive:
        archive.extractall(path=extract_dir)

    roots = [item for item in extract_dir.iterdir() if item.is_dir()]
    assert len(roots) == 1
    sdist_root = roots[0]
    scripts = [
        sdist_root / "examples" / "dashboard_admin_controls_app.py",
        sdist_root / "examples" / "plugin_template.py",
    ]

    for script in scripts:
        assert script.is_file()
        py_compile.compile(str(script), doraise=True)
    assert not (
        sdist_root
        / "examples"
        / "semantic_snapshot_compare_minimal.py"
    ).exists()


def test_sdist_configuration_is_an_explicit_public_allowlist():
    pyproject = load_pyproject()
    target = pyproject["tool"]["hatch"]["build"]["targets"]["sdist"]
    include = set(target["include"])
    exclude = set(target["exclude"])

    assert "/role_aware_dashboard_toolkit" in include
    assert "/docs" not in include
    assert "/schemas" not in include
    assert "/portable" not in include
    assert "/snapshot_manifests" not in include
    assert "/role_aware_dashboard_toolkit/_archive_review" in exclude
    assert "/role_aware_dashboard_toolkit/_archive_review/**" in exclude
    assert {
        path
        for path in include
        if path.startswith("/examples/") and path.endswith(".py")
    } == {
        "/examples/core_library.py",
        "/examples/dashboard_admin_controls_app.py",
        "/examples/plugin_template.py",
    }
    assert importlib.util.find_spec("role_aware_dashboard_toolkit") is not None
