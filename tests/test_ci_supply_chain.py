from __future__ import annotations

import re
from collections import Counter
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "ci.yml"
ACTION_PINS = {
    "actions/checkout": (
        "9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0",
        "v7.0.0",
        5,
    ),
    "actions/setup-python": (
        "5fda3b95a4ea91299a34e894583c3862153e4b97",
        "v7.0.0",
        5,
    ),
    "actions/upload-artifact": (
        "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
        "v7.0.1",
        3,
    ),
    "actions/download-artifact": (
        "3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
        "v8.0.1",
        1,
    ),
}


def test_ci_actions_are_pinned_to_reviewed_full_revisions():
    workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
    action_uses = Counter(
        re.findall(
            (
                r"^\s*-?\s*uses:\s+(actions/[^@\s]+)"
                r"@([0-9a-f]{40})\s+#\s+(v\d+\.\d+\.\d+)\s*$"
            ),
            workflow,
            flags=re.MULTILINE,
        )
    )
    candidate_uses = [
        line
        for line in workflow.splitlines()
        if re.search(r"\buses\b", line.split("#", 1)[0])
    ]
    all_uses = Counter(
        re.findall(
            r"^\s*-?\s*uses:\s+([^\s#]+)",
            workflow,
            flags=re.MULTILINE,
        )
    )
    expected_uses = Counter(
        {
            (action, sha, version): count
            for action, (sha, version, count) in ACTION_PINS.items()
        }
    )
    expected_refs = Counter(
        {
            f"{action}@{sha}": count
            for action, (sha, _version, count) in ACTION_PINS.items()
        }
    )

    assert action_uses == expected_uses
    assert len(candidate_uses) == sum(expected_uses.values())
    assert all_uses == expected_refs
    assert not re.search(r"uses\s*:\s+actions/[^@\s]+@v\d", workflow)
    assert "digest-mismatch: error" in workflow


def test_ci_checkouts_do_not_persist_credentials():
    workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
    checkout_sha, checkout_version, checkout_count = ACTION_PINS[
        "actions/checkout"
    ]
    checkout_line = (
        f"- uses: actions/checkout@{checkout_sha} # {checkout_version}"
    )
    pattern = (
        re.escape(checkout_line)
        + r"\n\s+with:\n\s+persist-credentials: false"
    )

    assert len(re.findall(pattern, workflow)) == checkout_count


def test_ci_smokes_each_supported_optional_extra_without_product_adapters():
    workflow = WORKFLOW_PATH.read_text(encoding="utf-8")

    for extra_name in ("workbench", "api", "pandas", "full"):
        assert (
            f'pip install "${{wheel}}[{extra_name}]"'
            in workflow
        )
        assert f".wheel-{extra_name}-smoke" in workflow

    lowered = workflow.lower()
    for forbidden in (
        "pack-builder",
        "pack-harness",
        "pack-repoos",
        "pack-sdk",
        "codex_builder",
        "repoos",
        "dashboard_stub",
        "standalone_demo",
        "semantic_snapshot",
    ):
        assert forbidden not in lowered


def test_all_hosted_ci_jobs_remain_disabled_until_owner_authorization():
    workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
    job_blocks = re.findall(r"^  ([A-Za-z0-9_-]+):\n(.*?)(?=^  [A-Za-z0-9_-]+:|\Z)", workflow.split("jobs:\n", 1)[1], flags=re.MULTILINE | re.DOTALL)
    assert len(job_blocks) == 5
    for name, block in job_blocks:
        guards = re.findall(r"^    if:\s*(.+)$", block, flags=re.MULTILINE)
        assert guards == ["${{ false }}"], name
