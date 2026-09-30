import re
from pathlib import Path
from urllib.parse import unquote, urlsplit

from role_aware_dashboard_toolkit.distribution import build_distribution_reference_markdown
from role_aware_dashboard_toolkit.public_api import build_public_api_reference_markdown
from role_aware_dashboard_toolkit.release_audit import build_release_audit_markdown


REPO_ROOT = Path(__file__).resolve().parents[1]

LIVE_DOCS = frozenset(
    {
        "docs/README.md",
        "docs/api_security.md",
        "docs/caseboard.md",
        "docs/dashboard_tools.md",
        "docs/decision_model.md",
        "docs/development_handoff.md",
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
    }
)

PUBLIC_ROOT_DOCS = frozenset(
    {
        "ARCHITECTURE_SCOPE.md",
        "AGENTS.md",
        "CHANGELOG.md",
        "CODE_OF_CONDUCT.md",
        "CONTRIBUTING.md",
        "README.md",
        "SECURITY.md",
        "examples/README.md",
        "examples/studio_dispatch/README.md",
        "examples/operator_review/README.md",
    }
)

GENERATED_DOCS = {
    "docs/public_api.md": build_public_api_reference_markdown,
    "docs/distribution.md": build_distribution_reference_markdown,
    "docs/release_audit.md": build_release_audit_markdown,
}

MARKDOWN_LINK_RE = re.compile(r"!?\[[^\]]*]\((?P<target><[^>]+>|[^)\s]+)")


def _read(path: str) -> str:
    return (REPO_ROOT / path).read_text(encoding="utf-8")


def _local_link_targets(source_path: str) -> list[tuple[str, int]]:
    source = REPO_ROOT / source_path
    text = source.read_text(encoding="utf-8")
    targets: list[tuple[str, int]] = []
    for match in MARKDOWN_LINK_RE.finditer(text):
        raw_target = match.group("target").strip("<>")
        parsed = urlsplit(raw_target)
        if parsed.scheme or parsed.netloc or not parsed.path:
            continue
        target = unquote(parsed.path)
        resolved = (source.parent / target).resolve()
        try:
            repo_target = resolved.relative_to(REPO_ROOT).as_posix()
        except ValueError:
            repo_target = f"<outside-repo>/{target}"
        line = text.count("\n", 0, match.start()) + 1
        targets.append((repo_target, line))
    return targets


def test_live_document_tree_matches_the_curated_index_boundary():
    actual = frozenset(
        path.relative_to(REPO_ROOT).as_posix()
        for path in (REPO_ROOT / "docs").rglob("*.md")
    )
    assert actual == LIVE_DOCS

    indexed_docs = {
        target
        for target, _line in _local_link_targets("docs/README.md")
        if target.startswith("docs/")
    }
    assert indexed_docs == (
        LIVE_DOCS
        - {"docs/README.md"}
    )

    readme_targets = {target for target, _line in _local_link_targets("README.md")}
    assert "docs/README.md" in readme_targets
    assert "docs/quickstart.md" in readme_targets


def test_release_facing_markdown_links_resolve_within_the_public_tree():
    missing: list[str] = []
    for source_path in sorted(LIVE_DOCS | PUBLIC_ROOT_DOCS):
        for target, line in _local_link_targets(source_path):
            if target.startswith("<outside-repo>/") or not (REPO_ROOT / target).exists():
                missing.append(f"{source_path}:{line} -> {target}")

    assert missing == []


def test_generated_reference_docs_are_exactly_in_sync():
    mismatches = [
        path
        for path, build_markdown in GENERATED_DOCS.items()
        if _read(path) != build_markdown()
    ]
    assert mismatches == []


def test_live_docs_are_valid_utf8_without_common_mojibake():
    bad: list[str] = []
    for path in sorted(LIVE_DOCS | PUBLIC_ROOT_DOCS):
        text = _read(path)
        if "\ufffd" in text or "â€”" in text or "â€œ" in text or "â€\x9d" in text:
            bad.append(path)
    assert bad == []
