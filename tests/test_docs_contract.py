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
        "docs/distribution.md",
        "docs/first_dashboard.md",
        "docs/governance.md",
        "docs/migration_0_2.md",
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
        "docs/record_workflows.md",
        "docs/replay.md",
        "docs/run_model.md",
        "docs/shared_store_patterns.md",
        "docs/security_lessons.md",
        "docs/team_ops.md",
        "docs/telemetry_contract.md",
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
        "examples/host_integration/README.md",
        "examples/record_workflows/README.md",
        "examples/landscaping/README.md",
        "examples/business_dashboard/README.md",
        "examples/business_dashboard/HOSTING.md",
        "examples/landscaping/HOSTING.md",
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


def test_generated_install_targets_explain_source_release_installation():
    for render in (build_distribution_reference_markdown, build_release_audit_markdown):
        text = render()
        assert "Install targets below identify package requirement metadata" in text
        assert "GitHub-source release" in text
        assert "no package-index release is assumed" in text
        assert 'python -m pip install ".[api]"' in text
        assert "absolute source path or reviewed local wheel filename" in text
        assert "Omit the extra to install the core alone" in text
        assert "- Install target: `role-aware-dashboard-toolkit[api]`" in text


def test_live_docs_are_valid_utf8_without_common_mojibake():
    bad: list[str] = []
    for path in sorted(LIVE_DOCS | PUBLIC_ROOT_DOCS):
        text = _read(path)
        if "\ufffd" in text or "â€”" in text or "â€œ" in text or "â€\x9d" in text:
            bad.append(path)
    assert bad == []


_FENCE_RE = re.compile(r"^```[^\n]*\n(.*?)^```", re.MULTILINE | re.DOTALL)
_AUTH_CHOICE_RE = re.compile(r"\b(?:auth_mode|access|auth_hook)\s*=")


def _dashboard_config_calls(text: str) -> list[tuple[int, str]]:
    calls: list[tuple[int, str]] = []
    for match in re.finditer(r"DashboardConfig\(", text):
        end, depth = match.end(), 1
        while end < len(text) and depth:
            depth += {"(": 1, ")": -1}.get(text[end], 0)
            end += 1
        calls.append((text.count("\n", 0, match.start()) + 1, text[match.start():end]))
    return calls


def test_documented_dashboard_configs_choose_an_auth_mode():
    """A DashboardConfig with neither access nor auth_hook raises unless auth_mode is given.

    Copying an example from the docs, guides, starters or the generated API
    reference must not hit that error.
    """
    package = REPO_ROOT / "role_aware_dashboard_toolkit"
    markdown = sorted(
        {REPO_ROOT / path for path in LIVE_DOCS | PUBLIC_ROOT_DOCS}
        | set((package / "resources").rglob("*.md"))
        | set((REPO_ROOT / "examples").rglob("*.md"))
    )
    python = sorted(
        set((package / "resources").rglob("*.py"))
        | set((REPO_ROOT / "examples").rglob("*.py"))
        | set((package / "public_api_parts").rglob("*.py"))
    )
    sources = [(path, block) for path in markdown
               for block in _FENCE_RE.findall(path.read_text(encoding="utf-8"))]
    sources += [(path, path.read_text(encoding="utf-8")) for path in python]
    missing = [
        f"{path.relative_to(REPO_ROOT).as_posix()}: {' '.join(call.split())[:80]}"
        for path, text in sources
        for _line, call in _dashboard_config_calls(text)
        if "**" not in call and not _AUTH_CHOICE_RE.search(call)
    ]
    assert len(sources) > 50
    assert missing == []
