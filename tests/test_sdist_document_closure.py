from __future__ import annotations

import posixpath
import re
import tarfile
from urllib.parse import unquote, urlsplit

MARKDOWN_LINK_RE = re.compile(
    r"!?\[[^\]]*]\((?P<target><[^>]+>|[^)\s]+)"
)


def _sdist_markdown(path) -> tuple[set[str], dict[str, str]]:
    with tarfile.open(path, "r:gz") as archive:
        members: set[str] = set()
        markdown: dict[str, str] = {}
        for member in archive.getmembers():
            normalized = member.name.replace("\\", "/").strip("/")
            if "/" not in normalized:
                continue
            logical = normalized.split("/", 1)[1]
            members.add(logical)
            if not member.isfile() or not logical.endswith(".md"):
                continue
            extracted = archive.extractfile(member)
            assert extracted is not None
            markdown[logical] = extracted.read().decode("utf-8")
        return members, markdown


def test_sdist_markdown_links_are_closed_over_shipped_files(
    built_release_artifacts,
):
    members, markdown = _sdist_markdown(
        built_release_artifacts["sdist"]
    )
    missing: list[str] = []
    for source_name, text in sorted(markdown.items()):
        for match in MARKDOWN_LINK_RE.finditer(text):
            raw_target = match.group("target").strip("<>")
            parsed = urlsplit(raw_target)
            if parsed.scheme or parsed.netloc or not parsed.path:
                continue
            target = unquote(parsed.path)
            if target.startswith("/"):
                logical_target = posixpath.normpath(target.lstrip("/"))
            else:
                logical_target = posixpath.normpath(
                    posixpath.join(
                        posixpath.dirname(source_name),
                        target,
                    )
                )
            if logical_target == ".." or logical_target.startswith("../"):
                logical_target = f"<outside-repo>/{target}"
            if logical_target not in members:
                line = text.count("\n", 0, match.start()) + 1
                missing.append(
                    f"{source_name}:{line} -> {logical_target}"
                )

    assert missing == []
