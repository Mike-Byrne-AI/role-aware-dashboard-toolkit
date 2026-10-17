"""Keep the demo's copied security-sensitive action helper synchronized."""

from __future__ import annotations

from pathlib import Path, PurePosixPath
import tarfile


REPO_ROOT = Path(__file__).resolve().parents[1]
CANONICAL = "examples/record_workflows/actions.py"
DEMO_COPY = "examples/landscaping/landscape/action_workflow.py"
SYNC_INSTRUCTION = (
    f"The landscaping action helper must match {CANONICAL} byte for byte. "
    f"Make shared fixes in that canonical helper, copy it to {DEMO_COPY}, "
    "then run the record workflow tests and the landscaping security suite. "
    "Keep application-specific behavior in the demo's callers."
)


def test_landscaping_action_helper_matches_canonical_source():
    assert (REPO_ROOT / DEMO_COPY).read_bytes() == (
        REPO_ROOT / CANONICAL
    ).read_bytes(), SYNC_INSTRUCTION


def test_sdist_ships_the_same_canonical_and_landscaping_action_helper(built_release_artifacts):
    payloads = {}
    with tarfile.open(built_release_artifacts["sdist"], "r:gz") as archive:
        for path in (CANONICAL, DEMO_COPY):
            matches = [
                member
                for member in archive.getmembers()
                if PurePosixPath(*PurePosixPath(member.name).parts[1:]).as_posix() == path
            ]
            assert len(matches) == 1 and matches[0].isfile(), (
                f"The source distribution must ship exactly one regular {path}."
            )
            contents = archive.extractfile(matches[0])
            assert contents is not None
            with contents:
                payloads[path] = contents.read()
    assert payloads[DEMO_COPY] == payloads[CANONICAL], SYNC_INSTRUCTION
    assert payloads[CANONICAL] == (REPO_ROOT / CANONICAL).read_bytes(), (
        "The source distribution contains a stale canonical action helper; "
        "rebuild both release artifacts from the current source."
    )
