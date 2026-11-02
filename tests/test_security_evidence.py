"""Imported receipts are bounded, source-bound and safe to display."""

from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "examples/business_dashboard"))
from business import evidence  # noqa: E402


@pytest.fixture
def source(tmp_path):
    root = tmp_path / "source"
    root.mkdir()
    (root / "pyproject.toml").write_text("# disposable source\n")
    return root


def _completed(source):
    receipt = evidence.new_receipt("scenarios", evidence.CHECKS, root=source)
    for row in receipt["checks"]:
        row["status"] = "passed"
    return evidence.finish_receipt(receipt, root=source)


def _resign(value):
    value.pop("sha256", None)
    value["sha256"] = hashlib.sha256(evidence._canonical(value)).hexdigest()
    return value


def test_source_bytes_detect_dirty_changes_without_publishing_local_paths(source):
    first = evidence.source_fingerprint(source)
    (source / "pyproject.toml").write_text("# changed uncommitted source\n")
    second = evidence.source_fingerprint(source)
    assert first["sha256"] != second["sha256"]
    assert first["files"] == second["files"] == 1
    assert str(source) not in json.dumps(second)
    assert "pyproject.toml" not in json.dumps(second)


def test_source_fingerprint_includes_password_corpus_and_acceptance_tests(source):
    corpus = source / "examples/business_dashboard/business/password_data/common-passwords.txt.gz"
    corpus.parent.mkdir(parents=True)
    corpus.write_bytes(b"synthetic corpus bytes")
    acceptance = source / "tests/test_business_security.py"
    acceptance.parent.mkdir()
    acceptance.write_text("# synthetic acceptance\n")
    before = evidence.source_fingerprint(source)["sha256"]
    corpus.write_bytes(b"changed corpus")
    after_corpus = evidence.source_fingerprint(source)["sha256"]
    acceptance.write_text("# changed acceptance\n")
    assert len({before, after_corpus, evidence.source_fingerprint(source)["sha256"]}) == 3


def test_completed_receipt_round_trips_and_is_detached(source, tmp_path):
    receipt = _completed(source)
    path = tmp_path / "receipt.json"
    path.write_text(json.dumps(receipt))
    assert evidence.load_receipt(path) == receipt
    public = evidence.public_receipt(receipt)
    public["checks"][0]["status"] = "failed"
    assert receipt["checks"][0]["status"] == "passed"


def test_receipt_writer_is_private_and_never_overwrites_previous_failure(source, tmp_path):
    receipt = _completed(source)
    path = tmp_path / "receipt.json"
    evidence.write_receipt(path, receipt)
    assert evidence.load_receipt(path) == receipt
    if os.name == "posix":
        assert path.stat().st_mode & 0o777 == 0o600
    before = path.read_bytes()
    with pytest.raises(FileExistsError):
        evidence.write_receipt(path, receipt)
    assert path.read_bytes() == before


@pytest.mark.parametrize("mutation", [
    lambda value: value.update(password="secret-canary"),
    lambda value: value["checks"][0].update(title="secret-canary"),
    lambda value: value["checks"][0].update(status="not_run"),
    lambda value: value["checks"].pop(),
    lambda value: value["checks"].append(deepcopy(value["checks"][0])),
    lambda value: value["source"].update(sha256="not-a-hash"),
    lambda value: value["source"].update(files=True),
    lambda value: value.update(source_unchanged=False),
    lambda value: value.update(scope="hosted"),
    lambda value: value.update(finished_at="2001-01-01T00:00:00Z"),
    lambda value: value["runtime"].update(platform="private-hostname"),
    lambda value: value["runtime"]["dependencies"].update(secret="canary"),
    lambda value: value.update(error={"type": "secret-canary", "code": "execution_error"}),
    lambda value: value["source"].update(path="private-path"),
])
def test_even_rechecksummed_invalid_or_secret_fields_are_refused(source, mutation):
    value = _completed(source)
    mutation(value)
    with pytest.raises(ValueError, match="Security receipt is invalid"):
        evidence.public_receipt(_resign(value))


def test_receipt_checksum_detects_mutation(source):
    value = _completed(source)
    value["source"]["sha256"] = "0" * 64
    with pytest.raises(ValueError):
        evidence.validate_receipt(value)


def test_source_change_during_run_preserves_passed_checks_but_fails_receipt(source):
    value = evidence.new_receipt("scenarios", evidence.CHECKS, root=source)
    for row in value["checks"]:
        row["status"] = "passed"
    (source / "pyproject.toml").write_text("# changed during acceptance\n")
    result = evidence.finish_receipt(value, root=source)
    assert result["status"] == "failed"
    assert result["source_unchanged"] is False
    assert result["error"]["code"] == "source_changed"
    assert all(row["status"] == "passed" for row in result["checks"])


def test_failure_preserves_failed_and_unrun_checks_without_exception_secrets(source):
    value = evidence.new_receipt("scenarios", evidence.CHECKS, root=source)
    value["checks"][0]["status"] = "failed"
    result = evidence.finish_receipt(value, root=source, error=RuntimeError("secret-canary C:\\private"))
    assert result["status"] == "failed"
    assert result["checks"][1]["status"] == "not_run"
    assert result["error"] == {"type": "ExecutionError", "code": "execution_error"}
    assert "secret-canary" not in json.dumps(result)
    assert "C:\\private" not in json.dumps(result)


def test_browser_receipt_requires_observed_browser_and_records_workflow_completion(source):
    value = evidence.new_receipt("passkeys", (), root=source)
    result = evidence.finish_browser_receipt(value, 3, completed=True, root=source,
                                             browser={"name": "chromium", "version": "140.0.0.0"})
    assert result["scope"] == "local_browser" and result["mode"] == "passkeys"
    assert result["runtime"]["browser"]["version"] == "140.0.0.0"
    assert len(result["checks"]) == 4
    assert sum(row["id"].startswith("browser_step_") for row in result["checks"]) == 3
    assert result["checks"][-1] == {"id": "browser_workflow_complete", "title": "Browser workflow completed", "status": "passed"}
    result["runtime"]["browser"] = None
    with pytest.raises(ValueError):
        evidence.validate_receipt(_resign(result))
    failed = evidence.finish_browser_receipt(evidence.new_receipt("security", (), root=source),
                                             2, completed=False, root=source, error=RuntimeError("secret-canary"))
    assert [row["status"] for row in failed["checks"]] == ["passed", "passed", "failed"]
    assert failed["checks"][-1]["id"] == "browser_workflow_complete"
    assert "secret-canary" not in json.dumps(failed)


@pytest.mark.parametrize("content", [b"{" * 2000, b" " * (evidence.MAX_BYTES + 1), b'{"x":1,"x":2}', b"\xff"],
                         ids=["nested", "oversized", "duplicate", "invalid-unicode"])
def test_loader_refuses_unbounded_malformed_or_duplicate_input(tmp_path, content):
    path = tmp_path / "input.json"
    path.write_bytes(content)
    with pytest.raises(ValueError, match="unavailable or invalid"):
        evidence.load_receipt(path)
