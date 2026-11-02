"""Public evidence cannot execute scenarios, disclose private state or hide staleness."""

from copy import deepcopy
import json
from pathlib import Path
import tempfile

import pytest

from tests.test_business_dashboard import business as business, business_seed as business_seed
from business.app import create_app
from business import evidence, security_lab
from business.db import create_private_file
from business.secret_store import default_key_path


@pytest.fixture
def receipt(monkeypatch):
    with tempfile.TemporaryDirectory(prefix="radt-lab-receipt-") as temporary:
        root = Path(temporary)
        (root / "pyproject.toml").write_text("# synthetic receipt validation fixture\n")
        value = evidence.new_receipt("scenarios", evidence.CHECKS, root=root)
        for check in value["checks"]:
            check["status"] = "passed"
        value = evidence.finish_receipt(value, root=root)
        path = root / "receipt.json"
        create_private_file(path, json.dumps(value).encode())
        monkeypatch.setenv("BUSINESS_SECURITY_EVIDENCE_FILE", str(path))
        monkeypatch.setattr(security_lab, "source_fingerprint", lambda: deepcopy(value["source"]))
        yield path, value


def client(business):
    return business.client(create_app(business.directory, mfa_key_file=default_key_path(business.directory)))


def test_public_lab_has_no_unearned_pass_and_preserves_business_state(business, monkeypatch):
    monkeypatch.delenv("BUSINESS_SECURITY_EVIDENCE_FILE", raising=False)
    with business.db() as connection:
        before = [tuple(row) for row in connection.execute("SELECT * FROM messages")]
    viewer = client(business)
    response = viewer.get("/api/security-lab")
    assert response.status_code == 200
    data = response.json()
    assert data["evidence"]["status"] == "not_run"
    assert data["evidence"]["receipt"] is None
    assert data["hosted_acceptance"]["status"] == "not_verified_here"
    assert len(data["scenarios"]) == 3
    assert {key for scene in data["scenarios"] for key in scene["checks"]} == set(evidence.CHECKS)
    assert "local" in data["evidence"]["message"].lower() or "reviewed" in data["evidence"]["message"]
    assert "events" not in data and "users" not in data
    assert viewer.get("/security-lab").status_code == 200
    assert viewer.get("/static/security-lab.js").status_code == 200
    assert viewer.get("/static/security-lab.css").status_code == 200
    assert viewer.post("/api/security-lab", json={}, headers={"Origin": "http://127.0.0.1:8091"}).status_code == 405
    with business.db() as connection:
        assert [tuple(row) for row in connection.execute("SELECT * FROM messages")] == before


def test_receipt_public_projection_has_exact_safe_schema_and_explicit_scope(business, receipt):
    path, value = receipt
    response = client(business).get("/api/security-lab")
    assert response.status_code == 200
    data = response.json()
    assert data["evidence"]["status"] == "passed"
    assert data["evidence"]["source_matches"] is True
    assert data["evidence"]["receipt"] == value
    assert "Operator-supplied" in data["evidence"]["message"]
    assert str(path) not in response.text
    assert data["hosted_acceptance"]["status"] == "not_verified_here"


def test_changed_source_marks_even_passing_receipt_stale(business, receipt, monkeypatch):
    _path, value = receipt
    current = {**value["source"], "sha256": "a" * 64}
    monkeypatch.setattr(security_lab, "source_fingerprint", lambda: current)
    data = client(business).get("/api/security-lab").json()
    assert data["evidence"]["status"] == "stale"
    assert data["evidence"]["source_matches"] is False
    assert data["evidence"]["receipt"]["status"] == "passed"


@pytest.mark.parametrize("invalid", [b'{"password":"credential-canary"}', b'not-json', b' ' * (evidence.MAX_BYTES + 1)], ids=["unknown-field", "malformed", "oversized"])
def test_invalid_or_secret_receipt_never_echoes_data(business, receipt, invalid):
    path, _value = receipt
    path.write_bytes(invalid)
    response = client(business).get("/api/security-lab")
    assert response.status_code == 200
    assert response.json()["evidence"]["status"] == "unavailable"
    assert response.json()["evidence"]["receipt"] is None
    assert "credential-canary" not in response.text and str(path) not in response.text


def test_failed_receipt_preserves_failure_and_not_run_checks(business, receipt):
    path, value = receipt
    failed = evidence.new_receipt("scenarios", evidence.CHECKS, root=path.parent)
    failed["checks"][0]["status"] = "failed"
    failed = evidence.finish_receipt(failed, root=path.parent, error=AssertionError("credential-canary"))
    assert failed["source"] == value["source"]
    path.write_text(json.dumps(failed))
    data = client(business).get("/api/security-lab").json()
    assert data["evidence"]["status"] == "failed"
    assert data["evidence"]["receipt"]["checks"][1]["status"] == "not_run"
    assert "credential-canary" not in json.dumps(data)


def test_fingerprint_is_taken_once_and_not_for_ordinary_requests(business, monkeypatch):
    calls = []
    def fingerprint():
        calls.append(True)
        return {"sha256": "b" * 64, "files": 1, "git_commit": None, "dirty": None}
    monkeypatch.delenv("BUSINESS_SECURITY_EVIDENCE_FILE", raising=False)
    monkeypatch.setattr(security_lab, "source_fingerprint", fingerprint)
    viewer = client(business)
    viewer.get("/healthz")
    assert calls == []
    viewer.get("/api/security-lab")
    viewer.get("/api/security-lab")
    assert calls == [True]


def test_source_drift_invalidates_results_even_after_original_source_returns(business, receipt):
    path, value = receipt
    original = (path.parent / "pyproject.toml").read_bytes()
    changed = evidence.new_receipt("scenarios", evidence.CHECKS, root=path.parent)
    for check in changed["checks"]:
        check["status"] = "passed"
    (path.parent / "pyproject.toml").write_text("# changed while tests ran\n")
    changed = evidence.finish_receipt(changed, root=path.parent)
    (path.parent / "pyproject.toml").write_bytes(original)
    path.write_text(json.dumps(changed))
    assert changed["source"] == value["source"]
    data = client(business).get("/api/security-lab").json()["evidence"]
    assert data["source_matches"] is True
    assert data["status"] == "stale"
    assert data["receipt"]["status"] == "failed"


def test_invalid_evidence_warning_is_bounded_and_recovers(business, receipt, caplog):
    path, value = receipt
    viewer = client(business)
    path.write_bytes(b'credential-canary')
    for _ in range(5):
        assert viewer.get("/api/security-lab").json()["evidence"]["status"] == "unavailable"
    messages = [record for record in caplog.records if record.name == security_lab.__name__]
    assert len(messages) == 1 and "credential-canary" not in messages[0].message
    path.write_text(json.dumps(value))
    assert viewer.get("/api/security-lab").json()["evidence"]["status"] == "passed"
    path.write_bytes(b'bad-again')
    assert viewer.get("/api/security-lab").json()["evidence"]["status"] == "unavailable"
    assert len([record for record in caplog.records if record.name == security_lab.__name__]) == 2
