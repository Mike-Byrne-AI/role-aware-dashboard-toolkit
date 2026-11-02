"""Security demonstrations execute their negative and positive controls."""

from contextlib import contextmanager
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

pytest.importorskip("fastapi")
httpx = pytest.importorskip("httpx")
pytest.importorskip("pyotp")

from tools import business_security_demo as demo  # noqa: E402


@pytest.fixture(autouse=True)
def no_external_http(monkeypatch):
    def reject(*args, **kwargs):
        raise AssertionError("The disposable demo attempted an external request.")
    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", reject)


@pytest.fixture
def source(tmp_path):
    (tmp_path / "pyproject.toml").write_text("# isolated receipt source\n")
    return tmp_path


def test_three_real_scenarios_pass_using_only_disposable_data(source, monkeypatch):
    monkeypatch.setenv("BUSINESS_MFA_KEY_FILE", "must-never-read-an-existing-key")
    result = demo.run_demo(root=source)
    assert result["status"] == "passed", result["error"]
    assert result["scope"] == "local_scenarios"
    assert len(result["checks"]) == 14
    assert all(row["status"] == "passed" for row in result["checks"])
    assert "must-never-read" not in json.dumps(result)


def test_owned_temporary_paths_are_canonical_before_private_storage(source, monkeypatch):
    temporary_directory = demo.tempfile.TemporaryDirectory
    fixture = demo._fixture
    checked = []

    @contextmanager
    def noncanonical_temporary(**kwargs):
        with temporary_directory(**kwargs) as temporary:
            marker = Path(temporary).resolve(strict=True) / "normalization-probe"
            marker.mkdir()
            yield str(marker / "..")

    def canonical_fixture(directory):
        # Private-storage checks reject redirected ancestors. The runner must
        # resolve its own newly created temp root before crossing that boundary.
        assert directory == directory.resolve()
        checked.append(directory)
        return fixture(directory)

    monkeypatch.setattr(demo, "tempfile", SimpleNamespace(TemporaryDirectory=noncanonical_temporary))
    monkeypatch.setattr(demo, "_fixture", canonical_fixture)
    result = demo.run_demo(root=source)
    assert result["status"] == "passed", result["error"]
    assert len(checked) == 2
    assert all(row["status"] == "passed" for row in result["checks"])


def test_fake_revocation_success_is_detected_and_remaining_scenarios_not_claimed(source, monkeypatch):
    from fastapi.testclient import TestClient

    original = TestClient.post
    def ineffective_revoke(self, url, **kwargs):
        if str(url).startswith("/api/security/sessions/") and str(url).endswith("/revoke"):
            return httpx.Response(200, json={"ok": True, "current_session_revoked": False})
        return original(self, url, **kwargs)
    monkeypatch.setattr(TestClient, "post", ineffective_revoke)
    result = demo.run_demo(root=source)
    assert result["status"] == "failed"
    statuses = {row["id"]: row["status"] for row in result["checks"]}
    assert statuses["revoke_next_request"] == "failed"
    assert statuses["revoke_no_business_change"] == "not_run"
    assert statuses["cas_one_winner"] == "not_run"
    assert statuses["restore_current_access"] == "not_run"


def test_unexpected_error_does_not_leak_secrets_or_claim_remaining_work(source, monkeypatch, capsys):
    def fail(*args):
        raise RuntimeError("secret-cookie-password-private-path-canary")
    monkeypatch.setattr(demo, "session_revocation", fail)
    result = demo.run_demo(root=source)
    assert result["status"] == "failed"
    assert all(row["status"] == "not_run" for row in result["checks"])
    assert "secret-cookie-password" not in json.dumps(result)
    assert capsys.readouterr().out == ""


@pytest.mark.parametrize("arguments", [["--url", "https://example.invalid"], ["--data-dir", "existing-data"]])
def test_cli_rejects_live_targets_and_existing_runtime(arguments):
    with pytest.raises(SystemExit) as error:
        demo.main(arguments)
    assert error.value.code == 2


def test_cli_preserves_existing_evidence(tmp_path, monkeypatch):
    marker = tmp_path / "receipt.json"
    marker.write_text("earlier failure")
    monkeypatch.setattr(demo, "run_demo", lambda: pytest.fail("Existing evidence reached execution"))
    with pytest.raises(SystemExit):
        demo.main(["--output-dir", str(tmp_path)])
    assert marker.read_text() == "earlier failure"


@pytest.mark.parametrize("optimization", ["-O", "-OO"])
def test_optimized_runner_is_refused_before_execution(tmp_path, optimization):
    output = tmp_path / "must-not-exist"
    environment = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    result = subprocess.run([sys.executable, optimization, str(demo.ROOT / "tools/business_security_demo.py"),
                             "--output-dir", str(output)], capture_output=True, text=True, env=environment, timeout=15)
    assert result.returncode != 0
    assert "requires assertions" in result.stderr
    assert not output.exists()
