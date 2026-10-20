"""The disposable fuzz runner exercises guards and catches broken guard mutants."""

import importlib.util
import json
from pathlib import Path
import sys

import pytest

pytest.importorskip("fastapi")
httpx = pytest.importorskip("httpx")
pytest.importorskip("pyotp")
from fastapi import HTTPException  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "business_security_fuzz", ROOT / "tools" / "business_dashboard_fuzz.py",
)
fuzz = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = fuzz
SPEC.loader.exec_module(fuzz)


@pytest.fixture(autouse=True)
def no_external_http(monkeypatch):
    """A real HTTP transport is forbidden, including on a failing campaign."""
    attempts = []

    def forbid(self, request):
        attempts.append(request)
        raise AssertionError("The fuzz runner attempted external HTTP")

    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", forbid)
    yield
    assert not attempts, "The fuzz runner attempted external HTTP"


@pytest.mark.parametrize("seed,cases", [(37, 36), (20261019, 45)])
def test_seeded_campaign_exercises_all_guards_and_required_mocked_provider(seed, cases, capsys):
    result = fuzz.run_campaign(seed=seed, cases=cases)
    assert result["passed"], result
    assert result["completed_cases"] == cases
    assert set(result["families"]) == {
        "cookie", "role", "csrf", "origin", "authority", "schema", "body", "login", "challenge",
    }
    assert all(count >= 4 for count in result["families"].values())
    assert result["mocked_provider_calls"] >= 2
    assert result["requests"] > cases
    assert capsys.readouterr().out == ""


def test_role_bypass_mutant_is_caught_instead_of_reporting_success(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "examples" / "business_dashboard"))
    from business.security import AuthContext

    monkeypatch.setattr(AuthContext, "authorize", lambda *args, **kwargs: None)
    result = fuzz.run_campaign(seed=37, cases=36)
    assert not result["passed"]
    failure = result["failure"]
    # Generated role probes and the employee moderation probe both exercise
    # the role boundary. Their ordering can change as the input corpus grows.
    assert failure["family"] in ("role", "moderation_sequence")
    assert failure["invariant"] == "unexpected_status"
    assert failure["route"].startswith("/api/admin/")
    assert failure["expected"] == 403
    assert failure["actual"] in (200, 201)


def test_reject_everything_mutant_fails_positive_authentication_control(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "examples" / "business_dashboard"))
    from business.security import AuthContext

    def deny(*args, **kwargs):
        raise HTTPException(403, "Synthetic blanket denial")

    monkeypatch.setattr(AuthContext, "authorize", deny)
    result = fuzz.run_campaign(seed=37, cases=9)
    assert not result["passed"]
    failure = result["failure"]
    assert failure["invariant"] == "unexpected_status"
    assert failure["route"] == "/api/login"
    assert failure["expected"] == 200
    assert failure["actual"] == 403


def test_unexpected_exception_report_does_not_disclose_sensitive_text(monkeypatch, capsys):
    secret = "synthetic-password-cookie-and-MFA-secret-canary"

    def fail(self):
        raise RuntimeError(secret)

    monkeypatch.setattr(fuzz.Campaign, "execute", fail)
    result = fuzz.run_campaign(seed=37, cases=9)
    assert not result["passed"]
    assert result["failure"]["type"] == "RuntimeError"
    assert secret not in json.dumps(result)
    assert secret not in repr(capsys.readouterr())
    assert not {"password", "cookie", "csrf", "otp", "body", "headers"} & result["failure"].keys()


@pytest.mark.parametrize("arguments", [
    ["--url", "https://example.invalid"],
    ["--data-dir", "existing-private-data"],
    ["--cases", "0"],
    ["--cases", "10001"],
    ["--seed", "-1"],
    ["--seed", "4294967296"],
])
def test_cli_rejects_live_targets_existing_data_and_unbounded_inputs(arguments, monkeypatch):
    def unexpected_campaign(**kwargs):
        pytest.fail("Invalid CLI input reached campaign execution")

    monkeypatch.setattr(fuzz, "run_campaign", unexpected_campaign)
    with pytest.raises(SystemExit) as error:
        fuzz.main(arguments)
    assert error.value.code == 2
