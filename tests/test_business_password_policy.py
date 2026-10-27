"""Offline new-password screening without breaking existing account sign-in."""

import gzip
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
pytest.importorskip("pyotp")

from tests.test_business_dashboard import (  # noqa: E402
    NEW_PASSWORD, business as business, business_seed as business_seed,
)
from business import auth_routes, password_policy  # noqa: E402
from business.security import hash_password, verify_password  # noqa: E402


def _error(password):
    return password_policy.password_policy_error(password, username="alex", name="Alex Rivera")


def _change(actor, current, replacement):
    # Escaped JSON also permits testing malformed Unicode received over HTTP.
    return actor.request("POST", "/api/password", content=json.dumps({
        "current_password": current, "new_password": replacement,
    }), headers={"Content-Type": "application/json"})


def _account_state(business):
    with business.db() as connection:
        return {
            "user": tuple(connection.execute("SELECT * FROM users WHERE id='alex'").fetchone()),
            "sessions": [tuple(row) for row in connection.execute(
                "SELECT token_hash,user_id,created_at,expires_at FROM sessions ORDER BY token_hash"
            )],
            "activity": [tuple(row) for row in connection.execute("SELECT * FROM activity ORDER BY id")],
        }


def test_bundled_common_password_corpus_is_the_documented_unmodified_snapshot():
    folder = Path(password_policy.__file__).with_name("password_data")
    data = (folder / "common-passwords.txt.gz").read_bytes()
    assert hashlib.sha256(data).hexdigest() == "3c1baed62596de36860824eb3f436d5932d37ca8b06e59df78f5a44ec175afe4"
    corpus = gzip.decompress(data).decode("utf-8").splitlines()
    assert len(corpus) == len(set(corpus)) == 19640
    assert len(password_policy._COMMON_PASSWORDS) == 19640
    assert hashlib.sha256((folder / "DJANGO_LICENSE.txt").read_bytes()).hexdigest() == (
        "b846415d1b514e9c1dff14a22deb906d794bc546ca6129f950a18cd091e2a669"
    )
    assert "Django 5.2.7" in (folder / "SOURCE.txt").read_text(encoding="utf-8")


def test_vendored_license_survives_fresh_autocrlf_checkout():
    root = Path(__file__).resolve().parents[1]
    relative = Path("examples/business_dashboard/business/password_data/DJANGO_LICENSE.txt")
    upstream = (root / relative).read_bytes()
    expected = "b846415d1b514e9c1dff14a22deb906d794bc546ca6129f950a18cd091e2a669"
    with tempfile.TemporaryDirectory(prefix="radt-license-checkout-") as temporary:
        checkout = Path(temporary)

        def git(*arguments):
            return subprocess.run(["git", "-c", "core.excludesfile=", "-C", str(checkout), *arguments],
                                  check=True, capture_output=True, text=True)

        git("init", "--quiet")
        git("config", "core.autocrlf", "true")
        git("config", "core.safecrlf", "false")
        license_file = checkout / relative
        license_file.parent.mkdir(parents=True)
        license_file.write_bytes(upstream)
        git("add", "--", relative.as_posix())
        license_file.unlink()
        git("checkout-index", "--all")
        assert b"\r\n" in license_file.read_bytes()
        assert hashlib.sha256(license_file.read_bytes()).hexdigest() != expected

        attributes = checkout / ".gitattributes"
        attributes.write_bytes((root / ".gitattributes").read_bytes())
        git("add", "--", ".gitattributes")
        license_file.unlink()
        attributes.unlink()
        # Both files are recreated from the index, as in a fresh checkout.
        # No application data, existing checkout metadata or commit is changed.
        git("checkout-index", "--all")
        assert hashlib.sha256(license_file.read_bytes()).hexdigest() == expected
        assert b"\r\n" not in license_file.read_bytes()


@pytest.mark.parametrize("password", [
    "", "Fourteen chars", "a" * 129,
    "111111111111111", "123456789987654321", "1Q2W3E4R5T6Y7U8I9O0P",
    "passwordpassword", "LetMeIn" * 3, "password1" * 12,
    "  111111111111111  ", " " * 15, "Westbridge Business Group",
    "Valid length but malformed text\ud800",
])
def test_rejects_short_common_expected_and_invalid_choices(password):
    result = _error(password)
    assert isinstance(result, str)
    assert len(result) < 200
    assert password not in result or not password


def test_minimum_counts_characters():
    password = "Cedar violet 75"
    assert len(password) == 15
    assert _error(password) is None
    assert _error(password[:-1]) is not None


@pytest.mark.parametrize("password", [
    NEW_PASSWORD,
    "cedar violet lantern river",
    "alex found a quiet orange moon",
    "111111111111111 plus an unrelated woodland phrase",
    "password buttercup password violet",
    "W9a!tZ6mQ2xN" * 2,
    "  cedar violet lantern river  ",
    "\u96ea\u706f\u685c\u5ddd\u661f\u82b1\u98a8\u7af9\u96f2\u8c37\u6e56\u9db4\u68ee\u6708\u77f3",
    "A bounded Unicode passphrase with a quiet comet " + "\U0001f680" * 80,
])
def test_allows_passphrases_unicode_spaces_and_unrelated_blocklist_substrings(password):
    assert 15 <= len(password) <= 128
    assert _error(password) is None


def test_exact_account_names_are_rejected_without_blocking_name_substrings():
    account_name = "Alexandra Rivera"
    assert password_policy.password_policy_error(
        account_name, username="alex", name=account_name,
    ) is not None
    assert password_policy.password_policy_error(
        account_name + " watches the quiet comet", username="alex", name=account_name,
    ) is None


@pytest.mark.parametrize("replacement", [
    "Short choice", "111111111111111", "1Q2W3E4R5T6Y7U8I9O0P",
    "passwordpassword", "Invalid Unicode choice\udfff",
])
def test_rejected_new_choice_preserves_password_sessions_and_activity(business, monkeypatch, caplog, replacement):
    first, second = business.login("alex"), business.login("alex")
    before = _account_state(business)

    def no_new_hash(_password):
        raise AssertionError("A rejected password must not reach password hashing")

    monkeypatch.setattr(auth_routes, "hash_password", no_new_hash)
    response = _change(first, business.credentials["alex"], replacement)
    assert response.status_code == 422
    assert "set-cookie" not in response.headers
    assert replacement not in response.text
    assert replacement not in caplog.text
    assert _account_state(business) == before
    assert first.request("GET", "/api/messages").status_code == 200
    assert second.request("GET", "/api/messages").status_code == 200


def test_current_password_is_checked_before_choice_screening(business, monkeypatch):
    actor = business.login("alex")

    def no_screening(*args, **kwargs):
        raise AssertionError("New-password policy ran before successful reauthentication")

    monkeypatch.setattr(auth_routes, "password_policy_error", no_screening)
    response = _change(actor, "Incorrect disposable current password", "111111111111111")
    assert response.status_code == 403
    assert response.json() == {"detail": "The current password is incorrect."}


def test_correcting_choices_preserves_existing_failed_guess_budget(business):
    actor = business.login("alex")
    assert _change(actor, "Incorrect disposable current password", NEW_PASSWORD).status_code == 403
    for _ in range(auth_routes.ATTEMPT_LIMIT + 1):
        assert _change(actor, business.credentials["alex"], "111111111111111").status_code == 422
    with business.db() as connection:
        assert connection.execute("SELECT attempts FROM login_limits").fetchone()[0] == 1
    assert _change(actor, business.credentials["alex"], NEW_PASSWORD).status_code == 200
    assert business.login("alex", NEW_PASSWORD).profile["id"] == "alex"


def test_existing_short_password_can_sign_in_and_change_without_rewriting_new_text(business):
    legacy = "LegacyPass12"
    replacement = "  cedar violet lantern river  "
    with business.db() as connection:
        connection.execute("UPDATE users SET password_hash=? WHERE id='alex'", (hash_password(legacy),))
    actor = business.login("alex", legacy)
    assert _change(actor, legacy, replacement).status_code == 200
    with business.db() as connection:
        stored = connection.execute("SELECT password_hash FROM users WHERE id='alex'").fetchone()[0]
    assert verify_password(stored, replacement)
    assert not verify_password(stored, replacement.strip())
    assert not verify_password(stored, legacy)
    assert business.login("alex", replacement).profile["id"] == "alex"
