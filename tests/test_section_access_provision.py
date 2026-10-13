"""Synthetic operator provisioning for the A/B/C example, outside the checkout."""

from __future__ import annotations

import getpass
from pathlib import Path
import tempfile
import warnings

import pytest

from examples.section_access import provision
from examples.section_access.policy import ROLE_SECTIONS
from role_aware_dashboard_toolkit.access import Identity, principal_id
from role_aware_dashboard_toolkit.access_cli import initialize_access, read_identity_key
from role_aware_dashboard_toolkit.access_store import SQLiteAccessStore


ISSUER = "https://synthetic-issuer.example.test"
SUBJECT = "synthetic-private-account"


@pytest.fixture
def configured(monkeypatch):
    # Repository tmp_path is deliberately inside the checkout, which must not
    # be accepted for real provisioning. This directory contains only fixtures.
    # Resolve the system temp root, which sits under the /var symlink on macOS.
    with tempfile.TemporaryDirectory(prefix="radt-section-provision-") as root:
        directory = Path(root).resolve(strict=True) / "protected"
        directory.mkdir(mode=0o700)
        initialize_access(directory)
        monkeypatch.setenv("RADT_ACCESS_DIRECTORY", str(directory))
        monkeypatch.setenv("RADT_OIDC_ISSUER", ISSUER)
        monkeypatch.setattr(getpass, "getpass", lambda prompt: SUBJECT)
        yield directory


def _store(directory):
    return SQLiteAccessStore(directory / "access.sqlite3", allowed_roles=tuple(ROLE_SECTIONS))


def _principal(directory, subject=SUBJECT):
    return principal_id(Identity(ISSUER, subject, 2000), read_identity_key(directory))


@pytest.mark.parametrize("role", ["Admin", "AOnly", "AB", "COnly"])
def test_each_custom_role_is_provisioned_without_unfreezing(configured, role):
    store = _store(configured)
    before = store.read_freeze()
    assert provision.main(["grant", "--role", role]) == 0
    assert store.read_grants(_principal(configured)) == (role,)
    assert store.read_freeze() == before


def test_replacement_and_revocation_are_account_specific(configured, monkeypatch):
    other = "another-synthetic-account"
    store = _store(configured)
    store.replace_grants(_principal(configured, other), ("COnly",))
    assert provision.main(["grant", "--role", "Admin", "--role", "AOnly"]) == 0
    assert store.read_grants(_principal(configured)) == ("Admin", "AOnly")
    assert provision.main(["grant", "--role", "AB"]) == 0
    assert store.read_grants(_principal(configured)) == ("AB",)
    assert provision.main(["revoke"]) == 0
    assert store.read_grants(_principal(configured)) == ()
    assert store.read_grants(_principal(configured, other)) == ("COnly",)


def test_subject_issuer_key_and_principal_are_not_disclosed(configured, capsys):
    assert provision.main(["grant", "--role", "Admin"]) == 0
    output = capsys.readouterr()
    printed = output.out + output.err
    database = (configured / "access.sqlite3").read_bytes()
    key = read_identity_key(configured)
    for value in (SUBJECT, ISSUER, _principal(configured), key.hex(), str(configured)):
        assert value not in printed
    for value in (SUBJECT.encode(), ISSUER.encode(), key):
        assert value not in database


@pytest.mark.parametrize("subject", [None, "", " padded", "padded ", "x" * 256, "caf\u00e9", "a\nb", "a\x7fb"])
def test_invalid_subject_cannot_replace_a_grant(configured, monkeypatch, capsys, subject):
    store = _store(configured)
    store.replace_grants(_principal(configured), ("AOnly",))
    monkeypatch.setattr(getpass, "getpass", lambda prompt: subject)
    assert provision.main(["grant", "--role", "Admin"]) == 1
    assert store.read_grants(_principal(configured)) == ("AOnly",)
    output = capsys.readouterr()
    assert output.out == ""
    assert output.err == "Provisioning failed. Check the protected directory and configuration.\n"


@pytest.mark.parametrize("issuer", ["", " padded", "padded ", "a\nb", "a\x7fb", "x" * 2049])
def test_invalid_issuer_fails_before_prompt(configured, monkeypatch, issuer):
    monkeypatch.setenv("RADT_OIDC_ISSUER", issuer)

    def forbidden_prompt(prompt):
        pytest.fail("Invalid issuer must fail before asking for a subject")

    monkeypatch.setattr(getpass, "getpass", forbidden_prompt)
    assert provision.main(["grant", "--role", "Admin"]) == 1
    assert _store(configured).read_grants(_principal(configured)) == ()


@pytest.mark.parametrize("name", ["RADT_ACCESS_DIRECTORY", "RADT_OIDC_ISSUER"])
def test_missing_configuration_fails_before_prompt(configured, monkeypatch, name):
    monkeypatch.delenv(name)

    def forbidden_prompt(prompt):
        pytest.fail("Missing configuration must fail before asking for a subject")

    monkeypatch.setattr(getpass, "getpass", forbidden_prompt)
    assert provision.main(["grant", "--role", "Admin"]) == 1


def test_no_echo_fallback_fails_before_visible_input(configured, monkeypatch, capsys):
    def unavailable_prompt(prompt):
        warnings.warn("private-terminal-detail", getpass.GetPassWarning)
        pytest.fail("Must not fall back to visible input")

    monkeypatch.setattr(getpass, "getpass", unavailable_prompt)
    assert provision.main(["grant", "--role", "Admin"]) == 1
    assert _store(configured).read_grants(_principal(configured)) == ()
    output = capsys.readouterr()
    assert "private-terminal-detail" not in output.out + output.err


@pytest.mark.parametrize("argv", [
    ["grant", "--role", "synthetic-private-input"],
    ["grant", "--role", "Admin", "--subject", "synthetic-private-input"],
    ["grant", "--role", "Admin", "--role", "Admin"],
    ["revoke", "synthetic-private-input"],
])
def test_bad_arguments_do_not_echo_or_change_existing_grants(configured, capsys, argv):
    store = _store(configured)
    store.replace_grants(_principal(configured), ("AOnly",))
    assert provision.main(argv) == 1
    assert store.read_grants(_principal(configured)) == ("AOnly",)
    output = capsys.readouterr()
    assert "synthetic-private-input" not in output.out + output.err


def test_private_exception_details_are_suppressed(configured, monkeypatch, capsys):
    def broken_prompt(prompt):
        raise RuntimeError("synthetic-private-provider-response")

    monkeypatch.setattr(getpass, "getpass", broken_prompt)
    assert provision.main(["revoke"]) == 1
    output = capsys.readouterr()
    assert "synthetic-private-provider-response" not in output.out + output.err


def test_repository_storage_is_rejected_before_prompt(tmp_path, monkeypatch):
    directory = tmp_path / "protected"
    directory.mkdir(mode=0o700)
    monkeypatch.setenv("RADT_ACCESS_DIRECTORY", str(directory))
    monkeypatch.setenv("RADT_OIDC_ISSUER", ISSUER)

    def forbidden_prompt(prompt):
        pytest.fail("Repository storage must fail before prompting")

    monkeypatch.setattr(getpass, "getpass", forbidden_prompt)
    assert provision.main(["grant", "--role", "Admin"]) == 1
    assert not list(directory.iterdir())
