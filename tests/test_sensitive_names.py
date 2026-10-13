"""Secret-named fields and controls are detected, and hosts can add names."""
from __future__ import annotations

import pytest

import role_aware_dashboard_toolkit.sensitive_values as sensitive_values
from role_aware_dashboard_toolkit import ControlRegistry
from role_aware_dashboard_toolkit.api import FASTAPI_AVAILABLE, create_app
from role_aware_dashboard_toolkit.sensitive_values import REDACTED_SECRET, is_sensitive_name

_HEADERS = {"X-API-Key": "synthetic-sensitive-name-key"}


@pytest.mark.parametrize(
    "name",
    [
        # Previously missed credential names.
        "private_key", "privateKey", "PRIVATE-KEY", "ssh private key",
        "passwd", "db_passwd", "pwd", "DB_PWD", "dbPwd",
        "access_key_id", "AWS_ACCESS_KEY_ID", "accessKeyId",
        "cookie", "session_cookie", "Cookie",
        "jwt", "id_jwt", "JWT_TOKEN", "authJwt",
        "dsn", "SENTRY_DSN", "sentryDsn", "database dsn",
        "connection_string", "ConnectionString", "connection-string",
        # Names that were already detected stay detected.
        "token", "api_key", "x-api-key", "Authorization", "client_secret", "credential", "passphrase",
    ],
)
def test_secret_names_are_sensitive(name):
    assert is_sensitive_name(name) is True


@pytest.mark.parametrize(
    "name",
    ["kidsName", "kids_name", "endsnow", "upwards", "window_size", "mode", "adsNetwork", "hotpot"],
)
def test_short_secret_words_match_whole_words_only(name):
    assert is_sensitive_name(name) is False


def test_controls_named_with_new_secret_words_are_sensitive_by_default():
    registry = ControlRegistry()
    registry.register("Database DSN", kind="text", key="database_dsn", default="postgres://u:p@h/db")
    registry.register("Session cookie", kind="text", key="session_cookie", default="c")
    registry.register("Kids name", kind="text", key="kids_name", default="Ada")

    assert registry.get("database_dsn").sensitive is True
    assert registry.get("session_cookie").sensitive is True
    assert registry.get("kids_name").sensitive is False


@pytest.mark.skipif(not FASTAPI_AVAILABLE, reason="FastAPI not installed")
def test_api_redacts_nested_fields_with_new_secret_names(monkeypatch):
    from fastapi.testclient import TestClient

    monkeypatch.setenv("ROLE_AWARE_DASHBOARD_TOOLKIT_API_KEY", _HEADERS["X-API-Key"])
    names = ["private_key", "passwd", "pwd", "access_key_id", "cookie", "jwt", "dsn", "connection_string"]
    target = {"service": "billing", **{name: f"VAL-{name}" for name in names}}
    registry = ControlRegistry()
    registry.register("Backend", kind="select", key="backend", options=[target, {"service": "other"}],
                      default=target)

    with TestClient(create_app(registry)) as client:
        value = client.get("/controls/backend", headers=_HEADERS).json()["value"]

    assert value["service"] == "billing"
    assert {name: value[name] for name in names} == {name: REDACTED_SECRET for name in names}


def test_hosts_can_register_more_sensitive_names(monkeypatch):
    # Restore the process-wide rules after the test, whatever it registers.
    monkeypatch.setattr(sensitive_values, "_RULES", getattr(sensitive_values, "_RULES", None), raising=False)
    assert is_sensitive_name("tenant_pin") is False

    sensitive_values.register_sensitive_names("tenant pin", "otp")

    assert is_sensitive_name("tenant_pin") is True
    assert is_sensitive_name("tenantPin") is True
    assert is_sensitive_name("TENANT-PIN-CODE") is True
    assert is_sensitive_name("user_otp") is True
    assert is_sensitive_name("hotpot") is False
    assert is_sensitive_name("token") is True
    registry = ControlRegistry()
    registry.register("Tenant PIN", kind="text", key="tenant_pin", default="0000")
    assert registry.get("tenant_pin").sensitive is True


@pytest.mark.parametrize("bad", ["", "   ", "_-_", None, 7])
def test_registering_a_blank_or_non_text_name_is_refused(monkeypatch, bad):
    monkeypatch.setattr(sensitive_values, "_RULES", getattr(sensitive_values, "_RULES", None), raising=False)
    with pytest.raises((TypeError, ValueError)):
        sensitive_values.register_sensitive_names(bad)


@pytest.mark.parametrize(
    "name",
    ["access_keyboard", "accessKeyboard", "private_keyboard_layout", "privateKeyboardLayout",
     "access_keystroke_log", "private_keynote"],
)
def test_access_and_private_key_do_not_match_a_longer_word(name):
    # "key" must end its word: a keyboard is not a key.
    assert is_sensitive_name(name) is False


@pytest.mark.parametrize(
    "name",
    ["access_keys", "privateKeys", "ACCESS_KEYBOARD", "accesskey", "private-key-pem"],
)
def test_access_and_private_key_still_match_plurals_and_capitals(name):
    # All-capital names carry no word boundary, so they stay sensitive.
    assert is_sensitive_name(name) is True


def test_api_key_keeps_its_0_1_0_substring_match():
    # 0.1.0 matched "api key" anywhere; narrowing it would expose values 0.1.0 hid.
    assert is_sensitive_name("api_keyboard") is True


@pytest.mark.parametrize(
    ("registered", "name", "expected"),
    [
        ("Straße", "Straße_code", True),
        ("Straße", "STRASSE_CODE", True),
        ("straße", "strasse", True),
        ("signing key", "signing_keyboard", False),
        ("signing key", "signingKeyId", True),
    ],
)
def test_registered_names_match_like_built_in_names(monkeypatch, registered, name, expected):
    monkeypatch.setattr(sensitive_values, "_RULES", getattr(sensitive_values, "_RULES", None), raising=False)

    sensitive_values.register_sensitive_names(registered)

    assert is_sensitive_name(name) is expected
