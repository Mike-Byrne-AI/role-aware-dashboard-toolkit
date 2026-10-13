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
    ["access_keyboard", "accessKeyboard", "ACCESS_KEYBOARD", "private_keyboard_layout",
     "privateKeyboardLayout", "access_keystroke_log", "private_keynote", "access_keypad",
     "private_keyword"],
)
def test_access_and_private_key_do_not_match_an_ordinary_longer_word(name):
    # A keyboard is not a key.
    assert is_sensitive_name(name) is False


@pytest.mark.parametrize(
    "name",
    ["access_keys", "privateKeys", "accesskey", "private-key-pem",
     # Key material written as one word stays secret.
     "accesskeyid", "awsaccesskeyid", "privatekeypem", "private_keyfile", "private_keystore",
     "private_keydata", "privateKeyfile", "sshprivatekeypath", "private-keyring"],
)
def test_access_and_private_key_still_match_key_material(name):
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
        ("signing key", "signingkeyfile", True),
    ],
)
def test_registered_names_match_like_built_in_names(monkeypatch, registered, name, expected):
    monkeypatch.setattr(sensitive_values, "_RULES", getattr(sensitive_values, "_RULES", None), raising=False)

    sensitive_values.register_sensitive_names(registered)

    assert is_sensitive_name(name) is expected


# sensitive=False keeps a control's values in audit, as the changelog promises.

def _control_changes(audit):
    return [event for event in audit.all_events() if event["type"] == "control_change"]


@pytest.mark.parametrize(
    ("sensitive", "kept"),
    [(False, True), (None, False), (True, False)],
)
def test_audit_honours_an_explicit_sensitive_false(tmp_path, sensitive, kept):
    import json

    from role_aware_dashboard_toolkit import AuditLog

    audit = AuditLog()
    path = tmp_path / "audit.jsonl"
    audit.start_writer(str(path))
    kwargs = {} if sensitive is None else {"sensitive": sensitive}
    audit.log_control_change("session_cookie_label", "Accept", "Accept all", role="Admin", **kwargs)
    audit.stop_writer()

    (event,) = _control_changes(audit)
    (on_disk,) = [json.loads(line) for line in path.read_text().splitlines()
                  if json.loads(line)["type"] == "control_change"]
    expected = ("Accept", "Accept all") if kept else (REDACTED_SECRET, REDACTED_SECRET)
    assert (event["old"], event["new"]) == expected
    assert (on_disk["old"], on_disk["new"]) == expected


def test_audit_sensitive_false_still_redacts_nested_secret_fields():
    from role_aware_dashboard_toolkit import AuditLog

    audit = AuditLog()
    audit.log_control_change("cookie_settings", {"mode": "a"}, {"mode": "b", "password": "p"}, sensitive=False)

    (event,) = _control_changes(audit)
    assert event["new"] == {"mode": "b", "password": REDACTED_SECRET}


def test_a_bound_audit_view_honours_sensitive_false():
    from role_aware_dashboard_toolkit import AuditLog
    from role_aware_dashboard_toolkit.access_audit import bind_audit_identity

    audit = AuditLog()
    view = bind_audit_identity(audit, "a" * 64, "b" * 32)
    view.log_control_change("session_cookie_label", "x", "y", sensitive=False)
    view.log_control_change("session_cookie_value", "x", "y")

    first, second = _control_changes(audit)
    assert (first["old"], first["new"], first["user_id"]) == ("x", "y", "a" * 64)
    assert (second["old"], second["new"]) == (REDACTED_SECRET, REDACTED_SECRET)


@pytest.mark.skipif(not FASTAPI_AVAILABLE, reason="FastAPI not installed")
def test_api_audits_a_control_registered_with_sensitive_false(monkeypatch):
    from fastapi.testclient import TestClient

    from role_aware_dashboard_toolkit import AuditLog

    monkeypatch.setenv("ROLE_AWARE_DASHBOARD_TOOLKIT_API_KEY", _HEADERS["X-API-Key"])
    registry = ControlRegistry()
    registry.register("Cookie banner", kind="text", key="cookie_banner", default="on", sensitive=False)
    registry.register("Session cookie", kind="text", key="session_cookie", default="c")
    audit = AuditLog()

    with TestClient(create_app(registry, audit=audit, api_role="Admin")) as client:
        response = client.patch("/controls", headers=_HEADERS,
                                json={"values": {"cookie_banner": "off", "session_cookie": "d"}})
        listed = client.get("/audit", headers=_HEADERS).json()

    assert response.status_code == 200
    banner, session = _control_changes(audit)
    assert (banner["old"], banner["new"]) == ("on", "off")
    assert (session["old"], session["new"]) == (REDACTED_SECRET, REDACTED_SECRET)
    assert [(event["old"], event["new"]) for event in listed] == [("on", "off"), (REDACTED_SECRET, REDACTED_SECRET)]
