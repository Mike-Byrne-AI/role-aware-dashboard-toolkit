"""Regression tests for the deployment boundary, using isolated fictional state."""

from __future__ import annotations

import hashlib
import importlib.util
import re
import secrets
import shutil
import sqlite3
import sys
from contextlib import closing
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

_SCRIPT = Path(__file__).resolve().parents[1] / "hosting" / "pilot.py"
_SPEC = importlib.util.spec_from_file_location("landscaping_host_runtime", _SCRIPT)
pilot = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = pilot
_SPEC.loader.exec_module(pilot)
SOURCE_ROOT = Path(__file__).resolve().parents[3]

ORIGIN = "https://landscaping.example.com"
COOKIE = "landscape_demo_session"


def configuration(directory, **overrides):
    return pilot.load_configuration({
        "PUBLIC_ORIGIN": ORIGIN,
        "LANDSCAPE_DATA_DIR": str(directory),
        **overrides,
    })


def snapshots(directory):
    return {
        str(path.relative_to(directory)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in directory.rglob("*") if path.is_file()
    }


@pytest.fixture(scope="session")
def provisioned(tmp_path_factory):
    directory = tmp_path_factory.mktemp("host-runtime-template") / "private"
    handoff = pilot.provision(configuration(directory))
    accounts = dict(re.findall(r"^\| ([a-z]+) \| `([^`]+)` \|$", handoff.read_text(), re.MULTILINE))
    assert set(accounts) == {"admin", "alex", "blair", "casey", "drew", "ellis"}
    return directory, accounts


@pytest.fixture
def storage(tmp_path, provisioned):
    source, accounts = provisioned
    directory = tmp_path / "private"
    shutil.copytree(source, directory)
    return configuration(directory), accounts


def login(client, accounts, username="alex", **headers):
    response = client.post(
        "/api/login", json={"username": username, "password": accounts[username]},
        headers={"Origin": ORIGIN, **headers},
    )
    assert response.status_code == 200, "Fictional account login failed"
    return response


@pytest.mark.parametrize("origin", [
    "", "http://landscaping.example.com", "https://landscaping.example.com/",
    "https://landscaping.example.com/path", "https://landscaping.example.com?key=secret",
    "https://landscaping.example.com#fragment", "https://user:secret@landscaping.example.com",
    "https://*.example.com", "https://landscaping.example.com:443",
    "https://LANDSCAPING.example.com", " https://landscaping.example.com",
    "https://landscaping.example.com\n", "https://localhost", "https://app.localhost",
    "https://127.0.0.1", "https://[::1]", "https://bad_label.example.com",
    "https://-bad.example.com", "https://bad-.example.com", "https://example.com.",
    "https://exämple.com", "https://example..com", "https://" + "a" * 64 + ".com",
])
def test_noncanonical_or_unsafe_public_origin_refused(tmp_path, origin):
    with pytest.raises(ValueError, match="PUBLIC_ORIGIN"):
        configuration(tmp_path / "private", PUBLIC_ORIGIN=origin)
    assert not (tmp_path / "private").exists()


@pytest.mark.parametrize("port", ["0", "65536", "-1", "80.0", "", "10000 ", "0x50", "١٠٠٠٠"])
def test_invalid_port_refused(tmp_path, port):
    with pytest.raises(ValueError, match="PORT"):
        configuration(tmp_path / "private", PORT=port)


def test_explicit_configuration_defaults_to_single_private_backend_port(tmp_path):
    config = configuration(tmp_path / "private")
    assert config.port == 10000
    assert config.public_origin == ORIGIN
    assert config.hostname == "landscaping.example.com"
    assert config.trusted_proxy_cidrs == ()
    assert not config.data_dir.exists()


@pytest.mark.parametrize("peers", [
    "*", "0.0.0.0/0", "::/0", "10.0.0.0/8", "2001:db8::/32", "proxy.example.test",
    "", "10.0.0.1/24", "10.0.0.1,", ",10.0.0.1", "10.0.0.1,,10.0.0.2", " ",
    "127.0.0.1:9000", "[::1]", "::1%eth0", "224.0.0.1", "ff02::1", "0.0.0.0", "::",
    "10.0.0.1,10.0.0.1/32",
])
def test_broad_invalid_or_ambiguous_proxy_trust_refused(tmp_path, peers):
    # Empty is the one intentional default: it trusts no forwarded address.
    if peers == "":
        assert configuration(tmp_path / "private", TRUSTED_PROXY_CIDRS=peers).trusted_proxy_cidrs == ()
    else:
        with pytest.raises(ValueError, match="TRUSTED_PROXY_CIDRS"):
            configuration(tmp_path / "private", TRUSTED_PROXY_CIDRS=peers)


def test_explicit_narrow_proxy_peers_are_canonicalized(tmp_path):
    config = configuration(tmp_path / "private", TRUSTED_PROXY_CIDRS="127.0.0.1, 10.23.0.0/24, 2001:db8:1::/64, ::1/128")
    assert config.trusted_proxy_cidrs == ("127.0.0.1", "10.23.0.0/24", "2001:db8:1::/64", "::1")


@pytest.mark.parametrize("directory", [
    "", "relative", "~/private", "/", str(SOURCE_ROOT), str(SOURCE_ROOT / "data"),
    str(SOURCE_ROOT / "docs" / "private"),
    str(SOURCE_ROOT / "examples" / "landscaping" / "private"),
])
def test_missing_relative_or_source_data_path_refused(directory):
    with pytest.raises(ValueError, match="LANDSCAPE_DATA_DIR"):
        configuration(directory)


def test_shipped_layout_protects_the_entire_source_tree():
    assert SOURCE_ROOT in pilot.SOURCE_ROOTS
    assert pilot.APPLICATION_ROOT == SOURCE_ROOT / "examples" / "landscaping"


def test_symlink_alias_to_source_and_direct_symlink_refused(tmp_path):
    alias = tmp_path / "source-alias"
    alias.symlink_to(SOURCE_ROOT, target_is_directory=True)
    with pytest.raises(ValueError, match="source"):
        configuration(alias / "data")
    outside = tmp_path / "outside"
    outside.mkdir()
    direct = tmp_path / "direct"
    direct.symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError, match="symbolic"):
        configuration(direct)


@pytest.mark.parametrize("state", ["missing", "empty", "database-only", "key-only"])
def test_serve_never_provisions_missing_or_incomplete_storage(tmp_path, state, monkeypatch):
    from landscape import app, launcher

    directory = tmp_path / "private"
    if state != "missing":
        directory.mkdir(mode=0o700)
    if state == "database-only":
        (directory / "landscape.sqlite3").touch(mode=0o600)
    if state == "key-only":
        (directory / "identity.key").write_bytes(b"x" * 32)
        (directory / "identity.key").chmod(0o600)
    before = snapshots(directory)
    def forbidden(*_args, **_kwargs):
        pytest.fail("Serve attempted initialization before rejecting incomplete storage")
    monkeypatch.setattr(launcher, "prepare_demo", forbidden)
    monkeypatch.setattr(app, "create_app", forbidden)
    with pytest.raises(ValueError, match="missing or incomplete"):
        pilot.create_application(configuration(directory))
    assert snapshots(directory) == before
    assert directory.exists() == (state != "missing")


def test_preflight_reads_existing_storage_without_altering_state(storage):
    config, _accounts = storage
    before = snapshots(config.data_dir)
    pilot.inspect_existing_storage(config)
    assert snapshots(config.data_dir) == before


@pytest.mark.parametrize("damage", ["no-users", "no-admin", "missing-table", "missing-column", "missing-settings", "bad-version", "bad-key", "public-key", "key-symlink"])
def test_damaged_storage_is_preserved_and_refused(storage, damage, tmp_path):
    config, _accounts = storage
    key = config.data_dir / "identity.key"
    if damage in {"no-users", "no-admin", "missing-table", "missing-column", "missing-settings", "bad-version"}:
        with closing(sqlite3.connect(config.data_dir / "landscape.sqlite3")) as connection:
            commands = {
                "no-users": "DELETE FROM users",
                "no-admin": "UPDATE users SET active=0 WHERE role='admin'",
                "missing-table": "DROP TABLE messages",
                "missing-column": "ALTER TABLE sessions DROP COLUMN csrf_hash",
                "missing-settings": "DELETE FROM settings",
                "bad-version": "PRAGMA user_version=999",
            }
            connection.execute(commands[damage])
            connection.commit()
    elif damage == "bad-key":
        key.write_bytes(b"bad-key")
    elif damage == "public-key":
        key.chmod(0o644)
    else:
        moved = tmp_path / "original-key"
        key.rename(moved)
        key.symlink_to(moved)
    before = snapshots(config.data_dir)
    with pytest.raises(ValueError):
        pilot.create_application(config)
    assert snapshots(config.data_dir) == before


def test_explicit_provision_refuses_to_replace_saved_accounts(storage):
    config, _accounts = storage
    before = snapshots(config.data_dir)
    with pytest.raises(ValueError, match="empty storage"):
        pilot.provision(config)
    assert snapshots(config.data_dir) == before


@pytest.mark.parametrize("damage", ["different-key", "active-principal", "inactive-principal"])
def test_mismatched_backup_identity_pair_refused_before_mutation_or_listener(storage, damage, monkeypatch, capsys):
    import uvicorn
    from landscape import app

    config, _accounts = storage
    if damage == "different-key":
        key_path = config.data_dir / "identity.key"
        original = key_path.read_bytes()
        replacement = secrets.token_bytes(32)
        while replacement == original:
            replacement = secrets.token_bytes(32)
        key_path.write_bytes(replacement)
    else:
        with closing(sqlite3.connect(config.data_dir / "landscape.sqlite3")) as connection:
            connection.execute(
                "UPDATE users SET principal=?,active=? WHERE username='alex'",
                ("invalid-principal-\N{SNOWMAN}", int(damage == "active-principal")),
            )
            connection.commit()
    before = snapshots(config.data_dir)
    def forbidden(*_args, **_kwargs):
        pytest.fail("Mismatched identity storage reached schema initialization or a listener")
    monkeypatch.setattr(app, "create_app", forbidden)
    monkeypatch.setattr(uvicorn, "run", forbidden)
    monkeypatch.setenv("PUBLIC_ORIGIN", config.public_origin)
    monkeypatch.setenv("LANDSCAPE_DATA_DIR", str(config.data_dir))
    with pytest.raises(ValueError, match="identity key do not match"):
        pilot.inspect_existing_storage(config)
    with pytest.raises(SystemExit) as refused:
        pilot.main(["serve"])
    assert refused.value.code == 1
    assert "identity key do not match" in capsys.readouterr().err
    assert snapshots(config.data_dir) == before


def test_secure_cookie_and_hsts_cannot_be_disabled_by_legacy_environment(storage, monkeypatch):
    config, accounts = storage
    monkeypatch.setenv("LANDSCAPE_SECURE_COOKIES", "0")
    with TestClient(pilot.create_application(config), base_url=ORIGIN) as client:
        response = login(client, accounts)
        cookie = response.headers["set-cookie"]
        assert "; Secure" in cookie and "; HttpOnly" in cookie and "SameSite=strict" in cookie
        assert "Domain=" not in cookie
        assert response.headers["strict-transport-security"] == "max-age=31536000"
        assert response.headers["cache-control"] == "no-store"
        assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
        assert client.get("/api/session").status_code == 200
        # The client cookie jar must withhold the Secure cookie on plain HTTP.
        assert client.get(ORIGIN.replace("https:", "http:") + "/api/session").status_code == 401


def test_forwarding_headers_cannot_override_configured_scheme_host_or_origin(storage):
    config, accounts = storage
    application = pilot.create_application(config)
    # Test transport presents plain HTTP scope, as a terminating ingress would.
    with TestClient(application, base_url=ORIGIN.replace("https:", "http:")) as client:
        assert login(client, accounts, **{
            "X-Forwarded-Proto": "http", "Forwarded": "proto=http;host=attacker.example",
            "X-Forwarded-Host": "attacker.example",
        }).status_code == 200
        wrong_origin = client.post("/api/login", json={"username": "alex", "password": accounts["alex"]}, headers={
            "Origin": ORIGIN.replace("https:", "http:"), "X-Forwarded-Proto": "http",
        })
        assert wrong_origin.status_code == 403
        evil_host = client.get("/", headers={"Host": "attacker.example", "X-Forwarded-Host": config.hostname})
        assert evil_host.status_code == 400
        evil_origin = client.post("/api/login", json={"username": "alex", "password": accounts["alex"]}, headers={
            "Origin": "https://attacker.example", "Forwarded": "proto=https;host=attacker.example",
        })
        assert evil_origin.status_code == 403


@pytest.mark.parametrize("trusted,peer,forwarded,expected", [
    ("", "10.23.0.8", "198.51.100.8", "10.23.0.8"),
    ("10.23.0.0/24", "10.23.0.8", "198.51.100.8", "198.51.100.8"),
    ("10.23.0.0/24", "10.24.0.8", "198.51.100.8", "10.24.0.8"),
    ("2001:db8:1::/64", "2001:db8:1::9", "2001:db8:2::20", "2001:db8:2::20"),
    # A verified ingress appends the actual client after any attacker prefix.
    ("10.23.0.0/24", "10.23.0.8", "198.51.100.99, 203.0.113.8", "203.0.113.8"),
])
def test_login_throttle_uses_forwarded_ip_only_from_explicit_trusted_peer(storage, trusted, peer, forwarded, expected):
    from landscape.db import rate_key

    previous, _accounts = storage
    config = configuration(previous.data_dir, TRUSTED_PROXY_CIDRS=trusted)
    with TestClient(pilot.create_application(config), base_url=ORIGIN, client=(peer, 12345)) as client:
        response = client.post("/api/login", json={"username": "unknown_worker", "password": "incorrect fictional password"}, headers={
            "Origin": ORIGIN, "X-Forwarded-For": forwarded,
        })
        assert response.status_code == 401
    key = (config.data_dir / "identity.key").read_bytes()
    with closing(sqlite3.connect(config.data_dir / "landscape.sqlite3")) as connection:
        source_failures = connection.execute(
            "SELECT failures FROM login_limits WHERE key_hash=?", (rate_key(key, "source", expected),),
        ).fetchone()
    assert source_failures == (1,)


def test_trusted_proxy_cannot_override_https_scheme_with_forwarded_proto(storage):
    previous, accounts = storage
    config = configuration(previous.data_dir, TRUSTED_PROXY_CIDRS="10.23.0.8")
    with TestClient(pilot.create_application(config), base_url=ORIGIN.replace("https:", "http:"), client=("10.23.0.8", 12345)) as client:
        login(client, accounts, **{"X-Forwarded-For": "198.51.100.8", "X-Forwarded-Proto": "http"})
        response = client.post("/api/login", json={"username": "alex", "password": accounts["alex"]}, headers={
            "Origin": ORIGIN.replace("https:", "http:"), "X-Forwarded-Proto": "http", "X-Forwarded-For": "198.51.100.8",
        })
        assert response.status_code == 403


def test_verified_distinct_forwarded_clients_do_not_share_source_lockout(storage):
    previous, accounts = storage
    config = configuration(previous.data_dir, TRUSTED_PROXY_CIDRS="10.23.0.8")
    with TestClient(pilot.create_application(config), base_url=ORIGIN, client=("10.23.0.8", 12345)) as client:
        # Thirty different bogus usernames trigger the source limit, without
        # consuming the separate legitimate account's failure allowance.
        for attempt in range(30):
            response = client.post("/api/login", json={"username": f"unknown_worker_{attempt}", "password": "incorrect fictional password"}, headers={
                "Origin": ORIGIN, "X-Forwarded-For": "198.51.100.8",
            })
            assert response.status_code == 401
        blocked = client.post("/api/login", json={"username": "alex", "password": accounts["alex"]}, headers={
            "Origin": ORIGIN, "X-Forwarded-For": "198.51.100.8",
        })
        assert blocked.status_code == 429
        assert login(client, accounts, **{"X-Forwarded-For": "198.51.100.9"}).status_code == 200


def test_changing_forwarded_client_does_not_bypass_account_failure_limit(storage):
    previous, accounts = storage
    config = configuration(previous.data_dir, TRUSTED_PROXY_CIDRS="10.23.0.8")
    with TestClient(pilot.create_application(config), base_url=ORIGIN, client=("10.23.0.8", 12345)) as client:
        for attempt in range(5):
            response = client.post("/api/login", json={"username": "alex", "password": "incorrect fictional password"}, headers={
                "Origin": ORIGIN, "X-Forwarded-For": f"198.51.100.{attempt + 1}",
            })
            assert response.status_code == 401
        blocked = client.post("/api/login", json={"username": "alex", "password": accounts["alex"]}, headers={
            "Origin": ORIGIN, "X-Forwarded-For": "198.51.100.99",
        })
        assert blocked.status_code == 429


def test_worker_boundaries_and_shared_messages_survive_application_restart(storage, monkeypatch):
    from landscape import launcher

    config, accounts = storage
    identity_before = (config.data_dir / "identity.key").read_bytes()
    handoff_before = (config.data_dir / "TRIAL_ACCOUNTS.md").read_bytes()
    def no_seed(*_args, **_kwargs):
        pytest.fail("Serve or restart attempted to provision accounts")
    monkeypatch.setattr(launcher, "prepare_demo", no_seed)
    with TestClient(pilot.create_application(config), base_url=ORIGIN) as client:
        response = login(client, accounts)
        csrf = response.json()["csrf_token"]
        assert client.get("/api/admin/health").status_code == 403
        assert client.post("/api/messages", json={"body": "Protected persistence check"}, headers={"Origin": ORIGIN}).status_code == 403
        assert client.post("/api/messages", json={"body": "Protected persistence check"}, headers={"Origin": ORIGIN, "X-CSRF-Token": csrf}).status_code == 200
        cookie = client.cookies.get(COOKIE)
    with TestClient(pilot.create_application(config), base_url=ORIGIN) as restarted:
        restarted.cookies.set(COOKIE, cookie, domain=config.hostname, path="/")
        assert restarted.get("/api/session").status_code == 200
        messages = restarted.get("/api/messages").json()["messages"]
        assert any(message["body"] == "Protected persistence check" for message in messages)
        login(restarted, accounts, "admin")
        assert restarted.get("/api/admin/health").status_code == 200
    assert (config.data_dir / "identity.key").read_bytes() == identity_before
    assert (config.data_dir / "TRIAL_ACCOUNTS.md").read_bytes() == handoff_before


def test_serve_starts_only_one_worker_with_proxy_trust_disabled(storage, monkeypatch, capsys):
    import uvicorn

    config, accounts = storage
    monkeypatch.setenv("PUBLIC_ORIGIN", config.public_origin)
    monkeypatch.setenv("LANDSCAPE_DATA_DIR", str(config.data_dir))
    monkeypatch.setenv("PORT", "18789")
    called = []
    monkeypatch.setattr(uvicorn, "run", lambda application, **kwargs: called.append((application, kwargs)))
    pilot.main(["serve"])
    assert len(called) == 1
    assert called[0][1] == {
        "host": "0.0.0.0", "port": 18789, "workers": 1, "access_log": False,
        "proxy_headers": False, "forwarded_allow_ips": "", "server_header": False,
    }
    output = capsys.readouterr()
    assert all(password not in output.out + output.err for password in accounts.values())


def test_preflight_and_provision_cli_never_print_private_account_contents(tmp_path, monkeypatch, capsys):
    directory = tmp_path / "private"
    monkeypatch.setenv("PUBLIC_ORIGIN", ORIGIN)
    monkeypatch.setenv("LANDSCAPE_DATA_DIR", str(directory))
    pilot.main(["provision"])
    pilot.main(["preflight"])
    output = capsys.readouterr()
    passwords = re.findall(r"^\| [a-z]+ \| `([^`]+)` \|$", (directory / "TRIAL_ACCOUNTS.md").read_text(), re.MULTILINE)
    assert len(passwords) == 6
    assert all(password not in output.out + output.err for password in passwords)
    assert "TRIAL_ACCOUNTS.md" in output.out
