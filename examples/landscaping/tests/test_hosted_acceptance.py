"""Negative protocol, credential privacy, TLS, and non-overwrite regressions."""
from __future__ import annotations

import http.server
import importlib.util
import json
import os
import ssl
import subprocess
import sys
import threading
from email.message import Message
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "hosted_acceptance.py"
SPEC = importlib.util.spec_from_file_location("landscaping_hosted_acceptance", SCRIPT)
acceptance = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = acceptance
SPEC.loader.exec_module(acceptance)

SECRET_PASSWORD = "private-password-sentinel-921"
SECRET_TOKEN = "z" * 43
SECRET_CSRF = "b" * 64


def headers(**extra):
    value = Message()
    values = {"Cache-Control": "no-store", "X-Frame-Options": "DENY",
              "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer",
              "Strict-Transport-Security": "max-age=31536000",
              "Content-Security-Policy": "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"}
    values.update(extra)
    for key, item in values.items():
        value[key] = item
    return value


def response(status, body=None, **extra):
    payload = json.dumps(body).encode() if body is not None else b""
    return acceptance.Response(status, headers(**extra), payload)


class FakeHost:
    """Stateful boundary model; intentional fault switches are detected below."""

    def __init__(self, fault=None):
        self.fault = fault
        self.requests = []
        self.tokens = {}
        self.counter = 0

    def client(self, base, context, timeout):
        assert context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED
        host = self

        class Actor:
            cookie = None

            def request(self, path, *, method="GET", body=None, origin=None, csrf=None, token=None):
                host.requests.append((method, path))
                if host.fault == "network":
                    raise RuntimeError(SECRET_PASSWORD + SECRET_TOKEN)
                if origin is not None and origin != base:
                    return response(403)
                if path == "/":
                    content = b"<title>Cedar & Stone</title><script src='/static/app.js'></script>"
                    if host.fault == "catch_all":
                        content = b"<title>Unrelated website</title>"
                    value = headers(**{"Content-Type": "text/html"})
                    if host.fault == "missing_hsts":
                        del value["Strict-Transport-Security"]
                    return acceptance.Response(200, value, content)
                if path == "/api/login":
                    host.counter += 1
                    self.cookie = (str(host.counter) + SECRET_TOKEN)[-43:]
                    # Distinct server-side session token for each identity.
                    self.cookie = str(host.counter).zfill(43)
                    role = "admin" if body["username"] == "private_admin" else "worker"
                    host.tokens[self.cookie] = {"username": body["username"], "role": role}
                    flags = "Secure; HttpOnly; SameSite=Strict; Path=/"
                    if host.fault == "missing_secure":
                        flags = "HttpOnly; SameSite=Strict; Path=/"
                    return response(200, {"user": host.tokens[self.cookie], "csrf_token": SECRET_CSRF},
                                    **{"Set-Cookie": f"{acceptance.COOKIE_NAME}={self.cookie}; {flags}"})
                user = host.tokens.get(token or self.cookie)
                if not user:
                    if path in acceptance.ADMIN_PAGES:
                        return response(303, Location="/")
                    return response(401)
                if path == "/api/logout":
                    if csrf != SECRET_CSRF:
                        return response(403)
                    if host.fault != "logout_replay":
                        host.tokens.pop(self.cookie)
                    self.cookie = None
                    return response(200, {"ok": True})
                if path == "/api/session":
                    return response(200, {"user": user})
                if path == "/api/jobs":
                    job_id = "work-1"
                    if host.fault == "private_schedule" and user["role"] == "worker":
                        job_id = "different-work"
                    crew = [{"display_name": "Fictional worker"}]
                    if host.fault == "crew_private_fields":
                        crew[0]["password"] = SECRET_PASSWORD
                    return response(200, {"jobs": [{"id": job_id, "crew": crew,
                                                   "joined": user["role"] == "worker"}]})
                if path.startswith("/api/jobs?"):
                    return response(422)
                if path == "/api/messages":
                    return response(200, {"messages": [{"body": SECRET_PASSWORD}]})
                if path in acceptance.ADMIN_APIS + acceptance.ADMIN_PAGES:
                    allowed = user["role"] == "admin" or host.fault == "worker_admin_access"
                    return response(200 if allowed else 403, {"private": SECRET_PASSWORD})
                raise AssertionError("Unexpected test route")

        return Actor()


def accounts():
    return [acceptance.Account("private_admin", SECRET_PASSWORD, "admin"),
            acceptance.Account("private_worker", SECRET_PASSWORD, "worker")]


def run_fake(fault=None, supplied=True):
    host = FakeHost(fault)
    report = acceptance.run_checks("https://landscaping.example.test", accounts() if supplied else [],
                                   client_factory=host.client)
    return host, report


def test_success_uses_separate_sessions_cleans_up_and_never_writes_business_data():
    host, report = run_fake()
    assert report["status"] == "passed"
    assert report["worker_accounts_requested"] == 1
    assert not host.tokens
    assert host.counter == 2
    assert {path for method, path in host.requests if method != "GET"} == {"/api/login", "/api/logout"}
    assert "browser_rendering_and_cookie_enforcement" in report["not_verified"]


@pytest.mark.parametrize("fault,expected", [
    ("missing_secure", "account_0_admin_session_cookie_flags"),
    ("worker_admin_access", "account_1_worker_admin_apis_authorized_by_role"),
    ("logout_replay", "account_0_admin_logged_out_token_replay_denied"),
    ("private_schedule", "same_jobs_and_visible_crew_for_all_accounts"),
    ("crew_private_fields", "account_0_admin_shared_schedule_read"),
    ("missing_hsts", "public_security_headers_and_hsts"),
    ("catch_all", "public_dashboard_shell"),
    ("network", "tls_certificate_and_hostname_verified"),
])
def test_real_boundary_faults_fail_without_exposing_response_data(fault, expected):
    host, report = run_fake(fault)
    assert report["status"] == "failed"
    assert {"check": expected, "status": "failed"} in report["checks"]
    serialized = json.dumps(report)
    for private in (SECRET_PASSWORD, SECRET_TOKEN, SECRET_CSRF, "private_admin", "private_worker"):
        assert private not in serialized
    if fault in ("missing_hsts", "catch_all", "network"):
        assert host.counter == 0
        assert report["authenticated_checks"] == "not-run"
    elif fault != "logout_replay":
        assert not host.tokens


def test_public_only_receipt_marks_authentication_not_run():
    host, report = run_fake(supplied=False)
    assert report["status"] == "passed"
    assert report["authenticated_checks"] == "not-run"
    assert not host.counter


@pytest.mark.parametrize("url", ["http://example.test", "https://user:secret@example.test",
    "https://example.test/private", "https://example.test?", "https://example.test#fragment",
    "https://example.test\\@other.test", "https://example.test\n", "https://example.test:0",
    "https://example.test:65536", "https://example.test:", "https://%65xample.test",
    "https://[::1", "https://bad..host", "https://-bad.test"])
def test_invalid_or_ambiguous_origins_rejected(url):
    with pytest.raises(acceptance.SafeFailure):
        acceptance.validate_base_url(url)


@pytest.mark.parametrize("url", ["https://landscaping.example.com", "https://localhost:18790",
                                "https://127.0.0.1:18790", "https://[::1]:18790/"])
def test_explicit_https_origin_supported(url):
    assert acceptance.validate_base_url(url) == url.rstrip("/")


def private_file(tmp_path, content=None):
    path = tmp_path / "accounts.json"
    if content is None:
        content = json.dumps({"admin": {"username": "private_admin", "password": SECRET_PASSWORD},
                              "workers": [{"username": "private_worker", "password": SECRET_PASSWORD}]})
    path.write_text(content)
    path.chmod(0o600)
    return path


def test_private_accounts_validated_and_not_repr_disclosed(tmp_path):
    loaded = acceptance.load_accounts(private_file(tmp_path))
    assert len(loaded) == 2
    assert SECRET_PASSWORD not in repr(loaded)
    assert "private_admin" not in repr(loaded)


def test_shipped_layout_protects_the_entire_source_tree():
    assert Path(__file__).resolve().parents[3] in acceptance.SOURCE_ROOTS


@pytest.mark.parametrize("alias", [False, True])
def test_account_file_inside_source_rejected_before_open(tmp_path, monkeypatch, alias):
    source = tmp_path / "source"
    source.mkdir()
    accounts_path = private_file(source)
    monkeypatch.setattr(acceptance, "SOURCE_ROOTS", frozenset({source}))
    if alias:
        link = tmp_path / "source-alias"
        link.symlink_to(source, target_is_directory=True)
        accounts_path = link / accounts_path.name
    monkeypatch.setattr(acceptance.os, "open", lambda *a, **kw: pytest.fail("Source credentials must not be opened"))
    with pytest.raises(acceptance.SafeFailure, match="outside_source"):
        acceptance.load_accounts(accounts_path)


@pytest.mark.parametrize("alias", [False, True])
def test_receipt_inside_source_rejected_before_network_or_creation(tmp_path, monkeypatch, capsys, alias):
    source = tmp_path / "source"
    source.mkdir()
    destination = source / "docs" / "receipt.json"
    monkeypatch.setattr(acceptance, "SOURCE_ROOTS", frozenset({source}))
    if alias:
        link = tmp_path / "source-alias"
        link.symlink_to(source, target_is_directory=True)
        destination = link / "docs" / "receipt.json"
    monkeypatch.setattr(acceptance, "run_checks", lambda *a, **kw: pytest.fail("Network must not run"))
    assert acceptance.main(["--base-url", "https://landscaping.example.com", "--output", str(destination)]) == 2
    assert not destination.exists()
    assert str(source) not in capsys.readouterr().err


@pytest.mark.parametrize("fault", ["readable", "symlink", "hardlink", "directory", "duplicate_json", "duplicate_user"])
def test_unsafe_account_files_rejected(tmp_path, fault):
    path = private_file(tmp_path)
    if fault == "readable":
        path.chmod(0o644)
    elif fault == "symlink":
        link = tmp_path / "link"
        link.symlink_to(path)
        path = link
    elif fault == "hardlink":
        os.link(path, tmp_path / "link")
    elif fault == "directory":
        path = tmp_path
    elif fault == "duplicate_json":
        path.write_text('{"admin":{},"admin":{},"workers":[]}')
    elif fault == "duplicate_user":
        value = json.loads(path.read_text())
        value["workers"][0]["username"] = value["admin"]["username"]
        path.write_text(json.dumps(value))
    with pytest.raises(acceptance.SafeFailure):
        acceptance.load_accounts(path)


@pytest.mark.parametrize("cookie", [
    "HttpOnly; SameSite=Strict; Path=/", "Secure; SameSite=Strict; Path=/",
    "Secure; HttpOnly; SameSite=Lax; Path=/", "Secure; HttpOnly; SameSite=None; Path=/",
    "Secure; HttpOnly; SameSite=Strict; Path=/; Domain=.example.test",
    "Secure; HttpOnly; SameSite=Strict; Path=/api",
])
def test_cookie_boundary_regressions_are_detected(cookie):
    reply = response(200, **{"Set-Cookie": f"{acceptance.COOKIE_NAME}={SECRET_TOKEN}; {cookie}"})
    assert not acceptance.cookie_flags_ok(acceptance.session_cookie(reply))


def test_existing_output_refused_before_network_and_errors_do_not_print_paths_or_secrets(tmp_path, monkeypatch, capsys):
    out = tmp_path / SECRET_PASSWORD
    out.write_text("keep")
    monkeypatch.setattr(acceptance, "run_checks", lambda *args, **kwargs: pytest.fail("Network must not run"))
    code = acceptance.main(["--base-url", "https://example.test", "--output", str(out)])
    assert code == 2
    assert out.read_text() == "keep"
    captured = capsys.readouterr()
    assert SECRET_PASSWORD not in captured.err + captured.out


@pytest.fixture(scope="module")
def tls_server(tmp_path_factory):
    directory = tmp_path_factory.mktemp("https-protocol")
    cert, key = directory / "cert.pem", directory / "key.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                    "-keyout", str(key), "-out", str(cert), "-subj", "/CN=localhost",
                    "-addext", "subjectAltName=DNS:localhost"], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(302 if self.path == "/redirect" else 200)
            if self.path == "/redirect":
                self.send_header("Location", "https://unreachable.invalid/")
            self.end_headers()
            self.wfile.write(b"fictional response")

        def log_message(self, format, *args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_port, cert
    finally:
        server.shutdown()
        thread.join(5)
        server.server_close()


def test_real_https_rejects_untrusted_certificate_and_wrong_hostname(tls_server):
    port, cert = tls_server
    untrusted = acceptance.Client(f"https://localhost:{port}", ssl.create_default_context(), 5)
    with pytest.raises(acceptance.SafeFailure):
        untrusted.request("/")
    wrong_host = acceptance.Client(f"https://127.0.0.1:{port}", ssl.create_default_context(cafile=cert), 5)
    with pytest.raises(acceptance.SafeFailure):
        wrong_host.request("/")


def test_real_https_accepts_explicit_ca_and_never_follows_redirects(tls_server):
    port, cert = tls_server
    client = acceptance.Client(f"https://localhost:{port}", ssl.create_default_context(cafile=cert), 5)
    assert client.request("/").status == 200
    assert client.request("/redirect").status == 302


def test_custom_ca_receipt_is_labeled_rehearsal(tls_server):
    _, cert = tls_server
    report = acceptance.run_checks("https://localhost:18790/", [], ca_file=cert, client_factory=FakeHost().client)
    assert report["trust"] == "custom_ca_rehearsal"
    assert report["requested_base_url"] == "https://localhost:18790/"
