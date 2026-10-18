#!/usr/bin/env python3
"""Read-mostly HTTPS protocol checks against an explicitly selected pilot.

This runner never starts a server or modifies business records. Requests create
telemetry/audit records; optional sign-ins create sessions and logout deletes
those sessions. Use dedicated pilot accounts. It is not browser/UI, restore,
concurrency, penetration-test, or production-readiness evidence.

Accounts JSON (owner-only POSIX file, mode 0600):
{"admin":{"username":"admin","password":"..."},
 "workers":[{"username":"alex","password":"..."}]}
Supply one to five distinct workers. Never place this file in source control.
Keep both this credential file and the output receipt outside the entire source
directory. The runner is shipped at <source>/examples/landscaping/scripts/.
"""
from __future__ import annotations

import argparse
import http.cookiejar
import ipaddress
import json
import os
import re
import ssl
import stat
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from http.cookies import CookieError, SimpleCookie
from pathlib import Path

SOURCE_ROOTS = frozenset({Path(__file__).absolute().parents[3], Path(__file__).resolve().parents[3]})
COOKIE_NAME = "landscape_demo_session"
MAX_BODY = 2 * 1024 * 1024
ADMIN_APIS = ("/api/workers", "/api/admin/jobs", "/api/admin/customers",
              "/api/admin/health", "/api/admin/metrics")
ADMIN_PAGES = ("/admin/customers", "/admin/health", "/admin/metrics")
NOT_VERIFIED = ["browser_rendering_and_cookie_enforcement", "business_write_workflows",
                "live_account_revocation", "restart_persistence", "backup_and_restore",
                "concurrency", "production_readiness", "http_to_https_redirect_or_rejection",
                "backend_network_isolation", "managed_ingress_configuration", "source_ip_abuse_limiting"]


class SafeFailure(Exception):
    """A fixed internal error; never put a remote response in this exception."""


def outside_source(path: Path) -> Path:
    """Do not read private credentials or create receipts inside shipped source."""
    requested = Path(os.path.abspath(path))
    resolved = requested.resolve()
    if any(candidate == root or root in candidate.parents
           for root in SOURCE_ROOTS for candidate in (requested, resolved)):
        raise SafeFailure("private_files_must_stay_outside_source")
    return requested


def validate_base_url(value: str) -> str:
    """Accept an HTTPS origin only; never send credentials through redirects."""
    if (not isinstance(value, str) or not value.isascii() or len(value) > 300
            or any(char.isspace() or ord(char) < 32 for char in value)
            or any(char in value for char in "\\?#")):
        raise SafeFailure("invalid_base_url")
    try:
        parsed = urllib.parse.urlsplit(value)
        host = parsed.hostname
        port = parsed.port
        if (parsed.scheme != "https" or not value.startswith("https://") or not host
                or parsed.username is not None or parsed.password is not None
                or parsed.path not in ("", "/") or port == 0):
            raise ValueError
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if not all(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", part)
                       for part in host.split(".")):
                raise ValueError
        # Reject ambiguous empty ports and percent-encoded host/user syntax.
        if parsed.netloc.endswith(":") or "%" in parsed.netloc:
            raise ValueError
    except ValueError:
        raise SafeFailure("invalid_base_url") from None
    return value.removesuffix("/")


@dataclass(frozen=True)
class Account:
    username: str = field(repr=False)
    password: str = field(repr=False)
    role: str


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise SafeFailure("invalid_accounts_file")
        result[key] = value
    return result


def load_accounts(path: Path) -> list[Account]:
    """Check the opened descriptor, not a racy preliminary path stat."""
    if not hasattr(os, "getuid") or not hasattr(os, "O_NOFOLLOW"):
        raise SafeFailure("private_accounts_require_posix")
    try:
        path = outside_source(path)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as handle:
            info = os.fstat(handle.fileno())
            if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600
                    or info.st_uid != os.getuid() or info.st_nlink != 1 or info.st_size > 65536):
                raise SafeFailure("accounts_file_must_be_private")
            raw = handle.read(65537)
        if len(raw) > 65536:
            raise SafeFailure("invalid_accounts_file")
        value = json.loads(raw, object_pairs_hook=_unique_object)
        if (not isinstance(value, dict) or set(value) != {"admin", "workers"}
                or not isinstance(value["workers"], list) or not 1 <= len(value["workers"]) <= 5):
            raise SafeFailure("invalid_accounts_file")
        result = []
        for role, item in [("admin", value["admin"]), *[("worker", x) for x in value["workers"]]]:
            if (not isinstance(item, dict) or set(item) != {"username", "password"}
                    or not isinstance(item["username"], str)
                    or not re.fullmatch(r"[a-z][a-z0-9_]{2,31}", item["username"])
                    or not isinstance(item["password"], str)
                    or not 12 <= len(item["password"]) <= 128):
                raise SafeFailure("invalid_accounts_file")
            result.append(Account(item["username"], item["password"], role))
        if len({account.username for account in result}) != len(result):
            raise SafeFailure("duplicate_accounts")
        return result
    except (OSError, ValueError, TypeError, UnicodeError):
        raise SafeFailure("invalid_accounts_file") from None


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


@dataclass(repr=False)
class Response:
    status: int
    headers: object
    body: bytes

    def json(self):
        try:
            return json.loads(self.body)
        except (ValueError, UnicodeError):
            raise SafeFailure("invalid_json_response") from None


class Client:
    def __init__(self, base: str, context: ssl.SSLContext, timeout: float):
        self.base = base
        self.timeout = timeout
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=context),
            urllib.request.HTTPCookieProcessor(self.jar), NoRedirect(),
        )

    def request(self, path: str, *, method="GET", body=None, origin=None, csrf=None, token=None):
        headers = {"Accept": "application/json, text/html", "User-Agent": "cedar-stone-pilot-acceptance/1"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        if origin is not None:
            headers["Origin"] = origin
        if csrf is not None:
            headers["X-CSRF-Token"] = csrf
        if token is not None:
            headers["Cookie"] = COOKIE_NAME + "=" + token
        data = None if body is None else json.dumps(body).encode()
        request = urllib.request.Request(self.base + path, data=data, headers=headers, method=method)
        try:
            try:
                response = self.opener.open(request, timeout=self.timeout)
            except urllib.error.HTTPError as error:
                response = error
            with response:
                payload = response.read(MAX_BODY + 1)
                if len(payload) > MAX_BODY:
                    raise SafeFailure("response_too_large")
                return Response(response.code, response.headers, payload)
        except (OSError, urllib.error.URLError, ValueError):
            raise SafeFailure("request_failed") from None


def security_headers_ok(response: Response, *, hsts=False) -> bool:
    headers = response.headers
    cache = {item.strip().lower() for item in headers.get("Cache-Control", "").split(",")}
    required = {"default-src": {"'self'"}, "script-src": {"'self'"},
                "object-src": {"'none'"}, "base-uri": {"'none'"},
                "form-action": {"'self'"}, "frame-ancestors": {"'none'"}}
    directives = {}
    for directive in headers.get("Content-Security-Policy", "").split(";"):
        parts = directive.split()
        if parts:
            if parts[0].lower() in directives:
                return False
            directives[parts[0].lower()] = set(parts[1:])
    good = ("no-store" in cache
            and headers.get("X-Content-Type-Options", "").lower() == "nosniff"
            and headers.get("X-Frame-Options", "").upper() == "DENY"
            and headers.get("Referrer-Policy", "").lower() == "no-referrer"
            and all(directives.get(key) == tokens for key, tokens in required.items()))
    if hsts:
        age = re.search(r"(?:^|;)\s*max-age\s*=\s*(\d+)\s*(?:;|$)",
                        headers.get("Strict-Transport-Security", ""), re.IGNORECASE)
        good = good and age is not None and int(age.group(1)) >= 31536000
    return bool(good)


def session_cookie(response: Response):
    found = []
    for header in response.headers.get_all("Set-Cookie", []):
        cookie = SimpleCookie()
        try:
            cookie.load(header)
        except CookieError:
            raise SafeFailure("invalid_session_cookie") from None
        if COOKIE_NAME in cookie:
            found.append(cookie[COOKIE_NAME])
    if len(found) != 1 or not re.fullmatch(r"[A-Za-z0-9_-]{43}", found[0].value):
        raise SafeFailure("invalid_session_cookie")
    return found[0]


def cookie_flags_ok(cookie) -> bool:
    return bool(cookie["secure"] and cookie["httponly"]
                and cookie["samesite"].lower() == "strict"
                and cookie["path"] == "/" and not cookie["domain"])


def jobs_projection(response: Response):
    if response.status != 200:
        raise SafeFailure("schedule_unavailable")
    payload = response.json()
    if not isinstance(payload, dict) or not isinstance(payload.get("jobs"), list) or not payload["jobs"]:
        raise SafeFailure("nonempty_schedule_required")
    result = []
    for job in payload["jobs"]:
        if (not isinstance(job, dict) or not isinstance(job.get("id"), str)
                or not isinstance(job.get("crew"), list)
                or any(not isinstance(member, dict) or set(member) != {"display_name"}
                       for member in job["crew"])):
            raise SafeFailure("invalid_schedule_response")
        result.append({key: value for key, value in job.items() if key != "joined"})
    return sorted(result, key=lambda item: item["id"])


class Results:
    def __init__(self):
        self.items = []

    def check(self, name: str, operation: Callable[[], bool]) -> bool:
        try:
            passed = operation() is True
        except Exception:  # noqa: BLE001 - reports must never serialize remote exceptions
            passed = False
        self.items.append({"check": name, "status": "passed" if passed else "failed"})
        return passed

    def skip(self, name: str):
        self.items.append({"check": name, "status": "not-run"})


def run_checks(base: str, accounts: list[Account], *, ca_file=None, timeout=15.0,
               client_factory=Client) -> dict:
    requested_base = base
    base = validate_base_url(base)
    context = ssl.create_default_context(cafile=ca_file)
    results = Results()
    client = client_factory(base, context, timeout)
    wrong_origin = "https://cross-origin-pilot-probe.invalid"
    if base == wrong_origin:
        wrong_origin = "https://different-pilot-probe.invalid"
    public = None

    def get_public():
        nonlocal public
        public = client.request("/")
        return True

    reached = results.check("tls_certificate_and_hostname_verified", get_public)
    if reached:
        results.check("public_dashboard_shell", lambda: public.status == 200
                      and "text/html" in public.headers.get("Content-Type", "")
                      and b"Cedar & Stone" in public.body and b"/static/app.js" in public.body)
        results.check("public_security_headers_and_hsts", lambda: security_headers_ok(public, hsts=True))
        results.check("unauthenticated_private_apis_denied", lambda: all(
            (response := client.request(path)).status == 401 and security_headers_ok(response)
            for path in ("/api/session", "/api/jobs", "/api/messages", *ADMIN_APIS)))
        results.check("unauthenticated_admin_pages_redirect_to_login", lambda: all(
            (response := client.request(path)).status == 303
            and response.headers.get("Location") == "/" and security_headers_ok(response)
            for path in ADMIN_PAGES))
        results.check("cross_origin_login_denied_before_validation", lambda:
                      client.request("/api/login", method="POST", body={}, origin=wrong_origin).status == 403)
    else:
        for name in ("public_dashboard_shell", "public_security_headers_and_hsts",
                     "unauthenticated_private_apis_denied", "unauthenticated_admin_pages_redirect_to_login",
                     "cross_origin_login_denied_before_validation"):
            results.skip(name)

    # Do not submit supplied credentials if the public host does not match this
    # app's expected boundaries. A login gateway or catch-all page is not proof.
    public_ready = reached and all(item["status"] == "passed" for item in results.items)
    projections = []
    def check_account(index, account):
        label = f"account_{index}_{account.role}"
        actor = client_factory(base, context, timeout)
        login = None
        csrf = None
        token = None

        def sign_in():
            nonlocal login, csrf, token
            login = actor.request("/api/login", method="POST", origin=base,
                                  body={"username": account.username, "password": account.password})
            if login.status != 200:
                return False
            payload = login.json()
            if isinstance(payload, dict) and re.fullmatch(r"[a-f0-9]{64}", str(payload.get("csrf_token", ""))):
                csrf = payload["csrf_token"]
            token = session_cookie(login).value
            return (csrf is not None and payload.get("user", {}).get("username") == account.username
                    and payload.get("user", {}).get("role") == account.role)

        signed_in = results.check(label + "_login_identity", sign_in)
        if signed_in:
            results.check(label + "_session_cookie_flags", lambda: cookie_flags_ok(session_cookie(login)))
            results.check(label + "_authenticated_security_headers", lambda: security_headers_ok(login))

            def session_identity():
                response = actor.request("/api/session")
                if response.status != 200 or not security_headers_ok(response):
                    return False
                user = response.json().get("user", {})
                return user.get("username") == account.username and user.get("role") == account.role

            results.check(label + "_separate_session_identity", session_identity)

            def shared_jobs():
                projection = jobs_projection(actor.request("/api/jobs"))
                projections.append(projection)
                return True

            results.check(label + "_shared_schedule_read", shared_jobs)
            results.check(label + "_shared_message_board_read", lambda:
                          (response := actor.request("/api/messages")).status == 200
                          and isinstance(response.json().get("messages"), list))
            expected = 200 if account.role == "admin" else 403
            results.check(label + "_admin_apis_authorized_by_role", lambda: all(
                (response := actor.request(path)).status == expected and security_headers_ok(response)
                for path in ADMIN_APIS))
            results.check(label + "_admin_pages_authorized_by_role", lambda: all(
                actor.request(path).status == expected for path in ADMIN_PAGES))
            if account.role == "worker":
                results.check(label + "_account_selector_rejected", lambda:
                              actor.request("/api/jobs?worker_id=hosted_acceptance_probe").status == 422)
            results.check(label + "_logout_without_csrf_denied", lambda:
                          actor.request("/api/logout", method="POST", body={}, origin=base).status == 403
                          and actor.request("/api/session").status == 200)
            results.check(label + "_cross_origin_logout_denied", lambda:
                          actor.request("/api/logout", method="POST", body={}, origin=wrong_origin,
                                        csrf=csrf).status == 403
                          and actor.request("/api/session").status == 200)
        else:
            results.skip(label + "_authenticated_checks")
        # Even a failed identity/cookie check must attempt to end its session.
        if csrf is not None:
            results.check(label + "_logout", lambda:
                          actor.request("/api/logout", method="POST", body={}, origin=base, csrf=csrf).status == 200)
            if token is not None:
                replay = client_factory(base, context, timeout)
                results.check(label + "_logged_out_token_replay_denied", lambda:
                              replay.request("/api/session", token=token).status == 401)
            else:
                results.skip(label + "_logged_out_token_replay_denied")
        elif login is not None and login.status == 200:
            results.check(label + "_session_cleanup_unavailable", lambda: False)
        else:
            results.skip(label + "_logout")

    if public_ready and accounts:
        for index, account in enumerate(accounts):
            check_account(index, account)
        results.check("same_jobs_and_visible_crew_for_all_accounts", lambda:
                      len(projections) == len(accounts) and all(item == projections[0] for item in projections))
    else:
        results.skip("authenticated_account_checks")
        results.skip("same_jobs_and_visible_crew_for_all_accounts")

    return {"schema_version": 1, "base_url": base, "requested_base_url": requested_base,
            "checked_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "scope": "https_protocol_read_only_business_data",
            "trust": "custom_ca_rehearsal" if ca_file else "client_default_ca_store",
            "status": "failed" if any(item["status"] == "failed" for item in results.items) else "passed",
            "authenticated_checks": "attempted" if public_ready and accounts else "not-run",
            "worker_accounts_requested": sum(account.role == "worker" for account in accounts),
            "effects": ["request_telemetry_and_denial_audit", "optional_login_logout_session_and_audit_records"],
            "checks": results.items, "not_verified": NOT_VERIFIED}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--base-url", required=True, help="Exact HTTPS origin; redirects are never followed")
    parser.add_argument("--output", required=True, type=Path, help="New JSON receipt outside source; never overwrite an existing file")
    parser.add_argument("--accounts-file", type=Path, help="Private owner-only mode-0600 accounts JSON outside source (POSIX)")
    parser.add_argument("--ca-file", type=Path, help="Custom CA PEM for local rehearsal; not public-host proof")
    parser.add_argument("--timeout", type=float, default=15, help="Per-request timeout, 1 to 60 seconds")
    options = parser.parse_args(argv)
    try:
        validate_base_url(options.base_url)
        if not 1 <= options.timeout <= 60:
            raise SafeFailure("invalid_timeout")
        output = outside_source(options.output)
        accounts = load_accounts(options.accounts_file) if options.accounts_file else []
        # Validate trust configuration before reserving output or sending requests.
        ssl.create_default_context(cafile=options.ca_file)
        fd = os.open(output, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            report = run_checks(options.base_url, accounts, ca_file=options.ca_file, timeout=options.timeout)
            json.dump(report, handle, indent=2)
            handle.write("\n")
        counts = {status: sum(item["status"] == status for item in report["checks"])
                  for status in ("passed", "failed", "not-run")}
        print("HTTPS protocol checks: " + ", ".join(f"{count} {status}" for status, count in counts.items()))
        return 0 if report["status"] == "passed" else 1
    except Exception:  # noqa: BLE001 - final privacy boundary for command-line failures
        # Never print exception text, remote bodies, cookies, accounts, or paths.
        print("Acceptance configuration or output failed; verify HTTPS URL, CA, and private accounts/new output paths outside source.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
