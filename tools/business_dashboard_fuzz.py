"""Seeded, bounded security fuzzing of a disposable business dashboard.

Uses the real ASGI application and a mocked challenge provider. There is no
remote-target or existing-data option. Reports never include account secrets.
"""

from __future__ import annotations

import argparse
from collections import Counter
from contextlib import ExitStack, redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import random
import tempfile
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
ORIGIN = "https://business-fuzz.invalid"
FAMILIES = ("cookie", "role", "csrf", "origin", "authority", "schema", "body", "login", "challenge")
TABLES = ("users", "settings", "submissions", "posts", "events", "assignments",
          "messages", "contacts", "activity", "revenue", "admin_mfa", "session_mfa")
TEXT = ("Ordinary notice", "<svg onload=alert(1)>", "' OR 1=1 --", "[link](javascript:alert(1))",
        "\u202eReversed text", "\x00Embedded null", "雪 café", "a" * 120)


class FuzzFailure(Exception):
    """Only sanitized oracle diagnostics may cross the runner boundary."""

    def __init__(self, invariant, **details):
        self.details = {"invariant": invariant, **details}
        super().__init__(invariant)


class Campaign:
    def __init__(self, seed, cases):
        self.rng = random.Random(seed)
        self.seed, self.cases = seed, cases
        self.requests = 0
        self.counts = Counter()
        self.index, self.family = -1, "setup"
        self.provider_calls = 0
        self.provider_body = None
        self.provider_status = 200

    def require(self, condition, invariant, **details):
        if not condition:
            raise FuzzFailure(invariant, **details)

    def noise(self, length):
        return "".join(self.rng.choices("abcXYZ019 <>\"'&/\\雪é\u202e", k=length))

    def request(self, actor, method, path, expected, *, payload=None, headers=None, content=None):
        self.requests += 1
        request_headers = {"Origin": ORIGIN, "Content-Type": "application/json"}
        if actor in self.csrf:
            request_headers["X-CSRF-Token"] = self.csrf[actor]
        if headers:
            for key, value in headers.items():
                if value is None:
                    request_headers.pop(key, None)
                else:
                    request_headers[key] = value
        kwargs = {"headers": request_headers}
        if content is not None:
            kwargs["content"] = content
        elif payload is not None:
            # ensure_ascii deliberately permits raw JSON surrogate mutations.
            kwargs["content"] = json.dumps(payload, ensure_ascii=True, allow_nan=False).encode()
        response = self.clients[actor].request(method, path, **kwargs)
        allowed = expected if isinstance(expected, tuple) else (expected,)
        self.require(response.status_code in allowed, "unexpected_status", method=method,
                     route=path, expected=expected, actual=response.status_code)
        return response

    def snapshot(self):
        with self.app.state.database.transaction() as connection:
            rows = tuple(tuple(tuple(row) for row in connection.execute(f"SELECT * FROM {table} ORDER BY 1"))
                         for table in TABLES)
            # last_seen legitimately changes during authenticated reads.
            sessions = tuple(tuple(row) for row in connection.execute(
                "SELECT token_hash,user_id,created_at,expires_at FROM sessions ORDER BY token_hash"))
            return rows, sessions

    def denied(self, actor, method, path, expected, **kwargs):
        before = self.snapshot()
        result = self.request(actor, method, path, expected, **kwargs)
        self.require(self.snapshot() == before, "denied_request_changed_persisted_state", route=path)
        return result

    def controls(self):
        self.request("guest", "GET", "/healthz", 200)
        board = self.request("guest", "GET", "/api/public/posts", 200).json()
        self.require(board["submission_challenge"]["required"] is True, "challenge_was_not_required")
        self.require({p["id"] for p in board["posts"]} == self.public_ids, "unexpected_publication")
        self.require(all(set(p) == {"id", "title", "body", "category", "published_at"}
                         for p in board["posts"]), "public_projection_contains_private_fields")
        self.request("employee", "GET", "/api/schedule", 200)
        self.request("admin", "GET", "/api/admin/overview", 200)

    def submission(self):
        return {"title": "Fuzz notice " + str(self.rng.getrandbits(32)),
                "body": self.rng.choice(TEXT) + " " + self.noise(self.rng.randrange(1, 160)),
                "accept_rules": True, "rules_version": self.rules_version, "turnstile_token": "fixture-token"}

    def post(self):
        return {"title": "Fuzz post", "body": self.rng.choice(TEXT) + self.noise(self.rng.randrange(1, 160)),
                "category": "Company", "published": True}

    def negative_case(self):
        rng, family = self.rng, self.family
        if family == "cookie":
            token = rng.choice(("", "admin", "null", "a" * 42, "a" * 44,
                                "eyJhbGciOiJub25lIn0.eyJyb2xlIjoiYWRtaW4ifQ.",
                                "".join(rng.choices("abcdefghijklmnopqrstuvwxyz0123456789_-", k=43))))
            self.denied("guest", "GET", rng.choice(("/api/messages", "/api/admin/users", "/api/schedule")),
                        401, headers={"Cookie": f"{self.cookie_name}={token}", "X-Role": "admin"})
        elif family == "role":
            role_headers = {"X-Role": "admin", "X-User-ID": "admin", "Authorization": "Bearer admin"}
            method, path, body = rng.choice((
                ("GET", "/api/admin/overview", None), ("GET", "/api/admin/submissions", None),
                ("POST", "/api/admin/posts", self.post()),
                ("POST", "/api/admin/freeze", {"frozen": True, "revision": 0}),
                ("PUT", "/api/admin/users/blair", {"active": False, "revision": 0}),
                ("POST", "/api/admin/posts/post-1/unpublish", {"revision": 0}),
            ))
            actor = rng.choice(("guest", "employee"))
            self.denied(actor, method, path, 401 if actor == "guest" else 403, payload=body, headers=role_headers)
        elif family == "csrf":
            value = rng.choice((None, "", "wrong", self.csrf["employee"],
                                "".join(rng.choices("0123456789abcdef", k=rng.choice((1, 63, 64, 65, 128))))))
            self.denied("admin", "POST", "/api/admin/posts", 403, payload=self.post(),
                        headers={"X-CSRF-Token": value})
        elif family == "origin":
            value = rng.choice((None, "null", ORIGIN + ".evil.invalid", ORIGIN + "/", "http://business-fuzz.invalid"))
            headers = rng.choice(({"Origin": value}, {"Sec-Fetch-Site": "cross-site"}))
            self.denied("admin", "POST", "/api/admin/posts", 403, payload=self.post(), headers=headers)
        elif family == "authority":
            actor, path, payload = rng.choice((
                ("guest", "/api/public/submissions", self.submission()),
                ("employee", "/api/messages", {"body": "A team message"}),
                ("admin", "/api/admin/posts", self.post()),
            ))
            payload[rng.choice(("role", "author_id", "owner", "is_admin", "approved"))] = rng.choice((True, "admin", 1, {}))
            self.denied(actor, "POST", path, 422, payload=payload)
        elif family == "schema":
            payload = self.post()
            field = rng.choice(("published", "title", "body", "category"))
            bad = {"published": (None, 0, 1, "true", [], {}),
                   "title": (None, 3, [], {}, "", " " * 5, "x" + self.noise(rng.randrange(121, 512)) + "x", chr(rng.randrange(0xD800, 0xE000))),
                   "body": (None, False, [], {}, "", "x" + self.noise(rng.randrange(4001, 4200)) + "x", "\udfff"),
                   "category": (None, True, [], {}, "", "x" + self.noise(rng.randrange(41, 128)) + "x")}
            payload[field] = rng.choice(bad[field])
            self.denied("admin", "POST", "/api/admin/posts", 422, payload=payload)
        elif family == "body":
            body, status, headers = rng.choice((
                (b'{"body":', 422, {}), (b"\xff" * rng.randrange(1, 20), 400, {}), (b"[]", 422, {}),
                (b"null", 422, {}), (b"{}", 422, {}),
                (b"x" * rng.randrange(32769, 34000), 413, {}), (b"body=hello", 415, {"Content-Type": "application/x-www-form-urlencoded"}),
                # A parser recursion limit can reject this JSON with 400;
                # parsers that decode it reach the object schema's 422.
                # Both reject this one payload, with no persisted mutation.
                (b"[" * 1500 + b"0" + b"]" * 1500, (400, 422), {}),
            ))
            self.denied("employee", "POST", "/api/messages", status, content=body, headers=headers)
        elif family == "login":
            payload = {"username": "admin", "password": "Fictional invalid password", "otp": "123456"}
            field = rng.choice(("username", "password", "otp", "role"))
            values = {"username": (None, [], {}, 1, "", "x" + self.noise(rng.randrange(65, 128)) + "x", "\ud800"),
                      "password": (None, [], {}, True, "", self.noise(rng.randrange(129, 512)), "\udfff"),
                      "otp": (123456, [], {}, "", "12345", "1234567", "abcdef"),
                      "role": ("admin", True, {})}
            payload[field] = rng.choice(values[field])
            self.denied("guest", "POST", "/api/login", 422, payload=payload)
        else:
            payload = self.submission()
            variant = rng.randrange(7)
            valid = {"success": True, "hostname": "business-fuzz.invalid", "action": "guest_submission"}
            outcomes = ({**valid, "success": False}, {**valid, "success": "true"},
                        {**valid, "hostname": "other.invalid"}, {**valid, "action": "login"}, [])
            if variant < 5:
                self.provider_body, expected = json.dumps(outcomes[variant]).encode(), 403
            elif variant == 5:
                self.provider_body, expected = b"not-json", 503
            else:
                payload["turnstile_token"], expected = rng.choice((None, "", "bad token", "雪", "x" * 2049)), 422
            before_calls = self.provider_calls
            self.denied("guest", "POST", "/api/public/submissions", expected, payload=payload)
            self.require(self.provider_calls == before_calls + (variant != 6), "challenge_guard_not_exercised")
            self.provider_body = None

    def lifecycle(self):
        self.family, self.index = "moderation_sequence", -1
        decisions = ["approve", "reject"]
        self.rng.shuffle(decisions)
        for decision in decisions:
            payload = self.submission()
            self.request("guest", "POST", "/api/public/submissions", 202, payload=payload)
            self.controls()  # Pending text must not appear publicly.
            queue = self.request("admin", "GET", "/api/admin/submissions", 200).json()["submissions"]
            item = next(item for item in queue if item["title"] == payload["title"])
            self.require(item["body"] == payload["body"].strip(), "submission_text_changed")
            route = f'/api/admin/submissions/{item["id"]}/review'
            review = {"decision": decision, "revision": item["revision"]}
            self.denied("employee", "POST", route, 403, payload=review)
            self.request("admin", "POST", route, 200, payload=review)
            self.denied("admin", "POST", route, 409, payload=review)
            with self.app.state.database.transaction() as connection:
                row = connection.execute("SELECT status,post_id FROM submissions WHERE id=?", (item["id"],)).fetchone()
            self.require(row["status"] == ("approved" if decision == "approve" else "rejected"), "wrong_moderation_state")
            if decision == "approve":
                self.require(bool(row["post_id"]), "approved_submission_has_no_post")
                self.public_ids.add(row["post_id"])
            else:
                self.require(row["post_id"] is None, "rejected_submission_has_post")
            self.controls()

        self.family = "freeze_sequence"
        self.request("admin", "POST", "/api/admin/freeze", 200, payload={"frozen": True, "revision": 0})
        self.denied("employee", "POST", "/api/messages", 403, payload={"body": "Frozen message"})
        self.denied("guest", "POST", "/api/public/submissions", 503, payload=self.submission())
        self.request("admin", "POST", "/api/admin/freeze", 200, payload={"frozen": False, "revision": 1})
        self.request("employee", "POST", "/api/messages", 201, payload={"body": "Valid message after resume"})

        self.family = "session_sequence"
        client = self.clients["employee"]
        old = client.cookies.get(self.cookie_name)
        self.login("employee", "alex")
        self.denied("guest", "GET", "/api/messages", 401, headers={"Cookie": f"{self.cookie_name}={old}"})
        active = client.cookies.get(self.cookie_name)
        self.request("employee", "POST", "/api/logout", 200, payload={})
        self.denied("guest", "GET", "/api/messages", 401, headers={"Cookie": f"{self.cookie_name}={active}"})
        self.login("employee", "alex")
        self.controls()
        with self.app.state.database.transaction() as connection:
            self.require(connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok", "database_integrity")

    def verification_budget_sequence(self):
        from business.submission_routes import PEER_ATTEMPT_LIMIT

        self.family, self.index = "verification_budget_sequence", -1
        self.advance_verification_window()
        self.provider_body = json.dumps({"success": False}).encode()
        calls = self.provider_calls
        for _ in range(PEER_ATTEMPT_LIMIT):
            self.denied("guest", "POST", "/api/public/submissions", 403, payload=self.submission())
        self.denied("guest", "POST", "/api/public/submissions", 429, payload=self.submission(),
                    headers={"X-Forwarded-For": "198.51.100.99", "CF-Connecting-IP": "203.0.113.88"})
        self.require(self.provider_calls == calls + PEER_ATTEMPT_LIMIT, "verification_budget_not_enforced")
        self.provider_body = None
        self.advance_verification_window()

    def advance_verification_window(self):
        from business.submission_routes import ATTEMPT_WINDOW_SECONDS

        # Vary inputs in fresh logical windows so rate limiting cannot mask
        # their guard. The separate burst sequence proves the limit itself.
        self.verification_clock[0] += ATTEMPT_WINDOW_SECONDS + 1

    def login(self, actor, username, otp=None):
        payload = {"username": username, "password": self.credentials[username]}
        if otp is not None:
            payload["otp"] = otp
        response = self.request(actor, "POST", "/api/login", 200, payload=payload)
        self.csrf[actor] = response.json()["csrf"]

    def execute(self):
        import sys
        sys.path.insert(0, str(ROOT / "examples" / "business_dashboard"))
        import httpx
        import pyotp
        from fastapi.testclient import TestClient
        from business import abuse, mfa, submission_routes
        from business.app import create_app
        from business.security import COOKIE_NAME
        from business.seed import provision

        real_client = httpx.Client

        def provider(request):
            self.require(str(request.url) == abuse.SITEVERIFY_URL, "unexpected_provider_destination")
            self.provider_calls += 1
            body = self.provider_body
            if body is None:
                body = json.dumps({"success": True, "hostname": "business-fuzz.invalid", "action": "guest_submission"}).encode()
            return httpx.Response(self.provider_status, stream=httpx.ByteStream(body))

        def provider_client(**kwargs):
            return real_client(transport=httpx.MockTransport(provider), **kwargs)

        with tempfile.TemporaryDirectory(prefix="radt-business-fuzz-data-") as temporary, ExitStack() as stack:
            directory = Path(temporary).resolve()
            self.require(not directory.is_relative_to(ROOT), "temporary_data_inside_checkout")
            with redirect_stdout(io.StringIO()):
                self.credentials = provision(directory / "private")
            stack.enter_context(patch.dict("os.environ", {
                "BUSINESS_TURNSTILE_SITE_KEY": "fictional-fuzz-site-key",
                "BUSINESS_TURNSTILE_SECRET_KEY": "fictional-fuzz-secret-key",
            }))
            stack.enter_context(patch.object(abuse.httpx, "Client", provider_client))
            self.verification_clock = [submission_routes.current_time()]
            stack.enter_context(patch.object(submission_routes, "current_time", lambda: self.verification_clock[0]))
            self.app = create_app(directory / "private", public_origin=ORIGIN)
            self.clients = {actor: stack.enter_context(TestClient(self.app, base_url=ORIGIN, raise_server_exceptions=False))
                            for actor in ("guest", "employee", "admin")}
            self.csrf, self.cookie_name = {}, COOKIE_NAME
            self.rules_version = abuse.PUBLIC_RULES["version"]
            with self.app.state.database.transaction() as connection:
                enrollment = connection.execute("SELECT * FROM admin_mfa WHERE user_id='admin'").fetchone()
                secret = self.app.state.database.mfa_secrets.decrypt(enrollment["secret_ciphertext"], "admin", enrollment["generation"])
            moment = mfa.current_time()
            stack.enter_context(patch.object(mfa, "current_time", lambda: moment))
            otp = pyotp.TOTP(secret).at(moment)
            self.denied("guest", "POST", "/api/login", 401,
                        payload={"username": "admin", "password": self.credentials["admin"]})
            self.login("admin", "admin", otp)
            self.denied("guest", "POST", "/api/login", 401,
                        payload={"username": "admin", "password": self.credentials["admin"], "otp": otp})
            self.login("employee", "alex")
            self.public_ids = {"post-1", "post-2", "post-3"}
            self.controls()
            for offset in range(0, self.cases, len(FAMILIES)):
                self.advance_verification_window()
                families = list(FAMILIES)
                self.rng.shuffle(families)
                for self.index in range(offset, min(offset + len(FAMILIES), self.cases)):
                    self.family = families[self.index - offset]
                    self.negative_case()
                    self.counts[self.family] += 1
                self.controls()
            self.verification_budget_sequence()
            self.lifecycle()


def run_campaign(*, seed=20261019, cases=500):
    if type(seed) is not int or not 0 <= seed <= 2**32 - 1:
        raise ValueError("seed must be an integer between 0 and 4294967295")
    if type(cases) is not int or not len(FAMILIES) <= cases <= 10000:
        raise ValueError("cases must be an integer between 9 and 10000")
    campaign = Campaign(seed, cases)
    source = hashlib.sha256()
    source_files = [Path(__file__).resolve()]
    for directory in (ROOT / "role_aware_dashboard_toolkit", ROOT / "examples" / "business_dashboard" / "business"):
        source_files.extend(directory.rglob("*.py"))
    for path in sorted(source_files):
        source.update(path.relative_to(ROOT).as_posix().encode() + b"\0")
        source.update(path.read_bytes() + b"\0")
    report = {"passed": False, "seed": seed, "requested_cases": cases,
              "source_sha256": source.hexdigest(),
              "scope": "in-process fictional dashboard; mocked required challenge; no live traffic"}
    try:
        campaign.execute()
        report["passed"] = True
    except FuzzFailure as error:
        report["failure"] = {"case": campaign.index, "family": campaign.family, **error.details}
    except Exception as error:
        # No exception message/body: provider and auth failures can contain secrets.
        report["failure"] = {"case": campaign.index, "family": campaign.family,
                             "invariant": "runner_or_application_exception", "type": type(error).__name__}
    report.update(requests=campaign.requests, completed_cases=sum(campaign.counts.values()),
                  families=dict(campaign.counts), mocked_provider_calls=campaign.provider_calls)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=20261019)
    parser.add_argument("--cases", type=int, default=500)
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args(argv)
    if not 0 <= args.seed <= 2**32 - 1 or not 9 <= args.cases <= 10000:
        parser.error("seed must be 0..4294967295 and cases must be 9..10000")
    output = args.output_dir or Path(tempfile.mkdtemp(prefix="radt-business-fuzz-report-"))
    output = output.resolve()
    if output.is_relative_to(ROOT) or (output.exists() and (not output.is_dir() or any(output.iterdir()))):
        parser.error("output directory must be empty and outside the checkout")
    output.mkdir(parents=True, exist_ok=True)
    report = run_campaign(seed=args.seed, cases=args.cases)
    with (output / "summary.json").open("x", encoding="utf-8") as report_file:
        report_file.write(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))
    print(f"Report: {output / 'summary.json'}")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
