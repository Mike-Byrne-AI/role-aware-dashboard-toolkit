"""Exercise real local login races with disposable accounts and virtual WebAuthn."""

from contextlib import ExitStack
from pathlib import Path
import argparse
import hashlib
import json
import socket
import sys
import tempfile
import time
import traceback
from unittest.mock import patch

if not __debug__:
    raise SystemExit("Login race evidence requires assertions; do not use optimized Python.")

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "examples" / "business_dashboard"))


def exercise(browser, url, application, credentials, clock, output, checks):
    import httpx
    import pyotp
    from playwright.sync_api import expect
    from tools.business_dashboard_browser import synthetic_account_enrollment

    database = application.state.database
    contexts, errors, pending, observations = [], [], [], []
    credential = None

    def code(username):
        secret, counter = synthetic_account_enrollment(database.directory, username)
        clock["now"] = max(clock["now"], (counter + 1) * 30)
        return pyotp.TOTP(secret).at(clock["now"])

    def new_context():
        context = browser.new_context(viewport={"width": 1440, "height": 1050})
        context.set_default_timeout(10000)
        context.add_init_script("""(() => {
          const original=window.fetch.bind(window);let settled=0;
          window.fetch=async (...args)=>{
            const response=await original(...args);
            if(['/api/login','/api/passkeys/login/verify'].includes(args[0])){
              const json=response.json.bind(response);
              response.json=async()=>{try{return await json();}finally{
                setTimeout(()=>document.documentElement.setAttribute('data-login-settled',String(++settled)),0);
              }};
            }
            return response;
          };
        })();""")
        contexts.append(context)
        return context

    def page_in(context):
        page = context.new_page()
        page.on("pageerror", lambda error: errors.append(type(error).__name__))
        page.goto(url)
        return page

    def device(page, *, copy=True):
        protocol = page.context.new_cdp_session(page)
        protocol.send("WebAuthn.enable")
        identifier = protocol.send("WebAuthn.addVirtualAuthenticator", {"options": {
            "protocol": "ctap2", "transport": "internal", "hasResidentKey": True,
            "hasUserVerification": True, "isUserVerified": True, "automaticPresenceSimulation": True,
        }})["authenticatorId"]
        if copy:
            protocol.send("WebAuthn.addCredential", {"authenticatorId": identifier, "credential": credential})
        return protocol, identifier

    def keep_counter(devices):
        nonlocal credential
        for protocol, identifier in devices:
            rows = protocol.send("WebAuthn.getCredentials", {"authenticatorId": identifier})["credentials"]
            for row in rows:
                if credential is None or row["signCount"] > credential["signCount"]:
                    credential = row

    def start(page, username, method):
        if method == "passkey":
            page.get_by_role("button", name="Sign in with a passkey", exact=True).click()
        else:
            page.get_by_label("Username", exact=True).fill(username)
            page.get_by_label("Password", exact=True).fill(credentials[username])
            page.get_by_label("Authenticator code", exact=True).fill(code(username))
            page.get_by_role("button", name="Sign in", exact=True).click()

    def wait_held(page, held):
        deadline = time.monotonic() + 10
        while not held and time.monotonic() < deadline:
            page.wait_for_timeout(20)
        assert len(held) == 1, "Expected exactly one held credential-changing request"

    def intercept(page, method):
        held = []
        endpoint = "/api/passkeys/login/verify" if method == "passkey" else "/api/login"
        def hold(route):
            held.append(route)
            pending.append(route)
        page.route("**" + endpoint, hold)
        return held

    def commit(route):
        request = route.request
        headers = {key: value for key, value in request.all_headers().items()
                   if key in ("origin", "cookie", "content-type", "x-csrf-token", "x-login-csrf", "sec-fetch-site")}
        # An isolated client prevents route.fetch from applying Set-Cookie to
        # the browser's shared API jar before the intentionally delayed reply.
        with httpx.Client(trust_env=False, timeout=10) as client:
            response = client.request(request.method, request.url, headers=headers, content=request.post_data)
        observations.append({"request": len(observations) + 1, "status": response.status_code,
                             "set_cookie": "set-cookie" in response.headers,
                             "passkey": request.url.endswith("/api/passkeys/login/verify")})
        return response

    def release(route, response):
        route.fulfill(status=response.status_code, body=response.content,
                      headers={key: value for key, value in response.headers.items()
                               if key in ("content-type", "set-cookie", "cache-control")})
        pending.remove(route)

    def settled(page, previous=None):
        if previous is None:
            expect(page.locator("html")).to_have_attribute("data-login-settled", "1")
        else:
            expect(page.locator("html")).not_to_have_attribute("data-login-settled", previous)

    def session(context):
        return context.request.get(url + "/api/session").json()

    def assert_dead_cookie(response):
        cookie = response.headers["set-cookie"].split(";", 1)[0]
        with httpx.Client(trust_env=False, timeout=5) as client:
            assert client.get(url + "/api/messages", headers={"Cookie": cookie}).status_code == 401

    def record(identifier, description):
        checks.append({"id": identifier, "status": "passed", "description": description})

    try:
        context = new_context()
        setup = page_in(context)
        protocol, identifier = device(setup, copy=False)
        start(setup, "admin", "password")
        expect(setup.get_by_role("button", name="Sign out", exact=True)).to_be_visible()
        setup.get_by_role("button", name="Security & recovery", exact=True).click()
        setup.get_by_role("button", name="Manage your passkeys", exact=True).click()
        dialog = setup.locator("#passkey-dialog")
        dialog.get_by_label("Passkey name", exact=True).fill("Disposable login race authenticator")
        dialog.get_by_role("button", name="Add a passkey", exact=True).click()
        expect(dialog.get_by_role("heading", name="Disposable login race authenticator", exact=True)).to_be_visible()
        keep_counter([(protocol, identifier)])
        assert credential is not None
        context.close()
        contexts.remove(context)

        # Both forms capture the same generation before either final proof is
        # delivered. Exercise both mixed-method orders with real signatures.
        for first_method, second_method in (("password", "password"), ("passkey", "password"),
                                            ("password", "passkey"), ("passkey", "passkey")):
            context = new_context()
            first, second = page_in(context), page_in(context)
            devices = [device(page) for page, method in ((first, first_method), (second, second_method))
                       if method == "passkey"]
            held_first, held_second = intercept(first, first_method), intercept(second, second_method)
            first_user = "admin" if first_method == "passkey" else "alex"
            second_user = "admin" if second_method == "passkey" else "blair"
            start(first, first_user, first_method)
            wait_held(first, held_first)
            start(second, second_user, second_method)
            wait_held(second, held_second)
            before = context.cookies()
            if first_method == second_method == "passkey":
                superseded = commit(held_first[0])
                assert superseded.status_code in (401, 403) and "set-cookie" not in superseded.headers
                winner = commit(held_second[0])
                assert winner.status_code == 200 and context.cookies() == before
                release(held_first.pop(), superseded)
                release(held_second.pop(), winner)
                expect(first.locator("#login-error")).to_be_visible()
                expect(second.get_by_role("button", name="Sign out", exact=True)).to_be_visible()
                assert session(context)["user"]["id"] == second_user
                keep_counter(devices)
                record("same_generation_passkey_challenge_replaced",
                       "The later challenge replaces its generation's earlier challenge; only the currently eligible actual assertion succeeds")
                context.close()
                contexts.remove(context)
                continue
            winner = commit(held_first[0])
            assert winner.status_code == 200
            assert context.cookies() == before, "Isolated proof transport changed the browser cookie jar"
            loser = commit(held_second[0])
            assert loser.status_code == 409 and "set-cookie" not in loser.headers
            release(held_first.pop(), winner)
            expect(first.get_by_role("button", name="Sign out", exact=True)).to_be_visible()
            release(held_second.pop(), loser)
            expect(second.locator("#login-error")).to_contain_text("changed or expired")
            assert session(context)["user"]["id"] == first_user
            keep_counter(devices)
            record(f"same_generation_{first_method}_{second_method}",
                   "The first actual credential proof commits; the competing captured generation is rejected without Set-Cookie")
            context.close()
            contexts.remove(context)

        # A successful response is deliberately withheld while another tab
        # reads a newer generation and signs in. The late cookie must be dead.
        for first_method, second_method in (("password", "password"), ("passkey", "password"), ("password", "passkey")):
            context = new_context()
            first, second = page_in(context), page_in(context)
            devices = [device(page) for page, method in ((first, first_method), (second, second_method))
                       if method == "passkey"]
            held = intercept(first, first_method)
            start(first, "admin" if first_method == "passkey" else "alex", first_method)
            wait_held(first, held)
            original_jar = context.cookies()
            earlier = commit(held[0])
            assert earlier.status_code == 200 and context.cookies() == original_jar
            expected = "admin" if second_method == "passkey" else "blair"
            start(second, expected, second_method)
            expect(second.get_by_role("button", name="Sign out", exact=True)).to_be_visible()
            assert session(context)["user"]["id"] == expected
            assert_dead_cookie(earlier)
            release(held.pop(), earlier)
            expect(first.locator("#login-error")).to_contain_text("changed or expired")
            current = session(context)
            assert current["user"] is None or current["user"]["id"] == expected
            expect(first.get_by_role("button", name="Sign out", exact=True)).to_have_count(0)
            assert context.request.get(url + "/api/admin/overview").status in (401, 403) or expected == "admin"
            keep_counter(devices)
            record(f"late_success_{first_method}_{second_method}",
                   "A deliberately newer login revokes the withheld earlier root; actual late Set-Cookie cannot restore it and its UI reconciles")
            context.close()
            contexts.remove(context)

        context = new_context()
        first, second = page_in(context), page_in(context)
        start(first, "alex", "password")
        expect(first.get_by_role("button", name="Sign out", exact=True)).to_be_visible()
        earlier = session(context)
        # This page was rendered anonymously before its sibling installed S.
        start(second, "blair", "password")
        expect(second.get_by_role("button", name="Sign out", exact=True)).to_be_visible()
        later = session(context)
        assert later["user"]["id"] == "blair" and later["session_id"] != earlier["session_id"]
        record("anonymous_view_observes_installed_session",
               "An already-rendered anonymous page reads installed authority and supplies its ordinary CSRF before replacement bootstrap")
        context.close()
        contexts.remove(context)

        context = new_context()
        first = page_in(context)
        held = intercept(first, "password")
        start(first, "alex", "password")
        wait_held(first, held)
        expect(first.get_by_role("button", name="Sign in with a passkey", exact=True)).to_be_disabled()
        expect(first.get_by_role("button", name="Sign in", exact=True)).to_be_disabled()
        first.get_by_role("button", name="Continue as guest", exact=True).click()
        first.get_by_role("button", name="Team sign in", exact=True).click()
        expect(first.get_by_role("button", name="Sign in", exact=True)).to_be_disabled()
        assert len(held) == 1
        first.get_by_role("button", name="Continue as guest", exact=True).click()
        first.get_by_role("button", name="Submit a post", exact=True).click()
        draft = first.locator("#editor")
        draft.get_by_label("Title", exact=True).fill("Keep this unrelated public-board draft")
        draft.get_by_label("Message", exact=True).fill("A delayed sign-in reply must not save or discard this text.")
        draft.get_by_label("I agree to the posting rules", exact=True).check()
        response = commit(held[0])
        assert response.status_code == 200
        release(held.pop(), response)
        settled(first)
        expect(draft).to_be_visible()
        expect(draft.get_by_label("Title", exact=True)).to_have_value("Keep this unrelated public-board draft")
        expect(draft.get_by_label("Message", exact=True)).to_have_value("A delayed sign-in reply must not save or discard this text.")
        expect(draft.get_by_label("I agree to the posting rules", exact=True)).to_be_checked()
        with database.transaction() as connection:
            assert connection.execute("SELECT COUNT(*) FROM submissions WHERE title=?",
                                      ("Keep this unrelated public-board draft",)).fetchone()[0] == 0
        expect(first.get_by_role("button", name="Sign out", exact=True)).to_have_count(0)
        record("one_page_operation_survives_navigation",
               "A pending proof blocks a new form; its late success does not adopt an obsolete view, discard the unrelated guest draft or submit it")
        context.close()
        contexts.remove(context)

        context = new_context()
        first = page_in(context)
        held = intercept(first, "password")
        start(first, "alex", "password")
        wait_held(first, held)
        first.get_by_role("button", name="Continue as guest", exact=True).click()
        first.get_by_role("button", name="Team sign in", exact=True).click()
        expect(first.locator("#login-status")).to_contain_text("Waiting for this sign-in to finish")
        expect(first.get_by_role("button", name="Sign in", exact=True)).to_be_disabled()
        response = commit(held[0])
        assert response.status_code == 200
        release(held.pop(), response)
        settled(first)
        expect(first.get_by_role("button", name="Sign in", exact=True)).to_be_enabled()
        expect(first.get_by_role("button", name="Sign in with a passkey", exact=True)).to_be_enabled()
        expect(first.locator("#login-status")).to_be_hidden()
        expect(first.locator("#login-status")).to_have_text("")
        expect(first.get_by_role("button", name="Sign out", exact=True)).to_have_count(0)
        record("obsolete_login_clears_only_busy_status",
               "When an obsolete final request settles, its waiting message clears from the new form without adopting its account")
        context.close()
        contexts.remove(context)

        context = new_context()
        first, second = page_in(context), page_in(context)
        held = intercept(first, "password")
        start(first, "alex", "password")
        wait_held(first, held)
        # Read only the public deadline. The private HttpOnly flow stays opaque
        # to page code; moving the controlled server clock does not edit rows.
        bootstrap = context.request.post(url + "/api/login/context", data={}, headers={"Origin": url}).json()
        horizon = bootstrap["flow_expires_at"]
        # The first held context expires sooner, so start a fresh explicit
        # attempt near H; no credentials are replayed automatically by the UI.
        clock["now"] = horizon - 10
        expired_context = commit(held[0])
        assert expired_context.status_code == 409 and "set-cookie" not in expired_context.headers
        release(held.pop(), expired_context)
        expect(first.locator("#login-error")).to_contain_text("changed or expired")
        start(first, "alex", "password")
        wait_held(first, held)
        near_expiry = commit(held[0])
        assert near_expiry.status_code == 200
        assert near_expiry.json()["expires_at"] == horizon
        expect(first.locator("#login-status")).to_contain_text("eight-hour window")
        clock["now"] = horizon
        start(second, "blair", "password")
        expect(second.get_by_role("button", name="Sign out", exact=True)).to_be_visible()
        assert session(context)["expires_at"] > horizon
        assert_dead_cookie(near_expiry)
        release(held.pop(), near_expiry)
        expect(first.locator("#login-error")).to_contain_text("changed or expired")
        current = session(context)
        assert current["user"] is None or current["user"]["id"] == "blair"
        first.screenshot(path=str(output / "expired-late-login-desktop.png"),
                         mask=[first.locator('input[type="password"],input[name="otp"]')])
        first.set_viewport_size({"width": 390, "height": 844})
        assert first.evaluate("document.documentElement.scrollWidth<=innerWidth")
        first.screenshot(path=str(output / "expired-late-login-mobile.png"),
                         mask=[first.locator('input[type="password"],input[name="otp"]')])
        record("fixed_horizon_late_cookie",
               "A near-expiry successful login is capped at H; after H a new window cannot be replaced by that expired delayed root")
        assert not errors, "Login race UI raised a JavaScript exception"
    finally:
        (output / "request-observations.json").write_text(json.dumps(observations, indent=2) + "\n", encoding="utf-8")
        for route in pending:
            route.abort()
        for context in contexts:
            context.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--browser-channel", default="chrome")
    options = parser.parse_args(argv)
    output = options.output_dir.resolve()
    if output == ROOT or ROOT in output.parents or output.exists() and any(output.iterdir()):
        parser.error("Use an empty evidence directory outside the checkout; earlier receipts are preserved.")
    output.mkdir(parents=True, exist_ok=True)

    import role_aware_dashboard_toolkit as toolkit
    from playwright.sync_api import sync_playwright
    from business import auth_routes, browser_flow, mfa, passkeys, session_state
    from business.evidence import finish_browser_receipt, new_receipt, write_receipt
    from tools.business_dashboard_browser import prepare_fixture
    from tools.business_enrollment_browser import local_server

    assert Path(toolkit.__file__).resolve().parent == ROOT / "role_aware_dashboard_toolkit"
    checks, failure, runtime = [], None, {}
    receipt = new_receipt("browser", ())
    result = {"passed": False, "checks": checks,
              "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "scope": "Actual local HTTP/Chrome with disposable accounts, synthetic server clock, isolated response delivery and virtual WebAuthn; no physical-device or hosted acceptance"}
    try:
        with tempfile.TemporaryDirectory(prefix="radt-login-flow-browser-") as temporary:
            with socket.socket() as reservation:
                reservation.bind(("127.0.0.1", 0))
                port = reservation.getsockname()[1]
            url = f"http://localhost:{port}"
            credentials, application = prepare_fixture(Path(temporary) / "private", url)
            clock = {"now": time.time()}
            with ExitStack() as stack:
                for module in (auth_routes, browser_flow, mfa, passkeys, session_state):
                    stack.enter_context(patch.object(module, "current_time", lambda: clock["now"]))
                with local_server(application, port, hostname="localhost"), sync_playwright() as playwright:
                    browser = playwright.chromium.launch(channel=options.browser_channel, headless=True)
                    try:
                        runtime.update(name=options.browser_channel, version=browser.version)
                        exercise(browser, url, application, credentials, clock, output, checks)
                    finally:
                        browser.close()
            result["passed"] = True
            result["owned_server_stopped"] = True
    except (Exception, KeyboardInterrupt) as error:
        failure = error
        result["error_type"] = type(error).__name__
        result["error_frames"] = [{"file": Path(frame.filename).name, "line": frame.lineno, "function": frame.name}
                                  for frame in traceback.extract_tb(error.__traceback__)]
        print(f"Login flow browser checks failed ({type(error).__name__}); private evidence preserved.", file=sys.stderr)
    finally:
        (output / "diagnostic-summary.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        receipt = finish_browser_receipt(receipt, len(checks), completed=result["passed"], error=failure, browser=runtime or None)
        write_receipt(output / "receipt.json", receipt)
        result["passed"] = receipt["status"] == "passed"
        (output / "summary.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(f"Login flow browser checks: {len(checks)}; evidence: {output}")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
