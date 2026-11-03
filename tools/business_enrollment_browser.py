"""Local Chrome proof for real HTTP enrollment; all accounts and factors are fictional."""

from contextlib import contextmanager
from pathlib import Path
import argparse
import json
import secrets
import socket
import sys
import tempfile
import threading
import time
import traceback
from urllib.error import URLError
from urllib.request import urlopen
from unittest.mock import patch

if not __debug__:
    raise SystemExit("Enrollment evidence requires assertions; do not use optimized Python.")

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "examples" / "business_dashboard"))


@contextmanager
def local_server(application, port, *, hostname="127.0.0.1"):
    import uvicorn

    server = uvicorn.Server(uvicorn.Config(application, host="127.0.0.1", port=port,
                           proxy_headers=False, access_log=False, log_config=None, timeout_graceful_shutdown=5))
    worker = threading.Thread(target=server.run, daemon=True)
    worker.start()
    try:
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if not worker.is_alive():
                raise RuntimeError("Owned enrollment server exited before readiness")
            try:
                with urlopen(f"http://{hostname}:{port}/healthz", timeout=1) as response:
                    if response.status == 200:
                        break
            except (URLError, TimeoutError):
                pass  # Connection refusal is expected during owned startup.
            time.sleep(0.1)
        else:
            raise TimeoutError("Owned enrollment server did not become ready")
        yield
    finally:
        server.should_exit = True
        worker.join(timeout=15)
        if worker.is_alive():
            raise RuntimeError("Owned enrollment server did not stop")


def exercise(browser, url, application, grants, clock, output, checks):
    import pyotp
    from playwright.sync_api import expect
    from business.enrollment import issue_grant

    database = application.state.database
    errors, credentials, factors = [], {}, {}
    context = browser.new_context(viewport={"width": 1440, "height": 1050})
    context.set_default_timeout(10000)
    context.add_init_script("""(() => {
      const original=window.fetch.bind(window);let settled=0;
      window.fetch=async (...args)=>{
        const response=await original(...args);
        if(args[0]==='/api/enrollment/complete'){
          const json=response.json.bind(response);
          response.json=async()=>{try{return await json();}finally{
            setTimeout(()=>document.documentElement.setAttribute('data-enrollment-settled',String(++settled)),0);
          }};
        }
        return response;
      };
    })();""")
    page = context.new_page()
    page.on("pageerror", lambda error: errors.append(type(error).__name__))

    def next_code(username):
        clock["now"] = (int(clock["now"] // 30) + 1) * 30
        return pyotp.TOTP(factors[username]).at(clock["now"])

    def begin(username, grant):
        page.get_by_role("button", name="Set up or recover your account", exact=True).click()
        dialog = page.locator("#enrollment-dialog")
        dialog.get_by_label("Username", exact=True).fill(username)
        dialog.get_by_label("Enrollment code", exact=True).fill(grant)
        dialog.get_by_role("button", name="Start account setup", exact=True).click()
        expect(dialog.get_by_label("Authenticator setup key", exact=True)).to_be_visible()
        return dialog

    def complete(username, dialog, *, submitted_only=False):
        factors[username] = dialog.get_by_label("Authenticator setup key", exact=True).input_value()
        credentials[username] = secrets.token_urlsafe(32)
        dialog.get_by_label("New password", exact=True).fill(credentials[username])
        dialog.get_by_label("Confirm new password", exact=True).fill(credentials[username])
        dialog.get_by_label("Authenticator code", exact=True).fill(pyotp.TOTP(factors[username]).at(clock["now"]))
        dialog.get_by_role("button", name="Finish account setup", exact=True).click()
        if not submitted_only:
            expect(page.locator("#enrollment-completion")).to_contain_text("Wait for your authenticator to show a new code")
            expect(dialog).not_to_be_visible()
            assert page.request.get(url + "/api/session").json()["user"] is None

    def login(username):
        page.get_by_label("Username", exact=True).fill(username)
        page.get_by_label("Password", exact=True).fill(credentials[username])
        page.get_by_label("Authenticator code", exact=True).fill(next_code(username))
        page.get_by_role("button", name="Sign in", exact=True).click()
        expect(page.get_by_role("button", name="Sign out", exact=True)).to_be_visible()
        assert page.request.get(url + "/api/session").json()["user"]["username"] == username

    try:
        page.goto(url)
        dialog = begin("admin", grants["admin"])
        assert page.request.get(url + "/api/messages").status == 401
        page.set_viewport_size({"width": 390, "height": 844})
        assert dialog.evaluate("e=>{const b=e.getBoundingClientRect();return b.left>=0&&b.right<=innerWidth&&b.top>=0&&b.bottom<=innerHeight;}")
        page.screenshot(path=str(output / "enrollment-mobile.png"), mask=[dialog.locator("input")])
        page.set_viewport_size({"width": 1440, "height": 1050})
        complete("admin", dialog)
        checks.append("Administrator completes actual one-use enrollment, sees next-code guidance, and receives no ordinary session")
        login("admin")
        page.get_by_role("button", name="Sign out", exact=True).click()
        expect(page.locator("#login-form")).to_be_visible()
        dialog = begin("alex", grants["alex"])
        complete("alex", dialog)
        login("alex")
        checks.append("Employee also completes enrollment and signs in with the chosen password and current authenticator")

        with database.transaction() as connection:
            recovery = issue_grant(connection, "alex", purpose="recovery", case_reference="browser-fictional-001")
        assert page.request.get(url + "/api/messages").status == 401
        page.goto(url)
        expect(page.locator("#login-form")).to_be_visible()
        dialog = begin("alex", recovery)
        dialog.get_by_role("button", name="Close", exact=True).click()
        expect(dialog).not_to_be_visible()
        assert dialog.locator("input").count() == 0
        page.get_by_role("button", name="Set up or recover your account", exact=True).click()
        dialog.get_by_label("Username", exact=True).fill("alex")
        dialog.get_by_label("Enrollment code", exact=True).fill(recovery)
        dialog.get_by_role("button", name="Start account setup", exact=True).click()
        expect(dialog.locator('[role="alert"]')).to_contain_text("unavailable or expired")
        dialog.get_by_role("button", name="Close", exact=True).click()
        checks.append("Recovery revokes the existing session; closing clears setup secrets and the claimed grant cannot be replayed")

        with database.transaction() as connection:
            recovery = issue_grant(connection, "alex", purpose="recovery", case_reference="browser-fictional-002")
        dialog = begin("alex", recovery)
        held = []

        def hold_completion(route):
            response = route.fetch()
            assert response.status == 200
            held.append((route, response))

        page.route("**/api/enrollment/complete", hold_completion)
        complete("alex", dialog, submitted_only=True)
        deadline = time.monotonic() + 10
        while not held and time.monotonic() < deadline:
            page.wait_for_timeout(50)
        assert held, "Expected a committed enrollment reply held in transport"
        dialog.get_by_role("button", name="Close", exact=True).click()
        login("admin")
        held[0][0].fulfill(response=held[0][1])
        page.unroute("**/api/enrollment/complete", hold_completion)
        # Observe the actual page fetch settling before checking newer ownership.
        expect(page.locator("html")).to_have_attribute("data-enrollment-settled", "1")
        expect(page.get_by_role("button", name="Sign out", exact=True)).to_be_visible()
        assert page.request.get(url + "/api/session").json()["user"]["username"] == "admin"
        assert page.locator("#enrollment-dialog input").count() == 0
        checks.append("A delayed committed enrollment reply does not clear a newer account's signed-in view or cookie")
        page.get_by_role("button", name="Sign out", exact=True).click()
        expect(page.locator("#login-form")).to_be_visible()
        login("alex")
        checks.append("The recovered employee can sign in with the newly chosen password and authenticator after the delayed reply")
        page.screenshot(path=str(output / "enrollment-completed.png"))
        page.get_by_role("button", name="Sign out", exact=True).click()
        expect(page.locator("#login-form")).to_be_visible()
        dialog = begin("casey", grants["casey"])
        held.clear()
        page.route("**/api/enrollment/complete", hold_completion)
        complete("casey", dialog, submitted_only=True)
        deadline = time.monotonic() + 10
        while not held and time.monotonic() < deadline:
            page.wait_for_timeout(50)
        assert held
        dialog.get_by_role("button", name="Close", exact=True).click()
        dialog = begin("drew", grants["drew"])
        newer_seed = dialog.get_by_label("Authenticator setup key", exact=True).input_value()
        held[0][0].fulfill(response=held[0][1])
        page.unroute("**/api/enrollment/complete", hold_completion)
        expect(page.locator("html")).to_have_attribute("data-enrollment-settled", "2")
        expect(dialog.get_by_label("Authenticator setup key", exact=True)).to_have_value(newer_seed)
        assert page.request.get(url + "/api/session").json()["user"] is None
        complete("drew", dialog)
        checks.append("A delayed completion from a closed setup leaves a distinct newer setup intact under the same signed-out session")
        page.clock.install(time=clock["now"])
        dialog = begin("blair", grants["blair"])
        seed = dialog.get_by_label("Authenticator setup key", exact=True).input_value()
        held.clear()
        page.route("**/api/enrollment/complete", hold_completion)
        complete("blair", dialog, submitted_only=True)
        deadline = time.monotonic() + 10
        while not held and time.monotonic() < deadline:
            page.wait_for_timeout(50)
        assert held, "Expected a committed reply held beyond the displayed setup expiry"
        page.clock.fast_forward(20 * 60 * 1000)
        expect(dialog.locator('[role="alert"]')).to_contain_text("expired")
        assert dialog.locator("input").count() == 0 and seed not in dialog.inner_html()
        held[0][0].fulfill(response=held[0][1])
        page.unroute("**/api/enrollment/complete", hold_completion)
        expect(page.locator("#enrollment-completion")).to_contain_text("Account setup is complete")
        assert page.request.get(url + "/api/session").json()["user"] is None
        checks.append("Expiry removes the setup key and all inputs even while a committed reply is delayed; its later success is still observed")
        assert not errors, "Enrollment browser produced a page error"
    except Exception:
        diagnostic = {"page_errors": errors, "title": page.title(),
                      "alerts": page.locator('[role="alert"]:visible').all_text_contents(),
                      "inputs": page.locator("input").evaluate_all("rows=>rows.map(e=>({name:e.name,disabled:e.disabled}))")}
        (output / "browser-diagnostic.json").write_text(json.dumps(diagnostic, indent=2) + "\n", encoding="utf-8")
        page.screenshot(path=str(output / "failure-masked.png"), mask=[page.locator("input")])
        raise
    finally:
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
    from business import enrollment, mfa
    from business.app import create_app
    from business.evidence import finish_browser_receipt, new_receipt, write_receipt
    from business.secret_store import create_key_file, default_key_path
    from business.seed import provision

    assert Path(toolkit.__file__).resolve().parent == ROOT / "role_aware_dashboard_toolkit"
    checks, failure, runtime = [], None, {}
    receipt = new_receipt("browser", ())
    result = {"passed": False, "checks": checks, "scope": "local_fictional_enrollment_with_synthetic_server_clock"}
    try:
        with tempfile.TemporaryDirectory(prefix="radt-enrollment-browser-") as temporary:
            data = Path(temporary) / "private"
            key = default_key_path(data)
            create_key_file(data, key)
            grants = provision(data, mfa_key_file=key)
            with socket.socket() as reservation:
                reservation.bind(("127.0.0.1", 0))
                port = reservation.getsockname()[1]
            url = f"http://127.0.0.1:{port}"
            application = create_app(data, public_origin=url, mfa_key_file=key)
            clock = {"now": time.time()}
            with patch.object(enrollment, "current_time", lambda: clock["now"]), patch.object(mfa, "current_time", lambda: clock["now"]):
                with local_server(application, port), sync_playwright() as playwright:
                    browser = playwright.chromium.launch(channel=options.browser_channel, headless=True)
                    try:
                        name = "chrome" if options.browser_channel.startswith("chrome") else "msedge" if options.browser_channel.startswith("msedge") else "chromium"
                        runtime.update(name=name, version=browser.version)
                        exercise(browser, url, application, grants, clock, output, checks)
                    finally:
                        browser.close()
            result["passed"] = True
    except (Exception, KeyboardInterrupt) as error:
        failure = error
        result["error_type"] = type(error).__name__
        result["error_frames"] = [{"file": Path(frame.filename).name, "line": frame.lineno, "function": frame.name}
                                  for frame in traceback.extract_tb(error.__traceback__)]
        print(f"Enrollment browser check failed ({type(error).__name__}); private evidence preserved.", file=sys.stderr)
    finally:
        (output / "diagnostic-summary.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        receipt = finish_browser_receipt(receipt, len(checks), completed=result["passed"], error=failure, browser=runtime or None)
        result["passed"] = receipt["status"] == "passed"
        write_receipt(output / "receipt.json", receipt)
        (output / "summary.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(f"Enrollment browser checks: {len(checks)}; evidence: {output}")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
