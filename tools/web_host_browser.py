"""Generate and exercise the editable FastAPI host with disposable local data.

Use --installed-package with a non-editable toolkit installation. The runner
never seeds an existing app, reads operator credentials, or writes private
runtime data into its retained evidence directory.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request


ROOT = Path(__file__).resolve().parents[1]


def request(origin, path, token=None, data=None):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    body = None
    if data is not None:
        headers["Content-Type"] = "application/json"
        body = json.dumps(data).encode("utf-8")
    call = urllib.request.Request(origin + path, data=body, headers=headers)
    try:
        response = urllib.request.urlopen(call, timeout=15)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        return response.status, json.load(response)


def run_python(python, app, env, *arguments):
    result = subprocess.run([str(python), "-B", *arguments], cwd=app, env=env,
                            capture_output=True, text=True, encoding="utf-8", timeout=60)
    # The subprocess may have handled a token; never echo its output on failure.
    if result.returncode:
        raise RuntimeError("A fixture subprocess failed.")
    return result.stdout.strip()


@contextmanager
def server(python, app, env, port):
    process = subprocess.Popen(
        [str(python), "-B", "-m", "uvicorn", "app:create_app", "--factory", "--host",
         "127.0.0.1", "--port", str(port), "--no-proxy-headers", "--no-access-log", "--log-level", "error"],
        cwd=app, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    origin = f"http://127.0.0.1:{port}"
    try:
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError("The generated host did not start.")
            try:
                with urllib.request.urlopen(origin + "/", timeout=1) as response:
                    if response.status == 200:
                        break
            except (OSError, urllib.error.URLError):
                time.sleep(.1)
        else:
            raise RuntimeError("The generated host did not become ready.")
        yield origin
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)


def output_directory(value):
    raw = Path(value).expanduser().absolute()
    if any(part.is_symlink() or part.is_junction() if hasattr(part, "is_junction") else part.is_symlink()
           for part in (raw, *raw.parents)):
        raise ValueError("Output must not traverse links.")
    directory = raw.resolve()
    if directory == ROOT or ROOT in directory.parents:
        raise ValueError("Output must be outside the checkout.")
    if directory.exists() and (not directory.is_dir() or any(directory.iterdir())):
        raise ValueError("Output must be a new or empty directory.")
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def sign_in(page, token, expect):
    page.get_by_label("Access token", exact=True).fill(token)
    page.get_by_role("button", name="Open workspace", exact=False).click()
    expect(page.locator("#workspace")).to_be_visible()
    expect(page.get_by_label("Access token", exact=True)).to_have_value("")


def exercise(page, context, origin, manager, viewer, operator, checks, output, grant):
    from playwright.sync_api import expect

    def capture(name, *, full_page=True):
        page.screenshot(path=str(output / f"{name}.png"), full_page=full_page,
                        mask=[page.locator("#access-token")])

    page.goto(origin)
    expect(page.locator("#brand")).to_have_text("Harbor & Co.")
    expect(page.locator("#headline")).to_have_text("Good work, from plan to delivery.")
    assert page.evaluate("getComputedStyle(document.documentElement).getPropertyValue('--radt-accent').trim()") == "#5C3A70"
    expect(page.locator("#workspace")).to_be_hidden()
    status, _ = request(origin, "/api/items")
    assert status == 401
    capture("01-branded-signin")
    checks.append("branded_public_shell_and_protected_records")

    sign_in(page, manager, expect)
    expect(page.get_by_role("button", name="New work item", exact=False)).to_be_disabled()
    page.get_by_role("button", name="Resume changes", exact=True).click()
    expect(page.get_by_role("button", name="Pause changes", exact=True)).to_be_enabled()
    expect(page.get_by_text("New work starts here.", exact=True)).to_be_visible()
    page.get_by_role("button", name="New work item", exact=False).click()
    expect(page.get_by_label("Work title", exact=True)).to_be_focused()
    page.get_by_label("Work title", exact=True).fill("Prepare the spring handover")
    page.keyboard.press("Tab")
    expect(page.get_by_label("Assigned account", exact=True)).to_be_focused()
    page.get_by_label("Assigned account", exact=True).fill("operator")
    page.get_by_label("Scheduled date and time", exact=True).fill("2030-04-05T10:30")
    page.get_by_label("Assigned account", exact=True).press("Enter")
    expect(page.locator("#editor")).not_to_be_visible()
    expect(page.get_by_role("heading", name="Prepare the spring handover", exact=True)).to_be_visible()
    status, data = request(origin, "/api/items", manager)
    assert status == 200 and len(data["items"]) == 1
    item = data["items"][0]
    assert item["label"] == "Prepare the spring handover" and item["owner"] == "operator"
    capture("02-manager-board")
    checks.append("keyboard_creation_commits_real_record")

    page.get_by_role("button", name="Reschedule: Prepare the spring handover", exact=True).click()
    page.get_by_label("Scheduled date and time", exact=True).fill("2030-04-06T11:45")
    page.get_by_label("Reason", exact=False).fill("Draft from the first tab")
    status, changed = request(origin, f"/api/items/{item['id']}/reschedule", manager,
                              {"expected_revision": item["revision"], "starts_at": "2030-04-07T12:00:00Z", "reason": "Competing update"})
    assert status == 200 and changed["item"]["revision"] == item["revision"] + 1
    page.get_by_role("button", name="Save changes", exact=True).click()
    expect(page.locator("#editor-error")).to_contain_text("Your draft is preserved")
    expect(page.get_by_label("Scheduled date and time", exact=True)).to_have_value("2030-04-06T11:45")
    expect(page.get_by_label("Reason", exact=False)).to_have_value("Draft from the first tab")
    status, unchanged = request(origin, "/api/items", manager)
    assert status == 200 and unchanged["items"][0] == changed["item"]
    page.get_by_role("button", name="Discard draft and load latest", exact=True).click()
    expect(page.locator("#editor-note")).to_contain_text(f"revision {changed['item']['revision']}")
    expect(page.get_by_label("Reason", exact=False)).to_have_value("")
    page.get_by_label("Scheduled date and time", exact=True).fill("2030-04-08T09:15")
    page.get_by_label("Reason", exact=False).fill("Agreed revised handover")
    page.get_by_role("button", name="Save changes", exact=True).click()
    expect(page.locator("#editor")).not_to_be_visible()
    checks.append("stale_edit_preserves_draft_and_requires_explicit_reload")

    page.get_by_role("button", name="Update status: Prepare the spring handover", exact=True).click()
    page.get_by_label("Status", exact=True).select_option("cancelled")
    page.get_by_role("button", name="Save changes", exact=True).click()
    expect(page.locator("#editor-error")).not_to_be_empty()
    expect(page.locator("#editor")).to_be_visible()
    page.get_by_label("Status", exact=True).select_option("completed")
    page.get_by_label("Reason", exact=False).fill("Ready for the customer")
    page.get_by_role("button", name="Save changes", exact=True).click()
    expect(page.locator("#editor")).not_to_be_visible()
    expect(page.locator('[data-lane="completed"]')).to_contain_text("Prepare the spring handover")
    page.get_by_role("link", name="Activity", exact=True).click()
    expect(page.locator("#history")).to_contain_text("Ready for the customer")
    page.go_back()
    expect(page.locator("#work-view")).to_be_visible()
    checks.append("validation_status_history_and_back_navigation")

    page.set_viewport_size({"width": 320, "height": 844})
    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
    page.get_by_role("button", name="Update status: Prepare the spring handover", exact=True).click()
    expect(page.get_by_label("Status", exact=True)).to_be_focused()
    assert page.locator("#editor").evaluate("element => element.scrollWidth <= element.clientWidth")
    capture("03-mobile-edit", full_page=False)
    page.keyboard.press("Escape")
    expect(page.locator("#editor")).not_to_be_visible()
    expect(page.get_by_role("button", name="Update status: Prepare the spring handover", exact=True)).to_be_focused()
    page.evaluate("scrollTo(0, 0)")
    capture("04-mobile-board")
    checks.append("narrow_layout_keyboard_dialog_and_focus_restore")

    operator_page = context.new_page()
    operator_page.goto(origin)
    sign_in(operator_page, operator, expect)
    expect(operator_page.locator("#new-item")).to_be_hidden()
    expect(operator_page.get_by_role("button", name="Update status: Prepare the spring handover", exact=True)).to_be_visible()
    operator_page.get_by_role("button", name="Update status: Prepare the spring handover", exact=True).click()
    operator_page.get_by_label("Status", exact=True).select_option("scheduled")
    operator_page.get_by_label("Reason", exact=False).fill("A draft before the pause")
    page.get_by_role("button", name="Pause changes", exact=True).click()
    expect(page.get_by_role("button", name="Resume changes", exact=True)).to_be_visible()
    operator_page.get_by_role("button", name="Save changes", exact=True).click()
    expect(operator_page.locator("#editor-error")).not_to_be_empty()
    expect(operator_page.get_by_label("Reason", exact=False)).to_have_value("A draft before the pause")
    expect(operator_page.get_by_role("button", name="Save changes", exact=True)).to_be_disabled()
    status, frozen = request(origin, "/api/items", manager)
    assert status == 200 and frozen["items"][0]["status"] == "completed"
    page.get_by_role("button", name="Resume changes", exact=True).click()
    expect(page.get_by_role("button", name="Pause changes", exact=True)).to_be_visible()
    checks.append("freeze_after_form_load_blocks_actual_write")

    operator_page.get_by_role("button", name="Cancel", exact=True).click()
    operator_page.get_by_role("button", name="Refresh", exact=True).click()
    expect(operator_page.get_by_role("button", name="Update status: Prepare the spring handover", exact=True)).to_be_enabled()
    operator_page.get_by_role("button", name="Update status: Prepare the spring handover", exact=True).click()
    operator_page.get_by_label("Status", exact=True).select_option("scheduled")
    operator_page.get_by_label("Reason", exact=False).fill("Draft before role downgrade")
    grant("operator", "Viewer")
    operator_page.get_by_role("button", name="Save changes", exact=True).click()
    expect(operator_page.locator("#editor")).not_to_be_visible()
    expect(operator_page.locator("#item-reason")).to_have_value("")
    expect(operator_page.locator("#editor-title")).to_have_text("New work item")
    expect(operator_page.locator("#editor-note")).to_be_empty()
    expect(operator_page.locator("#account-label")).to_have_text("operator · Viewer")
    expect(operator_page.locator("#board button")).to_have_count(0)
    operator_page.close()
    checks.append("role_downgrade_after_form_load_clears_draft_and_rebuilds_ui")

    page.get_by_role("button", name="Update status: Prepare the spring handover", exact=True).click()
    page.get_by_label("Status", exact=True).select_option("scheduled")
    page.get_by_label("Reason", exact=False).fill("Saved with a lost response")
    lost_response = f"**/api/items/{item['id']}/status"

    def save_without_response(route):
        expect(page.locator("#editor")).to_have_attribute("aria-busy", "true")
        expect(page.get_by_role("button", name="Save changes", exact=True)).to_be_disabled()
        reply = route.fetch()
        assert reply.status == 200
        route.abort("failed")

    page.route(lost_response, save_without_response)
    page.get_by_role("button", name="Save changes", exact=True).click()
    expect(page.locator("#editor-error")).to_contain_text("save result is uncertain")
    expect(page.get_by_role("button", name="Save changes", exact=True)).to_be_disabled()
    assert request(origin, "/api/items", manager)[1]["items"][0]["status"] == "scheduled"
    page.unroute(lost_response, save_without_response)
    page.get_by_role("button", name="Close draft and review saved work", exact=True).click()
    expect(page.locator("#editor")).not_to_be_visible()
    expect(page.locator('[data-lane="scheduled"]')).to_contain_text("Prepare the spring handover")
    page.get_by_role("button", name="Update status: Prepare the spring handover", exact=True).click()
    page.get_by_label("Status", exact=True).select_option("completed")
    page.get_by_role("button", name="Save changes", exact=True).click()
    expect(page.locator("#editor")).not_to_be_visible()
    checks.append("pending_and_lost_save_response_require_saved_state_review")

    page.evaluate("""() => {
        const original = window.fetch; let held = false;
        window.fetch = (...args) => {
            if (!held && args[0] === '/api/session') {
                held = true;
                return new Promise((resolve, reject) => {
                    window.rejectOldRead = () => reject(new TypeError('Synthetic delayed failure'));
                });
            }
            return original(...args);
        };
        window.restoreFetch = () => { window.fetch = original; };
    }""")
    page.get_by_role("button", name="Refresh", exact=True).click()
    page.wait_for_function("typeof window.rejectOldRead === 'function'")
    page.get_by_role("button", name="Sign out", exact=True).click()
    expect(page.locator("#board")).to_be_empty()
    expect(page.locator("#history")).to_be_empty()
    expect(page.locator("#editor-title")).to_have_text("New work item")
    expect(page.locator("#editor-note")).to_be_empty()
    expect(page.locator("#editor")).not_to_contain_text("Prepare the spring handover")
    sign_in(page, viewer, expect)
    page.evaluate("() => { window.rejectOldRead(); window.restoreFetch(); }")
    expect(page.locator("#account-label")).to_have_text("viewer · Viewer")
    expect(page.locator("#new-item")).to_be_hidden()
    expect(page.locator("#history-link")).to_be_hidden()
    expect(page.locator("#board button")).to_have_count(0)
    current = request(origin, "/api/items", manager)[1]["items"][0]
    status, _ = request(origin, f"/api/items/{item['id']}/status", viewer,
                        {"expected_revision": current["revision"], "status": "scheduled", "reason": "Denied"})
    assert status == 403
    assert request(origin, "/api/items", manager)[1]["items"][0] == current
    assert page.evaluate("localStorage.length === 0 && sessionStorage.length === 0")
    capture("05-viewer-board")
    page.reload()
    expect(page.locator("#signin")).to_be_visible()
    expect(page.locator("#board")).to_be_empty()
    checks.append("account_switch_clears_private_ui_and_viewer_denial_has_no_effect")
    checks.append("late_failed_read_cannot_replace_a_new_account_view")
    return current


def main(argv=None):
    if not __debug__:
        raise SystemExit("Run this acceptance tool without -O; assertions are required.")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--installed-package", action="store_true")
    parser.add_argument("--python", default=sys.executable, help="Interpreter for generation and the host.")
    parser.add_argument("--browser-executable")
    parser.add_argument("--browser-channel")
    args = parser.parse_args(argv)
    output = output_directory(args.output_dir)
    report = {"schema_version": 1, "passed": False, "checks": [], "installed_package": args.installed_package,
              "scope": "Local generated host with fictional accounts; no public ingress, external identity provider, or recovery proof."}
    checks = report["checks"]
    python = Path(args.python).resolve()
    try:
        from playwright.sync_api import sync_playwright

        with tempfile.TemporaryDirectory(prefix="radt-web-host-") as temporary:
            root = Path(temporary).resolve()
            app, private = root / "app", root / "private"
            env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1", "PYTHONIOENCODING": "utf-8"}
            env.pop("PYTHONPATH", None)
            if not args.installed_package:
                env["PYTHONPATH"] = str(ROOT)
            identity = json.loads(run_python(python, root, env, "-c", (
                "import json, pathlib, importlib.metadata as m; import role_aware_dashboard_toolkit as r; "
                "d=m.distribution('role-aware-dashboard-toolkit'); "
                "print(json.dumps({'path':str(pathlib.Path(r.__file__).resolve()),'version':d.version,"
                "'distribution_path':str(pathlib.Path(d.locate_file('role_aware_dashboard_toolkit/__init__.py')).resolve()),"
                "'direct_url':d.read_text('direct_url.json')}))"
            )))
            package = Path(identity["path"])
            direct = json.loads(identity["direct_url"] or "{}")
            distribution_origin_matches = package == Path(identity["distribution_path"])
            if args.installed_package and (ROOT in package.parents or direct.get("dir_info", {}).get("editable")
                                           or not distribution_origin_matches):
                raise RuntimeError("Installed-package checks refuse checkout or editable imports.")
            report["toolkit_version"] = identity["version"]
            report["package_import_outside_checkout"] = ROOT not in package.parents
            report["package_matches_distribution"] = distribution_origin_matches
            report["package_origin_sha256"] = hashlib.sha256(str(package).encode("utf-8")).hexdigest()
            report["package_init_sha256"] = hashlib.sha256(package.read_bytes()).hexdigest()
            run_python(python, root, env, "-c", (
                "from pathlib import Path; from role_aware_dashboard_toolkit.web import WebPresentation,WebTheme; "
                "Path('brand.json').write_text(WebPresentation(brand='Harbor & Co.',"
                "headline='Good work, from plan to delivery.',theme=WebTheme(accent='#5C3A70',"
                "accent_soft='#F0EAF5',dark='#302342')).to_json(),encoding='utf-8')"
            ))
            run_python(python, root, env, "-m", "role_aware_dashboard_toolkit", "init", str(app),
                       "--web-host", "--web-config", str(root / "brand.json"), "--format", "json")
            report["source_sha256"] = {
                path.relative_to(app).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
                for path in sorted(app.rglob("*")) if path.is_file()
            }
            run_python(python, app, env, "manage.py", "init", "--data-dir", str(private))
            tokens = {}
            for subject, role in (("manager", "Manager"), ("viewer", "Viewer"), ("operator", "Operator")):
                tokens[subject] = run_python(python, app, env, "manage.py", "issue-token", "--data-dir",
                                             str(private), "--subject", subject, "--role", role)
            with socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                port = listener.getsockname()[1]
            env.update(RADT_DATA_DIR=str(private), RADT_PUBLIC_ORIGIN=f"http://127.0.0.1:{port}")
            checks.append("generated_from_selected_package_with_editable_assets")
            with sync_playwright() as playwright:
                launch = {"headless": True}
                if args.browser_executable:
                    launch["executable_path"] = args.browser_executable
                if args.browser_channel:
                    launch["channel"] = args.browser_channel
                browser = playwright.chromium.launch(**launch)
                try:
                    context = browser.new_context(viewport={"width": 1440, "height": 1000})
                    page = context.new_page()
                    with server(python, app, env, port) as origin:
                        current = exercise(page, context, origin, tokens["manager"], tokens["viewer"],
                                           tokens["operator"], checks, output,
                                           lambda subject, role: run_python(python, app, env, "manage.py", "grant",
                                               "--data-dir", str(private), "--subject", subject, "--role", role))
                        history = request(origin, "/api/history", tokens["manager"])[1]
                    with server(python, app, env, port) as origin:
                        assert request(origin, "/api/items", tokens["manager"])[1]["items"] == [current]
                        assert request(origin, "/api/history", tokens["manager"])[1] == history
                        page.goto(origin)
                        from playwright.sync_api import expect
                        sign_in(page, tokens["manager"], expect)
                        expect(page.locator('[data-lane="completed"]')).to_contain_text(current["label"])
                        checks.append("records_history_and_access_survive_real_server_restart")
                    context.close()
                finally:
                    browser.close()
            after = {path.relative_to(app).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
                     for path in sorted(app.rglob("*")) if path.is_file()}
            assert after == report["source_sha256"]
            checks.append("generated_source_unchanged_during_acceptance")
        report["passed"] = True
    except Exception as error:
        report["error_type"] = type(error).__name__
        trace = error.__traceback__
        while trace:
            if Path(trace.tb_frame.f_code.co_filename).resolve() == Path(__file__).resolve():
                report["failure_line"] = trace.tb_lineno
            trace = trace.tb_next
    finally:
        (output / "summary.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"FastAPI starter browser checks: {len(checks)} completed; {'passed' if report['passed'] else 'failed'}.")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
