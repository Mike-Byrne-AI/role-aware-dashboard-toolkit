"""Real Chromium checks against isolated fake data; never prints login secrets."""
from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.request

from playwright.sync_api import sync_playwright, expect

EXAMPLE_ROOT = Path(__file__).resolve().parents[1]
CHECKOUT_ROOT = EXAMPLE_ROOT.parents[1]
sys.path.insert(0, str(EXAMPLE_ROOT))

from landscape.seed import seed_trial  # noqa: E402


def evidence_directory(value: str | None) -> Path:
    """Keep synthetic screenshots, logs and runtime state outside source trees."""
    path = Path(value).expanduser().absolute() if value else Path(tempfile.gettempdir()).absolute()
    if any(candidate == CHECKOUT_ROOT or CHECKOUT_ROOT in candidate.parents
           for candidate in (path, path.resolve())):
        raise ValueError("Browser output must be outside the repository")
    if value is None:
        return Path(tempfile.mkdtemp(prefix="radt-landscaping-browser-", dir=path))
    if path.exists() and (not path.is_dir() or any(path.iterdir())):
        raise ValueError("Browser output directory must be empty")
    path.mkdir(parents=True, exist_ok=True)
    return path.resolve()


def run(out: Path, browser_executable: str | None = None):
    results = []
    def checked(name):
        results.append(name)
        print(name, flush=True)

    with tempfile.TemporaryDirectory(prefix="landscape-browser-") as temp:
        data_dir = Path(temp) / "data"
        passwords = seed_trial(data_dir)
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        base = f"http://127.0.0.1:{port}"
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", LANDSCAPE_DATA_DIR=str(data_dir))
        log = (out / "server.log").open("w")
        server = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "landscape.app:create_default_app", "--factory",
             "--host", "127.0.0.1", "--port", str(port), "--no-access-log", "--no-proxy-headers"],
            cwd=EXAMPLE_ROOT, env=env, stdout=log, stderr=subprocess.STDOUT,
        )
        try:
            for _ in range(100):
                if server.poll() is not None:
                    raise RuntimeError("Browser test server exited; inspect server.log")
                try:
                    with urllib.request.urlopen(base, timeout=1):
                        break
                except OSError:
                    time.sleep(.1)
            else:
                raise RuntimeError("Browser test server did not start")
            with sync_playwright() as pw:
                browser = pw.chromium.launch(executable_path=browser_executable, headless=True)
                contexts = []
                errors = []
                try:
                    accounts = {}
                    for username in ("admin", "alex", "blair", "casey", "drew", "ellis"):
                        context = browser.new_context(viewport={"width":1440,"height":1000}, timezone_id="America/New_York")
                        contexts.append(context)
                        page = context.new_page()
                        page.on("pageerror", lambda error: errors.append(str(error)))
                        page.goto(base)
                        if username == "admin":
                            page.screenshot(path=str(out / "login.png"), full_page=True)
                        page.get_by_label("Username", exact=True).fill(username)
                        page.get_by_label("Password", exact=True).fill(passwords[username])
                        page.get_by_role("button", name=re.compile(r"^Sign in")).click()
                        page.get_by_role("button", name="Sign out", exact=True).wait_for(timeout=15000)
                        response = context.request.get(base + "/api/session")
                        assert response.status == 200
                        session = response.json()
                        assert session["user"]["username"] == username
                        accounts[username] = (context,page,session)
                        checked(f"Real browser password login: {username}")
                        if username != "admin":
                            assert page.get_by_text("Customers & outreach", exact=True).count() == 0
                            assert page.get_by_text("Business metrics", exact=True).count() == 0
                            data = context.request.get(base + "/api/jobs").json()
                            assert len(data["jobs"]) == 12
                            assert all(set(person) == {"display_name"} for job in data["jobs"] for person in job["crew"])
                    admin_context, admin_page, admin_session = accounts["admin"]
                    alex_context, alex_page, alex_session = accounts["alex"]
                    for username in ("alex", "blair", "casey", "drew", "ellis"):
                        context, page, session = accounts[username]
                        for other in ("alex", "blair", "casey", "drew", "ellis"):
                            if other == username:
                                continue
                            response = context.request.get(base + "/api/jobs", params={"worker_id":accounts[other][2]["user"]["id"]})
                            assert response.status == 422
                        assert {j["id"] for j in context.request.get(base + "/api/jobs").json()["jobs"]} == {j["id"] for j in alex_context.request.get(base + "/api/jobs").json()["jobs"]}
                        for endpoint in ("/api/workers","/api/admin/customers","/api/admin/health","/api/admin/metrics"):
                            assert context.request.get(base + endpoint).status == 403
                    checked("Five workers see the same shared jobs; all 20 retired identity-selector attempts rejected")
                    checked("All five workers denied private admin JSON endpoints")
                    # Additional UI flows appended once accessible controls are finalized.
                    run_ui_flows(base, accounts, out, checked, passwords, data_dir)
                    response = alex_page.goto(base + "/admin/metrics")
                    assert response.status == 403
                    assert "pipeline_value" not in alex_page.content()
                    checked("Direct worker navigation to admin page denied by HTTP server")
                    assert not errors, errors
                    checked("No uncaught browser errors")
                    (out / "summary.json").write_text(json.dumps({"passed":True,"checks":results,
                        "scope":"Real Chromium, separate admin and worker contexts, isolated fake database, normal password auth; completion uses an explicitly started fake fixture; no real provider or production deployment",
                        "browser":browser.version,"timezones":["America/New_York","America/Los_Angeles"],
                        "viewports":[{"width":1440,"height":1000},{"width":390,"height":844}]},indent=2)+"\n")
                except Exception:
                    # Preserve the failing UI before finally closes the isolated
                    # browser contexts. All users and records here are synthetic.
                    for username, (_, page, _) in accounts.items():
                        try:
                            page.screenshot(path=str(out / f"failure-{username}.png"))
                        except Exception:
                            pass  # Keep the original acceptance failure.
                    raise
                finally:
                    for context in contexts:
                        context.close()
                    browser.close()
        finally:
            server.terminate()
            try:
                server.wait(timeout=10)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait(timeout=5)
            log.close()


def run_ui_flows(base, accounts, out, checked, passwords, data_dir):
    admin_ctx, admin, admin_session = accounts["admin"]
    alex_ctx, alex, alex_session = accounts["alex"]
    blair_ctx, blair, _ = accounts["blair"]
    expect(alex.get_by_test_id("job-table")).to_be_visible()
    alex.screenshot(path=str(out / "worker-schedule.png"), full_page=True)
    admin.screenshot(path=str(out / "admin-team.png"), full_page=True)

    def row(page, job_id):
        return page.locator(f'[data-job-id="{job_id}"]')

    jobs = alex_ctx.request.get(base+"/api/jobs").json()["jobs"]
    shared = next(j for j in jobs if j["signup_count"] == 0 and j["capacity"] >= 2)
    job_id = shared["id"]
    row(alex, job_id).get_by_role("button", name=re.compile(r"^Join job:")).click()
    expect(row(alex, job_id).get_by_role("button", name=re.compile(r"^Leave job:"))).to_be_visible()
    blair.get_by_role("button", name="Refresh", exact=True).click()
    expect(row(blair, job_id).get_by_text("Alex Rivera", exact=True)).to_be_visible()
    row(blair, job_id).get_by_role("button", name=re.compile(r"^Join job:")).click()
    expect(row(blair, job_id).get_by_role("button", name=re.compile(r"^Leave job:"))).to_be_visible()
    alex.get_by_label("Message to the crew", exact=True).fill("Keep this unfinished crew update")
    alex.get_by_role("button", name="Refresh", exact=True).click()
    expect(row(alex, job_id).get_by_text("Blair Chen", exact=True)).to_be_visible()
    expect(alex.get_by_label("Message to the crew", exact=True)).to_have_value("Keep this unfinished crew update")
    checked("Alex and Blair join the same job and see each other's names; refresh preserves a message draft")
    other = accounts["drew"][1]
    other.get_by_role("button", name="Refresh", exact=True).click()
    expect(row(other, job_id).get_by_text("Alex Rivera", exact=True)).to_be_visible()
    expect(row(other, job_id).get_by_text("Blair Chen", exact=True)).to_be_visible()
    if shared["capacity"] == 2:
        expect(row(other, job_id).get_by_role("button", name=re.compile(r"^Join job:"))).to_be_disabled()
    row(alex, job_id).get_by_role("button", name=re.compile(r"^Leave job:")).click()
    expect(row(alex, job_id).get_by_text("Alex Rivera", exact=True)).to_have_count(0)
    expect(row(alex, job_id).get_by_text("Blair Chen", exact=True)).to_be_visible()
    checked("Leaving removes only the current worker; peers see the full crew and capacity limit")

    def wait_ids(page, params):
        ids = [j["id"] for j in alex_ctx.request.get(base+"/api/jobs", params=params).json()["jobs"]]
        page.wait_for_function("ids => JSON.stringify([...document.querySelectorAll('[data-job-id]')].map(x=>x.dataset.jobId))===JSON.stringify(ids)", arg=ids)
        return ids

    for sort in ("hours", "pay", "starts_at"):
        alex.get_by_label("Sort by", exact=True).select_option(sort)
        expect(alex.get_by_label("Sort by", exact=True)).to_have_value(sort)
        alex.get_by_label("Order", exact=True).select_option("desc")
        wait_ids(alex, {"sort": sort, "direction": "desc"})
    checked("Date, numeric hours and currency sorting match server order")
    alex.get_by_label("Service", exact=True).select_option("irrigation")
    assert wait_ids(alex, {"service": "irrigation", "sort": "starts_at", "direction": "desc"})
    alex.get_by_label("Service", exact=True).select_option("")
    wait_ids(alex, {"sort": "starts_at", "direction": "desc"})
    for view, label in (("mine", "My jobs"), ("open", "Open jobs"), ("all", "All jobs")):
        alex.get_by_role("button", name=label, exact=True).click()
        wait_ids(alex, {"view": view, "sort": "starts_at", "direction": "desc"})
    date = datetime.fromisoformat(shared["starts_at"]).astimezone(__import__('zoneinfo').ZoneInfo('America/New_York')).date().isoformat()
    alex.get_by_label("Date (New York)", exact=True).fill(date)
    wait_ids(alex, {"date": date, "sort": "starts_at", "direction": "desc"})
    alex.get_by_label("Date (New York)", exact=True).fill("")
    wait_ids(alex, {"sort": "starts_at", "direction": "desc"})
    checked("Service, New York date, all/open/my jobs filters match authenticated server results")
    alex.get_by_label("Message to the crew", exact=True).fill("")
    alex.get_by_label("Order", exact=True).select_option("asc")
    wait_ids(alex, {"sort": "starts_at", "direction": "asc"})
    expect(alex.locator("#toast")).not_to_be_visible()
    alex.screenshot(path=str(out / "worker-schedule.png"), full_page=True)
    alex.screenshot(path=str(out / "worker-desktop.png"))

    marker = '<img src=x onerror="window.landscape_xss=1"> Crew message <script>window.landscape_xss=1</script>'
    alex.get_by_label("Message to the crew",exact=True).fill(marker)
    alex.get_by_role("button",name=re.compile(r"^Post message")).click()
    expect(alex.get_by_test_id("message-list").get_by_text(marker,exact=True)).to_be_visible()
    blair.reload()
    expect(blair.get_by_test_id("message-list").get_by_text(marker,exact=True)).to_be_visible()
    assert blair.get_by_test_id("message-list").locator("img, script").count() == 0
    assert blair.evaluate("window.landscape_xss") is None
    assert blair.get_by_test_id("message-list").get_by_text("Alex Rivera",exact=True).count() == 1
    checked("Shared board attributes the real author and renders hostile markup as literal text")

    admin.locator("#team-panel > summary").click()
    admin.get_by_role("button",name="+ Create account",exact=True).click()
    modal=admin.get_by_role("dialog")
    modal.get_by_label("Full name",exact=True).fill("Garden Tester")
    modal.get_by_label("Username",exact=True).fill("garden_tester")
    test_password="Browser-only fictional 42!"
    modal.get_by_label("Initial password",exact=True).fill(test_password)
    modal.get_by_role("button",name="Create account",exact=True).click()
    expect(modal).not_to_be_visible()
    new_user=next(x for x in admin_ctx.request.get(base+"/api/workers").json()["workers"] if x["username"]=="garden_tester")
    assert new_user["role"]=="worker"
    admin.get_by_role("button",name="+ Schedule job",exact=True).click()
    modal.get_by_label("Customer",exact=True).fill("Autumn Grove test property")
    modal.get_by_label("Work location",exact=True).fill("123 Fictional Garden Way")
    modal.get_by_label("Service",exact=True).select_option("planting")
    modal.get_by_label("Start date & time (New York)",exact=True).fill((datetime.now()+timedelta(days=3)).strftime("%Y-%m-%dT10:00"))
    modal.get_by_label("Hours",exact=True).fill("2.5")
    modal.get_by_label("Pay per person ($)",exact=True).fill("82.50")
    modal.get_by_label("Crew size",exact=True).fill("2")
    modal.get_by_role("button",name="Schedule job",exact=True).click()
    expect(modal).not_to_be_visible()
    expect(admin.get_by_test_id("job-table").locator("tbody tr")).to_have_count(13)
    assert admin.get_by_role("button",name=re.compile(r"^(Join|Leave) job:")).count() == 0
    admin.screenshot(path=str(out / "admin-team.png"), full_page=True)
    new_context=admin_ctx.browser.new_context(viewport={"width":1280,"height":900})
    try:
        new_page=new_context.new_page()
        new_page.goto(base)
        new_page.get_by_label("Username",exact=True).fill("garden_tester")
        new_page.get_by_label("Password",exact=True).fill(test_password)
        new_page.get_by_role("button",name=re.compile(r"^Sign in")).click()
        expect(new_page.get_by_test_id("job-table").locator("tbody tr")).to_have_count(13)
        assert new_context.request.get(base+"/api/admin/metrics").status==403
        new_page.get_by_test_id("job-table").locator("tr").filter(has_text="Autumn Grove test property").get_by_role("button",name=re.compile(r"^Join job:")).click()
        expect(new_page.get_by_role("button",name=re.compile(r"^Leave job:"))).to_have_count(1)
        checked("Admin creates an account/password and a shared job; new worker sees all 13 jobs and joins")
    finally:
        new_context.close()

    before=admin_ctx.request.get(base+"/api/admin/metrics").json()["metrics"]["booked_revenue"]
    admin.get_by_role("link",name=re.compile("Customers & outreach")).click()
    expect(admin.get_by_role("button",name="+ Add customer",exact=True)).to_be_visible()
    admin.get_by_role("button",name="+ Add customer",exact=True).click()
    modal.get_by_label("Customer name",exact=True).fill("Autumn Grove browser prospect")
    modal.get_by_label("Contact details",exact=True).fill("garden@example.test")
    modal.get_by_label("Service",exact=True).select_option("planting")
    modal.get_by_label("Outreach stage",exact=True).select_option("Lead")
    modal.get_by_label("Estimated value ($)",exact=True).fill("1234")
    modal.get_by_label("Follow-up notes",exact=True).fill("Fictional browser workflow")
    modal.get_by_role("button",name="Add customer",exact=True).click()
    expect(modal).not_to_be_visible()
    card=admin.locator(".customer-card").filter(has=admin.get_by_role("heading",name="Autumn Grove browser prospect",exact=True))
    card.get_by_label("Outreach stage",exact=True).select_option("Booked")
    card.get_by_label("Follow-up notes",exact=True).fill("Booked in this synthetic exercise")
    card.get_by_role("button",name="Save follow-up",exact=True).click()
    expect(card.locator(".badge")).to_have_text("Booked")
    after=admin_ctx.request.get(base+"/api/admin/metrics").json()["metrics"]["booked_revenue"]
    assert after==before+1234
    admin.screenshot(path=str(out / "admin-customers.png"),full_page=True)
    admin.get_by_role("link",name=re.compile("Business metrics")).click()
    expect(admin.get_by_text("Booked revenue",exact=True)).to_be_visible()
    admin.screenshot(path=str(out / "admin-metrics.png"),full_page=True)
    checked("Customer creation and outreach booking update actual business metrics")
    admin.get_by_role("link",name=re.compile("Dashboard health")).click()
    expect(admin.get_by_role("table",name="Security and activity audit",exact=True)).to_be_visible()
    admin.screenshot(path=str(out / "admin-health.png"),full_page=True)
    health=admin_ctx.request.get(base+"/api/admin/health").json()
    assert health["telemetry"]["denied_requests"]>=20
    assert any(e["action"]=="account.created" for e in health["audit"])
    checked("Admin audit and telemetry display actual protected activity and denials")

    admin.get_by_role("button",name="Freeze work",exact=True).click()
    expect(admin.get_by_role("button",name="Resume work",exact=True)).to_be_visible()
    alex.get_by_role("button",name=re.compile(r"^Join job:")).and_(alex.locator(":enabled")).first.click()
    expect(alex.get_by_role("button",name=re.compile(r"^Join job:")).first).to_be_disabled()
    assert alex_ctx.request.get(base+"/api/jobs").json()["frozen"] is True
    admin.get_by_role("button",name="Resume work",exact=True).click()
    expect(admin.get_by_role("button",name="Freeze work",exact=True)).to_be_visible()
    alex.reload()
    expect(alex.get_by_role("button",name=re.compile(r"^Join job:")).first).to_be_enabled()
    checked("Cross-session freeze denies a stale worker click and unfreeze restores controls")

    run_admin_job_flows(base, accounts, out, checked, passwords)
    run_job_lifecycle_flows(base, accounts, out, checked, passwords, data_dir)

    admin.get_by_role("link",name=re.compile("Schedule")).click()
    admin.locator("#team-panel").evaluate("el => { el.open = true; }")
    admin.get_by_role("button",name="Reset password for Blair Chen",exact=True).click()
    modal.get_by_label("Replacement password",exact=True).fill("Reset only synthetic password 73!")
    modal.get_by_role("button",name="Reset password",exact=True).click()
    expect(modal).not_to_be_visible()
    assert blair_ctx.request.get(base+"/api/session").status==401
    blair.goto(base)
    expect(blair.get_by_role("button",name=re.compile(r"^Sign in"))).to_be_visible()
    admin.get_by_role("button",name="Disable Casey Brooks",exact=True).click()
    modal.get_by_role("button",name="Disable account",exact=True).click()
    expect(modal).not_to_be_visible()
    assert accounts["casey"][0].request.get(base+"/api/session").status==401
    checked("Admin UI password reset and disable invalidate other browsers immediately")

    admin.get_by_role("link",name=re.compile("Business metrics")).click()
    expect(admin.get_by_text("Booked revenue",exact=True)).to_be_visible()
    admin.get_by_role("button",name="Sign out",exact=True).click()
    expect(admin.get_by_role("button",name=re.compile(r"^Sign in"))).to_be_visible()
    assert admin_ctx.request.get(base+"/api/admin/metrics").status==401
    assert admin.get_by_text("Booked revenue",exact=True).count()==0
    checked("Admin logout clears private UI and denies replay from that browser")

    # Independent small-screen check uses an already-authenticated worker context.
    alex.set_viewport_size({"width":390,"height":844})
    alex.goto(base)
    expect(alex.get_by_test_id("job-table")).to_be_visible()
    assert alex.evaluate("document.documentElement.scrollWidth <= window.innerWidth + 1")
    expect(alex.locator(".job-roster").first).to_be_visible()
    expect(alex.locator(".job-actions button").first).to_be_visible()
    alex.screenshot(path=str(out / "worker-mobile.png"),full_page=True)
    alex.screenshot(path=str(out / "worker-mobile-viewport.png"))
    checked("Worker dashboard remains usable without page overflow at mobile width")


def run_admin_job_flows(base, accounts, out, checked, passwords):
    """Exercise business effects and denial states through actual admin dialogs."""
    admin_ctx, admin, admin_session = accounts["admin"]
    alex_ctx, alex, _ = accounts["alex"]
    admin_headers = {"X-CSRF-Token": admin_session["csrf_token"], "Origin": base}
    worker_ids = {name: values[2]["user"]["id"] for name, values in accounts.items()}
    admin.get_by_role("link", name=re.compile("Schedule")).click()
    expect(admin.get_by_test_id("job-table")).to_be_visible()
    jobs_response = admin_ctx.request.get(base + "/api/admin/jobs", params={"view": "active"})
    assert jobs_response.status == 200
    job = next(job for job in jobs_response.json()["jobs"] if job["customer"] == "Autumn Grove test property")
    job_id = job["id"]
    job_url = base + f"/api/admin/jobs/{job_id}"
    modal = admin.get_by_role("dialog")

    def current_job():
        response = admin_ctx.request.get(job_url)
        assert response.status == 200
        return response.json()["job"]

    def crew_ids():
        return {person["id"] for person in current_job()["crew"]}

    def job_row(page):
        return page.locator(f'[data-job-id="{job_id}"]')

    def open_manage(page=admin):
        job_row(page).get_by_role("button", name=re.compile(r"^Manage job:")).click()
        expect(page.get_by_role("dialog").get_by_label("Crew capacity", exact=True)).to_be_visible()

    def select_crew(names, capacity):
        for username in ("alex", "blair", "casey", "drew", "ellis"):
            modal.locator(f'input[name="worker_ids"][value="{worker_ids[username]}"]').set_checked(username in names)
        garden = modal.get_by_role("checkbox", name="Garden Tester", exact=True)
        if garden.count():
            garden.uncheck()
        modal.get_by_label("Crew capacity", exact=True).fill(str(capacity))

    def save_crew():
        modal.get_by_role("button", name="Save crew", exact=True).click()
        expect(modal).not_to_be_visible()

    def worker_refresh():
        alex.get_by_role("button", name="Refresh", exact=True).click()
        expect(alex.get_by_role("button", name="Refresh", exact=True)).to_be_enabled()
        response = alex_ctx.request.get(base + "/api/jobs")
        assert response.status == 200
        assert all(set(person) == {"display_name"} for job in response.json()["jobs"] for person in job["crew"])

    def set_freeze(frozen):
        session = admin_ctx.request.get(base + "/api/session").json()
        response = admin_ctx.request.post(base + "/api/admin/freeze", headers=admin_headers,
            data={"frozen": frozen, "expected_revision": session["freeze_revision"]})
        assert response.status == 200

    # Every worker can call these URLs directly, but cannot obtain identifiers
    # from the private roster or mutate someone else's membership.
    for username in ("alex", "blair", "casey", "drew", "ellis"):
        context, page, session = accounts[username]
        assert page.get_by_role("button", name=re.compile(r"^Manage job:")).count() == 0
        assert page.locator("#archived-jobs-panel").count() == 0
        headers = {"X-CSRF-Token": session["csrf_token"], "Origin": base}
        for endpoint in ("/api/admin/jobs?view=active", "/api/admin/jobs?view=archived", f"/api/admin/jobs/{job_id}"):
            assert context.request.get(base + endpoint).status == 403
        assert context.request.put(job_url + "/crew", headers=headers,
            data={"worker_ids": [worker_ids["alex"]], "capacity": 2, "expected_revision": job["revision"]}).status == 403
        for operation in ("archive", "restore"):
            assert context.request.post(job_url + "/" + operation, headers=headers,
                data={"expected_revision": job["revision"]}).status == 403
    checked("All five workers lack admin job controls and are denied all six admin job API operations")

    origin = job_row(admin).get_by_role("button", name=re.compile(r"^Manage job:"))
    origin.focus()
    origin.press("Enter")
    expect(modal.get_by_label("Crew capacity", exact=True)).to_be_visible()
    assert modal.evaluate("element => element.contains(document.activeElement)")
    admin.keyboard.press("Escape")
    expect(modal).not_to_be_visible()
    expect(origin).to_be_focused()
    checked("Manage job opens by keyboard, contains focus and returns it to the initiating row on Escape")

    draft = "Keep this admin crew update while changing assignments"
    admin.get_by_label("Message to the crew", exact=True).fill(draft)
    open_manage()
    select_crew({"alex", "blair", "ellis"}, 3)
    admin.screenshot(path=str(out / "admin-manage-job-desktop.png"))
    save_crew()
    assert crew_ids() == {worker_ids[name] for name in ("alex", "blair", "ellis")}
    worker_refresh()
    for display_name in ("Alex Rivera", "Blair Chen", "Ellis Quinn"):
        expect(job_row(alex).get_by_text(display_name, exact=True)).to_be_visible()
    expect(admin.get_by_label("Message to the crew", exact=True)).to_have_value(draft)
    checked("Admin assigns three workers and changes capacity; shared worker roster and unfinished message remain correct")

    open_manage()
    select_crew({"alex", "ellis"}, 2)
    save_crew()
    assert crew_ids() == {worker_ids[name] for name in ("alex", "ellis")}
    worker_refresh()
    expect(job_row(alex).get_by_text("Blair Chen", exact=True)).to_have_count(0)
    expect(job_row(alex).get_by_text("Alex Rivera", exact=True)).to_be_visible()
    expect(job_row(alex).get_by_text("Ellis Quinn", exact=True)).to_be_visible()
    checked("Admin removes one worker without changing the other assignments and updates the shared schedule")

    open_manage()
    select_crew({"alex", "casey"}, 2)
    latest = current_job()
    competing = admin_ctx.request.put(job_url + "/crew", headers=admin_headers,
        data={"worker_ids": [worker_ids["alex"], worker_ids["blair"]], "capacity": 2, "expected_revision": latest["revision"]})
    assert competing.status == 200
    with admin.expect_response(lambda response: response.url == job_url + "/crew" and response.request.method == "PUT") as stale_save:
        modal.get_by_role("button", name="Save crew", exact=True).click()
    assert stale_save.value.status == 409
    expect(modal.get_by_role("button", name="Reload job", exact=True)).to_be_visible()
    expect(modal.get_by_role("button", name="Save crew", exact=True)).to_be_disabled()
    expect(modal.get_by_role("checkbox", name="Casey Brooks", exact=True)).to_be_checked()
    assert crew_ids() == {worker_ids[name] for name in ("alex", "blair")}
    modal.get_by_role("button", name="Reload job", exact=True).click()
    expect(modal.get_by_role("checkbox", name="Blair Chen", exact=True)).to_be_checked()
    expect(modal.get_by_role("checkbox", name="Casey Brooks", exact=True)).not_to_be_checked()
    admin.keyboard.press("Escape")
    checked("Stale admin save is rejected without overwriting a newer crew; explicit reload shows the latest assignments")

    open_manage()
    modal.get_by_role("button", name="Remove job…", exact=True).click()
    expect(modal.get_by_role("button", name="Remove job", exact=True)).to_be_visible()
    modal.get_by_role("button", name="Keep job", exact=True).click()
    assert current_job()["archived"] is False
    assert len(crew_ids()) == 2
    modal.get_by_role("button", name="Remove job…", exact=True).click()
    admin.screenshot(path=str(out / "admin-remove-job-confirmation.png"))
    modal.get_by_role("button", name="Remove job", exact=True).click()
    expect(modal).not_to_be_visible()
    expect(job_row(admin)).to_have_count(0)
    worker_refresh()
    expect(job_row(alex)).to_have_count(0)
    assert current_job()["archived"] is True
    assert crew_ids() == {worker_ids[name] for name in ("alex", "blair")}
    expect(admin.get_by_label("Message to the crew", exact=True)).to_have_value(draft)
    checked("Removing a staffed job requires confirmation, preserves its archive and removes it from every worker's schedule")

    archive = admin.locator("#archived-jobs-panel")
    if not archive.evaluate("element => element.open"):
        archive.locator(":scope > summary").click()
    archive_row = archive.locator(f'[data-archived-job-id="{job_id}"]')
    archive_row.get_by_role("button", name=re.compile(r"^Restore job:")).click()
    expect(modal.get_by_role("heading", name="Restore job?", exact=True)).to_be_visible()
    admin.screenshot(path=str(out / "admin-restore-job-confirmation.png"))
    modal.get_by_role("button", name="Restore job", exact=True).click()
    expect(modal).not_to_be_visible()
    expect(job_row(admin)).to_be_visible()
    assert current_job()["archived"] is False
    assert crew_ids() == set()
    worker_refresh()
    expect(job_row(alex).get_by_text("No one yet", exact=True)).to_be_visible()
    expect(job_row(alex).get_by_role("button", name=re.compile(r"^Join job:"))).to_be_enabled()
    checked("Restoring an archived job returns it to workers with an empty crew, requiring fresh assignments")

    open_manage()
    select_crew({"alex"}, 2)
    set_freeze(True)
    with admin.expect_response(lambda response: response.url == job_url + "/crew" and response.request.method == "PUT") as frozen_save:
        modal.get_by_role("button", name="Save crew", exact=True).click()
    assert frozen_save.value.status == 403
    expect(modal.get_by_role("alert")).to_contain_text("This action is not allowed.")
    assert crew_ids() == set()
    reload_job = modal.get_by_role("button", name="Reload job", exact=True)
    if reload_job.is_visible():
        reload_job.click()
    expect(modal.get_by_role("button", name="Save crew", exact=True)).to_be_disabled()
    expect(modal.get_by_role("checkbox", name="Alex Rivera", exact=True)).to_be_disabled()
    expect(modal.locator(".job-pause-notice")).to_contain_text("Work is paused")
    admin.screenshot(path=str(out / "admin-job-frozen.png"))
    admin.keyboard.press("Escape")
    set_freeze(False)
    admin.get_by_role("button", name="Refresh", exact=True).click()
    expect(admin.get_by_role("button", name="Freeze work", exact=True)).to_be_visible()
    checked("A freeze in another request blocks an already-open admin editor and leaves the crew unchanged")

    admin.set_viewport_size({"width": 390, "height": 844})
    open_manage()
    select_crew({"casey", "drew"}, 2)
    assert admin.evaluate("document.documentElement.scrollWidth <= window.innerWidth + 1")
    assert modal.evaluate("element => element.scrollWidth <= element.clientWidth + 1")
    for _ in range(12):
        admin.keyboard.press("Tab")
        # Native dialogs permit tabbing into browser chrome; any focused page
        # control must remain inside the dialog, never in its inert background.
        assert modal.evaluate("element => !document.hasFocus() || element.contains(document.activeElement)")
    admin.screenshot(path=str(out / "admin-manage-job-mobile.png"))
    save = modal.get_by_role("button", name="Save crew", exact=True)
    save.focus()
    save.press("Enter")
    expect(modal).not_to_be_visible()
    assert crew_ids() == {worker_ids[name] for name in ("casey", "drew")}
    open_manage()
    select_crew({"drew"}, 1)
    save_crew()
    assert crew_ids() == {worker_ids["drew"]}
    worker_refresh()
    expect(job_row(alex).get_by_text("Drew Parker", exact=True)).to_be_visible()
    expect(job_row(alex).get_by_text("Casey Brooks", exact=True)).to_have_count(0)
    expect(admin.get_by_label("Message to the crew", exact=True)).to_have_value(draft)
    assert admin.evaluate("document.documentElement.scrollWidth <= window.innerWidth + 1")
    admin.screenshot(path=str(out / "admin-schedule-mobile.png"), full_page=True)
    checked("Mobile admin can assign and remove workers by keyboard without overflow, focusing background controls or losing drafts")
    admin.set_viewport_size({"width": 1440, "height": 1000})

    # A separate real login gives us an expendable admin session to revoke,
    # without ending the admin session used by the original acceptance flows.
    revoked_context = admin_ctx.browser.new_context(viewport={"width": 1280, "height": 900}, timezone_id="America/New_York")
    try:
        revoked = revoked_context.new_page()
        revoked.goto(base)
        revoked.get_by_label("Username", exact=True).fill("admin")
        revoked.get_by_label("Password", exact=True).fill(passwords["admin"])
        revoked.get_by_role("button", name="Sign in", exact=True).click()
        expect(revoked.get_by_test_id("job-table")).to_be_visible()
        open_manage(revoked)
        revoked_modal = revoked.get_by_role("dialog")
        revoked_modal.get_by_role("checkbox", name="Drew Parker", exact=True).uncheck()
        revoked_modal.get_by_role("checkbox", name="Ellis Quinn", exact=True).check()
        session = revoked_context.request.get(base + "/api/session").json()
        assert revoked_context.request.post(base + "/api/logout",
            headers={"X-CSRF-Token": session["csrf_token"], "Origin": base}, data={}).status == 200
        with revoked.expect_response(lambda response: response.url == job_url + "/crew" and response.request.method == "PUT") as revoked_save:
            revoked_modal.get_by_role("button", name="Save crew", exact=True).click()
        assert revoked_save.value.status == 401
        expect(revoked_modal).not_to_be_visible()
        expect(revoked.get_by_role("button", name="Sign in", exact=True)).to_be_visible()
        assert revoked.get_by_role("button", name=re.compile(r"^Manage job:")).count() == 0
        assert revoked.get_by_text("Autumn Grove test property", exact=True).count() == 0
        assert revoked_context.request.get(job_url).status == 401
        assert crew_ids() == {worker_ids["drew"]}
        checked("Revoking an admin session while a job dialog is open clears private UI and prevents its pending save")
    finally:
        revoked_context.close()
    admin.get_by_label("Message to the crew", exact=True).fill("")


def run_job_lifecycle_flows(base, accounts, out, checked, passwords, data_dir):
    """Real lifecycle dialogs against this runner's disposable database only."""
    admin_ctx, _, _ = accounts["admin"]
    alex_ctx, alex, alex_session = accounts["alex"]
    context = admin_ctx.browser.new_context(
        viewport={"width": 1440, "height": 1000}, timezone_id="America/Los_Angeles"
    )
    errors = []
    try:
        admin = context.new_page()
        admin.on("pageerror", lambda error: errors.append(str(error)))
        admin.goto(base)
        admin.get_by_label("Username", exact=True).fill("admin")
        admin.get_by_label("Password", exact=True).fill(passwords["admin"])
        admin.get_by_role("button", name="Sign in", exact=True).click()
        expect(admin.get_by_test_id("job-table")).to_be_visible()
        session = context.request.get(base + "/api/session").json()
        headers = {"X-CSRF-Token": session["csrf_token"], "Origin": base}
        worker_headers = {"X-CSRF-Token": alex_session["csrf_token"], "Origin": base}
        modal = admin.get_by_role("dialog")
        year = datetime.now(timezone.utc).year + 4
        summer = f"{year}-06-20T09:00"
        winter = f"{year}-12-02T09:00"
        job_name = "Lifecycle browser test property"

        admin.get_by_role("button", name="+ Schedule job", exact=True).click()
        modal.get_by_label("Customer", exact=True).fill(job_name)
        modal.get_by_label("Work location", exact=True).fill("901 Fictional Lifecycle Lane")
        modal.get_by_label("Service", exact=True).select_option("planting")
        modal.get_by_label("Start date & time (New York)", exact=True).fill(summer)
        modal.get_by_label("Hours", exact=True).fill("2")
        modal.get_by_label("Pay per person ($)", exact=True).fill("80")
        modal.get_by_label("Crew size", exact=True).fill("2")
        modal.get_by_role("button", name="Schedule job", exact=True).click()
        expect(modal).not_to_be_visible()
        jobs = context.request.get(base + "/api/admin/jobs", params={"view": "active"}).json()["jobs"]
        job_id = next(job["id"] for job in jobs if job["customer"] == job_name)
        job_url = base + f"/api/admin/jobs/{job_id}"

        def current_job():
            response = context.request.get(job_url)
            assert response.status == 200
            return response.json()["job"]

        def job_row(page=admin):
            return page.locator(f'[data-job-id="{job_id}"]')

        def refresh(page):
            page.get_by_role("button", name="Refresh", exact=True).click()
            expect(page.get_by_role("button", name="Refresh", exact=True)).to_be_enabled()

        def open_manage():
            job_row().get_by_role("button", name=re.compile(r"^Manage job:")).click()
            expect(modal.get_by_label("Crew capacity", exact=True)).to_be_visible()

        def section(label):
            summary = modal.locator("summary").filter(has_text=re.compile("^" + re.escape(label) + "$"))
            if not summary.evaluate("element => element.parentElement.open"):
                summary.click()

        def schedule_proposal(start, reason):
            section("Reschedule job")
            modal.locator("#reschedule-start").fill(start)
            modal.locator("#reschedule-reason").fill(reason)
            modal.get_by_role("button", name="Review new schedule", exact=True).click()
            expect(modal.get_by_role("button", name="Confirm reschedule", exact=True)).to_be_visible()

        def confirm_schedule(status=200):
            with admin.expect_response(lambda response: response.url == job_url + "/schedule" and response.request.method == "PUT") as response:
                modal.get_by_role("button", name="Confirm reschedule", exact=True).click()
            assert response.value.status == status, response.value.text()
            if status == 200:
                expect(modal).not_to_be_visible()
            return response.value

        def status_proposal(status, reason):
            section("Complete or cancel job" if current_job()["lifecycle"] == "scheduled" else "Reopen job")
            modal.locator("#job-status-choice").select_option(status)
            modal.locator("#job-status-reason").fill(reason)
            modal.get_by_role("button", name="Review status change", exact=True).click()
            expect(modal.get_by_role("button", name="Confirm status change", exact=True)).to_be_visible()

        def confirm_status():
            with admin.expect_response(lambda response: response.url == job_url + "/status" and response.request.method == "POST") as response:
                modal.get_by_role("button", name="Confirm status change", exact=True).click()
            assert response.value.status == 200, response.value.text()
            expect(modal).not_to_be_visible()

        def set_freeze(frozen):
            latest_session = context.request.get(base + "/api/session").json()
            response = context.request.post(base + "/api/admin/freeze", headers=headers,
                data={"frozen": frozen, "expected_revision": latest_session["freeze_revision"]})
            assert response.status == 200

        assert datetime.fromisoformat(current_job()["starts_at"]) == datetime(year, 6, 20, 13, tzinfo=timezone.utc)
        expect(job_row().locator(".job-when")).to_contain_text("9:00")
        checked("Los Angeles browser schedules 9 am New York summer work at the correct UTC instant")

        open_manage()
        modal.get_by_role("checkbox", name="Alex Rivera", exact=True).check()
        modal.get_by_role("checkbox", name="Drew Parker", exact=True).check()
        modal.get_by_role("button", name="Save crew", exact=True).click()
        expect(modal).not_to_be_visible()
        crew = {person["id"] for person in current_job()["crew"]}
        admin_draft = "Keep this admin note through schedule and status changes"
        worker_draft = "Keep this worker note while reviewing job history"
        admin.get_by_label("Message to the crew", exact=True).fill(admin_draft)
        alex.get_by_label("Message to the crew", exact=True).fill(worker_draft)
        reason = 'Rain delay <img src=x onerror="window.lifecycle_xss=1">'
        open_manage()
        schedule_proposal(winter, reason)
        admin.screenshot(path=str(out / "admin-reschedule-confirmation.png"))
        confirm_schedule()
        updated = current_job()
        assert datetime.fromisoformat(updated["starts_at"]) == datetime(year, 12, 2, 14, tzinfo=timezone.utc)
        assert {person["id"] for person in updated["crew"]} == crew
        refresh(alex)
        expect(job_row(alex).locator(".job-when")).to_contain_text("9:00")
        expect(job_row(alex).get_by_text("Alex Rivera", exact=True)).to_be_visible()
        expect(job_row(alex).get_by_text("Drew Parker", exact=True)).to_be_visible()
        expect(admin.get_by_label("Message to the crew", exact=True)).to_have_value(admin_draft)
        expect(alex.get_by_label("Message to the crew", exact=True)).to_have_value(worker_draft)
        checked("Admin reschedules summer to winter New York time without changing crew or either user's message draft")

        open_manage()
        section("Job history")
        expect(modal.locator("#job-history-content").get_by_text("Reason: " + reason, exact=True)).to_be_visible()
        assert modal.locator("img, script").count() == 0
        assert admin.evaluate("window.lifecycle_xss") is None
        history = context.request.get(job_url + "/history").json()["history"]
        change = next(event for event in history if event["reason"] == reason)
        assert change["before"]["starts_at"] != change["after"]["starts_at"]
        assert {person["id"] for person in change["after"]["crew"]} == crew
        admin.screenshot(path=str(out / "admin-job-history.png"))
        admin.keyboard.press("Escape")
        for username in ("alex", "blair", "casey", "drew", "ellis"):
            worker_context, _, worker_session = accounts[username]
            denied_headers = {"X-CSRF-Token": worker_session["csrf_token"], "Origin": base}
            assert worker_context.request.get(job_url + "/history").status == 403
            assert worker_context.request.put(job_url + "/schedule", headers=denied_headers,
                data={"starts_at": f"{year}-12-04T14:00:00+00:00", "expected_revision": updated["revision"], "reason": "Forbidden worker edit"}).status == 403
            assert worker_context.request.post(job_url + "/status", headers=denied_headers,
                data={"status": "cancelled", "expected_revision": updated["revision"], "reason": "Forbidden worker edit"}).status == 403
        checked("Admin history shows before and after with literal reasons; all five workers are denied history, rescheduling and status APIs")

        # The second Sunday in March skips 02:30; the first Sunday in November
        # repeats 01:30. Never let the browser's own zone silently choose either.
        march = datetime(year, 3, 8)
        spring = march + timedelta(days=(6 - march.weekday()) % 7)
        november = datetime(year, 11, 1)
        autumn = november + timedelta(days=(6 - november.weekday()) % 7)
        before = current_job()
        open_manage()
        section("Reschedule job")
        modal.locator("#reschedule-reason").fill("DST validation fixture")
        for value in (spring.strftime("%Y-%m-%dT02:30"), autumn.strftime("%Y-%m-%dT01:30")):
            modal.locator("#reschedule-start").fill(value)
            modal.get_by_role("button", name="Review new schedule", exact=True).click()
            expect(modal.get_by_role("alert")).to_contain_text(re.compile("(daylight|clock|ambiguous|exist|twice)", re.I))
            expect(modal.get_by_role("button", name="Confirm reschedule", exact=True)).not_to_be_visible()
        assert current_job() == before
        admin.keyboard.press("Escape")
        checked("New York daylight-saving gaps and repeated times are rejected before confirmation in a different browser timezone")

        # A second job shares Drew and deliberately conflicts with this proposal.
        response = context.request.post(base + "/api/admin/jobs", headers=headers, data={
            "customer": "Lifecycle overlap fixture", "site": "902 Fictional Lifecycle Lane", "service": "cleanup",
            "starts_at": f"{year}-12-03T14:00:00+00:00", "hours": 2, "pay": 60, "capacity": 1,
        })
        assert response.status == 200, response.text()
        conflict_jobs = context.request.get(base + "/api/admin/jobs", params={"view": "active"}).json()["jobs"]
        conflict_id = next(job["id"] for job in conflict_jobs if job["customer"] == "Lifecycle overlap fixture")
        conflict_url = base + f"/api/admin/jobs/{conflict_id}"
        conflict = context.request.get(conflict_url).json()["job"]
        response = context.request.put(conflict_url + "/crew", headers=headers, data={
            "worker_ids": [accounts["drew"][2]["user"]["id"]], "capacity": 1, "expected_revision": conflict["revision"],
        })
        assert response.status == 200
        open_manage()
        schedule_proposal(f"{year}-12-03T09:00", "Customer requested an overlapping slot")
        before = current_job()
        conflict_response = confirm_schedule(status=409)
        assert conflict_response.json()["code"] == "schedule_conflict"
        assert current_job() == before
        override = modal.get_by_role("button", name="Save despite overlap", exact=True)
        expect(override).to_be_disabled()
        modal.locator("#reschedule-start-overlap").check()
        expect(override).to_be_enabled()
        admin.screenshot(path=str(out / "admin-schedule-overlap.png"))
        with admin.expect_response(lambda response: response.url == job_url + "/schedule" and response.request.method == "PUT") as accepted:
            override.click()
        assert accepted.value.status == 200
        expect(modal).not_to_be_visible()
        assert {person["id"] for person in current_job()["crew"]} == crew
        checked("Overlapping employee work warns without saving and requires an explicit acknowledgement before the admin overrides it")

        open_manage()
        schedule_proposal(f"{year}-12-04T09:00", "Stale schedule reason must remain visible")
        before = current_job()
        competing = context.request.put(job_url + "/crew", headers=headers, data={
            "worker_ids": list(crew), "capacity": 3, "expected_revision": before["revision"],
        })
        assert competing.status == 200
        stale = confirm_schedule(status=409)
        assert stale.json().get("code") != "schedule_conflict"
        expect(modal.get_by_role("button", name="Save despite overlap", exact=True)).not_to_be_visible()
        expect(modal.get_by_role("button", name="Reload job", exact=True)).to_be_visible()
        expect(modal.get_by_role("button", name="Confirm reschedule", exact=True)).to_be_disabled()
        expect(modal.locator("#reschedule-reason")).to_have_value("Stale schedule reason must remain visible")
        assert current_job()["starts_at"] == before["starts_at"]
        modal.get_by_role("button", name="Reload job", exact=True).click()
        expect(modal.get_by_label("Crew capacity", exact=True)).to_have_value("3")
        admin.keyboard.press("Escape")
        checked("A stale schedule confirmation cannot use overlap override or overwrite newer staffing and requires an explicit reload")

        open_manage()
        schedule_proposal(f"{year}-12-04T09:00", "Frozen schedule must not save")
        before = current_job()
        set_freeze(True)
        confirm_schedule(status=403)
        assert current_job() == before
        expect(modal.get_by_role("button", name="Confirm reschedule", exact=True)).to_be_disabled()
        admin.keyboard.press("Escape")
        set_freeze(False)
        refresh(admin)
        checked("A cross-session freeze rejects an already-reviewed reschedule without changing the job")

        admin.set_viewport_size({"width": 390, "height": 844})
        open_manage()
        schedule_proposal(f"{year}-12-04T09:00", "Mobile keyboard reschedule")
        assert admin.evaluate("document.documentElement.scrollWidth <= window.innerWidth + 1")
        assert modal.evaluate("element => element.scrollWidth <= element.clientWidth + 1")
        for _ in range(12):
            admin.keyboard.press("Tab")
            assert modal.evaluate("element => !document.hasFocus() || element.contains(document.activeElement)")
        confirm = modal.get_by_role("button", name="Confirm reschedule", exact=True)
        confirm.focus()
        confirm.scroll_into_view_if_needed()
        admin.screenshot(path=str(out / "admin-reschedule-mobile.png"))
        with admin.expect_response(lambda response: response.url == job_url + "/schedule" and response.request.method == "PUT") as mobile_save:
            confirm.press("Enter")
        assert mobile_save.value.status == 200
        expect(modal).not_to_be_visible()
        expect(admin.get_by_label("Message to the crew", exact=True)).to_have_value(admin_draft)
        checked("Mobile rescheduling can be reviewed and confirmed by keyboard without overflow, background focus or lost drafts")
        admin.set_viewport_size({"width": 1440, "height": 1000})

        open_manage()
        section("Complete or cancel job")
        expect(modal.locator('#job-status-choice option[value="completed"]')).to_be_disabled()
        status_proposal("cancelled", "Customer cancelled due to access restrictions")
        admin.screenshot(path=str(out / "admin-status-confirmation.png"))
        confirm_status()
        expect(job_row().get_by_text("Cancelled", exact=True)).to_be_visible()
        admin.get_by_role("button", name="All jobs", exact=True).click()
        expect(job_row()).to_have_count(0)
        refresh(alex)
        expect(job_row(alex)).to_have_count(0)
        alex.get_by_role("button", name="Completed & cancelled", exact=True).click()
        expect(job_row(alex).get_by_text("Cancelled", exact=True)).to_be_visible()
        assert job_row(alex).get_by_role("button", name=re.compile(r"^(Join|Leave) job:")).count() == 0
        assert alex_ctx.request.post(base + f"/api/jobs/{job_id}/signup", headers=worker_headers, data={}).status == 409
        assert alex_ctx.request.delete(base + f"/api/jobs/{job_id}/signup", headers=worker_headers).status == 409
        expect(alex.get_by_label("Message to the crew", exact=True)).to_have_value(worker_draft)
        alex.screenshot(path=str(out / "worker-cancelled-history.png"), full_page=True)
        checked("Cancelled jobs move out of upcoming work into shared history, retain their crew and reject worker signup changes")

        admin.get_by_role("button", name="Completed & cancelled", exact=True).click()
        open_manage()
        status_proposal("scheduled", "Customer restored access; reopen the original crew")
        confirm_status()
        admin.get_by_role("button", name="All jobs", exact=True).click()
        expect(job_row()).to_be_visible()
        assert {person["id"] for person in current_job()["crew"]} == crew
        alex.get_by_role("button", name="All jobs", exact=True).click()
        expect(job_row(alex).get_by_role("button", name=re.compile(r"^Leave job:")).first).to_be_enabled()
        checked("Admin can correct a cancellation by reopening the job with its original crew visible to workers")

        # Creating a started fixture is setup, not a product operation. The
        # passed directory is exclusively this runner's TemporaryDirectory;
        # live runtime data and accounts are never opened by this test.
        started_at = (datetime.now(timezone.utc) - timedelta(days=1)).replace(microsecond=0).isoformat()
        with sqlite3.connect(data_dir / "landscape.sqlite3") as fixture:
            fixture.execute("UPDATE jobs SET starts_at=?, revision=revision+1 WHERE id=?", (started_at, job_id))
        refresh(admin)
        open_manage()
        status_proposal("completed", "Crew confirmed all work finished")
        confirm_status()
        expect(job_row().get_by_text("Completed", exact=True)).to_be_visible()
        admin.get_by_role("button", name="All jobs", exact=True).click()
        expect(job_row()).to_have_count(0)
        alex.get_by_role("button", name="Completed & cancelled", exact=True).click()
        expect(job_row(alex).get_by_text("Completed", exact=True)).to_be_visible()
        assert job_row(alex).get_by_role("button", name=re.compile(r"^(Join|Leave) job:")).count() == 0
        assert alex_ctx.request.post(base + f"/api/jobs/{job_id}/signup", headers=worker_headers, data={}).status == 409
        admin.get_by_role("button", name="Completed & cancelled", exact=True).click()
        open_manage()
        section("Job history")
        expect(modal.locator("#job-history-content").get_by_text("Reason: Crew confirmed all work finished", exact=True)).to_be_visible()
        admin.screenshot(path=str(out / "admin-completed-job-history.png"))
        status_proposal("scheduled", "Correct premature completion before the final site inspection")
        confirm_status()
        admin.get_by_role("button", name="All jobs", exact=True).click()
        expect(job_row().get_by_text("Started", exact=True)).to_be_visible()
        assert current_job()["lifecycle"] == "scheduled"
        assert {person["id"] for person in current_job()["crew"]} == crew
        checked("Started work can be completed into shared history and an admin can reopen a mistaken completion with its crew intact")

        open_manage()
        schedule_proposal(f"{year}-12-05T09:00", "Revoked admin confirmation must not save")
        before = current_job()
        response = context.request.post(base + "/api/logout", headers=headers, data={})
        assert response.status == 200
        confirm_schedule(status=401)
        expect(modal).not_to_be_visible()
        expect(admin.get_by_role("button", name="Sign in", exact=True)).to_be_visible()
        assert admin.get_by_text(job_name, exact=True).count() == 0
        assert context.request.get(job_url + "/history").status == 401
        assert admin_ctx.request.get(job_url).json()["job"] == before
        checked("Revoking an admin session after review blocks reschedule confirmation and clears private job and history UI")
        alex.get_by_role("button", name="All jobs", exact=True).click()
        alex.get_by_label("Message to the crew", exact=True).fill("")
        assert not errors, errors
    except Exception:
        try:
            admin.screenshot(path=str(out / "failure-lifecycle-admin.png"))
        except Exception:
            pass
        raise
    finally:
        context.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", help="Empty evidence directory outside the repository")
    parser.add_argument("--browser-executable", help="Optional Chromium executable; defaults to Playwright's browser")
    args = parser.parse_args()
    try:
        out = evidence_directory(args.output_dir)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    print(f"Browser evidence: {out}", flush=True)
    run(out, args.browser_executable)


if __name__ == "__main__":
    main()
