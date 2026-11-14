"""Disposable browser proof of delivery and the installed web component studio."""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta
import json
from pathlib import Path
import socket
import sys
import tempfile
import traceback

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "examples" / "business_dashboard"))

from tools.business_dashboard_browser import prepare_fixture, synthetic_database, synthetic_mfa_clock  # noqa: E402
from tools.business_enrollment_browser import local_server  # noqa: E402


def exercise_walkthrough(page, expect, checks, role, capture):
    titles = (["Start with the business outcome", "Turn interest into committed work",
               "Follow through to the handover", "Inspect the proof"] if role == "admin" else
              ["Know the plan", "Make your next move", "Keep everyone in sync"])
    writes = []

    def observe(request):
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            writes.append(request.method)

    page.on("request", observe)
    page.get_by_role("button", name="Workspace walkthrough", exact=True).click()
    tour = page.locator(".radt-tour")
    for index, title in enumerate(titles):
        expect(tour.get_by_role("heading", name=title, exact=True)).to_be_visible()
        expect(tour).to_have_attribute("aria-busy", "false")
        if index == 0:
            page.keyboard.press("Tab")
            assert page.evaluate("document.querySelector('.radt-tour').contains(document.activeElement)")
            capture(f"walkthrough-{role}")
        tour.get_by_role("button", name="Finish" if index == len(titles) - 1 else "Next", exact=True).click()
    expect(tour).to_have_count(0)
    expect(page.get_by_role("button", name="Workspace walkthrough", exact=True)).to_be_focused()
    page.get_by_role("button", name="Workspace walkthrough", exact=True).click()
    expect(tour).to_have_attribute("aria-busy", "false")
    page.keyboard.press("Escape")
    expect(tour).to_have_count(0)
    expect(page.get_by_role("button", name="Workspace walkthrough", exact=True)).to_be_focused()
    page.get_by_role("button", name="Workspace walkthrough", exact=True).click()
    expect(tour).to_have_attribute("aria-busy", "false")
    # Simulate the host learning of a changed role; this does not change a server grant.
    assert page.evaluate("""() => {
        const original=state.user;
        setSession({...state,user:{...original,role:original.role==='admin'?'employee':'admin'}});
        const closed=!document.querySelector('.radt-tour');
        setSession({...state,user:original});return closed;
    }"""), "A changed role left the old walkthrough open"
    expect(tour).to_have_count(0)
    assert not writes, "Walkthrough navigation must not send business writes"
    page.remove_listener("request", observe)
    checks.append(f"{role} walkthrough visits only its role's pages, traps and restores focus, closes on a simulated role change and sends no writes")


def exercise_branding(page, expect, checks, capture, origin, root, output):
    from role_aware_dashboard_toolkit.cli import initialize_project
    from role_aware_dashboard_toolkit.web import WebPresentation, WebTheme

    page.set_viewport_size({"width": 1440, "height": 1000})
    page.locator("#brand-studio > summary").click()
    page.get_by_label("Brand name", exact=True).fill("Harbor & Co.")
    page.get_by_label("Headline", exact=True).fill("A clearer day for your team.")
    for label, value in (("Accent color", "#5C3A70"), ("Soft accent color", "#F0EAF5"),
                         ("Dark surface color", "#302342")):
        page.get_by_label(label, exact=True).fill(value)
    page.get_by_role("button", name="Apply brand", exact=True).click()
    expect(page.locator("#brand")).to_have_text("Harbor & Co. / Component studio")
    page.get_by_label("Text color", exact=True).fill("#FFFFFF")
    page.get_by_role("button", name="Apply brand", exact=True).click()
    expect(page.locator("#brand-error")).to_contain_text("contrast")
    expect(page.locator("#brand")).to_have_text("Harbor & Co. / Component studio")
    page.get_by_label("Text color", exact=True).fill("#203D3A")
    page.get_by_role("button", name="Apply brand", exact=True).click()
    with page.expect_download() as download:
        page.get_by_role("button", name="Export configuration", exact=True).click()
    exported = output / "exported-brand.json"
    download.value.save_as(str(exported))
    config = WebPresentation.from_json(exported.read_text(encoding="utf-8"))
    assert config.brand == "Harbor & Co." and config.theme.accent == "#5C3A70"
    initialize_project(str(root / "configured-studio"), web=True, web_config=str(exported))
    page.goto(origin + "/configured-studio/")
    expect(page.locator("#brand")).to_have_text("Harbor & Co. / Component studio")
    expect(page.locator("#title")).to_have_text("A clearer day for your team.")
    assert page.evaluate("getComputedStyle(document.documentElement).getPropertyValue('--radt-accent').trim()") == "#5C3A70"
    capture("11-configured-studio")
    checks.append("browser-exported branding regenerates a fresh studio through the Python CLI with identical colors and text")

    page.locator("#brand-studio > summary").click()
    for contents, message in ((b'{"schema_version":1,"brand":"first","brand":"last"}', "Duplicate"),
                              (b" " * 65537, "64 KiB")):
        page.locator("#brand-import").set_input_files({"name": "rejected.json", "mimeType": "application/json", "buffer": contents})
        expect(page.locator("#brand-error")).to_contain_text(message)
        expect(page.locator("#brand")).to_have_text("Harbor & Co. / Component studio")
    hostile = json.loads(config.to_json())
    hostile["brand"] = "<img src=x onerror=alert(1)>"
    page.locator("#brand-import").set_input_files({"name": "text.json", "mimeType": "application/json", "buffer": json.dumps(hostile).encode()})
    expect(page.locator("#brand")).to_contain_text(hostile["brand"])
    expect(page.locator("#brand img, #records img")).to_have_count(0)
    page.locator("#brand-import").set_input_files(str(exported))
    expect(page.locator("#brand")).to_have_text("Harbor & Co. / Component studio")
    page.evaluate("""() => {
        const original=File.prototype.text;
        File.prototype.text=function(){return new Promise(resolve=>window.releaseBrandImport=resolve);};
        try{
            const transfer=new DataTransfer();transfer.items.add(new File(['{}'],'delayed.json',{type:'application/json'}));
            const input=document.querySelector('#brand-import');input.files=transfer.files;
            input.dispatchEvent(new Event('change',{bubbles:true}));
        }finally{File.prototype.text=original;}
    }""")
    page.get_by_label("Brand name", exact=True).fill("A newer draft")
    page.evaluate("async text=>{window.releaseBrandImport(text);await Promise.resolve();await Promise.resolve();}", config.to_json())
    expect(page.get_by_label("Brand name", exact=True)).to_have_value("A newer draft")
    expect(page.locator("#brand")).to_have_text("Harbor & Co. / Component studio")
    page.get_by_label("Brand name", exact=True).fill("Harbor & Co.")
    page.set_viewport_size({"width": 320, "height": 844})
    capture("12-brand-editor-mobile")
    checks.append("brand imports reject ambiguous and oversized files, preserve newer drafts and applied state on failure, and render markup as text at 320 pixels")

    page.get_by_role("button", name="Quick walkthrough", exact=True).click()
    tour = page.locator(".radt-tour")
    for title in ("One toolkit, your brand", "Connect the numbers to the work", "See the whole delivery", "Make the next demo repeatable"):
        expect(tour.get_by_role("heading", name=title, exact=True)).to_be_visible()
        expect(tour).to_have_attribute("aria-busy", "false")
        if title == "One toolkit, your brand":
            capture("13-studio-walkthrough-mobile")
        tour.get_by_role("button", name="Finish" if title == "Make the next demo repeatable" else "Next", exact=True).click()
    expect(tour).to_have_count(0)
    expect(page.get_by_role("button", name="Quick walkthrough", exact=True)).to_be_focused()
    # Exercise delayed callbacks and failure/retry without a network or business action.
    assert page.evaluate("""async () => {
        let release,closes=0;
        const first=RADTTour.create({steps:[{title:'<img src=x>',body:'Plain text'}],
            onStep:()=>new Promise(resolve=>release=resolve),onClose:()=>closes++});
        const pending=first.start();
        if(document.querySelector('.radt-tour img'))return false;
        first.close();release();await pending;
        if(closes!==1||document.querySelector('.radt-tour'))return false;
        let calls=0;
        const second=RADTTour.create({steps:[{title:'Retry example',body:'Read-only'}],
            onStep:async()=>{if(++calls===1)throw new Error('synthetic');}});
        await second.start();
        if(document.querySelector('[data-tour=next]').textContent!=='Try again')return false;
        document.querySelector('[data-tour=next]').click();
        await Promise.resolve();await Promise.resolve();
        const valid=calls===2&&document.querySelector('[data-tour=next]').textContent==='Finish';
        second.close();return valid&&!document.querySelector('.radt-tour');
    }""")
    checks.append("shared walkthrough works in the second host on mobile; dismissal ignores late callbacks and failed steps retry without advancing")
    night = WebPresentation(brand="Nightshift", theme=WebTheme(
        ink="#F4F5F0", muted="#D9E2DB", canvas="#14211D", surface="#172B25",
        accent="#CFE7C9", accent_soft="#263C32", line="#52685C", dark="#EDF4E8"))
    page.locator("#brand-import").set_input_files({"name": "night.json", "mimeType": "application/json", "buffer": night.to_json().encode()})
    expect(page.locator("#brand")).to_have_text("Nightshift / Component studio")
    assert page.evaluate("""() => ['.radt-metric-accent','.radt-metric-accent .radt-note','#steps [aria-current=step] > span'].every(selector=>getComputedStyle(document.querySelector(selector)).color==='rgb(23, 43, 37)')""")
    page.set_viewport_size({"width": 1440, "height": 1000})
    capture("14-inverted-theme")
    page.locator("#brand-import").set_input_files(str(exported))
    expect(page.locator("#brand")).to_have_text("Harbor & Co. / Component studio")
    checks.append("an inverted palette passes both validators and rendered emphasized text follows its declared theme instead of fixed white")


def main(argv=None):
    if not __debug__:
        raise SystemExit("Browser proof requires assertions; do not use -O.")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--browser-channel", default=None)
    args = parser.parse_args(argv)
    output = args.output_dir.resolve()
    if output == ROOT or ROOT in output.parents or (output.exists() and any(output.iterdir())):
        parser.error("Use a new, empty evidence directory outside the checkout.")
    output.mkdir(parents=True, exist_ok=True)
    from fastapi.staticfiles import StaticFiles
    from playwright.sync_api import sync_playwright, expect
    from business.evidence import new_receipt, finish_browser_receipt, write_receipt
    from role_aware_dashboard_toolkit.cli import initialize_project

    checks, failure, runtime = [], None, {}
    receipt = new_receipt("browser", ())
    try:
        with tempfile.TemporaryDirectory(prefix="radt-delivery-") as temporary:
            root = Path(temporary)
            with socket.socket() as reservation:
                reservation.bind(("127.0.0.1", 0))
                port = reservation.getsockname()[1]
            origin = f"http://127.0.0.1:{port}"
            credentials, application = prepare_fixture(root / "private", origin)
            initialize_project(str(root / "studio"), web=True)
            application.mount("/component-studio", StaticFiles(directory=root / "studio", html=True))
            application.mount("/configured-studio", StaticFiles(directory=root / "configured-studio", html=True, check_dir=False))
            with local_server(application, port), synthetic_mfa_clock(synthetic_database(root / "private")) as code, sync_playwright() as playwright:
                browser = playwright.chromium.launch(channel=args.browser_channel, headless=True)
                runtime = {"name": "chrome" if args.browser_channel and args.browser_channel.startswith("chrome") else "chromium", "version": browser.version}
                context = browser.new_context(viewport={"width": 1440, "height": 1000})
                page = context.new_page()
                errors = []
                page.on("pageerror", lambda error: errors.append(type(error).__name__))

                def capture(name):
                    if name != "failure" and page.locator("#toast").count():
                        expect(page.locator("#toast")).not_to_be_visible(timeout=7000)
                    page.screenshot(path=str(output / f"{name}.png"), full_page=not bool(page.locator(".radt-tour[open]").count()),
                                    mask=[page.locator('input[type=password],input[name=otp]')])
                    if name != "failure":
                        assert page.evaluate("document.documentElement.scrollWidth<=innerWidth"), "Horizontal overflow"

                def login(username):
                    page.goto(origin)
                    page.get_by_label("Username", exact=True).fill(username)
                    page.get_by_label("Password", exact=True).fill(credentials[username])
                    page.get_by_label("Authenticator code", exact=True).fill(code(username))
                    page.get_by_role("button", name="Sign in", exact=True).click()
                    expect(page.get_by_role("button", name="Sign out", exact=True)).to_be_visible()

                try:
                    login("admin")
                    expect(page.get_by_role("heading", name="A clear view,", exact=False)).to_be_visible()
                    exercise_walkthrough(page, expect, checks, "admin", capture)
                    page.get_by_role("button", name="Overview", exact=True).click()
                    capture("01-owner-overview")
                    page.get_by_role("button", name="Work", exact=True).click()
                    expect(page.locator(".radt-board-lane")).to_have_count(3)
                    expect(page.locator(".radt-board-card")).to_have_count(0)
                    expect(page.locator("#work-result-count")).to_have_text("0 of 0 work items · Workspace delivery")
                    checks.append("empty workspace presents all three stages with an accurate zero result count")
                    page.get_by_role("button", name="Outreach", exact=True).click()
                    page.get_by_role("button", name="Edit Jordan Lee", exact=True).click()
                    page.locator("#editor select[name=stage]").select_option("Won")
                    page.locator("#editor").get_by_role("button", name="Save contact", exact=True).click()
                    expect(page.locator("#editor")).not_to_be_visible()
                    page.get_by_role("button", name="Overview", exact=True).click()
                    page.get_by_role("button", name="Schedule won opportunities", exact=False).click()
                    expect(page.locator("#contact-filter")).to_have_value("Won")
                    page.get_by_role("button", name="Schedule Northline Studio", exact=True).click()
                    dialog = page.locator("#editor")
                    dialog.get_by_label("Event title", exact=True).fill("Northline Studio client handover")
                    starts = (datetime.now() + timedelta(days=20)).replace(hour=10, minute=0, second=0, microsecond=0)
                    dialog.get_by_label("Starts", exact=True).fill(starts.strftime("%Y-%m-%dT%H:%M"))
                    dialog.get_by_label("Ends", exact=True).fill((starts + timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M"))
                    dialog.get_by_label("Alex Morgan", exact=True).check()
                    dialog.get_by_role("button", name="Schedule delivery", exact=True).click()
                    expect(page.get_by_role("heading", name="Good work, delivered.", exact=True)).to_be_visible()
                    expect(page.get_by_role("heading", name="Northline Studio client handover", exact=True)).to_be_visible()
                    expect(page.locator(".work-intro [aria-current=step]")).to_have_count(0)
                    expect(page.locator('.radt-board-lane[data-lane="scheduled"] .radt-board-card')).to_have_count(1)
                    page.get_by_role("button", name="View details: Northline Studio client handover", exact=True).click()
                    expect(page.locator(".work-card")).to_be_focused()
                    expect(page.locator(".work-card [aria-current=step]")).to_have_text("1Scheduled")
                    capture("02-scheduled-work")
                    checks.append("owner converts a won contact into one scheduled assignment through the real UI")
                    page.get_by_role("button", name="Sign out", exact=True).click()
                    expect(page.get_by_label("Username", exact=True)).to_be_visible()
                    login("alex")
                    exercise_walkthrough(page, expect, checks, "employee", capture)
                    page.get_by_role("button", name="Work", exact=True).click()
                    page.set_viewport_size({"width": 390, "height": 844})
                    expect(page.get_by_role("heading", name="Your work. Your next move.", exact=True)).to_be_visible()
                    page.get_by_role("button", name="Cards", exact=True).click()
                    page.get_by_role("button", name="Start work", exact=False).click()
                    dialog.get_by_label("Progress note", exact=True).fill("Delivering the agreed client scope.")
                    dialog.get_by_role("button", name="Start work", exact=True).click()
                    expect(dialog).not_to_be_visible()
                    expect(page.locator(".work-card .badge")).to_have_text("In progress")
                    capture("03-mobile-in-progress")
                    page.get_by_role("button", name="Complete & hand over", exact=False).click()
                    dialog.get_by_label("Handover note", exact=True).fill("Delivered the final package. <img src=x onerror=alert(1)>")
                    dialog.get_by_role("button", name="Record completion", exact=True).click()
                    expect(dialog).not_to_be_visible()
                    expect(page.locator(".completed-label")).to_be_visible()
                    page.locator(".work-history summary").click()
                    expect(page.locator(".work-history img")).to_have_count(0)
                    expect(page.get_by_text("Delivered the final package.", exact=False)).to_be_visible()
                    for width in (390, 320):
                        page.set_viewport_size({"width": width, "height": 844})
                        capture(f"04-completed-{width}")
                    checks.append("assigned employee starts and completes on mobile; handover markup remains escaped at 390 and 320 pixels")
                    page.set_viewport_size({"width": 1440, "height": 1000})
                    page.get_by_role("button", name="Sign out", exact=True).click()
                    expect(page.get_by_label("Username", exact=True)).to_be_visible()
                    login("admin")
                    completed = page.get_by_role("button", name="Completed work", exact=False)
                    expect(completed.locator("strong")).to_have_text("1")
                    capture("05-owner-updated")
                    page.set_viewport_size({"width": 390, "height": 844})
                    capture("05-owner-mobile")
                    page.set_viewport_size({"width": 1440, "height": 1000})
                    completed.click()
                    expect(page.locator('[data-work-filter="completed"]')).to_have_attribute("aria-pressed", "true")
                    expect(page.get_by_role("heading", name="Northline Studio client handover", exact=True)).to_be_visible()
                    checks.append("owner metric derives from saved completion and drills down to completed work")

                    # Populate the other lanes through the real protected UI.
                    for company, person, employee, offset in (("Form & Function", None, "Alex Morgan", 21),
                                                              ("Fieldwork Co.", "Taylor Quinn", "Blair Chen", 22)):
                        page.get_by_role("button", name="Outreach", exact=True).click()
                        if person:
                            page.get_by_role("button", name=f"Edit {person}", exact=True).click()
                            dialog.locator('select[name=stage]').select_option("Won")
                            dialog.get_by_role("button", name="Save contact", exact=True).click()
                            expect(dialog).not_to_be_visible()
                        page.get_by_role("button", name=f"Schedule {company}", exact=True).click()
                        dialog.get_by_label("Event title", exact=True).fill(company + " onboarding")
                        begins = starts + timedelta(days=offset - 20)
                        dialog.get_by_label("Starts", exact=True).fill(begins.strftime("%Y-%m-%dT%H:%M"))
                        dialog.get_by_label("Ends", exact=True).fill((begins + timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M"))
                        dialog.get_by_label(employee, exact=True).check()
                        dialog.get_by_role("button", name="Schedule delivery", exact=True).click()
                        expect(dialog).not_to_be_visible()
                        page.get_by_role("button", name="Clear filters", exact=True).click()
                    page.get_by_role("button", name="Start work: Fieldwork Co. onboarding", exact=True).click()
                    dialog.get_by_label("Progress note", exact=True).fill("Preparing the client welcome session.")
                    dialog.get_by_role("button", name="Start work", exact=True).click()
                    expect(dialog).not_to_be_visible()
                    for lane in ("scheduled", "in_progress", "completed"):
                        expect(page.locator(f'[data-lane="{lane}"] .radt-board-card')).to_have_count(1)
                    capture("08-delivery-board-desktop")
                    checks.append("three real deliveries render in their saved status lanes after protected UI transitions")

                    writes = []
                    def track_writes(request):
                        if request.method not in ("GET", "HEAD", "OPTIONS"):
                            writes.append(request.method)
                    page.on("request", track_writes)
                    search = page.get_by_role("searchbox", name="Search work", exact=True)
                    search.fill("FORM alex")
                    expect(page.locator(".radt-board-card")).to_have_count(1)
                    expect(search).to_be_focused()
                    expect(page.locator("#work-result-count")).to_have_text("1 of 3 work items · Workspace delivery")
                    page.get_by_label("Assigned to", exact=True).select_option("blair")
                    expect(page.get_by_text("No matching work", exact=True)).to_be_visible()
                    page.get_by_role("button", name="Clear filters", exact=True).click()
                    expect(search).to_have_value("")
                    expect(page.get_by_role("button", name="Clear filters", exact=True)).to_be_focused()
                    page.get_by_label("Assigned to", exact=True).select_option("blair")
                    expect(page.locator(".radt-board-card")).to_have_count(1)
                    page.locator('[data-work-filter="completed"]').click()
                    expect(page.get_by_text("No matching work", exact=True)).to_be_visible()
                    page.get_by_role("button", name="Clear filters", exact=True).click()
                    page.get_by_role("button", name="Cards", exact=True).focus()
                    page.keyboard.press("Enter")
                    expect(page.locator(".work-card")).to_have_count(3)
                    expect(page.get_by_role("button", name="Cards", exact=True)).to_be_focused()
                    page.get_by_role("button", name="Board", exact=True).click()
                    assert not writes, "Search, filters and layout must not send writes"
                    page.remove_listener("request", track_writes)
                    checks.append("combined word, owner and stage filters preserve focus, count matches and send no writes")
                    for width in (390, 320):
                        page.set_viewport_size({"width": width, "height": 844})
                        capture(f"09-delivery-board-{width}")
                    page.set_viewport_size({"width": 1440, "height": 1000})
                    page.get_by_role("button", name="Overview", exact=True).click()
                    page.get_by_role("switch", name="Pause workspace changes", exact=True).click()
                    dialog.get_by_role("button", name="Pause changes", exact=True).click()
                    expect(dialog).not_to_be_visible()
                    expect(page.get_by_role("switch", name="Pause workspace changes", exact=True)).to_have_attribute("aria-checked", "true")
                    page.get_by_role("button", name="Work", exact=True).click()
                    expect(page.get_by_role("button", name="Start work: Form & Function onboarding", exact=True)).to_be_disabled()
                    expect(page.get_by_role("button", name="Complete & hand over: Fieldwork Co. onboarding", exact=True)).to_be_disabled()
                    page.get_by_role("button", name="View details: Form & Function onboarding", exact=True).click()
                    expect(page.locator('.work-card').filter(has=page.get_by_role("heading", name="Form & Function onboarding", exact=True))).to_be_focused()
                    page.get_by_role("button", name="Overview", exact=True).click()
                    page.get_by_role("switch", name="Pause workspace changes", exact=True).click()
                    dialog.get_by_role("button", name="Resume changes", exact=True).click()
                    expect(dialog).not_to_be_visible()
                    expect(page.get_by_role("switch", name="Pause workspace changes", exact=True)).to_have_attribute("aria-checked", "false")
                    checks.append("board reflows at 390 and 320 pixels and paused writes keep read-only details available")
                    page.get_by_role("button", name="Work", exact=True).click()
                    page.get_by_role("searchbox", name="Search work", exact=True).fill("Northline")
                    page.get_by_role("button", name="Sign out", exact=True).click()
                    expect(page.get_by_label("Username", exact=True)).to_be_visible()
                    login("blair")
                    page.get_by_role("button", name="Work", exact=True).click()
                    expect(page.get_by_role("searchbox", name="Search work", exact=True)).to_have_value("")
                    expect(page.locator(".radt-board-card")).to_have_count(1)
                    expect(page.locator("#work-result-count")).to_have_text("1 of 1 work items · Your assigned work")
                    expect(page.locator("#work-owner option")).to_have_count(2)
                    expect(page.locator("#work-results")).not_to_contain_text("Northline")
                    expect(page.locator(".radt-board-eyebrow")).to_have_text("Your assignment")
                    checks.append("switching accounts resets filters; employee board and people filter use only assigned work")

                    page.get_by_role("button", name="Sign out", exact=True).click()
                    expect(page.get_by_label("Username", exact=True)).to_be_visible()
                    login("admin")
                    page.get_by_role("button", name="Work", exact=True).click()
                    page.get_by_label("Assigned to", exact=True).select_option("blair")
                    page.get_by_role("button", name="Cards", exact=True).click()
                    page.get_by_role("button", name="Edit schedule", exact=True).click()
                    dialog.get_by_label("Blair Chen", exact=True).uncheck()
                    dialog.get_by_label("Alex Morgan", exact=True).check()
                    dialog.get_by_role("button", name="Save event", exact=True).click()
                    expect(dialog).not_to_be_visible()
                    # Schedule edits return to the schedule; the next Work load
                    # must reconcile an assignee filter that no longer exists.
                    page.get_by_role("button", name="Work", exact=True).click()
                    expect(page.get_by_label("Assigned to", exact=True)).to_have_value("")
                    expect(page.locator(".work-card")).to_have_count(3)
                    expect(page.locator("#work-result-count")).to_have_text("3 of 3 work items · Workspace delivery")
                    checks.append("reassignment clears an unavailable person filter on the next load instead of silently hiding work")

                    page.goto(origin + "/component-studio/")
                    expect(page.locator("#brand")).to_have_text("Fieldwork / Component studio")
                    scheduled = page.locator('[data-action="show-scheduled"].radt-metric')
                    scheduled.focus()
                    page.keyboard.press("Enter")
                    expect(page.locator("#records .radt-board-card")).to_have_count(2)
                    expect(scheduled).to_be_focused()
                    page.get_by_role("button", name="Completed", exact=True).click()
                    expect(page.locator("#records .radt-board-card")).to_have_count(1)
                    page.locator("#preset").select_option("studio")
                    expect(page.locator("#brand")).to_have_text("Northline Studio / Component studio")
                    expect(page.locator("#records .radt-board-card")).to_have_count(4)
                    page.get_by_role("searchbox", name="Search work", exact=True).fill("atlas jules")
                    expect(page.locator("#records .radt-board-card")).to_have_count(1)
                    expect(page.get_by_role("searchbox", name="Search work", exact=True)).to_be_focused()
                    page.get_by_role("searchbox", name="Search work", exact=True).fill("")
                    capture("06-second-consumer")
                    page.locator("#preset").select_option("field")
                    page.set_viewport_size({"width": 320, "height": 844})
                    capture("07-studio-mobile")
                    assert page.evaluate("""() => {
                        const ui=window.RADTWeb, target=document.createElement('div');
                        const payload='<img src=x onerror=alert(1)>';
                        target.innerHTML=ui.metric({label:payload,value:payload,note:payload})+
                            ui.action({title:payload,description:payload,action:'safe',count:payload})+
                            ui.steps([payload],0)+ui.empty({title:payload,description:payload})+
                            ui.board({label:payload,lanes:[{id:'open',label:payload,description:payload}],items:[{id:payload,lane:'open',title:payload,eyebrow:payload,description:payload,meta:payload,people:[{id:'person',name:payload}],actions:[{action:'safe',label:payload}]}]});
                        if(target.querySelector('img') || !target.textContent.includes(payload))return false;
                        try { ui.action({action:'unsafe" onclick="alert(1)'}); return false; } catch {}
                        try { ui.board({lanes:[{id:'open'}],items:[{id:'one',lane:'missing'}]}); return false; } catch {}
                        try { ui.board({lanes:[{id:'open'},{id:'open'}],items:[]}); return false; } catch {}
                        try { ui.board({lanes:[{id:'open'}],items:[{id:'one',lane:'open'},{id:'one',lane:'open'}]}); return false; } catch {}
                        try { ui.board({lanes:[{id:'open'}],items:[{id:'one',lane:'open',actions:[{action:'bad" onclick="alert(1)'}]}]}); return false; } catch {}
                        const items=[{id:'one',title:'Riverside service',lane:'open',people:[{id:'alex',name:'Alex Morgan'}]},{id:'two',title:'Riverside service',lane:'done',people:[{id:'blair',name:'Blair Chen'}]}];
                        const before=JSON.stringify(items);
                        if(ui.filterItems(items,{query:' ALEX riverside ',lane:'open',owner:'alex'}).map(item=>item.id).join()!=='one')return false;
                        if(ui.filterItems(items,{query:'Riverside',lane:'done',owner:'alex'}).length || JSON.stringify(items)!==before)return false;
                        return true;
                    }""")
                    assert not errors, "JavaScript errors were observed"
                    checks.append("generated studio reuses toolkit assets with two brands, keyboard filters, retained focus and mobile layout")
                    checks.append("all five toolkit components escape markup; board rejects ambiguous records and unsafe actions; combined filtering preserves its input")
                    page.evaluate("""() => {
                        const title='Unbroken'.repeat(18)+' <img src=x onerror=alert(1)>';
                        document.querySelector('#records').innerHTML=RADTWeb.board({
                            lanes:[{id:'open',label:'Long text fixture'}],
                            items:[{id:'long',lane:'open',title,people:[{id:'one',name:title}],actions:[{action:'inspect',label:title}]}]
                        });
                    }""")
                    expect(page.locator("#records img")).to_have_count(0)
                    capture("10-component-long-text-320")
                    checks.append("long unbroken titles, people and action labels wrap at 320 pixels without interpreting markup")
                    exercise_branding(page, expect, checks, capture, origin, root, output)
                    assert not errors, "JavaScript errors were observed"
                except Exception:
                    capture("failure")
                    raise
                finally:
                    context.close()
                    browser.close()
    except Exception as error:
        failure = error
        (output / "failure-frames.json").write_text(json.dumps([{"file": Path(frame.filename).name, "line": frame.lineno, "function": frame.name} for frame in traceback.extract_tb(error.__traceback__)], indent=2))
        print(f"Delivery browser proof failed ({type(error).__name__}); inspect retained screenshots.", file=sys.stderr)
    receipt = finish_browser_receipt(receipt, len(checks), completed=failure is None,
                                     error=failure, browser=runtime or None)
    write_receipt(output / "receipt.json", receipt)
    (output / "summary.json").write_text(json.dumps({"passed": receipt["status"] == "passed", "checks": checks,
                                                       "error_type": type(failure).__name__ if failure else None}, indent=2) + "\n")
    print(f"Delivery browser checks: {len(checks)}; status: {receipt['status']}; evidence: {output}")
    return 0 if receipt["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
