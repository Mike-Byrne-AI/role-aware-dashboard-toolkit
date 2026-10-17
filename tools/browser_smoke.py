"""Exercise the demo, starter and record workflow screen with temporary data.

Install the workbench extra and Playwright, then install Chromium with
``python -m playwright install chromium``. The starter is checked at desktop and
phone sizes, including keyboard use. These local role pickers do not authenticate
identities or test an identity provider. Use --installed-package after installing
the wheel to exercise its resources instead of this checkout's package.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import traceback
from urllib.error import URLError
from urllib.request import urlopen


ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "examples" / "dashboard_admin_controls_app.py"
WORKFLOWS = ROOT / "examples" / "record_workflows"


def wait_for_server(process: subprocess.Popen, url: str) -> None:
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"Streamlit exited with code {process.returncode}; see server.log")
        try:
            with urlopen(f"{url}/_stcore/health", timeout=1) as response:
                if response.status == 200:
                    return
        except (URLError, TimeoutError):
            pass  # Connection refusal is expected while the owned server starts.
        time.sleep(0.2)
    raise TimeoutError("Streamlit did not become healthy within 60 seconds")


def stop_server(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return
    if os.name == "nt":
        # A Windows venv's Python launcher can own a child interpreter. Target
        # only this Popen PID and its descendants, never a process name or port.
        subprocess.run(
            ["taskkill", "/PID", str(process.pid), "/T", "/F"],
            check=True, capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW,
        )
    else:
        os.killpg(process.pid, signal.SIGTERM)
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        if os.name == "nt":
            process.kill()
        else:
            os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=10)


def exercise_browser(
    url: str, output: Path, channel: str | None, checks: list[str],
    executable: str | None = None,
) -> None:
    from playwright.sync_api import expect, sync_playwright

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(
            headless=True, channel=channel, executable_path=executable,
        )
        context = browser.new_context(viewport={"width": 1440, "height": 1100})
        context.set_default_timeout(20_000)
        context.tracing.start(screenshots=True, snapshots=True, sources=True)
        page = context.new_page()
        page_errors: list[str] = []
        page.on("pageerror", lambda error: page_errors.append(str(error)))
        expect.set_options(timeout=20_000)

        def healthy() -> None:
            expect(page.get_by_test_id("stException")).to_have_count(0)
            expect(page.get_by_test_id("stAlertContentError")).to_have_count(0)
            if page_errors:
                raise AssertionError(f"Uncaught browser errors: {page_errors}")

        def passed(name: str) -> None:
            healthy()
            checks.append(name)
            print(f"PASS: {name}", flush=True)

        def select(label: str, value: str) -> None:
            page.get_by_role("combobox", name=label, exact=True).click()
            page.get_by_role("option", name=value, exact=True).click()

        def toggle(label: str) -> None:
            # Streamlit visually hides the native input inside its clickable
            # label. Click the actual label rather than forcing a hidden input.
            page.locator("label").filter(
                has=page.get_by_role("switch", name=label, exact=True),
            ).click()

        def controls_disabled(disabled: bool) -> None:
            controls = [
                page.get_by_role("slider", name=re.compile(r"^Request Timeout(?: Request Timeout)?$")),
                page.get_by_role("spinbutton", name="Worker Limit", exact=True),
                page.get_by_role("combobox", name="Deployment Track", exact=True),
                page.get_by_role("switch", name="Maintenance Mode", exact=True),
            ]
            for control in controls:
                if disabled:
                    expect(control).to_be_disabled()
                else:
                    expect(control).to_be_enabled()

        try:
            page.goto(url, wait_until="domcontentloaded")
            expect(page.get_by_role("heading", level=1)).to_contain_text("Dashboard Admin Controls")
            # A new demo session starts in its least-privileged role.
            expect(page.get_by_text("Role=Viewer; writable=True", exact=True)).to_be_visible()
            controls_disabled(True)
            select("Role", "Admin")
            expect(page.get_by_text("Role=Admin; writable=True", exact=True)).to_be_visible()
            controls_disabled(False)
            passed("dashboard startup")

            snapshot = page.get_by_test_id("stExpander").filter(
                has=page.locator("summary", has_text="State snapshot"),
            )
            snapshot.locator("summary").click()
            expect(snapshot.get_by_test_id("stJson")).to_be_visible()
            expect(snapshot).to_contain_text(re.compile(r'worker_limit["\s:]+8'))
            passed("state panel navigation")

            profile = "browser-smoke-baseline"
            page.get_by_role("textbox", name="Profile name", exact=True).fill(profile)
            page.get_by_role("textbox", name="Profile name", exact=True).press("Enter")
            page.get_by_role("button", name="Save", exact=True).click()
            select("Load profile", profile)
            expect(page.get_by_role("button", name="Load", exact=True)).to_be_enabled()
            passed("profile save and selection")

            worker = page.get_by_role("spinbutton", name="Worker Limit", exact=True)
            worker.fill("16")
            worker.press("Enter")
            expect(snapshot).to_contain_text(re.compile(r'worker_limit["\s:]+16'))
            select("Deployment Track", "Canary")
            expect(snapshot).to_contain_text(re.compile(r'deployment_track["\s:]+Canary'))
            toggle("Maintenance Mode")
            expect(snapshot).to_contain_text(re.compile(r'maintenance_mode["\s:]+true'))
            passed("editable control changes")

            page.get_by_role("button", name="Load", exact=True).click()
            expect(worker).to_have_value("8")
            expect(snapshot).to_contain_text(re.compile(r'worker_limit["\s:]+8'))
            expect(snapshot).to_contain_text(re.compile(r'deployment_track["\s:]+Stable'))
            expect(page.get_by_role("switch", name="Maintenance Mode", exact=True)).not_to_be_checked()
            passed("saved profile restoration")

            select("Role", "Viewer")
            expect(page.get_by_text("Role=Viewer; writable=True", exact=True)).to_be_visible()
            controls_disabled(True)
            expect(page.get_by_role("button", name="Save", exact=True)).to_be_disabled()
            expect(worker).to_have_value("8")
            passed("Viewer controls and profile save disabled")

            select("Role", "Admin")
            expect(page.get_by_text("Role=Admin; writable=True", exact=True)).to_be_visible()
            controls_disabled(False)
            toggle("Controls Writable")
            expect(page.get_by_text("Role=Admin; writable=False", exact=True)).to_be_visible()
            controls_disabled(True)
            expect(page.get_by_role("button", name="Load", exact=True)).to_be_disabled()
            expect(worker).to_have_value("8")
            passed("frozen Admin controls and profile load disabled")

            toggle("Controls Writable")
            expect(page.get_by_text("Role=Admin; writable=True", exact=True)).to_be_visible()
            controls_disabled(False)
            expect(page.get_by_role("button", name="Load", exact=True)).to_be_enabled()
            audit = page.get_by_test_id("stExpander").filter(
                has=page.locator("summary", has_text="Audit Log"),
            )
            audit.locator("summary").click()
            expect(audit.get_by_role("heading", name="Timeline", exact=True)).to_be_visible()
            passed("unfreeze and audit panel navigation")
            page.screenshot(path=str(output / "dashboard.png"), full_page=True)
        except BaseException:
            try:
                page.screenshot(path=str(output / "failure.png"), full_page=True)
            except Exception as error:
                print(f"Could not capture failure screenshot: {error}", file=sys.stderr)
            raise
        finally:
            try:
                context.tracing.stop(path=str(output / "trace.zip"))
            finally:
                browser.close()


def exercise_starter(
    url: str, output: Path, channel: str | None, checks: list[str],
    executable: str | None = None,
) -> None:
    """Use the generated app as a person would, in independent browser sessions."""
    from playwright.sync_api import expect, sync_playwright

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(
            headless=True, channel=channel, executable_path=executable,
        )
        expect.set_options(timeout=20_000)
        try:
            for name, viewport in (
                ("desktop", {"width": 1440, "height": 1100}),
                ("mobile", {"width": 390, "height": 844}),
            ):
                context = browser.new_context(viewport=viewport, has_touch=name == "mobile")
                context.set_default_timeout(20_000)
                context.tracing.start(screenshots=True, snapshots=True, sources=True)
                page = context.new_page()
                page_errors: list[str] = []
                page.on("pageerror", lambda error: page_errors.append(str(error)))

                def passed(description: str) -> None:
                    expect(page.get_by_test_id("stException")).to_have_count(0)
                    expect(page.get_by_test_id("stAlertContentError")).to_have_count(0)
                    if page_errors:
                        raise AssertionError(f"Uncaught browser errors: {page_errors}")
                    check = f"starter {name}: {description}"
                    checks.append(check)
                    print(f"PASS: {check}", flush=True)

                def sidebar(opened: bool) -> None:
                    if name != "mobile":
                        return
                    toggle = page.get_by_test_id(
                        "stExpandSidebarButton" if opened else "stSidebarCollapseButton",
                    )
                    toggle.click()

                def select_role(role: str) -> None:
                    control = page.get_by_role("combobox", name="Role", exact=True)
                    control.scroll_into_view_if_needed()
                    if name == "mobile":
                        # The searchable text input can only receive focus on
                        # its first tap. Exercise the visible dropdown button
                        # to verify ordinary touch use as well as keyboard use.
                        page.get_by_test_id("stSelectbox").filter(has=control).get_by_role(
                            "button", name="Open", exact=True,
                        ).tap()
                    else:
                        control.press("ArrowDown")
                    page.get_by_role("option", name=role, exact=True).click()

                def choose_view(view: str) -> None:
                    page.locator("label").filter(
                        has=page.get_by_role("radio", name=view, exact=True),
                    ).click()
                    if view == "Plan":
                        expect(page.get_by_role("spinbutton", name="Weekly target", exact=True)).to_be_visible()
                    elif view == "Activity":
                        expect(page.locator("summary", has_text="Audit Log")).to_be_visible()
                    else:
                        expect(page.get_by_role(
                            "heading", name="Project overview" if view == "Overview" else "Project progress",
                            exact=True,
                        )).to_be_visible()
                    # A new view can appear before Streamlit's rerun finishes.
                    # Wait before opening a select menu, which a rerun closes.
                    expect(page.get_by_test_id("stApp")).to_have_attribute(
                        "data-test-script-state", "notRunning",
                    )

                def toggle(label: str) -> None:
                    page.locator("label").filter(
                        has=page.get_by_role("switch", name=label, exact=True),
                    ).click()

                def no_horizontal_overflow() -> None:
                    widths = page.evaluate("""() => {
                        const root = document.documentElement;
                        const main = document.querySelector('[data-testid="stMain"]');
                        return [root, main].filter(Boolean).map(node => ({
                            width: node.clientWidth, content: node.scrollWidth
                        }));
                    }""")
                    assert all(item["content"] <= item["width"] + 1 for item in widths), widths

                try:
                    page.goto(url, wait_until="domcontentloaded")
                    expect(page.get_by_role("heading", level=1)).to_contain_text("Project Pulse")
                    expect(page.get_by_test_id("stMetric").filter(
                        has=page.get_by_text("Planned tasks", exact=True),
                    ).get_by_test_id("stMetricValue")).to_have_text("40")
                    no_horizontal_overflow()
                    page.screenshot(path=str(output / f"starter-{name}-overview.png"), full_page=True)
                    passed("overview starts with usable summary and fits viewport")

                    sidebar(True)
                    expect(page.get_by_text("Read-only access", exact=True)).to_be_visible()
                    choose_view("Plan")
                    sidebar(False)
                    target = page.get_by_role("spinbutton", name="Weekly target", exact=True)
                    intake = page.get_by_role("switch", name="Intake open", exact=True)
                    expect(target).to_be_disabled()
                    expect(intake).to_be_disabled()
                    passed("Viewer plan cannot be edited")

                    sidebar(True)
                    select_role("Admin")
                    expect(page.get_by_text("Administrative access", exact=True)).to_be_visible()
                    sidebar(False)
                    expect(target).to_be_enabled()
                    target.scroll_into_view_if_needed()
                    expect(target).to_be_in_viewport()
                    box = target.bounding_box()
                    assert box and box["x"] >= 0 and box["x"] + box["width"] <= viewport["width"] + 1
                    target.focus()
                    target.press("ControlOrMeta+A")
                    target.press("4")
                    target.press("8")
                    target.press("Enter")
                    expect(target).to_have_value("48")
                    no_horizontal_overflow()
                    page.screenshot(path=str(output / f"starter-{name}-plan.png"), full_page=True)

                    sidebar(True)
                    choose_view("Overview")
                    sidebar(False)
                    expect(page.get_by_test_id("stMetric").filter(
                        has=page.get_by_text("Planned tasks", exact=True),
                    ).get_by_test_id("stMetricValue")).to_have_text("48")
                    passed("keyboard edit persists through view navigation")

                    sidebar(True)
                    choose_view("Plan")
                    select_role("Planner")
                    expect(page.get_by_text("Planning access", exact=True)).to_be_visible()
                    sidebar(False)
                    expect(target).to_be_enabled()
                    expect(target).to_have_value("48")
                    expect(intake).to_be_disabled()
                    passed("Planner edits the plan while intake stays restricted")

                    sidebar(True)
                    select_role("Admin")
                    expect(page.get_by_text("Administrative access", exact=True)).to_be_visible()
                    toggle("Controls Writable")
                    expect(page.get_by_text("Changes paused", exact=True)).to_be_visible()
                    sidebar(False)
                    for control in (
                        target,
                        page.get_by_role("slider", name=re.compile(r"^Completion(?: Completion)?$")),
                        page.get_by_role("combobox", name="Priority", exact=True),
                        page.get_by_role("textbox", name="Project name", exact=True),
                        intake,
                        page.get_by_role("button", name="Chart color color picker", exact=True),
                    ):
                        expect(control).to_be_disabled()
                    expect(target).to_have_value("48")
                    no_horizontal_overflow()
                    passed("freeze visibly blocks Admin changes without losing the plan")

                    sidebar(True)
                    toggle("Controls Writable")
                    expect(page.get_by_text("Changes paused", exact=True)).to_have_count(0)
                    choose_view("Progress")
                    sidebar(False)
                    expect(page.get_by_test_id("stVegaLiteChart")).to_be_visible()
                    no_horizontal_overflow()
                    passed("progress chart remains readable")

                    sidebar(True)
                    choose_view("Activity")
                    sidebar(False)
                    audit = page.get_by_test_id("stExpander").filter(
                        has=page.locator("summary", has_text="Audit Log"),
                    )
                    audit.locator("summary").click()
                    expect(audit.get_by_role("heading", name="Timeline", exact=True)).to_be_visible()
                    no_horizontal_overflow()
                    passed("activity audit can be opened")
                except BaseException:
                    try:
                        page.screenshot(path=str(output / f"starter-{name}-failure.png"), full_page=True)
                    except Exception as error:
                        print(f"Could not capture failure screenshot: {error}", file=sys.stderr)
                    raise
                finally:
                    try:
                        context.tracing.stop(path=str(output / f"starter-{name}-trace.zip"))
                    finally:
                        context.close()
        finally:
            browser.close()


def exercise_record_workflows(
    url: str, output: Path, channel: str | None, checks: list[str],
    executable: str | None = None,
) -> None:
    """Check real record edits, account changes and history at both viewports."""
    from playwright.sync_api import expect, sync_playwright

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(
            headless=True, channel=channel, executable_path=executable,
        )
        expect.set_options(timeout=20_000)
        try:
            for name, viewport in (
                ("desktop", {"width": 1440, "height": 1100}),
                ("mobile", {"width": 390, "height": 844}),
            ):
                context = browser.new_context(viewport=viewport, has_touch=name == "mobile")
                context.set_default_timeout(20_000)
                context.tracing.start(screenshots=True, snapshots=True, sources=True)
                page = context.new_page()
                page_errors: list[str] = []
                page.on("pageerror", lambda error: page_errors.append(str(error)))

                def finished() -> None:
                    expect(page.get_by_test_id("stApp")).to_have_attribute(
                        "data-test-script-state", "notRunning",
                    )

                def sidebar(opened: bool) -> None:
                    if name == "mobile":
                        page.get_by_test_id(
                            "stExpandSidebarButton" if opened else "stSidebarCollapseButton",
                        ).click()
                        # Wait for the sidebar's slide animation before reading
                        # layout or taking evidence; its old position can cover
                        # a valid page even after the toggle has changed state.
                        page.wait_for_function("""opened => {
                            const sidebar = document.querySelector('[data-testid="stSidebar"]');
                            if (!sidebar) return !opened;
                            const rect = sidebar.getBoundingClientRect();
                            return opened ? rect.left >= -1 : rect.right <= 1;
                        }""", arg=opened)

                def select(label: str, value: str) -> None:
                    finished()
                    control = page.get_by_role("combobox", name=label, exact=True)
                    control.scroll_into_view_if_needed()
                    if name == "mobile":
                        page.get_by_test_id("stSelectbox").filter(has=control).get_by_role(
                            "button", name="Open", exact=True,
                        ).tap()
                    else:
                        control.press("ArrowDown")
                    page.get_by_role("option", name=value, exact=True).click()

                def passed(description: str) -> None:
                    finished()
                    expect(page.get_by_test_id("stException")).to_have_count(0)
                    expect(page.get_by_test_id("stAlertContentError")).to_have_count(0)
                    if page_errors:
                        raise AssertionError(f"Uncaught browser errors: {page_errors}")
                    widths = page.evaluate("""() => [document.documentElement,
                        document.querySelector('[data-testid="stMain"]')]
                        .filter(Boolean).map(node => ({width: node.clientWidth, content: node.scrollWidth}))
                    """)
                    assert all(item["content"] <= item["width"] + 1 for item in widths), widths
                    check = f"record workflows {name}: {description}"
                    checks.append(check)
                    print(f"PASS: {check}", flush=True)

                schedule_reason = page.get_by_role("textbox", name="Reason for rescheduling", exact=True)
                status_reason = page.get_by_role("textbox", name="Reason for status change", exact=True)
                save = page.get_by_role("button", name="Save schedule", exact=True)
                apply = page.get_by_role("button", name="Apply status", exact=True)
                confirm = page.get_by_role("checkbox", name="I reviewed this status change", exact=True)

                def confirm_status() -> None:
                    page.locator("label").filter(has=confirm).click()

                try:
                    page.goto(url, wait_until="domcontentloaded")
                    expect(page.get_by_role("heading", level=1, name="Record workflows", exact=True)).to_be_visible()
                    expect(page.get_by_text("Changes paused. A Manager can resume changes.", exact=True)).to_be_visible()
                    expect(save).to_be_disabled()
                    expect(apply).to_be_disabled()
                    expect(schedule_reason).to_be_disabled()
                    page.screenshot(path=str(output / f"workflows-{name}-overview.png"), full_page=True)
                    passed("initial freeze prevents record changes and layout fits")

                    sidebar(True)
                    page.get_by_role("button", name="Resume changes", exact=True).click()
                    expect(page.get_by_text("Editing enabled. The server checks permission again when you save.", exact=True)).to_be_visible()
                    sidebar(False)
                    hour = page.get_by_role("spinbutton", name="hour, New time (UTC)", exact=True)
                    minute = page.get_by_role("spinbutton", name="minute, New time (UTC)", exact=True)
                    expect(hour).to_be_enabled()
                    hour.focus()
                    hour.press_sequentially("10")
                    minute.focus()
                    minute.press_sequentially("15")
                    minute.press("Tab")
                    schedule_reason.focus()
                    schedule_reason.press_sequentially("Customer requested a later start")
                    save.click()
                    expect(page.get_by_text("Schedule saved with change history.", exact=True)).to_be_visible()
                    expect(page.get_by_text("Reason: Customer requested a later start", exact=True)).to_be_visible()
                    expect(hour).to_have_attribute("aria-valuenow", "10")
                    expect(minute).to_have_attribute("aria-valuenow", "15")
                    expect(schedule_reason).to_have_value("")
                    passed("keyboard schedule change saves with visible history")

                    select("New status", "Cancelled")
                    status_reason.fill("Customer postponed the work")
                    confirm_status()
                    apply.click()
                    expect(page.get_by_test_id("stMetricValue").filter(has_text="Cancelled")).to_be_visible()
                    expect(page.get_by_text("Reason: Customer postponed the work", exact=True)).to_be_visible()
                    expect(save).to_be_disabled()
                    expect(confirm).not_to_be_checked()
                    expect(status_reason).to_have_value("")
                    passed("confirmed cancellation records its reason and blocks rescheduling")

                    status_reason.fill("Customer confirmed a new plan")
                    confirm_status()
                    apply.click()
                    expect(page.get_by_test_id("stMetricValue").filter(has_text="Scheduled")).to_be_visible()
                    expect(save).to_be_enabled()
                    expect(page.get_by_text("Reason: Customer confirmed a new plan", exact=True)).to_be_visible()
                    passed("reopening restores scheduling and preserves change history")

                    hour.focus()
                    hour.press_sequentially("16")
                    minute.focus()
                    minute.press_sequentially("30")
                    minute.press("Tab")
                    schedule_reason.fill("Unsubmitted manager draft")
                    status_reason.fill("Unsubmitted status draft")
                    confirm_status()
                    sidebar(True)
                    select("Demo account", "Viewer")
                    expect(page.get_by_text("Read-only account. Select a work item to view its current state.", exact=True)).to_be_visible()
                    sidebar(False)
                    expect(save).to_be_disabled()
                    expect(apply).to_be_disabled()
                    expect(schedule_reason).to_have_value("")
                    expect(status_reason).to_have_value("")
                    expect(confirm).not_to_be_checked()
                    expect(page.get_by_role("heading", name="Change history", exact=True)).to_have_count(0)
                    expect(hour).to_have_attribute("aria-valuenow", "10")
                    expect(minute).to_have_attribute("aria-valuenow", "15")
                    page.get_by_role("heading", level=1, name="Record workflows", exact=True).scroll_into_view_if_needed()
                    page.screenshot(path=str(output / f"workflows-{name}-viewer.png"), full_page=True)
                    passed("Viewer cannot edit and account switch clears the prior draft")

                    sidebar(True)
                    select("Demo account", "Manager")
                    expect(page.get_by_role("button", name="Pause changes", exact=True)).to_be_visible()
                    expect(schedule_reason).to_have_value("")
                    page.get_by_role("button", name="Pause changes", exact=True).click()
                    expect(page.get_by_text("Changes paused. A Manager can resume changes.", exact=True)).to_be_visible()
                    sidebar(False)
                    expect(save).to_be_disabled()
                    expect(apply).to_be_disabled()
                    expect(hour).to_have_attribute("aria-valuenow", "10")
                    expect(minute).to_have_attribute("aria-valuenow", "15")
                    expect(page.get_by_text("Reason: Customer requested a later start", exact=True)).to_be_visible()
                    page.get_by_role("heading", name="Change history", exact=True).scroll_into_view_if_needed()
                    page.screenshot(path=str(output / f"workflows-{name}-history.png"), full_page=True)
                    passed("pause blocks further changes while saved state and history remain")
                except BaseException:
                    try:
                        page.screenshot(path=str(output / f"workflows-{name}-failure.png"), full_page=True)
                    except Exception as error:
                        print(f"Could not capture failure screenshot: {error}", file=sys.stderr)
                    raise
                finally:
                    try:
                        context.tracing.stop(path=str(output / f"workflows-{name}-trace.zip"))
                    finally:
                        context.close()
        finally:
            browser.close()


@contextmanager
def running_app(app: Path, runtime: Path, env: dict, log_path: Path):
    """Own and stop one Streamlit process, including on browser failure."""
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    url = f"http://127.0.0.1:{port}"
    with log_path.open("w", encoding="utf-8") as log:
        process = subprocess.Popen(
            [sys.executable, "-m", "streamlit", "run", str(app),
             "--server.address=127.0.0.1", f"--server.port={port}",
             "--server.headless=true", "--server.fileWatcherType=none",
             "--browser.gatherUsageStats=false"],
            cwd=runtime, env=env, stdout=log, stderr=subprocess.STDOUT,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
            start_new_session=os.name != "nt",
        )
        try:
            wait_for_server(process, url)
            yield url
        finally:
            stop_server(process)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True, help="Evidence directory outside the checkout")
    browser = parser.add_mutually_exclusive_group()
    browser.add_argument("--browser-channel", help="Optional installed Chromium channel, e.g. chrome")
    browser.add_argument("--browser-executable", type=Path, help="Optional Chromium executable path")
    parser.add_argument(
        "--installed-package", action="store_true",
        help="Use the interpreter's installed toolkit, without adding this checkout to PYTHONPATH",
    )
    args = parser.parse_args()
    output = args.output_dir.resolve()
    if output == ROOT or ROOT in output.parents:
        parser.error("--output-dir must be outside the checkout")
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        parser.error("--output-dir must be an empty directory to preserve earlier evidence")
    output.mkdir(parents=True, exist_ok=True)
    summary: dict = {
        "started_at": datetime.now(timezone.utc).isoformat(),
        "app": APP.relative_to(ROOT).as_posix(), "passed": False, "checks": [],
        "scope": "Demo, generated starter and record workflow UI; no identity-provider or deployment acceptance",
        "package_source": "installed" if args.installed_package else "checkout",
        "starter_viewports": {"desktop": [1440, 1100], "mobile": [390, 844]},
        "workflow_viewports": {"desktop": [1440, 1100], "mobile": [390, 844]},
    }
    try:
        with tempfile.TemporaryDirectory(prefix="radt-browser-runtime-") as runtime:
            env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTHONPATH=str(ROOT))
            if args.installed_package:
                env.pop("PYTHONPATH", None)
            executable = str(args.browser_executable.resolve()) if args.browser_executable else None
            runtime_path = Path(runtime)
            package_path = subprocess.run(
                [sys.executable, "-c", "import role_aware_dashboard_toolkit as r; print(r.__file__)"],
                cwd=runtime, env=env, capture_output=True, text=True, check=True,
            ).stdout.strip()
            summary["package_path"] = package_path
            if args.installed_package and (ROOT / "role_aware_dashboard_toolkit") in Path(package_path).resolve().parents:
                raise RuntimeError(
                    "--installed-package resolved to this checkout; install a non-editable wheel first"
                )
            with running_app(APP, runtime_path, env, output / "server.log") as url:
                exercise_browser(url, output, args.browser_channel, summary["checks"], executable)
            starter = runtime_path / "starter"
            with (output / "starter-generation.log").open("w", encoding="utf-8") as log:
                subprocess.run(
                    [sys.executable, "-m", "role_aware_dashboard_toolkit", "init", str(starter)],
                    cwd=runtime, env=env, stdout=log, stderr=subprocess.STDOUT, check=True,
                )
            with running_app(starter / "app.py", starter, env, output / "starter-server.log") as url:
                exercise_starter(url, output, args.browser_channel, summary["checks"], executable)
            # Keep source examples importable without adding the checkout in an
            # installed-package run. The toolkit still resolves to its probed
            # wheel installation; only this copy-and-adapt example is copied.
            workflow_runtime = runtime_path / "workflows"
            workflow_sources = workflow_runtime / "examples" / "record_workflows"
            workflow_sources.mkdir(parents=True)
            for source in sorted(WORKFLOWS.glob("*.py")):
                shutil.copyfile(source, workflow_sources / source.name)
            with running_app(
                workflow_sources / "app.py", workflow_runtime, env, output / "workflow-server.log",
            ) as url:
                exercise_record_workflows(url, output, args.browser_channel, summary["checks"], executable)
        summary["passed"] = True
        return 0
    except Exception:
        summary["error"] = traceback.format_exc()
        print(summary["error"], file=sys.stderr)
        return 1
    finally:
        (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
        print(f"Browser evidence: {output}", flush=True)


if __name__ == "__main__":
    raise SystemExit(main())
