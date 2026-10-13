"""Exercise the bundled demo in a real browser, using only temporary runtime data.

Install the workbench extra and Playwright, then install Chromium with
``python -m playwright install chromium``. This checks demo UI behavior; the
demo role picker does not authenticate identities or test an identity provider.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
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


def exercise_browser(url: str, output: Path, channel: str | None, checks: list[str]) -> None:
    from playwright.sync_api import expect, sync_playwright

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True, channel=channel)
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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True, help="Evidence directory outside the checkout")
    parser.add_argument("--browser-channel", help="Optional installed Chromium channel, e.g. chrome")
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
        "scope": "Demo UI only; no identity-provider or deployment acceptance",
    }
    try:
        with tempfile.TemporaryDirectory(prefix="radt-browser-runtime-") as runtime:
            env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTHONPATH=str(ROOT))
            with socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                port = listener.getsockname()[1]
            url = f"http://127.0.0.1:{port}"
            with (output / "server.log").open("w", encoding="utf-8") as log:
                process = subprocess.Popen(
                    [sys.executable, "-m", "streamlit", "run", str(APP),
                     "--server.address=127.0.0.1", f"--server.port={port}",
                     "--server.headless=true", "--server.fileWatcherType=none",
                     "--browser.gatherUsageStats=false"],
                    cwd=runtime, env=env, stdout=log, stderr=subprocess.STDOUT,
                    creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
                    start_new_session=os.name != "nt",
                )
                try:
                    wait_for_server(process, url)
                    exercise_browser(url, output, args.browser_channel, summary["checks"])
                finally:
                    stop_server(process)
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
