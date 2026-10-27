"""Check the business example in a real browser with disposable fictional data."""

from __future__ import annotations

import argparse
from contextlib import closing
from datetime import datetime, timedelta
import json
import logging
from pathlib import Path
import socket
import sqlite3
import sys
import tempfile
import threading
import time
import traceback
from urllib.error import URLError
from urllib.parse import urlsplit
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples" / "business_dashboard"


def synthetic_admin_enrollment(data_dir):
    """Decrypt only this runner's newly generated disposable enrollment."""
    from business.db import Database

    database = Database(data_dir)
    with database.transaction() as connection:
        row = connection.execute("SELECT * FROM admin_mfa WHERE user_id='admin'").fetchone()
        assert row is not None, "Disposable administrator enrollment is missing"
        return database.mfa_secrets.decrypt(row["secret_ciphertext"], "admin", row["generation"]), row["last_counter"]


class PublicBoardObserver:
    """Watch real administrator changes from a separately signed-out browser."""

    DRAFT_TITLE = "Unsent notice retained during board updates"
    DRAFT_BODY = "This draft must remain in the form while published notices change."

    def __init__(self, browser, url, output, checks):
        from playwright.sync_api import expect

        self.url, self.output, self.checks = url, output, checks
        self.context = browser.new_context(viewport={"width": 1440, "height": 1050})
        self.context.set_default_timeout(10000)
        self.page = self.context.new_page()
        self.requests, self.errors = [], []
        self.page.on("request", lambda request: self.requests.append((request.method, urlsplit(request.url).path)))
        self.page.on("pageerror", lambda error: self.errors.append(type(error).__name__))
        self.page.clock.install(time=time.time() - 1)
        self.page.goto(url + "/board")
        expect(self.page.get_by_role("heading", name="The public board.", exact=True)).to_be_visible()
        expect(self.page.locator("#public-board-content")).to_be_visible()
        self.page.clock.pause_at(self.page.evaluate("Date.now() / 1000") + 1)
        self.request_start = len(self.requests)
        assert not any(cookie["name"] == "westbridge_session" for cookie in self.context.cookies())
        checks.append("a shared /board link opens the public board in a separate unsigned-in browser")

    def poll(self):
        """Advance one normal interval and wait for the real public response."""
        with self.page.expect_response(self.url + "/api/public/posts") as received:
            self.page.clock.run_for(10000)
        assert received.value.status == 200
        assert isinstance(received.value.json().get("posts"), list)
        assert all(
            method == "GET" and path == "/api/public/posts"
            for method, path in self.requests[self.request_start:]
            if path.startswith("/api/")
        ), "Public observation unexpectedly called a private or mutating API"
        assert not self.errors, f"Public observer browser errors: {self.errors}"

    def start_draft(self):
        from playwright.sync_api import expect

        self.page.get_by_role("button", name="Submit a post", exact=True).click()
        dialog = self.page.get_by_role("dialog")
        dialog.get_by_label("Title", exact=True).fill(self.DRAFT_TITLE)
        dialog.get_by_label("Message", exact=True).fill(self.DRAFT_BODY)
        dialog.get_by_label("I agree to the posting rules", exact=True).check()
        expect(dialog.get_by_role("button", name="Send for approval", exact=True)).to_be_enabled()
        self.page.evaluate("window.boardDraftNode = document.querySelector('dialog form')")
        self.assert_draft()

    def assert_draft(self, *, accepting=True):
        from playwright.sync_api import expect

        dialog = self.page.get_by_role("dialog")
        expect(dialog).to_be_visible()
        expect(dialog.get_by_label("Title", exact=True)).to_have_value(self.DRAFT_TITLE)
        expect(dialog.get_by_label("Message", exact=True)).to_have_value(self.DRAFT_BODY)
        expect(dialog.get_by_label("I agree to the posting rules", exact=True)).to_be_checked()
        assert self.page.evaluate("Boolean(window.boardDraftNode) && window.boardDraftNode === document.querySelector('dialog form')")
        send = dialog.get_by_role("button", name="Send for approval", exact=True)
        if accepting:
            expect(send).to_be_enabled()
        else:
            expect(send).to_be_disabled()

    def assert_post(self, title, *, visible=True):
        from playwright.sync_api import expect

        heading = self.page.locator("#public-board-content").get_by_text(title, exact=True)
        # A native modal can cover the feed, so check rendered content rather
        # than requiring the background announcement to be interactable.
        expect(heading).to_have_count(1 if visible else 0)

    def finish(self):
        from playwright.sync_api import expect

        self.assert_draft()
        self.page.keyboard.press("Escape")
        self.page.set_viewport_size({"width": 390, "height": 844})
        self.context.grant_permissions(["clipboard-read", "clipboard-write"])
        self.page.get_by_role("button", name="Share board", exact=True).click()
        dialog = self.page.get_by_role("dialog")
        link = dialog.get_by_label("Board link", exact=True)
        expect(link).to_have_value(self.url + "/board")
        expect(link).to_have_attribute("readonly", "")
        dialog.get_by_role("button", name="Copy link", exact=True).click()
        assert self.page.evaluate("navigator.clipboard.readText()") == self.url + "/board"
        assert self.page.evaluate("document.documentElement.scrollWidth <= innerWidth")
        assert dialog.evaluate("""element => {
          const box = element.getBoundingClientRect();
          return box.left >= 0 && box.right <= innerWidth && box.top >= 0 && box.bottom <= innerHeight;
        }""")
        self.page.screenshot(path=str(self.output / "18-mobile-shared-board.png"), full_page=False)
        self.page.keyboard.press("Escape")
        expect(dialog).not_to_be_visible()
        self.checks.append("public board updates preserve an unsent dialog and use only read-only public requests")
        self.checks.append("mobile public board shares a copyable direct link without a staff session")

    def close(self):
        self.context.close()


def check_public_board_recovery(browser, url, output, checks):
    """Exercise timing/failure boundaries with intercepted public reads only."""
    from playwright.sync_api import expect

    observer = PublicBoardObserver(browser, url, output, [])
    page = observer.page
    mode, calls, held = {"value": "hold"}, [], []
    public_url = url + "/api/public/posts"
    baseline = observer.context.request.get(public_url).json()

    def public_read(route):
        calls.append(route.request.method)
        if mode["value"] == "hold":
            held.append(route)
        else:
            route.continue_()

    page.route(public_url, public_read)
    try:
        content = page.locator("#public-board-content").inner_text()
        with page.expect_request(public_url):
            page.get_by_role("button", name="Refresh board", exact=True).click()
        assert len(held) == 1
        page.clock.run_for(10000)
        page.get_by_role("button", name="Refresh board", exact=True).click()
        assert len(calls) == 1, "A slow poll allowed overlapping automatic/manual requests"
        page.clock.run_for(2001)
        expect(page.locator("#board-status")).to_have_attribute("data-state", "retrying")
        assert page.locator("#public-board-content").inner_text() == content
        held.pop().abort()
        mode["value"] = "pass"
        page.clock.run_for(19000)
        assert len(calls) == 1, "A failed poll retried before its backoff interval"
        with page.expect_response(public_url) as recovered:
            page.clock.run_for(1001)
        assert recovered.value.status == 200
        expect(page.locator("#board-status")).to_have_attribute("data-state", "live")
        checks.append("a stalled public read times out without overlapping polls, retains posts, and recovers after backoff")

        observer.context.set_offline(True)
        expect(page.locator("#board-status")).to_have_attribute("data-state", "offline")
        before = len(calls)
        page.clock.run_for(60000)
        assert len(calls) == before
        observer.context.set_offline(False)
        with page.expect_response(public_url):
            page.clock.run_for(1)
        expect(page.locator("#board-status")).to_have_attribute("data-state", "live")

        # Headless tabs do not reliably change visibility when another page is
        # focused. Dispatch browser visibility events with the corresponding
        # read-only document properties emulated; never call app internals.
        page.evaluate("""() => {
          Object.defineProperty(document, "hidden", {configurable:true, value:true});
          Object.defineProperty(document, "visibilityState", {configurable:true, value:"hidden"});
          document.dispatchEvent(new Event("visibilitychange"));
        }""")
        before = len(calls)
        page.clock.run_for(60000)
        assert len(calls) == before
        page.evaluate("""() => {
          delete document.hidden; delete document.visibilityState;
          document.dispatchEvent(new Event("visibilitychange"));
        }""")
        with page.expect_response(public_url):
            page.clock.run_for(1)
        expect(page.locator("#board-status")).to_have_attribute("data-state", "live")
        checks.append("offline and simulated hidden-tab events pause public polling and resume it when available")

        mode["value"] = "hold"
        with page.expect_request(public_url):
            page.get_by_role("button", name="Refresh board", exact=True).click()
        assert len(held) == 1
        page.get_by_role("button", name="Team sign in", exact=True).click()
        expect(page.get_by_label("Username", exact=True)).to_be_visible()
        stale = {**baseline, "posts": [{
            "id": "stale-browser-response", "title": "Stale response must not return",
            "body": "This intercepted response arrived after navigation.",
            "category": "Company", "published_at": None,
        }]}
        held.pop().fulfill(status=200, content_type="application/json", body=json.dumps(stale))
        before = len(calls)
        page.clock.run_for(60000)
        assert len(calls) == before, "Polling continued after leaving the public board"
        expect(page.get_by_label("Username", exact=True)).to_be_visible()
        expect(page.get_by_text("Stale response must not return", exact=True)).to_have_count(0)
        mode["value"] = "pass"
        page.get_by_role("button", name="Continue as guest", exact=True).click()
        expect(page.locator("#public-board-content")).to_be_visible()
        observer.poll()
        page.screenshot(path=str(output / "19-public-board-recovery.png"), full_page=True)
        checks.append("late public responses cannot replace sign-in navigation and returning to the board restores polling")
        assert not observer.errors, f"Board recovery browser errors: {observer.errors}"
    except Exception:
        page.screenshot(path=str(output / "public-recovery-failure.png"), full_page=True)
        raise
    finally:
        observer.close()


def check_admin_board_is_manual(page, checks):
    """An idle admin board must not keep its authenticated session alive."""
    requests = []

    def record(request):
        if urlsplit(request.url).path.startswith("/api/"):
            requests.append(request.method)

    page.clock.pause_at(page.evaluate("Date.now() / 1000") + 1)
    page.on("request", record)
    try:
        page.clock.run_for(30000)
        assert not requests, "The administrator board performed background authenticated requests"
    finally:
        page.remove_listener("request", record)
        page.clock.resume()
    checks.append("an idle administrator board does not poll authenticated endpoints or extend its session")


def check_guest_resizing(page, output, checks):
    """Resize the same guest page across desktop, tablet and phone layouts."""
    for width in (1440, 1100, 900, 768, 600, 390, 1440):
        page.set_viewport_size({"width": width, "height": 1050})
        layout = page.evaluate("""() => {
          const main = document.querySelector('.guest-workspace .workspace-main').getBoundingClientRect();
          const cards = [...document.querySelectorAll('.post-card')];
          return {
            viewport: innerWidth, document: document.documentElement.scrollWidth,
            mainLeft: main.left, mainRight: main.right,
            readable: cards.length > 0 && cards.every(card =>
              card.getBoundingClientRect().width >= Math.min(240, innerWidth * .7)
              && card.scrollWidth <= card.clientWidth + 1),
          };
        }""")
        assert layout["document"] <= width + 1, f"Guest page overflows at {width}px"
        assert abs(layout["mainLeft"]) <= 1 and abs(layout["mainRight"] - width) <= 1, (
            f"Guest workspace is squeezed into a partial-width column at {width}px"
        )
        assert layout["readable"], f"Public notices become compressed or clipped at {width}px"
        if width == 900:
            page.screenshot(path=str(output / "14-tablet-public-board.png"), full_page=True)
    checks.append("guest page and notice cards retain usable width while resizing desktop, tablet and phone windows")


def check_dialog_resizing(page, output, checks, *, name, drafts):
    """Keep one populated dialog open through width and height changes."""
    from playwright.sync_api import expect

    dialog = page.get_by_role("dialog")
    sizes = ((1440, 1050), (1100, 850), (900, 850), (768, 850), (600, 850),
             (390, 844), (390, 400), (768, 400), (1100, 400), (1440, 1050))
    for width, height in sizes:
        page.set_viewport_size({"width": width, "height": height})
        expect(dialog).to_be_visible()
        for label, value in drafts.items():
            expect(dialog.get_by_label(label, exact=True)).to_have_value(value)
        layout = dialog.evaluate("""element => {
          const box = element.getBoundingClientRect();
          const footer = element.querySelector('.dialog-footer').getBoundingClientRect();
          const body = element.querySelector('.dialog-body');
          return {
            inside: box.left >= 0 && box.right <= innerWidth && box.top >= 0 && box.bottom <= innerHeight,
            centered: Math.abs(box.left + box.width / 2 - innerWidth / 2) <= 2,
            footerInside: footer.left >= box.left && footer.right <= box.right
              && footer.top >= box.top && footer.bottom <= box.bottom,
            bodyUsable: body.clientHeight > 0 && body.scrollWidth <= body.clientWidth + 1,
          };
        }""")
        assert all(layout.values()), f"{name} dialog clips or moves off-center at {width}x{height}: {layout}"
        expect(dialog.locator('.dialog-footer button[type="submit"]')).to_be_in_viewport(ratio=1)
        if (width, height) == (390, 400):
            page.screenshot(path=str(output / f"15-{name}-short-window.png"), full_page=False)
    checks.append(f"{name} dialog stays centered with visible actions and preserves its draft while resizing")


def check_staff_resizing(page, output, checks):
    """Cross the mobile breakpoint with both closed and open navigation."""
    from playwright.sync_api import expect

    for width in (1100, 900, 768, 701, 700, 600, 390):
        page.set_viewport_size({"width": width, "height": 1050})
        assert page.evaluate("document.documentElement.scrollWidth <= innerWidth"), f"Staff page overflows at {width}px"
        assert page.locator(".workspace-main").evaluate("""element => {
          const box = element.getBoundingClientRect();
          return box.left >= 0 && Math.abs(box.right - innerWidth) <= 1 && box.width >= innerWidth / 2;
        }"""), f"Staff content collapses or extends outside the window at {width}px"
    page.get_by_role("button", name="Open navigation", exact=True).click()
    expect(page.locator(".workspace-main")).to_have_attribute("inert", "")
    page.set_viewport_size({"width": 900, "height": 1050})
    expect(page.locator(".workspace-main")).not_to_have_attribute("inert", "")
    expect(page.locator(".mobile-scrim")).to_have_count(0)
    expect(page.locator(".nav-link.active")).to_be_focused()
    page.get_by_role("button", name="Refresh workspace", exact=True).click()
    expect(page.get_by_text("Loading your workspace…", exact=True)).to_have_count(0)
    expect(page.get_by_role("heading", name="A clear view,", exact=False)).to_be_visible()
    page.screenshot(path=str(output / "17-navigation-after-window-resize.png"), full_page=False)
    page.set_viewport_size({"width": 1440, "height": 1050})
    checks.append("staff layout and controls remain usable when an open mobile navigation is resized to desktop")


def exercise_submission_challenge(browser, url, output, checks):
    """Exercise required verification without a provider connection or secrets."""
    from playwright.sync_api import expect

    context = browser.new_context(viewport={"width": 1440, "height": 1050})
    context.set_default_timeout(10000)
    page = context.new_page()
    errors = []
    page.on("pageerror", lambda error: errors.append(type(error).__name__))
    provider_requests = []
    submission_requests = []
    provider_script = """(() => {
  const script = document.currentScript;
  const asynchronous = script.async || script.defer;
  const onload = new URL(script.src).searchParams.get("onload");
  const widgets = [];
  window.businessChallengeProbe = {
    widgets,
    emit(index, event) {
      const options = widgets[index].options;
      if (event === "success") options.callback("disposable-fixture-token-" + index);
      else options[event + "-callback"]();
    },
  };
  window.turnstile = {
    ready(callback) {
      if (asynchronous) throw new Error("Remove async/defer before using turnstile.ready()");
      callback();
    },
    render(container, options) {
      const id = "fixture-" + widgets.length;
      widgets.push({id, options, container, removed: false});
      container.dataset.fixtureWidget = id;
      container.textContent = "Disposable visitor verification";
      return id;
    },
    remove(id) {
      const widget = widgets.find(item => item.id === id);
      if (widget) { widget.removed = true; widget.container.replaceChildren(); }
    },
    reset() {},
  };
  if (onload) {
    if (typeof window[onload] !== "function") throw new Error("Missing verification onload callback");
    window[onload]();
  }
})();
"""

    def document_with_challenge_policy(route):
        response = route.fetch()
        headers = dict(response.headers)
        policy = headers["content-security-policy"]
        headers["content-security-policy"] = (
            policy.replace("script-src 'self'", "script-src 'self' https://challenges.cloudflare.com")
            .replace("connect-src 'self'", "connect-src 'self' https://challenges.cloudflare.com")
            + "; frame-src https://challenges.cloudflare.com"
        )
        route.fulfill(response=response, headers=headers)

    def public_with_required_challenge(route):
        response = route.fetch()
        payload = response.json()
        payload["submission_challenge"] = {
            "provider": "turnstile", "required": True, "site_key": "disposable-browser-fixture",
        }
        route.fulfill(response=response, json=payload)

    def provider(route):
        provider_requests.append(route)
        if len(provider_requests) > 1:
            route.fulfill(status=200, content_type="application/javascript", body=provider_script)
        # Hold the first load until the visitor has entered a draft, then fail
        # it explicitly below. Every provider request stays inside this fixture.

    context.route("https://**/*", lambda route: route.abort())
    context.route("https://challenges.cloudflare.com/turnstile/v0/api.js*", provider)
    context.route(url + "/", document_with_challenge_policy)
    context.route(url + "/api/public/posts", public_with_required_challenge)
    try:
        page.goto(url)
        page.get_by_role("button", name="Continue as guest", exact=True).click()
        with page.expect_request("https://challenges.cloudflare.com/turnstile/v0/api.js*"):
            page.get_by_role("button", name="Submit a post", exact=True).click()
        dialog = page.get_by_role("dialog")
        send = dialog.get_by_role("button", name="Send for approval", exact=True)
        agree = dialog.get_by_label("I agree to the posting rules", exact=True)
        retry = dialog.get_by_role("button", name="Retry verification", exact=True)
        title = "Draft preserved through visitor verification"
        body = "A fictional community notice retained when verification needs another attempt."
        dialog.get_by_label("Title", exact=True).fill(title)
        dialog.get_by_label("Message", exact=True).fill(body)
        agree.check()
        expect(send).to_be_disabled()
        assert len(provider_requests) == 1
        provider_requests[0].abort("failed")
        expect(retry).to_be_visible()
        expect(send).to_be_disabled()
        retry.click()
        expect(page.locator("#submission-verification-widget")).to_have_attribute("data-fixture-widget", "fixture-0")
        expect(dialog.get_by_label("Title", exact=True)).to_have_value(title)
        expect(dialog.get_by_label("Message", exact=True)).to_have_value(body)
        expect(agree).to_be_checked()
        expect(send).to_be_disabled()
        agree.uncheck()
        page.evaluate("businessChallengeProbe.emit(0, 'success')")
        expect(send).to_be_disabled()
        agree.check()
        expect(send).to_be_enabled()
        agree.uncheck()
        expect(send).to_be_disabled()
        agree.check()
        expect(send).to_be_enabled()
        assert len(provider_requests) == 2
        checks.append("required visitor verification loads asynchronously through the provider onload callback")
        checks.append("verification load failure and retry preserve draft text and require both rules and a token")

        page.evaluate("businessChallengeProbe.emit(0, 'expired')")
        expect(send).to_be_disabled()
        expect(retry).to_be_visible()
        retry.click()
        expect(page.locator("#submission-verification-widget")).to_have_attribute("data-fixture-widget", "fixture-1")
        assert page.evaluate("businessChallengeProbe.widgets[0].removed")
        expect(send).to_be_disabled()
        page.evaluate("businessChallengeProbe.emit(1, 'success')")
        expect(send).to_be_enabled()
        page.evaluate("businessChallengeProbe.emit(1, 'error')")
        expect(send).to_be_disabled()
        expect(retry).to_be_visible()
        dialog.get_by_role("button", name="Cancel", exact=True).click()
        expect(dialog).not_to_be_visible()
        page.get_by_role("button", name="Submit a post", exact=True).click()
        expect(page.locator("#submission-verification-widget")).to_have_attribute("data-fixture-widget", "fixture-2")
        assert page.evaluate("businessChallengeProbe.widgets[1].removed")
        agree.check()
        page.evaluate("businessChallengeProbe.emit(1, 'success')")
        expect(send).to_be_disabled()
        page.evaluate("businessChallengeProbe.emit(2, 'success')")
        expect(send).to_be_enabled()
        page.evaluate("businessChallengeProbe.emit(1, 'expired')")
        expect(send).to_be_enabled()
        page.evaluate("businessChallengeProbe.emit(2, 'timeout')")
        expect(send).to_be_disabled()
        assert not errors, f"Verification browser errors: {errors}"
        page.screenshot(path=str(output / "13-required-guest-verification.png"), full_page=True)
        checks.append("expired, errored and cancelled verification cannot enable submission through stale callbacks")

        context.route(url + "/api/public/submissions", lambda route: submission_requests.append(route))
        dialog.get_by_label("Title", exact=True).fill("Pending verified fixture post")
        dialog.get_by_label("Message", exact=True).fill("Keep verification callbacks from unlocking this request.")
        page.evaluate("businessChallengeProbe.emit(2, 'success')")
        with page.expect_request(url + "/api/public/submissions"):
            send.click()
        expect(dialog.locator('button[type="submit"]')).to_be_disabled()
        page.evaluate("businessChallengeProbe.emit(2, 'success')")
        for field in dialog.locator("input, textarea, button[type=submit]").all():
            expect(field).to_be_disabled()
        page.evaluate("businessChallengeProbe.emit(2, 'error')")
        expect(retry).to_be_visible()
        expect(retry).to_be_disabled()
        submission_requests.pop().fulfill(status=409, json={"detail": "Fixture submission rejected."})
        expect(dialog.locator("#dialog-error")).to_have_text("Fixture submission rejected.")
        expect(dialog.get_by_label("Title", exact=True)).to_be_enabled()
        expect(dialog.get_by_label("Title", exact=True)).to_have_value("Pending verified fixture post")
        expect(agree).to_be_enabled()
        expect(send).to_be_disabled()
        assert not errors, f"Verification browser errors: {errors}"
        checks.append("verification callbacks cannot unlock a pending guest submission and rejection preserves its draft for fresh verification")
    except Exception:
        page.screenshot(path=str(output / "challenge-failure.png"), full_page=True)
        raise
    finally:
        while submission_requests:
            submission_requests.pop().abort()
        context.unroute_all(behavior="wait")
        context.close()


def exercise_pending_saves(browser, output, checks, *, static_dir=None):
    """Hold fictional writes while exercising the actual browser form lifecycle."""
    from playwright.sync_api import expect

    static = static_dir or EXAMPLE / "business" / "static"
    # Retried creates use Web Crypto, as they do on real HTTPS/localhost hosts.
    origin = "https://business-save-fixture.test"
    context = browser.new_context(viewport={"width": 1440, "height": 1050})
    context.set_default_timeout(10000)
    # Wait until a response body has been consumed and its promise continuations
    # have run. This observes fetch only; no application functions are replaced.
    context.add_init_script("""(() => {
      const fetch = window.fetch.bind(window);
      window.saveResponsesSettled = 0;
      window.fetch = async (...args) => {
        const response = await fetch(...args);
        if (args[1]?.method === 'POST') {
          const json = response.json.bind(response);
          response.json = async () => {
            try { return await json(); }
            finally { setTimeout(() => window.saveResponsesSettled++, 0); }
          };
        }
        return response;
      };
    })();""")
    page = context.new_page()
    errors, held = [], []
    page.on("pageerror", lambda error: errors.append(type(error).__name__))
    session = {"user": {"id": "fixture-admin", "name": "Fixture Admin", "role": "admin"},
               "csrf": "fictional-fixture-token", "frozen": False, "freeze_revision": 0}
    payloads = {
        "/api/session": session,
        "/api/admin/overview": {"metrics": {}, "events": [], "revenue": [], "activity": []},
        "/api/schedule": {"events": [], "employees": [], "frozen": False, "freeze_revision": 0},
        "/api/admin/users": {"users": []},
        "/api/admin/contacts": {"contacts": [], "frozen": False, "freeze_revision": 0},
        "/api/messages": {"messages": [], "frozen": False, "freeze_revision": 0},
    }

    def intercept(route):
        path = urlsplit(route.request.url).path
        assets = {"/": ("index.html", "text/html"), "/static/app.js": ("app.js", "application/javascript"),
                  "/static/styles.css": ("styles.css", "text/css")}
        if not route.request.url.startswith(origin + "/"):
            route.abort()
            return
        if path in assets:
            name, content_type = assets[path]
            route.fulfill(status=200, content_type=content_type + "; charset=utf-8", body=(static / name).read_bytes())
        elif route.request.method == "POST" and path in ("/api/admin/contacts", "/api/messages"):
            held.append(route)
        elif path in payloads:
            route.fulfill(status=200, json=payloads[path])
        else:
            route.fulfill(status=404, json={"detail": "Unexpected fixture request"})

    context.route("**/*", intercept)

    def open_contact(title):
        page.get_by_role("button", name="New contact", exact=True).click()
        dialog = page.get_by_role("dialog")
        for label, value in (("Contact name", title), ("Company", "Fictional company"),
                             ("Email", "fixture@example.test"), ("Relationship notes", "Retain this draft.")):
            dialog.get_by_label(label, exact=True).fill(value)
        return dialog

    def hold_contact(dialog):
        with page.expect_request(lambda request: request.method == "POST"):
            dialog.get_by_role("button", name="Create contact", exact=True).click()
        assert len(held) == 1
        fields = dialog.locator("input, select, textarea, button[type=submit]")
        for field in fields.all():
            expect(field).to_be_disabled()
        expect(dialog.get_by_role("button", name="Close", exact=True)).to_be_enabled()
        expect(dialog.get_by_role("status")).to_be_visible()

    def finish_write(status=200):
        settled = page.evaluate("window.saveResponsesSettled")
        route = held.pop()
        field = "contact" if urlsplit(route.request.url).path == "/api/admin/contacts" else "message"
        route.fulfill(status=status, json={field: {"id": "fixture-saved-record"}} if status == 200
                      else {"detail": "Fixture save rejected."})
        page.wait_for_function("count => window.saveResponsesSettled > count", arg=settled)

    try:
        page.goto(origin)
        page.get_by_role("button", name="Outreach", exact=True).click()
        expect(page.get_by_role("heading", name="Make the next connection.", exact=True)).to_be_visible()
        for dismiss in ("Close", "Close dialog", "Escape"):
            dialog = open_contact("Original submitted contact")
            hold_contact(dialog)
            if dismiss == "Escape":
                page.keyboard.press("Escape")
            else:
                dialog.get_by_role("button", name=dismiss, exact=True).click()
            expect(dialog).not_to_be_visible()
            dialog = open_contact("New draft survives the old save")
            finish_write()
            expect(dialog).to_be_visible()
            expect(dialog.get_by_label("Contact name", exact=True)).to_have_value("New draft survives the old save")
            expect(dialog.get_by_role("button", name="Create contact", exact=True)).to_be_enabled()
            expect(dialog.locator("#dialog-error")).not_to_be_visible()
            dialog.get_by_role("button", name="Cancel", exact=True).click()
        checks.append("pending saves disable editable fields and Close, X and Escape preserve a newer dialog when an old save completes")

        dialog = open_contact("Rejected save retains my draft")
        hold_contact(dialog)
        finish_write(409)
        expect(dialog.locator("#dialog-error")).to_have_text("Fixture save rejected.")
        for field in dialog.locator("input, select, textarea, button[type=submit]").all():
            expect(field).to_be_enabled()
        expect(dialog.get_by_label("Contact name", exact=True)).to_have_value("Rejected save retains my draft")
        expect(dialog.get_by_role("button", name="Cancel", exact=True)).to_be_enabled()
        page.screenshot(path=str(output / "20-save-failure-retains-draft.png"), full_page=False)
        dialog.get_by_role("button", name="Cancel", exact=True).click()
        checks.append("a rejected save restores its own form controls and retains the draft for correction")

        for status in (409, 401):
            dialog = open_contact("Original request will fail")
            hold_contact(dialog)
            page.keyboard.press("Escape")
            dialog = open_contact("New draft survives a stale error")
            finish_write(status)
            expect(dialog).to_be_visible()
            expect(dialog.get_by_label("Contact name", exact=True)).to_have_value("New draft survives a stale error")
            expect(dialog.get_by_role("button", name="Create contact", exact=True)).to_be_enabled()
            expect(dialog.locator("#dialog-error")).not_to_be_visible()
            dialog.get_by_role("button", name="Cancel", exact=True).click()
        checks.append("stale conflict and authentication responses cannot replace or alter a newer dialog")

        page.get_by_role("button", name="Team board", exact=True).click()
        page.get_by_label("Your message", exact=True).fill("Fictional delayed team message.")
        with page.expect_request(lambda request: request.method == "POST"):
            page.get_by_role("button", name="Post message", exact=True).click()
        expect(page.get_by_label("Your message", exact=True)).to_be_disabled()
        page.get_by_role("button", name="Schedule", exact=True).click()
        expect(page.get_by_role("heading", name="The team schedule.", exact=True)).to_be_visible()
        finish_write()
        expect(page.get_by_role("heading", name="The team schedule.", exact=True)).to_be_visible()
        expect(page.locator("#message-form")).to_have_count(0)
        checks.append("a delayed team message cannot pull the user back after navigating to the schedule")

        for close_first in (False, True):
            page.get_by_role("button", name="Team board", exact=True).click()
            page.get_by_label("Your message", exact=True).fill("Message sent while viewing my profile.")
            with page.expect_request(lambda request: request.method == "POST"):
                page.get_by_role("button", name="Post message", exact=True).click()
            page.get_by_role("button", name="Your profile", exact=True).click()
            dialog = page.get_by_role("dialog")
            expect(dialog.get_by_role("heading", name="Your profile", exact=True)).to_be_visible()
            dialog.get_by_label("Confirm new password", exact=True).fill("Unsent fictional profile draft")
            if close_first:
                dialog.get_by_role("button", name="Cancel", exact=True).click()
            finish_write()
            if not close_first:
                expect(dialog.get_by_role("heading", name="Your profile", exact=True)).to_be_visible()
                expect(dialog.get_by_label("Confirm new password", exact=True)).to_have_value("Unsent fictional profile draft")
                dialog.get_by_role("button", name="Cancel", exact=True).click()
            expect(page.get_by_label("Your message", exact=True)).to_be_enabled()
            expect(page.get_by_label("Your message", exact=True)).to_have_value("")
            expect(page.get_by_role("button", name="Post message", exact=True)).to_be_enabled()
        checks.append("viewing or closing a profile during a pending message does not leave its still-connected form disabled")
        assert not errors, f"Pending-save browser errors: {errors}"
    except Exception:
        page.screenshot(path=str(output / "pending-save-failure.png"), full_page=True)
        raise
    finally:
        while held:
            held.pop().abort()
        context.unroute_all(behavior="wait")
        context.close()


def exercise_admin_tools(browser, output, checks):
    """Exercise administrator guidance and session races with fictional responses."""
    from playwright.sync_api import expect

    origin = "https://business-admin-fixture.test"
    static = EXAMPLE / "business" / "static"
    context = browser.new_context(viewport={"width": 1440, "height": 1050})
    context.set_default_timeout(10000)
    context.grant_permissions(["clipboard-read", "clipboard-write"], origin=origin)
    context.add_init_script("""(() => {
      const fetch = window.fetch.bind(window);
      window.sessionResponsesSettled = 0;
      window.fetch = async (...args) => {
        const response = await fetch(...args);
        if (args[0] === '/api/session') {
          const json = response.json.bind(response);
          response.json = async () => {
            try { return await json(); }
            finally { setTimeout(() => window.sessionResponsesSettled++, 0); }
          };
        }
        return response;
      };
    })();""")
    page = context.new_page()
    errors, held, unexpected, requests = [], [], [], []
    page.on("pageerror", lambda error: errors.append(type(error).__name__))
    admin = {"id": "fixture-admin", "username": "admin", "name": "Fixture Admin", "role": "admin"}
    employee = {"id": "fixture-employee", "username": "employee", "name": "Fixture Employee", "role": "employee"}
    session = {"user": admin, "csrf": "fictional-csrf", "frozen": False, "freeze_revision": 0}
    session_status, hold_session = 200, False
    untrusted = '<img src=x onerror="window.activityMarkupExecuted=true">'
    activity = [
        {"id": index, "actor": untrusted if index == 7 else f"Fictional actor {index}",
         "action": "Updated schedule" if index % 2 else "Added outreach contact",
         "target": f"Fictional item {index}", "created_at": "2026-10-23T12:00:00+00:00"}
        for index in range(50)
    ]
    payloads = {
        "/api/admin/overview": {"metrics": {}, "revenue": [], "activity": activity},
        "/api/schedule": {"events": [], "employees": [], "frozen": False, "freeze_revision": 0},
        "/api/admin/users": {"users": []},
        "/api/admin/contacts": {"contacts": [], "frozen": False, "freeze_revision": 0},
        "/api/admin/posts": {"posts": [], "frozen": False, "freeze_revision": 0},
        "/api/admin/submissions": {"submissions": []},
        "/api/public/posts": {"posts": [], "accepting_submissions": True},
    }

    def intercept(route):
        path = urlsplit(route.request.url).path
        requests.append((route.request.method, path))
        assets = {"/": ("index.html", "text/html"), "/board": ("index.html", "text/html"),
                  "/static/app.js": ("app.js", "application/javascript"),
                  "/static/styles.css": ("styles.css", "text/css")}
        if not route.request.url.startswith(origin + "/"):
            unexpected.append("external request")
            route.abort()
        elif path in assets:
            name, content_type = assets[path]
            route.fulfill(status=200, content_type=content_type + "; charset=utf-8", body=(static / name).read_bytes())
        elif path == "/api/session":
            if hold_session:
                held.append(route)
            else:
                route.fulfill(status=session_status, json=session)
        elif path == "/api/logout" and route.request.method == "POST":
            route.fulfill(status=200, json={})
        elif path == "/api/admin/freeze" and route.request.method == "POST":
            session["frozen"] = bool(route.request.post_data_json["frozen"])
            session["freeze_revision"] += 1
            payloads["/api/schedule"].update(frozen=session["frozen"], freeze_revision=session["freeze_revision"])
            route.fulfill(status=200, json={"frozen": session["frozen"], "freeze_revision": session["freeze_revision"]})
        elif path in payloads and route.request.method == "GET":
            route.fulfill(status=200, json=payloads[path])
        else:
            unexpected.append((route.request.method, path))
            route.fulfill(status=404, json={"detail": "Unexpected administrator fixture request"})

    context.route("**/*", intercept)

    def overview():
        page.goto(origin)
        expect(page.get_by_role("heading", name="A clear view,", exact=False)).to_be_visible()

    def finish_session(body, status=200):
        assert len(held) == 1
        settled = page.evaluate("window.sessionResponsesSettled")
        held.pop().fulfill(status=status, json=body)
        page.wait_for_function("count => window.sessionResponsesSettled > count", arg=settled)

    def no_admin_actions():
        for label in ("Security & recovery", "Open recovery guide", "Explore recent activity", "Plan an event", "Add a contact"):
            expect(page.get_by_role("button", name=label, exact=True)).to_have_count(0)

    try:
        overview()
        dialog = page.get_by_role("dialog")
        for label, heading in (("Plan an event", "Plan a team event"), ("Add a contact", "A new connection")):
            page.get_by_role("button", name=label, exact=True).click()
            expect(dialog).to_be_visible()
            expect(dialog.get_by_role("heading", name=heading, exact=True)).to_be_visible()
            page.keyboard.press("Escape")
            expect(dialog).not_to_be_visible()
            expect(page.get_by_role("button", name=label, exact=True)).to_be_focused()
        page.get_by_role("button", name="Review public posts", exact=True).click()
        expect(page.get_by_role("heading", name="The public board.", exact=True)).to_be_visible()
        page.get_by_role("button", name="Overview", exact=True).click()
        page.get_by_role("button", name="Open recovery guide", exact=True).click()
        expect(page.get_by_role("heading", name="Keep access in your hands.", exact=True)).to_be_visible()
        checks.append("overview quick actions open the existing event/contact dialogs, public board and recovery guide")

        expect(page.get_by_text("Recovery copies are managed on your computer. This dashboard cannot confirm whether you have one.", exact=True)).to_be_visible()
        expect(page.locator('#main input, #main textarea, #main input[type="file"]')).to_have_count(0)
        before_copy = list(requests)
        for action in ("encrypt", "verify", "restore"):
            page.get_by_role("button", name=f"Copy {action} command", exact=True).click()
            copied = page.evaluate("navigator.clipboard.readText()")
            assert "recovery.py" in copied and f" {action} " in copied, "Expected a generic recovery command"
            assert "Michael" not in copied and "fictional-csrf" not in copied, "Command contains user-specific data"
        assert requests == before_copy, "Copying local recovery commands performed a network request"
        page.get_by_label("Terminal platform", exact=True).select_option(label="macOS / Linux")
        expect(page.locator("#recovery-encrypt")).to_contain_text(".venv/bin/python")
        page.get_by_label("Terminal platform", exact=True).select_option(label="Windows PowerShell")
        expect(page.locator("#recovery-encrypt")).to_contain_text(".venv")
        page.clock.install()
        before_idle = list(requests)
        page.clock.fast_forward(30000)
        assert requests == before_idle, "An idle recovery guide performed a background request"
        page.get_by_role("button", name="Change password", exact=True).click()
        expect(dialog.get_by_role("heading", name="Your profile", exact=True)).to_be_visible()
        expect(dialog.get_by_label("Current password", exact=True)).to_be_visible()
        page.keyboard.press("Escape")
        expect(dialog).not_to_be_visible()
        expect(page.get_by_role("button", name="Change password", exact=True)).to_be_focused()
        page.get_by_role("button", name="Pause workspace changes", exact=True).click()
        dialog.get_by_role("button", name="Pause changes", exact=True).click()
        expect(dialog).not_to_be_visible()
        expect(page.get_by_role("heading", name="Keep access in your hands.", exact=True)).to_be_visible()
        expect(page.get_by_role("heading", name="Changes are paused", exact=True)).to_be_visible()
        page.get_by_role("button", name="Resume workspace changes", exact=True).click()
        dialog.get_by_role("button", name="Resume changes", exact=True).click()
        expect(dialog).not_to_be_visible()
        expect(page.get_by_role("heading", name="Keep access in your hands.", exact=True)).to_be_visible()
        expect(page.get_by_role("heading", name="Changes are enabled", exact=True)).to_be_visible()
        page.clock.fast_forward(5001)
        page.evaluate("window.scrollTo(0, 0)")
        page.screenshot(path=str(output / "22-admin-recovery-guide.png"), full_page=True)
        for width in (900, 600, 390):
            page.set_viewport_size({"width": width, "height": 844})
            assert page.evaluate("document.documentElement.scrollWidth <= innerWidth"), f"Recovery guide overflows at {width}px"
            expect(page.get_by_role("button", name="Copy restore command", exact=True)).to_be_visible()
        page.evaluate("window.scrollTo(0, 0)")
        page.screenshot(path=str(output / "23-mobile-recovery-guide.png"), full_page=True)
        page.get_by_role("button", name="Open navigation", exact=True).click()
        page.get_by_role("button", name="Overview", exact=True).click()
        expect(page.get_by_role("heading", name="A clear view,", exact=False)).to_be_focused()
        page.screenshot(path=str(output / "24-mobile-overview-actions.png"), full_page=True)
        assert page.evaluate("document.documentElement.scrollWidth <= innerWidth"), "Overview actions overflow on mobile"
        checks.append("recovery guide copies local Windows/POSIX commands without uploading data or polling and fits desktop/tablet/mobile")

        page.get_by_role("button", name="Explore recent activity", exact=True).click()
        expect(dialog.get_by_role("heading", name="Recent workspace activity", exact=True)).to_be_visible()
        search = dialog.get_by_label("Search recent activity", exact=True)
        results = dialog.locator("#activity-results .activity-item")
        search.fill("Fictional item 37")
        expect(results.filter(has_text="Fictional item 37")).to_be_visible()
        expect(results.filter(has_text="Fictional item 36")).to_have_count(0)
        expect(dialog.locator("#activity-count")).to_have_text("1 of 50 recent changes")
        search.press("Enter")
        expect(search).to_have_value("Fictional item 37")
        expect(dialog.locator("#activity-count")).to_have_text("1 of 50 recent changes")
        expect(dialog.locator("#dialog-error")).not_to_be_visible()
        search.fill("Fictional actor 41")
        expect(results.filter(has_text="Fictional item 41")).to_be_visible()
        search.fill("Updated schedule")
        expect(results.filter(has_text="Fictional item 41")).to_be_visible()
        expect(results.filter(has_text="Fictional item 42")).to_have_count(0)
        search.fill("no-matching-fictional-change")
        expect(dialog.locator("#activity-count")).to_have_text("0 of 50 recent changes")
        search.fill("<img")
        expect(dialog.get_by_text(untrusted, exact=True)).to_be_visible()
        expect(dialog.locator('img[src="x"]')).to_have_count(0)
        assert page.evaluate("window.activityMarkupExecuted !== true")
        search.fill("")
        page.screenshot(path=str(output / "25-mobile-activity-search.png"), full_page=False)
        assert page.evaluate("document.documentElement.scrollWidth <= innerWidth"), "Activity dialog overflows on mobile"
        page.keyboard.press("Escape")
        expect(dialog).not_to_be_visible()
        expect(page.get_by_role("button", name="Explore recent activity", exact=True)).to_be_focused()
        page.set_viewport_size({"width": 1440, "height": 1050})
        checks.append("recent activity searches actor/action/target in the latest 50 entries, escapes markup and restores keyboard focus")

        session["frozen"] = True
        payloads["/api/schedule"]["frozen"] = True
        overview()
        expect(page.get_by_role("button", name="Plan an event", exact=True)).to_be_disabled()
        expect(page.get_by_role("button", name="Add a contact", exact=True)).to_be_disabled()
        expect(page.get_by_role("button", name="Open recovery guide", exact=True)).to_be_enabled()
        session["frozen"] = False
        payloads["/api/schedule"]["frozen"] = False
        checks.append("overview create actions respect the paused workspace while recovery guidance remains accessible")

        for role in (employee, None):
            session["user"] = role
            page.goto(origin)
            if role:
                expect(page.get_by_role("heading", name="The team schedule.", exact=True)).to_be_visible()
            else:
                page.get_by_role("button", name="Continue as guest", exact=True).click()
                expect(page.get_by_role("heading", name="The public board.", exact=True)).to_be_visible()
            no_admin_actions()
        session["user"] = admin
        checks.append("employees and guests do not receive administrator recovery or overview actions")

        for response_user, status in ((None, 200), (None, 401), (employee, 200)):
            session_status, session["user"] = 200, admin
            overview()
            session_status, session["user"] = status, response_user
            page.get_by_role("button", name="Security & recovery", exact=True).click()
            if response_user is employee:
                expect(page.get_by_role("heading", name="The team schedule.", exact=True)).to_be_visible()
            else:
                expect(page.get_by_role("button", name="Sign in", exact=True)).to_be_visible()
            no_admin_actions()
            expect(page.get_by_role("button", name="Copy encrypt command", exact=True)).to_have_count(0)
        session_status, session["user"] = 200, admin
        checks.append("opening recovery guidance revalidates expired, rejected and downgraded sessions")

        for action in ("Security & recovery", "Refresh workspace"):
            for stale_user, status in ((None, 200), (None, 401), (employee, 200)):
                overview()
                hold_session = True
                with page.expect_request(lambda request: request.url == origin + "/api/session"):
                    page.get_by_role("button", name=action, exact=True).click()
                # The request event can precede dispatch of its route callback.
                # Wait for that callback, retaining the exact one-request check.
                deadline = time.monotonic() + 2
                while not held and time.monotonic() < deadline:
                    page.wait_for_timeout(10)
                assert len(held) == 1
                page.get_by_role("button", name="Schedule", exact=True).click()
                expect(page.get_by_role("heading", name="The team schedule.", exact=True)).to_be_visible()
                finish_session({**session, "user": stale_user}, status)
                expect(page.get_by_role("heading", name="The team schedule.", exact=True)).to_be_visible()
                expect(page.get_by_role("button", name="Security & recovery", exact=True)).to_be_visible()
                hold_session = False
            overview()
            hold_session = True
            with page.expect_request(lambda request: request.url == origin + "/api/session"):
                page.get_by_role("button", name=action, exact=True).click()
            deadline = time.monotonic() + 2
            while not held and time.monotonic() < deadline:
                page.wait_for_timeout(10)
            assert len(held) == 1
            page.get_by_role("button", name="Sign out", exact=True).click()
            expect(page.get_by_role("button", name="Sign in", exact=True)).to_be_visible()
            finish_session(session)
            expect(page.get_by_role("button", name="Sign in", exact=True)).to_be_visible()
            expect(page.get_by_role("button", name="Sign out", exact=True)).to_have_count(0)
            no_admin_actions()
            hold_session = False
        checks.append("late recovery and header-refresh session responses cannot change a newer page, downgrade its role or restore a signed-out session")
        assert not unexpected, f"Unexpected administrator fixture requests: {unexpected}"
        assert not errors, f"Administrator tools browser errors: {errors}"
    except Exception:
        page.screenshot(path=str(output / "admin-tools-failure.png"), full_page=True)
        raise
    finally:
        while held:
            held.pop().abort()
        context.unroute_all(behavior="wait")
        context.close()


def exercise_password_faults(browser, url, output, credentials, checks):
    """Drop or delay real local password requests using disposable accounts only."""
    from playwright.sync_api import expect

    observations, violations = [], []
    password = credentials["blair"]

    def record(case, **results):
        observations.append({"case": case, **results})
        violations.extend(f"{case}: {name}" for name, passed in results.items() if not passed)

    def sign_in(page, supplied):
        page.get_by_label("Username", exact=True).fill("blair")
        page.get_by_label("Password", exact=True).fill(supplied)
        page.get_by_role("button", name="Sign in", exact=True).click()
        expect(page.get_by_role("heading", name="The team schedule.", exact=True)).to_be_visible()

    for case in ("dropped-before-server", "dropped-after-commit", "gateway-error-after-commit",
                 "unreadable-response-after-commit", "unconfirmed-success-without-commit",
                 "closed-before-commit", "navigated-before-commit", "session-revoked-before-commit", "new-login-before-old-success",
                 "new-login-before-old-network-error", "old-tab-after-password-change", "incorrect-current-password"):
        context = browser.new_context(viewport={"width": 1440, "height": 1050})
        context.set_default_timeout(10000)
        context.add_init_script("""(() => {
          const fetch = window.fetch.bind(window);
          window.passwordResponsesSettled = 0;
          const settled = () => setTimeout(() => {
            window.passwordResponsesSettled++;
            document.documentElement.setAttribute('data-password-responses-settled', String(window.passwordResponsesSettled));
          }, 0);
          window.fetch = async (...args) => {
            try {
              const response = await fetch(...args);
              if (args[0] === '/api/password') {
                const json = response.json.bind(response);
                response.json = async () => {
                  try { return await json(); }
                  finally { settled(); }
                };
              }
              return response;
            } catch (error) {
              if (args[0] === '/api/password') settled();
              throw error;
            }
          };
        })();""")
        page = context.new_page()
        held, errors = [], []
        page.on("pageerror", lambda error: errors.append(type(error).__name__))
        next_password = f"Disposable browser fault password {len(observations)}!"
        old_password = password
        cookie = None
        try:
            page.goto(url)
            sign_in(page, password)
            other_tab = None
            if case == "old-tab-after-password-change":
                other_tab = context.new_page()
                other_tab.goto(url)
                expect(other_tab.get_by_role("heading", name="The team schedule.", exact=True)).to_be_visible()
            cookie = next(item for item in context.cookies() if item["name"] == "westbridge_session")
            page.route("**/api/password", lambda route: held.append(route))
            page.get_by_role("button", name="Your profile", exact=True).click()
            dialog = page.get_by_role("dialog")
            dialog.get_by_label("Current password", exact=True).fill(
                "Incorrect disposable password!" if case == "incorrect-current-password" else password)
            dialog.locator('input[name="new_password"]').fill(next_password)
            dialog.get_by_label("Confirm new password", exact=True).fill(next_password)
            with page.expect_request(lambda request: urlsplit(request.url).path == "/api/password"):
                dialog.get_by_role("button", name="Change password", exact=True).click()
            assert len(held) == 1
            expect(dialog.get_by_role("button", name="Saving…", exact=True)).to_be_disabled()
            # Repeated submit events cannot send a second in-flight credential change.
            dialog.locator("form").evaluate("form => form.dispatchEvent(new Event('submit', {bubbles:true, cancelable:true}))")
            assert len(held) == 1
            request = held.pop()
            if case == "dropped-before-server":
                request.abort("connectionfailed")
            elif case in ("dropped-after-commit", "gateway-error-after-commit", "unreadable-response-after-commit"):
                response = request.fetch()
                assert response.status == 200
                password = next_password
                if case == "dropped-after-commit":
                    request.abort("connectionclosed")
                elif case == "unreadable-response-after-commit":
                    request.fulfill(status=200, content_type="application/json", body='{"ok":')
                else:
                    request.fulfill(status=502, content_type="text/html", body="Temporary fictional gateway failure")
            elif case == "unconfirmed-success-without-commit":
                request.fulfill(status=200, json={})
            elif case in ("closed-before-commit", "navigated-before-commit"):
                page.keyboard.press("Escape")
                expect(dialog).not_to_be_visible()
                if case == "closed-before-commit":
                    page.get_by_role("button", name="Your profile", exact=True).click()
                    dialog.get_by_label("Confirm new password", exact=True).fill("Another unfinished fictional draft")
                else:
                    page.get_by_role("button", name="Team board", exact=True).click()
                    expect(page.get_by_label("Your message", exact=True)).to_be_visible()
                response = request.fetch()
                assert response.status == 200
                password = next_password
                request.fulfill(response=response)
            elif case == "session-revoked-before-commit":
                page.keyboard.press("Escape")
                page.get_by_role("button", name="Your profile", exact=True).click()
                session = context.request.get(url + "/api/session").json()
                revoked = context.request.post(url + "/api/logout", data={}, headers={
                    "Origin": url, "X-CSRF-Token": session["csrf"]})
                assert revoked.status == 200
                response = request.fetch()
                assert response.status == 401
                request.fulfill(response=response)
            elif case.startswith("new-login-before-old-"):
                response = request.fetch()
                assert response.status == 200
                password = next_password
                page.keyboard.press("Escape")
                page.get_by_role("button", name="Refresh workspace", exact=True).click()
                expect(page.get_by_role("button", name="Sign in", exact=True)).to_be_visible()
                sign_in(page, password)
                if case.endswith("success"):
                    request.fulfill(response=response)
                else:
                    request.abort("connectionclosed")
            elif case == "old-tab-after-password-change":
                response = request.fetch()
                assert response.status == 200
                password = next_password
                request.fulfill(response=response)
            else:
                response = request.fetch()
                assert response.status == 403
                request.fulfill(response=response)
            # Observe the promise continuation without string-evaluation polling;
            # the real application CSP remains enforced in every browser tab.
            expect(page.locator("html")).to_have_attribute("data-password-responses-settled", "1")
            if case in ("dropped-before-server", "dropped-after-commit", "gateway-error-after-commit",
                        "unreadable-response-after-commit", "unconfirmed-success-without-commit"):
                record(case,
                       sign_in_shown=page.get_by_role("button", name="Sign in", exact=True).is_visible(),
                       uncertainty_explained=any(text in page.locator("body").inner_text().lower()
                                                 for text in ("could not confirm", "couldn’t confirm")),
                       password_fields_cleared=page.locator('input[type="password"]').evaluate_all(
                           "fields => fields.every(field => !field.value)"))
                # Authenticate independently to prove what happened on the server,
                # without relying on the text shown in the affected browser tab.
                probe = browser.new_context()
                try:
                    accepted = probe.request.post(url + "/api/login", headers={"Origin": url},
                                                  data={"username": "blair", "password": password})
                    assert accepted.status == 200
                    rejected = probe.request.post(url + "/api/login", headers={"Origin": url},
                                                  data={"username": "blair", "password":
                                                        next_password if password == old_password else old_password})
                    assert rejected.status == 401
                    probe.clear_cookies()
                    probe.add_cookies([cookie])
                    assert probe.request.get(url + "/api/schedule").status == (
                        200 if password == old_password else 401)
                finally:
                    probe.close()
            elif case in ("closed-before-commit", "navigated-before-commit", "session-revoked-before-commit"):
                record(case,
                       revoked_session_cleared=page.get_by_role("button", name="Sign in", exact=True).is_visible(),
                       password_fields_cleared=page.locator('input[type="password"]').evaluate_all(
                           "fields => fields.every(field => !field.value)"))
            elif case.startswith("new-login-before-old-"):
                record(case,
                       new_session_ui_preserved=page.get_by_role("heading", name="The team schedule.", exact=True).is_visible(),
                       new_session_cookie_preserved=context.request.get(url + "/api/schedule").status == 200,
                       old_password_fields_cleared=page.locator('input[type="password"]').evaluate_all(
                           "fields => fields.every(field => !field.value)"))
            elif case == "old-tab-after-password-change":
                other_tab.get_by_role("button", name="Team board", exact=True).click()
                expect(other_tab.get_by_role("button", name="Sign in", exact=True)).to_be_visible()
                record(case,
                       submitted_tab_signed_out=page.get_by_role("button", name="Sign in", exact=True).is_visible(),
                       other_tab_denied_and_signed_out=context.request.get(url + "/api/messages").status == 401)
            else:
                expect(dialog.locator("#dialog-error")).to_have_text("The current password is incorrect.")
                expect(dialog.get_by_role("button", name="Change password", exact=True)).to_be_enabled()
                assert context.request.get(url + "/api/schedule").status == 200
                record(case, confirmed_rejection_remains_correctable=True)
            assert not errors, f"Password-fault browser errors: {errors}"
            page.screenshot(path=str(output / f"password-{case}.png"), full_page=True,
                            mask=[page.locator('input[type="password"]')], mask_color="#dce3df")
        except Exception:
            page.screenshot(path=str(output / f"password-{case}-failure.png"), full_page=True,
                            mask=[page.locator('input[type="password"]')], mask_color="#dce3df")
            raise
        finally:
            while held:
                held.pop().abort()
            context.close()
            (output / "password-fault-observations.json").write_text(
                json.dumps({"cases": observations, "violations": violations}, indent=2) + "\n", encoding="utf-8")
    for case in ("new-login-before-old-logout-success", "new-login-before-old-logout-rejection",
                 "new-login-before-old-logout-network-error"):
        context = browser.new_context(viewport={"width": 1440, "height": 1050})
        context.set_default_timeout(10000)
        context.add_init_script("""(() => {
          const fetch = window.fetch.bind(window);
          window.logoutResponsesSettled = 0;
          const settled = () => setTimeout(() => {
            window.logoutResponsesSettled++;
            document.documentElement.setAttribute('data-logout-responses-settled', String(window.logoutResponsesSettled));
          }, 0);
          window.fetch = async (...args) => {
            try {
              const response = await fetch(...args);
              if (args[0] === '/api/logout') {
                const json = response.json.bind(response);
                response.json = async () => {
                  try { return await json(); }
                  finally { settled(); }
                };
              }
              return response;
            } catch (error) {
              if (args[0] === '/api/logout') settled();
              throw error;
            }
          };
        })();""")
        page = context.new_page()
        held = []
        try:
            page.goto(url)
            sign_in(page, password)
            session = context.request.get(url + "/api/session").json()
            page.route("**/api/logout", lambda route: held.append(route))
            with page.expect_request(lambda request: urlsplit(request.url).path == "/api/logout"):
                page.get_by_role("button", name="Sign out", exact=True).click()
            assert len(held) == 1
            request = held.pop()
            if case.endswith("rejection"):
                revoked = context.request.post(url + "/api/logout", data={}, headers={
                    "Origin": url, "X-CSRF-Token": session["csrf"]})
                assert revoked.status == 200
                response = request.fetch()
                assert response.status == 401
            else:
                response = request.fetch()
                assert response.status == 200
            page.get_by_role("button", name="Refresh workspace", exact=True).click()
            expect(page.get_by_role("button", name="Sign in", exact=True)).to_be_visible()
            sign_in(page, password)
            if case.endswith("network-error"):
                request.abort("connectionclosed")
            else:
                request.fulfill(response=response)
            expect(page.locator("html")).to_have_attribute("data-logout-responses-settled", "1")
            record(case,
                   new_session_ui_preserved=page.get_by_role("heading", name="The team schedule.", exact=True).is_visible(),
                   new_session_cookie_preserved=context.request.get(url + "/api/schedule").status == 200)
            page.screenshot(path=str(output / f"{case}.png"), full_page=True,
                            mask=[page.locator('input[type="password"]')], mask_color="#dce3df")
        except Exception:
            page.screenshot(path=str(output / f"{case}-failure.png"), full_page=True,
                            mask=[page.locator('input[type="password"]')], mask_color="#dce3df")
            raise
        finally:
            while held:
                held.pop().abort()
            context.close()
            (output / "password-fault-observations.json").write_text(
                json.dumps({"cases": observations, "violations": violations}, indent=2) + "\n", encoding="utf-8")
    assert not violations, "; ".join(violations)
    checks.extend([
        "dropped, gateway-failed and malformed password responses explain the uncertain outcome without retaining password fields",
        "a request dropped before delivery changes nothing; a dropped response after commit changes the password and revokes old sessions",
        "duplicate password submissions stay blocked while closing or navigating cannot hide a completed sign-out",
        "old password-change successes and network failures preserve a newer login and its session cookie",
        "another open tab is denied private data and returns to sign-in after password revocation",
        "a confirmed wrong current password remains correctable without signing out",
        "delayed logout success, rejection and network failure preserve a newer login and its session cookie",
    ])


def exercise_elapsed_event_retry(browser, url, output, credentials, checks, data_dir):
    """Advance only browser time past a committed event's end, then retry it."""
    import pyotp
    from playwright.sync_api import expect

    context = browser.new_context(viewport={"width": 1440, "height": 1050})
    context.set_default_timeout(10000)
    page = context.new_page()
    page.clock.install(time=time.time())
    held, keys = [], []
    title = "Disposable elapsed event retry"

    def saved_state():
        with closing(sqlite3.connect((data_dir / "business.sqlite3").as_uri() + "?mode=ro", uri=True)) as connection:
            return (
                connection.execute("SELECT COUNT(*) FROM events WHERE title=?", (title,)).fetchone()[0],
                connection.execute("SELECT COUNT(*) FROM activity WHERE action='Scheduled work' AND target=?", (title,)).fetchone()[0],
            )

    def intercept(route):
        if route.request.method == "POST":
            keys.append(route.request.headers.get("idempotency-key"))
            held.append(route)
        else:
            route.continue_()

    try:
        page.goto(url)
        page.get_by_label("Username", exact=True).fill("admin")
        page.get_by_label("Password", exact=True).fill(credentials["admin"])
        # Only the owned fixture's generated enrollment is read. Avoid reusing
        # the admin code consumed by an earlier full-workflow login.
        secret, last_counter = synthetic_admin_enrollment(data_dir)
        remaining = (last_counter + 1) * 30 - time.time()
        if remaining > 0:
            assert remaining <= 30, "Disposable administrator clock unexpectedly moved ahead"
            time.sleep(remaining + 0.05)
        page.get_by_label("Authenticator code", exact=True).fill(pyotp.TOTP(secret).now())
        page.get_by_role("button", name="Sign in", exact=True).click()
        expect(page.get_by_role("heading", name="A clear view,", exact=False)).to_be_visible()
        page.get_by_role("button", name="Schedule", exact=True).click()
        page.route("**/api/schedule", intercept)
        times = page.evaluate("""() => {
          const local = date => `${date.getFullYear()}-${String(date.getMonth()+1).padStart(2,'0')}-${String(date.getDate()).padStart(2,'0')}T${String(date.getHours()).padStart(2,'0')}:${String(date.getMinutes()).padStart(2,'0')}`;
          return [local(new Date(Date.now()+60*60*1000)), local(new Date(Date.now()+2*60*60*1000))];
        }""")

        def fill_event():
            page.get_by_role("button", name="Add event", exact=True).click()
            dialog = page.get_by_role("dialog")
            dialog.get_by_label("Event title", exact=True).fill(title)
            dialog.get_by_label("Starts", exact=True).fill(times[0])
            dialog.get_by_label("Ends", exact=True).fill(times[1])
            dialog.get_by_label("Location", exact=True).fill("Disposable browser meeting room")
            dialog.get_by_label("Ellis Jordan", exact=True).check()
            return dialog

        dialog = fill_event()
        with page.expect_request(lambda request: request.method == "POST" and urlsplit(request.url).path == "/api/schedule"):
            dialog.get_by_role("button", name="Create event", exact=True).click()
        response = held[0].fetch()
        assert response.status == 201 and saved_state() == (1, 1)
        held.pop().abort("connectionclosed")
        expect(dialog.locator("#dialog-error")).to_contain_text("save could not be confirmed")
        page.keyboard.press("Escape")
        page.clock.set_system_time(time.time() + 3 * 60 * 60)
        dialog = fill_event()
        assert dialog.get_by_label("Ends", exact=True).evaluate("element => new Date(element.value) < new Date()")
        with page.expect_request(lambda request: request.method == "POST" and urlsplit(request.url).path == "/api/schedule"):
            dialog.get_by_role("button", name="Create event", exact=True).click()
        response = held[0].fetch()
        assert response.status == 201
        held.pop().fulfill(response=response)
        expect(dialog).not_to_be_visible()
        assert len(keys) == 2 and keys[0] and keys[0] == keys[1]
        assert saved_state() == (1, 1)
        checks.append("a committed event retries once after its end under simulated browser time, preserving one record and audit entry")
        page.screenshot(path=str(output / "safe-ended-event-retry.png"), full_page=True)
    except Exception:
        page.screenshot(path=str(output / "safe-ended-event-retry-failure.png"), full_page=True,
                        mask=[page.locator('input[type="password"], input[name="otp"]')], mask_color="#dce3df")
        raise
    finally:
        while held:
            held.pop().abort()
        context.close()


def exercise_safe_saves(browser, url, output, credentials, checks, data_dir):
    """Exercise real create receipts, posting budgets and password correction."""
    from playwright.sync_api import expect

    observations = []
    storage_key = "westbridge.create-retries.v1"

    def state(body):
        with closing(sqlite3.connect((data_dir / "business.sqlite3").as_uri() + "?mode=ro", uri=True)) as connection:
            return (
                connection.execute("SELECT COUNT(*) FROM messages WHERE body=?", (body,)).fetchone()[0],
                connection.execute("SELECT COUNT(*) FROM activity WHERE action='Posted a team message'").fetchone()[0],
            )

    def sign_in(page, username="ellis"):
        page.get_by_label("Username", exact=True).fill(username)
        page.get_by_label("Password", exact=True).fill(credentials[username])
        page.get_by_role("button", name="Sign in", exact=True).click()
        expect(page.get_by_role("heading", name="The team schedule.", exact=True)).to_be_visible()

    for case in ("lost-before-send", "lost-after-commit-refresh", "changed-content", "expired-key",
                 "storage-unavailable", "new-login-before-old-create", "identical-inflight-success",
                 "identical-inflight-lost-reply", "navigated-before-success", "posting-limit", "password-policy"):
        context = browser.new_context(viewport={"width": 1440, "height": 1050})
        context.set_default_timeout(10000)
        # Observe response continuations without weakening the application's CSP.
        context.add_init_script("""(() => {
          const fetch = window.fetch.bind(window);
          let count = 0;
          const settled = () => setTimeout(() => document.documentElement.setAttribute('data-safe-save-settled', String(++count)), 0);
          window.fetch = async (...args) => {
            const tracked = args[0] === '/api/messages' && args[1]?.method === 'POST';
            try {
              const response = await fetch(...args);
              if (tracked) {
                const json = response.json.bind(response);
                response.json = async () => { try { return await json(); } finally { settled(); } };
              }
              return response;
            } catch (error) { if (tracked) settled(); throw error; }
          };
        })();""")
        page = context.new_page()
        held, keys, errors = [], [], []
        page.on("pageerror", lambda error: errors.append(type(error).__name__))
        body = f"Disposable safe-save check: {case}"
        username = "drew" if case == "posting-limit" else "casey" if case == "password-policy" else "ellis"
        before = state(body)

        def intercept(route):
            if route.request.method == "POST":
                keys.append(route.request.headers.get("idempotency-key"))
                held.append(route)
            else:
                route.continue_()

        def submit():
            with page.expect_request(lambda request: request.method == "POST" and urlsplit(request.url).path == "/api/messages"):
                page.get_by_role("button", name="Post message", exact=True).click()
            assert len(held) == 1
            return held.pop()

        try:
            page.goto(url)
            sign_in(page, username)
            if case == "password-policy":
                requests = []
                page.on("request", lambda request: requests.append(True) if urlsplit(request.url).path == "/api/password" else None)
                page.get_by_role("button", name="Your profile", exact=True).click()
                dialog = page.get_by_role("dialog")
                expect(dialog).to_contain_text("15–128 characters")
                dialog.get_by_label("Current password", exact=True).fill(credentials[username])
                dialog.locator('input[name="new_password"]').fill("Too short 123!")
                dialog.get_by_label("Confirm new password", exact=True).fill("Too short 123!")
                dialog.get_by_role("button", name="Change password", exact=True).click()
                expect(dialog.locator("#dialog-error")).to_contain_text("at least 15 characters")
                assert not requests
                dialog.locator('input[name="new_password"]').fill("111111111111111")
                dialog.get_by_label("Confirm new password", exact=True).fill("111111111111111")
                with page.expect_response(url + "/api/password") as rejected:
                    dialog.get_by_role("button", name="Change password", exact=True).click()
                assert rejected.value.status == 422
                expect(dialog.locator("#dialog-error")).to_contain_text("less common password")
                expect(dialog.get_by_role("button", name="Change password", exact=True)).to_be_enabled()
                expect(dialog.locator('input[name="new_password"]')).to_have_value("111111111111111")
                assert context.request.get(url + "/api/schedule").status == 200
                assert page.evaluate("sessionStorage.getItem('westbridge.create-retries.v1')") is None
                checks.append("short and common new passwords remain correctable without revoking the existing session or storing password drafts")
            else:
                page.get_by_role("button", name="Team board", exact=True).click()
                expect(page.get_by_role("heading", name="The team board.", exact=True)).to_be_visible()
                page.route("**/api/messages", intercept)
                field = page.get_by_label("Your message", exact=True)
                field.fill(body)
                if case == "posting-limit":
                    session = context.request.get(url + "/api/session").json()
                    for index in range(10):
                        response = context.request.post(url + "/api/messages", data={"body": f"Disposable quota filler {index}"},
                                                        headers={"Origin": url, "X-CSRF-Token": session["csrf"]})
                        assert response.status == 201
                    request = submit()
                    response = request.fetch()
                    assert response.status == 429 and int(response.headers["retry-after"]) > 0
                    request.fulfill(response=response)
                    expect(page.locator("#message-error")).to_contain_text("Try again in")
                    expect(field).to_have_value(body)
                    expect(page.get_by_role("button", name="Post message", exact=True)).to_be_enabled()
                    assert state(body)[0] == 0
                    checks.append("real team-message rate limits retain the draft and show the server retry interval")
                elif case == "storage-unavailable":
                    page.evaluate("""() => {
                      window.restoreStorageWrite = Storage.prototype.setItem;
                      Storage.prototype.setItem = function(key, value) {
                        if (key === 'westbridge.create-retries.v1') throw new DOMException('Storage disabled', 'SecurityError');
                        return window.restoreStorageWrite.call(this, key, value);
                      };
                    }""")
                    page.get_by_role("button", name="Post message", exact=True).click()
                    expect(page.locator("#message-error")).to_contain_text("Safe saving is unavailable")
                    expect(field).to_have_value(body)
                    assert not keys and state(body) == before
                    page.evaluate("() => { Storage.prototype.setItem = window.restoreStorageWrite; }")
                    request = submit()
                    request.fulfill(response=request.fetch())
                    expect(field).to_have_value("")
                    assert state(body) == (1, before[1] + 1)
                    checks.append("unavailable browser retry storage stops a create before transmission and preserves a correctable draft")
                elif case == "new-login-before-old-create":
                    request = submit()
                    response = request.fetch()
                    assert response.status == 201
                    session = context.request.get(url + "/api/session").json()
                    assert context.request.post(url + "/api/logout", data={}, headers={"Origin": url, "X-CSRF-Token": session["csrf"]}).status == 200
                    page.get_by_role("button", name="Refresh workspace", exact=True).click()
                    expect(page.get_by_role("button", name="Sign in", exact=True)).to_be_visible()
                    sign_in(page)
                    page.get_by_role("button", name="Team board", exact=True).click()
                    field.fill(body)
                    page.get_by_role("button", name="Post message", exact=True).click()
                    expect(page.locator("#message-error")).to_be_visible()
                    expect(page.get_by_role("button", name="Post message", exact=True)).to_be_enabled()
                    assert len(keys) == 1
                    request.fulfill(response=response)
                    expect(page.locator("html")).to_have_attribute("data-safe-save-settled", "1")
                    expect(field).to_have_value(body)
                    assert context.request.get(url + "/api/messages").status == 200
                    assert len(page.evaluate("key => JSON.parse(sessionStorage.getItem(key))", storage_key)) == 1
                    request = submit()
                    request.fulfill(response=request.fetch())
                    expect(field).to_have_value("")
                    assert keys[0] == keys[1]
                    assert state(body) == (1, before[1] + 1)
                    checks.append("a pending create cannot cross sign-in sessions; its delayed reply preserves the new draft and later retries replay once")
                elif case in ("identical-inflight-success", "identical-inflight-lost-reply", "navigated-before-success"):
                    request = submit()
                    page.get_by_role("button", name="Schedule", exact=True).click()
                    expect(page.get_by_role("heading", name="The team schedule.", exact=True)).to_be_visible()
                    if case != "navigated-before-success":
                        page.get_by_role("button", name="Team board", exact=True).click()
                        field.fill(body)
                        page.get_by_role("button", name="Post message", exact=True).click()
                        expect(page.get_by_role("button", name="Saving…", exact=True)).to_be_disabled()
                    response = request.fetch()
                    assert response.status == 201
                    if case == "identical-inflight-lost-reply":
                        request.abort("connectionclosed")
                        expect(page.locator("#message-error")).to_contain_text("save could not be confirmed")
                        expect(field).to_have_value(body)
                        assert len(keys) == 1
                        request = submit()
                        request.fulfill(response=request.fetch())
                        expect(field).to_have_value("")
                        assert len(keys) == 2 and keys[0] == keys[1]
                    else:
                        request.fulfill(response=response)
                        expect(page.locator("html")).to_have_attribute("data-safe-save-settled", "1")
                        if case == "navigated-before-success":
                            expect(page.get_by_role("heading", name="The team schedule.", exact=True)).to_be_visible()
                            assert len(page.evaluate("key => JSON.parse(sessionStorage.getItem(key))", storage_key)) == 1
                            page.get_by_role("button", name="Team board", exact=True).click()
                            field.fill(body)
                            request = submit()
                            request.fulfill(response=request.fetch())
                            expect(field).to_have_value("")
                            assert len(keys) == 2 and keys[0] == keys[1]
                        else:
                            expect(field).to_have_value("")
                            assert len(keys) == 1
                    assert state(body) == (1, before[1] + 1)
                    assert page.evaluate("key => JSON.parse(sessionStorage.getItem(key))", storage_key) == []
                    checks.append({
                        "identical-inflight-success": "overlapping identical drafts share one in-flight request and commit one message and audit entry",
                        "identical-inflight-lost-reply": "overlapping identical drafts retain one retry key after a lost reply and recover without duplicate records",
                        "navigated-before-success": "an unseen successful create retains its retry key after navigation so a later identical save retrieves it once",
                    }[case])
                else:
                    request = submit()
                    if case == "lost-after-commit-refresh":
                        response = request.fetch()
                        assert response.status == 201
                        assert state(body) == (1, before[1] + 1)
                    request.abort("connectionclosed")
                    expect(page.locator("#message-error")).to_contain_text("save could not be confirmed")
                    expect(field).to_have_value(body)
                    entries = page.evaluate("key => JSON.parse(sessionStorage.getItem(key))", storage_key)
                    assert len(entries) == 1
                    assert set(entries[0]) == {"fingerprint", "key", "created"}
                    assert body not in json.dumps(entries)
                    if case == "lost-after-commit-refresh":
                        page.reload()
                        expect(page.get_by_role("heading", name="The team schedule.", exact=True)).to_be_visible()
                        page.get_by_role("button", name="Team board", exact=True).click()
                        field.fill(body)
                    elif case == "changed-content":
                        body += " with changed content"
                        field.fill(body)
                    elif case == "expired-key":
                        page.evaluate("""key => {
                          const entries = JSON.parse(sessionStorage.getItem(key));
                          entries[0].created = Date.now() - 23 * 60 * 60 * 1000;
                          sessionStorage.setItem(key, JSON.stringify(entries));
                        }""", storage_key)
                        page.get_by_role("button", name="Post message", exact=True).click()
                        expect(page.locator("#message-error")).to_contain_text("too old to retry safely")
                        assert len(keys) == 1 and state(body) == before
                        page.get_by_role("button", name="I checked the records — start a separate save", exact=True).click()
                    request = submit()
                    response = request.fetch()
                    assert response.status == 201
                    request.fulfill(response=response)
                    expect(field).to_have_value("")
                    assert state(body) == (1, before[1] + 1)
                    assert len(keys) == 2 and all(keys)
                    assert (keys[0] == keys[1]) == (case in ("lost-before-send", "lost-after-commit-refresh"))
                    remaining = page.evaluate("key => JSON.parse(sessionStorage.getItem(key))", storage_key)
                    assert len(remaining) == (1 if case == "changed-content" else 0)
                    checks.append({
                        "lost-before-send": "a create dropped before delivery retries once with the same key and records one message and one audit entry",
                        "lost-after-commit-refresh": "a lost create reply survives refresh and unchanged refill without duplicating the committed message or audit entry",
                        "changed-content": "changed create content receives a different retry key while opaque storage retains no draft text",
                        "expired-key": "an expired uncertain create is stopped before transmission until the user explicitly starts a separate save",
                    }[case])
            assert not errors, f"Safe-save browser errors: {errors}"
            observations.append({"case": case, "passed": True})
            page.screenshot(path=str(output / f"safe-{case}.png"), full_page=True,
                            mask=[page.locator('input[type="password"]')], mask_color="#dce3df")
        except Exception:
            page.screenshot(path=str(output / f"safe-{case}-failure.png"), full_page=True,
                            mask=[page.locator('input[type="password"]')], mask_color="#dce3df")
            raise
        finally:
            while held:
                held.pop().abort()
            context.close()
            (output / "safe-save-observations.json").write_text(json.dumps(observations, indent=2) + "\n", encoding="utf-8")
    exercise_elapsed_event_retry(browser, url, output, credentials, checks, data_dir)
    observations.append({"case": "ended-event-retry", "passed": True, "time_scope": "simulated browser clock only"})
    (output / "safe-save-observations.json").write_text(json.dumps(observations, indent=2) + "\n", encoding="utf-8")


def exercise_security(browser, url, output, credentials, checks, data_dir):
    """Real local session controls plus a deliberately delayed reply boundary."""
    import pyotp
    from playwright.sync_api import expect
    from business import mfa
    from business.db import Database

    database = Database(data_dir)
    contexts = []
    errors = []
    clock = {"now": time.time()}
    original_clock = mfa.current_time
    mfa.current_time = lambda: clock["now"]

    def code():
        secret, counter = synthetic_admin_enrollment(data_dir)
        clock["now"] = max(clock["now"], (counter + 1) * 30)
        return pyotp.TOTP(secret).at(clock["now"])

    def login(username):
        context = browser.new_context(viewport={"width": 1440, "height": 1050})
        contexts.append(context)
        context.set_default_timeout(10000)
        page = context.new_page()
        page.on("pageerror", lambda error: errors.append(type(error).__name__))
        page.goto(url)
        page.get_by_label("Username", exact=True).fill(username)
        page.get_by_label("Password", exact=True).fill(credentials[username])
        if username == "admin":
            page.get_by_label("Authenticator code", exact=True).fill(code())
        page.get_by_role("button", name="Sign in", exact=True).click()
        expect(page.get_by_role("button", name="Sign out", exact=True)).to_be_visible()
        return context, page

    def expire_verification():
        with database.transaction() as connection:
            connection.execute("UPDATE session_security SET verified_at=0")

    def draft(page, title):
        page.get_by_role("button", name="Public board", exact=True).click()
        page.get_by_role("button", name="New post", exact=True).click()
        editor = page.locator("#editor")
        editor.get_by_label("Title", exact=True).fill(title)
        editor.get_by_label("Announcement", exact=True).fill("A preserved fictional announcement.")
        return editor

    def count_posts(title):
        with database.transaction() as connection:
            return connection.execute("SELECT COUNT(*) FROM posts WHERE title=?", (title,)).fetchone()[0]

    try:
        context, page = login("admin")
        second_context, second_page = login("admin")
        expire_verification()
        title = "Fresh verification preserves this draft"
        editor = draft(page, title)
        with page.expect_response(url + "/api/admin/posts") as denied:
            editor.get_by_role("button", name="Save post", exact=True).click()
        assert denied.value.status == 403
        verification = page.locator("#verification-dialog")
        expect(verification).to_be_visible()
        expect(editor.get_by_label("Title", exact=True)).to_have_value(title)
        assert count_posts(title) == 0
        page.set_viewport_size({"width": 390, "height": 844})
        assert verification.evaluate("element => {const box=element.getBoundingClientRect();return box.left>=0 && box.right<=innerWidth && box.top>=0 && box.bottom<=innerHeight;}")
        page.screenshot(path=str(output / "security-verification-mobile.png"))
        page.set_viewport_size({"width": 1440, "height": 1050})
        verification.get_by_label("Current password", exact=True).fill("Incorrect disposable password")
        verification.get_by_label("Authenticator code", exact=True).fill(code())
        verification.get_by_role("button", name="Verify identity", exact=True).click()
        expect(verification.locator('[role="alert"]')).to_contain_text("incorrect")
        expect(verification.get_by_label("Current password", exact=True)).to_have_value("")
        expect(verification.get_by_label("Authenticator code", exact=True)).to_have_value("")
        verification.get_by_label("Current password", exact=True).fill(credentials["admin"])
        verification.get_by_label("Authenticator code", exact=True).fill(code())
        verification.get_by_role("button", name="Verify identity", exact=True).click()
        expect(verification).not_to_be_visible()
        expect(editor.get_by_label("Title", exact=True)).to_have_value(title)
        expect(editor.get_by_label("Announcement", exact=True)).to_have_value("A preserved fictional announcement.")
        assert count_posts(title) == 0, "Verification automatically replayed an administrator write"
        editor.get_by_role("button", name="Save post", exact=True).click()
        expect(editor).not_to_be_visible()
        assert count_posts(title) == 1
        checks.append("real stale administrator save is denied; password plus fresh TOTP preserves the draft and deliberate retry creates exactly one record")

        page.get_by_role("button", name="Security & recovery", exact=True).click()
        metric_reads = []
        page.on("request", lambda request: metric_reads.append(request.method) if urlsplit(request.url).path == "/api/admin/security-metrics" else None)
        expect(page.get_by_role("button", name="Load security activity", exact=True)).to_be_visible()
        assert metric_reads == [], "Security activity fetched without an operator request"
        page.get_by_role("button", name="Load security activity", exact=True).click()
        expect(page.locator("#metrics-status")).to_contain_text("resets when this application instance restarts")
        page.get_by_text("Fresh identity verification", exact=True).click()
        metric_rows = page.locator(".metric-group dl > div")
        expect(metric_rows.filter(has=page.get_by_text("Verification credentials rejected", exact=True)).locator("dd")).to_have_text("1")
        expect(metric_rows.filter(has=page.get_by_text("Verifications completed", exact=True)).locator("dd")).to_have_text("1")
        assert metric_reads == ["GET"]
        page.screenshot(path=str(output / "security-metrics-desktop.png"), full_page=True)
        checks.append("administrator manually loads aggregate decision counts with explicit instance-start and restart boundaries; verification failures and successes match real actions")
        page.get_by_role("button", name="Manage your sessions", exact=True).click()
        inventory = page.locator("#session-dialog")
        expect(inventory.locator(".session-card")).to_have_count(2)
        page.screenshot(path=str(output / "security-sessions-desktop.png"))
        page.set_viewport_size({"width": 390, "height": 844})
        expect(inventory.get_by_role("button", name="Sign out other session", exact=True)).to_be_visible()
        assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
        assert inventory.evaluate("element => {const box=element.getBoundingClientRect();return box.left>=0 && box.right<=innerWidth && box.top>=0 && box.bottom<=innerHeight;}")
        page.screenshot(path=str(output / "security-sessions-mobile.png"))
        inventory.get_by_role("button", name="Sign out other session", exact=True).click()
        expect(inventory.locator(".session-card")).to_have_count(1)
        assert second_context.request.get(url + "/api/messages").status == 401
        second_page.get_by_role("button", name="Team board", exact=True).click()
        expect(second_page.get_by_role("heading", name="Welcome back.", exact=True)).to_be_visible()
        checks.append("desktop and mobile session inventory revokes the selected other session and the other browser loses access")
        inventory.get_by_role("button", name="Done", exact=True).click()
        page.set_viewport_size({"width": 1440, "height": 1050})

        employee_context, employee = login("alex")
        other_context, _ = login("blair")
        employee.locator('[data-action="profile"]').click()
        employee.get_by_role("button", name="Manage your sessions", exact=True).click()
        expect(employee.locator("#session-dialog .session-card")).to_have_count(1)
        own = employee_context.request.get(url + "/api/security/sessions").json()
        foreign = other_context.request.get(url + "/api/security/sessions").json()
        assert len(own["sessions"]) == len(foreign["sessions"]) == 1
        csrf = employee_context.request.get(url + "/api/session").json()["csrf"]
        assert employee_context.request.post(url + "/api/security/sessions/" + foreign["sessions"][0]["id"] + "/revoke",
                                             data={}, headers={"Origin": url, "X-CSRF-Token": csrf}).status == 404
        employee.locator("#session-dialog").get_by_role("button", name="Sign out this session", exact=True).click()
        expect(employee.get_by_role("heading", name="Welcome back.", exact=True)).to_be_visible()
        assert employee_context.request.get(url + "/api/messages").status == 401
        assert other_context.request.get(url + "/api/messages").status == 200
        checks.append("employee profile exposes only its own sessions; a foreign opaque identifier cannot revoke another account; current-session revocation signs out")

        expire_verification()
        title = "A delayed verification must not save this"
        editor = draft(page, title)
        editor.get_by_role("button", name="Save post", exact=True).click()
        expect(verification).to_be_visible()
        held = []
        page.route("**/api/security/reauthenticate", lambda route: held.append(route))
        verification.get_by_label("Current password", exact=True).fill(credentials["admin"])
        verification.get_by_label("Authenticator code", exact=True).fill(code())
        with page.expect_request(url + "/api/security/reauthenticate"):
            verification.get_by_role("button", name="Verify identity", exact=True).click()
        expect(verification.get_by_label("Current password", exact=True)).to_have_value("")
        verification.get_by_role("button", name="Cancel verification", exact=True).click()
        expect(editor.get_by_label("Title", exact=True)).to_have_value(title)
        editor.get_by_role("button", name="Close dialog", exact=True).click()
        page.get_by_role("button", name="Sign out", exact=True).click()
        expect(page.get_by_label("Username", exact=True)).to_be_visible()
        page.get_by_label("Username", exact=True).fill("alex")
        page.get_by_label("Password", exact=True).fill(credentials["alex"])
        page.get_by_role("button", name="Sign in", exact=True).click()
        expect(page.get_by_role("button", name="Sign out", exact=True)).to_be_visible()
        assert len(held) == 1
        held.pop().fulfill(status=401, content_type="application/json", body=json.dumps({"detail": "Old session ended."}))
        page.wait_for_timeout(100)
        expect(page.get_by_role("button", name="Sign out", exact=True)).to_be_visible()
        expect(verification).not_to_be_visible()
        assert page.locator("#verification-dialog input").count() == 0
        assert context.request.get(url + "/api/session").json()["user"]["username"] == "alex"
        assert count_posts(title) == 0
        checks.append("a delayed verification denial cannot clear a newer account, revive a dismissed form, retain credentials or replay the abandoned save")
        assert not errors, "Session UI caused a browser exception"
    finally:
        mfa.current_time = original_clock
        for context in contexts:
            context.close()


def exercise_passkeys(browser, url, output, credentials, checks, data_dir):
    """Real browser WebAuthn with Chrome's virtual authenticator, never a live key."""
    import pyotp
    from playwright.sync_api import expect
    from business import mfa
    from business.db import Database

    database = Database(data_dir)
    context = browser.new_context(viewport={"width": 1440, "height": 1050})
    context.set_default_timeout(12000)
    page = context.new_page()
    errors = []
    page.on("pageerror", lambda error: errors.append(type(error).__name__))
    protocol = context.new_cdp_session(page)
    protocol.send("WebAuthn.enable")
    authenticator = protocol.send("WebAuthn.addVirtualAuthenticator", {"options": {
        "protocol": "ctap2", "transport": "internal", "hasResidentKey": True,
        "hasUserVerification": True, "isUserVerified": True, "automaticPresenceSimulation": True,
    }})["authenticatorId"]
    original_clock = mfa.current_time
    clock = {"now": time.time()}
    mfa.current_time = lambda: clock["now"]

    def password_login():
        secret, counter = synthetic_admin_enrollment(data_dir)
        clock["now"] = max(clock["now"], (counter + 1) * 30)
        page.get_by_label("Username", exact=True).fill("admin")
        page.get_by_label("Password", exact=True).fill(credentials["admin"])
        page.get_by_label("Authenticator code", exact=True).fill(pyotp.TOTP(secret).at(clock["now"]))
        page.get_by_role("button", name="Sign in", exact=True).click()
        expect(page.get_by_role("button", name="Sign out", exact=True)).to_be_visible()

    def open_passkeys():
        page.get_by_role("button", name="Security & recovery", exact=True).click()
        page.get_by_role("button", name="Manage your passkeys", exact=True).click()
        dialog = page.locator("#passkey-dialog")
        expect(dialog).to_be_visible()
        return dialog

    try:
        page.goto(url)
        password_login()
        dialog = open_passkeys()
        dialog.get_by_label("Passkey name", exact=True).fill("Disposable virtual security key")
        with page.expect_response(url + "/api/security/passkeys/register/verify") as registered:
            dialog.get_by_role("button", name="Add a passkey", exact=True).click()
        assert registered.value.status == 200
        expect(dialog.get_by_role("heading", name="Disposable virtual security key", exact=True)).to_be_visible()
        expect(dialog.get_by_label("Passkey name", exact=True)).to_have_value("")
        page.screenshot(path=str(output / "passkeys-registered-desktop.png"))
        page.set_viewport_size({"width": 390, "height": 844})
        assert page.evaluate("document.documentElement.scrollWidth<=innerWidth")
        assert dialog.evaluate("element=>{const b=element.getBoundingClientRect();return b.left>=0&&b.right<=innerWidth&&b.top>=0&&b.bottom<=innerHeight;}")
        page.screenshot(path=str(output / "passkeys-registered-mobile.png"))
        page.set_viewport_size({"width": 1440, "height": 1050})
        dialog.get_by_role("button", name="Done", exact=True).click()
        page.get_by_role("button", name="Sign out", exact=True).click()
        expect(page.get_by_role("button", name="Sign in with a passkey", exact=True)).to_be_visible()
        with page.expect_response(url + "/api/passkeys/login/verify") as signed_in:
            page.get_by_role("button", name="Sign in with a passkey", exact=True).click()
        assert signed_in.value.status == 200
        expect(page.get_by_role("button", name="Sign out", exact=True)).to_be_visible()
        session = context.request.get(url + "/api/security/sessions").json()
        assert any(row["current"] and row["method"] == "passkey" for row in session["sessions"])
        checks.append("real WebAuthn registration and discoverable passkey sign-in succeed with Chrome's disposable virtual authenticator; passkey management fits desktop and mobile")

        with database.transaction() as connection:
            connection.execute("UPDATE session_security SET verified_at=0")
        page.get_by_role("button", name="Public board", exact=True).click()
        page.get_by_role("button", name="New post", exact=True).click()
        editor = page.locator("#editor")
        title = "Passkey verification preserves the draft"
        editor.get_by_label("Title", exact=True).fill(title)
        editor.get_by_label("Announcement", exact=True).fill("Created only after a deliberate retry.")
        editor.get_by_role("button", name="Save post", exact=True).click()
        verification = page.locator("#verification-dialog")
        expect(verification).to_be_visible()
        with page.expect_response(url + "/api/security/passkeys/reauth/verify") as verified:
            verification.get_by_role("button", name="Use a passkey instead", exact=True).click()
        assert verified.value.status == 200
        expect(verification).not_to_be_visible()
        expect(editor.get_by_label("Title", exact=True)).to_have_value(title)
        with database.transaction() as connection:
            assert connection.execute("SELECT COUNT(*) FROM posts WHERE title=?", (title,)).fetchone()[0] == 0
        editor.get_by_role("button", name="Save post", exact=True).click()
        expect(editor).not_to_be_visible()
        with database.transaction() as connection:
            assert connection.execute("SELECT COUNT(*) FROM posts WHERE title=?", (title,)).fetchone()[0] == 1
        checks.append("a fresh passkey assertion unlocks a stale administrator action while preserving its draft and requiring one deliberate save")

        dialog = open_passkeys()
        dialog.get_by_role("button", name="Remove passkey", exact=True).click()
        expect(page.get_by_role("heading", name="Welcome back.", exact=True)).to_be_visible()
        assert context.request.get(url + "/api/messages").status == 401
        with page.expect_response(url + "/api/passkeys/login/verify") as removed:
            page.get_by_role("button", name="Sign in with a passkey", exact=True).click()
        assert removed.value.status in (401, 403)
        expect(page.get_by_role("heading", name="Welcome back.", exact=True)).to_be_visible()
        password_login()
        checks.append("removing the passkey revokes its current session and rejects the still-present authenticator credential while password plus TOTP remains usable")

        dialog = open_passkeys()
        protocol.send("WebAuthn.setAutomaticPresenceSimulation", {"authenticatorId": authenticator, "enabled": False})
        dialog.get_by_label("Passkey name", exact=True).fill("Cancelled passkey")
        with page.expect_response(url + "/api/security/passkeys/register/options"):
            dialog.get_by_role("button", name="Add a passkey", exact=True).click()
        dialog.get_by_role("button", name="Close passkeys", exact=True).click()
        page.get_by_role("button", name="Team board", exact=True).click()
        expect(page.get_by_role("heading", name="The team board.", exact=True)).to_be_visible()
        assert context.request.get(url + "/api/security/passkeys").json()["passkeys"] == []
        expect(page.locator("#passkey-dialog")).not_to_be_visible()
        assert not errors
        checks.append("closing a pending native registration aborts the ceremony without a registered key or changes to the next page")
    except Exception:
        page.screenshot(path=str(output / "passkeys-failure.png"),
                        mask=[page.locator('input[type="password"],input[name="otp"]')])
        raise
    finally:
        mfa.current_time = original_clock
        context.close()


def exercise(url, output, credentials, channel, checks, data_dir, *, challenge_only=False, save_only=False, admin_tools_only=False, password_faults_only=False, safe_saves_only=False, security_only=False, passkeys_only=False):
    import pyotp
    from playwright.sync_api import expect, sync_playwright

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True, channel=channel)
        context = browser.new_context(viewport={"width": 1440, "height": 1050})
        context.set_default_timeout(10000)
        page = context.new_page()
        page.clock.install(time=time.time() - 1)
        errors = []
        create_headers = {}
        def observe_create(request):
            path = urlsplit(request.url).path
            if request.method == "POST" and path in ("/api/messages", "/api/schedule", "/api/admin/contacts", "/api/admin/posts"):
                create_headers.setdefault(path, []).append(bool(request.headers.get("idempotency-key")))
        page.on("request", observe_create)
        page.on("pageerror", lambda error: errors.append(type(error).__name__))
        page.on("console", lambda message: errors.append("browser console error") if message.type == "error" else None)
        observer = None

        def capture(name):
            expect(page.get_by_text("Loading your workspace…", exact=True)).to_have_count(0)
            page.screenshot(
                path=str(output / f"{name}.png"), full_page=True,
                mask=[page.locator('input[type="password"]:not(:placeholder-shown), input[name="otp"]:not(:placeholder-shown)')],
                mask_color="#dce3df",
            )
            assert page.evaluate("document.documentElement.scrollWidth <= innerWidth"), "Page overflows viewport"

        def navigate(name):
            page.get_by_role("button", name=name, exact=True).click()

        def login(username):
            page.goto(url)
            page.get_by_label("Username", exact=True).fill(username)
            page.get_by_label("Password", exact=True).fill(credentials[username])
            if username == "admin":
                secret, last_counter = synthetic_admin_enrollment(data_dir)
                remaining = (last_counter + 1) * 30 - time.time()
                if remaining > 0:
                    assert remaining <= 30, "Disposable administrator clock unexpectedly moved ahead"
                    time.sleep(remaining + 0.05)
                page.get_by_label("Authenticator code", exact=True).fill(pyotp.TOTP(secret).now())
            page.get_by_role("button", name="Sign in", exact=True).click()
            expect(page.get_by_role("button", name="Sign out", exact=True)).to_be_visible()

        try:
            if passkeys_only:
                exercise_passkeys(browser, url, output, credentials, checks, data_dir)
                return
            if security_only:
                exercise_security(browser, url, output, credentials, checks, data_dir)
                return
            if safe_saves_only:
                exercise_safe_saves(browser, url, output, credentials, checks, data_dir)
                return
            if password_faults_only:
                exercise_password_faults(browser, url, output, credentials, checks)
                return
            if admin_tools_only:
                exercise_admin_tools(browser, output, checks)
                return
            if save_only:
                exercise_pending_saves(browser, output, checks)
                return
            if challenge_only:
                exercise_submission_challenge(browser, url, output, checks)
                return
            page.goto(url)
            expect(page.get_by_role("button", name="Continue as guest", exact=True)).to_be_visible()
            capture("01-sign-in")
            navigate("Continue as guest")
            expect(page.get_by_role("heading", name="The public board.", exact=True)).to_be_visible()
            assert context.request.get(url + "/api/schedule").status == 401
            expect(page.get_by_text("Upcoming partnership announcement", exact=True)).to_have_count(0)
            capture("02-public-board")
            expect(page.get_by_role("button", name="Security & recovery", exact=True)).to_have_count(0)
            checks.append("guest board and private-data denial")
            check_guest_resizing(page, output, checks)

            dialog = page.get_by_role("dialog")
            approved_title = "Community workshop invitation"
            rejected_title = "Unapproved community notice"
            untrusted_body = '<img src=x onerror="window.guestMarkupExecuted=true">'
            for title in (approved_title, rejected_title):
                navigate("Submit a post")
                dialog.get_by_label("Title", exact=True).fill(title)
                dialog.get_by_label("Message", exact=True).fill(
                    "Join our community workshop next month. Everyone is welcome."
                    if title == approved_title else untrusted_body,
                )
                expect(dialog.get_by_role("heading", name="Posting rules", exact=True)).to_be_visible()
                expect(dialog.get_by_role("button", name="Send for approval", exact=True)).to_be_disabled()
                dialog.get_by_label("I agree to the posting rules", exact=True).check()
                expect(dialog.get_by_role("button", name="Send for approval", exact=True)).to_be_enabled()
                if title == approved_title:
                    capture("10-guest-submission")
                    check_dialog_resizing(page, output, checks, name="guest-submission", drafts={
                        "Title": approved_title,
                        "Message": "Join our community workshop next month. Everyone is welcome.",
                    })
                dialog.get_by_role("button", name="Send for approval", exact=True).click()
                expect(dialog).not_to_be_visible()
                expect(page.get_by_text(title, exact=True)).to_have_count(0)
            public = context.request.get(url + "/api/public/posts").json()["posts"]
            assert not any(post["title"] in (approved_title, rejected_title) for post in public)
            assert context.request.get(url + "/api/admin/submissions").status == 401
            checks.append("guest submissions stay private until administrator approval")
            checks.append("guest posting rules are visible and agreement is required before submitting")
            page.set_viewport_size({"width": 390, "height": 844})
            navigate("Submit a post")
            expect(dialog.get_by_role("button", name="Send for approval", exact=True)).to_be_in_viewport()
            capture("11-mobile-guest-submission")
            page.keyboard.press("Escape")
            expect(dialog).not_to_be_visible()
            page.set_viewport_size({"width": 1440, "height": 1050})
            checks.append("guest submission dialog fits mobile and supports keyboard dismissal")

            observer = PublicBoardObserver(browser, url, output, checks)
            observer.assert_post(approved_title, visible=False)
            observer.assert_post(rejected_title, visible=False)
            observer.start_draft()

            login("admin")
            expect(page.get_by_role("heading", name="A clear view,", exact=False)).to_be_visible()
            capture("03-admin-overview")
            checks.append("administrator signs in with password and authenticator code and sees analytics")
            check_staff_resizing(page, output, checks)
            navigate("Security & recovery")
            expect(page.get_by_role("heading", name="Keep access in your hands.", exact=True)).to_be_visible()
            expect(page.get_by_role("button", name="Copy encrypt command", exact=True)).to_be_visible()
            expect(page.locator('#main input[type="file"], #main input[type="password"]')).to_have_count(0)
            navigate("Overview")
            expect(page.get_by_role("button", name="Explore recent activity", exact=True)).to_be_visible()
            checks.append("the real administrator session opens local recovery guidance without a secret upload form")

            navigate("Public board")
            expect(page.get_by_role("button", name=f"Approve {approved_title}", exact=True)).to_be_visible()
            check_admin_board_is_manual(page, checks)
            expect(page.get_by_text(untrusted_body, exact=True)).to_be_visible()
            expect(page.locator('img[src="x"]')).to_have_count(0)
            assert page.evaluate("window.guestMarkupExecuted !== true")
            checks.append("untrusted guest markup is displayed as text in administrator review")
            capture("09-admin-moderation")
            navigate(f"Approve {approved_title}")
            dialog.get_by_role("button", name="Approve post", exact=True).click()
            expect(dialog).not_to_be_visible()
            expect(page.get_by_role("button", name=f"Approve {approved_title}", exact=True)).to_have_count(0)
            observer.poll()
            observer.assert_post(approved_title)
            observer.assert_post(rejected_title, visible=False)
            observer.assert_draft()
            navigate(f"Reject {rejected_title}")
            dialog.get_by_role("button", name="Reject post", exact=True).click()
            expect(dialog).not_to_be_visible()
            expect(page.get_by_text(rejected_title, exact=True)).to_have_count(0)
            public = context.request.get(url + "/api/public/posts").json()["posts"]
            assert sum(post["title"] == approved_title for post in public) == 1
            assert not any(post["title"] == rejected_title for post in public)
            checks.append("administrator approves one guest post and rejects another")
            observer.poll()
            observer.assert_post(rejected_title, visible=False)
            observer.assert_draft()
            checks.append("a second guest automatically sees approved posts while pending and rejected submissions remain private")

            navigate("Schedule")
            navigate("Add event")
            dialog.get_by_label("Event title", exact=True).fill("Browser planning session")
            start = (datetime.now() + timedelta(days=8)).replace(hour=10, minute=0, second=0, microsecond=0)
            dialog.get_by_label("Starts", exact=True).fill(start.strftime("%Y-%m-%dT%H:%M"))
            dialog.get_by_label("Ends", exact=True).fill((start + timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M"))
            dialog.get_by_label("Location", exact=True).fill("Main office")
            dialog.get_by_label("Alex Morgan", exact=True).check()
            check_dialog_resizing(page, output, checks, name="schedule-event", drafts={
                "Event title": "Browser planning session", "Location": "Main office",
            })
            dialog.get_by_role("button", name="Create event", exact=True).click()
            expect(dialog).not_to_be_visible()
            capture("04-schedule")
            saved = context.request.get(url + "/api/schedule").json()["events"]
            assert any(event["title"] == "Browser planning session" for event in saved)
            checks.append("administrator schedules assigned work")

            navigate("Outreach")
            navigate("New contact")
            dialog.get_by_label("Contact name", exact=True).fill("Taylor Mason")
            dialog.get_by_label("Company", exact=True).fill("Mason Studio")
            dialog.get_by_label("Email", exact=True).fill("taylor@example.com")
            dialog.get_by_label("Opportunity value (USD)", exact=True).fill("2400")
            dialog.get_by_role("button", name="Create contact", exact=True).click()
            expect(dialog).not_to_be_visible()
            expect(page.get_by_text("Mason Studio", exact=True)).to_be_visible()
            capture("05-outreach")
            checks.append("outreach contact saved through UI")
            for width in (768, 600, 390, 1440):
                page.set_viewport_size({"width": width, "height": 1050})
                assert page.evaluate("document.documentElement.scrollWidth <= innerWidth"), f"Outreach page overflows at {width}px"
                if width == 390:
                    assert page.locator(".table-wrap").evaluate("element => { element.scrollLeft = element.scrollWidth; return element.scrollLeft > 0; }")
                    capture("16-mobile-outreach")
            checks.append("mobile outreach table scrolls within its panel without widening the page")

            navigate("Public board")
            navigate("New post")
            dialog.get_by_label("Title", exact=True).fill("October office hours")
            dialog.get_by_label("Announcement", exact=True).fill("Our team welcomes visitors on Friday afternoons.")
            dialog.get_by_label("Publish to the public board", exact=True).check()
            dialog.get_by_role("button", name="Save post", exact=True).click()
            expect(dialog).not_to_be_visible()
            public = context.request.get(url + "/api/public/posts").json()["posts"]
            assert any(post["title"] == "October office hours" for post in public)
            checks.append("administrator publishes a guest-visible notice")
            observer.poll()
            observer.assert_post("October office hours")
            observer.assert_draft()

            navigate("Overview")
            page.get_by_role("switch", name="Pause workspace changes", exact=True).click()
            dialog.get_by_role("button", name="Pause changes", exact=True).click()
            expect(dialog).not_to_be_visible()
            expect(page.get_by_role("button", name="Plan an event", exact=True)).to_be_disabled()
            expect(page.get_by_role("button", name="Add a contact", exact=True)).to_be_disabled()
            observer.poll()
            observer.assert_draft(accepting=False)
            navigate("Schedule")
            expect(page.get_by_role("button", name="Add event", exact=True)).to_be_disabled()
            navigate("Public board")
            expect(page.get_by_role("button", name="New post", exact=True)).to_be_disabled()
            expect(page.get_by_role("button", name="Edit October office hours", exact=True)).to_be_disabled()
            expect(page.get_by_role("button", name="Unpublish October office hours", exact=True)).to_be_enabled()
            posts = context.request.get(url + "/api/admin/posts").json()["posts"]
            published_post = next(post for post in posts if post["title"] == "October office hours")
            session = context.request.get(url + "/api/session").json()
            headers = {"Origin": url, "X-CSRF-Token": session["csrf"]}
            edit = {key: published_post[key] for key in ("title", "body", "category", "published", "revision")}
            assert context.request.put(
                url + "/api/admin/posts/" + published_post["id"], data=edit, headers=headers,
            ).status == 403
            assert context.request.post(
                url + "/api/admin/posts", data={key: value for key, value in edit.items() if key != "revision"},
                headers=headers,
            ).status == 403
            navigate("Unpublish October office hours")
            dialog.get_by_role("button", name="Unpublish post", exact=True).click()
            expect(dialog).not_to_be_visible()
            expect(page.get_by_role("heading", name="October office hours", exact=True)).to_be_visible()
            expect(page.get_by_role("button", name="Unpublish October office hours", exact=True)).to_have_count(0)
            public = context.request.get(url + "/api/public/posts").json()["posts"]
            assert not any(post["id"] == published_post["id"] for post in public)
            capture("12-paused-emergency-unpublish")
            checks.append("paused administrator unpublishes a notice while editing and publishing remain denied")
            observer.poll()
            observer.assert_post("October office hours", visible=False)
            observer.assert_draft(accepting=False)
            navigate("Overview")
            page.get_by_role("switch", name="Pause workspace changes", exact=True).click()
            dialog.get_by_role("button", name="Resume changes", exact=True).click()
            expect(dialog).not_to_be_visible()
            observer.poll()
            observer.assert_draft()
            observer.finish()
            checks.append("public polling removes unpublished notices and applies pause/resume without losing a guest draft")
            navigate("Schedule")
            expect(page.get_by_role("button", name="Add event", exact=True)).to_be_enabled()
            checks.append("shared pause disables editing and administrator can resume")

            navigate("Sign out")
            navigate("Continue as guest")
            expect(page.get_by_role("heading", name=approved_title, exact=True)).to_be_visible()
            expect(page.get_by_text(rejected_title, exact=True)).to_have_count(0)
            expect(page.get_by_role("button", name=f"Approve {approved_title}", exact=True)).to_have_count(0)
            checks.append("guest sees only the approved community post")
            login("alex")
            expect(page.get_by_role("button", name="Overview", exact=True)).to_have_count(0)
            expect(page.get_by_role("button", name="Outreach", exact=True)).to_have_count(0)
            expect(page.get_by_role("button", name="Security & recovery", exact=True)).to_have_count(0)
            assert context.request.get(url + "/api/admin/overview").status == 403
            assert context.request.get(url + "/api/admin/submissions").status == 403
            navigate("Team board")
            page.get_by_label("Your message", exact=True).fill("The planning notes are ready for the team.")
            navigate("Post message")
            expect(page.get_by_text("The planning notes are ready for the team.", exact=True)).to_be_visible()
            capture("06-employee-board")
            checks.append("employee posts a private team message and cannot open admin data")

            page.set_viewport_size({"width": 390, "height": 844})
            capture("07-mobile-team")
            checks.append("mobile layout has no horizontal overflow")
            navigate("Open navigation")
            expect(page.get_by_role("button", name="Schedule", exact=True)).to_be_visible()
            page.keyboard.press("Escape")
            expect(page.get_by_role("button", name="Open navigation", exact=True)).to_be_focused()
            navigate("Open navigation")
            navigate("Schedule")
            expect(page.get_by_role("heading", name="The team schedule.", exact=True)).to_be_visible()
            capture("08-mobile-schedule")
            checks.append("mobile navigation supports keyboard dismissal and page selection")
            assert set(create_headers) == {"/api/messages", "/api/schedule", "/api/admin/contacts", "/api/admin/posts"}
            assert all(all(values) for values in create_headers.values())
            checks.append("all four authenticated create forms send retry keys through real browser workflows")
            assert not errors, f"Browser errors: {errors}"
            checks.append("no JavaScript or console errors")
            check_public_board_recovery(browser, url, output, checks)
            exercise_submission_challenge(browser, url, output, checks)
            exercise_pending_saves(browser, output, checks)
            exercise_admin_tools(browser, output, checks)
            exercise_safe_saves(browser, url, output, credentials, checks, data_dir)
            exercise_password_faults(browser, url, output, credentials, checks)
        except Exception:
            # No traces or network payloads: they can capture test account secrets.
            page.screenshot(
                path=str(output / "failure.png"), full_page=True,
                mask=[page.locator('input[type="password"]:not(:placeholder-shown), input[name="otp"]:not(:placeholder-shown)')],
                mask_color="#dce3df",
            )
            if observer is not None:
                observer.page.screenshot(path=str(output / "public-observer-failure.png"), full_page=True)
            raise
        finally:
            if observer is not None:
                observer.close()
            context.close()
            browser.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--browser-channel", default=None)
    focused = parser.add_mutually_exclusive_group()
    focused.add_argument("--challenge-only", action="store_true", help="Run only the isolated required-verification browser checks.")
    focused.add_argument("--save-only", action="store_true", help="Run only the isolated pending-save browser checks.")
    focused.add_argument("--admin-tools-only", action="store_true", help="Run only administrator guidance, activity and session-race browser checks.")
    focused.add_argument("--password-faults-only", action="store_true", help="Run only real local password-change interruption and session-race checks.")
    focused.add_argument("--safe-saves-only", action="store_true", help="Run only real create retry, posting-limit and password-policy browser checks.")
    focused.add_argument("--security-only", action="store_true", help="Run real local session revocation, fresh verification and draft-preservation checks.")
    focused.add_argument("--passkeys-only", action="store_true", help="Run real local WebAuthn with a disposable Chrome virtual authenticator.")
    options = parser.parse_args(argv)
    output = options.output_dir.resolve()
    if output == ROOT or ROOT in output.parents:
        parser.error("Evidence must be outside the checkout.")
    if output.exists() and any(output.iterdir()):
        parser.error("Evidence directory must be empty; earlier results were preserved.")
    output.mkdir(parents=True, exist_ok=True)
    sys.path.insert(0, str(ROOT))
    sys.path.insert(0, str(EXAMPLE))
    from business.seed import provision
    from business.app import create_app
    import role_aware_dashboard_toolkit as toolkit
    import uvicorn

    assert Path(toolkit.__file__).resolve().parent == ROOT / "role_aware_dashboard_toolkit", "Expected this checkout's toolkit"
    checks = []
    result = {"passed": False, "checks": checks}
    try:
        with tempfile.TemporaryDirectory(prefix="radt-business-browser-") as temporary:
            data = Path(temporary).resolve() / "private"
            credentials = provision(data)
            with socket.socket() as reservation:
                reservation.bind(("127.0.0.1", 0))
                port = reservation.getsockname()[1]
            url = f"http://{'localhost' if options.passkeys_only else '127.0.0.1'}:{port}"
            log = logging.FileHandler(output / "server.log", encoding="utf-8")
            logger = logging.getLogger("uvicorn")
            logger.addHandler(log)
            logger.setLevel(logging.INFO)
            try:
                server = uvicorn.Server(uvicorn.Config(
                    create_app(data, public_origin=url), host="127.0.0.1", port=port,
                    proxy_headers=False, access_log=False, log_config=None,
                    timeout_graceful_shutdown=5,
                ))
                # An owned thread avoids orphaning a Windows venv launcher child.
                worker = threading.Thread(target=server.run, daemon=True)
                worker.start()
                try:
                    deadline = time.monotonic() + 30
                    while True:
                        if not worker.is_alive():
                            raise RuntimeError("Owned server exited before readiness; inspect server.log")
                        try:
                            with urlopen(url + "/healthz", timeout=1) as response:
                                if response.status == 200:
                                    break
                        except (URLError, TimeoutError):
                            pass  # Connection refusal is expected during owned startup.
                        if time.monotonic() >= deadline:
                            raise TimeoutError("Owned server did not become ready")
                        time.sleep(0.1)
                    exercise(url, output, credentials, options.browser_channel, checks, data,
                             challenge_only=options.challenge_only, save_only=options.save_only,
                             admin_tools_only=options.admin_tools_only, password_faults_only=options.password_faults_only,
                             safe_saves_only=options.safe_saves_only, security_only=options.security_only,
                             passkeys_only=options.passkeys_only)
                finally:
                    server.should_exit = True
                    worker.join(timeout=15)
                    if worker.is_alive():
                        raise RuntimeError("Owned server did not stop")
            finally:
                logger.removeHandler(log)
                log.close()
            result["passed"] = True
    except Exception as error:
        result["error_type"] = type(error).__name__
        result["error_frames"] = [{"file": Path(frame.filename).name, "line": frame.lineno, "function": frame.name}
                                  for frame in traceback.extract_tb(error.__traceback__)]
        result["error_categories"] = [marker for marker in (
            "Content Security Policy", "unsafe-eval", "Execution context was destroyed", "Target closed",
            "Target page, context or browser has been closed", "ReferenceError", "TypeError", "ECONNRESET",
            "ECONNREFUSED", "strict mode violation", "disconnected", "interrupted", "Cannot find context",
        ) if marker in str(error)]
        # Playwright call logs can contain filled passwords; never serialize them.
        print(f"Business browser check failed ({type(error).__name__}); inspect screenshots and server.log.", file=sys.stderr)
    finally:
        (output / "summary.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(f"Business browser checks: {len(checks)} passed; evidence: {output}")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
