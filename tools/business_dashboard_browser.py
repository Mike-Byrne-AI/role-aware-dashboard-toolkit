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
from urllib.error import URLError
from urllib.parse import urlsplit
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples" / "business_dashboard"


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
    except Exception:
        page.screenshot(path=str(output / "challenge-failure.png"), full_page=True)
        raise
    finally:
        context.close()


def exercise(url, output, credentials, channel, checks, data_dir, *, challenge_only=False):
    import pyotp
    from playwright.sync_api import expect, sync_playwright

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True, channel=channel)
        context = browser.new_context(viewport={"width": 1440, "height": 1050})
        context.set_default_timeout(10000)
        page = context.new_page()
        page.clock.install(time=time.time() - 1)
        errors = []
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
                with closing(sqlite3.connect((data_dir / "business.sqlite3").as_uri() + "?mode=ro", uri=True)) as connection:
                    enrollment = connection.execute(
                        "SELECT a.secret FROM admin_mfa a JOIN users u ON u.id=a.user_id WHERE u.username=?",
                        (username,),
                    ).fetchone()
                assert enrollment is not None, "Disposable administrator enrollment is missing"
                page.get_by_label("Authenticator code", exact=True).fill(pyotp.TOTP(enrollment[0]).now())
            page.get_by_role("button", name="Sign in", exact=True).click()
            expect(page.get_by_role("button", name="Sign out", exact=True)).to_be_visible()

        try:
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
            assert not errors, f"Browser errors: {errors}"
            checks.append("no JavaScript or console errors")
            check_public_board_recovery(browser, url, output, checks)
            exercise_submission_challenge(browser, url, output, checks)
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
    parser.add_argument("--challenge-only", action="store_true", help="Run only the isolated required-verification browser checks.")
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
            url = f"http://127.0.0.1:{port}"
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
                             challenge_only=options.challenge_only)
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
        # Playwright call logs can contain filled passwords; never serialize them.
        print(f"Business browser check failed ({type(error).__name__}); inspect screenshots and server.log.", file=sys.stderr)
    finally:
        (output / "summary.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(f"Business browser checks: {len(checks)} passed; evidence: {output}")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
