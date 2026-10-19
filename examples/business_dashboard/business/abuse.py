"""Public posting rules and server-verified challenges for this example host.

Challenges reduce automated submissions; they do not decide whether a post is
acceptable. Every guest post still requires a current administrator's approval.
"""

from dataclasses import dataclass, field
import json
import os
import time

from fastapi import HTTPException
import httpx

from .request_security import validate_origin

SITEVERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
CHALLENGE_ACTION = "guest_submission"
MAX_PROVIDER_BYTES = 16384
PROVIDER_DEADLINE_SECONDS = 8.0
PUBLIC_RULES = {
    "version": "2026-10-18",
    "rules": [
        "Post genuine job opportunities, business notices, or relevant community updates.",
        "Do not post scams, deceptive offers, impersonation, or repetitive advertising.",
        "Do not post harassment, hateful content, or discriminatory job requirements.",
        "Do not offer illegal or exploitative work.",
        "Do not include private or sensitive information about yourself or other people.",
        "All submissions are reviewed before publication and may be declined or removed.",
    ],
}
_TEST_KEYS = frozenset({
    "1x00000000000000000000AA", "2x00000000000000000000AB",
    "1x00000000000000000000BB", "2x00000000000000000000BB",
    "3x00000000000000000000FF", "1x0000000000000000000000000000000AA",
    "2x0000000000000000000000000000000AA", "3x0000000000000000000000000000000AA",
})


@dataclass(frozen=True)
class SubmissionGuard:
    hostname: str
    required: bool
    site_key: str = ""
    secret_key: str = field(default="", repr=False)

    @classmethod
    def from_origin(cls, public_origin):
        origin = validate_origin(public_origin)
        if origin.scheme == "http":
            # validate_origin permits plain HTTP only for explicit loopback hosts.
            return cls(origin.hostname, False)
        site_key = os.environ.get("BUSINESS_TURNSTILE_SITE_KEY", "")
        secret_key = os.environ.get("BUSINESS_TURNSTILE_SECRET_KEY", "")
        if any(not key or len(key) > 256 or not key.isascii() or any(char.isspace() for char in key)
               for key in (site_key, secret_key)):
            raise ValueError("HTTPS requires BUSINESS_TURNSTILE_SITE_KEY and BUSINESS_TURNSTILE_SECRET_KEY.")
        if origin.hostname not in ("localhost", "127.0.0.1", "::1") and (
                site_key in _TEST_KEYS or secret_key in _TEST_KEYS):
            raise ValueError("Public hosting requires real Turnstile keys, not testing credentials.")
        return cls(origin.hostname, True, site_key, secret_key)

    def public_config(self):
        return {
            "provider": "turnstile" if self.required else "none",
            "site_key": self.site_key if self.required else None,
            "required": self.required,
        }

    @staticmethod
    def validate_policy(version, accepted):
        if version != PUBLIC_RULES["version"] or accepted is not True:
            raise HTTPException(422, "Read and accept the current posting rules before submitting.")

    def verify(self, token, remote=None):
        if not self.required:
            return
        if (not isinstance(token, str) or not 1 <= len(token) <= 2048
                or not token.isascii() or any(char.isspace() for char in token)):
            raise HTTPException(422, "Complete the verification challenge before submitting.")
        payload = {"secret": self.secret_key, "response": token}
        # remote is the transport peer, which can be a hosting proxy rather
        # than the visitor. Omit optional remoteip instead of asserting an
        # unverified visitor address or trusting forwarding headers.
        started = time.monotonic()
        try:
            with httpx.Client(timeout=httpx.Timeout(5.0, connect=3.0), follow_redirects=False,
                              trust_env=False) as client:
                with client.stream("POST", SITEVERIFY_URL, data=payload,
                                   headers={"Accept": "application/json", "Accept-Encoding": "identity"}) as response:
                    if response.status_code != 200 or response.headers.get("content-encoding", "identity") != "identity":
                        raise ValueError("Unexpected challenge service response.")
                    body = bytearray()
                    # Inspect each transport chunk. Buffering until a requested
                    # chunk size fills can hide a slow trickle from the deadline.
                    # A blocked read is separately capped at five seconds.
                    for chunk in response.iter_raw():
                        body.extend(chunk)
                        if len(body) > MAX_PROVIDER_BYTES or time.monotonic() - started > PROVIDER_DEADLINE_SECONDS:
                            raise ValueError("Challenge service response exceeds its bounds.")
                    result = json.loads(body)
        except (httpx.HTTPError, ValueError, UnicodeError):
            # Do not log tokens, secrets, provider response bodies, or exception
            # messages. A provider/network failure must never approve a post.
            raise HTTPException(503, "Verification is unavailable. Please try again later.") from None
        if (not isinstance(result, dict) or result.get("success") is not True
                or result.get("hostname") != self.hostname
                or result.get("action") != CHALLENGE_ACTION):
            raise HTTPException(403, "Verification failed or expired. Please complete a new challenge.")
