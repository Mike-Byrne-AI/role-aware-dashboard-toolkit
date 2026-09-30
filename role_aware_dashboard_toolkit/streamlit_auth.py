"""Minimal identity adapter for a host-configured Streamlit OIDC connection.

Streamlit and its authentication dependency verify the provider's token during
the login flow. This adapter reads only ``st.user`` from that flow; it is not a
JWT verifier and must not be used with user-supplied claims. Configure the
provider and credentials through host secrets, outside the public source tree.
The adapter retains no claim dictionary, email, display name, or token.
"""

from __future__ import annotations

import math
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, NoReturn

from .access import AccessDenied, Identity


def _nonempty_string(value: Any) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and value == value.strip()
        and not any(ord(char) < 32 or ord(char) == 127 for char in value)
    )


def _timestamp(value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise AccessDenied()
    result = float(value)
    if not math.isfinite(result) or result <= 0:
        raise AccessDenied()
    return result


@dataclass(frozen=True, kw_only=True)
class StreamlitIdentityResolver:
    """Resolve a minimal identity from Streamlit's verified OIDC user.

    ``trusted_issuer`` and ``expected_audience`` are exact provider issuer and
    client ID values from server configuration. Neither may come from widgets,
    query parameters, profiles, or a claim supplied by the browser.

    Every call enforces ``exp`` and bounds the age of ``iat``. If ``auth_time``
    is present, its age is bounded too. Set ``require_auth_time=True`` and
    configure the provider to request ``max_age`` when fresh authentication is
    required: issuance time alone does not prove that credentials were recently
    re-entered. ``expires_at`` is the earliest of these deadlines. Future dates,
    malformed claims, missing authentication, and read failures deny access.

    Streamlit keeps ``st.user`` for the life of its session. This adapter does
    not check provider-side revocation or end another tab's session. The access
    policy must recheck server-controlled role assignments for every action.
    Do not cache the result or the authenticated user's authorization context.

    Install the optional authentication dependencies in the host application;
    importing this module does not import Streamlit or Authlib.
    """

    trusted_issuer: str
    expected_audience: str
    max_session_age: float = 3600
    require_auth_time: bool = False
    clock: Callable[[], float] = field(default=time.time, repr=False, compare=False)

    def __post_init__(self) -> None:
        if not _nonempty_string(self.trusted_issuer):
            raise ValueError("trusted_issuer must be a nonempty exact issuer.")
        if not _nonempty_string(self.expected_audience):
            raise ValueError("expected_audience must be a nonempty client ID.")
        try:
            _timestamp(self.max_session_age)
        except (AccessDenied, OverflowError):
            raise ValueError("max_session_age must be positive and finite.") from None
        if not isinstance(self.require_auth_time, bool):
            raise ValueError("require_auth_time must be a boolean.")
        if not callable(self.clock):
            raise ValueError("clock must be callable.")

    def __call__(self) -> Identity:
        # Lazy import keeps the core package usable without a UI dependency.
        # Read the current runtime object on every call: it is never captured
        # while building a process-wide policy or copied into session state.
        try:
            import streamlit as st

            user = st.user
            if not isinstance(user, Mapping) or user.get("is_logged_in") is not True:
                raise AccessDenied()
            issuer = user.get("iss")
            subject = user.get("sub")
            if issuer != self.trusted_issuer:
                raise AccessDenied()
            if (
                not _nonempty_string(subject)
                or len(subject) > 255
                or not subject.isascii()
            ):
                raise AccessDenied()

            audience = user.get("aud")
            if isinstance(audience, str):
                audiences = [audience]
            elif isinstance(audience, list):
                audiences = audience
            else:
                raise AccessDenied()
            if (
                not audiences
                or any(not _nonempty_string(item) for item in audiences)
                or self.expected_audience not in audiences
            ):
                raise AccessDenied()
            # Require the authorized party to identify this client when a token
            # has multiple audiences; check it whenever it is supplied.
            if (len(audiences) > 1 or "azp" in user) and (
                user.get("azp") != self.expected_audience
            ):
                raise AccessDenied()

            now = _timestamp(self.clock())
            issued_at = _timestamp(user.get("iat"))
            token_expires_at = _timestamp(user.get("exp"))
            if issued_at > now or token_expires_at <= issued_at:
                raise AccessDenied()
            expires_at = min(token_expires_at, issued_at + self.max_session_age)
            if "auth_time" in user:
                authenticated_at = _timestamp(user.get("auth_time"))
                if authenticated_at > issued_at:
                    raise AccessDenied()
                expires_at = min(expires_at, authenticated_at + self.max_session_age)
            elif self.require_auth_time:
                raise AccessDenied()
            if "nbf" in user and _timestamp(user.get("nbf")) > now:
                raise AccessDenied()
            if expires_at <= now:
                raise AccessDenied()
            return Identity(issuer=issuer, subject=subject, expires_at=expires_at)
        except Exception:
            # Provider/configuration errors can contain personal data or secrets.
            # Expose one fixed denial without copying the original exception.
            raise AccessDenied() from None


def render_sign_in(st: Any, *, provider: str | None = None) -> NoReturn:
    """Render recovery after denial and always stop before protected content.

    Call from an ``except AccessDenied`` block before loading application data.
    An existing identity may be expired or unassigned; signing out allows the
    user to start a fresh login with an authorized account. The host is still
    responsible for offering sign-out on an authorized page. Streamlit logout
    affects the current session and cookie, not other already-open sessions.
    """

    st.warning("Sign in with an authorized account to continue.")
    try:
        logged_in = st.user.get("is_logged_in") is True
    except Exception:
        logged_in = False
    try:
        if logged_in:
            if st.button("Sign out", key="_radt_sign_out"):
                st.logout()
        elif st.button("Sign in", key="_radt_sign_in"):
            st.login(provider)
    except Exception:
        st.error("Sign-in is unavailable. Contact the dashboard administrator.")
    st.stop()
    # Real Streamlit raises its stop signal. Keep denial intact for host wrappers
    # or test doubles that incorrectly return instead.
    raise AccessDenied()
