"""Fixed, in-memory security counters without request data or database writes."""

from datetime import datetime, timezone
from threading import Lock

MAX_COUNTER = (1 << 63) - 1
EVENTS = (
    "auth_lookup_started", "auth_lookup_busy",
    "auth_known_started", "auth_known_busy",
    "auth_unknown_started", "auth_unknown_busy",
    "login_budget_denied", "login_reservation_expired", "login_identity_changed",
    "login_rejected", "login_succeeded",
    "password_budget_denied", "password_reservation_expired", "password_identity_changed",
    "password_rejected", "password_policy_rejected", "password_changed",
    "reauth_started", "reauth_busy", "reauth_budget_denied", "reauth_rejected",
    "reauth_succeeded", "reauth_identity_changed", "reauth_reservation_expired",
    "body_capacity_denied", "body_timeout", "body_oversized",
    "public_verification_started", "public_verification_busy", "public_verification_budget_denied",
    "public_verification_rejected", "public_verification_unavailable",
    "public_submission_quota_denied", "public_submission_paused", "public_submission_accepted",
    "message_quota_denied", "message_capacity_denied",
    "passkey_options_started", "passkey_options_busy", "passkey_verification_started", "passkey_verification_busy",
    "passkey_challenge_capacity_denied", "passkey_credential_capacity_denied", "passkey_rejected",
    "passkey_registered", "passkey_login_succeeded", "passkey_reauth_succeeded", "passkey_removed",
)


class SecurityMetrics:
    """One application's bounded decision counts; not a durable audit trail.

    Names are a fixed allowlist. No account, address, token, submitted content or
    arbitrary label is accepted. Counts saturate instead of growing indefinitely.
    """

    def __init__(self):
        self._lock = Lock()
        self._counts = dict.fromkeys(EVENTS, 0)
        self._started_at = datetime.now(timezone.utc).isoformat(timespec="seconds")

    def record(self, event):
        if event not in self._counts:
            raise ValueError("Unsupported security metric.")
        with self._lock:
            self._counts[event] = min(MAX_COUNTER, self._counts[event] + 1)

    def snapshot(self):
        with self._lock:
            counts = dict(self._counts)
        return {
            "scope": "application_instance", "resets_on_restart": True,
            "started_at": self._started_at, "counters": counts,
        }
