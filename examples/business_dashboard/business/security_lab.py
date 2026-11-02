"""Read-only, public explanations and explicitly scoped operator-supplied evidence.

This surface never executes scenarios or exposes the private event timeline.
Operators select one already sanitized receipt outside source storage. Its
checksum detects corruption; it is not an independent signature or attestation.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from threading import Lock

from fastapi.responses import FileResponse

from .db import SOURCE_ROOTS, check_private_file
from .evidence import load_receipt, public_receipt, source_fingerprint

LOGGER = logging.getLogger(__name__)

SCENARIOS = (
    {
        "id": "session_revocation", "number": "01", "title": "Revoke access mid-session",
        "checks": ["revoke_initial_access", "revoke_other_session", "revoke_next_request", "revoke_no_business_change", "revoke_legitimate_control"],
        "scope": "Westbridge application", "threat": "A signed-in session outlives its permission to act.",
        "steps": ["Establish a disposable employee session.", "Revoke its access while it remains open.",
                  "Submit the next protected action and inspect the result."],
        "invariant": "The rejected action changes no business record; another authorized session still succeeds.",
        "decision": "Current authority is checked in the same transaction as the protected operation.",
    },
    {
        "id": "stale_editor", "number": "02", "title": "Let two editors race",
        "checks": ["cas_shared_revision", "cas_one_winner", "cas_one_commit", "cas_fresh_control"],
        "scope": "Toolkit API", "threat": "An old draft silently overwrites a newer decision.",
        "steps": ["Read the same revision in two independent clients.", "Commit a change from the first client.",
                  "Submit the second client's stale revision, then read the stored result."],
        "invariant": "One write succeeds; the stale write is rejected without changing the winning value.",
        "decision": "Revision preconditions make conflicts explicit. Refresh and review before retrying.",
    },
    {
        "id": "recovery_authority", "number": "03", "title": "Restore data, preserve revocation",
        "checks": ["restore_historical_record", "restore_old_session_denied", "restore_disabled_user_denied", "restore_current_access", "restore_remains_frozen"],
        "scope": "Westbridge application", "threat": "An old backup brings a disabled account or old session back to life.",
        "steps": ["Back up a disposable workspace, then revoke access.",
                  "Restore into a new directory with an explicitly trusted current security source.",
                  "Check old-session rejection, current grants, and a legitimate account."],
        "invariant": "Business data can be recovered while historical sessions and revoked authority stay rejected.",
        "decision": "A backup is historical data, not proof of current authority. Unreconciled restores stay quarantined.",
    },
)

DECISIONS = (
    {"title": "Authority belongs on the server", "body": "Role labels and hidden buttons are presentation. Current identity, grants, freeze state and revisions decide protected actions."},
    {"title": "Failures must have a defined outcome", "body": "Security events for protected changes share the business transaction. Delivery can retry independently with a stable event identity."},
    {"title": "Recovery has its own trust boundary", "body": "Keys remain separate from backups. Restores require current authority, and MFA-key rotation is an offline operator procedure."},
    {"title": "Every result has a scope", "body": "Local scenario and virtual-authenticator results do not prove the deployed proxy, a physical authenticator, or hosted recovery."},
)


def _read_evidence(configured, current_source):
    if not configured:
        return {"status": "not_run", "receipt": None, "message": "No reviewed evidence receipt has been selected for this service."}
    try:
        path = Path(configured).absolute()
        resolved = path.resolve(strict=True)
        if any(resolved == root or root in resolved.parents for root in SOURCE_ROOTS):
            raise ValueError("Evidence must be outside source storage.")
        for item in (path, *path.parents):
            if item.is_symlink() or (hasattr(item, "is_junction") and item.is_junction()):
                raise ValueError("Evidence paths must not be redirected.")
        check_private_file(path)
        receipt = public_receipt(load_receipt(path))
        matches = receipt["source"]["sha256"] == current_source["sha256"]
        status = receipt["status"] if matches and receipt["source_unchanged"] else "stale"
        return {"status": status, "receipt": receipt, "source_matches": matches,
                "message": "Operator-supplied local evidence. Its checksum is not an independent attestation."}
    except (OSError, ValueError, TypeError, KeyError):
        return {"status": "unavailable", "receipt": None, "message": "The selected evidence could not be validated. No result is claimed."}


def install_security_lab_routes(app, database, authorized):
    """Install public static explanations; private runtime events use other routes."""
    configured = os.environ.get("BUSINESS_SECURITY_EVIDENCE_FILE")
    # Take one source snapshot on first use. Ordinary application traffic never
    # scans the checkout, and subsequent public reads use the same bounded view.
    current_source = None
    previous_evidence_status = None
    source_lock = Lock()

    @app.get("/api/security-lab")
    def security_lab():
        nonlocal current_source, previous_evidence_status
        with source_lock:
            if current_source is None:
                current_source = source_fingerprint()
        evidence = _read_evidence(configured, current_source)
        with source_lock:
            if evidence["status"] == "unavailable" and previous_evidence_status != "unavailable":
                LOGGER.warning("Security lab evidence could not be validated; no receipt was exposed.")
            previous_evidence_status = evidence["status"]
        return {"title": "Security, with the evidence.", "scenarios": SCENARIOS, "decisions": DECISIONS,
                "source": current_source, "source_scope": "first_lab_request_in_this_process",
                "evidence": evidence,
                "hosted_acceptance": {"status": "not_verified_here",
                                      "message": "Physical-device passkeys, deployed build identity and hosted recovery need separate acceptance records."}}

    @app.get("/security-lab", include_in_schema=False)
    def security_lab_page():
        return FileResponse(Path(__file__).parent / "static" / "index.html")
