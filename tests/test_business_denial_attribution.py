"""Denial evidence uses a verified session identity, never request assertions."""

import pytest

from tests.test_business_dashboard import (
    ORIGIN, business as business, business_seed as business_seed,
)


def _denials(business):
    with business.db() as connection:
        return [dict(row) for row in connection.execute(
            "SELECT code,reason,actor FROM security_events WHERE outcome='denied' ORDER BY sequence"
        )]


@pytest.mark.parametrize("failure", ["permission", "csrf"])
def test_denial_preserves_authenticated_principal(business, failure):
    employee = business.login("alex")
    with business.db() as connection:
        principal = connection.execute("SELECT principal FROM users WHERE id='alex'").fetchone()[0]
        before = connection.execute("SELECT COUNT(*) FROM messages").fetchone()[0]
    if failure == "permission":
        response = employee.request("GET", "/api/admin/users")
    else:
        response = employee.request("POST", "/api/messages", json={"body": "Must remain unsaved"},
                                    headers={"X-CSRF-Token": "unverified-value"})
    assert response.status_code == 403
    assert _denials(business) == [
        {"code": "authorization_denied", "reason": "forbidden", "actor": principal},
    ]
    with business.db() as connection:
        assert connection.execute("SELECT COUNT(*) FROM messages").fetchone()[0] == before


@pytest.mark.parametrize("cookie", [None, "unverified-session-value"])
def test_unverified_request_cannot_claim_an_audit_principal(business, cookie):
    with business.db() as connection:
        principal = connection.execute("SELECT principal FROM users WHERE id='alex'").fetchone()[0]
    client = business.client()
    if cookie:
        client.cookies.set("westbridge_session", cookie)
    response = client.get("/api/admin/users", headers={"Origin": ORIGIN, "X-Security-Actor": principal})
    assert response.status_code == 401
    assert _denials(business) == [
        {"code": "authorization_denied", "reason": "unauthenticated", "actor": None},
    ]
