"""Real signed WebAuthn responses against disposable host state, never hardware claims."""

from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import secrets
from threading import Barrier, Event

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
pytest.importorskip("pyotp")
pytest.importorskip("webauthn")
import cbor2  # noqa: E402
from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from webauthn import base64url_to_bytes  # noqa: E402
from webauthn.helpers import bytes_to_base64url  # noqa: E402

from tests.test_business_dashboard import (  # noqa: E402
    ORIGIN, business as business, business_seed as business_seed,
)
from business import auth_routes, passkeys  # noqa: E402
from business.security import COOKIE_NAME, token_hash  # noqa: E402


class Authenticator:
    """A fresh disposable key signs actual ES256 WebAuthn protocol messages."""

    def __init__(self, *, synced=False):
        self.private = ec.generate_private_key(ec.SECP256R1())
        self.identifier = secrets.token_bytes(32)
        self.synced = synced
        self.handle = None

    def _client(self, options, kind, **changes):
        return json.dumps({"type": kind, "challenge": options["challenge"], "origin": ORIGIN,
                           "crossOrigin": False, **changes}, separators=(",", ":")).encode()

    def register(self, options, *, uv=True):
        self.handle = base64url_to_bytes(options["user"]["id"])
        point = self.private.public_key().public_numbers()
        public = cbor2.dumps({1: 2, 3: -7, -1: 1, -2: point.x.to_bytes(32, "big"), -3: point.y.to_bytes(32, "big")})
        flags = 0x41 | (0x04 if uv else 0) | (0x18 if self.synced else 0)
        data = (hashlib.sha256(options["rp"]["id"].encode()).digest() + bytes([flags]) + (0).to_bytes(4, "big")
                + bytes(16) + len(self.identifier).to_bytes(2, "big") + self.identifier + public)
        client = self._client(options, "webauthn.create")
        signature = self.private.sign(data + hashlib.sha256(client).digest(), ec.ECDSA(hashes.SHA256()))
        # Packed self-attestation exercises signature verification during both
        # enrollment and login. It does not attest a hardware vendor or device.
        attestation = cbor2.dumps({"fmt": "packed", "attStmt": {"alg": -7, "sig": signature}, "authData": data})
        return {"id": bytes_to_base64url(self.identifier), "rawId": bytes_to_base64url(self.identifier),
                "type": "public-key", "response": {"clientDataJSON": bytes_to_base64url(client),
                "attestationObject": bytes_to_base64url(attestation), "transports": ["internal"]},
                "clientExtensionResults": {"credProps": {"rk": True}}}

    def assertion(self, options, *, counter=1, change=None):
        client = self._client(options, "webauthn.get", **{
            "origin": "https://foreign.invalid"} if change == "origin" else {})
        if change in ("challenge", "type", "cross_origin"):
            values = {"challenge": {"challenge": bytes_to_base64url(b"wrong")},
                      "type": {"type": "webauthn.create"}, "cross_origin": {"crossOrigin": True}}[change]
            client = self._client(options, "webauthn.get", **values)
        flags = 0x05 | (0x18 if self.synced else 0)
        if change == "uv":
            flags &= ~0x04
        if change == "up":
            flags &= ~0x01
        if change == "backup":
            flags ^= 0x08
        rp_id = "foreign.invalid" if change == "rp" else options["rpId"]
        data = hashlib.sha256(rp_id.encode()).digest() + bytes([flags]) + counter.to_bytes(4, "big")
        signature = self.private.sign(data + hashlib.sha256(client).digest(), ec.ECDSA(hashes.SHA256()))
        if change == "signature":
            signature = signature[:-1] + bytes([signature[-1] ^ 1])
        credential = {"id": bytes_to_base64url(self.identifier), "rawId": bytes_to_base64url(self.identifier),
                      "type": "public-key", "response": {"clientDataJSON": bytes_to_base64url(client),
                      "authenticatorData": bytes_to_base64url(data), "signature": bytes_to_base64url(signature),
                      "userHandle": bytes_to_base64url(self.handle)}, "clientExtensionResults": {}}
        if change == "user_handle":
            credential["response"]["userHandle"] = bytes_to_base64url(b"another-account")
        elif change == "missing_handle":
            credential["response"].pop("userHandle")
        elif change == "raw_id":
            credential["id"] = bytes_to_base64url(b"different-id")
        return credential


def enroll(actor, key=None):
    key = key or Authenticator()
    response = actor.request("POST", "/api/security/passkeys/register/options", json={})
    assert response.status_code == 200
    ceremony = response.json()
    options = ceremony["options"]
    assert options["authenticatorSelection"]["residentKey"] == "required"
    assert options["authenticatorSelection"]["userVerification"] == "required"
    response = actor.request("POST", "/api/security/passkeys/register/verify", json={
        "request_id": ceremony["request_id"], "credential": key.register(options), "name": "Disposable test key",
    })
    assert response.status_code == 200
    return key, response.json()["passkey"]


def login_options(client):
    response = client.post("/api/passkeys/login/options", headers={"Origin": ORIGIN}, json={})
    assert response.status_code == 200
    result = response.json()
    assert result["options"]["userVerification"] == "required"
    assert result["options"].get("allowCredentials", []) == []
    return result


def finish_login(client, ceremony, credential, **headers):
    return client.post("/api/passkeys/login/verify", json={
        "request_id": ceremony["request_id"], "credential": credential,
    }, headers={"Origin": ORIGIN, "X-Passkey-CSRF": ceremony["csrf"], **headers})


@pytest.mark.parametrize("username", ["alex", "admin"])
def test_signed_registration_and_login_for_both_roles_issue_bound_current_session(business, username):
    owner = business.login(username)
    key, registered = enroll(owner)
    listed = owner.request("GET", "/api/security/passkeys").json()
    assert listed["passkeys"] == [registered]
    assert listed["max_credentials"] == 8
    client = business.client()
    ceremony = login_options(client)
    response = finish_login(client, ceremony, key.assertion(ceremony["options"]))
    assert response.status_code == 200 and response.json()["user"]["id"] == username
    assert client.get("/api/messages").status_code == 200
    counters = business.app.state.security_metrics.snapshot()["counters"]
    assert counters["passkey_registered"] == counters["passkey_login_succeeded"] == 1
    with business.db() as connection:
        hashed = token_hash(client.cookies[COOKIE_NAME])
        assert connection.execute("SELECT credential_id FROM session_passkey WHERE token_hash=?", (hashed,)).fetchone()[0] == key.identifier
        assert connection.execute("SELECT method FROM session_security WHERE token_hash=?", (hashed,)).fetchone()[0] == "passkey"
        assert connection.execute("SELECT 1 FROM session_mfa WHERE token_hash=?", (hashed,)).fetchone() is None


def test_password_guess_lockout_does_not_spend_or_block_passkey_login(business, monkeypatch):
    owner = business.login("admin")
    key, _ = enroll(owner)
    monkeypatch.setattr(auth_routes, "verify_password", lambda *args: False)
    attacker = business.client()
    for _ in range(auth_routes.ATTEMPT_LIMIT):
        assert attacker.post("/api/login", headers={"Origin": ORIGIN}, json={
            "username": "admin", "password": "wrong-disposable-password",
        }).status_code == 401
    assert attacker.post("/api/login", headers={"Origin": ORIGIN}, json={
        "username": "admin", "password": "wrong-disposable-password",
    }).status_code == 429
    client = business.client()
    ceremony = login_options(client)
    assert finish_login(client, ceremony, key.assertion(ceremony["options"])).status_code == 200


@pytest.mark.parametrize("change", ["origin", "rp", "challenge", "type", "uv", "up", "signature",
                                   "user_handle", "missing_handle", "raw_id", "cross_origin", "backup"])
def test_invalid_signed_assertions_fail_closed_and_consume_challenge(business, change):
    key, _ = enroll(business.login("alex"))
    client = business.client()
    ceremony = login_options(client)
    assert finish_login(client, ceremony, key.assertion(ceremony["options"], change=change)).status_code == 403
    assert finish_login(client, ceremony, key.assertion(ceremony["options"])).status_code == 403
    assert client.get("/api/messages").status_code == 401
    with business.db() as connection:
        assert connection.execute("SELECT COUNT(*) FROM passkey_challenges").fetchone()[0] == 0
        assert connection.execute("SELECT sign_count,revision FROM passkey_credentials").fetchone()[:] == (0, 0)


def test_foreign_cookie_and_missing_csrf_cannot_consume_legitimate_login(business):
    key, _ = enroll(business.login("alex"))
    owner, foreign = business.client(), business.client()
    ceremony = login_options(owner)
    signed = key.assertion(ceremony["options"])
    assert finish_login(foreign, ceremony, signed).status_code == 403
    assert finish_login(owner, ceremony, signed, **{"X-Passkey-CSRF": "invalid"}).status_code == 403
    assert finish_login(owner, ceremony, signed).status_code == 200
    assert finish_login(owner, ceremony, signed).status_code == 403


def test_registration_requires_csrf_freshness_and_original_session(business):
    owner = business.login("alex")
    foreign = business.login("alex")
    assert owner.request("POST", "/api/security/passkeys/register/options", json={}, headers={"X-CSRF-Token": "invalid"}).status_code == 403
    ceremony = owner.request("POST", "/api/security/passkeys/register/options", json={}).json()
    payload = {"request_id": ceremony["request_id"], "credential": Authenticator().register(ceremony["options"]), "name": "Local key"}
    assert foreign.request("POST", "/api/security/passkeys/register/verify", json=payload).status_code == 403
    assert owner.request("POST", "/api/security/passkeys/register/verify", json=payload).status_code == 200
    with business.db() as connection:
        connection.execute("UPDATE session_security SET verified_at=0 WHERE token_hash=?", (token_hash(owner.client.cookies[COOKIE_NAME]),))
    response = owner.request("POST", "/api/security/passkeys/register/options", json={})
    assert response.status_code == 403 and response.headers["x-reauthentication-required"] == "true"


def test_expired_challenges_and_bounded_pending_storage(business, monkeypatch):
    key, _ = enroll(business.login("alex"))
    monkeypatch.setattr(passkeys, "MAX_LOGIN_CHALLENGES", 1)
    first, second = business.client(), business.client()
    ceremony = login_options(first)
    assert second.post("/api/passkeys/login/options", headers={"Origin": ORIGIN}, json={}).status_code == 429
    moment = passkeys.current_time()
    monkeypatch.setattr(passkeys, "current_time", lambda: moment + passkeys.CHALLENGE_SECONDS + 1)
    assert finish_login(first, ceremony, key.assertion(ceremony["options"])).status_code == 403
    assert login_options(second)
    with business.db() as connection:
        assert connection.execute("SELECT COUNT(*) FROM passkey_challenges").fetchone()[0] == 1


def test_passkey_removal_revokes_bound_sessions_and_cannot_remove_another_accounts_key(business):
    owner = business.login("alex")
    other = business.login("blair")
    key, registered = enroll(owner)
    client = business.client()
    ceremony = login_options(client)
    assert finish_login(client, ceremony, key.assertion(ceremony["options"])).status_code == 200
    path = f"/api/security/passkeys/{registered['id']}/remove"
    assert other.request("POST", path, json={}).status_code == 404
    response = owner.request("POST", path, json={})
    assert response.status_code == 200 and response.json()["current_session_revoked"] is False
    assert client.get("/api/messages").status_code == 401
    ceremony = login_options(client)
    assert finish_login(client, ceremony, key.assertion(ceremony["options"], counter=2)).status_code == 403


def test_passkey_reverification_refreshes_only_its_session_and_removal_of_current_key_revokes_it(business):
    owner = business.login("admin")
    key, registered = enroll(owner)
    with business.db() as connection:
        connection.execute("UPDATE session_security SET verified_at=0")
    ceremony = owner.request("POST", "/api/security/passkeys/reauth/options", json={}).json()
    response = owner.request("POST", "/api/security/passkeys/reauth/verify", json={
        "request_id": ceremony["request_id"], "credential": key.assertion(ceremony["options"]),
    })
    assert response.status_code == 200 and response.json()["verification_expires_at"] > passkeys.current_time()
    response = owner.request("POST", f"/api/security/passkeys/{registered['id']}/remove", json={})
    assert response.status_code == 200 and response.json()["current_session_revoked"] is True
    assert owner.request("GET", "/api/messages").status_code == 401


def test_another_accounts_valid_key_cannot_reverify_a_stolen_session(business):
    admin = business.login("admin")
    enroll(admin)
    employee_key, _ = enroll(business.login("alex"))
    with business.db() as connection:
        connection.execute("UPDATE session_security SET verified_at=0 WHERE token_hash=?", (token_hash(admin.client.cookies[COOKIE_NAME]),))
    ceremony = admin.request("POST", "/api/security/passkeys/reauth/options", json={}).json()
    response = admin.request("POST", "/api/security/passkeys/reauth/verify", json={
        "request_id": ceremony["request_id"], "credential": employee_key.assertion(ceremony["options"]),
    })
    assert response.status_code == 403
    with business.db() as connection:
        assert connection.execute("SELECT verified_at FROM session_security WHERE token_hash=?",
                                  (token_hash(admin.client.cookies[COOKIE_NAME]),)).fetchone()[0] == 0


@pytest.mark.parametrize("change", ["disabled", "password-changed", "credential-removed"])
def test_account_or_credential_change_during_signature_verification_prevents_new_session(business, monkeypatch, change):
    key, _ = enroll(business.login("alex"))
    original = passkeys._assertion

    def change_after_crypto(*args, **kwargs):
        result = original(*args, **kwargs)
        with business.db() as connection:
            connection.execute({
                "disabled": "UPDATE users SET active=0,revision=revision+1 WHERE id='alex'",
                "password-changed": "UPDATE users SET password_hash='changed',revision=revision+1 WHERE id='alex'",
                "credential-removed": "DELETE FROM passkey_credentials",
            }[change])
        return result

    monkeypatch.setattr(passkeys, "_assertion", change_after_crypto)
    client = business.client()
    ceremony = login_options(client)
    assert finish_login(client, ceremony, key.assertion(ceremony["options"])).status_code == 403
    assert COOKIE_NAME not in client.cookies


def test_revoked_enrollment_session_cannot_add_a_key_after_crypto(business, monkeypatch):
    owner = business.login("admin")
    ceremony = owner.request("POST", "/api/security/passkeys/register/options", json={}).json()
    original = passkeys._registration

    def revoke_after_crypto(*args):
        result = original(*args)
        with business.db() as connection:
            connection.execute("DELETE FROM sessions")
        return result

    monkeypatch.setattr(passkeys, "_registration", revoke_after_crypto)
    assert owner.request("POST", "/api/security/passkeys/register/verify", json={
        "request_id": ceremony["request_id"], "credential": Authenticator().register(ceremony["options"]), "name": "Revoked key",
    }).status_code == 401
    with business.db() as connection:
        assert connection.execute("SELECT COUNT(*) FROM passkey_credentials").fetchone()[0] == 0


def test_enrollment_challenge_expiring_during_verification_cannot_add_a_key(business, monkeypatch):
    owner = business.login("alex")
    ceremony = owner.request("POST", "/api/security/passkeys/register/options", json={}).json()
    original = passkeys._registration
    moment = passkeys.current_time()

    def expire_after_crypto(*args):
        result = original(*args)
        monkeypatch.setattr(passkeys, "current_time", lambda: moment + passkeys.CHALLENGE_SECONDS + 1)
        return result

    monkeypatch.setattr(passkeys, "_registration", expire_after_crypto)
    assert owner.request("POST", "/api/security/passkeys/register/verify", json={
        "request_id": ceremony["request_id"], "credential": Authenticator().register(ceremony["options"]), "name": "Expired key",
    }).status_code == 403
    assert owner.request("GET", "/api/security/passkeys").json()["passkeys"] == []


def test_syncable_counter_zero_is_accepted_but_concurrent_credential_updates_compare_revision(business, monkeypatch):
    key, _ = enroll(business.login("alex"), Authenticator(synced=True))
    clients = [business.client(), business.client()]
    ceremonies = [login_options(client) for client in clients]
    original = passkeys._assertion
    arrived = Barrier(2)

    def together(*args, **kwargs):
        result = original(*args, **kwargs)
        arrived.wait(timeout=5)
        return result

    monkeypatch.setattr(passkeys, "_assertion", together)
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(finish_login, client, ceremony, key.assertion(ceremony["options"], counter=0))
                   for client, ceremony in zip(clients, ceremonies)]
        assert sorted(future.result(timeout=10).status_code for future in futures) == [200, 403]
    monkeypatch.setattr(passkeys, "_assertion", original)
    client = business.client()
    ceremony = login_options(client)
    assert finish_login(client, ceremony, key.assertion(ceremony["options"], counter=0)).status_code == 200


def test_device_bound_counter_regression_and_missing_session_attestation_are_rejected(business):
    key, _ = enroll(business.login("admin"))
    client = business.client()
    ceremony = login_options(client)
    assert finish_login(client, ceremony, key.assertion(ceremony["options"], counter=2)).status_code == 200
    ceremony = login_options(client)
    assert finish_login(client, ceremony, key.assertion(ceremony["options"], counter=1)).status_code == 403
    with business.db() as connection:
        connection.execute("DELETE FROM session_passkey WHERE token_hash=?", (token_hash(client.cookies[COOKIE_NAME]),))
    assert client.get("/api/admin/overview").status_code == 401


@pytest.mark.parametrize("change", ["uv", "signature"])
def test_invalid_registration_cannot_be_replayed_with_a_valid_response(business, change):
    owner = business.login("alex")
    ceremony = owner.request("POST", "/api/security/passkeys/register/options", json={}).json()
    key = Authenticator()
    credential = key.register(ceremony["options"], uv=change != "uv")
    if change == "signature":
        attestation = cbor2.loads(base64url_to_bytes(credential["response"]["attestationObject"]))
        signature = attestation["attStmt"]["sig"]
        attestation["attStmt"]["sig"] = signature[:-1] + bytes([signature[-1] ^ 1])
        credential["response"]["attestationObject"] = bytes_to_base64url(cbor2.dumps(attestation))
    payload = {"request_id": ceremony["request_id"], "credential": credential, "name": "Invalid local key"}
    assert owner.request("POST", "/api/security/passkeys/register/verify", json=payload).status_code == 403
    payload["credential"] = key.register(ceremony["options"])
    assert owner.request("POST", "/api/security/passkeys/register/verify", json=payload).status_code == 403
    assert owner.request("GET", "/api/security/passkeys").json()["passkeys"] == []


def test_purpose_binding_and_credential_capacity_preserve_existing_key(business, monkeypatch):
    owner = business.login("alex")
    ceremony = owner.request("POST", "/api/security/passkeys/register/options", json={}).json()
    key = Authenticator()
    credential = key.register(ceremony["options"])
    assert owner.request("POST", "/api/security/passkeys/reauth/verify", json={
        "request_id": ceremony["request_id"], "credential": credential,
    }).status_code == 403
    assert owner.request("POST", "/api/security/passkeys/register/verify", json={
        "request_id": ceremony["request_id"], "credential": credential, "name": "First local key",
    }).status_code == 200
    monkeypatch.setattr(passkeys, "MAX_CREDENTIALS", 1)
    assert owner.request("POST", "/api/security/passkeys/register/options", json={}).status_code == 409
    assert len(owner.request("GET", "/api/security/passkeys").json()["passkeys"]) == 1
    counters = business.app.state.security_metrics.snapshot()["counters"]
    assert counters["passkey_credential_capacity_denied"] == 1


def test_passkey_option_work_and_verification_work_are_bounded_and_observable(business, monkeypatch):
    key, _ = enroll(business.login("alex"))
    clients = [business.client() for _ in range(3)]
    original_options = passkeys.generate_authentication_options
    arrived, release = Barrier(3), Event()

    def held_options(*args, **kwargs):
        arrived.wait(timeout=5)
        assert release.wait(timeout=10)
        return original_options(*args, **kwargs)

    monkeypatch.setattr(passkeys, "generate_authentication_options", held_options)
    with ThreadPoolExecutor(max_workers=2) as executor:
        pending = [executor.submit(login_options, client) for client in clients[:2]]
        try:
            arrived.wait(timeout=5)
            response = clients[2].post("/api/passkeys/login/options", headers={"Origin": ORIGIN}, json={})
            assert response.status_code == 429 and response.headers["retry-after"] == "1"
            assert business.client().get("/healthz").status_code == 200
        finally:
            release.set()
        ceremonies = [future.result(timeout=5) for future in pending]
    monkeypatch.setattr(passkeys, "generate_authentication_options", original_options)
    ceremonies.append(login_options(clients[2]))
    original_assertion = passkeys._assertion
    arrived, release = Barrier(3), Event()

    def held_assertion(*args, **kwargs):
        result = original_assertion(*args, **kwargs)
        arrived.wait(timeout=5)
        assert release.wait(timeout=10)
        return result

    monkeypatch.setattr(passkeys, "_assertion", held_assertion)
    with ThreadPoolExecutor(max_workers=2) as executor:
        pending = [executor.submit(finish_login, client, ceremony, key.assertion(ceremony["options"], counter=index + 1))
                   for index, (client, ceremony) in enumerate(zip(clients[:2], ceremonies[:2]))]
        try:
            arrived.wait(timeout=5)
            third = key.assertion(ceremonies[2]["options"], counter=3)
            response = finish_login(clients[2], ceremonies[2], third)
            assert response.status_code == 429 and response.headers["retry-after"] == "1"
        finally:
            release.set()
        assert sorted(future.result(timeout=5).status_code for future in pending) == [200, 403]
    monkeypatch.setattr(passkeys, "_assertion", original_assertion)
    assert finish_login(clients[2], ceremonies[2], third).status_code == 200
    counters = business.app.state.security_metrics.snapshot()["counters"]
    assert counters["passkey_options_busy"] == counters["passkey_verification_busy"] == 1
