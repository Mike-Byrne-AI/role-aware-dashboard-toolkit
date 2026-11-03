"""Older operator work remains discoverable without unbounded list responses."""

import base64
import json

import pytest

from tests.test_security_event_collector import (
    COLLECTOR, INBOX, TestClient, create_app, event, wire,
    no_external_http as no_external_http, pair as pair, tmp_path as tmp_path,
)
from collector.pagination import decode_cursor, encode_cursor
from collector.storage import ServiceError, safe_json


def application(service, clock):
    app = create_app(service.store.directory, clock=lambda: clock[0], evaluator=False)
    app.notifier = None
    return app


def conflict(collector, issued, index):
    arguments = {"event_id": f"{index:032x}", "sequence": index}
    collector.ingest_event(issued.ingest_token, event(**arguments))
    with pytest.raises(ServiceError, match="identity_conflict"):
        collector.ingest_event(issued.ingest_token, event(actor="b" * 64, **arguments))


def deliver(collector, inbox, credentials):
    delivered = []
    while pending := collector.pending_alerts():
        for item in pending:
            attempt = collector.begin_alert_attempt(item.alert_id, item.number)
            receipt = inbox.ingest_alert(credentials.ingest_token, attempt.body)
            collector.ack_alert(item.alert_id, item.number, receipt)
            delivered.append(attempt)
    return delivered


def test_tied_records_beyond_100_remain_reachable_during_new_inserts_and_can_be_acknowledged(pair):
    collector, issued, inbox, inbox_issued, clock = pair
    for index in range(1, 108):
        conflict(collector, issued, index)
    deliveries = deliver(collector, inbox, inbox_issued)
    # Two collector identities may use the same alert ID/number and receipt
    # timestamp. The complete inbox primary key must break those ties.
    other_collector, other_destination = "0" * 32, "9" * 32
    other_token = inbox.store.register_channel(other_destination, peer_id=other_collector)
    fields = json.loads(base64.b64decode(json.loads(deliveries[0].body)["payload"]))
    fields["collector_id"] = other_collector
    inbox.ingest_alert(other_token, wire.alert_request(INBOX, other_destination, wire.freeze_alert(fields)))
    with collector.store.read() as connection:
        expected_cases = [row[0] for row in connection.execute("SELECT id FROM alert_cases ORDER BY created_at DESC,id")]
        assert connection.execute("SELECT COUNT(DISTINCT created_at) FROM alert_cases").fetchone()[0] == 1
    with inbox.store.read() as connection:
        expected_messages = [tuple(row) for row in connection.execute(
            "SELECT collector_id,alert_id,number FROM inbox_messages ORDER BY received_at DESC,collector_id,alert_id,number")]
        assert connection.execute("SELECT COUNT(DISTINCT received_at) FROM inbox_messages").fetchone()[0] == 1
    assert len(expected_cases) == 107 and len(expected_messages) == 108
    assert isinstance(collector.list_alerts(issued.operator_token), list)
    assert isinstance(inbox.list_messages(inbox_issued.operator_token), list)

    with TestClient(application(collector, clock)) as collector_client, TestClient(application(inbox, clock)) as inbox_client:
        def get(client, path, token):
            clock[0] += 1
            response = client.get(path, headers={"Authorization": "Bearer " + token})
            assert response.status_code == 200, response.text
            return response.json()

        contexts = ((collector_client, "alerts", issued.operator_token), (inbox_client, "messages", inbox_issued.operator_token))
        pages, all_rows = {}, {}
        for client, kind, token in contexts:
            default = get(client, "/v1/operator/" + kind, token)
            assert len(default[kind]) == 100 and default["next_cursor"] is not None
            pages[kind] = get(client, "/v1/operator/" + kind + "?limit=13", token)
            all_rows[kind] = list(pages[kind][kind])

        # Newer arrivals after the first page cannot push old records out of
        # this traversal. A fresh first page is how an operator discovers them.
        clock[0] += 1
        conflict(collector, issued, 999)
        deliver(collector, inbox, inbox_issued)
        for client, kind, token in contexts:
            seen_cursors = set()
            while cursor := pages[kind]["next_cursor"]:
                assert cursor not in seen_cursors
                seen_cursors.add(cursor)
                pages[kind] = get(client, "/v1/operator/" + kind + "?limit=13&cursor=" + cursor, token)
                assert len(pages[kind][kind]) <= 13
                all_rows[kind].extend(pages[kind][kind])
        assert [row["id"] for row in all_rows["alerts"]] == expected_cases
        assert [(row["collector_id"], row["alert_id"], row["number"]) for row in all_rows["messages"]] == expected_messages
        oldest_case, oldest_message = all_rows["alerts"][-1], all_rows["messages"][-1]
        assert oldest_case["condition_open"] == 1 and oldest_case["acknowledged"] == 0
        assert oldest_message["acknowledged_at"] is None
        for client, token, path, number in (
            (collector_client, issued.operator_token, f"/v1/operator/alerts/{oldest_case['id']}/ack", oldest_case["number"]),
            (inbox_client, inbox_issued.operator_token,
             f"/v1/operator/messages/{oldest_message['collector_id']}/{oldest_message['alert_id']}/ack", oldest_message["number"]),
        ):
            clock[0] += 1
            response = client.post(path, headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"},
                                   content=safe_json({"number": number}))
            assert response.status_code == 200
    with collector.store.read() as connection:
        row = connection.execute("SELECT condition_open,acknowledged FROM alert_cases WHERE id=?", (oldest_case["id"],)).fetchone()
        assert tuple(row) == (1, 1)
    with inbox.store.read() as connection:
        assert connection.execute("SELECT 1 FROM inbox_acknowledgements WHERE collector_id=? AND alert_id=? AND number=?",
                                  (oldest_message["collector_id"], oldest_message["alert_id"], oldest_message["number"])).fetchone()


@pytest.mark.parametrize("query", [
    "limit=0", "limit=101", "limit=999999999999999999999999", "limit=-1", "limit=1.0", "limit=true", "limit=01",
    "limit=1&limit=2", "unknown=1", "cursor=", "cursor=YQ==", "cursor=%59Q", "cursor=_", "cursor=" + "A" * 257,
    "cursor=YQ&cursor=YQ", "limit=1&", "limit=1=2",
])
def test_operator_pagination_rejects_noncanonical_unknown_duplicate_and_unbounded_queries(pair, query):
    collector, issued, _, _, clock = pair
    with TestClient(application(collector, clock)) as client:
        response = client.get("/v1/operator/alerts?" + query, headers={"Authorization": "Bearer " + issued.operator_token})
        assert response.status_code == 400
        assert response.json() == {"v": 1, "error": "invalid_message"}


def encoded(fields):
    raw = fields if isinstance(fields, bytes) else safe_json(fields)
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


@pytest.mark.parametrize("kind,fields", [
    ("alerts", {"v": True, "kind": "alerts", "id": "a" * 32}),
    ("alerts", {"v": 2, "kind": "alerts", "id": "a" * 32}),
    ("alerts", {"v": 1, "kind": "messages", "id": "a" * 32}),
    ("alerts", {"v": 1, "kind": "alerts", "id": "A" * 32}),
    ("alerts", {"v": 1, "kind": "alerts", "id": "a" * 32, "at": 0.0}),
    ("alerts", {"v": 1, "kind": "alerts"}),
    ("alerts", b'{"id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","kind":"alerts","v":1,"v":1}'),
    ("messages", {"v": 1, "kind": "messages", "collector_id": COLLECTOR, "alert_id": "a" * 32, "number": 2**63}),
    ("messages", {"v": 1, "kind": "messages", "collector_id": COLLECTOR, "alert_id": "a" * 32, "number": True}),
    ("messages", {"v": 1, "kind": "messages", "collector_id": COLLECTOR, "alert_id": "a" * 32, "number": 0}),
    ("messages", {"v": 1, "kind": "messages", "collector_id": COLLECTOR, "alert_id": "a" * 32, "number": 1.0}),
])
def test_cursor_schema_is_collection_bound_and_never_accepts_untrusted_time_or_integer_overflow(kind, fields):
    with pytest.raises(ServiceError) as error:
        decode_cursor(encoded(fields), kind)
    assert error.value.status == 400


@pytest.mark.parametrize("kind", ["alerts", "messages"])
def test_unknown_anchor_is_refused_and_ingest_cannot_read_any_page(pair, kind):
    collector, issued, inbox, inbox_issued, clock = pair
    service, credentials = (collector, issued) if kind == "alerts" else (inbox, inbox_issued)
    row = {"id": "a" * 32, "collector_id": COLLECTOR, "alert_id": "a" * 32, "number": 1}
    cursor = encode_cursor(kind, row)
    with TestClient(application(service, clock)) as client:
        path = "/v1/operator/" + kind + "?limit=100&cursor=" + cursor
        response = client.get(path, headers={"Authorization": "Bearer " + credentials.operator_token})
        assert response.status_code == 400
        for selected in (path, "/v1/operator/" + kind + "?limit=1"):
            clock[0] += 1
            response = client.get(selected, headers={"Authorization": "Bearer " + credentials.ingest_token})
            assert response.status_code == 401


@pytest.mark.parametrize("method,path", [
    ("GET", "/healthz"), ("GET", "/v1/operator/status"), ("GET", "/v1/operator/messages"),
    ("POST", "/v1/events"), ("POST", "/v1/heartbeat"), ("POST", "/v1/operator/alerts/" + "a" * 32 + "/ack"),
])
def test_queries_remain_forbidden_outside_the_matching_operator_get_collection(pair, method, path):
    collector, issued, _, _, clock = pair
    with TestClient(application(collector, clock)) as client:
        response = client.request(method, path + "?limit=1", headers={"Authorization": "Bearer " + issued.operator_token})
        assert response.status_code == 400


@pytest.mark.parametrize("limit", [True, 0, 101, 1.0, "1", 2**63])
def test_service_page_limits_are_bounded_without_changing_legacy_list_contract(pair, limit):
    collector, issued, inbox, inbox_issued, _ = pair
    for service, credentials, name in ((collector, issued, "page_alerts"), (inbox, inbox_issued, "page_messages")):
        with pytest.raises(ServiceError) as error:
            getattr(service, name)(credentials.operator_token, limit=limit)
        assert error.value.status == 400


def test_empty_pages_have_no_cursor_and_keep_collection_shape(pair):
    collector, issued, inbox, inbox_issued, _ = pair
    assert collector.page_alerts(issued.operator_token) == {"alerts": [], "next_cursor": None}
    assert inbox.page_messages(inbox_issued.operator_token) == {"messages": [], "next_cursor": None}
    assert collector.list_alerts(issued.operator_token) == inbox.list_messages(inbox_issued.operator_token) == []
