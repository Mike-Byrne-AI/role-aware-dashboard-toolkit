"""Disposable three-process TLS collector proof; no external destination input.

The source is a delivery worker, not a business HTTPS server. All credentials,
keys, databases and child logs stay in a new private directory outside source.
Lost acknowledgement is injected after actual HTTPS receiver commitment.
"""

from __future__ import annotations

# Refuse before dependency imports or runtime setup can begin.
if not __debug__:
    raise SystemExit("Collector evidence requires assertions; do not use optimized Python.")

import argparse
import asyncio
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import ipaddress
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import subprocess
import sys
import time
import traceback
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
for _path in (ROOT, ROOT / "examples/business_dashboard", ROOT / "examples/security_event_collector"):
    sys.path.insert(0, str(_path))

CHECKS = (
    "three_process_tls_delivery", "lost_ack_exact_retry", "immutable_duplicate_conflict",
    "restart_receipt_and_heartbeat_replay", "missing_heartbeat_independent",
    "backlog_alert_and_inbox_recovery", "arrival_separate_operator_ack",
    "source_current_authority_restore", "collector_restore_quarantine", "processes_stopped", "source_unchanged",
)
LIMITATIONS = ("local_computer_only", "source_worker_not_business_https_server", "no_off_host_custody_proof",
               "no_human_attention_proof", "source_ack_loss_simulation", "short_fixture_timing")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")


def clean_environment(environment):
    blocked = {"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "SSL_CERT_FILE", "SSL_CERT_DIR",
               "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"}
    result = {key: value for key, value in environment.items()
              if not key.upper().startswith(("BUSINESS_", "PYTHON")) and key.upper() not in blocked}
    result.update(PYTHONDONTWRITEBYTECODE="1", PYTHONNOUSERSITE="1")
    return result


@contextmanager
def isolated_host_settings():
    saved = {key: value for key, value in os.environ.items() if key.upper().startswith("BUSINESS_")}
    try:
        for key in saved:
            os.environ.pop(key)
        yield
    finally:
        os.environ.update(saved)


def new_output(path):
    from collector.private_files import private_directory
    return private_directory(path, create=True)


def write_private(path, data):
    from collector.private_files import write_private as write
    write(path, data)


def pace_intake(namespace):
    # Refill one token before EVERY manual request, including the first after
    # worker shutdown or receiver restart. Their durable quota may be empty.
    # Rates are 1/s for heartbeat/operator and 10/s for events; leave a margin.
    interval = {"heartbeat": 1.05, "operator": 1.05, "events": 0.11}[namespace]
    deadline = time.monotonic() + interval
    while (remaining := deadline - time.monotonic()) > 0:
        time.sleep(remaining)


def poll(predicate, *, timeout=30, processes=()):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if any(process.process.poll() is not None for process in processes):
            raise RuntimeError("An owned process stopped before its acceptance boundary.")
        result = predicate()
        if result:
            return result
        time.sleep(0.2)
    raise TimeoutError("A bounded local acceptance condition did not complete.")


class ReservedPorts:
    def __init__(self):
        self.sockets = []
        for _ in range(2):
            item = socket.socket()
            item.bind(("127.0.0.1", 0))
            self.sockets.append(item)
        self.ports = tuple(item.getsockname()[1] for item in self.sockets)

    def release(self, index):
        self.sockets[index].close()

    def close(self):
        for item in self.sockets:
            item.close()


class OwnedProcess:
    def __init__(self, command, log, *, graceful=False):
        self.graceful = graceful
        write_private(log, b"")
        self.log = log.open("ab")
        try:
            self.process = subprocess.Popen(command, cwd=ROOT, env=clean_environment(os.environ),
                                            stdin=subprocess.PIPE if graceful else subprocess.DEVNULL,
                                            stdout=self.log, stderr=subprocess.STDOUT,
                                            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        except BaseException:
            self.log.close()
            raise

    def stop(self):
        try:
            if self.process.poll() is None and self.graceful:
                try:
                    self.process.stdin.write(b"stop\n")
                    self.process.stdin.flush()
                except (BrokenPipeError, OSError):
                    pass  # The child may have exited before the stop command.
                try:
                    self.process.wait(timeout=12)
                except subprocess.TimeoutExpired:
                    self.process.terminate()
            elif self.process.poll() is None:
                self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
            if self.graceful and self.process.returncode != 0:
                raise RuntimeError("The owned source worker did not stop successfully.")
        finally:
            if self.process.stdin:
                self.process.stdin.close()
            self.log.close()


def make_tls(output):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Disposable local collector drill")])
    now = datetime.now(timezone.utc)
    certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                   .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1))
                   .not_valid_after(now + timedelta(days=1))
                   .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                   .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
                   .sign(key, hashes.SHA256()))
    cert, private_key = output / "tls-ca.pem", output / "tls-key.pem"
    write_private(cert, certificate.public_bytes(serialization.Encoding.PEM))
    write_private(private_key, key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                               serialization.NoEncryption()))
    return cert, private_key


def source_worker(configuration):
    """Internal child entry; only a parent-created disposable manifest is valid."""
    from business.db import Database
    from business.event_remote import RemoteSecurityEventDispatcher
    from business.secret_store import default_key_path
    from collector.private_files import check_private_file, private_directory

    configuration = check_private_file(configuration)
    output = private_directory(configuration.parent)
    value = json.loads(configuration.read_bytes())
    assert set(value) == {"v", "run_id", "generation"} and value["v"] == 1
    marker = json.loads(check_private_file(output / "drill-marker.json").read_bytes())
    assert marker == {"v": 1, "run_id": value["run_id"], "scope": "disposable_collector_drill"}
    generation = value["generation"]
    assert type(generation) is int and 1 <= generation <= 10
    assert configuration.name == f"source-worker-{generation}.json"
    database = Database(output / "source", mfa_key_file=default_key_path(output / "source"))
    dispatcher = RemoteSecurityEventDispatcher(database, config_file=output / "delivery.json",
                                              interval=0.5, heartbeat_interval=2.0, batch_limit=5)
    assert Path(sys.modules[Database.__module__].__file__).resolve().is_relative_to(ROOT)
    dispatcher.start()
    try:
        write_private(output / f"source-ready-{generation}.json", canonical({"ready": True, "pid": os.getpid()}))
        assert sys.stdin.readline().strip() == "stop"
    finally:
        dispatcher.stop()
    assert not dispatcher.snapshot()["running"]
    return 0


class Drill:
    def __init__(self, output, run_id, checks):
        self.output, self.run_id, self.checks = output, run_id, checks
        self.processes, self.generation, self.server_generations = [], 0, {}
        self.ports = ReservedPorts()
        try:
            self.cert, self.key = make_tls(output)
        except BaseException:
            self.ports.close()
            raise
        self.collector_url, self.inbox_url = (f"https://127.0.0.1:{port}" for port in self.ports.ports)

    def start_server(self, name):
        index = 0 if name == "collector" else 1
        self.ports.release(index)
        count = self.server_generations.get(name, 0) + 1
        self.server_generations[name] = count
        args = [sys.executable, "-B", str(ROOT / "examples/security_event_collector/run.py"), "serve",
                str(self.output / name), "--port", str(self.ports.ports[index]), "--tls-cert", str(self.cert),
                "--tls-key", str(self.key)]
        if name == "collector":
            args.extend(("--inbox-token-file", str(self.output / "inbox-writer.token"), "--inbox-ca-file", str(self.cert)))
        process = OwnedProcess(args, self.output / f"{name}-{count}.log")
        self.processes.append(process)
        import httpx
        url = self.collector_url if name == "collector" else self.inbox_url
        def ready():
            try:
                return self.request("GET", url + "/healthz").status_code == 200
            except (httpx.HTTPError, OSError):
                return False  # A refused connection is expected during owned startup.
        poll(ready, processes=(process,))
        return process

    def start_source(self):
        self.generation += 1
        config = self.output / f"source-worker-{self.generation}.json"
        write_private(config, canonical({"v": 1, "run_id": self.run_id, "generation": self.generation}))
        process = OwnedProcess([sys.executable, "-B", str(Path(__file__).resolve()), "--_source-config", str(config)],
                               self.output / f"source-{self.generation}.log", graceful=True)
        self.processes.append(process)
        poll(lambda: (self.output / f"source-ready-{self.generation}.json").is_file(), processes=(process,))
        return process

    def request(self, method, url, *, token=None, data=None):
        import httpx
        headers = {"Accept": "application/json", "Accept-Encoding": "identity"}
        if token:
            headers["Authorization"] = "Bearer " + token
        if data is not None:
            headers["Content-Type"] = "application/json"
        context = ssl.create_default_context(cafile=str(self.cert))
        if urlsplit(url).path.startswith("/v1/operator/"):
            pace_intake("operator")
        with httpx.Client(verify=context, trust_env=False, follow_redirects=False, timeout=5) as client:
            return client.request(method, url, headers=headers, content=data)

    def post(self, transport, data, *, heartbeat=False):
        if any(process.graceful and process.process.poll() is None for process in self.processes):
            raise RuntimeError("Stop the owned source worker before manual intake checks.")
        pace_intake("heartbeat" if heartbeat else "events")
        # Exactly one send. An unexpected response consumes and fails this run;
        # Retry-After never causes this acceptance driver to replay a request.
        return asyncio.run(transport.post(data, heartbeat=heartbeat))

    def passed(self, name):
        assert name in self.checks and self.checks[name] == "not_run"
        self.checks[name] = "passed"

    def close(self):
        errors = []
        for process in reversed(self.processes):
            try:
                process.stop()
            except (OSError, RuntimeError, subprocess.SubprocessError):
                errors.append(True)
        self.ports.close()
        if errors or any(process.process.poll() is None for process in self.processes):
            raise RuntimeError("An owned drill process could not be reaped.")
        self.passed("processes_stopped")

    def exercise(self):
        import backup
        from business.db import Database
        from business.event_config import load_delivery_configuration
        from business.event_destinations import DestinationDescriptor, allocate_heartbeat, destination_status, enable_remote_destination, source_identity
        from business.event_dispatch import acknowledge_event, prepare_event_batch
        from business.event_wire import load_transport, wire
        from business.secret_store import default_key_path
        from business.security_events import record_event
        from collector.app import create_app
        from collector.custody import create_backup, restore_quarantined
        from collector.service import Collector
        from collector.storage import provision
        from tools.business_dashboard_browser import prepare_fixture

        runtime = self.output / "source"
        with isolated_host_settings():
            _, app = prepare_fixture(runtime, "http://127.0.0.1:8091")
        database = app.state.database
        backup.create_backup(runtime, self.output / "source-backup", mfa_key_file=default_key_path(runtime))
        with database.readonly_snapshot() as connection:
            source_id = source_identity(connection)["source_id"]
        collector_id, inbox_id, destination_id, alert_destination = (secrets.token_hex(16) for _ in range(4))
        inbox = provision(self.output / "inbox", kind="inbox", source_id=source_id, destination_id=alert_destination,
                          service_id=inbox_id, peer_id=collector_id)
        receiver = provision(self.output / "collector", kind="collector", source_id=source_id, destination_id=destination_id,
                             service_id=collector_id, inbox_id=inbox_id, alert_destination_id=alert_destination,
                             alert_endpoint=self.inbox_url + "/v1/alerts", heartbeat_timeout=4, backlog_threshold=2)
        write_private(self.output / "source-writer.token", (receiver.ingest_token + "\n").encode("ascii"))
        write_private(self.output / "inbox-writer.token", (inbox.ingest_token + "\n").encode("ascii"))
        descriptor = DestinationDescriptor(destination_id, collector_id, self.collector_url + "/v1/events")
        write_private(self.output / "delivery.json", canonical({"v": 1, "source_id": source_id, "collector_id": collector_id,
                      "destination_id": destination_id, "endpoint": descriptor.endpoint,
                      "token_file": str(self.output / "source-writer.token"), "ca_file": str(self.cert)}))
        config = load_delivery_configuration(self.output / "delivery.json", source_id=source_id, descriptor=descriptor)
        with database.transaction() as connection:
            enable_remote_destination(connection, descriptor)
        collector = self.start_server("collector")
        source = self.start_source()
        service = Collector(self.output / "collector")
        def drained():
            with database.readonly_snapshot() as connection:
                return destination_status(connection, destination_id)["pending"] == 0
        poll(drained, timeout=45, processes=(collector, source))
        with database.readonly_snapshot() as connection, service.store.read() as received:
            assert received.execute("SELECT COUNT(*) FROM events").fetchone()[0] == connection.execute("SELECT COUNT(*) FROM security_events").fetchone()[0]
        source.stop()

        # Actual HTTPS commit; deliberately omit only the source acknowledgement.
        with database.transaction() as connection:
            event_id = record_event(connection, "editing_paused")
            attempt, = prepare_event_batch(connection, destination_id)
        original_receipt = self.post(config.transport, attempt.request)
        wire.parse_event_receipt(original_receipt, attempt.expected_receipt)
        with database.transaction() as connection:
            assert destination_status(connection, destination_id)["pending"] == 1
            retry, = prepare_event_batch(connection, destination_id)
        assert retry.request == attempt.request and retry.event_id == event_id
        write_private(self.output / "lost-ack-request.bin", attempt.request)
        write_private(self.output / "lost-ack-receipt.bin", original_receipt)
        source = self.start_source()
        poll(drained, processes=(collector, source))
        source.stop()
        with service.store.read() as connection:
            accepted = connection.execute("SELECT * FROM events WHERE event_id=?", (event_id,)).fetchone()
            assert accepted is not None
        self.passed("lost_ack_exact_retry")
        assert self.post(config.transport, attempt.request) == original_receipt
        payload = wire.parse_event_request(attempt.request, {"collector_id": collector_id, "destination_id": destination_id, "source_id": source_id}).payload_fields
        payload["event"]["method"] = "password"
        conflict = wire.event_request(collector_id, destination_id, "live", wire.freeze_event(source_id, payload["event"]))
        try:
            self.post(config.transport, conflict)
        except load_transport().DeliveryFailure as error:
            assert error.code == "remote_conflict"
        else:
            raise AssertionError("A conflicting event identity was accepted.")
        with service.store.read() as connection:
            assert dict(connection.execute("SELECT * FROM events WHERE event_id=?", (event_id,)).fetchone()) == dict(accepted)
        self.passed("immutable_duplicate_conflict")

        with database.transaction() as connection:
            heartbeat = allocate_heartbeat(connection, destination_id)
        heartbeat_receipt = self.post(config.transport, heartbeat.data, heartbeat=True)
        heartbeat_fields = json.loads(heartbeat.data)
        expected_heartbeat = {key: heartbeat_fields[key] for key in ("collector_id", "destination_id", "source_id", "sequence")}
        wire.parse_heartbeat_receipt(heartbeat_receipt, {**expected_heartbeat, "sha256": heartbeat.sha256})
        collector.stop()
        collector = self.start_server("collector")
        assert self.post(config.transport, attempt.request) == original_receipt
        assert self.post(config.transport, heartbeat.data, heartbeat=True) == heartbeat_receipt
        heartbeat_fields["retained_events"] += 1
        try:
            self.post(config.transport, wire.heartbeat_request(heartbeat_fields).data, heartbeat=True)
        except load_transport().DeliveryFailure as error:
            assert error.code == "remote_conflict"
        else:
            raise AssertionError("A conflicting heartbeat replay was accepted.")
        heartbeat_fields["sequence"] -= 1
        try:
            self.post(config.transport, wire.heartbeat_request(heartbeat_fields).data, heartbeat=True)
        except load_transport().DeliveryFailure as error:
            assert error.code == "remote_conflict"
        else:
            raise AssertionError("A lower heartbeat sequence was accepted.")
        self.passed("restart_receipt_and_heartbeat_replay")

        # Replay pacing can cross the short fixture deadline. Begin the health
        # traffic proof from a newly accepted heartbeat and a closed condition.
        with database.transaction() as connection:
            heartbeat = allocate_heartbeat(connection, destination_id)
        heartbeat_receipt = self.post(config.transport, heartbeat.data, heartbeat=True)
        expected_heartbeat["sequence"] = json.loads(heartbeat.data)["sequence"]
        wire.parse_heartbeat_receipt(heartbeat_receipt, {**expected_heartbeat, "sha256": heartbeat.sha256})
        with service.store.read() as connection:
            assert not connection.execute("SELECT 1 FROM alert_cases WHERE rule='source_missing' AND condition_open=1").fetchone()

        def missing_with_health_traffic():
            assert self.request("GET", self.collector_url + "/healthz").status_code == 200
            with service.store.read() as connection:
                return connection.execute("SELECT 1 FROM alert_cases WHERE rule='source_missing' AND condition_open=1").fetchone()
        poll(missing_with_health_traffic, timeout=20, processes=(collector,))
        with service.store.read() as connection:
            assert bytes(connection.execute("SELECT receipt FROM heartbeats WHERE source_id=?", (source_id,)).fetchone()[0]) == heartbeat_receipt
        self.passed("missing_heartbeat_independent")
        with database.transaction() as connection:
            record_event(connection, "editing_resumed")
        time.sleep(2.2)  # Real enqueue age crosses this fixture's two-second policy.
        with database.transaction() as connection:
            backlog_heartbeat = allocate_heartbeat(connection, destination_id)
        self.post(config.transport, backlog_heartbeat.data, heartbeat=True)
        with service.store.read() as connection:
            assert connection.execute("SELECT 1 FROM alert_cases WHERE rule='source_backlog' AND condition_open=1").fetchone()
            assert connection.execute("SELECT COUNT(*) FROM alert_outbox WHERE acknowledged_at IS NULL").fetchone()[0] > 0
        inbox_process = self.start_server("inbox")
        source = self.start_source()
        assert all(item.process.poll() is None for item in (collector, inbox_process, source))
        poll(drained, timeout=30, processes=(collector, inbox_process, source))
        self.passed("three_process_tls_delivery")
        def notifications_drained():
            with service.store.read() as connection:
                return connection.execute("SELECT COUNT(*) FROM alert_outbox WHERE acknowledged_at IS NULL").fetchone()[0] == 0
        poll(notifications_drained, timeout=60, processes=(collector, inbox_process, source))
        self.passed("backlog_alert_and_inbox_recovery")
        response = self.request("GET", self.inbox_url + "/v1/operator/messages", token=inbox.operator_token)
        assert response.status_code == 200
        messages = response.json()["messages"]
        assert messages and all(item["acknowledged_at"] is None for item in messages)
        message = next(item for item in messages if json.loads(item["payload"])["rule"] == "source_backlog")
        ack_url = self.inbox_url + f"/v1/operator/messages/{collector_id}/{message['alert_id']}/ack"
        ack_body = canonical({"number": message["number"]})
        assert self.request("POST", ack_url, token=inbox.ingest_token, data=ack_body).status_code == 401
        assert self.request("POST", ack_url, token=inbox.operator_token, data=ack_body).status_code == 200
        updated = self.request("GET", self.inbox_url + "/v1/operator/messages", token=inbox.operator_token)
        assert updated.status_code == 200
        assert sum(item["acknowledged_at"] is not None for item in updated.json()["messages"]) == 1
        self.passed("arrival_separate_operator_ack")
        source.stop()

        # Current authority, including a committed-but-unacknowledged event, wins
        # over the historical source backup without reserializing its payload.
        with database.transaction() as connection:
            record_event(connection, "editing_paused")
            recovery_attempt, = prepare_event_batch(connection, destination_id)
        recovery_receipt = self.post(config.transport, recovery_attempt.request)
        tables = ("security_delivery_identity", "security_destinations", "security_events", "security_event_payloads",
                  "security_delivery_obligations", "security_sink_receipts", "security_denial_budget")
        with database.readonly_snapshot() as connection:
            original = {table: [tuple(row) for row in connection.execute(f"SELECT * FROM {table} ORDER BY rowid")] for table in tables}
            highwater = source_identity(connection)["heartbeat_sequence"]
            event_sequence = connection.execute("SELECT seq FROM sqlite_sequence WHERE name='security_events'").fetchone()[0]
        result = backup.restore_backup(self.output / "source-backup", self.output / "source-restored",
                                       security_source=runtime, mfa_key_file=default_key_path(runtime))
        assert result == {"quarantined": False, "sessions_revoked": True, "frozen": True}
        recovered = Database(self.output / "source-restored", mfa_key_file=default_key_path(runtime))
        with recovered.transaction() as connection:
            assert {table: [tuple(row) for row in connection.execute(f"SELECT * FROM {table} ORDER BY rowid")] for table in tables} == original
            assert connection.execute("SELECT seq FROM sqlite_sequence WHERE name='security_events'").fetchone()[0] == event_sequence
            restored_heartbeat = allocate_heartbeat(connection, destination_id)
            recovered_attempt, = prepare_event_batch(connection, destination_id)
        assert json.loads(restored_heartbeat.data)["sequence"] == highwater + 1
        assert recovered_attempt.request == recovery_attempt.request
        assert self.post(config.transport, recovered_attempt.request) == recovery_receipt
        with recovered.transaction() as connection:
            assert acknowledge_event(connection, recovered_attempt, recovery_receipt)
        self.post(config.transport, restored_heartbeat.data, heartbeat=True)
        self.passed("source_current_authority_restore")
        collector.stop()
        create_backup(self.output / "collector", self.output / "collector-backup")
        restore_quarantined(self.output / "collector-backup", self.output / "collector-restored")
        assert (self.output / "collector-restored/RESTORE_QUARANTINE").is_file()
        try:
            create_app(self.output / "collector-restored")
        except ValueError:
            pass
        else:
            raise AssertionError("A quarantined collector restore could serve.")
        self.passed("collector_restore_quarantine")


def run(output):
    from business.evidence import source_fingerprint
    import role_aware_dashboard_toolkit
    assert Path(role_aware_dashboard_toolkit.__file__).resolve().is_relative_to(ROOT)
    output = new_output(output)
    run_id = secrets.token_hex(16)
    write_private(output / "drill-marker.json", canonical({"v": 1, "run_id": run_id, "scope": "disposable_collector_drill"}))
    before = source_fingerprint(ROOT)
    checks = {name: "not_run" for name in CHECKS}
    receipt = {"v": 1, "scope": "local_three_process_tls_reference", "status": "failed",
               "source_before": before, "source_after": None, "checks": checks, "limitations": list(LIMITATIONS), "error": None}
    write_private(output / "started.json", canonical(receipt) + b"\n")
    drill = None
    try:
        drill = Drill(output, run_id, checks)
        drill.exercise()
    except BaseException as error:
        receipt["error"] = "interrupted" if isinstance(error, (KeyboardInterrupt, SystemExit)) else "assertion_failed" if isinstance(error, AssertionError) else "execution_error"
        # Private diagnostic only; the exported receipt contains fixed codes.
        write_private(output / "failure.txt", traceback.format_exc().encode("utf-8"))
    finally:
        if drill:
            try:
                drill.close()
            except BaseException:
                receipt["error"] = "process_cleanup_failed"
        receipt["source_after"] = source_fingerprint(ROOT)
        if before == receipt["source_after"]:
            checks["source_unchanged"] = "passed"
        else:
            checks["source_unchanged"] = "failed"
            receipt["error"] = "source_changed"
        if receipt["error"] is None and all(value == "passed" for value in checks.values()):
            receipt["status"] = "passed"
        write_private(output / "receipt.json", canonical(receipt) + b"\n")
    return receipt


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument("--output-dir", type=Path, help="New private directory outside source; existing paths are refused.")
    selection.add_argument("--_source-config", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if args._source_config:
        return source_worker(args._source_config)
    try:
        receipt = run(args.output_dir)
    except (OSError, ValueError):
        print('{"status":"refused","error":"output_unavailable"}')
        return 1
    print(canonical(receipt).decode("ascii"))
    return 0 if receipt["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
