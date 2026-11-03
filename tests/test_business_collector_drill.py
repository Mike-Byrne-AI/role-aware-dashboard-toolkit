"""Harness admission and evidence boundaries; the CLI runs the actual TLS drill."""

import builtins
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

import pytest

from tools import business_collector_drill as drill


@pytest.fixture
def private_parent():
    # The standard repository basetemp deliberately lives inside source, where
    # runtime creation must remain refused even in a test.
    with tempfile.TemporaryDirectory(prefix="westbridge-collector-harness-") as path:
        # Canonicalize only this owned root (macOS temp paths traverse /var).
        root = Path(path).resolve(strict=True)
        if os.name != "nt":
            root.chmod(0o700)
        yield root


def test_environment_cannot_inherit_hosted_credentials_or_ambient_transport():
    supplied = {"BUSINESS_MFA_KEY_FILE": "private", "business_security_delivery_config": "private",
                "HTTP_PROXY": "private", "https_proxy": "private", "SSL_CERT_FILE": "private",
                "PYTHONPATH": "foreign", "PYTHONOPTIMIZE": "1", "PATH": "ordinary", "SystemRoot": "ordinary"}
    assert drill.clean_environment(supplied) == {"PATH": "ordinary", "SystemRoot": "ordinary",
                                              "PYTHONDONTWRITEBYTECODE": "1", "PYTHONNOUSERSITE": "1"}
    assert supplied["BUSINESS_MFA_KEY_FILE"] == "private"


def test_output_never_reuses_existing_storage_or_source_tree(private_parent):
    output = private_parent / "new"
    assert drill.new_output(output) == output
    marker = output / "preserve.txt"
    marker.write_text("preserve")
    with pytest.raises((ValueError, FileExistsError)):
        drill.new_output(output)
    with pytest.raises(ValueError):
        drill.new_output(drill.ROOT / "refused-collector-runtime")
    assert marker.read_text() == "preserve"
    assert not (drill.ROOT / "refused-collector-runtime").exists()


def test_two_ports_remain_distinct_and_reserved_until_release():
    import socket
    reservations = drill.ReservedPorts()
    try:
        assert len(set(reservations.ports)) == 2
        for port in reservations.ports:
            with socket.socket() as contender, pytest.raises(OSError):
                contender.bind(("127.0.0.1", port))
    finally:
        reservations.close()


def test_owned_process_cleanup_joins_actual_child_and_hides_no_output(private_parent):
    process = drill.OwnedProcess([sys.executable, "-B", "-c", "import time;time.sleep(30)"], private_parent / "child.log")
    assert process.process.poll() is None
    process.stop()
    process.stop()  # Nested cleanup may revisit an earlier explicitly stopped peer.
    assert process.process.poll() is not None
    assert process.log.closed


def test_failed_source_exit_does_not_skip_cleanup_of_other_owned_processes(private_parent):
    other = drill.OwnedProcess([sys.executable, "-B", "-c", "import time;time.sleep(30)"], private_parent / "other.log")
    failed = drill.OwnedProcess([sys.executable, "-B", "-c", "raise SystemExit(3)"], private_parent / "failed.log", graceful=True)
    failed.process.wait(timeout=5)
    fixture = object.__new__(drill.Drill)
    fixture.processes, fixture.ports = [other, failed], drill.ReservedPorts()
    fixture.checks = {name: "not_run" for name in drill.CHECKS}
    with pytest.raises(RuntimeError):
        fixture.close()
    assert other.process.poll() is not None and failed.process.poll() == 3
    assert fixture.checks["processes_stopped"] == "not_run"


def test_failed_drill_receipt_cannot_export_exception_secrets_or_claim_checks(private_parent, monkeypatch):
    from business import evidence
    fingerprint = {"sha256": "a" * 64, "files": 1, "git_commit": None, "dirty": None}
    monkeypatch.setattr(evidence, "source_fingerprint", lambda _root: fingerprint)
    def fail(self):
        raise ValueError("synthetic-private-token C:\\private\\runtime")
    monkeypatch.setattr(drill.Drill, "exercise", fail)
    result = drill.run(private_parent / "failed")
    encoded = drill.canonical(result)
    assert result["status"] == "failed" and result["error"] == "execution_error"
    assert b"synthetic-private-token" not in encoded and b"private" not in encoded
    assert result["checks"]["processes_stopped"] == "passed"
    assert result["checks"]["three_process_tls_delivery"] == "not_run"
    assert json.loads((private_parent / "failed/receipt.json").read_bytes()) == result
    assert (private_parent / "failed/failure.txt").is_file()


def test_changed_source_forces_failed_receipt_even_when_scenario_returns(private_parent, monkeypatch):
    from business import evidence
    fingerprints = iter({"sha256": char * 64, "files": 1, "git_commit": None, "dirty": None} for char in "ab")
    monkeypatch.setattr(evidence, "source_fingerprint", lambda _root: next(fingerprints))
    def complete(self):
        for check in drill.CHECKS[:-2]:
            self.passed(check)
    monkeypatch.setattr(drill.Drill, "exercise", complete)
    result = drill.run(private_parent / "changed")
    assert result["status"] == "failed" and result["error"] == "source_changed"
    assert result["checks"]["source_unchanged"] == "failed"


@pytest.mark.parametrize("optimization", [1, 2])
def test_optimized_runner_refuses_before_imports_or_runtime_access(optimization):
    path = Path(drill.__file__).resolve()
    source = path.read_text(encoding="utf-8")
    attempted = []

    def refuse_import(name, *args, **kwargs):
        if name == "__future__":
            return builtins.__import__(name, *args, **kwargs)
        attempted.append("import")
        pytest.fail(f"Optimized runner reached dependency import: {name}")

    def refuse_open(*args, **kwargs):
        attempted.append("file")
        pytest.fail("Optimized runner reached runtime file access")

    namespace = {"__name__": "__main__", "__file__": str(path),
                 "__builtins__": {**vars(builtins), "__import__": refuse_import, "open": refuse_open}}
    with pytest.raises(SystemExit, match="requires assertions"):
        exec(compile(source, str(path), "exec", optimize=optimization), namespace)
    assert attempted == []


@pytest.mark.parametrize("optimization", ["-O", "-OO"])
def test_optimized_child_cannot_issue_success_receipt(private_parent, optimization):
    output = private_parent / "optimized"
    # Refusal needs no site startup, user configuration or installed packages.
    result = subprocess.run([sys.executable, "-I", "-S", "-B", optimization,
                             str(Path(drill.__file__).resolve()), "--output-dir", str(output)],
                            cwd=private_parent, env=drill.clean_environment(os.environ), capture_output=True, timeout=10)
    assert result.returncode != 0
    assert result.stdout == b""
    assert not output.exists()
    assert b"requires assertions" in result.stderr


def test_worker_refuses_unmarked_existing_runtime(private_parent):
    config = private_parent / "source-worker-1.json"
    drill.write_private(config, drill.canonical({"v": 1, "run_id": "a" * 32, "generation": 1}))
    with pytest.raises((ValueError, FileNotFoundError)):
        drill.source_worker(config)
    assert not (private_parent / "source").exists()


class IntakeClock:
    def __init__(self, *, early_wake=False):
        self.now, self.sleeps, self.early_wake = 100.0, [], early_wake

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        assert seconds > 0
        self.sleeps.append(seconds)
        if self.early_wake:
            self.early_wake = False
            self.now += seconds / 2
        else:
            self.now += seconds


@pytest.mark.parametrize("namespace,minimum", [("heartbeat", 1.05), ("operator", 1.05), ("events", 0.11)])
def test_manual_intake_waits_through_early_wake_before_first_and_subsequent_send(monkeypatch, namespace, minimum):
    clock = IntakeClock(early_wake=True)
    monkeypatch.setattr(drill, "time", clock)
    started = clock.now
    drill.pace_intake(namespace)
    assert clock.now - started >= minimum - 1e-12
    assert len(clock.sleeps) == 2
    started = clock.now
    drill.pace_intake(namespace)
    assert clock.now - started >= minimum - 1e-12


def test_manual_heartbeats_refill_actual_persisted_quota_across_restart_and_worker_handoff(private_parent, monkeypatch):
    from collector.storage import Store, provision

    clock = IntakeClock()
    monkeypatch.setattr(drill, "time", clock)
    runtime = private_parent / "limited"
    provision(runtime, kind="collector", source_id="a" * 32, destination_id="b" * 32,
              inbox_id="c" * 32, alert_destination_id="d" * 32, now=clock.now)
    for _ in range(4):
        Store(runtime, clock=clock.monotonic).reserve_intake("heartbeat")
    calls = []

    class Transport:
        async def post(self, body, *, heartbeat=False):
            assert heartbeat
            # Reopen the real durable limiter on every send, as after restart.
            Store(runtime, clock=clock.monotonic).reserve_intake("heartbeat")
            calls.append((body, clock.now))
            return b"receipt"

    fixture = object.__new__(drill.Drill)
    fixture.processes = []
    for number in range(6):
        assert fixture.post(Transport(), str(number).encode(), heartbeat=True) == b"receipt"
    assert calls[0][1] >= 101.05
    assert all(right[1] - left[1] >= 1.05 - 1e-12 for left, right in zip(calls, calls[1:]))
    # A worker ran between manual phases and exhausted the persisted allowance.
    clock.now += 10
    for _ in range(4):
        Store(runtime, clock=clock.monotonic).reserve_intake("heartbeat")
    stopped_at = clock.now
    assert fixture.post(Transport(), b"restored-heartbeat", heartbeat=True) == b"receipt"
    assert calls[-1][1] - stopped_at >= 1.05 - 1e-12


@pytest.mark.parametrize("code", ["remote_throttled", "remote_unavailable", "remote_conflict"])
def test_manual_post_sends_exactly_once_and_does_not_retry_a_consumed_failure(monkeypatch, code):
    from business.event_wire import load_transport

    clock = IntakeClock()
    monkeypatch.setattr(drill, "time", clock)
    failure = load_transport().DeliveryFailure(code, retry_after=30)
    sent = []

    class Transport:
        async def post(self, body, *, heartbeat=False):
            sent.append((body, heartbeat, clock.now))
            raise failure

    fixture = object.__new__(drill.Drill)
    fixture.processes = []
    with pytest.raises(type(failure)) as caught:
        fixture.post(Transport(), b"unchanged-proof", heartbeat=True)
    assert caught.value is failure
    assert sent == [(b"unchanged-proof", True, 101.05)]
    assert len(clock.sleeps) == 1


def test_manual_source_channel_post_refuses_a_live_owned_source_worker(monkeypatch):
    from types import SimpleNamespace

    clock = IntakeClock()
    monkeypatch.setattr(drill, "time", clock)
    fixture = object.__new__(drill.Drill)
    fixture.processes = [SimpleNamespace(graceful=True, process=SimpleNamespace(poll=lambda: None))]
    with pytest.raises(RuntimeError, match="source worker"):
        fixture.post(object(), b"must-not-send", heartbeat=True)
    assert not clock.sleeps


def test_operator_request_is_paced_independently_and_health_probe_is_not(monkeypatch):
    import httpx

    clock = IntakeClock()
    monkeypatch.setattr(drill, "time", clock)
    sent = []

    class Client:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def request(self, method, url, **_kwargs):
            sent.append((method, url, clock.now))
            return httpx.Response(200)

    monkeypatch.setattr(httpx, "Client", lambda **_kwargs: Client())
    monkeypatch.setattr(drill.ssl, "create_default_context", lambda **_kwargs: object())
    fixture = object.__new__(drill.Drill)
    fixture.cert = Path("unused-test-cert")
    fixture.request("GET", "https://127.0.0.1:1234/healthz")
    fixture.request("GET", "https://127.0.0.1:1234/v1/operator/messages", token="fixture")
    fixture.request("POST", "https://127.0.0.1:1234/v1/operator/messages/one/ack", token="fixture", data=b"{}")
    assert [item[2] for item in sent] == [100.0, 101.05, 102.1]
