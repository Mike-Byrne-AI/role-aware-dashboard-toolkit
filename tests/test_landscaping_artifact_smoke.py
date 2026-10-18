from __future__ import annotations

import importlib.util
import errno
import io
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
from types import SimpleNamespace

import pytest


_SPEC = importlib.util.spec_from_file_location(
    "landscaping_artifact_smoke_under_test",
    Path(__file__).resolve().parents[1] / "tools/landscaping_artifact_smoke.py",
)
smoke = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(smoke)

ROOT = "sample-0.1"
MEMBER = ROOT + "/README.md"


def archive(path, entries):
    with tarfile.open(path, "w:gz") as output:
        for name, kind, data in entries:
            entry = tarfile.TarInfo(name)
            entry.type = kind
            entry.size = len(data) if kind == tarfile.REGTYPE else 0
            if kind in {tarfile.SYMTYPE, tarfile.LNKTYPE}:
                entry.linkname = "../../outside"
            output.addfile(entry, io.BytesIO(data) if entry.size else None)
    return path


def extract(tmp_path, entries, expected=None):
    artifact = archive(tmp_path / "source.tar.gz", entries)
    return smoke.extract_sdist(artifact, tmp_path / "extracted", ROOT, expected or {MEMBER})


def test_valid_archive_extracts_exact_regular_files_without_archived_permissions(tmp_path):
    source = extract(tmp_path, [(MEMBER, tarfile.REGTYPE, b"reviewed content")])
    assert source == tmp_path / "extracted" / ROOT
    assert (source / "README.md").read_bytes() == b"reviewed content"
    assert not (source / "README.md").is_symlink()


@pytest.mark.parametrize("name", [
    "../outside", "/tmp/outside", ROOT + "/../outside", ROOT + "//README.md",
    ROOT + "/./README.md", ROOT + "/README.md/", "C:/outside",
    ROOT + "\\README.md", ROOT + "/line\nbreak", ROOT + "/tab\tname",
])
def test_unsafe_archive_names_are_rejected_before_any_extraction(tmp_path, name):
    with pytest.raises(smoke.SmokeFailure, match="unsafe"):
        extract(tmp_path, [(MEMBER, tarfile.REGTYPE, b"safe"), (name, tarfile.REGTYPE, b"bad")])
    assert not (tmp_path / "extracted").exists()


@pytest.mark.parametrize("kind", [tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.DIRTYPE, tarfile.FIFOTYPE, tarfile.CHRTYPE, tarfile.BLKTYPE])
def test_special_archive_members_cannot_write_outside_the_release(tmp_path, kind):
    with pytest.raises(smoke.SmokeFailure, match="unsafe"):
        extract(tmp_path, [(MEMBER, tarfile.REGTYPE, b"safe"), (ROOT + "/special", kind, b"")])
    assert not (tmp_path / "extracted").exists()


def test_duplicate_names_are_not_silently_overwritten(tmp_path):
    with pytest.raises(smoke.SmokeFailure, match="duplicate"):
        extract(tmp_path, [(MEMBER, tarfile.REGTYPE, b"first"), (MEMBER, tarfile.REGTYPE, b"second")])
    assert not (tmp_path / "extracted").exists()


@pytest.mark.parametrize("entries, expected", [
    ([(MEMBER, tarfile.REGTYPE, b"safe")], {MEMBER, ROOT + "/missing.py"}),
    ([(MEMBER, tarfile.REGTYPE, b"safe"), (ROOT + "/unreviewed.py", tarfile.REGTYPE, b"extra")], {MEMBER}),
])
def test_missing_or_extra_public_members_fail_exact_closure(tmp_path, entries, expected):
    with pytest.raises(smoke.SmokeFailure, match="exact reviewed release closure"):
        extract(tmp_path, entries, expected)
    assert not (tmp_path / "extracted").exists()


@pytest.mark.parametrize("limit, value", [("MAX_MEMBER_BYTES", 2), ("MAX_EXPANDED_BYTES", 2), ("MAX_MEMBERS", 0), ("MAX_ARCHIVE_BYTES", 1)])
def test_archive_resource_limits_fail_before_writing(tmp_path, monkeypatch, limit, value):
    monkeypatch.setattr(smoke, limit, value)
    with pytest.raises(smoke.SmokeFailure, match="limit|too many"):
        extract(tmp_path, [(MEMBER, tarfile.REGTYPE, b"safe")])
    assert not (tmp_path / "extracted").exists()


def test_existing_extraction_destination_is_never_reused(tmp_path):
    destination = tmp_path / "extracted"
    destination.mkdir()
    (destination / "saved").write_text("preserve")
    with pytest.raises(smoke.SmokeFailure, match="already exists"):
        extract(tmp_path, [(MEMBER, tarfile.REGTYPE, b"safe")])
    assert (destination / "saved").read_text() == "preserve"


@pytest.mark.skipif(os.name != "posix", reason="POSIX symlink test")
def test_symlink_archive_is_rejected(tmp_path):
    real = archive(tmp_path / "real.tar.gz", [(MEMBER, tarfile.REGTYPE, b"safe")])
    link = tmp_path / "linked.tar.gz"
    link.symlink_to(real)
    with pytest.raises(smoke.SmokeFailure, match="regular file"):
        smoke.extract_sdist(link, tmp_path / "extracted", ROOT, {MEMBER})


def test_output_cannot_overwrite_evidence_or_write_into_checkout(tmp_path):
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    with pytest.raises(smoke.SmokeFailure, match="outside"):
        smoke.prepare_output(checkout / "evidence", checkout)
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    (evidence / "summary.json").write_text("keep")
    with pytest.raises(smoke.SmokeFailure, match="new or empty"):
        smoke.prepare_output(evidence, checkout)
    assert (evidence / "summary.json").read_text() == "keep"


def test_empty_external_output_is_accepted(tmp_path):
    output = tmp_path / "evidence"
    output.mkdir()
    assert smoke.prepare_output(output, tmp_path / "checkout") == output


def test_subprocess_environment_discards_import_and_live_demo_overrides(monkeypatch):
    names = ("PYTHONPATH", "PYTHONHOME", "VIRTUAL_ENV", "LANDSCAPE_DATA_DIR",
             "PUBLIC_ORIGIN", "PORT", "TRUSTED_PROXY_CIDRS")
    for name in names:
        monkeypatch.setenv(name, "must-not-be-inherited")
    environment = smoke.clean_environment()
    assert all(name not in environment for name in names)
    assert environment["PYTHONDONTWRITEBYTECODE"] == "1"


@pytest.mark.skipif(os.name != "posix", reason="POSIX process-group controller")
def test_failed_subprocess_output_cannot_leak_configuration(tmp_path):
    with pytest.raises(smoke.SmokeFailure) as failure:
        smoke.run_command([sys.executable, "-c", "print('synthetic-secret'); raise SystemExit(1)"], tmp_path, label="Probe")
    assert "synthetic-secret" not in str(failure.value)


@pytest.mark.skipif(os.name != "posix", reason="POSIX process-group controller")
def test_expected_rejection_requires_the_exact_exit_code(tmp_path):
    result = smoke.run_command(
        [sys.executable, "-c", "print('refused'); raise SystemExit(2)"], tmp_path,
        label="Expected rejection", expected_returncode=2,
    )
    assert result.strip() == b"refused"
    for exit_code in (0, 1):
        with pytest.raises(smoke.SmokeFailure):
            smoke.run_command(
                [sys.executable, "-c", f"raise SystemExit({exit_code})"], tmp_path,
                label="Expected rejection", expected_returncode=2,
            )


@pytest.mark.skipif(os.name != "posix", reason="POSIX process-group controller")
def test_timed_out_process_is_stopped(tmp_path):
    pid_file = tmp_path / "pid"
    script = "import os,pathlib,time; pathlib.Path('pid').write_text(str(os.getpid())); time.sleep(60)"
    with pytest.raises(smoke.SmokeFailure, match="timed out"):
        smoke.run_command([sys.executable, "-c", script], tmp_path, label="Probe", timeout=0.3)
    pid = int(pid_file.read_text())
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)


@pytest.mark.skipif(os.name != "posix", reason="POSIX process-group controller")
@pytest.mark.parametrize("platform,outcomes,raises,retries", [
    ("darwin", [None], False, False),
    ("darwin", [errno.ESRCH], False, False),
    ("darwin", [errno.EPERM, None], False, True),
    ("darwin", [errno.EPERM, errno.ESRCH], False, True),
    ("darwin", [errno.EPERM], True, True),
    ("linux", [errno.EPERM], True, False),
    ("darwin", [errno.EACCES], True, False),
    ("darwin", [errno.EINVAL], True, False),
], ids=["success", "absent", "darwin-retry-success", "darwin-retry-absent",
        "darwin-persistent-denial", "linux-denial", "darwin-access-denial", "invalid-signal"])
def test_group_signal_retries_only_transient_darwin_permission_errors(monkeypatch, platform, outcomes, raises, retries):
    clock = SimpleNamespace(now=0.0)
    sleeps = []
    calls = []
    failures = [OSError(code, "synthetic signal failure") if code is not None else None for code in outcomes]

    def sleep(delay):
        assert delay == 0.01
        sleeps.append(delay)
        clock.now += delay

    def killpg(pgid, signum):
        calls.append((pgid, signum))
        failure = failures[min(len(calls) - 1, len(failures) - 1)]
        if failure is not None:
            raise failure

    monkeypatch.setattr(smoke, "sys", SimpleNamespace(platform=platform))
    monkeypatch.setattr(smoke, "time", SimpleNamespace(monotonic=lambda: clock.now, sleep=sleep))
    monkeypatch.setattr(smoke.os, "killpg", killpg)
    if raises:
        with pytest.raises(OSError) as caught:
            smoke._signal_group(424242, signal.SIGTERM)
        assert caught.value is failures[-1]
    else:
        smoke._signal_group(424242, signal.SIGTERM)
    assert all(call == (424242, signal.SIGTERM) for call in calls)
    assert bool(sleeps) is retries
    if raises and retries:
        assert 5 <= clock.now <= 5.02
        assert 2 < len(calls) <= 503
    else:
        assert len(calls) == (2 if retries else 1)
        assert clock.now == (0.01 if retries else 0)


@pytest.mark.skipif(os.name != "posix", reason="POSIX process-group controller")
@pytest.mark.parametrize("ignore_term", [False, True], ids=["terminate", "escalate-to-kill"])
def test_cleanup_stops_descendants_after_group_leader_exits(tmp_path, ignore_term):
    # A build backend can leave a child behind after its own successful exit.
    child = (
        "import os,signal,sys,time; "
        "signal.signal(signal.SIGTERM, signal.SIG_IGN) if sys.argv[2] == '1' else None; "
        "os.write(int(sys.argv[1]), b'ready\\n'); time.sleep(60)"
    )
    script = (
        "import subprocess,sys; fd=int(sys.argv[1]); "
        f"subprocess.Popen([sys.executable,'-c',{child!r},str(fd),sys.argv[2]], pass_fds=(fd,))"
    )
    read_fd, write_fd = os.pipe()
    process = None
    try:
        process = subprocess.Popen(
            [sys.executable, "-c", script, str(write_fd), str(int(ignore_term))],
            cwd=tmp_path, start_new_session=True, pass_fds=(write_fd,),
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        os.close(write_fd)
        write_fd = None
        assert select.select([read_fd], [], [], 5)[0], "Descendant did not become ready"
        assert os.read(read_fd, 64) == b"ready\n"
        assert process.wait(timeout=5) == 0
        assert not select.select([read_fd], [], [], 0)[0], "Descendant exited before cleanup"

        smoke.stop_process(process)
        assert select.select([read_fd], [], [], 5)[0], "Cleanup left the descendant running"
        # The child retains this pipe until exit. EOF proves termination even
        # when the orphan remains a zombie awaiting its new parent's waitpid.
        assert os.read(read_fd, 1) == b""
        smoke.stop_process(process)  # Cleanup must also be safe to repeat.
    finally:
        # Independent cleanup prevents leaks even when the implementation under
        # test regresses or the readiness/exit assertion fails.
        if process is not None:
            deadline = time.monotonic() + 5
            while True:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                    break
                except ProcessLookupError:
                    break
                except PermissionError as error:
                    # Keep this independent of the helper under test while
                    # allowing Darwin to reap a zombie-only group.
                    if sys.platform != "darwin" or error.errno != errno.EPERM or time.monotonic() >= deadline:
                        raise
                    time.sleep(0.01)
            process.wait(timeout=5)
        os.close(read_fd)
        if write_fd is not None:
            os.close(write_fd)


@pytest.mark.skipif(os.name != "posix", reason="POSIX CLI boundary")
def test_failure_receipt_is_safe_and_never_claims_a_pass(monkeypatch, capsys):
    def fail(*args):
        raise RuntimeError("synthetic-private-password")

    monkeypatch.setattr(smoke, "smoke", fail)
    with tempfile.TemporaryDirectory(prefix="radt-artifact-receipt-", dir="/tmp") as temporary:
        output = Path(temporary)
        assert smoke.main(["--sdist", str(output / "source.tar.gz"), "--output-dir", str(output)]) == 1
        receipt = json.loads((output / "summary.json").read_text())
        assert receipt["passed"] is False
        assert "synthetic-private-password" not in (output / "summary.json").read_text()
    assert "synthetic-private-password" not in capsys.readouterr().out
    assert "HTTPS" in receipt["coverage_boundary"]["excluded"]


def test_release_contract_is_exact_and_contains_the_demo_and_maintained_runner():
    root, expected = smoke.release_contract()
    assert f"{root}/examples/landscaping/run.py" in expected
    assert f"{root}/examples/landscaping/HOSTING.md" in expected
    assert f"{root}/examples/landscaping/hosting/pilot.py" in expected
    assert f"{root}/examples/landscaping/scripts/hosted_acceptance.py" in expected
    assert f"{root}/tools/landscaping_artifact_smoke.py" in expected
    assert not any("TRIAL_ACCOUNTS" in member or member.endswith(".sqlite3") for member in expected)
