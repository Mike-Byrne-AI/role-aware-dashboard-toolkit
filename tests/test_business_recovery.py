"""Recovery wrapper orchestration with fake age results, never real credentials.

These tests do not establish encryption correctness or terminal prompt behavior.
"""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import stat
import subprocess
import tempfile

import pytest


SCRIPT = Path(__file__).resolve().parents[1] / "examples/business_dashboard/recovery.py"
SPEC = importlib.util.spec_from_file_location("business_recovery", SCRIPT)
recovery = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(recovery)

PLAINTEXT = b"FICTIONAL-RECOVERY-SECRET\nnot an actual credential\n"
CIPHERTEXT = b"FAKE-AGE-OUTPUT-for-orchestration-only"
EXECUTABLE = str(Path(tempfile.gettempdir()) / "trusted-age-test-executable")


@pytest.fixture
def private_dir():
    # tmp_path is inside the checkout by default, which recovery must reject.
    with tempfile.TemporaryDirectory(prefix="radt-recovery-test-") as temporary:
        directory = Path(temporary).resolve()
        if os.name == "posix":
            directory.chmod(0o700)
        assert not any(root == directory or root in directory.parents for root in recovery.SOURCE_ROOTS)
        yield directory


def private_file(directory, name="original.txt", data=PLAINTEXT):
    path = directory / name
    path.write_bytes(data)
    if os.name == "posix":
        path.chmod(0o600)
    return path


@pytest.fixture
def fake_age(monkeypatch):
    """Install predetermined age outcomes and inspect its process boundary."""
    monkeypatch.setattr(recovery.shutil, "which", lambda executable: EXECUTABLE)

    def install(*outcomes):
        pending = list(outcomes)
        calls = []

        def run(command, **kwargs):
            calls.append((command, kwargs))
            # age alone owns passphrase collection from the controlling terminal.
            assert command in ([EXECUTABLE, "--encrypt", "--passphrase"], [EXECUTABLE, "--decrypt"])
            assert set(kwargs) == {"input", "stdout", "check"}
            assert kwargs["stdout"] is subprocess.PIPE
            assert kwargs["check"] is False
            outcome = pending.pop(0)
            if callable(outcome):
                outcome = outcome(command, kwargs)
            if isinstance(outcome, BaseException):
                raise outcome
            if isinstance(outcome, tuple):
                returncode, output = outcome
            else:
                returncode, output = 0, outcome
            return subprocess.CompletedProcess(command, returncode, stdout=output)

        monkeypatch.setattr(recovery.subprocess, "run", run)
        return calls

    return install


def invoke(command, source, output=None, original=None):
    argv = [command, str(source)]
    if output is not None:
        argv += ["--output", str(output)]
    if original is not None:
        argv += ["--original", str(original)]
    return recovery.main(argv)


def test_encrypt_verifies_recovery_before_saving_and_retains_original(private_dir, fake_age, capsys):
    source = private_file(private_dir)
    destination = private_dir / "backup.age"

    def verification(command, kwargs):
        assert command == [EXECUTABLE, "--decrypt"]
        assert kwargs["input"] == CIPHERTEXT
        assert not destination.exists()
        assert source.read_bytes() == PLAINTEXT
        return PLAINTEXT

    calls = fake_age(CIPHERTEXT, verification)
    assert invoke("encrypt", source, destination) == 0
    assert destination.read_bytes() == CIPHERTEXT
    assert source.read_bytes() == PLAINTEXT
    assert calls[0][0] == [EXECUTABLE, "--encrypt", "--passphrase"]
    assert calls[0][1]["input"] == PLAINTEXT
    output = capsys.readouterr()
    assert PLAINTEXT.decode() not in output.out + output.err
    assert CIPHERTEXT.decode() not in output.out + output.err
    assert "Original retained" in output.out
    if os.name == "posix":
        assert stat.S_IMODE(destination.stat().st_mode) == 0o600


@pytest.mark.parametrize("command", ["encrypt", "restore", "verify"])
def test_failed_age_exit_never_uses_stdout(private_dir, fake_age, capsys, command):
    source = private_file(private_dir, data=PLAINTEXT if command == "encrypt" else CIPHERTEXT)
    original = private_file(private_dir, "expected.txt")
    destination = private_dir / "output"
    calls = fake_age((1, b"FICTIONAL-PARTIAL-PLAINTEXT"))
    assert invoke(command, source, None if command == "verify" else destination,
                  original if command == "verify" else None) == 1
    assert len(calls) == 1
    assert not destination.exists()
    assert original.read_bytes() == PLAINTEXT
    output = capsys.readouterr()
    assert "FICTIONAL-PARTIAL-PLAINTEXT" not in output.out + output.err
    assert "did not complete successfully" in output.err


def test_encrypt_failed_final_decryption_leaves_no_output(private_dir, fake_age):
    source = private_file(private_dir)
    destination = private_dir / "backup.age"
    calls = fake_age(CIPHERTEXT, (1, PLAINTEXT))
    assert invoke("encrypt", source, destination) == 1
    assert len(calls) == 2
    assert not destination.exists()
    assert source.read_bytes() == PLAINTEXT


@pytest.mark.parametrize("command", ["encrypt", "verify"])
def test_mismatched_recovery_is_rejected(private_dir, fake_age, command):
    original = private_file(private_dir)
    encrypted = private_file(private_dir, "existing.age", CIPHERTEXT)
    destination = private_dir / "backup.age"
    fake_age(*([CIPHERTEXT, b"different content"] if command == "encrypt" else [b"different content"]))
    assert invoke(command, original if command == "encrypt" else encrypted,
                  destination if command == "encrypt" else None,
                  original if command == "verify" else None) == 1
    assert not destination.exists()
    assert original.read_bytes() == PLAINTEXT
    assert encrypted.read_bytes() == CIPHERTEXT


def test_verify_matches_original_without_writing_files(private_dir, fake_age, capsys):
    original = private_file(private_dir)
    encrypted = private_file(private_dir, "backup.age", CIPHERTEXT)
    before = {path.name: path.read_bytes() for path in private_dir.iterdir()}
    calls = fake_age(PLAINTEXT)
    assert invoke("verify", encrypted, original=original) == 0
    assert len(calls) == 1
    assert {path.name: path.read_bytes() for path in private_dir.iterdir()} == before
    assert "No files changed" in capsys.readouterr().out


def test_ciphertext_changed_during_verification_does_not_report_success(private_dir, fake_age, capsys):
    original = private_file(private_dir)
    encrypted = private_file(private_dir, "backup.age", CIPHERTEXT)
    changed_ciphertext = b"another writer replaced the encrypted backup"

    def final_prompt(command, kwargs):
        assert kwargs["input"] == CIPHERTEXT
        encrypted.write_bytes(changed_ciphertext)
        return PLAINTEXT

    fake_age(final_prompt)
    assert invoke("verify", encrypted, original=original) == 1
    assert original.read_bytes() == PLAINTEXT
    assert encrypted.read_bytes() == changed_ciphertext
    output = capsys.readouterr()
    assert "Recovery verified" not in output.out
    assert "Recovery failed" in output.err


def test_restore_only_writes_after_successful_age_exit(private_dir, fake_age):
    source = private_file(private_dir, "backup.age", CIPHERTEXT)
    destination = private_dir / "recovered.txt"

    def decryption(command, kwargs):
        assert command == [EXECUTABLE, "--decrypt"]
        assert not destination.exists()
        assert kwargs["input"] == CIPHERTEXT
        return PLAINTEXT

    fake_age(decryption)
    assert invoke("restore", source, destination) == 0
    assert destination.read_bytes() == PLAINTEXT
    assert source.read_bytes() == CIPHERTEXT


def test_existing_output_is_never_overwritten_or_sent_to_age(private_dir, fake_age):
    source = private_file(private_dir)
    destination = private_file(private_dir, "existing.age", b"existing backup")
    calls = fake_age()
    assert invoke("encrypt", source, destination) == 1
    assert destination.read_bytes() == b"existing backup"
    assert source.read_bytes() == PLAINTEXT
    assert calls == []


def test_output_appearing_during_prompt_is_preserved(private_dir, fake_age):
    source = private_file(private_dir)
    destination = private_dir / "backup.age"

    def final_prompt(command, kwargs):
        private_file(private_dir, destination.name, b"other writer")
        return PLAINTEXT

    fake_age(CIPHERTEXT, final_prompt)
    assert invoke("encrypt", source, destination) == 1
    assert destination.read_bytes() == b"other writer"
    assert source.read_bytes() == PLAINTEXT


def test_exclusive_open_protects_output_appearing_after_last_check(private_dir, fake_age, monkeypatch):
    source = private_file(private_dir, "backup.age", CIPHERTEXT)
    destination = private_dir / "recovered.txt"
    real_open = recovery.os.open

    def racing_open(path, flags, *args, **kwargs):
        if Path(path) == destination and flags & os.O_CREAT:
            private_file(private_dir, destination.name, b"racing writer")
        return real_open(path, flags, *args, **kwargs)

    fake_age(PLAINTEXT)
    monkeypatch.setattr(recovery.os, "open", racing_open)
    assert invoke("restore", source, destination) == 1
    assert destination.read_bytes() == b"racing writer"


@pytest.mark.parametrize("command", ["encrypt", "verify"])
def test_original_changed_during_prompt_prevents_success(private_dir, fake_age, command):
    original = private_file(private_dir)
    encrypted = private_file(private_dir, "existing.age", CIPHERTEXT)
    destination = private_dir / "backup.age"

    def final_prompt(command, kwargs):
        original.write_bytes(b"edited while age was prompting")
        return PLAINTEXT

    fake_age(*([CIPHERTEXT, final_prompt] if command == "encrypt" else [final_prompt]))
    assert invoke(command, original if command == "encrypt" else encrypted,
                  destination if command == "encrypt" else None,
                  original if command == "verify" else None) == 1
    assert not destination.exists()
    assert original.read_bytes() == b"edited while age was prompting"


@pytest.mark.parametrize("source_in_tree", [True, False])
def test_source_tree_paths_rejected_before_age(private_dir, fake_age, source_in_tree):
    source = SCRIPT if source_in_tree else private_file(private_dir)
    destination = private_dir / "backup.age" if source_in_tree else SCRIPT.parent / "must-not-create.age"
    calls = fake_age()
    assert invoke("encrypt", source, destination) == 1
    assert calls == []
    assert not destination.exists()


@pytest.mark.parametrize("git_marker", ["directory", "file"])
def test_other_git_working_tree_rejected(private_dir, fake_age, git_marker):
    marker = private_dir / ".git"
    if git_marker == "directory":
        marker.mkdir()
    else:
        marker.write_text("gitdir: elsewhere", encoding="utf-8")
    source = private_file(private_dir)
    calls = fake_age()
    assert invoke("encrypt", source, private_dir / "backup.age") == 1
    assert calls == []


def make_symlink(link, target, *, directory=False):
    try:
        link.symlink_to(target, target_is_directory=directory)
    except (OSError, NotImplementedError):
        pytest.skip("Creating symbolic links is unavailable for this test account.")


@pytest.mark.parametrize("kind", ["input", "parent", "output"])
def test_linked_paths_rejected(private_dir, fake_age, kind):
    source = private_file(private_dir)
    destination = private_dir / "backup.age"
    if kind == "input":
        link = private_dir / "linked.txt"
        make_symlink(link, source)
        source = link
    elif kind == "parent":
        real = private_dir / "real"
        real.mkdir(mode=0o700)
        source = private_file(real)
        link = private_dir / "linked-dir"
        make_symlink(link, real, directory=True)
        source = link / source.name
    else:
        make_symlink(destination, source)
    calls = fake_age()
    assert invoke("encrypt", source, destination) == 1
    assert calls == []
    assert source.read_bytes() == PLAINTEXT


def test_hardlinked_input_rejected(private_dir, fake_age):
    source = private_file(private_dir)
    try:
        os.link(source, private_dir / "second-name.txt")
    except OSError:
        pytest.skip("Hard links are unavailable for this filesystem.")
    calls = fake_age()
    assert invoke("encrypt", source, private_dir / "backup.age") == 1
    assert calls == []


def test_input_replaced_during_open_rejected(private_dir, fake_age, monkeypatch):
    source = private_file(private_dir)
    replacement = private_file(private_dir, "replacement.txt", b"different file")
    real_open = recovery.os.open

    def racing_open(path, flags, *args, **kwargs):
        if Path(path) == source:
            replacement.replace(source)
        return real_open(path, flags, *args, **kwargs)

    calls = fake_age()
    monkeypatch.setattr(recovery.os, "open", racing_open)
    assert invoke("encrypt", source, private_dir / "backup.age") == 1
    assert calls == []
    assert source.read_bytes() == b"different file"
    assert not (private_dir / "backup.age").exists()


@pytest.mark.parametrize("command,limit", [("encrypt", recovery.MAX_PLAINTEXT), ("restore", recovery.MAX_CIPHERTEXT)])
def test_oversized_input_rejected_before_age(private_dir, fake_age, command, limit):
    source = private_file(private_dir, data=b"x" * (limit + 1))
    calls = fake_age()
    assert invoke(command, source, private_dir / "output") == 1
    assert calls == []
    assert not (private_dir / "output").exists()


@pytest.mark.parametrize("command,limit", [("encrypt", recovery.MAX_CIPHERTEXT), ("restore", recovery.MAX_PLAINTEXT)])
def test_oversized_age_output_rejected(private_dir, fake_age, command, limit):
    source = private_file(private_dir)
    fake_age(b"x" * (limit + 1))
    assert invoke(command, source, private_dir / "output") == 1
    assert not (private_dir / "output").exists()


@pytest.mark.skipif(os.name != "posix", reason="POSIX mode bits are not Windows ACLs.")
@pytest.mark.parametrize("kind", ["directory", "input"])
def test_nonprivate_posix_permissions_rejected(private_dir, fake_age, kind):
    source = private_file(private_dir)
    target = private_dir if kind == "directory" else source
    target.chmod(0o755 if kind == "directory" else 0o644)
    calls = fake_age()
    try:
        assert invoke("encrypt", source, private_dir / "backup.age") == 1
        assert calls == []
    finally:
        target.chmod(0o700 if kind == "directory" else 0o600)


@pytest.mark.skipif(os.name != "nt", reason="Windows device names and alternate streams.")
@pytest.mark.parametrize("name", ["NUL", "con.txt", "COM1.age", "backup.age:hidden", "backup.age.", "backup.age "])
def test_windows_special_output_names_rejected(private_dir, fake_age, name):
    source = private_file(private_dir)
    calls = fake_age()
    assert invoke("encrypt", source, private_dir / name) == 1
    assert calls == []


def test_cancellation_during_final_verification_retains_original(private_dir, fake_age, capsys):
    source = private_file(private_dir)
    destination = private_dir / "backup.age"
    fake_age(CIPHERTEXT, KeyboardInterrupt())
    assert invoke("encrypt", source, destination) == 130
    assert not destination.exists()
    assert source.read_bytes() == PLAINTEXT
    assert "cancelled" in capsys.readouterr().err


@pytest.mark.parametrize("failure", [OSError("synthetic write failure"), KeyboardInterrupt()])
def test_partial_write_failure_cleans_only_new_output(private_dir, fake_age, monkeypatch, failure):
    source = private_file(private_dir, "backup.age", CIPHERTEXT)
    destination = private_dir / "recovered.txt"
    fake_age(PLAINTEXT)

    def failed_sync(descriptor):
        assert destination.read_bytes() == PLAINTEXT
        raise failure

    monkeypatch.setattr(recovery.os, "fsync", failed_sync)
    assert invoke("restore", source, destination) == (130 if isinstance(failure, KeyboardInterrupt) else 1)
    assert not destination.exists()
    assert source.read_bytes() == CIPHERTEXT


def test_failed_output_stream_creation_closes_descriptor_and_removes_output(private_dir, fake_age, monkeypatch):
    source = private_file(private_dir, "backup.age", CIPHERTEXT)
    destination = private_dir / "recovered.txt"
    real_fdopen = recovery.os.fdopen
    failed_descriptors = []

    def fail_output_stream(descriptor, mode, *args, **kwargs):
        if mode == "wb":
            failed_descriptors.append(descriptor)
            raise OSError("synthetic fdopen failure")
        return real_fdopen(descriptor, mode, *args, **kwargs)

    fake_age(PLAINTEXT)
    monkeypatch.setattr(recovery.os, "fdopen", fail_output_stream)
    assert invoke("restore", source, destination) == 1
    assert len(failed_descriptors) == 1
    with pytest.raises(OSError):
        os.fstat(failed_descriptors[0])
    assert not destination.exists()
    assert source.read_bytes() == CIPHERTEXT


@pytest.mark.skipif(os.name == "nt", reason="Windows disallows replacing this open output file.")
def test_failed_write_does_not_remove_replacement_path(private_dir, fake_age, monkeypatch):
    source = private_file(private_dir, "backup.age", CIPHERTEXT)
    destination = private_dir / "recovered.txt"
    fake_age(PLAINTEXT)

    def replace_then_fail(descriptor):
        destination.unlink()
        private_file(private_dir, destination.name, b"replacement owned by another writer")
        raise OSError("synthetic fsync failure")

    monkeypatch.setattr(recovery.os, "fsync", replace_then_fail)
    assert invoke("restore", source, destination) == 1
    assert destination.read_bytes() == b"replacement owned by another writer"


def test_missing_age_reports_safe_failure_without_output(private_dir, monkeypatch, capsys):
    source = private_file(private_dir)
    monkeypatch.setattr(recovery.shutil, "which", lambda executable: None)
    assert invoke("encrypt", source, private_dir / "backup.age") == 1
    assert not (private_dir / "backup.age").exists()
    assert "Install the official age CLI" in capsys.readouterr().err


def test_process_launch_failure_does_not_disclose_exception_text(private_dir, fake_age, capsys):
    source = private_file(private_dir)
    fake_age(OSError("FICTIONAL-SENSITIVE-EXCEPTION-TEXT"))
    assert invoke("encrypt", source, private_dir / "backup.age") == 1
    output = capsys.readouterr()
    assert "FICTIONAL-SENSITIVE-EXCEPTION-TEXT" not in output.out + output.err
    assert PLAINTEXT.decode() not in output.out + output.err
    assert not (private_dir / "backup.age").exists()
