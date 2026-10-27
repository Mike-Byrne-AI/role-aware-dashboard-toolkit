"""Optional, interactive age wrapper for small recovery files, outside source.

Requires the official age executable on PATH (or --age-executable). All crypto
and passphrase prompts belong to age. No application imports or dependencies.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys

SOURCE_ROOTS = {Path(__file__).absolute().parents[2], Path(__file__).resolve().parents[2]}
MAX_PLAINTEXT = 1024 * 1024
MAX_CIPHERTEXT = MAX_PLAINTEXT + 65536


class RecoveryError(Exception):
    """An operator-safe failure message, without secret contents."""


def _linked(info: os.stat_result) -> bool:
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )


def _private(info: os.stat_result) -> None:
    # Windows callers must protect the parent directory's inherited ACL first.
    # chmod(0600) does not establish a private Windows DACL.
    if os.name == "posix" and (
        info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077
    ):
        raise RecoveryError("Use an owner-only directory (0700) and files (0600).")


def _path(value: str | Path) -> Path:
    expanded = Path(value).expanduser()
    if os.name == "nt":
        reserved = {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"}
        reserved.update(f"{prefix}{n}" for prefix in ("COM", "LPT") for n in "123456789¹²³")
        # Validate before abspath: Windows normalizes trailing dots/spaces away.
        for part in expanded.parts[1:] if expanded.anchor else expanded.parts:
            if part in (".", ".."):
                continue
            if ":" in part or part.endswith((".", " ")) or part.split(".")[0].upper() in reserved:
                raise RecoveryError("Use ordinary file names, without device names or alternate streams.")
    path = Path(os.path.abspath(expanded))
    resolved = path.resolve()
    if any(root == item or root in item.parents for root in SOURCE_ROOTS for item in (path, resolved)):
        raise RecoveryError("Keep recovery files outside the entire source tree.")
    for parent in path.parents:
        info = parent.lstat()
        if _linked(info) or not stat.S_ISDIR(info.st_mode):
            raise RecoveryError("Recovery directories must not use links or reparse points.")
        if (parent / ".git").exists():
            raise RecoveryError("Keep recovery files outside Git working trees.")
    _private(path.parent.stat())
    return path


def _read(path: Path, limit: int) -> bytes:
    info = path.lstat()
    if _linked(info) or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise RecoveryError("Recovery inputs must be regular files without links.")
    _private(info)
    if info.st_size > limit:
        raise RecoveryError("Recovery files must be at most 1 MiB of plaintext.")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    with os.fdopen(os.open(path, flags), "rb") as stream:
        opened = os.fstat(stream.fileno())
        if not os.path.samestat(info, opened) or opened.st_nlink != 1:
            raise RecoveryError("Input changed while opening it; nothing was written.")
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise RecoveryError("Recovery files must be at most 1 MiB of plaintext.")
    return data


def _destination(value: str | Path) -> Path:
    path = _path(value)
    if os.path.lexists(path):
        raise RecoveryError("Output already exists; choose a new file name.")
    return path


def _write_new(path: Path, data: bytes) -> None:
    # Recheck after interactive prompts, then use exclusive creation to avoid
    # clobbering a file that appeared since the initial destination check.
    _destination(path)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    info = os.fstat(descriptor)
    stream = None
    try:
        stream = os.fdopen(descriptor, "wb")
        with stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        if stream is None:
            os.close(descriptor)
        # Remove only our incomplete output, never a replaced path.
        if path.exists() and os.path.samestat(info, path.lstat()):
            path.unlink()
        raise


def _age(executable: str, data: bytes, *, encrypt: bool) -> bytes:
    command = [executable, "--encrypt", "--passphrase"] if encrypt else [executable, "--decrypt"]
    # age opens the controlling terminal itself for hidden passphrase input.
    # Never detach its console, put a passphrase in argv/env, or use shell=True.
    result = subprocess.run(command, input=data, stdout=subprocess.PIPE, check=False)
    if result.returncode:
        raise RecoveryError("age did not complete successfully; no output was saved.")
    limit = MAX_CIPHERTEXT if encrypt else MAX_PLAINTEXT
    if len(result.stdout) > limit:
        raise RecoveryError("age output exceeded the recovery-file size limit.")
    return result.stdout


def execute(args: argparse.Namespace) -> None:
    source = _path(args.input)
    destination = _destination(args.output) if args.command != "verify" else None
    original = _path(args.original) if args.command == "verify" else source
    data = _read(source, MAX_PLAINTEXT if args.command == "encrypt" else MAX_CIPHERTEXT)
    expected = _read(original, MAX_PLAINTEXT) if args.command == "verify" else data
    executable = shutil.which(args.age_executable)
    if executable is None:
        raise RecoveryError("Install the official age CLI, or pass --age-executable before the command.")
    if args.command == "encrypt":
        print("Enter a nonempty, unique passphrase at age's private prompts.", flush=True)
        encrypted = _age(executable, data, encrypt=True)
        print("Now enter it again to verify recovery before saving the encrypted copy.", flush=True)
        recovered = _age(executable, encrypted, encrypt=False)
        if recovered != data or _read(_path(source), MAX_PLAINTEXT) != data:
            raise RecoveryError("Recovery did not match the unchanged original; no output was saved.")
        _write_new(destination, encrypted)
        print("Encrypted copy saved and recovery verified. Original retained.")
    elif args.command == "verify":
        recovered = _age(executable, data, encrypt=False)
        if (
            recovered != expected
            or _read(_path(original), MAX_PLAINTEXT) != expected
            or _read(_path(source), MAX_CIPHERTEXT) != data
        ):
            raise RecoveryError("Recovery did not match, or an input changed during verification.")
        print("Recovery verified: decrypted bytes match the original. No files changed.")
    else:
        recovered = _age(executable, data, encrypt=False)
        _write_new(destination, recovered)
        print("Recovered plaintext saved to the new file. Encrypted original retained.")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--age-executable", default="age", help="Trusted age executable (default: age on PATH)")
    commands = parser.add_subparsers(dest="command", required=True)
    descriptions = {
        "encrypt": "Encrypt and verify recovery before saving a new encrypted copy",
        "verify": "Decrypt in memory and compare with the original plaintext",
        "restore": "Authenticate and decrypt into a new private plaintext file",
    }
    for name, description in descriptions.items():
        command = commands.add_parser(name, help=description, description=description)
        command.add_argument("input", help="Existing private input file outside source")
        if name == "verify":
            command.add_argument("--original", required=True, help="Original plaintext to compare in memory")
        else:
            command.add_argument("--output", required=True, help="New file in an existing private directory")
    args = parser.parse_args(argv)
    try:
        execute(args)
    except RecoveryError as exc:
        print(f"Recovery failed: {exc}", file=sys.stderr)
        return 1
    except OSError:
        print("Recovery failed: could not access a file or run age. Check paths and permissions.", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("Recovery cancelled. Original files retained.", file=sys.stderr)
        return 130
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
