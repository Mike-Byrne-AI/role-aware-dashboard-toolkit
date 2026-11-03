"""Explicit private runtime files; never initialize an existing installation."""

import os
from pathlib import Path
import stat


SOURCE_ROOT = Path(__file__).resolve().parents[3]


def private_directory(value, *, create=False):
    path = Path(os.path.abspath(Path(value).expanduser()))
    if path == Path(path.anchor) or path.is_relative_to(SOURCE_ROOT):
        raise ValueError("Use a private runtime directory outside source.")
    for part in (path, *path.parents):
        if (part / "pyproject.toml").is_file() and (part / "role_aware_dashboard_toolkit").is_dir():
            raise ValueError("Runtime data must stay outside source checkouts.")
        reparse = part.exists() and getattr(part.lstat(), "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
        if part.is_symlink() or reparse or (part.exists() and not part.is_dir()):
            raise ValueError("Runtime directories must not traverse links or files.")
    if create:
        path.mkdir(mode=0o700, parents=False, exist_ok=False)
    if not path.is_dir():
        raise ValueError("The private runtime directory does not exist.")
    if os.name != "nt" and (stat.S_IMODE(path.stat().st_mode) & 0o077 or path.stat().st_uid != os.geteuid()):
        raise ValueError("Runtime directory ownership and permissions must be private.")
    return path


def private_file_metadata(path):
    """Validate one metadata snapshot; only a safe unlinked inode is absent."""
    path = Path(path)
    info = path.lstat()
    reparse = getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink not in (0, 1) or reparse:
        raise ValueError("A private regular file without links is required.")
    if os.name != "nt" and (stat.S_IMODE(info.st_mode) & 0o077 or info.st_uid != os.geteuid()):
        raise ValueError("Private file ownership and permissions are required.")
    if info.st_nlink == 0:
        # A lookup may observe regular-file metadata after another connection
        # unlinks it. Required files still fail; only sidecar callers may ignore.
        raise FileNotFoundError("Private file was removed during validation.")
    return info


def check_private_file(path):
    path = Path(path)
    private_file_metadata(path)
    return path


def write_private(path, data):
    path = Path(path)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
