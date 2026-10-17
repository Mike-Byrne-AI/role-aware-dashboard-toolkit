"""Keep demonstration credentials and mutable state outside the source tree."""

from __future__ import annotations

import os
from pathlib import Path


SOURCE_ROOTS = frozenset({Path(__file__).absolute().parents[3], Path(__file__).resolve().parents[3]})


def default_data_dir() -> Path:
    """Use a private, persistent POSIX/WSL user-data directory."""
    return Path.home() / ".local" / "share" / "radt-landscaping-demo"


def validate_data_dir(data_dir: str | Path) -> Path:
    """Reject source-tree storage, including symlink aliases in either direction.

    This shipped source example has the fixed layout
    ``<source>/examples/landscaping/landscape/paths.py``. Check the entire source
    tree, not only the application package, before creating any files.
    """
    requested = Path(os.path.abspath(Path(data_dir).expanduser()))
    resolved = requested.resolve()
    for source_root in SOURCE_ROOTS:
        for candidate in (requested, resolved):
            if candidate == source_root or source_root in candidate.parents:
                raise ValueError("Keep demo storage outside the entire repository/source directory.")
    if requested.is_symlink():
        raise ValueError("Demo storage must not be a symbolic link.")
    return requested
