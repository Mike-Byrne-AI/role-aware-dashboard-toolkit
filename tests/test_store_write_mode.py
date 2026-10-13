"""Replacing a record keeps the file mode an operator set; new records stay private."""
from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from role_aware_dashboard_toolkit.profile_store import FileProfileStore

pytestmark = pytest.mark.skipif(os.name == "nt", reason="POSIX file modes")


def _mode(path: str) -> int:
    return stat.S_IMODE(Path(path).stat().st_mode)


@pytest.mark.parametrize("operator_mode", [0o640, 0o644, 0o400])
def test_update_keeps_the_existing_mode(tmp_path, operator_mode):
    store = FileProfileStore(str(tmp_path))
    path = store.save({"profile_id": "ops", "values": {"v": 1}})
    os.chmod(path, operator_mode)
    store.save({"profile_id": "ops", "values": {"v": 2}})
    assert _mode(path) == operator_mode
    assert store.load("ops")["values"] == {"v": 2}


def test_a_new_record_is_private(tmp_path):
    path = FileProfileStore(str(tmp_path)).save({"profile_id": "ops", "values": {}})
    assert _mode(path) == 0o600
