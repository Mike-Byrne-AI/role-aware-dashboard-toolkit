"""Access storage inside the application tree is refused, however the path is spelled.

The authenticated starter and the A/B/C example refuse an access directory
inside their own source tree. The check must compare resolved paths: on
macOS /tmp is a root-owned link to /private/tmp, which the provisioning
helpers accept, so /tmp/deploy/app/secrets must still count as inside an app
deployed at /tmp/deploy/app.
"""
from __future__ import annotations

import importlib.util
import os
import shutil
from pathlib import Path

import pytest

pytest.importorskip("streamlit")

REPO_ROOT = Path(__file__).resolve().parents[1]
APPS = {
    "authenticated_starter": REPO_ROOT / "role_aware_dashboard_toolkit/resources/authenticated_starter/app.py",
    "section_access_example": REPO_ROOT / "examples/section_access/app.py",
}


class KeyRead(Exception):
    """Raised by the stand-in key reader: the app-tree check let the path through."""


def _deploy(tmp_path: Path, name: str, monkeypatch, *, key_reader):
    real = tmp_path / "private"
    (real / "deploy" / "app").mkdir(parents=True)
    shutil.copyfile(APPS[name], real / "deploy" / "app" / "app.py")
    link = tmp_path / "tmp"
    try:
        os.symlink(real, link, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("this platform cannot create a directory symlink here")
    spec = importlib.util.spec_from_file_location(f"deployed_{name}", link / "deploy" / "app" / "app.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    # Stand in for the provisioning check, which accepts root-owned system
    # links such as macOS /tmp; this test isolates the app-tree comparison.
    monkeypatch.setattr(module, "read_identity_key", key_reader)
    for variable in ("RADT_OIDC_ISSUER", "RADT_OIDC_AUDIENCE"):
        monkeypatch.delenv(variable, raising=False)
    return module, link, real


@pytest.mark.parametrize("name", sorted(APPS))
@pytest.mark.parametrize("spelling", ["through_link", "dot_dot"])
def test_access_storage_inside_the_app_tree_is_refused(tmp_path, monkeypatch, name, spelling):
    module, link, real = _deploy(tmp_path, name, monkeypatch, key_reader=lambda directory: b"k" * 32)
    if spelling == "through_link":
        directory = link / "deploy" / "app" / "secrets"  # like /tmp/deploy/app/secrets
    else:
        directory = real / "deploy" / "elsewhere" / ".." / "app" / "secrets"
    monkeypatch.setenv("RADT_ACCESS_DIRECTORY", str(directory))

    with pytest.raises(ValueError, match="outside the application source tree"):
        module.build_access_policy()


@pytest.mark.parametrize("name", sorted(APPS))
def test_access_storage_outside_the_app_tree_reaches_the_key_check(tmp_path, monkeypatch, name):
    def key_reader(directory):
        raise KeyRead(str(directory))

    module, link, _real = _deploy(tmp_path, name, monkeypatch, key_reader=key_reader)
    monkeypatch.setenv("RADT_ACCESS_DIRECTORY", str(link / "deploy" / "access"))

    with pytest.raises(KeyRead):
        module.build_access_policy()
