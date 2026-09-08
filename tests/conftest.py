from __future__ import annotations

import shutil
import sys
import tempfile
from pathlib import Path

# Keep repository hygiene checks deterministic during test collection.
sys.dont_write_bytecode = True

pytest_plugins = ("tests.release_hygiene_helpers",)


ROOT = Path(__file__).resolve().parents[1]
root_str = str(ROOT)
if root_str not in sys.path:
    sys.path.insert(0, root_str)

_MANAGED_BASETEMP_ROOT = ROOT / ".pytest-runtime-tmp"


def pytest_configure(config):
    if getattr(config.option, "basetemp", None) is not None:
        return
    managed_root = _MANAGED_BASETEMP_ROOT
    managed_root.mkdir(parents=True, exist_ok=True)
    resolved_root = managed_root.resolve(strict=True)
    resolved_repo = ROOT.resolve(strict=True)
    try:
        resolved_root.relative_to(resolved_repo)
    except ValueError as exc:
        raise RuntimeError(
            "Managed pytest basetemp root must stay within the repository."
        ) from exc
    managed_basetemp = Path(
        tempfile.mkdtemp(prefix="session-", dir=resolved_root)
    )
    config.option.basetemp = str(managed_basetemp)
    config._role_aware_dashboard_toolkit_managed_basetemp = managed_basetemp
    config._role_aware_dashboard_toolkit_managed_basetemp_root = resolved_root


def pytest_sessionfinish(session, exitstatus):
    target = getattr(session.config, "_role_aware_dashboard_toolkit_managed_basetemp", None)
    managed_root = getattr(
        session.config, "_role_aware_dashboard_toolkit_managed_basetemp_root", None
    )
    if target is None or managed_root is None:
        return
    target = Path(target)
    managed_root = Path(managed_root)
    if not target.is_absolute() or target.parent != managed_root:
        _emit_managed_basetemp_cleanup_refusal("target is not an owned direct child")
        return
    resolved_target = target.resolve(strict=False)
    resolved_root = managed_root.resolve(strict=False)
    resolved_repo = ROOT.resolve(strict=False)
    try:
        resolved_root.relative_to(resolved_repo)
    except ValueError:
        _emit_managed_basetemp_cleanup_refusal("managed root escaped the repository")
        return
    if resolved_root != managed_root or resolved_target != target:
        _emit_managed_basetemp_cleanup_refusal("target or managed root was redirected")
        return
    if not target.exists():
        return
    shutil.rmtree(
        target,
        ignore_errors=False,
        onerror=_emit_managed_basetemp_cleanup_warning,
    )


def _emit_managed_basetemp_cleanup_refusal(reason):
    sys.stderr.write(
        "[role_aware_dashboard_toolkit pytest cleanup warning] managed basetemp cleanup refused: "
        f"{reason}\n"
    )


def _emit_managed_basetemp_cleanup_warning(func, path, exc_info):
    exc = exc_info[1]
    sys.stderr.write(
        "[role_aware_dashboard_toolkit pytest cleanup warning] managed basetemp cleanup failed: "
        f"{func.__name__}({path!s}) -> {type(exc).__name__}: {exc}\n"
    )
