"""Load the reviewed sibling package without cwd or installed-name discovery."""

import _imp
import importlib
import importlib.util
from pathlib import Path
import sys

_NAME = "_westbridge_security_event_wire"


def _check_origins(directory):
    for name, module in tuple(sys.modules.items()):
        if name != _NAME and not name.startswith(_NAME + "."):
            continue
        suffix = name[len(_NAME):].lstrip(".")
        expected = directory / (suffix.replace(".", "/") + ".py" if suffix else "__init__.py")
        actual = getattr(module, "__file__", None)
        if actual is None or not expected.is_file() or Path(actual).resolve() != expected:
            raise ImportError("Shared security wire module has an unexpected origin.")


def load_wire():
    """Return one completely initialized, origin-checked protocol module.

    The interpreter import lock is process-shared and reentrant, including when
    separate consumers execute this bootstrap through runpy. It prevents those
    consumers from observing the temporary package entry needed by relative
    imports. Only entries created by a failed attempt are removed.
    """
    directory = Path(__file__).resolve().parent
    if not (directory / "__init__.py").is_file() or not (directory / "protocol.py").is_file():
        raise ImportError("The shared security wire source package is missing.")
    _imp.acquire_lock()
    try:
        _check_origins(directory)
        cached = sys.modules.get(_NAME)
        if cached is not None:
            if not getattr(cached, "_WIRE_READY", False) or not hasattr(cached, "protocol"):
                raise ImportError("Shared security wire initialization is incomplete.")
            return cached.protocol
        if any(name.startswith(_NAME + ".") for name in sys.modules):
            raise ImportError("Shared security wire initialization is incomplete.")
        before = set(sys.modules)
        spec = importlib.util.spec_from_file_location(
            _NAME, directory / "__init__.py", submodule_search_locations=[str(directory)],
        )
        if spec is None or spec.loader is None:
            raise ImportError("The shared security wire source package cannot be loaded.")
        package = importlib.util.module_from_spec(spec)
        sys.modules[_NAME] = package
        try:
            spec.loader.exec_module(package)
            _check_origins(directory)
            if not getattr(package, "_WIRE_READY", False) or not hasattr(package, "protocol"):
                raise ImportError("Shared security wire initialization is incomplete.")
        except BaseException:
            for name in tuple(sys.modules):
                if name not in before and (name == _NAME or name.startswith(_NAME + ".")):
                    del sys.modules[name]
            raise
        return package.protocol
    finally:
        _imp.release_lock()


def load_transport():
    """Explicitly load the optional reviewed sibling adapter after the core."""
    directory = Path(__file__).resolve().parent
    load_wire()
    _imp.acquire_lock()
    try:
        _check_origins(directory)
        if not (directory / "transport.py").is_file():
            raise ImportError("The optional security wire transport is missing.")
        before = set(sys.modules)
        try:
            module = importlib.import_module(_NAME + ".transport")
            _check_origins(directory)
        except BaseException:
            for name in tuple(sys.modules):
                if name not in before and (name == _NAME or name.startswith(_NAME + ".")):
                    del sys.modules[name]
            raise
        return module
    finally:
        _imp.release_lock()
