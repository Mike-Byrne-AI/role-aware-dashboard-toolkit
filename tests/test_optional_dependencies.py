import builtins

import pytest

from role_aware_dashboard_toolkit._optional_pandas import load_optional_pandas


def test_optional_pandas_absence_is_cached_as_unavailable(monkeypatch):
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "pandas":
            raise ModuleNotFoundError("No module named 'pandas'", name="pandas")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    module, available, checked = load_optional_pandas(None, None)

    assert module is None
    assert available is False
    assert checked is True


def test_optional_pandas_surfaces_nested_import_error(monkeypatch):
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "pandas":
            raise ModuleNotFoundError("No module named 'pandas._libs'", name="pandas._libs")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    with pytest.raises(ModuleNotFoundError, match="pandas._libs"):
        load_optional_pandas(None, None)
