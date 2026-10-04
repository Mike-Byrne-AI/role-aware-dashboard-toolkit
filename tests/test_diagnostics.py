from __future__ import annotations

from dataclasses import fields
import json
from pathlib import Path
import subprocess
import sys
import warnings

import pytest

from role_aware_dashboard_toolkit.diagnostics import (
    attach_diagnostic,
    build_diagnostic,
    diagnostic_text,
    list_diagnostics,
)
from role_aware_dashboard_toolkit.runtime import (
    RuntimeErrorRecord,
    build_runtime_diagnostic_record,
    build_runtime_error_record,
    cleanup_runtime,
    safe_call,
)
from role_aware_dashboard_toolkit.version import ROLE_AWARE_DASHBOARD_TOOLKIT_VERSION

_CODES = {
    "RADT-CONTROL-DEFINITION": ("controls", "register_control"),
    "RADT-CONTROL-RENDER": ("controls", "render_controls"),
    "RADT-APPEARANCE": ("appearance", "configure_appearance"),
    "RADT-SECTIONS": ("sections", "configure_sections"),
    "RADT-STREAMLIT": ("start", "render_dashboard"),
    "RADT-PERMISSION": ("permissions", "apply_controls"),
    "RADT-PROFILE-IO": ("profiles", "access_profiles"),
    "RADT-PLUGIN": ("plugins", "plugin_callback"),
    "RADT-TELEMETRY": ("telemetry", "sample_telemetry"),
    "RADT-AUDIT-IO": ("troubleshooting", "persist_audit"),
    "RADT-AUTH": ("permissions", "authenticate"),
    "RADT-CALLBACK": ("troubleshooting", "call_callback"),
}


@pytest.mark.parametrize("code,topic_operation", _CODES.items())
def test_fixed_catalog_contract_and_offline_help(code, topic_operation):
    topic, operation = topic_operation
    record = build_diagnostic(code)
    assert set(record) == {
        "schema_version", "toolkit_version", "code", "operation", "message",
        "effect", "guide_topic", "guide_command",
    }
    assert record["schema_version"] == 1
    assert record["toolkit_version"] == ROLE_AWARE_DASHBOARD_TOOLKIT_VERSION
    assert record["code"] == code
    assert record["operation"] == operation
    assert record["guide_topic"] == topic
    assert record["guide_command"] == f"python -m role_aware_dashboard_toolkit guide {topic}"
    assert record["message"] and record["effect"]
    assert json.loads(json.dumps(record)) == record
    text = diagnostic_text(code)
    for value in (code, record["message"], record["effect"], record["guide_command"]):
        assert value in text


def test_catalog_and_each_diagnostic_are_detached():
    catalog = list_diagnostics()
    assert [entry["code"] for entry in catalog] == list(_CODES)
    catalog[0]["message"] = "mutated"
    catalog.pop()
    record = build_diagnostic("RADT-CONTROL-DEFINITION")
    record["effect"] = "mutated too"
    fresh = list_diagnostics()
    assert len(fresh) == 12
    assert fresh[0]["message"] == "The control definition was rejected."
    assert fresh[0]["effect"] != record["effect"]


@pytest.mark.parametrize("code", ["secret-token-abc", "", None, []])
def test_unknown_codes_have_fixed_failure_text(code):
    with pytest.raises(ValueError) as caught:
        build_diagnostic(code)
    assert str(caught.value) == "Unknown diagnostic code."


@pytest.mark.parametrize("exception_type", [ValueError, TypeError, KeyError, RuntimeError])
def test_attach_preserves_exception_identity_class_and_remaining_args(exception_type):
    marker = object()
    error = exception_type("Rejected configuration", marker)
    annotated = attach_diagnostic(error, "RADT-APPEARANCE")
    assert annotated is error
    assert type(annotated) is exception_type
    assert annotated.args[1] is marker
    assert annotated.diagnostic == build_diagnostic("RADT-APPEARANCE")
    assert "Rejected configuration" in str(annotated)
    assert "guide appearance" in str(annotated)


def test_attach_redacts_library_message_paths_and_is_idempotent():
    error = ValueError("Cannot configure /private/project/settings.py")
    attach_diagnostic(error, "RADT-APPEARANCE")
    original_args = error.args
    error.diagnostic["effect"] = "caller mutation"
    attach_diagnostic(error, "RADT-APPEARANCE")
    assert error.args == original_args
    assert "/private/project/settings.py" not in str(error)
    assert "<redacted-local-path>" in str(error)
    assert str(error).count("[RADT-APPEARANCE]") == 1
    assert error.diagnostic == build_diagnostic("RADT-APPEARANCE")


def test_attach_supports_exception_without_args():
    error = RuntimeError()
    assert attach_diagnostic(error, "RADT-STREAMLIT") is error
    assert error.args == (diagnostic_text("RADT-STREAMLIT"),)


@pytest.mark.parametrize("exception_type", [ImportError, ModuleNotFoundError])
def test_attach_dependency_exception_renders_help_and_preserves_name(exception_type):
    error = exception_type("Streamlit is required", name="streamlit")
    assert attach_diagnostic(error, "RADT-STREAMLIT") is error
    assert error.name == "streamlit"
    assert error.msg == error.args[0]
    assert str(error) == error.args[0]
    assert "guide start" in str(error)
    attach_diagnostic(error, "RADT-STREAMLIT")
    assert str(error).count("[RADT-STREAMLIT]") == 1


def test_runtime_record_preserves_constructor_and_base_fields():
    record = RuntimeErrorRecord("ui", "graph", "ValueError", "caller-owned message")
    assert [field.name for field in fields(record)] == ["stage", "source", "exception_type", "message"]
    exported = record.to_dict()
    assert {key: value for key, value in exported.items() if key != "diagnostic"} == {
        "stage": "ui", "source": "graph", "exception_type": "ValueError",
        "error_type": "ValueError", "message": "caller-owned message",
    }
    exported["diagnostic"]["code"] = "mutated"
    record.diagnostic["message"] = "mutated"
    assert record.to_dict()["diagnostic"]["code"] == "RADT-CALLBACK"


def test_generated_runtime_record_does_not_read_arbitrary_exception_message():
    class SecretError(RuntimeError):
        def __str__(self):
            pytest.fail("raw third-party exception payload must not be read")

    record = build_runtime_error_record("safe_call", "host_callback", SecretError("token=private"))
    assert record.exception_type == "SecretError"
    assert record.message == "A callback failed."
    assert "private" not in json.dumps(record.to_dict())


def test_runtime_default_preserves_last_good_sample_and_retries_normally():
    last_good = {"timestamp": "2026-09-10T12:00:00Z", "metrics": {"latency": 10}}
    fresh = {"timestamp": "2026-09-10T12:01:00Z", "metrics": {"latency": 20}}
    original = json.dumps(last_good, sort_keys=True)
    calls = []
    errors = []
    failure = RuntimeError("token=private-password")

    def sample():
        calls.append("sample")
        if len(calls) == 1:
            raise failure
        return fresh

    retained = safe_call(sample, default=last_good, on_error=errors.append)
    assert retained is last_good
    assert json.dumps(retained, sort_keys=True) == original
    assert errors == [failure]
    assert str(errors[0]) == "token=private-password"
    assert "private-password" not in json.dumps(failure.role_aware_dashboard_toolkit_error_record.to_dict())
    assert safe_call(sample, default=last_good, on_error=errors.append) is fresh
    assert calls == ["sample", "sample"]
    assert errors == [failure]


def test_runtime_warning_contains_guide_and_effect_without_non_path_secret():
    def fail():
        raise ValueError("API_TOKEN=private-token")

    with pytest.warns(RuntimeWarning) as caught:
        assert safe_call(fail, default="last good") == "last good"
    text = str(caught[0].message)
    assert "ValueError" in text
    assert "returning default" in text
    assert "RADT-CALLBACK" in text
    assert "guide troubleshooting" in text
    assert "partial" in text
    assert "private-token" not in text


def test_failure_to_attach_record_does_not_expose_attachment_exception():
    class RefusesRecord(RuntimeError):
        def __setattr__(self, name, value):
            if name == "role_aware_dashboard_toolkit_error_record":
                raise ValueError("attachment-token=private-secret")
            super().__setattr__(name, value)

    def fail():
        raise RefusesRecord("original-token=private-secret")

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        assert safe_call(fail, default=7) == 7
    assert len(caught) == 2
    text = " ".join(str(item.message) for item in caught)
    assert "could not attach" in text
    assert "guide troubleshooting" in text
    assert "private-secret" not in text


def test_audit_shutdown_failure_diagnostic_does_not_claim_durability_and_retries():
    class Audit:
        calls = 0

        def stop_writer(self):
            self.calls += 1
            if self.calls == 1:
                raise OSError("database-password=secret")

    audit = Audit()
    first = cleanup_runtime(audit=audit, run_gc=False, try_torch_cuda_empty_cache=False)
    assert first["audit_writer_stopped"] is False
    record = first["error_records"][0]
    assert record["exception_type"] == "OSError"
    assert record["diagnostic"]["code"] == "RADT-AUDIT-IO"
    assert "unconfirmed" in record["diagnostic"]["effect"]
    assert "secret" not in json.dumps(first)
    second = cleanup_runtime(audit=audit, run_gc=False, try_torch_cuda_empty_cache=False)
    assert audit.calls == 2
    assert second["audit_writer_stopped"] is True
    assert second["error_records"] == []


def test_runtime_fallback_record_retains_safe_context():
    record = build_runtime_diagnostic_record(
        "ui", "render_graph", RuntimeError("token=secret"), fallback="plain text"
    )
    assert record["fallback"] == "plain text"
    assert record["source"] == "render_graph"
    assert record["diagnostic"]["code"] == "RADT-CALLBACK"
    assert "secret" not in json.dumps(record)


def test_diagnostics_and_runtime_need_no_optional_packages_or_import_output():
    script = """
import builtins
import sys
optional = {"streamlit", "pandas", "fastapi", "pydantic", "uvicorn", "torch"}
original_import = builtins.__import__
def guarded_import(name, *args, **kwargs):
    if name.split(".")[0] in optional:
        raise AssertionError("optional import attempted: " + name)
    return original_import(name, *args, **kwargs)
builtins.__import__ = guarded_import
import role_aware_dashboard_toolkit
from role_aware_dashboard_toolkit.diagnostics import list_diagnostics
from role_aware_dashboard_toolkit.runtime import cleanup_runtime
assert len(list_diagnostics()) == 12
assert cleanup_runtime(run_gc=False, try_torch_cuda_empty_cache=False)["error_records"] == []
assert not (optional & set(sys.modules))
"""
    result = subprocess.run(
        [sys.executable, "-B", "-S", "-c", script],
        cwd=Path(__file__).resolve().parents[1], capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == ""
    assert result.stderr == ""
