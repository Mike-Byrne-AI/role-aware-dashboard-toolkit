"""Consumer receipts bind supplied reports to explicit before/after source bytes."""
from __future__ import annotations

from copy import deepcopy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest


SCRIPT = Path(__file__).resolve().parents[1] / "tools/consumer_evidence.py"
_SPEC = importlib.util.spec_from_file_location("consumer_evidence_under_test", SCRIPT)
evidence = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(evidence)


def junit_text(*, outcome="", tests=2):
    count = ' failures="1"' if outcome == "failure" else ' failures="0"'
    count += ' errors="1"' if outcome == "error" else ' errors="0"'
    count += ' skipped="1"' if outcome == "skipped" else ' skipped="0"'
    result = f'<{outcome}>DO_NOT_ECHO_REPORT_MESSAGE</{outcome}>' if outcome else ""
    return (f'<testsuites><testsuite tests="{tests}"{count}>'
            '<testcase classname="host" name="allowed"/>'
            f'<testcase classname="host" name="DO_NOT_ECHO_CASE_NAME">{result}</testcase>'
            '</testsuite></testsuites>')


@pytest.fixture
def consumer(tmp_path):
    root = tmp_path / "consumer"
    (root / "assets").mkdir(parents=True)
    (root / "vendor").mkdir()
    (root / "app.py").write_text("print('application')\n", encoding="utf-8")
    (root / "assets/app.js").write_text("'use strict';\n", encoding="utf-8")
    (root / "vendor/toolkit.whl").write_bytes(b"fictional installed artifact")
    snapshot = evidence.capture_source(root, ["app.py", "assets/app.js"],
                                       artifacts=["vendor/toolkit.whl"])
    junit = tmp_path / "api.xml"
    junit.write_text(junit_text(), encoding="utf-8")
    browser = tmp_path / "browser.json"
    value = {"passed": True, "checks": ["DO_NOT_ECHO_BROWSER_LABEL", "another_check"],
             "source_sha256": deepcopy(snapshot["source_sha256"]),
             "diagnostic": "DO_NOT_ECHO_PRIVATE_DIAGNOSTIC"}
    browser.write_text(json.dumps(value), encoding="utf-8")
    return root, snapshot, junit, browser


def finish(consumer):
    root, snapshot, junit, browser = consumer
    return evidence.finish_evidence(root, snapshot, junit_path=junit, browser_path=browser)


def test_supplied_reports_bind_to_unchanged_explicit_source_and_artifact(consumer):
    root, snapshot, junit, browser = consumer
    receipt = finish(consumer)
    assert receipt["status"] == "passed" and receipt["errors"] == []
    assert receipt["source_unchanged"] is True and receipt["artifacts_unchanged"] is True
    assert receipt["counts"] == {"junit_cases": 2, "browser_checks": 2}
    assert set(snapshot["source_sha256"]) == {"app.py", "assets/app.js"}
    assert set(snapshot["artifact_sha256"]) == {"vendor/toolkit.whl"}
    assert all(len(value) == 64 for value in receipt["reports"].values())
    serialized = json.dumps(receipt)
    assert str(root) not in serialized and str(junit) not in serialized
    assert "DO_NOT_ECHO" not in serialized
    assert "binding" in receipt["scope"].lower()
    assert receipt["snapshot"] == snapshot
    # Results must not share mutable state with a caller's original snapshot.
    snapshot["source_sha256"].clear()
    assert receipt["snapshot"]["source_sha256"]


@pytest.mark.parametrize("change,code", [
    ("source_edit", "source_changed"), ("source_delete", "source_changed"),
    ("artifact_edit", "artifact_changed"),
])
def test_changed_or_missing_selected_bytes_refuse_passing_evidence(consumer, change, code):
    root, _, _, _ = consumer
    if change == "source_edit":
        (root / "app.py").write_text("different bytes", encoding="utf-8")
    elif change == "source_delete":
        (root / "app.py").unlink()
    else:
        (root / "vendor/toolkit.whl").write_bytes(b"replacement artifact")
    receipt = finish(consumer)
    assert receipt["status"] == "failed" and code in receipt["errors"]


@pytest.mark.parametrize("files", [[], ["app.py", "app.py"], ["missing.py"],
                                   ["../outside.py"], ["/outside.py"], ["C:/outside.py"]])
def test_snapshot_refuses_empty_duplicate_missing_or_escaping_selection(consumer, files):
    root, _, _, _ = consumer
    with pytest.raises(ValueError):
        evidence.capture_source(root, files)


def test_snapshot_refuses_symlink_escape(consumer, tmp_path):
    root, _, _, _ = consumer
    outside = tmp_path / "outside.py"
    outside.write_text("outside", encoding="utf-8")
    try:
        (root / "linked.py").symlink_to(outside)
    except OSError:
        pytest.skip("This Windows account cannot create test symlinks.")
    with pytest.raises(ValueError):
        evidence.capture_source(root, ["linked.py"])


def test_case_alias_selection_obeys_the_host_filesystem(consumer):
    root, _, _, _ = consumer
    (root / "APP.py").write_text("second case spelling", encoding="utf-8")
    if os.name == "nt":
        with pytest.raises(ValueError):
            evidence.capture_source(root, ["app.py", "APP.py"])
    else:
        snapshot = evidence.capture_source(root, ["app.py", "APP.py"])
        assert set(snapshot["source_sha256"]) == {"app.py", "APP.py"}


@pytest.mark.parametrize("mutation", ["empty_source", "invalid_digest"])
def test_finish_refuses_a_forged_or_incomplete_snapshot(consumer, mutation):
    root, snapshot, junit, browser = consumer
    altered = deepcopy(snapshot)
    if mutation == "empty_source":
        altered["source_sha256"].clear()
    else:
        altered["source_sha256"]["app.py"] = "not-a-sha256"
    with pytest.raises(ValueError):
        evidence.finish_evidence(root, altered, junit_path=junit, browser_path=browser)


@pytest.mark.parametrize("case,code", [
    ("failed", "junit_failed"), ("skipped", "junit_failed"),
    ("aggregate_mismatch", "junit_invalid"), ("empty", "junit_invalid"),
    ("doctype", "junit_invalid"), ("doctype_utf16", "junit_invalid"),
    ("not_run", "junit_failed"), ("skipped_result", "junit_failed"),
])
def test_junit_checks_actual_cases_and_refuses_failed_or_ambiguous_reports(consumer, case, code):
    _, _, junit, _ = consumer
    if case == "failed":
        text = junit_text(outcome="failure")
    elif case == "skipped":
        text = junit_text(outcome="skipped")
    elif case == "aggregate_mismatch":
        text = junit_text(tests=99)
    elif case == "empty":
        text = '<testsuite tests="2" failures="0" errors="0" skipped="0"/>'
    elif case == "not_run":
        text = '<testsuite tests="1"><testcase name="pending" status="notrun"/></testsuite>'
    elif case == "skipped_result":
        text = '<testsuite tests="1"><testcase name="pending" result="skipped"/></testsuite>'
    else:
        text = '<!DOCTYPE testsuite [<!ENTITY a "unsafe">]><testsuite><testcase name="&a;"/></testsuite>'
    if case == "doctype_utf16":
        junit.write_bytes(text.encode("utf-16"))
    else:
        junit.write_text(text, encoding="utf-8")
    receipt = finish(consumer)
    assert receipt["status"] == "failed" and code in receipt["errors"]
    assert "DO_NOT_ECHO" not in json.dumps(receipt)


@pytest.mark.parametrize("outcome", ["failure", "error", "skipped"])
def test_junit_refuses_namespaced_outcomes_instead_of_treating_them_as_passed(consumer, outcome):
    _, _, junit, _ = consumer
    junit.write_text(
        '<testsuite xmlns:result="urn:consumer-results" tests="1">'
        f'<testcase><result:{outcome}/></testcase></testsuite>', encoding="utf-8",
    )
    receipt = finish(consumer)
    assert receipt["status"] == "failed" and "junit_invalid" in receipt["errors"]


def test_junit_refuses_namespaced_status_attributes(consumer):
    _, _, junit, _ = consumer
    junit.write_text(
        '<testsuite xmlns:result="urn:consumer-results" tests="1">'
        '<testcase result:status="failed"/></testsuite>', encoding="utf-8",
    )
    receipt = finish(consumer)
    assert receipt["status"] == "failed" and "junit_invalid" in receipt["errors"]


def test_junit_refuses_excessive_nesting_before_suite_aggregation(consumer):
    _, _, junit, _ = consumer
    junit.write_text(
        '<testsuite>' * 5000 + '<testcase/>' + '</testsuite>' * 5000, encoding="utf-8",
    )
    receipt = finish(consumer)
    assert receipt["status"] == "failed" and "junit_invalid" in receipt["errors"]


def test_junit_node_budget_includes_non_testcase_elements(consumer, monkeypatch):
    _, _, junit, _ = consumer
    monkeypatch.setattr(evidence, "MAX_JUNIT_NODES", 10)
    junit.write_text(
        '<testsuite><testcase/>' + '<property name="x"/>' * 10 + '</testsuite>',
        encoding="utf-8",
    )
    receipt = finish(consumer)
    assert receipt["status"] == "failed" and "junit_invalid" in receipt["errors"]


@pytest.mark.parametrize("case,code", [
    ("empty", "browser_invalid"), ("duplicate", "browser_invalid"),
    ("failed", "browser_failed"), ("source_mismatch", "browser_source_mismatch"),
])
def test_browser_report_requires_nonempty_distinct_checks_and_exact_source(consumer, case, code):
    _, _, _, browser = consumer
    value = json.loads(browser.read_text(encoding="utf-8"))
    if case == "empty":
        value["checks"] = []
    elif case == "duplicate":
        value["checks"] = ["same", "same"]
    elif case == "failed":
        value["passed"] = False
    else:
        value["source_sha256"].pop("assets/app.js")
    browser.write_text(json.dumps(value), encoding="utf-8")
    receipt = finish(consumer)
    assert receipt["status"] == "failed" and code in receipt["errors"]
    assert "DO_NOT_ECHO" not in json.dumps(receipt)


def test_missing_reports_remain_failed_and_named_without_exception_details(consumer):
    _, _, junit, browser = consumer
    junit.unlink()
    browser.unlink()
    receipt = finish(consumer)
    assert receipt["status"] == "failed"
    assert {"junit_missing", "browser_missing"} <= set(receipt["errors"])
    assert receipt["reports"] == {"junit_sha256": None, "browser_sha256": None}


def test_json_loader_refuses_duplicate_fields(tmp_path):
    document = tmp_path / "duplicate.json"
    document.write_text('{"passed":false,"passed":true}', encoding="utf-8")
    with pytest.raises(ValueError):
        evidence.load_json(document)


def test_receipt_writer_never_overwrites_a_previous_result(tmp_path):
    destination = tmp_path / "receipt.json"
    evidence.write_json(destination, {"status": "failed"})
    before = destination.read_bytes()
    with pytest.raises(ValueError):
        evidence.write_json(destination, {"status": "passed"})
    assert destination.read_bytes() == before


def test_cli_captures_before_run_and_preserves_failed_drift_receipt(consumer, tmp_path):
    root, _, junit, browser = consumer
    baseline, receipt = tmp_path / "before.json", tmp_path / "after.json"
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    captured = subprocess.run([sys.executable, "-B", str(SCRIPT), "snapshot", "--root", str(root),
                               "--file", "app.py", "--file", "assets/app.js", "--artifact",
                               "vendor/toolkit.whl", "--output", str(baseline)],
                              capture_output=True, env=env, check=False)
    assert captured.returncode == 0
    (root / "app.py").write_text("changed after capture", encoding="utf-8")
    completed = subprocess.run([sys.executable, "-B", str(SCRIPT), "finish", "--root", str(root),
                                "--snapshot", str(baseline), "--junit", str(junit),
                                "--browser", str(browser), "--output", str(receipt)],
                               capture_output=True, env=env, check=False)
    assert completed.returncode == 1
    saved = json.loads(receipt.read_text(encoding="utf-8"))
    assert saved["status"] == "failed" and "source_changed" in saved["errors"]
    assert "DO_NOT_ECHO" not in completed.stdout.decode(errors="replace")
