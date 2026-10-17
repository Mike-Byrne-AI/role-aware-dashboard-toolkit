"""Consumer acceptance checks exercise effects, not a role/permission truth table."""

from dataclasses import replace
import json
import sqlite3
import time

import pytest

from examples.record_workflows.acceptance import (
    ActionScenario, ProtectedState, REQUIRED_CASES, run_acceptance,
)
from examples.record_workflows.actions import ActionConflict, ActionValidation
from examples.record_workflows.service import WorkItems
from role_aware_dashboard_toolkit.access import AccessDenied, Identity, principal_id


def _sqlite_observer(path):
    """Test-only access outside the service/action's response and authorization."""
    with sqlite3.connect(path) as connection:
        connection.row_factory = sqlite3.Row
        records = tuple(dict(row) for row in connection.execute("SELECT * FROM items ORDER BY id"))
        history = tuple({
            "id": row["id"], "item_id": row["item_id"], "action": row["action"],
            "actor": row["actor"], "reason": row["reason"],
            "before": json.loads(row["before_json"]), "after": json.loads(row["after_json"]),
        } for row in connection.execute("SELECT * FROM history ORDER BY id"))
        return ProtectedState(records, history)


def _sqlite_scenario(directory, case, action):
    key = b"synthetic-consumer-acceptance-key!"
    path = directory / f"{action}-{case}.sqlite3"
    service = WorkItems(path, identity_key=key)
    identities = {name: Identity("synthetic-consumer-test", name, time.time() + 600)
                  for name in ("manager", "operator", "viewer")}
    sessions = {}
    for name, role in (("manager", "Manager"), ("operator", "Operator"), ("viewer", "Viewer")):
        service.provision(identities[name], (role,))
        sessions[name] = service.open_session(lambda name=name: identities[name])
    service.change_freeze(sessions["manager"], "Manager", False, 0)
    original = service.create_item(label="Synthetic item", starts_at="2030-06-09T08:00:00-04:00")
    # Observing all rows catches unintended changes outside the selected item.
    service.create_item(label="Untouched item", starts_at="2030-06-09T09:00:00-04:00")
    item_id = original["id"]
    session, role = ((sessions["viewer"], "Viewer") if case == "denied"
                     else (sessions["operator"], "Operator"))
    reason = "Synthetic review"

    def invoke():
        if action == "reschedule":
            return service.reschedule(
                session, role, item_id, expected_revision=0,
                starts_at=("2030-06-10T08:00:00" if case == "invalid"
                           else "2030-06-10T08:00:00-04:00"), reason=reason,
            )
        return service.change_status(
            session, role, item_id, expected_revision=0,
            status="cancelled" if case == "invalid" else "completed",
            reason="" if case == "invalid" else reason,
        )

    def prepare():
        # Load while permitted, then alter the live state before the old form
        # submits. These are actual durable updates, not assumed outcomes.
        service.read(session, role, item_id)
        if case == "revoked":
            service.provision(identities["operator"], ())
        elif case == "frozen":
            state = service.freeze_state(sessions["manager"], "Manager")
            service.change_freeze(sessions["manager"], "Manager", True, state.revision)
        elif case == "stale":
            service.reschedule(
                sessions["manager"], "Manager", item_id, expected_revision=0,
                starts_at="2030-06-11T08:00:00-04:00", reason="Competing change",
            )
        elif case == "duplicate":
            invoke()

    def expected_after(before):
        changed = {**original, "revision": 1}
        if action == "reschedule":
            changed["starts_at"] = "2030-06-10T12:00:00+00:00"
        else:
            changed["status"] = "completed"
        records = tuple(changed if row["id"] == item_id else row for row in before.records)
        event = {
            "id": 1, "item_id": item_id,
            "action": "rescheduled" if action == "reschedule" else "status_changed",
            "actor": principal_id(identities["operator"], key), "reason": reason,
            "before": original, "after": changed,
        }
        return ProtectedState(records, (*before.history, event))

    exception = (None if case == "applied" else ActionValidation if case == "invalid"
                 else ActionConflict if case in {"stale", "duplicate"} else AccessDenied)
    return ActionScenario(
        name=f"{action}-{case}", case=case, invoke=invoke,
        observe=lambda: _sqlite_observer(path), prepare=prepare,
        expected_exception=exception,
        expected_after=expected_after if case == "applied" else None,
    )


@pytest.mark.parametrize("action", ("reschedule", "status"))
def test_consumer_acceptance_checks_real_sqlite_records_and_history(tmp_path, action):
    scenarios = [_sqlite_scenario(tmp_path, case, action) for case in (*REQUIRED_CASES, "invalid")]
    report = run_acceptance(scenarios)
    assert report.passed, report
    assert len(report.checks) == 7
    assert all(check.passed for check in report.checks)
    # Results never contain the synthetic identities or the observed records.
    assert "Synthetic item" not in repr(report)
    assert "synthetic-consumer-test" not in repr(report)


def _denial(*, invoke=None, observe=None, prepare=None):
    def denied():
        raise AccessDenied()
    return ActionScenario(
        "viewer-denied", "denied", invoke or denied,
        observe or (lambda: ProtectedState(("unchanged",), ())),
        expected_exception=AccessDenied, prepare=prepare,
    )


def _run(scenario):
    return run_acceptance([scenario], required_cases=(scenario.case,))


def test_empty_and_incomplete_suites_do_not_pass():
    empty = run_acceptance([])
    assert not empty.passed
    assert empty.configuration_errors == ("no_scenarios",)
    incomplete = run_acceptance([_denial()])
    assert not incomplete.passed
    assert set(incomplete.missing_cases) == set(REQUIRED_CASES) - {"denied"}
    assert incomplete.checks[0].passed


def test_rejection_action_is_invoked_and_faulty_mutation_is_detected():
    state = ProtectedState(records=["original"], history=[])
    calls = []

    def faulty_action():
        calls.append("invoked")
        state.records.append("unauthorized")
        raise AccessDenied()

    report = _run(_denial(invoke=faulty_action, observe=lambda: state))
    assert calls == ["invoked"]
    assert not report.passed
    assert report.checks[0].failures == ("state_mismatch",)


def test_sqlite_adapter_that_mutates_before_denial_fails_acceptance(tmp_path):
    scenario = _sqlite_scenario(tmp_path, "denied", "reschedule")
    original_invoke = scenario.invoke
    path = tmp_path / "reschedule-denied.sqlite3"

    def faulty_adapter():
        with sqlite3.connect(path) as connection:
            connection.execute("UPDATE items SET label = 'Unauthorized mutation'")
        original_invoke()

    report = _run(replace(scenario, invoke=faulty_adapter))
    assert not report.passed
    assert report.checks[0].failures == ("state_mismatch",)


def test_denial_that_adds_successful_change_history_fails():
    state = ProtectedState([], [])

    def faulty_action():
        state.history.append("a change that did not happen")
        raise AccessDenied()

    report = _run(_denial(invoke=faulty_action, observe=lambda: state))
    assert report.checks[0].failures == ("state_mismatch",)


def test_expected_denial_cannot_be_replaced_by_a_return_value():
    report = _run(_denial(invoke=lambda: "denied"))
    assert not report.passed
    assert report.checks[0].failures == ("expected_exception_missing",)


@pytest.mark.parametrize("exception", (ValueError, RuntimeError, type("OtherDenial", (AccessDenied,), {})))
def test_only_the_exact_declared_exception_is_accepted(exception):
    def unrelated_failure():
        raise exception("private-exception-detail")

    report = _run(_denial(invoke=unrelated_failure))
    assert not report.passed
    assert report.checks[0].failures == ("unexpected_exception",)
    assert "private-exception-detail" not in repr(report)


def test_state_is_observed_even_after_an_unexpected_exception():
    state = ProtectedState([], [])

    def failed():
        state.records.append("should-have-rolled-back")
        raise RuntimeError("private-error")

    report = _run(_denial(invoke=failed, observe=lambda: state))
    assert report.checks[0].failures == ("unexpected_exception", "state_mismatch")


def test_applied_case_checks_record_and_history_not_just_success_return():
    state = ProtectedState([], [])

    def missing_history():
        state.records.append("saved")
        return True

    scenario = ActionScenario(
        "missing-history", "applied", missing_history, lambda: state,
        expected_after=lambda before: ProtectedState(["saved"], ["saved once"]),
    )
    report = _run(scenario)
    assert report.checks[0].failures == ("state_mismatch",)


@pytest.mark.parametrize("expected,code", (
    (ProtectedState([], ["event"]), "applied_records_unchanged"),
    (ProtectedState(["record"], []), "applied_history_unchanged"),
))
def test_applied_expectation_must_describe_both_effects(expected, code):
    called = []
    scenario = ActionScenario(
        "invalid-success", "applied", lambda: called.append(True),
        lambda: ProtectedState([], []), expected_after=lambda before: expected,
    )
    assert _run(scenario).checks[0].failures == (code,)
    assert not called


def test_expectation_receives_a_detached_copy():
    state = ProtectedState([], [])

    def expected(before):
        before.records.append("saved")
        before.history.append("saved once")
        return before

    def applied():
        assert state == ProtectedState([], [])
        state.records.append("saved")
        state.history.append("saved once")

    scenario = ActionScenario("detached", "applied", applied, lambda: state, expected_after=expected)
    assert _run(scenario).passed


@pytest.mark.parametrize("stage,code", (
    ("prepare", "prepare_failed"), ("before", "before_observation_failed"),
    ("after", "after_observation_failed"), ("expectation", "expectation_failed"),
))
def test_fixture_errors_have_safe_codes_and_do_not_expose_values(stage, code):
    observations = []

    def private_failure(*args):
        raise RuntimeError("private-token-and-record")

    def observe():
        observations.append(True)
        if stage == "before" or (stage == "after" and len(observations) == 2):
            private_failure()
        return ProtectedState([], [])

    scenario = _denial(observe=observe, prepare=private_failure if stage == "prepare" else None)
    if stage == "expectation":
        scenario = replace(scenario, case="applied", expected_exception=None, expected_after=private_failure)
    report = _run(scenario)
    assert report.checks[0].failures == (code,)
    assert "private-token-and-record" not in repr(report)


@pytest.mark.parametrize("changes,error", (
    ({"name": "invalid name"}, "invalid_scenario_name"),
    ({"case": "unknown"}, "invalid_scenario_case"),
    ({"invoke": None}, "invalid_callback"),
    ({"prepare": False}, "invalid_callback"),
    ({"expected_exception": Exception}, "invalid_rejection_expectation"),
    ({"expected_exception": None}, "invalid_rejection_expectation"),
    ({"expected_after": lambda before: before}, "invalid_rejection_expectation"),
    ({"case": "applied"}, "invalid_applied_expectation"),
))
def test_invalid_configuration_runs_no_actions(changes, error):
    called = []
    scenario = replace(_denial(invoke=lambda: called.append(True)), **changes)
    report = run_acceptance([scenario])
    assert not report.passed
    assert error in report.configuration_errors
    assert not called


def test_duplicate_names_and_empty_required_case_set_are_configuration_errors():
    report = run_acceptance([_denial(), _denial()], required_cases=())
    assert set(report.configuration_errors) == {"invalid_required_cases", "duplicate_scenario_name"}
    assert not report.passed


def test_one_failed_case_does_not_hide_later_checks():
    first = _denial(invoke=lambda: "incorrect success")
    second = replace(_denial(), name="actual-denial")
    report = run_acceptance([first, second], required_cases=("denied",))
    assert not report.passed
    assert [check.passed for check in report.checks] == [False, True]


def test_interrupt_is_not_reported_as_an_expected_denial():
    def interrupted():
        raise KeyboardInterrupt()
    with pytest.raises(KeyboardInterrupt):
        _run(_denial(invoke=interrupted))
