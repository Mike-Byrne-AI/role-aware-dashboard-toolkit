"""Consumer checks against actual host actions and independently observed state.

This copyable example has no UI, database or test-framework dependency. It does
not supply authorization or establish that an adapter observes all protected
records. The host's test fixture must provide that observation independently of
the action's response. Results deliberately omit record values and exceptions.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import re
from typing import Callable, Iterable


REQUIRED_CASES = ("applied", "denied", "revoked", "frozen", "stale", "duplicate")
_CASES = frozenset((*REQUIRED_CASES, "invalid"))
_NAME = re.compile(r"[a-z][a-z0-9_-]{0,63}\Z")


@dataclass(frozen=True)
class ProtectedState:
    """Independent business-record and successful-change-history observations.

    Include all protected rows an action could affect, not only its return value.
    A separate security log may legitimately record denied attempts; exclude it
    from successful-change history and check its safe contents separately.
    """

    records: object
    history: object


@dataclass(frozen=True)
class ActionScenario:
    """One real action, its exact outcome, and its expected persisted effects.

    ``prepare`` arranges the test fixture before observation, for example by
    revoking a grant after a form was loaded. ``invoke`` must call the real host
    action even for rejection cases. ``observe`` must read independently of its
    response. For applied cases ``expected_after`` computes the complete expected
    state from a detached copy of the prior state; other cases require unchanged
    protected records and successful-change history. An expected exception is
    matched by exact class, never by message or broad subclass handling.
    """

    name: str
    case: str
    invoke: Callable[[], object]
    observe: Callable[[], ProtectedState]
    expected_exception: type[Exception] | None = None
    expected_after: Callable[[ProtectedState], ProtectedState] | None = None
    prepare: Callable[[], object] | None = None


@dataclass(frozen=True)
class ActionCheck:
    name: str
    case: str
    failures: tuple[str, ...] = ()

    @property
    def passed(self) -> bool:
        return not self.failures


@dataclass(frozen=True)
class AcceptanceReport:
    checks: tuple[ActionCheck, ...]
    missing_cases: tuple[str, ...] = ()
    configuration_errors: tuple[str, ...] = ()

    @property
    def passed(self) -> bool:
        return (bool(self.checks) and not self.missing_cases
                and not self.configuration_errors
                and all(check.passed for check in self.checks))


def _check(scenario: ActionScenario) -> ActionCheck:
    def failed(code: str) -> ActionCheck:
        return ActionCheck(scenario.name, scenario.case, (code,))

    try:
        if scenario.prepare is not None:
            scenario.prepare()
    except Exception:
        return failed("prepare_failed")
    try:
        before = deepcopy(scenario.observe())
        if not isinstance(before, ProtectedState):
            return failed("invalid_observation")
    except Exception:
        return failed("before_observation_failed")
    try:
        expected = (scenario.expected_after(deepcopy(before))
                    if scenario.expected_after is not None else before)
        if not isinstance(expected, ProtectedState):
            return failed("invalid_expectation")
        expected = deepcopy(expected)
        if scenario.case == "applied":
            if expected.records == before.records:
                return failed("applied_records_unchanged")
            if expected.history == before.history:
                return failed("applied_history_unchanged")
    except Exception:
        return failed("expectation_failed")

    failures = []
    try:
        scenario.invoke()
    except Exception as exc:
        if type(exc) is not scenario.expected_exception:
            failures.append("unexpected_exception")
    else:
        if scenario.expected_exception is not None:
            failures.append("expected_exception_missing")

    # Always observe after an invoked action, including an unexpected exception:
    # a rejected request can still have incorrectly changed the database.
    try:
        after = deepcopy(scenario.observe())
        if not isinstance(after, ProtectedState):
            failures.append("invalid_observation")
        elif after != expected:
            failures.append("state_mismatch")
    except Exception:
        failures.append("after_observation_failed")
    return ActionCheck(scenario.name, scenario.case, tuple(failures))


def run_acceptance(
    scenarios: Iterable[ActionScenario], *, required_cases: Iterable[str] = REQUIRED_CASES,
) -> AcceptanceReport:
    """Run all configured cases; an empty or incomplete suite cannot pass.

    Use the default required cases for consumer acceptance. A smaller explicit
    set is useful only for focused development. Configuration failures run no
    actions. Runtime failures are returned as stable codes without record dumps,
    exception messages or exception chains. Interrupts still propagate.
    """
    scenarios = tuple(scenarios)
    required = tuple(required_cases)
    errors = []
    if not required or any(not isinstance(case, str) or case not in _CASES for case in required):
        errors.append("invalid_required_cases")
    if not scenarios:
        errors.append("no_scenarios")
    names = set()
    for scenario in scenarios:
        if not isinstance(scenario, ActionScenario):
            errors.append("invalid_scenario")
            continue
        if not isinstance(scenario.name, str) or not _NAME.fullmatch(scenario.name):
            errors.append("invalid_scenario_name")
        elif scenario.name in names:
            errors.append("duplicate_scenario_name")
        if isinstance(scenario.name, str):
            names.add(scenario.name)
        if not isinstance(scenario.case, str) or scenario.case not in _CASES:
            errors.append("invalid_scenario_case")
        if not callable(scenario.invoke) or not callable(scenario.observe):
            errors.append("invalid_callback")
        if scenario.prepare is not None and not callable(scenario.prepare):
            errors.append("invalid_callback")
        if scenario.case == "applied":
            if scenario.expected_exception is not None or not callable(scenario.expected_after):
                errors.append("invalid_applied_expectation")
        else:
            exception = scenario.expected_exception
            if (not isinstance(exception, type) or not issubclass(exception, Exception)
                    or exception is Exception or scenario.expected_after is not None):
                errors.append("invalid_rejection_expectation")
    if errors:
        return AcceptanceReport((), (), tuple(dict.fromkeys(errors)))
    missing = tuple(sorted(set(required) - {scenario.case for scenario in scenarios}))
    return AcceptanceReport(tuple(_check(scenario) for scenario in scenarios), missing)
