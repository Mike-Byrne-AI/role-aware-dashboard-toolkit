# Add protected record actions

Record editing repeatedly needs the same safeguards: current permission,
validation, stale-edit detection, an atomic save and an attributable history
entry. The [record workflow example](../examples/record_workflows/README.md)
shows those safeguards shared by rescheduling and status changes in a small
SQLite service. Adapt the example in the host application; these helpers are
not a new stable toolkit API.

The complete implementation and UI recipes are also available offline:

```powershell
python -m role_aware_dashboard_toolkit inspect --format json
python -m role_aware_dashboard_toolkit guide workflows
```

Run these with the application's Python interpreter, so developers and Codex
read the installed version's capabilities. The
[workflow guide](../role_aware_dashboard_toolkit/resources/guides/workflows.md)
covers rescheduling, completion/cancellation, customer record editing,
accessible forms and browser acceptance. The source examples are included in
the source distribution; installing only the wheel does not install the
`examples` package.

## Reuse the change boundary

The example separates three responsibilities:

| Part | Responsibility |
| --- | --- |
| `actions.execute_change` | Require an existing transaction, check revision, derive allowed changes, recheck authority and roll back record/history together on failure |
| `service.WorkItems` | Own verified sessions, permissions, SQLite access/business/history rows and domain rules |
| Host UI or API | Parse requests, show accessible forms, preserve drafts and handle success, validation and conflict responses |

In [service.py](../examples/record_workflows/service.py), both `reschedule` and
`change_status` use the same `_change` boundary. To add another action:

1. Define editable fields, permission, expected revision and bounded inputs.
2. Make a pure proposal function that derives allowed field changes from the
   current record. Read related business rows through the same transaction if
   the decision depends on them; coordinate their other writers too.
3. Supply the repository's revision-checked write and safe history insertion,
   both using the same connection as authorization. Callbacks may not commit,
   launch jobs, send messages or perform unrelated writes.
4. Exercise the real action with the consumer checks below and test the screen
   that calls it.

An old revision remains a conflict even when its desired value already matches.
A valid no-op at the current revision returns `changed=False` without a new
revision or successful-change event. Authorization and freeze still apply.
Revision checks prevent stale overwrites and repeats of an old submission;
external effects need their own retry and idempotency design.

## Check actual effects

[acceptance.py](../examples/record_workflows/acceptance.py) supplies a small
dependency-free runner for host-owned test fixtures. It calls the actual host
action, then checks the exact expected outcome and independently observed
business records and successful-change history. It does not infer access
denial from a role name, hidden button or precomputed policy table.

Use `ActionScenario` with these fields:

| Field | Meaning |
| --- | --- |
| `name` | Stable lowercase scenario identifier; never personal data |
| `case` | `applied`, `denied`, `revoked`, `frozen`, `stale`, `duplicate`, or optional `invalid` |
| `prepare` | Optional trusted fixture setup performed before the first observation |
| `invoke` | The actual service method or request; rejection cases must invoke it too |
| `observe` | Independent committed-state read returning `ProtectedState(records, history)` |
| `expected_exception` | Exact exception class for rejection; `None` for an applied change |
| `expected_after` | For an applied change, compute the complete expected state from a detached copy of the prior state |

The default required cases are `applied`, `denied`, `revoked`, `frozen`, `stale`
and `duplicate`. Applied cases must change records and successful-change
history. Rejected cases require both to remain unchanged. A valid no-op should
have its own direct regression test; it is not the applied-change acceptance
case. A separate security log can record denied attempts: do not confuse it
with committed business-change history.

For a single denial regression in an existing synthetic fixture:

```python
from examples.record_workflows.acceptance import (
    ActionScenario, ProtectedState, run_acceptance,
)
from role_aware_dashboard_toolkit.access import AccessDenied

# These host fixture functions independently read committed synthetic records
# and successful-change history. They do not inspect an action response.
def observe():
    return ProtectedState(read_test_records(), read_test_history())

scenario = ActionScenario(
    name="viewer-reschedule", case="denied",
    invoke=lambda: service.reschedule(
        viewer_session, "Viewer", item_id,
        expected_revision=loaded_revision,
        starts_at="2030-06-10T08:00:00-04:00",
    ),
    observe=observe,
    expected_exception=AccessDenied,
)
report = run_acceptance([scenario], required_cases=("denied",))
assert report.passed
```

This is fixture pseudocode: create the synthetic service, identities, item and
independent observation functions in your test. The smaller `required_cases`
set is for this focused regression only. Full consumer acceptance uses the
defaults and includes all six cases. In a repository checkout,
`tests/test_action_acceptance.py` provides a complete SQLite example that
queries stored rows independently and detects a faulty adapter that mutates
before denying access. Contributor tests are not included in the source package.

For revocation, load the form while the user is permitted, revoke that user's
grant, then call the action with the old form. For stale edits, another actor
must commit a competing change first. For duplicate submission, save once and
submit the same old revision again. Freeze after form loading. Use a separate
trusted observer so denial does not prevent the test from inspecting the
database. Observe every row the action could affect, not only the selected
record, and exclude only fields with an explicitly justified normalization.

The runner deep-copies observations to detect in-place mutation. It returns
only scenario identifiers, case names and failure codes; no record values or
exception messages. It still requires truthful fixture adapters, meaningful
business expectations and isolated test data. It does not certify a host's
authentication provider or all possible races.

From the repository root, run the example acceptance checks in PowerShell:

```powershell
$env:PYTHONDONTWRITEBYTECODE = "1"
.\.venv\Scripts\python.exe -m pytest tests/test_action_acceptance.py -q
```

On Linux or macOS, set `PYTHONDONTWRITEBYTECODE=1` and use
`.venv/bin/python`. The tests use temporary SQLite databases and synthetic
identities; no provider credentials or optional UI dependencies are required.

## Verify the interaction and operating environment

Use the workflow guide's date/time, crew selection, conflict/reload,
confirmation/reason and history patterns in the application's own frontend.
For each new screen, exercise desktop and narrow touch layouts, keyboard-only
editing, long labels, server validation, a pending request and two simultaneous
editors. Keep a stale draft visible without silently changing its revision.
Assert the saved server state as well as the displayed result.

The toolkit's Streamlit starter and browser smoke are useful reference
interactions. They do not supply JavaScript components or cover another host's
routes. Run that host's own browser and direct-request checks.

Before inviting users, follow the
[deployment and recovery acceptance recipe](../role_aware_dashboard_toolkit/resources/guides/deployment.md)
with the actual provider, installed artifact and persistence configuration.
MFA, backups, a tested restore, monitoring and rollback remain operator work;
an example service or successful unit suite does not establish their readiness.
