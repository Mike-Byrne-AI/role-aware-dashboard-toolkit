# Record workflows: protected changes with durable history

This example makes two kinds of business change share a small, testable recipe:
rescheduling a work item and changing its status. A SQLite transaction connects
the toolkit's existing `AccessPolicy` to current grants, freeze, record revisions
and before/after audit history. It is source you can copy and adapt, **not a new
installed core API, authentication provider or workflow engine**.

The example uses synthetic identities and fictional records. Constructing an
`Identity` does not verify anyone. A real host must supply its currently verified
identity, protect sessions and storage, and define its own business rules.

## Run the small durable example

From the repository root, after following [Contributing](../../CONTRIBUTING.md):

```powershell
$env:PYTHONDONTWRITEBYTECODE = "1"
.\.venv\Scripts\python.exe -m examples.record_workflows.demo
```

On Linux or macOS:

```bash
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m examples.record_workflows.demo
```

The demo reschedules, completes and cancels synthetic items, then opens a new
service against the same database and checks the saved records and three audit
entries. It uses only the Python standard library and toolkit core. Its database
lives in a temporary directory and is removed when the process exits. There is
no login, listener, real customer data or connection to an external provider.

## Try the administration screen

Install the `workbench` extra described in the contributing guide, then launch
the local screen from the repository root. On Windows, use PowerShell:

```powershell
$env:PYTHONDONTWRITEBYTECODE = "1"
.\.venv\Scripts\python.exe -m streamlit run examples/record_workflows/app.py --server.address=127.0.0.1
```

On Linux or macOS:

```bash
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m streamlit run examples/record_workflows/app.py --server.address=127.0.0.1
```

Open the local URL printed by Streamlit in a browser on the **same computer**.
Stop the server with Ctrl+C. A remote/cloud machine needs supported forwarding
before its local server can be reached from another computer.

The screen starts as a synthetic Manager with changes paused. Use **Resume
changes** in the sidebar, choose a work item and edit its date/time in UTC.
Schedule and status forms require a reason; status changes also require a review
checkbox. The change history shows the saved before/after fields. A record that
changes while you edit keeps your draft and asks you to **Reload latest record**
before retrying. Switching the demo account clears the prior account's draft;
Viewer controls remain read-only. On a phone, open the sidebar to switch accounts
or pause/resume changes.

The account selector simulates separate accounts and grants no real identity.
Every browser session creates its own temporary database and fictional items;
the screen is a local interaction example, not a shared deployed application or
durable workspace. Adapt the service to host-owned storage and verified sign-in
before sharing it. The browser smoke exercises schedule/status changes, reason
history, account changes, freeze and layout on desktop and mobile; it does not
test an identity provider.

## What is reusable

| Source | Responsibility |
| --- | --- |
| [actions.py](actions.py) | Validate revision/reason, prepare a change, recheck the same actor, compare and save, audit or roll back |
| [service.py](service.py) | Concrete SQLite tables, transaction ownership, live `AccessPolicy` adapter, reschedule/status domain rules |
| [demo.py](demo.py) | Synthetic trusted setup and durable round trip |
| [app.py](app.py) | Runnable schedule/status administration screen with reason, confirmation and history |
| [acceptance.py](acceptance.py) | Host-supplied acceptance scenarios that compare protected records and history before and after actions |

`actions.py` has no toolkit or host dependency beyond Python's SQLite module.
The service demonstrates how to connect it to the toolkit. The host remains
responsible for choosing which fields can change and which fields are safe to
retain in audit history; never pass raw account records, provider claims, tokens
or secrets as the loaded/audited record.

The service uses these defaults:

- `Viewer` can read; `Operator` can read and edit; `Manager` can also manage
  freeze and read change history. A submitted role name supplies no grant.
- All new databases start frozen. A manager can unfreeze with the current
  freeze revision. Trusted `provision` supplies grants; an empty list revokes.
- A scheduled item can be completed or cancelled. Cancellation requires a
  reason. Completed/cancelled items can be reopened to `scheduled`; they must
  be reopened before rescheduling.
- Schedules require an ISO date/time with an explicit UTC offset and are
  normalized to UTC with seconds precision. These rules do not implement
  holidays, availability, time-zone display or assignment overlap detection.
- Trusted `WorkItemRules` configuration can change the allowed status pairs,
  states that require a reason and states that can be rescheduled.

`create_item` and `provision` are **trusted setup operations**, not user-facing
endpoints. Build separate protected actions before exposing either in an app.

## Adapt an action

The host owns a transaction around all action callbacks:

```python
from examples.record_workflows.actions import execute_change

# Integration pseudocode: these callbacks and transaction manager are supplied
# by your host. Never accept them, the actor, or permission rules from a browser.
with host_database.write_transaction() as connection:
    result = execute_change(
        connection=connection,
        expected_revision=submitted_revision,
        authorize=resolve_and_authorize_current_actor,
        load=load_selected_business_fields,
        propose=validate_and_propose_field_updates,
        save=compare_and_save_on_this_connection,
        audit=append_history_on_this_connection,
        reason=submitted_reason,
        require_reason=True,
    )
```

Use [service.py](service.py) for runnable definitions of the callbacks.

1. `authorize()` resolves the **current verified account**, checks live assigned
   roles and freeze, and returns its stable principal ID or raises. A browser
   role picker, hidden button or cached permission object is insufficient.
2. `load()` returns a selected business record with a strict integer `revision`.
   An old submitted revision raises `ActionConflict`, including a replay whose
   requested values already match the newer record.
3. `propose(record)` validates domain rules and returns updates to existing
   fields. It receives a copy and must not write, mutate authorization, start
   jobs or contact another service. The helper rejects revision changes and
   unknown fields; the host's proposal code must whitelist editable fields
   and protect identifiers and ownership.
4. The helper reauthorizes immediately before saving and requires the same
   actor as its first check. A valid no-op still checks authority, then returns
   `changed=False` without incrementing revision, saving or auditing.
5. `save(after, previous_revision)` performs a compare-and-set update and
   returns exactly `True` only if one record was saved. The helper increments
   the revision once. A failed compare-and-set raises `ActionConflict`.
6. `audit(result)` persists the selected before/after fields, checked actor and
   normalized reason on the same connection. Both the record and any partial
   audit inserts roll back on failure, even if the caller catches the error
   inside its outer transaction.

Reasons are plain text, trimmed and limited to 500 characters. Line feeds and
tabs are permitted; other characters below U+0020 are rejected. Render reasons
as text in the host UI, never as trusted HTML. A required reason is checked even
for a no-op request.

`ChangeResult` describes a pending transaction result. It becomes durable only
when the **outer transaction commits**; do not announce success before then.

## What the transaction guarantees, and what it cannot

Every service operation uses `BEGIN IMMEDIATE`, including grants and shared
freeze updates. Independent SQLite connections on the same local database
therefore serialize current authorization with record changes. The helper also
uses a savepoint so a failing history write cannot leave its business update
partially committed.

This guarantee depends on the host contract. All callbacks are trusted code,
must use that connection, and must not commit, roll back or bypass it. The helper
checks for an active transaction but cannot prove its mode or police arbitrary
callbacks. Keep grants, freeze, business writes and audit in the coordinated
database; replacing a store on another connection does not provide the same
atomicity. Other processes must use the same boundary. This is a single-host,
local-disk example, not distributed locking or a network-filesystem design.

Host identity-provider revocation and in-memory session changes remain external
to SQLite: the final authorization check cannot cancel an effect already in
progress. Session objects bind one actor, reject an observed account switch,
and must be closed/discarded on every login/logout transition, including a fresh
login to the same account. The real host must implement expiry and verification.

Emails, notifications and external jobs cannot be rolled back by a database
savepoint. Add a transactional outbox or another explicit delivery/idempotency
design before connecting such effects. A successful action replay conflicts;
this example does not implement durable request IDs or return a cached response
after a client loses its connection.

The reference does not set production filesystem permissions, verify HTTPS or
CSRF, provide schema migration/backup/recovery machinery, or audit its trusted
setup methods. Those remain host responsibilities. See the
[host integration example](../host_integration/README.md) for deferred intents
and session cleanup, and the
[deployment guide](../../role_aware_dashboard_toolkit/resources/guides/deployment.md)
for operational acceptance.

## Check behavior at the real effect

```powershell
$env:PYTHONDONTWRITEBYTECODE = "1"
.\.venv\Scripts\python.exe -m pytest tests/test_record_workflow_example.py -q
.\.venv\Scripts\python.exe -m pytest tests/test_action_acceptance.py -q
```

The tests inspect business rows and history after denials, revocation, freeze,
account changes, expiry, invalid inputs, stale requests and audit failures. They
also race two independent SQLite connections: one save succeeds and the stale
request conflicts. The same helper handles schedule and status changes. These
checks exercise actual writes and rollback, not merely button visibility.
The [implementation recipes](../../docs/record_workflows.md) connect these pieces
to additional business actions and describe the reusable acceptance runner.
