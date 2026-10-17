# Build protected record workflows

Use this recipe when adding record editing, rescheduling, status changes or
staff assignment to a host application. The toolkit provides access policy and
dashboard components. Your host owns the records, business rules, verified
session, database transaction and durable change history.

These are implementation patterns, not new built-in CRUD widgets or a stable
record-service API. The source checkout includes the copy-and-adapt
`examples/record_workflows` SQLite service and acceptance runner. Those Python
examples ship in the source distribution, not as importable wheel modules. Do
not assume `examples` is present after installing a wheel.

## Start from the installed version

Use the same Python interpreter that runs the dashboard:

```powershell
python -m role_aware_dashboard_toolkit inspect --format json
python -m role_aware_dashboard_toolkit guide workflows
python -m role_aware_dashboard_toolkit guide authentication
```

For a developer or Codex, first identify the existing route/callback, verified
identity resolver, record repository and test fixture. Read the project's own
instructions. Define the desired action and acceptance cases before editing.
Installed guidance describes this toolkit version; it does not authorize
changes to a project or replace its business rules. Preserve existing APIs and
use the host's UI framework. Streamlit controls do not drop into a JavaScript
frontend, and disabled buttons do not enforce access.

## The protected-change boundary

1. Parse bounded inputs and a nonnegative integer `expected_revision`. The
   browser submits record identifiers and proposed values, never a trusted
   actor, permission decision, history entry or replacement revision.
2. Begin the host's write transaction. Resolve the current verified identity,
   check live role grants and shared freeze, then load the permitted record.
   Loading private data must also enforce access.
3. Compare the current revision with the revision the form originally loaded.
   A mismatch returns a conflict even if a requested value happens to match.
4. Derive changes with side-effect-free business validation. Use a separate
   required reason when the action calls for one. Validate foreign identifiers,
   status transitions and dates on the server.
5. Recheck current authority immediately before the write. Reject a changed
   account as well as revoked permission or frozen writes. Update only the
   allowed fields using a revision-checked write; the server increments the
   revision.
6. Write the safe before/after history and actor in the same transaction. If
   validation, the final write or history persistence fails, roll back the
   business change. Respond only after committing.

Every path that changes grants, freeze and protected records must participate
in the chosen coordination mechanism. A separate `SQLiteAccessStore` database
does not make business writes in another connection atomic. The example uses
one SQLite transaction for its access rows, record and change history. Its
savepoint helper requires trusted callbacks to use that same connection, not
commit early and perform no external side effects. It cannot enforce those
constraints on arbitrary host code.

A record revision rejects an old repeated submission; it is not a general
idempotency token for payments, email or queued jobs. External effects require
their own authorization, ownership and retry strategy, such as a transactional
outbox. Do not send them from a validator or database save callback.

## Recipe: reschedule a record

Load the record and its revision into an edit form. Show its current date,
time and time zone beside the proposed date. Define whether your application
stores an instant or a local appointment; do not silently interpret a browser's
time zone as the business time zone. For local appointments, handle ambiguous
and nonexistent daylight-saving times explicitly.

Validate the allowed date range and record state. If overlap checks depend on
current assignments or availability, query and validate those rows inside the
host transaction and coordinate every other writer that can affect them. The
toolkit cannot infer which overlaps are forbidden. Decide whether a conflict is
an error or a warning requiring an explicit override reason.

The source service's `reschedule` method demonstrates a scheduled item, an
offset-aware timestamp normalized to UTC, a revision check and an atomic
history entry. It does not implement employee availability or overlap rules.

## Recipe: complete or cancel a record

Write an explicit allowed-transition table in the host. Separate status from
archive visibility: hiding a record does not establish that work completed.
Show the target status and affected record in a confirmation. Require a bounded
reason for cancellation; preserve the user's draft if validation fails.

Reuse the same protected-change boundary for the transition. The example
allows `scheduled` to become `completed` or `cancelled`, requires a reason
for cancellation, and permits reopening either state as `scheduled`. Its
`WorkItemRules` makes these choices explicit. Whether reopening is permitted,
assignments remain visible or totals change is application policy. Audit the actual committed transition,
not the user's click. A retry using the old revision must not add another
successful-change entry.

## Recipe: edit or link a customer record

Use the same boundary with an allowlist of editable fields and separate read
and edit permissions. Validate referenced customer/site identifiers against
the current actor's scope inside the transaction; a dropdown's contents are
not an authorization rule. A customer selected in one tab can become disabled
or inaccessible before submission.

Choose field-specific bounds and normalizations. Display names are text, not
HTML; notes and access instructions may be sensitive. Store only the minimum
safe history needed for accountability. Redaction after logging a full customer
object is too late. The generic example has no customer schema: define one in
the application instead of treating this recipe as a supplied CRM.

## Form and history patterns

- Use visible labels for date, time, time zone and reason. Connect inline
  validation to each control and focus the first error after submission.
- For crew selection, show readable employee names, selected crew and capacity
  together. A real multi-select or labelled checkboxes must support keyboard
  operation. Submit stable IDs and validate active, permitted employees on the
  server. A hidden input or a caller-supplied name cannot grant access.
- For consequential status changes, removal or a conflict override, provide a
  review step showing the selected record, current values, proposed values and
  reason before confirmation. Editing any field invalidates that review. An
  override needs a clear acknowledgement; never treat an ordinary **Save** as
  permission to bypass a new server warning.
- On a stale revision, retain the draft and show a clear conflict with **Reload
  latest** and **Cancel editing**. Do not silently attach a new revision to an
  old draft or automatically retry a destructive action. After reload, require
  the person to review and submit the intended changes again.
- Disable submission while a request is pending and announce success or failure
  accessibly. This improves usability; the server still checks duplicate and
  stale requests. After success, replace the displayed record and revision with
  the server's committed result.
- Show history as who changed what, when and why, with localized times and
  bounded plain text. Do not expose credentials, private provider claims or
  unrestricted record dumps. A failed attempt belongs in a separate security
  log, not in successful business-change history.
- Use stacked form groups on narrow screens. Keep save/cancel buttons reachable,
  labels readable, focus visible and confirmation content scrollable. Check
  long names and validation text as well as the default happy path.

## Consumer acceptance

Test the actual host action and independently observe the persisted records and
successful-change history before and after it. Required cases are an allowed
change, an unpermitted caller, revoked access after loading a form, frozen
writes, a stale revision and a duplicate submission. Also test invalid input,
account switching and failure to write history where relevant.

The source example's `acceptance.py` provides `ActionScenario`, `ProtectedState`
and `run_acceptance`. It invokes each action, matches an exact expected exception
class and checks the complete expected state. Applied cases must change both
records and history; rejected cases must preserve both. Empty or missing-case
suites fail. Its reports contain scenario names and failure codes, not exception
messages or record values. A truthful independent observer and meaningful
scenario setup remain the host test author's responsibility.

Use two browser sessions to verify that the second editor sees a conflict,
keeps their draft and cannot overwrite the first editor's change. Test the
form, reason validation, status display and history on desktop and a narrow
touch viewport, then complete the workflow using only the keyboard. Assert the
server result as well as the screen. UI checks do not replace direct denied
request tests.

For shared hosting and recovery, run
`python -m role_aware_dashboard_toolkit guide deployment`. Verify login, account
revocation, restart, migration, restore and rollback against the actual host and
the exact installed artifact. MFA configuration, protected backups, monitoring
and a restore drill belong to the operator; this recipe does not automate them.
