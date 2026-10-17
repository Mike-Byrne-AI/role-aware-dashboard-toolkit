# Host integration: protected notes and deferred saves

This small, dependency-free example connects a host-verified identity to the
toolkit's `AccessPolicy`, then protects actual note reads and writes. It is a
service layer you can call from a UI or API. It does not start a server, accept
passwords, verify provider tokens or create accounts.

The runnable [demo.py](demo.py) uses **synthetic identities only**. Manufacturing
an `Identity` object is not authentication. The demo has no network listener and
keeps all notes, grants and sessions in memory; stopping it discards everything.

## Run the example

From the repository root, use the environment described in
[Contributing](../../CONTRIBUTING.md#development-setup):

```powershell
$env:PYTHONDONTWRITEBYTECODE = "1"
.\.venv\Scripts\python.exe -m examples.host_integration.demo
```

On Linux or macOS, use `export PYTHONDONTWRITEBYTECODE=1` and
`.venv/bin/python -m examples.host_integration.demo`. Only the toolkit's core is
needed; Streamlit, FastAPI and pandas are not imported.

The demo saves one note, shows that another account cannot read it, and rejects
deferred saves after an account switch, grant revocation and shared freeze.
These are actual in-memory effects and denials, not button-visibility checks.

## Connect a verified host session

[service.py](service.py) owns the business records and their protection. The
host supplies a resolver that reads its **currently verified** authentication:

```python
from examples.host_integration.service import HostNotes

# Load this application's protected, random identity key in trusted host code.
notes = HostNotes(identity_key=host_identity_key)

# This callback is implemented by your trusted authentication integration.
# It returns Identity only after verifying the current account, or None.
session = notes.open_session(resolve_current_verified_identity)

# This example's permitted role names are Reader, Writer and Manager.
# A submitted role name selects a role; it never grants it.
visible_notes = notes.read_notes(session, selected_role)
ticket = notes.stage_note(session, selected_role, "A proposed note")

# Later: after a confirmation, rerun, or deferred callback.
notes.commit_note(session, selected_role, ticket)
```

This is integration pseudocode: the host variables are deliberately not a
login implementation. Construct one service per process and one `HostSession`
per verified host session. Do not share a session object between users or build
one from submitted claims. Connect an existing authenticated app using the
[authentication guide](../../role_aware_dashboard_toolkit/resources/guides/authentication.md)
or [authenticated starter](../../role_aware_dashboard_toolkit/resources/authenticated_starter/README.md).

Trusted operator code calls `provision(verified_identity, roles)` to replace
assignments; an empty role list revokes access. This method is not a visitor
endpoint. All new services start with no grants and freeze enabled. `Manager`
can call `change_freeze` with the current revision from `freeze_state`; stale
revisions raise `FreezeConflict`. Readers and writers cannot manage freeze.

| Boundary | What the example enforces |
| --- | --- |
| Protected read | Re-resolve identity and live grants before fetching only that actor's notes |
| Staged save | Validate permission and text; retain actor, role, text and expiry on the server |
| Actual save | Recheck identity, role and freeze; consume a matching, unexpired session ticket once |
| Forged role or actor | Role must be assigned; record ownership always comes from the checked principal |
| Account change or denied access | Clear old pending work and cached reads before proceeding |
| Host sign-out | Call `session.close()` before provider logout; discard it and create a new session after fresh verified login |

A ticket is an opaque lookup ID, not an authorization token. It cannot be used
from another session, substituted with client-owned note/actor fields, or
replayed after completion. Pending intents expire after five minutes and each
session holds at most eight. Changing accounts with the same role still clears
the old state. Call `close()` at every host logout/login transition, including a
new login to the same account: polling an identity alone cannot detect a switch
away and back that the host never reports.

## Transaction and deployment limits

Every operation, grant update and freeze update in this example participates in
one process-local lock. It serializes those in-memory changes with the final
permission check and note append. Keep the underlying store private; direct
store access would bypass that coordination. The lock has no cross-process or
distributed effect, provides no durable rollback, and cannot stop independent
provider revocation or cancel an external request already in flight.

For a real database, the host must put current authorization and the actual
business read/write in an appropriate shared transaction or otherwise define
its consistency behavior. Merely replacing `InMemoryAccessStore` with
`SQLiteAccessStore` does not make a separate business write atomic with grants.
External jobs need their own cancellation, idempotency and result-ownership
checks. A browser/API host also owns session verification, CSRF, request
validation, transport protection, protected storage and operational recovery.

For section navigation and actual OIDC configuration, see the
[Access Lab](../section_access/README.md). This example adds a small business
service and deferred-work boundary; it does not establish provider or deployment
acceptance.

## Verify the integration behavior

```powershell
$env:PYTHONDONTWRITEBYTECODE = "1"
.\.venv\Scripts\python.exe -m pytest tests/test_host_integration_example.py -q
```

The tests use synthetic identities to exercise ownership, forged roles, stale
sessions, expiry, replay, freeze, revocation and unavailable access storage.
They also run the example in a subprocess without importing optional hosts.
