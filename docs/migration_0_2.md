# Upgrade from 0.1 to 0.2

The current candidate is **0.2.0rc1**, dated 2026-10-17. It changes several
security defaults and host contracts. Treat it as a candidate until the
[release checklist](release_checklist.md) and
[publication runbook](release_runbook.md) have been completed for the final
source and artifacts. This guide does not assert that a hosted release or
package-index upload exists.

Read the [changelog](../CHANGELOG.md) for the complete change list. The steps
below apply to host applications previously built with 0.1.0; a new example
already demonstrates the revised behavior.

## Prepare a separate upgrade environment

Retain the current application, interpreter environment and exact package
artifact. Back up persistent stores together with their original identity key
and private configuration using a method appropriate to the store. Prove a
restore in a separate, private directory before replacing a working deployment.
Do not generate a replacement identity key to get past an upgrade failure.
Old grants in a backup may include access revoked since the backup was made;
reconcile them before reopening restored service.

Install the reviewed candidate artifact and the application's existing extras
into a fresh virtual environment without system site packages. For example,
from a directory containing the verified wheel, in PowerShell:

```powershell
python -m venv .venv-candidate
.\.venv-candidate\Scripts\python.exe -m pip install ".\role_aware_dashboard_toolkit-0.2.0rc1-py3-none-any.whl[auth]"
.\.venv-candidate\Scripts\python.exe -c "import role_aware_dashboard_toolkit as r; print(r.__version__); print(r.__file__)"
```

For bash or zsh, use `.venv-candidate/bin/python` and
`"./role_aware_dashboard_toolkit-0.2.0rc1-py3-none-any.whl[auth]"`. Select `api`,
`workbench`, `full` or no extra as appropriate to the host; the example does
not require every application to install `auth`. Compare the wheel's SHA-256
with the candidate evidence and record the resolved dependency versions.

These are install instructions for a local artifact, not a package-index
publication claim. Supported Python remains 3.10 and later. Optional dependency
floors have changed; resolve and audit the application's complete environment,
including its own dependencies.

## Make authentication and role contracts explicit

- `DashboardConfig` no longer silently enters demo mode when neither `access`
  nor `auth_hook` is supplied. For a local role-selection demo, pass
  `auth_mode="demo"`. For a shared application, provide verified access or a
  trusted host hook; do not use the demo selector as authentication.
- Demo sessions initially select their least-privileged role, which is Viewer
  for the built-ins. Select Admin to change Controls Writable; that action now
  requires `can_manage_freeze`.
- `RoleDef` requires a permission mapping with nonempty string keys and actual
  `bool` values. Replace `None` with `{}`, and replace truthy strings or numbers
  with deliberate `True` or `False` values. Only `True` grants permission.
- Every registered control requires a nonempty string `permission`; the API
  refuses a control without one. Inventory custom controls and grant their
  explicit permissions to the intended roles.
- With governance configured, the built-in Close case action requires
  `can_view_team_ops`, `can_view_decisions` and `can_view_governance` to evaluate
  governance, as well as `can_manage_runs`. The `close_case` governance block
  and failed evaluation deny the action. Update custom roles that previously
  carried only `can_manage_runs`; built-in roles already have the required
  grants. See [caseboard](caseboard.md).

Recheck permission immediately before host reads and writes. New checkpoint
checks close a toolkit-specific stale-authority gap; they do not automatically
protect an unrelated database or external service callback.

## Update HTTP clients

The API accepts exact, valid control values. It no longer clamps out-of-range
values or substitutes defaults on control writes. Send the correct JSON types,
handle 422 responses and show the user which control needs correction.

`PATCH /controls` requires the envelope below; sending the mapping directly is
no longer supported. Both that route and `POST /profiles` refuse unknown fields.

```json
{"values": {"worker_limit": 5}}
```

For `allow_anonymous=True`, a `POST`, `PATCH` or `DELETE` without `X-API-Key`
must send `Content-Type: application/json`, or it receives 415. If no API key
is configured, writes also require a loopback `Host`: `localhost`, a `127.x`
address or `[::1]`. Use a loopback base URL in tests rather than a test client's
default hostname. Configure an API key before using another host name, LAN
address or container name. Anonymous reads remain anonymous; this write check
does not make a public anonymous deployment private.

Toolkit routes reject bodies above `max_body_bytes` (1 MiB by default) with
413 and JSON nesting above 32 levels with 422. Pass an appropriate
`create_app(max_body_bytes=...)` value if needed. Validation responses expose
only `type`, `loc` and `msg`; clients must not depend on rejected input values
appearing in errors. These limits apply to toolkit routes. A host's additional
FastAPI routes need their own controls. See [API security](api_security.md).

## Review plugins and sensitive fields

Plugin allowlists now require `distribution:group:name`. Replace the former
`group:name` form with the actual installed distribution name. A same-named
entry point from a different distribution is refused. Conflicting copies of
an allowlisted distribution that point to different code are also refused;
remove stale installations instead of broadening the allowlist. Identical
targets, including matching editable-install metadata, count as one. Plugins
still run as trusted Python code. See [plugins](plugins.md).

Names such as `private_key`, `passwd`, `pwd`, `access_key_id`, `cookie`, `jwt`,
`dsn` and `connection_string` are now sensitive. Profiles omit these values and
audit redacts them. Inspect registered fields and profile expectations before
upgrading. An intentionally nonsecret control can explicitly use
`register(..., sensitive=False)`, but never use that exception simply to make a
secret appear in an export. Sensitive-name matching includes casefolded names;
ordinary words such as `access_keyboard` are excluded from the key-name pattern.

`AuditLog.log_control_change()` now defaults `sensitive` to `None`, preserving
name-based redaction. An explicit `sensitive=False` deliberately records the
value even if its control name looks secret; 0.1.0 still redacted that case.
Remove old explicit `False` arguments where the name should determine secrecy.
Secret-named fields nested inside the value remain redacted. Hosts can register
additional names with `sensitive_values.register_sensitive_names()`.

## Adjust audit lifecycle, diagnostics and evidence handling

A dashboard render no longer starts or stops an audit writer because of a stale
session toggle, or retries a failed start. Start the writer explicitly in host
code when durable audit is required, and share the intended log per process.
Only an explicit toggle or path change by a `can_manage_audit` role manages it
through the dashboard. Follow the durable audit instructions in the
[README](../README.md).

Writer start/stop and clear operations emit attributable events.
`AuditLog.clear()` returns the cleared count and leaves one `audit_cleared`
event; update callers that expected an empty log. A stop event records a stop
request, not proof of immediate worker termination. A shutdown timeout retains
the worker and reports an error; handle it before assuming audit is stopped.

Store `read_errors` now retains only the newest 200 errors. Detect newly failed
reads with `read_error_count` or
`store_diagnostics.store_read_error_total(store)`, not a change in list length.
Do not turn an unreadable store into an empty successful result.

Path redaction limits each string to 1 MiB in audit events, packets, exports
and diagnostics. The line crossing that limit and the remainder are replaced
with `<redacted-oversize-text: N characters omitted>`; an oversized single line
is replaced whole. Keep longer evidence in appropriate storage and refer to
its file name instead of expecting the complete text to survive export.

Packets containing cycles or more than 500 levels of mappings/lists, counting
the envelope, raise `ValueError` during build, export or load. Flatten deeply
nested payloads and handle validation failure. Previously accepted excessive
depth is not a migration guarantee. Audit timeline CSV fields now receive the
same formula protection as other audit CSV exports; downstream consumers should
not strip that protection before opening data in a spreadsheet.

## Verify existing storage before startup

File record stores for profiles, runs, cases, decisions and governance require
each record ID to match its filename. A mismatch is excluded from reads/listing
and blocks save/delete with `StorePathSecurityError` (409 through the API).
Inventory externally renamed files and correct them under operator control;
do not overwrite unreadable records to recover a missing item. Team and
operator-memory collection stores still list arbitrary filenames but refuse to
save over another record's ID.

On POSIX, protected access storage, `identity.key` and `access.sqlite3` must
belong to the caller or root. Ancestor directories must also belong to the
caller or root. Group/world-writable ancestors are refused unless they are
root-owned and sticky, such as `/tmp`; trusted root-owned system links remain
supported. In particular, running as root no longer grants permission to use
another user's access directory or database. Use an appropriate private path
and consistent service account instead of widening permissions.

Extended ACLs on the protected directory, key or database are refused. On macOS,
an ancestor ACL that allows access is also refused. Review the actual ACL before
removing it; the platform commands are `chmod -N` on macOS and `setfacl -b` on
Linux. Preserve private file modes and ownership. See
[authenticated access](../role_aware_dashboard_toolkit/resources/guides/authentication.md)
for supported storage provisioning and Windows-specific requirements.

Existing generated authenticated apps are copied source and do not update when
the package is upgraded. Compare their `build_access_policy` and `_inside`
directory-containment check with the current
[authenticated starter](../role_aware_dashboard_toolkit/resources/authenticated_starter/app.py).
The revised check compares filesystem directory identities, so case aliases,
macOS `/tmp` aliases and firmlinks cannot put access storage back inside the app
tree. Apply that check before reading the key. Preserve the host's explicit
login, current-grant, freeze and account-switch boundaries while updating.

## Adopt examples deliberately and verify the result

The new [record workflow recipes](record_workflows.md) and
[landscaping application](../examples/landscaping/README.md) are source examples,
not additional installed core modules or stable public APIs. The workflow
helper requires host-owned transactions, current authorization, business rules
and audit selection. Its rollback scope cannot cover external messages or
services. Keep repeated external effects behind an explicit retry/idempotency
design.

The landscaping demo has its own SQLite schema, local password sessions and
optional dependencies. Its source launcher provisions fresh fictional accounts
in a private outside-repository directory and refuses incomplete existing
storage. It is separate from the older Windows ZIP trial, with a separate data
directory and cookie. Do not copy trial credentials or customer data into the
example tree. The demo supports Linux/macOS and Windows through WSL; native
Windows toolkit support does not imply native Windows demo storage support.

Before changing a deployed host, exercise successful actions and direct denied,
revoked, frozen, stale and duplicate requests against the candidate. Inspect
committed records and history, including rejected actions. Test role/account
switches, stale forms and confirmation reset in a real browser. Verify restart
and restore against separate test storage, then run the
[deployment acceptance sequence](../role_aware_dashboard_toolkit/resources/guides/deployment.md)
with the actual HTTPS proxy and identity provider. Unit checks and a synthetic
demo are not proof of a host's operational security.

Maintainers must additionally set `RELEASE_CI_APPROVED_SHA` to the reviewed
commit before arming release CI. Empty Unreleased notes, a passing local check
or this candidate's version string does not establish that hosted checks ran
on that commit. Retain exact artifact hashes and publish only the artifacts
that passed the release procedure.
