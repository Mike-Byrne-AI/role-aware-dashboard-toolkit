# Changelog

## Unreleased

The next release is 0.2.0: the changes under "Changed (BREAKING)" need host
changes.

### Security

- A dashboard render no longer stops a host-started audit writer. Only an
  explicit toggle or path change by a `can_manage_audit` role starts, stops
  or moves it, and the toggle shows the live state to every role.
- Starting or stopping the audit writer and `AuditLog.clear()` record
  `audit_writer_start`, `audit_writer_stop` and `audit_cleared` events; an
  identity-bound audit view pins its actor on them. A stop that times out
  records its `audit_writer_stop` (detail "timed out ...") before raising,
  and the stop that finds the writer ended appends it to the file.
- The audit Timeline table and its CSV download get the audit CSV's formula
  protection.
- Path redaction runs in linear time and scans at most 1 MiB of a string;
  `file:` URIs without `//` and editor `file` links are redacted. A path under
  the repository root no longer carries a later path through when it starts
  the string or runs on past a comma, and a Windows path glued to a URL
  (`\\srv\share\vscode://file/...`) is redacted with the URL.
- Record and packet validation errors no longer repeat saved values, and an
  oversized schema version no longer raises.
- The incident timeline narrative renders as plain text, not Markdown.
- API request bodies over `max_body_bytes` (1 MiB default) get 413 and JSON
  nested more than 32 levels gets 422; a 422 body lists only `type`, `loc` and
  `msg` per error. These apply to the toolkit's routes; routes a host adds to
  the returned app keep FastAPI's defaults.
- The authenticated starter and the A/B/C example compare directory
  identities (device and inode) when refusing access storage inside the app
  tree, so `/tmp/app/secrets` on macOS, a case-changed `/deploy/APP/secrets`
  and the `/System/Volumes/Data/...` firmlink no longer get through, and check
  before reading the key. Apply the same change (`_inside`) to the
  `build_access_policy` of an app scaffolded from 0.1.0.

### Changed (BREAKING)

- `DashboardConfig` raises when `auth_mode` is omitted with neither `access`
  nor `auth_hook`; a missing access policy no longer means the demo. Pass
  `auth_mode="demo"` for the self-selected demo.
- API control writes store the value as sent or return 422 naming the
  control; the API no longer substitutes defaults or clamps. `PATCH /controls`
  requires `{"values": {...}}`, and it and `POST /profiles` refuse unknown
  fields with 422. Send exact, in-range JSON values.
- With `allow_anonymous=True`, a `POST`, `PATCH` or `DELETE` without
  `X-API-Key` must send `Content-Type: application/json` (else 415), so a
  browser cannot send it cross-site. Send JSON with that header.
- With `allow_anonymous=True` and no API key set, a `POST`, `PATCH` or
  `DELETE` whose `Host` header is not `localhost`, a `127.x` address or
  `[::1]` gets 403, which stops DNS rebinding. Address an anonymous demo as
  `localhost` or `127.0.0.1`, or set an API key to serve it under another name
  (a LAN address, a container name, or a test client's default host).
- `RoleDef` permission values must be `True` or `False` (`TypeError`
  otherwise), and only `True` grants. `register()` refuses an empty or
  non-string `permission`, and the API denies a control without one.
- Plugin allowlist entries are `distribution:group:name`; an old
  `group:name` entry raises `ValueError` before anything loads, and a
  same-named entry point from another distribution is not loaded. When more
  than one installed distribution declares an allowlisted name, none of its
  entry points loads. Add the distribution name to each entry, and remove a
  duplicate or stale copy of an allowlisted distribution.
- The built-in Close case button honours governance's `close_case` block and
  is refused when governance cannot be evaluated.
- Controls and fields named like `private_key`, `passwd`, `pwd`,
  `access_key_id`, `cookie`, `jwt`, `dsn` or `connection_string` are now
  sensitive, so profiles stop saving them. Pass `sensitive=False` to keep one.
  `access key` and `private key` match only where "key" ends a word
  (`access_keyboard` is not sensitive), and a registered name such as
  `Straße` matches both its spelling and its casefold (`STRASSE`).
- Demo mode: a new session starts in its least-privileged role (Viewer for the
  built-ins), and only a `can_manage_freeze` role can change Controls
  Writable. Pick Admin in the sidebar to edit.
- A render no longer starts the audit writer from a stale session toggle or
  retries a failed start. Start the writer in host code, or share one log per
  process (README, durable audit).
- Path redaction keeps at most 1 MiB of one string in audit events, packets,
  exports and diagnostics: the line that crosses the limit and everything
  after it are dropped and replaced by
  `<redacted-oversize-text: N characters omitted>` (a single line over 1 MiB
  is replaced whole), and packet validation still passes. 0.1.0 kept the
  whole value. Keep longer text in a file and record the file's name.
- Building, exporting or loading a packet nested more than 500 levels of
  mappings and lists (counting the envelope) raises `ValueError`, as does one
  with a cycle; 0.1.0 had no limit and handled about 990 levels before
  `RecursionError`. Flatten deeper data before putting it in a packet.
- `AuditLog.clear()` returns the number of events cleared and leaves one
  `audit_cleared` event in the view.
- `read_errors` keeps the newest 200 errors. Detect new errors with
  `read_error_count` or `store_read_error_total(store)`, not its length.
- Record stores check a record's id against its file: a mismatched file is not
  loaded or listed, and `save` or `delete` over it raises
  `StorePathSecurityError` (the API returns 409).
- On POSIX the protected access directory, `identity.key` and, on every
  `SQLiteAccessStore` connection, `access.sqlite3` must belong to the caller
  or root, so a root process can no longer use another account's directory or
  database. Every directory above the protected directory must also belong to
  the caller or root, and may be group- or world-writable only when it is
  root-owned and sticky (like `/tmp`). Root-owned system links such as macOS
  `/var` and `/tmp` are accepted. Move a protected directory that sits below
  another account's directory or a shared writable one.
- Provisioning, `read_identity_key` and `SQLiteAccessStore` refuse a protected
  directory, `identity.key` or `access.sqlite3` that carries an extended ACL
  (macOS ACLs, Linux POSIX ACLs), and on macOS a parent directory whose ACL
  allows access. Remove the ACL (`chmod -N` on macOS, `setfacl -b` on Linux).
- Release CI reads `RELEASE_CI_APPROVED_SHA`; maintainers set it before
  arming a release run.

### Fixed

- An audit writer still running at exit is drained (three-second cap) and
  records its stop; a dropped `AuditLog` stops its writer thread.
- An audit append after a torn line starts on a new line.
- A record replaced during a read is re-read, not reported missing. Record
  writes fsync the file and directory, stale temporary files are swept, and a
  replaced record keeps its file mode without group or other write access.
- Run, evidence and API reads still detect a failed store read after
  `read_errors` is full.
- The API reports an unreadable stored profile instead of 404 or overwriting
  it: 500 on read and activation, 409 on save, an `X-Unreadable-Records`
  header on the list.
- `create_app()` warns when every protected route would return 401.
- The default `icon` is empty, so titles no longer start "Control Panel".
- Shipped code no longer uses `assert` for control flow.
- Deep, cyclic or exploding packets raise `ValueError`, not `RecursionError`.
- Root exports have real types for type checkers, and `ControlRegistry`
  state methods accept `st.session_state`.
- Telemetry comparison and observability drift deltas print without
  floating-point noise (0.25, not 0.24999999999999997).
- `access_cli` and the A/B/C provisioning example say why provisioning was
  refused; argument errors have their own message.
- Access-provisioning tests pass on macOS.
- Dependency floors install and work at their lowest: `pandas>=2.2.2` and
  `pydantic>=2.7.0` (both higher on Python 3.13 and 3.14), and `black>=24.1.0`.
- Install and launch docs give bash/zsh commands beside PowerShell, and `init`
  prints the interpreter that ran it.
- SECURITY.md states that private vulnerability reporting is enabled, and the
  architecture scope says only the JSONL audit file is append-only.
- The admin demo installs only the workbench extra.
- Release CI keeps artifacts and evidence for 90 days, and its
  installed-wheel smokes pass `auth_mode="demo"`.

### Added

- Pull-request CI now runs the full Windows test suite, Linux tests on Python
  3.13 and 3.14, and a Chromium dashboard smoke with retained diagnostics.
- Dependency CI audits resolved API and full runtime installations on pull
  requests and weekly, retaining inventories and advisory reports. Incomplete
  scans and vulnerability findings both block its required check.
- Pull-request CI adds a macOS / Python 3.12 test cell, and the dev extra
  installs mypy so the root-export typing check runs.
- `sensitive_values.register_sensitive_names()` adds secret names for a host.
- File stores expose `read_error_count`, and
  `store_diagnostics.store_read_error_total()` counts any store's read errors.
- `create_app(max_body_bytes=...)` sets the API request body limit.
- Package metadata declares `License-Expression: MIT` and `Typing :: Typed`.
- The release-mode pre-release check fails while Unreleased has entries.
- Tests guard the sensitive-audit redaction and plugin allowlist lines.

## 0.1.0 (2026-10-13)

Initial beta release of Role-Aware Dashboard Toolkit.

### Highlights

- Dependency-free Python core with typed controls, value validation, roles,
  per-control permissions, explicit write policy, and sensitive-value handling.
- Optional Streamlit dashboards, FastAPI endpoints, and pandas history views,
  with configurable dashboard themes and section visibility.
- Saved profiles with restore previews and replacement confirmation, audit
  history, and permission-aware handling of sensitive values in native views
  and exports.
- Optional Streamlit OIDC sign-in with operator-provisioned role grants,
  SQLite-backed shared freeze state, and audit attribution to opaque actors.
  Demo and host-hook integrations remain available.
- Runs, checkpoints, outcome comparisons, ledgers, and permission-checked replay,
  plus team, decision, incident, case, and governance records for review workflows.
- Validated JSON evidence packets, visible storage diagnostics, and review
  summaries that identify incomplete evidence.
- Trusted plugin hooks, normalized telemetry, offline guides, capability
  inspection, and editable demo and authenticated starters.
- Runnable examples, including the Operator Review Lab, connecting profiles,
  checkpoints, human review, and portable evidence reports. See the
  [examples index](examples/README.md).

### Fixed since the release candidate

- API control writes preserve nested-secret confidentiality and withhold values
  without metrics read permission. Single-control reads support slash-containing
  keys. Unsafe structured-to-text coercion is rejected before mutation.
- Existing invalid store paths produce read diagnostics and block dependent
  reviews instead of appearing as complete, empty evidence.
- Rejected checkpoint approvals remain blocking through decision and governance
  review; completed assignments no longer imply an outstanding review.
  Checkpoint-only case links count as governance evidence.
- Review chronology compares ISO timestamps in UTC. Governance approval coverage
  uses current signoffs per reviewer and run/checkpoint scope, and incident
  evidence follows the case's additive links.
- Native record-save failures preserve the dashboard and drafts, report uncertain
  completion without raw provider errors, and do not emit success audit events.
- Profiles named `(none)` remain selectable, loadable and deletable. Empty
  snapshot restore mappings remain authoritative in comparisons, and empty
  latest control snapshots clear previous decision summaries.
- Native profile saves omit historical and nested parent secrets from saved
  differences. Run narratives use captured checkpoint evidence, and incident
  timelines preserve authenticated audit attribution.
- The Access Lab keeps access denied after a failed sign-out until recovery.
- The protocol catalog points telemetry samples to their actual sample builder.

### Usage boundaries

- Shared deployments require host-configured identity providers, secrets, and
  explicit role provisioning. Demo role selection is not access control. See
  [authenticated access](role_aware_dashboard_toolkit/resources/guides/authentication.md)
  and [deployment guidance](role_aware_dashboard_toolkit/resources/guides/deployment.md).
- JSON record stores use trusted local filesystems without cross-process
  transactions. SQLite access state supports one application on one host with
  local disk storage; its transactions do not cover other records or host actions.
- Plugins run as trusted Python code. Host applications own authorization around
  their operations and any external side effects. See
  [architecture scope](ARCHITECTURE_SCOPE.md).
