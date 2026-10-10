# Changelog

## 0.1.0

Initial release candidate of Role-Aware Dashboard Toolkit.

- Audit JSONL reads preserve Unicode separators inside event text and report
  corrupt records using physical line numbers.
- Run comparisons preserve explicitly empty latest snapshots, and profile,
  run and ledger diffs include additions/removals of null-valued controls while
  retaining the existing `from`/`to` result format.

- Typed dashboard controls with explicit roles, per-control permissions,
  write policy, finite numeric validation, and sensitive-value handling.
- Profiles and audit history with detached records, strict JSON persistence,
  and visible storage diagnostics.
- Trusted plugin hooks, telemetry normalization, and optional Streamlit,
  FastAPI, and pandas capabilities.
- Runs, checkpoints, comparisons, ledgers, and permission-checked replay.
- Team, decision, incident, case, and governance records with explicit writes.
- Validated JSON packet envelopes for inspectable application evidence.
- Retained live controls across run/profile/replay actions, timestamped checkpoint
  telemetry, addressable API profile identifiers and detached ordered ledgers.
- Validated page/card themes, explicit section visibility and registry removal.
- Offline installed guides, capability inspection, structured command output and
  an editable starter with a project-local assistant guidance pointer.
- Versioned runtime diagnostics with installed guide links, safe callback
  failure summaries and explicit partial-effect/durability limits.
- Audit display preserves source value types while avoiding mixed-column
  Arrow conversion fallbacks.
- Profile menus refresh immediately after saving or deleting, preserving
  surrounding widgets and avoiding an additional script rerun.
- Optional outcome comparisons with metric units and recorded sample times,
  keeping existing comparison results unchanged unless requested.
- Read-only profile restore previews explain current, saved and effective
  values, sanitation and permission restrictions before loading.
- A synthetic Operator Review Lab connects baseline profiles, candidate
  checkpoints, human review and portable read-only evidence reports.
- HTTP API guidance makes per-instance state and callback boundaries explicit.
- Optional authenticated access verifies OIDC identities, enforces server-owned
  role grants and a durable administrator-controlled freeze, and attributes
  native writes to opaque actors. Explicit local provisioning and `init --auth`
  provide a starter without automatically enrolling users or storing passwords.
  Existing demo and host-hook integrations remain available.
- Observability rechecks audit-read permission after telemetry sampling; the
  authenticated starter retains its verified session-start audit event.
- Decision and handoff views respect control-read permission without altering
  the stored evidence.

The core package has no required third-party dependencies. Public release
remains subject to the metadata, security-intake, and validation gates in the
[release checklist](docs/release_checklist.md).
