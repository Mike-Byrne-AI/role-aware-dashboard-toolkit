# Changelog

## 0.1.0

Initial release candidate of Role-Aware Dashboard Toolkit.

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

The core package has no required third-party dependencies. Public release
remains subject to the metadata, security-intake, and validation gates in the
[release checklist](docs/release_checklist.md).
