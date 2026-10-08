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
- Sensitive controls keep stored values and choices out of client widgets;
  permitted edits use explicit blank replacement inputs for every control kind.
- Spreadsheet-oriented audit CSV exports neutralize formula-like text while
  JSONL exports retain the original audit evidence. NUL characters are displayed
  as visible escapes in CSV for compatibility with Python 3.10 readers/writers.
- Record validation reports malformed field shapes consistently, and profile
  loading rejects invalid stored values before changing live controls.
- Decision validation accepts structured blockers; run validation checks nested
  checkpoint and approval records, and governance validation checks summary
  counters and role lists while packet envelopes retain partial-record support.
- Malformed non-ASCII API credentials return a generic unauthorized response
  without server errors or anonymous fallback.
- Store identifiers use consistent canonical values across save, list, load,
  and delete, including reads of existing records.
- The README dashboard retains session-local audit history across reruns, and
  starter installation guidance applies the workbench dependency requirements
  through a reviewed source checkout or local wheel.
- Independent API installations enforce the reviewed dependency floors;
  development tooling supports the metadata emitted by isolated builds.
- Read-only contributor CI runs automatically on pull requests and updates to
  `main`, with a stable aggregate check for branch protection. Release-candidate
  validation remains separately gated by an approved source commit.
- API profile responses and activation honor historical sensitivity, omit removed
  controls and nested secret fields, and preserve stored profile evidence.
- Ledger entries and governance policy checks reject invalid nested values;
  malformed schema-version text produces structured validation errors.
- Governance action lists remain disjoint, and timeline evidence retains incident
  status. Monitoring and mitigated incidents remain unresolved until closed.
- File stores bound readable filename prefixes while retaining complete logical
  identifiers and reusing existing Unicode filenames.
- Slider definitions, sanitation and rendering share effective bounds; numeric
  widgets reject unsupported integer limits before rendering, and control keys
  cannot occupy the reserved `_radt_` state namespace.
- Native profile selection and draft names survive pages that hide the profile
  controls, while account changes still clear the previous user's session.
- Optional-dependency recovery instructions support source and local-wheel
  installations without assuming a package-index release.
- Windows release checks include long and Unicode store identifier regressions.
- Authenticated freeze callbacks reject queued changes when the same submission
  switches away from the callback's assigned role.
- Runbook rendering tolerates records disappearing after listing, and deeply
  nested audit lines produce diagnostics without hiding healthy neighboring events.
- Native profile replacement requires confirmation tied to the current draft;
  changed, unreadable or no-longer-authorized targets cannot reuse stale consent.
  Read-only profile names are disabled, and partial loads explain retained settings.
- Signed-out pages show a neutral sign-in prompt; denied or unavailable access
  provides account recovery without disclosing identity details or weakening checks.
- Native profile Load omits historical-sensitive values and values containing
  nested secret fields, matching its preview while preserving stored evidence.
- Failed run-history reads show a warning, retain active-run associations and
  draft notes, and keep healthy neighboring records visible during recovery.
- Shared plugin registries synchronize setup per registration; concurrent callers
  share its result, with safe retry, removal and callback re-entry behavior.

The core package has no required third-party dependencies. Public release
remains subject to the metadata, security-intake, and validation gates in the
[release checklist](docs/release_checklist.md).
