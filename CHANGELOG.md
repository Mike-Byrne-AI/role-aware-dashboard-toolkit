# Changelog

## Unreleased

### Added

- Pull-request CI now runs the full Windows test suite, Linux tests on Python
  3.13 and 3.14, and a Chromium dashboard smoke with retained diagnostics.
- Dependency CI audits resolved API and full runtime installations on pull
  requests and weekly, retaining inventories and advisory reports. Incomplete
  scans and vulnerability findings both block its required check.

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
