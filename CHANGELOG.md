# Changelog

## 0.1.0

Initial release candidate of Role-Aware Dashboard Toolkit.

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

Public release remains subject to the [release checklist](docs/release_checklist.md).
