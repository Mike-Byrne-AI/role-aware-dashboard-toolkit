# Role-Aware Dashboard Toolkit documentation

You can use the dashboard without learning every record type or release tool.
Start with the main workflow, then consult the reference pages as needed.

## First reading path

1. [Root README](../README.md) — what the toolkit does and a first dashboard.
2. [Dashboard tools](dashboard_tools.md) — controls, roles, profiles, and audit.
3. [Operator Review Lab](../examples/operator_review/README.md) — follow a run from
   baseline through comparison, human review, and export using synthetic data.
4. [Architecture scope](../ARCHITECTURE_SCOPE.md) — how the layers fit together
   and what the host application owns.

For use without a UI, start with the [core quickstart](quickstart.md) instead.
The [examples index](../examples/README.md) also covers Studio Dispatch for UI
customization and the Access Lab for section permissions.

## Repository map

| Location | Purpose |
| --- | --- |
| `role_aware_dashboard_toolkit/` | Library source: controls and state, optional UI/API adapters, records and stores |
| `role_aware_dashboard_toolkit/resources/` | Offline guides and starter apps included in an installed package |
| `examples/` | Runnable applications with synthetic data |
| `tests/` | Regression coverage for the library and examples |
| `docs/` | Usage and contract references, plus maintainer release instructions |
| `tools/` and `.github/workflows/` | Local release checks and continuous integration |

The offline guides support installed users who do not have this source tree.
Discover them with `python -m role_aware_dashboard_toolkit guide start`.

## Build and deploy an application

- [Upgrade from 0.1 to 0.2](migration_0_2.md) — candidate compatibility changes, host updates and upgrade verification
- [Run your first dashboard](first_dashboard.md) — install, generate, open, stop and restart the starter on Windows, macOS or Linux
- [Installed guidance](../role_aware_dashboard_toolkit/resources/guides/start.md) — capability discovery and starter commands
- [Authenticated access](../role_aware_dashboard_toolkit/resources/guides/authentication.md) — verified login, assigned roles, shared freeze, and private provisioning
- [Host integration example](../examples/host_integration/README.md) — protect host reads and deferred writes with current identity, role and freeze checks
- [Landscaping dashboard demo](../examples/landscaping/README.md) — run a complete fictional business app with password sign-in, shared work and protected admin tools
- [Protected record workflows](record_workflows.md) — implement edits, date changes and status transitions with transactional history and consumer acceptance checks
- [Shared deployment](../role_aware_dashboard_toolkit/resources/guides/deployment.md) — single-host HTTPS setup and deployment acceptance

## API and extension points

- [Public API reference](public_api.md)
- [Plugin contract](plugins.md)
- [API security](api_security.md)
- [Telemetry contract](telemetry_contract.md)
- [Shared store patterns](shared_store_patterns.md)

## Runs and exported evidence

- [Run model](run_model.md)
- [Replay and its application contract](replay.md)
- [Protocol overview](protocol/overview.md)
- [Packets](protocol/packets.md)
- [Ledgers](protocol/ledger.md)

## Optional review workflows

Read these when your application needs the corresponding records or store-backed
panels. They are not prerequisites for a basic dashboard.

- [Team operations](team_ops.md) — comments, assignments, signoffs, and handoffs
- [Decision model](decision_model.md) — derive review state from recorded evidence
- [Operator memory](operator_memory.md) — notes and incident timelines
- [Caseboard](caseboard.md) — group related evidence into a case
- [Governance](governance.md) — review policy checks and blocked actions

## Contributing and releasing

Start with [CONTRIBUTING.md](../CONTRIBUTING.md) to work on the library.
The following references are for maintainers preparing a release:

- [Distribution reference](distribution.md) — generated package and extras metadata
- [Release audit](release_audit.md) — generated release manifest summary
- [OSS boundary](oss_boundary.md)
- [Release checklist](release_checklist.md) — source, build, and installation checks
- [Publication runbook](release_runbook.md) — staging, hosted verification, and publication order

The [public API reference](public_api.md), distribution reference, and release
audit are generated from code and checked for synchronization; edit their
generators when changing those contracts.
