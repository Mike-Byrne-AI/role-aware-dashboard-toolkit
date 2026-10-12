# Role-Aware Dashboard Toolkit architecture scope

Role-Aware Dashboard Toolkit is a reusable library for operator dashboards. Its architecture is
organized around a dependency-free core with optional presentation and service
adapters.

## Core responsibilities

The OSS core owns:

- control definitions, defaults, validation, and sensitive-value handling
- roles, permission checks, and explicit write policy
- access policy for trusted identities, live role grants, shared freeze state,
  and trusted operator provisioning
- profiles and append-only audit records
- trusted plugin registration and lifecycle diagnostics
- runs, checkpoints, comparisons, ledgers, and replay previews
- neutral packet envelopes and protocol metadata
- local operator records for teams, decisions, incidents, cases, and governance
- runtime diagnostics and telemetry normalization
- installed offline reference guidance, capability inspection and an explicit
  starter-copy command for a new consumer directory

All state transitions are explicit Python calls. UI rendering does not grant
authority beyond the policy supplied by the host application.

`AccessPolicy` consumes identities verified by the host and checks current role
grants, permissions, and freeze state at each authorization call. The host owns
identity-provider configuration, secrets, and authorization checks around its
own operations. Role-grant revocation takes effect at the next check; it does not
cancel work already in progress.

## Optional layers

Optional dependencies stay behind narrow boundaries:

- `workbench` provides Streamlit rendering
- `auth` adds Streamlit OIDC sign-in dependencies; the adapter supplies verified
  identity to the dependency-free access policy
- `api` provides FastAPI routes
- `pandas` provides tabular history views
- `full` installs all supported runtime extras

Importing `role_aware_dashboard_toolkit` or constructing a `DashboardConfig` must not require an
optional dependency. The dependency is loaded only when its capability is used.

## Dependency direction

```text
application
    -> core APIs directly
    -> optional Streamlit / OIDC or FastAPI adapters
        -> core APIs

core APIs: dashboard configuration, controls, security, access policy,
           profiles, audit, plugins, records, stores, packets, diagnostics
    -> Python standard library (including sqlite3)
```

Core modules must not import application integrations. Optional adapters may
depend on the core, never the reverse. The FastAPI adapter has its own API-key
and role configuration; it does not automatically use Streamlit login or
`AccessPolicy`.

## Public API policy

The root API is an intentionally bounded convenience surface. Generic,
frequently used symbols may be exported from `role_aware_dashboard_toolkit`; specialized operator
records, protocol metadata, validators, and release tooling remain available
from their owning modules. The generated
[`docs/public_api.md`](docs/public_api.md) is the source of truth for that
classification.

Public APIs should remain:

- typed and deterministic
- usable without global process state
- explicit about persistence and side effects
- strict about malformed inputs
- safe to import without optional dependencies

## Persistence boundary

In-memory stores support process-local composition. JSON and JSONL record stores
support trusted local filesystems and surface read/write diagnostics; they do
not provide cross-process transactions.

`SQLiteAccessStore` persists role grants and revisioned shared freeze state. Its
transactions coordinate access updates across processes and reject stale freeze
revisions. It supports one application on one host with local disk storage.
These transactions do not extend to other dashboard records or host side effects.
No built-in store provides distributed locking or multi-region coordination.

## Protocol boundary

Packets are inspectable JSON envelopes around records that already exist.
Role-Aware Dashboard Toolkit redacts local path data by default, validates before export, rejects
non-finite JSON numbers, and reserves the `x_` prefix for application-defined
packet types. A packet describes evidence or a replay preview; it is not an
execution instruction.

## Intentional non-goals

Role-Aware Dashboard Toolkit is not:

- an authentication provider
- an autonomous execution or orchestration runtime
- a repository management framework
- a secret manager
- a distributed database
- a home for product-specific adapters

Applications can compose those systems around Role-Aware Dashboard Toolkit through ordinary Python
APIs, trusted plugins, or their own namespaced packets.

## Installed guidance boundary

The standard-library CLI reads version-matched package resources. It does not
load a host application, install dependencies, call a model, contact a service,
or supply authority over the host project. The explicit `init` command copies a
small runnable example and a guidance pointer into a new directory; it never
creates Git state or overwrites an existing project. Existing projects can read
and adapt the same example through `example starter --format json`.

`init --auth` selects the authenticated starter, also available through
`example authenticated --format json`. The host must configure its identity
provider and provision access before using that starter.
