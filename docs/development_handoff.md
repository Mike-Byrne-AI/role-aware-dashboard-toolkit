# Development handoff

This repository is the active library-development source. Its package, tests,
examples, documentation and build configuration are self-contained. Use
[CONTRIBUTING.md](../CONTRIBUTING.md) for the normal development loop.

## Starting point

The preserved `candidate` branch points to
`35956fadb5d72ec044ba0fbaa00a5fe2cb450dfa`. That implementation includes the state,
profile, API, telemetry and ledger repairs; appearance and section configuration;
offline guides and starter; runtime diagnostics; and immediate profile-menu
refresh. The `codex/development-handoff` branch adds contributor onboarding and
the synthetic Studio Dispatch example with its behavior tests. It retains the
existing history and does not replace the package with an older source export.

## Work locally

From this repository root on Windows:

```powershell
$env:PYTHONDONTWRITEBYTECODE = "1"
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -c "import role_aware_dashboard_toolkit as r; print(r.__file__)"
.\.venv\Scripts\python.exe -m pytest tests/test_studio_dispatch_example.py -q
```

Create the environment only if it does not already exist. The printed package
path must resolve inside this checkout. The local handoff environment may reuse
already installed system packages; that is convenient development setup, not an
isolated installation proof. Follow the release checklist for isolated builds.
The bytecode setting applies before test collection and is inherited by child
processes, keeping generated cache files out of the source tree.

Run the full suite with `python -m pytest -q` and lint with
`python -m ruff check role_aware_dashboard_toolkit tools examples tests --no-cache`
using the same environment. Installed package guidance is available through
`python -m role_aware_dashboard_toolkit inspect` and `guide start`.

## Examples and regression coverage

[Operator Review Lab](../examples/operator_review/README.md) demonstrates the
complete baseline, candidate, outcome comparison, human review and evidence
export workflow. Its metrics are deterministic simulations and its stores are
session-local. A separate report renderer converts validated run packets to
standalone read-only HTML. Tests cover the workflow, permission/freeze boundaries,
and imported report validation and escaping. Independent adopter feedback remains
to be collected; automated checks do not establish usefulness or development speed.

[Studio Dispatch](../examples/studio_dispatch/README.md) demonstrates six control
types, named profiles, Viewer permissions, freeze, navigation, metrics and a
workload chart. Its data and stores are entirely synthetic and session-local.
Tests live in `tests/test_studio_dispatch_example.py` and run in the normal suite.

Existing core, API and UI regression tests retain the library fixes that came
from consumer exercises. Private applications, source data, trial logs and
historical orchestration records were not imported into this public tree. Further
consumer examples should be transferred selectively with synthetic fixtures.

## Authenticated access work

The optional access layer adds provider-neutral OIDC, explicit server-owned role
grants, a SQLite shared freeze and pseudonymous event attribution. See the
[installed authentication guide](../role_aware_dashboard_toolkit/resources/guides/authentication.md)
and generate a host app with `init shared-dashboard --auth`. No provider
credentials or account grants belong in this checkout. Existing demo behavior
is retained and labeled; the optional HTTP API has its own access policy.

Source tests cover role spoofing, expiry/revocation, account changes, concurrent
freeze updates and denied native writes. Actual provider configuration and
deployment ACL/TLS verification remain host acceptance work. These changes do
not extend earlier release evidence.

### Local acceptance, 2026-09-30

[verified] The working tree passed the full suite: 1,416 tests passed and one
POSIX-permission test was skipped on Windows (Python 3.11, Streamlit 1.52.2).
Ruff and the local pre-release configuration checks passed. The installed-wheel
smoke test additionally checked authentication imports without optional hosts,
the authenticated starter files, and its offline guide. Windows emitted cleanup
warnings for temporary Git fixture files; test assertions completed successfully.

[verified] A separate local test provider completed signed OIDC login through
isolated Edge browser sessions. All 12 acceptance assertions passed, covering
unassigned-account denial, assigned-role selection, removal of authority in
Viewer mode, shared freeze, stale revision rejection, live revocation, logout
recovery and downgraded administrator actions. Only invented accounts and
synthetic data were used; provider state and evidence stay outside this source
tree. This does not certify an external identity provider configuration.

```powershell
.\.venv\Scripts\python.exe -m pytest -o addopts='-ra -p no:cacheprovider' -q
.\.venv\Scripts\python.exe -m ruff check role_aware_dashboard_toolkit tools examples tests --no-cache
.\.venv\Scripts\python.exe -B tools/pre_release_check.py --json
.\.venv\Scripts\python.exe -m pytest tests/test_release_hygiene_distribution.py::test_wheel_installed_core_imports_without_optional_dependencies -q
```

This is local feature acceptance, not publication or hosted deployment evidence.
Provider credentials, explicit real-account grants, TLS and storage ACLs must be
configured and checked for each deployment. Start with the authenticated starter
and its guide; no real identities or credentials were provisioned during testing.

## Release status

Local development readiness does not establish a hosted or public release.
Historical evidence for `35956fa` covers that earlier commit only. Source and
artifact checks must be refreshed for whichever commit is ultimately released.

Contributor validation in `.github/workflows/contributor-ci.yml` runs on pull
requests and pushes to `main`. Its stable required check is `contributor-checks`.
The release workflow in `.github/workflows/ci.yml` remains manually dispatched
and requires the exact approved commit. Verify live branch protection and the
actual checks for a commit; workflow configuration alone is not hosted evidence.

Before publication, follow the [release checklist](release_checklist.md) and
[publication runbook](release_runbook.md): freeze the intended source, build and
validate its artifacts, obtain actual hosted evidence, and verify the intended
repository visibility and reporting configuration. Existing private historical
validators require a reviewed update before they can certify a later commit.
Do not relabel old receipts or weaken checks to make a new commit appear covered.

## Transfer validation

The full local suite passed 987 tests, including ten Studio Dispatch cases, on
Python 3.11 and Streamlit 1.52.2. Ruff passed. Windows reported permission errors
while cleaning temporary Git fixtures after the tests; the assertions passed.
Those ignored test artifacts do not belong in release distributions. This local
result does not replace the hosted and isolated-install release checks above.
