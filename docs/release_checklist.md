# Release checklist

Use this checklist for the GitHub-source release channel. Package-index
publication is a separate future decision.

## Public metadata

- `pyproject.toml` version matches `role_aware_dashboard_toolkit/version.py` and the changelog
- repository, issues, documentation, and homepage URLs match the configured
  `Mike-Byrne-AI/role-aware-dashboard-toolkit` destination; they remain planned
  coordinates until the repository is reachable
- `[tool.role_aware_dashboard_toolkit.release]` selects `github-source`, names
  the repository, and sets `package-index-publication = false`
- `SECURITY.md` documents the configured GitHub private vulnerability reporting
  route and the need to check live availability and notification settings
- `LICENSE`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, and `SECURITY.md` are
  included and current
- no placeholder, localhost, private, or example public coordinates remain

`distribution_name_ownership` is a retained check identifier. For this channel
it checks the normalized distribution and source-repository identity only;
it does not verify or claim PyPI ownership, reservation, or publishing rights.

## Source quality

```powershell
py -3 -m pytest -q
py -3 -m pytest -q --cov=role_aware_dashboard_toolkit --cov-report=term-missing --cov-fail-under=75
py -3 -m ruff check role_aware_dashboard_toolkit tools examples tests --no-cache
py -3 tools/pre_release_check.py --json --require-clean
py -3 -m pip check
```

The clean-source gate includes tracked and untracked files so candidate
artifacts can be tied to the checked-out commit. Every local check must pass,
including `oss_public_coordinates`, `distribution_name_ownership`, and
`security_intake_contact`; `failure_count` must remain `0`. The blocked and
warning counts must also be zero. No actual local failure is an allowed
publication blocker.

The report declares `validation_scope = local-configuration` and lists
`live_validation_required`. These are separate launch requirements, not failed
local checks or claims of live success. They cover repository reachability,
security reporting activation and notification configuration, branch
protection, hosted CI for the same commit, and public visibility. Notification
configuration is not proof of delivery or human monitoring.

Pytest creates each default basetemp as a unique session-owned child under
`.pytest-runtime-tmp/`. Explicit `--basetemp` overrides must be cleaned by the
caller.

Hosted CI is manual-only and unarmed by default. It requires
`workflow_dispatch`, a `candidate` or `main` ref, and the repository variable
`XL422_CI_APPROVED_SHA` equal to that run's exact commit SHA. Setting the
variable and dispatching a run require separate maintainer authorization.
The dedicated `coverage-gate` job keeps coverage instrumentation out of the
ordinary Python matrix. Local verification does not establish hosted success.

## Generated references

- `docs/public_api.md` matches
  `role_aware_dashboard_toolkit.public_api.build_public_api_reference_markdown()`
- `docs/distribution.md` matches
  `role_aware_dashboard_toolkit.distribution.build_distribution_reference_markdown()`
- `docs/release_audit.md` matches
  `role_aware_dashboard_toolkit.release_audit.build_release_audit_markdown()`
- README imports and examples use retained public APIs
- all local documentation links resolve

## Build

Use a clean release checkout with a fresh output directory. Build and validate:

```powershell
py -3 -m build
$distArtifacts = Get-ChildItem -LiteralPath dist -File
$twineArgs = @("-3", "-m", "twine", "check") + $distArtifacts.FullName
py @twineArgs
```

Audit both wheel and source-distribution member lists with
`role_aware_dashboard_toolkit.release_audit.audit_release_artifact_members`.
Require exactly one wheel and one source distribution. Audit each archive
independently for its complete expected member set, duplicate names, and
non-regular entries; a combined list can hide a missing member in one archive.

Confirm artifacts exclude:

- private records and internal maintenance data
- tests, fixtures, repository task state, and maintainer-only docs
- caches, coverage data, temporary files, and stale build output
- application-specific adapters and local datasets

## Install smokes

From temporary directories outside the repository:

- install the built core wheel and import `role_aware_dashboard_toolkit`
- construct `ControlRegistry`, `DashboardConfig`, a run, and a packet without
  optional dependencies present
- install and smoke `workbench`, `api`, and `pandas` independently
- install `full`
- install the source distribution with build isolation enabled
- run `python -m examples.core_library` from source
- launch `examples/dashboard_admin_controls_app.py` as the visual smoke

Keep every install environment outside the checkout. Use isolated Python and
verify the imported package comes from the installed environment; do not
remove that environment from the import search path.

## CI and artifacts

- required Linux and Windows jobs and every required step pass for the exact
  final release commit; a skipped or cancelled job is insufficient
- workflow permissions remain read-only, actions remain pinned, runs have
  bounded timeouts, and artifacts have one-day retention
- the release candidate reuses the exact audited artifacts rather than
  rebuilding them in the evidence job
- SHA-256 digests are recorded for every uploaded artifact, along with the
  source commit, branch, run identifier, and run attempt
- live repository settings and evidence refer to that same final commit
- public visibility is changed without a subsequent metadata commit

Continue with [release_runbook.md](release_runbook.md) for the staged launch.
