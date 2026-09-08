# Release checklist

Use this checklist for every public release candidate.

## Public metadata

- `pyproject.toml` version matches `role_aware_dashboard_toolkit/version.py` and the changelog
- repository, issues, documentation, and homepage URLs are real
- the configured PyPI distribution name is available to the releasing account
- after that check, `[tool.role_aware_dashboard_toolkit.release] verified-distribution-name`
  records the same normalized PyPI identity as the configured distribution name;
  changing the name alone does not clear the publication gate
- `SECURITY.md` names a monitored public reporting contact
- `LICENSE`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, and `SECURITY.md` are
  included and current
- no placeholder, localhost, private, or example public coordinates remain

## Source quality

```powershell
py -3 -m pytest -q
py -3 -m pytest -q --cov=role_aware_dashboard_toolkit --cov-report=term-missing --cov-fail-under=75
py -3 -m ruff check role_aware_dashboard_toolkit tools examples tests --no-cache
py -3 tools/pre_release_check.py --json --require-clean
py -3 -m pip check
```

The clean-source gate includes tracked and untracked files so candidate
artifacts can be tied to the checked-out commit. Resolve every failed or
unexpectedly blocked pre-release check. Before public
coordinates and package-name clearance exist, only
`distribution_name_ownership`, `oss_public_coordinates`, and
`security_intake_contact` may remain blocked; `failure_count` must remain `0`.

Pytest creates each default basetemp as a unique session-owned child under
`.pytest-runtime-tmp/`. Explicit `--basetemp` overrides must be cleaned by the
caller.

Hosted CI is currently disabled. Maintainers must explicitly enable hosted
execution before claiming CI verification. When enabled, the dedicated
`coverage-gate` job runs the coverage command above so ordinary matrix runs
do not inherit coverage instrumentation. Run the local checks while CI is disabled.

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

```powershell
py -3 -m build
$distArtifacts = Get-ChildItem -LiteralPath dist -File
$twineArgs = @("-3", "-m", "twine", "check") + $distArtifacts.FullName
py @twineArgs
```

Audit both wheel and source-distribution member lists with
`role_aware_dashboard_toolkit.release_audit.audit_release_artifact_members`.

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
- install the source distribution with build isolation configured
- run `python -m examples.core_library` from source
- launch `examples/dashboard_admin_controls_app.py` as the visual smoke

## CI and artifacts

- required Linux and Windows jobs pass for the exact release commit
- workflow permissions remain least privilege
- action references are pinned to reviewed commit SHAs
- the release candidate reuses the exact audited artifacts rather than
  rebuilding them
- SHA-256 digests are recorded for every uploaded artifact

Continue with [release_runbook.md](release_runbook.md) only after all gates pass.
