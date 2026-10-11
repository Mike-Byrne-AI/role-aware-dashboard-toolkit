# Contributing to Role-Aware Dashboard Toolkit

Contributions should keep the dashboard library usable across applications.

Use the [documentation map](docs/README.md) to find the relevant guide or example,
and [architecture scope](ARCHITECTURE_SCOPE.md) for the library's boundaries.

## Development setup

Use Python 3.10 or later. From the repository root:

```powershell
$env:PYTHONDONTWRITEBYTECODE = "1"
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -c "import role_aware_dashboard_toolkit as r; print(r.__file__)"
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m ruff check role_aware_dashboard_toolkit tools examples tests --no-cache
```

The printed package path must resolve inside this checkout; an older installed
wheel can otherwise give misleading test results.

Create `.venv` only when it does not already exist. On Linux or macOS with bash
or zsh, use `export PYTHONDONTWRITEBYTECODE=1` instead of the PowerShell
environment assignment, and `.venv/bin/python` instead of
`.\.venv\Scripts\python.exe`. Do not enable system site packages in a new
environment. Reinstall `.[dev]` after dependency changes; this upgrades
tools that no longer meet the declared floors, including Twine 7's metadata
reader. For a release, use the fresh environment in the release checklist.

Run focused tests while developing, then run the full checks before submitting
changes. The [release checklist](docs/release_checklist.md) adds coverage, build,
artifact, and installation verification for release candidates.

Set `PYTHONDONTWRITEBYTECODE` before starting Python so pytest collection and
child processes do not create bytecode in the source tree. The release checker
rejects generated cache files. Ruff's selected `E4`, `E7`, `E9`, and `F` checks
are explicit in `pyproject.toml`, so a new Ruff default does not change the
repository's lint policy.

## Change scope

- Keep changes small and explain the behavior they affect.
- Preserve documented public APIs unless a reviewed change explicitly updates
  the contract and its migration guidance.
- Add focused regression tests when behavior changes.
- Keep identity-provider configuration, credentials, deployment policy, and
  application-specific integrations in the host application. The optional access
  layer supplies verification adapters, role grants and shared freeze enforcement.
- Update documentation and generated references when their contracts change.

## Before submission

Confirm tests, lint, and documentation links pass. Describe the problem, the
resulting behavior, and the verification performed. Follow
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md), and consult [SECURITY.md](SECURITY.md)
before sharing sensitive findings.

Pull requests automatically run `.github/workflows/contributor-ci.yml`: tests
on Python 3.10–3.12, lint, coverage, and package build/metadata validation. The
stable required check is `contributor-checks`; failed, skipped, or cancelled
dependency jobs make it fail. The workflow has read-only permissions and does
not receive release credentials. GitHub may require a maintainer to approve
the first workflow run for a fork contributor.

Maintainers should require `contributor-checks` on `main`, with the branch up
to date before merging and force pushes/deletions disabled. Check the live
repository rules rather than assuming this document configures protection.
The separately guarded release workflow in `ci.yml` remains manually dispatched.

## Contribution channels

Use the [issue tracker](https://github.com/Mike-Byrne-AI/role-aware-dashboard-toolkit/issues)
for public bug reports and feature proposals. Follow [SECURITY.md](SECURITY.md)
for vulnerability reports; do not include sensitive details in public issues.
