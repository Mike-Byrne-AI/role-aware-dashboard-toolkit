# Contributing to Role-Aware Dashboard Toolkit

Contributions should keep the dashboard library usable across applications.

See the [development handoff](docs/development_handoff.md) for the active
checkout and the Studio Dispatch example.

## Development setup

Use Python 3.10 or later. From the repository root:

```powershell
python -m pip install -e ".[dev]"
python -m pytest -q
python -m ruff check role_aware_dashboard_toolkit tools examples tests --no-cache
```

Run focused tests while developing, then run the full checks before submitting
changes. The [release checklist](docs/release_checklist.md) adds coverage, build,
artifact, and installation verification for release candidates.

## Change scope

- Keep changes small and explain the behavior they affect.
- Preserve documented public APIs unless a reviewed change explicitly updates
  the contract and its migration guidance.
- Add focused regression tests when behavior changes.
- Keep authentication, deployment policy, and application-specific integrations
  in the host application.
- Update documentation and generated references when their contracts change.

## Before submission

Confirm tests, lint, and documentation links pass. Describe the problem, the
resulting behavior, and the verification performed. Follow
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md), and consult [SECURITY.md](SECURITY.md)
before sharing sensitive findings.

## Contribution channels

Use the [issue tracker](https://github.com/Mike-Byrne-AI/role-aware-dashboard-toolkit/issues)
for public bug reports and feature proposals. Follow [SECURITY.md](SECURITY.md)
for vulnerability reports; do not include sensitive details in public issues.
