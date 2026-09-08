# Contributing to Role-Aware Dashboard Toolkit

Contributions should keep the dashboard library usable across applications.

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

## Release readiness

Pre-OSS release state remains blocked on `oss_public_coordinates` and
`security_intake_contact` until real public project URLs and a monitored public
security reporting contact are documented. This local candidate does not yet
provide a public submission or reporting destination.
