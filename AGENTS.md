# Working on Role-Aware Dashboard Toolkit

This checkout is the active source for the library. Start with
[CONTRIBUTING.md](CONTRIBUTING.md) and the [documentation map](docs/README.md),
then inspect the files relevant to the user's request. User instructions take
precedence over these repository defaults.

- Keep changes small and preserve public APIs unless their change is requested.
- Keep application-specific integrations, private data, credentials, historical
  evidence, and development-harness state outside the public source tree.
  Curated fictional applications such as `examples/landscaping` may demonstrate
  host integration; their runtime data and credentials must stay outside the checkout.
- Discover package capabilities with `python -m role_aware_dashboard_toolkit
  inspect` and read only relevant `guide` topics. Do not invent supported APIs.
- Verify imports resolve to this checkout when testing source changes. An older
  installed wheel can give a misleading result.
- Run focused regression tests for behavior changes. Check real UI interactions
  for appearance, navigation, profiles, roles, and freeze changes.
- Run the broader checks in CONTRIBUTING before completing coupled changes.
  Report exact commands and results; distinguish historical from current proof.
- Source-distribution contents are explicitly allowed in both `pyproject.toml`
  and `role_aware_dashboard_toolkit/release_audit.py`. Update their contracts when
  adding a shipped example or document; do not broaden the allowlist wholesale.
- Do not overwrite earlier release evidence to describe a new commit. Follow
  the release runbook when preparing a new release candidate.
- Use PowerShell-compatible commands when giving Windows operator instructions.

On Windows, the local development interpreter is `.venv\Scripts\python.exe`
when present. Use its full relative path or activate it before running commands.
No task harness is required to contribute to this repository.
