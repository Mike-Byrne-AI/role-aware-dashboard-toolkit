# Role-Aware Dashboard Toolkit distribution strategy

- Strategy id: `single-package-optional-extras`.
- The Python distribution is `role-aware-dashboard-toolkit`.
- The import namespace is `role_aware_dashboard_toolkit`.
- The initial release candidate is version `0.1.0`.
- The core has no required third-party dependencies.
- `workbench`, `api`, and `pandas` add isolated optional capabilities.
- `full` installs every supported public runtime dependency.
- Application-specific integrations belong in separate applications or plugins.

The configured release channel is `github-source` at
[Mike-Byrne-AI/role-aware-dashboard-toolkit](https://github.com/Mike-Byrne-AI/role-aware-dashboard-toolkit).
These are planned coordinates until the repository is reachable. Finish local
metadata and policy checks before freezing the commit, then verify hosted CI
and live repository settings for that same SHA before the visibility change.
See the [release checklist](release_checklist.md) and
[publication runbook](release_runbook.md).

Package-index publication is disabled for this channel. No PyPI ownership,
reservation, or publishing authority is claimed. A future package-index release
requires a separate decision and current account/name verification.
