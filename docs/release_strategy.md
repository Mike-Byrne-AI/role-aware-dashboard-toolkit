# Role-Aware Dashboard Toolkit distribution strategy

- Strategy id: `single-package-optional-extras`.
- The Python distribution is `role-aware-dashboard-toolkit`.
- The import namespace is `role_aware_dashboard_toolkit`.
- The initial release candidate is version `0.1.0`.
- The core has no required third-party dependencies.
- `workbench`, `api`, and `pandas` add isolated optional capabilities.
- `full` installs every supported public runtime dependency.
- Application-specific integrations belong in separate applications or plugins.

Publication requires a current distribution-name check, real project URLs,
a monitored security-reporting channel, and the complete
[release checklist](release_checklist.md). A package-index availability check
is an observation, not a reservation or proof of publishing authority.
