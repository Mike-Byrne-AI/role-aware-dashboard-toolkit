# Role-Aware Dashboard Toolkit distribution reference

Role-Aware Dashboard Toolkit defines one Python distribution with a dependency-free core and explicit optional extras.

## Role-Aware Dashboard Toolkit API

- Artifact id: `api`
- Family: `extension`
- Install target: `role-aware-dashboard-toolkit[api]`
- Docs: `docs/api_security.md`
- Description: Optional FastAPI control, profile, role, and audit routes.

## Role-Aware Dashboard Toolkit authenticated Streamlit UI

- Artifact id: `auth`
- Family: `ui`
- Install target: `role-aware-dashboard-toolkit[auth]`
- Docs: `role_aware_dashboard_toolkit/resources/guides/authentication.md`, `role_aware_dashboard_toolkit/resources/guides/deployment.md`
- Description: Optional OIDC login with server-owned role grants and shared freeze.

## Role-Aware Dashboard Toolkit core

- Artifact id: `core`
- Family: `core`
- Install target: `role-aware-dashboard-toolkit`
- Docs: `README.md`, `docs/public_api.md`
- Description: Dependency-free dashboard controls, profiles, audit, plugins, and records.

## Role-Aware Dashboard Toolkit full

- Artifact id: `full`
- Family: `full`
- Install target: `role-aware-dashboard-toolkit[full]`
- Docs: `README.md`, `docs/distribution.md`
- Description: All supported public Role-Aware Dashboard Toolkit runtime dependencies.

## Role-Aware Dashboard Toolkit tabular views

- Artifact id: `pandas`
- Family: `extension`
- Install target: `role-aware-dashboard-toolkit[pandas]`
- Docs: `docs/dashboard_tools.md`
- Description: Optional pandas-backed audit and observability tables.

## Role-Aware Dashboard Toolkit Streamlit UI

- Artifact id: `workbench`
- Family: `ui`
- Install target: `role-aware-dashboard-toolkit[workbench]`
- Docs: `README.md`, `docs/dashboard_tools.md`
- Description: Optional Streamlit dashboard rendering.
