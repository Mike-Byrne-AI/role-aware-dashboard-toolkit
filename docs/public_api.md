# Role-Aware Dashboard Toolkit public API families

This reference is generated from the OSS-standard API manifest.

## Root export boundary

- Total root exports: `59`
- Stable exports: `59`
- Experimental exports: `0`
- Undocumented exports: `0`
- Root export budget: `60`
- Documented module-only public symbols: `36`

## Usage recipes

### Dashboard controls

```python
import role_aware_dashboard_toolkit as radt

registry = radt.ControlRegistry()
registry.register("Queue depth", kind="number", key="queue_depth", min_value=0, default=0)
registry.register("Maintenance mode", kind="toggle", key="maintenance", default=False)
config = radt.DashboardConfig(registry=registry)
radt.render(config)
```

### Profiles and audit

```python
import role_aware_dashboard_toolkit as radt

registry = radt.ControlRegistry()
registry.register("Page size", kind="number", key="page_size", min_value=1, default=25)
state = {}
registry.ensure_defaults(state)
radt.save_profile("default", registry, state, profile_dir="profiles")
audit = radt.AuditLog()
audit.log("dashboard_ready", detail="default profile loaded", role="Operator")
```

### Optional API server

```python
import role_aware_dashboard_toolkit as radt

registry = radt.ControlRegistry()
registry.register("Page size", kind="number", key="page_size", min_value=1, default=25)
app = radt.create_app(registry)
```

Install `role-aware-dashboard-toolkit[api]` before constructing the FastAPI application.

## Dashboard app shell

Classification: `stable`

Root exports: `5`; module-only symbols: `1`.

- `DashboardConfig`
- `DashboardSections`
- `build_streamlit_theme_toml` (module-only)
- `render`
- `DashboardPlugin`
- `PluginRegistry`

Dashboard rendering and trusted plugin registration.

## Controls and security

Classification: `stable`

Root exports: `9`; module-only symbols: `0`.

- `ControlDef`
- `ControlRegistry`
- `SecurityContext`
- `RoleDef`
- `can_write`
- `get_role`
- `get_role_names`
- `has_perm`
- `make_security_context`

Typed controls, value sanitation, and explicit role policy.

## Operator record modules

Classification: `stable`

Root exports: `0`; module-only symbols: `26`.

- `BaseTeamStore` (module-only)
- `FileTeamStore` (module-only)
- `InMemoryTeamStore` (module-only)
- `BaseDecisionStore` (module-only)
- `FileDecisionStore` (module-only)
- `InMemoryDecisionStore` (module-only)
- `BaseCaseStore` (module-only)
- `FileCaseStore` (module-only)
- `InMemoryCaseStore` (module-only)
- `BaseGovernanceStore` (module-only)
- `FileGovernanceStore` (module-only)
- `InMemoryGovernanceStore` (module-only)
- `BaseOperatorMemoryStore` (module-only)
- `FileOperatorMemoryStore` (module-only)
- `InMemoryOperatorMemoryStore` (module-only)
- `build_team_comment` (module-only)
- `build_review_assignment` (module-only)
- `build_signoff_record` (module-only)
- `build_handoff_summary` (module-only)
- `build_decision_case` (module-only)
- `build_policy_check` (module-only)
- `build_governance_record` (module-only)
- `build_case_record` (module-only)
- `build_operator_note` (module-only)
- `build_incident_record` (module-only)
- `build_incident_timeline` (module-only)

Module-only local operator records; these do not expand the root API.

## Optional API server

Classification: `stable`

Root exports: `2`; module-only symbols: `0`.

- `FASTAPI_AVAILABLE`
- `create_app`

Optional FastAPI routes for controls, profiles, roles, and audit.

## Neutral packets

Classification: `stable`

Root exports: `9`; module-only symbols: `0`.

- `build_packet`
- `build_run_packet`
- `build_checkpoint_packet`
- `build_audit_slice_packet`
- `build_compare_packet`
- `build_ledger_packet`
- `export_packet_json`
- `extract_packet_payload`
- `load_packet_json`

Redacted packet envelopes for core records and namespaced extensions.

## Profiles and audit

Classification: `stable`

Root exports: `15`; module-only symbols: `0`.

- `AuditLog`
- `BaseAuditStore`
- `FileAuditStore`
- `InMemoryAuditStore`
- `BaseProfileStore`
- `FileProfileStore`
- `InMemoryProfileStore`
- `build_profile`
- `delete_profile`
- `list_profiles`
- `load_profile`
- `load_profile_data`
- `merge_profile_values`
- `profile_diff`
- `save_profile`

Profile persistence and auditable dashboard state changes.

## Release tooling

Classification: `stable`

Root exports: `0`; module-only symbols: `3`.

- `audit_release_artifact_members` (module-only)
- `build_release_manifest` (module-only)
- `build_release_audit_markdown` (module-only)

Module-only release audit helpers used by this repository.

## Runbook and snapshots

Classification: `stable`

Root exports: `12`; module-only symbols: `0`.

- `BaseRunStore`
- `FileRunStore`
- `InMemoryRunStore`
- `build_run`
- `append_checkpoint`
- `end_run`
- `build_dashboard_snapshot`
- `compare_dashboard_snapshots`
- `compare_checkpoints`
- `compare_runs`
- `build_replay_packet_from_checkpoint`
- `build_run_ledger`

Local run history, dashboard snapshots, replay previews, and comparisons.

## Runtime and observability

Classification: `stable`

Root exports: `7`; module-only symbols: `0`.

- `cleanup_runtime`
- `normalize_telemetry`
- `safe_call`
- `summarize_telemetry`
- `ObservabilityConfig`
- `ObservabilityPanel`
- `build_observability_snapshot`

Visible callback failures, telemetry normalization, and optional metrics UI.

## Validation and protocol metadata

Classification: `stable`

Root exports: `0`; module-only symbols: `6`.

- `validate_record` (module-only)
- `validate_packet` (module-only)
- `PROTOCOL_CATALOG` (module-only)
- `RECORD_SCHEMA_VERSIONS` (module-only)
- `get_protocol_entry` (module-only)
- `list_protocol_entries` (module-only)

Module-only validators and protocol catalog metadata.
