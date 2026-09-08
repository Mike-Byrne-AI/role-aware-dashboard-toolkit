from __future__ import annotations


def build_public_api_usage_recipe_lines() -> list[str]:
    return [
        "## Usage recipes",
        "",
        "### Dashboard controls",
        "",
        "```python",
        "import role_aware_dashboard_toolkit as radt",
        "",
        "registry = radt.ControlRegistry()",
        'registry.register("Queue depth", kind="number", key="queue_depth", min_value=0, default=0)',
        'registry.register("Maintenance mode", kind="toggle", key="maintenance", default=False)',
        "config = radt.DashboardConfig(registry=registry)",
        "radt.render(config)",
        "```",
        "",
        "### Profiles and audit",
        "",
        "```python",
        "import role_aware_dashboard_toolkit as radt",
        "",
        "registry = radt.ControlRegistry()",
        'registry.register("Page size", kind="number", key="page_size", min_value=1, default=25)',
        "state = {}",
        "registry.ensure_defaults(state)",
        'radt.save_profile("default", registry, state, profile_dir="profiles")',
        "audit = radt.AuditLog()",
        'audit.log("dashboard_ready", detail="default profile loaded", role="Operator")',
        "```",
        "",
        "### Optional API server",
        "",
        "```python",
        "import role_aware_dashboard_toolkit as radt",
        "",
        "registry = radt.ControlRegistry()",
        'registry.register("Page size", kind="number", key="page_size", min_value=1, default=25)',
        "app = radt.create_app(registry)",
        "```",
        "",
        "Install `role-aware-dashboard-toolkit[api]` before constructing the FastAPI application.",
        "",
    ]


__all__ = ["build_public_api_usage_recipe_lines"]
