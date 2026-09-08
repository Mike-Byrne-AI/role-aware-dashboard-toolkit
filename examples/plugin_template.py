import role_aware_dashboard_toolkit as radt


def build_plugin():
    return radt.DashboardPlugin(
        name="example-plugin",
        version="0.1.0",
        description="Template plugin that renders a small sidebar section and panel.",
        capabilities=["sidebar", "panel"],
        render_sidebar=lambda context: context["st"].caption("Example sidebar plugin loaded."),
        render_panel=lambda context: context["st"].write("Example panel plugin loaded."),
    )
