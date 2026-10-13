# Change page, card and widget colors

Global colors use Streamlit's official configuration. This helper returns text;
it does not write a file or modify a running app.

```python
from role_aware_dashboard_toolkit.appearance import build_streamlit_theme_toml

snippet = build_streamlit_theme_toml(
    base="light", background_color="#F3F6FA",
    secondary_background_color="#E2E8F0", text_color="#172033",
    primary_color="#0F766E", sidebar_background_color="#E8EEF4",
)
```

Merge the snippet into the host project's `.streamlit/config.toml`, preserving
unrelated options and editing existing theme sections rather than duplicating
them. Start Streamlit from that project directory. `background_color` controls
the page; `secondary_background_color` controls widget/input surfaces. It does
not set individual group-card fills.

For group cards, configure Python:

```python
config = radt.DashboardConfig(
    auth_mode="demo",
    registry=registry, layout="columns", columns_per_row=2,
    card_background_color="#FFFFFF",
    group_background_colors={"Plan": "#EFF6FF"},
)
```

Use six-digit `#RRGGBB` colors. Per-group entries override the shared fill.
Names must match registered groups, including groups registered during plugin
setup; hidden registered groups remain valid targets.

The supported workbench baseline is Streamlit >=1.65.0. Global theme APIs were
introduced in >=1.30, independent sidebar colors in >=1.44, and the documented
keyed-container API for group fills in >=1.39; unsupported runtimes fail clearly.
With no fill options, default rendering is preserved. Current runtime details
are available through `inspect`.

Verify page, sidebar, inputs and each group in the actual browser, in both
layouts you use. Check text contrast and rerun after editing a control. The
starter's Chart color field recolors its chart, not the global theme.
