# Change page, card and widget colors

Global colors use Streamlit's official configuration. This helper returns text;
it does not write a file or modify a running app.

```python
from role_aware_dashboard_toolkit.appearance import build_streamlit_theme_toml

snippet = build_streamlit_theme_toml(
    base="light", background_color="#F6F7F2",
    secondary_background_color="#FFFFFF", text_color="#1D342A",
    primary_color="#2F614B", sidebar_background_color="#E7EDE1",
    sidebar_secondary_background_color="#FFFFFF", sidebar_text_color="#1D342A",
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
    group_background_colors={"Plan": "#EEF3E9"},
)
```

Use six-digit `#RRGGBB` colors. Per-group entries override the shared fill.
Names must match registered groups, including groups registered during plugin
setup; hidden registered groups remain valid targets.

The supported workbench baseline is Python >=3.11 and Streamlit >=1.66.1. Global theme APIs were
introduced in >=1.30, independent sidebar colors in >=1.44, and the documented
keyed-container API for group fills in >=1.39; unsupported runtimes fail clearly.
With no fill options, default rendering is preserved. Current runtime details
are available through `inspect`.

## Make the screen useful before adding decoration

The installed Project Pulse starter demonstrates this palette with four named
views: Overview, Plan, Progress and Activity. Its overview shows a small set of
metrics with stated units and sources. Editing controls and audit details have
their own views, using `DashboardSections` rather than hiding generated HTML.
The sidebar explains the current role's editing access and displays Changes
paused when the writable switch is off. Permission checks still run inside
callbacks; presentation never grants access.

Use native Streamlit containers, columns, metrics, labels and help text. Prefer
clear task names and visible actions over decorative panels. Keep a restrained
palette, distinguish surfaces from accents, and do not communicate status by
color alone. Render user-authored names as plain text, not Markdown images or
links. The starter's Chart color field recolors its chart, not the global theme.

These are Streamlit patterns, not an arbitrary HTML/CSS theme adapter. Avoid
targeting Streamlit's private generated DOM selectors. The toolkit's group-fill
implementation uses only its documented keyed containers and validated colors.

## Check the rendered workflow

Verify page, sidebar, inputs and each group in the actual browser, in both
layouts you use. Check text contrast and rerun after editing a control. Also
inspect a phone-width viewport: open its sidebar, navigate between views, and
confirm that labels, values and actions remain visible without horizontal page
scrolling. Test keyboard focus and editing, not only pointer clicks.

Switch between Viewer, Planner and Admin where the application provides those
demo roles. Check that restrictions and the frozen state remain clear, values
survive navigation, and saving then loading a profile restores permitted values.
Keep screenshots alongside interaction results when reviewing a visual change;
screenshots alone do not prove authorization or successful state updates.
