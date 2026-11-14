# Web component studio

Run `python -m http.server 8092 --bind 127.0.0.1` from this directory, then open
http://127.0.0.1:8092. Stop with Ctrl+C. The gallery uses fictional browser-only
data and makes no business writes. It is not an authenticated application.

`gallery.js` supplies two brand presets and records. `components.js` supplies
escaped metric cards, attention actions, workflow steps, delivery boards and empty states;
`components.css` consumes semantic colors from `theme.css`. Adapt the gallery
or load the same assets in an existing web host. Components never fetch data or
register business handlers. `data-action` is an event identifier, not permission.

The board and `filterItems` helper power both this studio and Westbridge. Try
combined search words (for example `riverside alex`), stage filters and both
brand presets. Search leaves the focused input mounted. Lanes stack on narrow
screens. Each preset has scheduled, in-progress and completed fictional work.
Use `board({lanes, items})` with unique record IDs and declared lanes; pass only
records your host has authorized. See `guide web` for the item/action contract.

For generated colors use `role_aware_dashboard_toolkit.web.WebTheme.css()`;
`streamlit_toml()` maps the same palette to Streamlit configuration. Color
validation prevents CSS injection but does not certify contrast. Verify chosen
palettes in their actual context, including keyboard focus and reduced motion.

Every host must authenticate users and check current permissions, freeze state,
record ownership and revision inside its write transaction. Disabled controls
do not enforce these checks. Read `python -m role_aware_dashboard_toolkit guide
web` and `guide workflows`. The source-distributed Westbridge example shows a
real contact-to-delivery workflow; it is not silently installed by this gallery.

## Repeat this presentation

Choose **Quick walkthrough** for the four-stop introduction. The same tour
controller is used by Westbridge's role-specific workspace walkthroughs.

Open **Make it your own**, edit the brand and palette, and choose **Apply brand**.
Export the applied configuration as `web-presentation.json`. The browser keeps
no saved preference; keep the exported file and generate a fresh studio:

```powershell
python -m role_aware_dashboard_toolkit init ./next-client --web --web-config ./web-presentation.json
```

Import accepts a selected local configuration. Failed validation preserves the
currently applied brand. Configuration contains only version, preset, brand,
headline and theme colors; fictional scenario records remain in `gallery.js`.
The ten declared text/background pairs must reach 4.5:1. This check does not
replace accessibility review of the final application.

`presentation.js` provides validation and presets; `tour.js` provides the
disposable walkthrough controller. `web-config.js` is generated configuration,
and `theme.css` is its generated stylesheet. See `guide web` for the contracts.
