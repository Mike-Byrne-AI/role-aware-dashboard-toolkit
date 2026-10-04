# Save and restore named settings

Profiles contain registered non-sensitive control values. Keep the store across
Streamlit reruns. The starter's `session_resources()` already does this.

```python
store = radt.InMemoryProfileStore()
state = {}
registry.ensure_defaults(state)
radt.save_profile("baseline", registry, state, role="Planner", store=store)
loaded = radt.load_profile("baseline", registry, state, store=store)
```

These core helpers operate on dictionaries; a host using them directly owns
authorization. The native dashboard profile menu enforces its action and
per-control permissions.

Loading merges known non-sensitive fields, retains unspecified live values, and
sanitizes stale/out-of-range values. Unknown controls are ignored. Sensitive
values remain live and are not restored. Profile `role` is descriptive metadata.
Selecting a profile previews it; only a successful load records it as active.
When navigation hides the profile menu with `DashboardSections(profiles=False)`,
keep calling `radt.render(config)` on each page. The native menu retains its
selection and unsaved profile name across those reruns without host access to
private session keys. If the selected profile is removed while hidden, reopening
the menu selects `(none)` and retains the draft name and live controls. Current
permissions and freeze still govern actions. An authenticated principal change
clears this state with the rest of the session.

Expand **Preview profile changes** to compare current, saved and effective
values before loading. The preview shows corrections, missing fields retained
from live state, omitted unknown/sensitive fields, and freeze or permission
blocks. Effective values are proposed values; a blocked load applies nothing.
Viewing values requires both metrics-view and profile-load permission. Sensitive
values and values from removed controls are hidden. Previewing does not change
live state, run callbacks, save records or add audit events. Load rereads the
profile and checks current permissions before applying it.

`InMemoryProfileStore` is session-local when retained by the host.
`FileProfileStore(profile_dir)` enables durable local JSON only when the host
explicitly chooses it. Profiles are not a credential store. Preserve corrupt
records and surface `read_errors`; do not reseed or overwrite data simply because
a load returned `None`.

Native loading validates saved field shapes again when Load is requested. A
malformed record raises `ValueError` for direct callers; the dashboard shows a
storage error and the API returns 422. A known-invalid selection disables Save
and Load; authorized Delete remains available. Select `(none)` to save without
using that record as a parent. Live controls remain unchanged. Older
profiles may omit current metadata, and their missing or null values/metadata
retain the historical empty-field meaning. Do not overwrite an invalid profile
as part of recovery without first preserving or deliberately replacing it.

For API-created profiles, use the canonical identifier returned by the API and
encode it as a single route segment; see `guide api`.

Verify save, later changes, reload and a partial profile. Test a mixed-permission
load: either all eligible values apply or none do. Persistence failures should
remain visible, preserve live controls, and produce no success audit event.
