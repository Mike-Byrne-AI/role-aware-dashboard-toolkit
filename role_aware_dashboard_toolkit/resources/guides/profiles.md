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

`InMemoryProfileStore` is session-local when retained by the host.
`FileProfileStore(profile_dir)` enables durable local JSON only when the host
explicitly chooses it. Profiles are not a credential store. Preserve corrupt
records and surface `read_errors`; do not reseed or overwrite data simply because
a load returned `None`.

For API-created profiles, use the canonical identifier returned by the API and
encode it as a single route segment; see `guide api`.

Verify save, later changes, reload and a partial profile. Test a mixed-permission
load: either all eligible values apply or none do. Persistence failures should
remain visible, preserve live controls, and produce no success audit event.
