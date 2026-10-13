# Preserve authority while customizing

In demo mode the role selector is a local demonstration of authorization. A
new demo session starts in its least-privileged role (Viewer for the built-in
roles), and only a role with `can_manage_freeze` can change Controls Writable.
Shared apps should use `init my-dashboard --auth` and `guide authentication`:
verified identity receives server-owned role grants and can select only assigned
roles. Shared freeze is checked again at protected writes. The legacy
`DashboardConfig(auth_hook=...)` remains available for host-managed identity.
Auth failure locks the context instead of falling back to Admin.
The reserved `Unauthenticated` role always denies permission checks, including
when host code supplies `default=True` to a permission helper.

```python
roles = {
    "Planner": radt.RoleDef(
        "Planner",
        {"can_view_metrics": True, "can_edit_controls": True,
         "can_save_profiles": True, "can_load_profiles": True},
    ),
}
config = radt.DashboardConfig(auth_mode="demo", registry=registry, custom_roles=roles)
```

Custom definitions extend/override named built-in roles; they do not remove
other built-ins. A custom permission is not automatically granted to Admin:
define that grant explicitly when the application needs it. Permission values
must be `True` or `False`; other values raise `TypeError`, and only an explicit
`True` grants.

A registered control requires its declared permission and an enabled writable
switch. Native profile loads and replays check every affected control before
applying anything. Saved profile role metadata never grants permissions or
overrides authenticated identity.

Read permission for a panel does not override control sensitivity. Native
historical views, comparisons, summaries, audit downloads and API responses
filter sensitive values using the current registry and historical sensitivity
metadata. The stored evidence remains unchanged. Custom output code must apply
equivalent checks; raw record builders and stores are trusted host interfaces.

Combined reviews also require access to the evidence they consume. For example,
a governance panel needs decision-read permission as well as governance access,
including saved reviews after a decision store is removed. Unreadable or denied evidence cannot
be treated as an empty collection to produce an approval.

For custom code:

```python
if radt.has_perm(context["ctx"], "can_view_metrics"):
    context["st"].write("Authorized data")
if radt.can_write(context["ctx"], "can_request_review"):
    # The host must define this permission and check it at action time.
    pass
```

Hiding a section is presentation only. Plugin callbacks must enforce their own
data/action boundaries using the current context. In authenticated mode, setup
receives the prepared access context; other modes pass `ctx=None` to setup.
Setup runs once per registration and can be shared across sessions: never cache
user data, identities or authorization decisions there. Use the current render
context and check permissions again at each protected read or action.

Verify allowed and denied roles, freeze on/off, auth-hook failure, and mixed
profiles containing a restricted field. Confirm denied changes create no success
audit event. Do not put credentials in field defaults, profiles or guide text.
