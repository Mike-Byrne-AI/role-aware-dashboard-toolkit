# Preserve authority while customizing

In demo mode the role selector is a local demonstration of authorization.
Shared apps should use `init my-dashboard --auth` and `guide authentication`:
verified identity receives server-owned role grants and can select only assigned
roles. Shared freeze is checked again at protected writes. The legacy
`DashboardConfig(auth_hook=...)` remains available for host-managed identity.
Auth failure locks the context instead of falling back to Admin.

```python
roles = {
    "Planner": radt.RoleDef(
        "Planner",
        {"can_view_metrics": True, "can_edit_controls": True,
         "can_save_profiles": True, "can_load_profiles": True},
    ),
}
config = radt.DashboardConfig(registry=registry, custom_roles=roles)
```

Custom definitions extend/override named built-in roles; they do not remove
other built-ins. A custom permission is not automatically granted to Admin:
define that grant explicitly when the application needs it.

A registered control requires its declared permission and an enabled writable
switch. Native profile loads and replays check every affected control before
applying anything. Saved profile role metadata never grants permissions or
overrides authenticated identity.

For custom code:

```python
if radt.has_perm(context["ctx"], "can_view_metrics"):
    context["st"].write("Authorized data")
if radt.can_write(context["ctx"], "can_request_review"):
    # The host must define this permission and check it at action time.
    pass
```

Hiding a section is presentation only. Plugin callbacks must enforce their own
data/action boundaries using the current context; setup has no user context.

Verify allowed and denied roles, freeze on/off, auth-hook failure, and mixed
profiles containing a restricted field. Confirm denied changes create no success
audit event. Do not put credentials in field defaults, profiles or guide text.
