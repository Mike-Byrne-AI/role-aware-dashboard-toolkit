# Working on this authenticated dashboard

Follow the user's request and the host project's instructions. Discover actual
APIs with `python -m role_aware_dashboard_toolkit inspect` and read
`python -m role_aware_dashboard_toolkit guide authentication` before changing
access controls.

Keep OIDC secrets, the identity HMAC key, access database and backups outside
this source tree. Use synthetic data in tests. Never dump `st.user`, tokens,
credentials, raw subjects or complete session state into diagnostics or files.

Keep `prepare_access(config)` before private host reads or session resources.
Check `has_perm` for protected reads and `can_write` immediately before host
mutations. Hidden widgets do not authorize operations. The host controls role
grants; browser values, profile imports and the first visitor never grant Admin.

Verify Viewer denial, unknown-account denial, assigned-role selection, revocation
in an existing session, account switches, and shared freeze before sharing.
Test the real provider redirect flow separately; synthetic claims cannot prove it.
