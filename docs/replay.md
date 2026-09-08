# Replay

Replay helpers reconstruct control state from a checkpoint or audit history.
They are intended for preview and operator-approved restoration, not automatic
execution.

```python
import role_aware_dashboard_toolkit as radt

preview = radt.build_replay_packet_from_checkpoint(checkpoint)
```

The root helper returns a replay record containing the source id, approval
state, controls, and touched keys. Lower-level helpers for audit-derived
previews and explicit application are available from `role_aware_dashboard_toolkit.replay`.

See [replay_contract.md](replay_contract.md) for the application boundary.
