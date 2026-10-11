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

## Fields

- `schema_version`
- `source_type`
- `source_id`
- `approval_state` when derived from a checkpoint
- `controls`
- `touched_keys`

## Rules

- build replay records only from recorded checkpoint or audit data
- deeply detach replay control values from their source evidence
- display the source and touched keys before application
- pass values through the current `ControlRegistry` during application
- apply only controls that are registered, non-sensitive, and not equal to the
  `<redacted-secret>` marker
- restore eligible values with sensitive restoration disabled while preserving
  registry sanitation
- require host-application authorization before changing live state
- record the resulting change in the host audit path

Audit-derived previews may contain redaction markers or keys no longer present
in the registry. Those entries remain inspectable in the packet but are inert
during application. `apply_replay_packet()` reports only eligible controls in
`applied` and `touched_keys`; ignored sensitive, redacted, and unknown entries
do not count as applied. `corrected` remains the registry sanitation count.

Replay does not perform external actions or bypass the dashboard's
authorization boundary.

## Native dashboard lifecycle

The native replay button stages an operation without changing live widgets or
recording success. On the next render, after resolving the current auth role and
writable switch but before control widgets are created, the dashboard rechecks
the action permission and every affected control permission. A denial cancels
the whole operation with visible feedback and no success audit event. An auth
failure also cancels a pending replay. Successful application records one
`checkpoint_replay` event and preserves sensitive values.

Native replay additionally omits historically sensitive controls and values
containing nested secret-named fields before restoration can turn them into
visible text. The staged operation retains the source classification and checks
current sensitivity again at application time. This browser boundary does not
change the trusted core `apply_replay_packet()` contract.
