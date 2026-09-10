# Replay contract

A replay record is an explicit description of a possible control-state restore.

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
