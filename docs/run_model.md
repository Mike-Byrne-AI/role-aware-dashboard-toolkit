# Run and checkpoint model

A run captures one bounded operator session. A checkpoint captures an explicit
point-in-time state inside that run.

## Run fields

The run record includes:

- identity, timestamps, actor, role, and source context
- status, notes, tags, and outcome
- source and active profile identifiers
- initial and latest control snapshots
- ordered checkpoints and the latest checkpoint id

Valid statuses are `draft`, `active`, `completed`, and `aborted`.

## Checkpoints

A checkpoint includes:

- identity, timestamp, label, and reason
- control, audit, and telemetry snapshots
- approval state and approval record
- actor, role, and source

Valid approval states are `proposed`, `approved`, `rejected`, `frozen`, and
`replay_only`.

## Example

```python
import role_aware_dashboard_toolkit as radt

run = radt.build_run({"maintenance_mode": False}, role="Operator")
run = radt.append_checkpoint(
    run,
    {"maintenance_mode": True},
    label="maintenance enabled",
    approval_state="approved",
)
run = radt.end_run(run, outcome="maintenance window opened")
```

Builders return new dictionaries. Recorded checkpoints can be compared,
converted to replay previews, stored, exported as packets, or assembled into a
ledger.

## Guardrails

- replay data comes from explicit recorded state
- approval state remains visible and serializable
- a record does not prove an external action occurred
- the model remains useful without a UI or external service
