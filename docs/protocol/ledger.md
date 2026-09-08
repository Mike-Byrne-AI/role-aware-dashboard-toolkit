# Run ledgers

A run ledger is a deterministic chronological view of one run. It contains:

- a `run_started` entry
- one entry for each checkpoint
- embedded checkpoint audit-event entries
- an optional `run_ended` entry

Ledger entries preserve control snapshots, control diffs, approval state,
telemetry, actor/role context, and source identifiers.

```python
import role_aware_dashboard_toolkit as radt

ledger = radt.build_run_ledger(run)
packet = radt.build_ledger_packet(ledger)
```

`reconstruct_controls_from_ledger()` and `ledger_summary()` are available from
`role_aware_dashboard_toolkit.ledger`. Reconstruction returns the most recent non-empty control
snapshot; it does not apply values to a live dashboard.

Ledgers are evidence records. They do not prove external side effects or grant
permission to replay a state.
