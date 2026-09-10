# Run ledgers

A run ledger is a deterministic chronological view of one run (apart from its
fresh `generated_at` timestamp). It contains:

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
`role_aware_dashboard_toolkit.ledger`. Reconstruction returns the latest full
control snapshot in source sequence; it does not apply values to a live dashboard.
An explicitly empty snapshot clears the reconstructed controls.

## Ordering and snapshots

Entries with valid ISO timestamps are sorted by their UTC instant. Timestamp
text is preserved; naive timestamps are interpreted as UTC. Equal instants
retain source order. Missing or malformed timestamps remain visible after dated
entries, in source order.

Each entry includes `source_sequence`, its position before chronological
sorting: run start, each checkpoint and its embedded audit events in append
order, then run end. Control diffs compare successive checkpoint snapshots in
this source order. Reconstruction also uses source order, so clock skew or an
older audit event cannot replace a later authoritative checkpoint snapshot.
Audit entries are evidence and do not apply their `old`/`new` values.

New ledgers and reconstructed controls detach nested input data. Legacy ledgers
without complete, unique, nonnegative integer `source_sequence` values use
their existing entry order for reconstruction.

`latest_approval_state` describes the latest checkpoint decision in source
order, or an empty string when there is no checkpoint decision. Starting or
completing a run does not approve a checkpoint; start/end entries carry an empty
approval state. Run lifecycle remains available separately as `run_status`.

Ledgers are evidence records. They do not prove external side effects or grant
permission to replay a state.
