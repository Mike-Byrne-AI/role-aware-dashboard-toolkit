# Record runs, checkpoints and replay

Retain a run store, then enable the native runbook:

```python
config = radt.DashboardConfig(
    registry=registry, run_store=retained_run_store,
    sections=radt.DashboardSections(runbook=True),
)
```

Use `radt.InMemoryRunStore()` for session-local experiments. Choose a file store
explicitly when durable records are required. The starter already retains an
in-memory run store; change its `runbook=False` flag to enable it.

Start a run, adjust controls, capture labeled checkpoints, compare them, and
end the run with an outcome. A checkpoint contains detached control, audit and
telemetry evidence subject to the current visibility permissions. Sensitive
controls are excluded. The run keeps its starting profile identifier and updates
its active profile identifier at checkpoint/end.

Replay restores registered non-sensitive values. Native replay is staged after
widgets and applied before widgets on the next render; current role, writable
state and every affected permission are rechecked. A denied replay applies
nothing and records no successful replay event. Direct core
`apply_replay_packet` callers own authorization.

Run completion is not approval of a rejected checkpoint. Ledger approval
summaries describe checkpoint decisions independently of completion status.
Chronological ledgers are detached from source records.

Verify Start, Checkpoint and End preserve all live controls. Change values,
replay an earlier checkpoint, and confirm exactly one success event. Test replay
while frozen or missing a field permission. Inspect timestamped telemetry rather
than assuming it was sampled at checkpoint time; read `guide telemetry`.
