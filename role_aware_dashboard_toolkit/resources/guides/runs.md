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

The native runbook warns when run history cannot be read completely, while
continuing to show readable runs. An unreadable active run keeps its selection;
its actions remain unavailable until storage recovers. A confirmed missing run
clears the active selection. Preserve damaged records, check the store's
`read_errors` and restore access or repair the record before retrying. Historical
read diagnostics remain available even after a successful retry; they do not
keep a recovered run disabled or make a current successful read appear to fail.

Start a run, adjust controls, capture labeled checkpoints, compare them, and
end the run with an outcome. A checkpoint contains detached control, audit and
telemetry evidence subject to the current visibility permissions. Sensitive
controls are excluded. The run keeps its starting profile identifier and updates
its active profile identifier at checkpoint/end.

Native checkpoint and run comparisons show recorded outcome measurements next
to control changes when `can_view_metrics` is granted. They retain sample times
and host-supplied units. Change means right minus left; missing, invalid or
incompatible measurements have no numeric delta. These observations do not prove
that a control change caused an outcome. Run comparisons use each run's final
checkpoint without substituting an older sample when telemetry is absent.

For a custom comparison, opt in explicitly; existing calls keep their original
result shape:

```python
comparison = radt.compare_checkpoints(left, right, include_telemetry=True)
observations = comparison["telemetry_comparison"]
# observations: left_sample_ts, right_sample_ts, metrics
# Each metric: from, to, from_unit, to_unit, delta, status
```

Telemetry hooks can supply `{"metrics": {"latency": 120}, "units": {"latency": "ms"}}`.
Unknown units are shown as unspecified; the toolkit does not convert units.
Direct callers own authorization for the records they compare.

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
