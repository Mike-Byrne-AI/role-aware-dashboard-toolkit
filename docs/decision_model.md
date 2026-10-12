# Decision Model

Role-Aware Dashboard Toolkit provides a first-class decision layer on top of runs, checkpoints, approvals, assignments, signoffs, and handoffs.

## Why this exists

The runbook records what happened.
The decision layer records what the operating team currently believes should happen next.

It turns adjacent review artifacts into one durable case object with:

- a current decision state
- blocker summaries
- allowed next actions
- a transition history
- the latest approval, signoff, and handoff status

## Core record

A decision case includes:

- `decision_id`
- `run_id`
- `checkpoint_id`
- `state`
- `approval_state`
- `latest_signoff_decision`
- `latest_handoff_status`
- `open_assignment_count`
- `blockers`
- `allowed_actions`
- `history`

## State ladder

Role-Aware Dashboard Toolkit decision states are:

- `proposed`
- `review_requested`
- `in_review`
- `changes_requested`
- `approved`
- `rejected`
- `frozen`
- `replay_only`
- `handoff_pending`
- `handed_off`
- `closed`

## Derivation order

The state machine is derived with this priority shape:

1. closed handoff closes the case
2. frozen / replay_only approval blocks further live progression
3. rejected checkpoint approval or rejected signoff rejects the case
4. accepted or pending handoff moves into handoff states
5. changes_requested signoff blocks with revision intent
6. approved signoff approves the case
7. in_review assignment status moves into active review
8. any open assignment moves into review_requested
9. otherwise approval state decides between approved or proposed

Completed assignments do not request another review. A rejected checkpoint
retains a rejection blocker even when another workflow state, such as a closed
handoff, takes precedence. An approving signoff does not clear a rejected
checkpoint approval.
Governance also checks the decision's recorded checkpoint approval independently
of its workflow state, including closed cases and older saved decision snapshots.

Latest evidence is ordered by its ISO timestamp as an instant in UTC, including
offset-bearing timestamps and the `Z` suffix. Historical timestamps without a
timezone are treated as UTC. Undated or malformed timestamps remain visible
after dated records; their order is not inferred from their text.

Decision summaries retain an explicitly empty latest control snapshot from the
run. Synchronization uses the previous summary's controls only when the supplied
run omits `latest_controls` or sets it to `None`.

## Scope

This layer is local-first and human-supervised.
It is not a ticketing system, workflow engine, or autonomous coordinator.
Runbook rendering previews decision state, but persistence is explicit: operators must press **Save decision snapshot** to write a decision record.
