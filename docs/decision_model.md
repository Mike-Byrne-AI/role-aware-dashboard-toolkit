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
3. rejected signoff rejects the case
4. accepted or pending handoff moves into handoff states
5. changes_requested signoff blocks with revision intent
6. approved signoff approves the case
7. in_review assignment status moves into active review
8. any open assignment moves into review_requested
9. otherwise approval state decides between approved or proposed

## Scope

This layer is local-first and human-supervised.
It is not a ticketing system, workflow engine, or autonomous coordinator.
Runbook rendering previews decision state, but persistence is explicit: operators must press **Save decision snapshot** to write a decision record.
