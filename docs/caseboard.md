# Caseboard Model

Role-Aware Dashboard Toolkit provides a cross-run caseboard layer.

A case is a durable investigation record that can outlive any single run. It links:

- runs
- checkpoints
- decisions
- incidents
- narrative handoff packets
- operator notes

## Core fields

- `case_id`
- `title`
- `summary`
- `state`
- `priority`
- `linked_run_ids`
- `linked_incident_ids`
- `linked_narrative_ids`
- `history`
- `findings`
- `hypotheses`

## States

- `open`
- `investigating`
- `monitoring`
- `mitigated`
- `closed`

## Why it exists

The runbook tells the story of a single run.
The caseboard tells the story of a repeated or ongoing issue across runs.

This is the bridge from per-run operator memory to multi-run investigation memory.

## Typical flow

1. An operator opens an incident on a run.
2. A narrative handoff packet is saved.
3. A case is created that links the run, incident, and narrative.
4. Later incidents from other runs are linked into the same case.
5. The case is reopened or closed as the investigation evolves.

Caseboard records are review artifacts, not execution triggers. Saving or linking cases/governance snapshots is always an explicit operator action.

## Closing a case

When a governance store is configured, the native **Close case** button honours
governance. Each render evaluates the selected case as the governance panel
previews it; while that evaluation lists `close_case` among its blocked
actions (unresolved incidents, or missing signoff roles for the case's
severity), the button is disabled, a caption gives the governance summary, and
a click is refused. If governance cannot be evaluated for the current user,
for example without `can_view_governance` or `can_view_decisions`, or with
unreadable linked evidence, closing is refused and the caption says so. Without
a governance store the button keeps its earlier behaviour. Reopening a case is
not gated.

Since 0.2.0 this replaces the earlier behaviour, in which the button closed a
case whatever governance said.

## Design guardrail

Cases describe linked records and investigation state.
They do not claim to prove causation.
