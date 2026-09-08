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

## Design guardrail

Cases describe linked records and investigation state.
They do not claim to prove causation.
