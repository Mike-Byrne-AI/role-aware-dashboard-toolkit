# Operator Memory / Incident Timeline

Role-Aware Dashboard Toolkit provides a local-first operator-memory layer on top of runs, team ops, and decisions.

## What this layer adds

- operator notes and annotations linked to runs, checkpoints, and decisions
- incident records with severity, status, impact, and suspected-cause fields
- synthesized incident timelines that merge checkpoints, decisions, notes, incidents, audit events, telemetry alerts, and handoffs
- narrative handoff packets that compress the recent operating story of a run into a durable text-first record

## Design intent

This layer is descriptive, not magical.

Role-Aware Dashboard Toolkit can summarize temporal adjacency across records, but it should not claim that it has proven causation.
The operator summary explicitly includes a disclaimer for that reason.

Incident timeline events preserve the source incident status. Counts of open
incidents include `open`, `monitoring`, and `mitigated`; only `closed` removes an
incident from that count. Governance uses the same lifecycle for case closure.

## Stores

Role-Aware Dashboard Toolkit ships:

- `FileOperatorMemoryStore`
- `InMemoryOperatorMemoryStore`

The file-backed store keeps notes, incidents, and narratives in separate local directories under `operator_memory/` by default.

## Public objects

- `build_operator_note(...)`
- `build_incident_record(...)`
- `build_incident_timeline(...)`
- `summarize_incident_timeline(...)`
- `build_operator_summary(...)`
- `build_narrative_handoff_packet(...)`

## UI behavior

When an operator-memory store is configured, the runbook surfaces:

- note entry in the sidebar for the active run
- incident creation for the active run
- a timeline panel inside the runbook
- a narrative handoff preview for the selected run

Native timelines and saved narrative handoffs use audit and telemetry context
captured in the selected run's checkpoints, subject to the corresponding read
permissions. Identical records repeated across checkpoint slices appear once.
The current session's audit log and live telemetry history are not added to a
historical run. A run without captured context has no audit or telemetry timeline
events. Capturing context associates that snapshot with a run; it does not prove
that every captured audit event originated during that run. Public timeline
builders continue to summarize the evidence explicitly supplied by their caller.

## Defer line

This phase does not add:

- autonomous root-cause analysis
- cross-run graph reasoning
- hosted incident collaboration
- background notifications or paging integrations
