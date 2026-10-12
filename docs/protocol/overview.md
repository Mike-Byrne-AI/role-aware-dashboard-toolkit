# Protocol overview

Role-Aware Dashboard Toolkit defines versioned, inspectable records for dashboard operations. The
protocol exists to make state export, validation, comparison, and replay review
predictable without relying on hidden runtime state.

## Records

The protocol catalog describes the retained generic records:

- profiles and audit events
- runs, checkpoints, approvals, and ledgers
- team comments, assignments, signoffs, and handoffs
- decisions, operator notes, incidents, cases, and governance records
- telemetry samples

Each catalog entry names its schema version, builder, validator, and
documentation.

```python
from role_aware_dashboard_toolkit.protocol import get_protocol_entry, list_protocol_entries

run_entry = get_protocol_entry("run")
entries = list_protocol_entries()
```

## Packets

Packets wrap an existing record or comparison in a common export envelope. The
envelope carries identity, source metadata, payload schema version, payload, and
application metadata. See [packets.md](packets.md).

## Validation

Validators are explicit module APIs:

```python
from role_aware_dashboard_toolkit.validators import validate_packet, validate_record
```

Validation returns an `ok` flag and structured errors. JSON loading and export
raise `ValueError` when the packet contract is invalid.

Record validators check required field types, including control mappings,
record lists, and string lists. Invalid list members or scalar values in place
of mappings produce structured errors rather than conversion exceptions.
Full run validation also validates each embedded checkpoint and approval,
including required metadata, schema versions and declared approval states.
Embedded audit rows retain their existing field-shape checks, so checkpoint
builders can still accept partial external audit events.
Decision blockers are records containing named details. Governance
summary counters must be integers and its approval role lists must contain strings
when present; older records may omit these optional fields.
Governance policy checks require their declared identifiers, titles and results;
optional blocker flags must be booleans. Present enum fields must name a declared
value, including inside approvals and policy checks; an empty string is invalid.
Ledger entry fields are validated before import, including control mappings and
nonnegative integer source sequences. Complete unique sequences reconstruct in
source order. Legacy entries with omitted, incomplete or duplicate valid sequences
retain their list order; validation does not invent or repair sequence metadata.
Additional application fields are retained. Validation does not grant authority
or evaluate application business rules.

## JSON schemas

The source checkout and source distribution include 12 JSON Schema Draft 2020-12
contracts in `schemas/`: case, checkpoint, decision, governance, incident,
incident timeline, ledger, narrative handoff, operator note, packet, replay, and
run. Each file is self-contained and can validate records offline; nested
definitions do not require another file or a network lookup. The installed wheel
provides the Python validators, not this separate schema directory.

Record schemas describe complete records. The packet schema instead checks
present fields in partial payloads, including nested records, to preserve packet
compatibility. Both permit additional application fields. Required fields, field
types, allowed values, versions, and nested rules are checked against runtime
validation by mandatory development tests. `jsonschema` is a development
dependency; the library does not load these files or require it at runtime.

The portable schema contract uses numeric versions and canonical packet names.
It does not promise identical results for every Python input:

- JSON Schema treats an integral number such as `1.0` as an integer; Python
  validators require actual integers in integer fields and reject floats.
- Python accepts some legacy packet version strings and normalizes packet names;
  those compatibility behaviors are described in [packets.md](packets.md).
- Extension payload version comparisons remain runtime checks. Applications own
  the rest of an extension payload's contract.

## Compatibility

Schema versions change only when a record shape changes incompatibly. Readers
should validate before consuming a record and should not infer authority from
the presence of a packet. Application extensions use an `x_` packet-type prefix
and own their payload schema.
