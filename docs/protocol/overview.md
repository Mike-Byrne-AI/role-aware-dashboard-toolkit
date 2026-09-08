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

## Compatibility

Schema versions change only when a record shape changes incompatibly. Readers
should validate before consuming a record and should not infer authority from
the presence of a packet. Application extensions use an `x_` packet-type prefix
and own their payload schema.
