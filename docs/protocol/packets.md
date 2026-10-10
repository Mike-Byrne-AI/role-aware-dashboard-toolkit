# Role-Aware Dashboard Toolkit packets

A packet is a JSON-safe envelope around an inspectable record. Packets make
exports uniform; they do not grant permission or execute work.

## Envelope

Every packet contains:

- `schema_version`
- `packet_type`
- `packet_id`
- `exported_at`
- `source_app`
- `source_version`
- `payload_schema_version`
- `payload`
- `meta`

## Built-in types

The built-in packet types are:

- `profile`
- `run`
- `checkpoint`
- `audit_slice`
- `compare`
- `replay`
- `ledger`
- `narrative_handoff`

Applications may define types prefixed with `x_`. Other unknown types are
rejected. Type names are lowercase identifiers of at most 64 characters, starting
with a letter and containing only letters, digits and underscores. Construction,
validation, import and export share these rules. Surrounding whitespace and
uppercase letters are accepted and canonicalized to lowercase by construction,
import and export. Validation reports validity without mutating the input;
export also leaves the original packet unchanged.

## Builders

The package root exports the common builders:

```python
import role_aware_dashboard_toolkit as radt

packet = radt.build_run_packet(run, source_version=radt.__version__)
raw = radt.export_packet_json(packet)
restored = radt.load_packet_json(raw)
```

`build_packet()` is the generic entry point for built-in and namespaced
application types. Convenience wrappers provide stable metadata for runs,
checkpoints, audit slices, comparisons, and ledgers.

## Redaction and serialization

Payload and metadata path values are redacted by default. Callers must opt in
explicitly to local paths when constructing a generic packet. Export validates
the envelope first and uses strict JSON encoding; `NaN`, positive infinity, and
negative infinity are rejected.

Do not put credentials in packets. Redaction is a defensive boundary for local
paths and known sensitive values, not a secret-management system.

## Validation

```python
from role_aware_dashboard_toolkit.validators import validate_packet

result = validate_packet(packet)
if not result["ok"]:
    raise ValueError(result["errors"])
```

Consumers should validate before trusting packet structure and separately apply
their own authorization and business rules to the payload.

Built-in packet types also check the types, schema versions and declared states
of toolkit fields present in their payload, including embedded run checkpoints
and approvals. For compatibility, partial payloads remain accepted; envelope
validation does not require missing record metadata, including metadata omitted
from those embedded records. Use `validate_record()` when a consumer needs a
complete current record. Extension payloads remain application-owned.
Present ledger entry fields are also checked, so malformed entry kinds, control
mappings and source sequences cannot pass import and alter reconstruction.
Optional legacy sequence metadata may remain absent; incomplete or duplicate
nonnegative sequences retain the existing list-order behavior.
