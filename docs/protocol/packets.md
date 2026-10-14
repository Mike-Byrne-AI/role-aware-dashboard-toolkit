# Role-Aware Dashboard Toolkit packets

A packet is a JSON-safe envelope around an inspectable record. Packets make
exports uniform; they do not grant permission or execute work.

## Envelope

Toolkit packet builders include:

- `schema_version`
- `packet_type`
- `packet_id`
- `exported_at`
- `source_app`
- `source_version`
- `payload_schema_version`
- `payload`
- `meta`

Validation requires `schema_version`, `packet_type`, `packet_id`, `exported_at`,
`payload_schema_version`, and `payload`. Source metadata and `meta` may be absent
on imported packets; when present, their types are checked. Additional application
fields are accepted and retained.

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

A packet nests at most 500 levels of mappings and lists, counting the envelope
(`MAX_PACKET_NESTING_DEPTH`). Building, exporting, loading and rendering a
packet at that limit leaves the host about 450 to 490 of Python's default
1,000 stack frames on Python 3.10 to 3.14; the low end is for a deepest value
that is itself a URL nested in other URLs' queries. Construction, import and export raise `ValueError`
for a deeper packet, or for a payload or metadata that contains a cycle, before
redaction or JSON encoding starts. A value referenced from several places is
walked once per reference, so they also refuse a packet whose shared values
would add more than 1,000,000 container visits beyond the containers it holds
(`MAX_SHARED_VALUE_EXPANSION`); a packet without shared values is never limited
by this.

File URIs, with or without `//` (`file:///x`, `file:/x`, `file:C:/x`), and
editor links that carry a local path (`vscode://file/...` and the same form in
other editors) are redacted as local paths.

Path redaction takes time proportional to the length of the text. It scans at
most 1 MiB (1,048,576 characters) of any one string value or mapping key. An
oversize string keeps the whole lines before that limit, with their normal
redaction; the line that crosses the limit and everything after it are
dropped, never emitted unscanned, and replaced by
`<redacted-oversize-text: N characters omitted>`. A string with no line break
before the limit is replaced whole. The same limit applies wherever the
toolkit redacts local paths, including audit events and diagnostics. A single path longer than 4,096 characters is redacted without
being resolved. URL queries and fragments are scanned for paths, including URLs
nested inside them, to eight levels; anything nested deeper is replaced by
`<redacted-local-path>`. Opting in to local paths skips redaction and its
limits.

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
their own authorization and business rules to the payload. Validation errors
name the field and its allowed values or expected type; they never repeat a
rejected value, so error text can be logged without copying payload content.
An integer `schema_version` is the one value named, as in
`Unexpected schema_version for run: expected 1, found 2.`

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

The self-contained [packet JSON schema](../../schemas/packet.schema.json) covers
all eight built-in payload types with these same partial-record rules. Its
portable contract requires canonical lowercase packet names and numeric
`payload_schema_version` values. Runtime validation additionally accepts legacy
digit strings such as `"1"` for `payload_schema_version`. Import and export can
retain those strings, so successful export alone does not guarantee schema
conformance. Use integer versions when creating portable packets.

For `x_` extensions, runtime validation also compares `payload_schema_version`
with `payload.schema_version` when both can be interpreted as integers, including
legacy digit strings. A mismatch is rejected. That comparison between arbitrary
application versions is not expressed by the JSON schema; extension consumers
must perform it themselves or use `validate_packet()`. Other payload fields
remain application-owned. See the [protocol overview](overview.md#json-schemas)
for the JSON Schema versus Python integer distinction.
