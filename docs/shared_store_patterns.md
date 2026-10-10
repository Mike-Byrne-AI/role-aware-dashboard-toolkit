# Shared store patterns

Role-Aware Dashboard Toolkit offers in-memory and file-backed stores for profiles, audit events,
runs, team records, decisions, operator memory, cases, and governance records.

## Choose the smallest store that fits

Use an in-memory store when:

- state is session-scoped
- you are writing tests
- the host application owns persistence

Use a file store when:

- a trusted local or mounted filesystem is available
- records need to survive process restarts
- one application instance owns the write lifecycle

Role-Aware Dashboard Toolkit file stores do not provide distributed locking, cross-process
transactions, or live conflict resolution.

## Diagnostics

Collection reads do not turn unreadable files into a silent empty result.
File-backed stores expose `read_errors`, with entries containing:

- `path`
- `error_type`
- `exception_type`
- `message`

Call `clear_read_errors()` after the host application has surfaced or recorded
the diagnostics.

Missing records remain normal `None`/empty results. Present but corrupt, unsafe,
or unreadable records produce diagnostics.

## Strict JSON boundary

File-store reads and packet imports accept standards-compliant JSON only. They
reject the non-standard `NaN`, `Infinity`, and `-Infinity` constants, as well as
numeric exponents too large to remain finite (for example, `1e9999`). Rejected
store records are skipped and reported through `read_errors`.

Audit JSONL records are separated by physical LF newlines (including CRLF).
Unicode line separators inside JSON strings remain part of the event text and
do not create extra records or change diagnostic line numbers.

Ordinary file and in-memory store writes also reject non-finite numbers. A file
record is serialized successfully before its existing path is replaced, so a
rejected write leaves the prior good record intact. Diagnostic and telemetry
producers that intentionally accept untrusted numeric input must sanitize it at
their own boundary before writing.

## Filesystem safety

Shared record helpers:

- constrain reads and writes to the configured root
- reject symlink and resolved-path escapes
- require regular files with stable identity
- use strict UTF-8 decoding
- use hashed filenames to avoid normalized-id collisions
- resolve direct record reads through hashed filenames only
- surface short writes, replacements, and close failures

These checks protect the final record path. The configured root and actors able
to rename ancestor directories remain part of the trust boundary.

## Store families

| Family | Shape | Ordering | Notes |
| --- | --- | --- | --- |
| Profiles | one JSON object per profile | stable id order | sensitive controls are omitted |
| Runs | one JSON object per run | stable id order | checkpoints remain embedded in the run |
| Team records | JSON collections | timestamp then stable id | comments, assignments, signoffs, handoffs |
| Decisions | one JSON object per decision | stable id order | derived review state remains explicit |
| Operator memory | JSON collections | timestamp then stable id | notes and incidents |
| Cases | one JSON object per case | stable id order | links records without claiming causation |
| Governance | one JSON object per record | stable id order | policy evidence, not external enforcement |
| Audit | append-only JSONL | file order | corrupt lines are diagnosed and skipped |

In-memory variants use JSON-roundtrip copy semantics so callers cannot mutate
stored records through a returned reference.

## Audit writer

`AuditLog` serializes its own background persistence queue. Startup, append, and
shutdown failures are exposed through writer status while bounded in-memory
history remains available. Multiple independent `FileAuditStore` writers do not
gain record-level locking automatically.

## Host responsibilities

The host application should:

- choose a directory with appropriate operating-system permissions
- surface `read_errors` and writer errors
- avoid placing secrets in ordinary records
- define backup and retention policy
- provide coordination if multiple processes can write the same store
