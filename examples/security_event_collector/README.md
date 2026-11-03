# Local security-event collector and operator inbox

This example gives Westbridge a separate HTTPS destination for retained
security events and a separate HTTPS inbox for alert transitions. It is an
example-private integration, not a new toolkit API. Keep this directory,
the sibling security_event_wire directory and the business example together
when copying a source distribution.

A local run has three processes and separate private runtime directories.
It does **not** establish separate administrators, disks, cloud accounts,
off-host custody, unattended notification or human response. A compromised
source can still suppress future events or forge reports with its ingest
credential. The collector protects previously accepted records from the
source's API authority, not from its own database owner.

## Delivery and retention contract

Westbridge schema nine freezes each event's canonical bytes and SHA-256 once,
and creates an obligation for every active destination in the same transaction
as the action. The existing local consumer is local-v1. Remote activation
queues **all currently retained events**, including events already acknowledged
locally, and records the cutoff/count. Earlier pruned history is outside that
backfill. Missing credentials never disable a committed destination.

Source pruning requires acknowledgement from every destination. A network
failure leaves the committed event pending; the worker retries event delivery,
not the business action. This retention can fill the finite source queue and
cause ordinary sensitive operations to fail closed. Existing administrator
containment and employee-session termination reservations remain finite.
Restore delivery or review capacity; do not discard pending evidence to obtain
a healthy status.

The collector deduplicates by source/event identity and exact payload hash.
Identical retries return persisted receipt bytes; a conflict retains the
accepted record and opens an alert. The source acknowledges only a validated
HTTP-200 receipt with matching source, destination, collector, event and hash.
A redirect, generic success page or HTTP 202 is not delivery.

The shared codec accepts only fixed fields, codes, bounded canonical JSON and
finite numbers. Its ASCII encoding is example-specific, not RFC 8785.
The optional HTTPX adapter verifies TLS certificates and hostnames, ignores
ambient proxies/CA variables, rejects redirects and compression, limits requests
to 4 KiB and receipts to 2 KiB, and cancels each network attempt after five
seconds, including a trickling response. There is no HTTP fallback.

Default collector limits are 100,000 events, 512 MiB for database and SQLite
sidecars, 1,000 alert cases and 10,000 alert transitions. Page reservations and
admission checks leave operational headroom; they are not unlimited storage or
a power-loss guarantee. There is no retention deletion API. Identical receipts
remain usable at the event-count limit; new events are refused and remain
pending at the source. A filesystem or operational-budget failure that also
prevents alerts requires independent collector monitoring.

## Run the disposable acceptance drill

Install the repository development environment as described in
[CONTRIBUTING](../../CONTRIBUTING.md). Keep the matching business example,
shared wire package and tools together; the drill is not a live-host probe.

~~~powershell
.\.venv\Scripts\python.exe -B tools/business_collector_drill.py --help
~~~

Use the options shown by that command to create a new private attempt. The
drill launches a source delivery worker and separate TLS collector/inbox
processes with generated disposable credentials. Its receipt records the exact
source fingerprint, completed checks and local scope. Preserve failed receipts
and diagnostics; a later successful run does not replace them. Source changes
during a run invalidate its source-bound result.
The fixture uses short monitoring thresholds and simulates lost acknowledgement
at the source after an actual HTTPS commit; it does not simulate physical packet
loss or measure the production-default 90-second/five-minute alert latency.

The source worker is the source process in this drill. It does not qualify the
Westbridge browser, public HTTPS ingress, a physical authenticator, hosted
storage, a real notification recipient or human incident handling.

## Configure a reviewed private installation

Start with disposable data. For existing Westbridge data, preserve the database,
identity key, independent MFA key and current-authority backup, stop ingress and
writers, rehearse explicit schema-nine migration on a protected copy, then follow
the business [hosting procedure](../business_dashboard/HOSTING.md). Do not
reprovision an existing installation.

Install the example requirements into the intended environment:

~~~powershell
.\.venv\Scripts\python.exe -B -m pip install -r examples/security_event_collector/requirements.txt
~~~

Inspect the source identity and destination status without changing them:

~~~powershell
.\.venv\Scripts\python.exe -B examples/business_dashboard/configure_security_delivery.py status --data-dir 'C:\Private\Westbridge'
~~~

Allocate new opaque 32-character lowercase hexadecimal IDs for the collector,
inbox, source-to-collector destination and collector-to-inbox destination.
Register the exact source identity from that status. Provision each service into
a different empty private directory using run.py provision --help. For the
inbox, --peer-id is the collector ID; for the collector, it is the source ID.
The collector requires --inbox-id and --alert-destination-id at provisioning.
Before delivery, set a fixed HTTPS --inbox-endpoint ending in /v1/alerts, either
at provisioning or once through the configure-alerts command.

Provisioning writes ingest.token and a separate operator.token to private
files and prints no token contents. Deliver only the ingest token to the
corresponding writer. Keep collector and inbox operator tokens outside the
source service's authority. On Windows, explicitly inspect directory ACLs;
POSIX owner/mode checks do not prove Windows protection.

Use trusted TLS certificates with the actual hostname/IP in their subject
alternative names. For local tests, use a disposable private CA and supply its
certificate file explicitly. Never distribute its private signing key to the
writers. Serve the inbox first, then the collector:

~~~powershell
.\.venv\Scripts\python.exe -B examples/security_event_collector/run.py serve 'C:\Private\Inbox' --port 8444 --tls-cert 'C:\Private\InboxTLS\server.pem' --tls-key 'C:\Private\InboxTLS\server.key'
~~~

~~~powershell
.\.venv\Scripts\python.exe -B examples/security_event_collector/run.py serve 'C:\Private\Collector' --port 8443 --tls-cert 'C:\Private\CollectorTLS\server.pem' --tls-key 'C:\Private\CollectorTLS\server.key' --inbox-token-file 'C:\Private\CollectorSecrets\inbox.token' --inbox-ca-file 'C:\Private\CollectorSecrets\inbox-ca.pem'
~~~

The default listener is loopback. Access logging and proxy-header trust are
disabled. Expanding network exposure needs separate ingress/firewall and
operational review.

Create a private UTF-8 JSON source configuration, with exactly these keys.
Substitute registered IDs and absolute private paths; these values are
placeholders, not credentials:

~~~json
{
  "v": 1,
  "source_id": "SOURCE_ID",
  "collector_id": "COLLECTOR_ID",
  "destination_id": "DESTINATION_ID",
  "endpoint": "https://127.0.0.1:8443/v1/events",
  "token_file": "C:\\Private\\WestbridgeSecrets\\collector.token",
  "ca_file": "C:\\Private\\WestbridgeSecrets\\collector-ca.pem"
}
~~~

The ca_file value may be null for the adapter's explicit public CA bundle.
Tokens remain in their own private files, never command arguments, JSON values,
URLs or public diagnostics. UTF-16 configuration and duplicate/extra keys are
refused. Paths may not traverse symlinks, junctions or source/Git trees.

With writers stopped, activate the destination using its registered IDs,
endpoint and configuration:

~~~powershell
.\.venv\Scripts\python.exe -B examples/business_dashboard/configure_security_delivery.py enable --data-dir 'C:\Private\Westbridge' --collector-id 'COLLECTOR_ID' --destination-id 'DESTINATION_ID' --endpoint 'https://127.0.0.1:8443/v1/events' --config-file 'C:\Private\WestbridgeSecrets\delivery.json' --maintenance-confirmed
~~~

The maintenance flag is an operator assertion. Activation verifies local
configuration and commits obligations; it does not prove remote delivery.
The endpoint/collector identity cannot be changed in place. A replacement
requires a new destination ID and fully drained prior obligations. Token
rotation for the same destination does not reset receipts or backfill.

Start the business application with --security-delivery-config pointing to
that file. The hosted adapter uses BUSINESS_SECURITY_DELIVERY_CONFIG.
The protected /api/admin/security/events response reports remote destination
counts separately from local delivery and exposes only bounded worker
diagnostics. The offline status command also reports each destination.
Credentials are reloaded from private files; a missing or invalid file leaves
a visible failure and pending obligations.

## Alerts and operator actions

The source sends dedicated heartbeats every 30 seconds independently of event
batches. A persisted source-wide counter prevents old heartbeat requests from
refreshing liveness, including after collector restart or destination changes.
Only a newly accepted heartbeat updates the receiver's timestamp. Event traffic
and /healthz do not refresh it; /healthz reports process life only.

| Rule | Meaning | Operator action |
| --- | --- | --- |
| source_missing | More than 90 seconds since a new dedicated heartbeat or initial registration | Check source process, TLS, egress and scoped credentials. Preserve evidence/access before restarting. |
| source_backlog | Oldest pending destination obligation exceeds 300 seconds, or queue timing is untrustworthy | Inspect failures and capacity. Check clocks/restore state for clock_untrusted. Retry delivery, not the original action. |
| collector_capacity | 80% warning or exhausted count/byte/operational budget | Preserve history and independently recoverable backups; review capacity. Do not purge pending source evidence. |
| event_conflict | Same source/event identity arrived with different bytes | Preserve the accepted record and conflict diagnostics. Investigate sender identity, restore state and possible compromise before resolution. |

Backlog timing uses destination enqueue time, so old history newly backfilled is
not immediately described as a stalled delivery. Future enqueue times or
backward movement within a nonempty queue raise clock_untrusted; they are not
clamped to a healthy age. Receiver-clock rollback prevents normal monitoring
updates until time is trustworthy. A source report is not independent proof of
the source's truthfulness.

Alert cases, immutable transitions and notification obligations commit together.
Ingest credentials cannot read or acknowledge alerts. Collector operator
routes provide bounded GET /v1/operator/status, GET /v1/operator/alerts
and revision-bound POST /v1/operator/alerts/{id}/ack with canonical
{"number":N}. Manual resolve is limited to investigated event conflicts;
condition-driven alerts resolve from their evidence. Operator acknowledgement
does not resolve an ongoing condition.

The inbox has separate operator routes for listing messages and acknowledging
an exact transition. A durable inbox receipt proves arrival only. Automated
tests may exercise an operator credential, but that is not evidence a human
read or acted on a notification. A real unattended channel still needs verified
recipients, ownership, escalation and an exercised runbook.

Both GET /v1/operator/alerts and GET /v1/operator/messages return a collection
and next_cursor. Follow each non-null next_cursor as the cursor query value
until it is null to reach older retained items, including unresolved or
unacknowledged items. The optional limit query parameter is an integer from
1 through 100 (default 100); for example, start with ?limit=50 and continue
with ?limit=50&cursor=<next_cursor>. Pass the returned URL-safe cursor unchanged.
Duplicate, unknown or noncanonical query values are refused. Other routes
do not accept query parameters.

Pages order by creation/arrival time, newest first, with immutable identity
fields breaking ties. A cursor identifies a retained record; the server looks
up its timestamp. Paging is a live traversal, not a frozen snapshot. Newer
arrivals appear when restarting from the first page. Acknowledgement updates
do not move a record between pages, and paging never deletes records.

## Backups and continuity

The source's current-authority restore preserves source identity, destination
descriptors, canonical payload bytes, delivery receipts, pending obligations,
the event-sequence high-water mark and heartbeat counter together. Historical
credentials, sessions, enrollment grants and pending setup authority are still
reconciled/revoked as described in the business recovery guide. Delivery tokens
and TLS private keys are not included in the application bundle.

Collector/inbox backup uses a consistent SQLite snapshot into a new private
directory. Encrypt retained backups and keep them under separately reviewed
custody. Restore-quarantined always produces an offline result that refuses
serving. There is no automatic continuity override.

An old collector backup may have lost events it acknowledged before the source
pruned them. Replaying the source's remaining queue cannot establish that this
gap is absent. Preserve accepted receipt history and an independently current
ledger before deciding continuity; otherwise use a reviewed new destination
identity and explicitly record the unrecoverable gap. Do not remove a quarantine
marker to make an old ledger appear current.
