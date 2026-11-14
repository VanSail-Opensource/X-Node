# Bounded command receipts

Command admission reserves a bounded worker and registers its request identity
without filesystem I/O. Two workers handle ordinary network/bulk utilities;
one separate slot handles urgent controls and traffic barriers, one handles
hourly credit operations, and one handles bounded status reads. `jobs.list` and
`update.status` remain immediate recovery reads. A stalled download, full
mutation history or failed DDNS provider cannot occupy all these consumers.
Admission returns a busy error when the appropriate lane is full; there is no
unbounded queue. Unsupported command names are rejected before admission.

Live command IDs bind the command name and canonical argument digest. Canonical
arguments retain exact JSON numbers and reject duplicate object keys, trailing
JSON, non-object roots and excessive nesting. The digest stays in memory; raw
credentials and provider arguments do not enter the receipt journal. A retained
identical ID replays its result; different arguments cannot reuse the ID. Use a
new command ID for a deliberate retry after a terminal failure.

## Persistence ownership

`job_privacy.go` persists only operations that need the generic uncertain-intent
barrier: certificate issuance/renewal, update installation/rollback, transactional
firewall apply, and exact traffic flush barriers. A worker first persists the
intent, then executes the operation and replaces the intent with its result.
File and directory barriers must succeed before execution. Completion-write
failure preserves uncertainty across restart because effects may already exist.
`state.AtomicWrite` owns both durability barriers; the command journal does not
repeat the same directory fsync.

DDNS SET/discovery, runtime reload, geodata refresh, versioned firewall ban/GeoIP
synchronization and transaction confirmation reconcile current state. Hourly
credit installation, sealing and proof acknowledgment already own stronger
reservation/issue/proof identities in the durable credit journal. These commands
keep bounded live replay receipts and use their native state on a restart; they
no longer write a second generic command intent. Repeating a command after a
restart must retain its original native identity. This does not clear or bypass
financial credit, firewall, certificate or update evidence.

Observations, config validation, update checks, speed tests and existing volatile
IP/session/lease controls also remain off disk. Their independent state and epoch
policies remain authoritative. Observed client source-IP and machine-metric
payloads never enter the command journal.

`job_journal.go` serializes worker-only writes using `persistMu`. Bounded state
copies use the short registry mutex, which never owns disk I/O. Traffic ACKs,
authorization reception, status reads and repeatable utilities remain independent
of a blocked generic journal write. A failed same-resource operation can still
require its own native recovery barrier; unrelated features retain capacity.

## Bounds and terminal failures

Durable receipts and volatile results each retain at most 128 entries and
strictly less than 2 MiB of serialized JSON. Individual retained results are at
most 64 KiB. Protected uncertain identities cannot be evicted by observations or
new mutations; exhausting durable capacity refuses those mutations only. IDs
remain globally unique beyond the bounded completed-receipt window. Result data
retains exact JSON integers. Native read results can use the 16 MiB transport
frame limit with envelope headroom; large reads are returned but not retained.
Oversized mutation outcomes become small uncertain receipts rather than false
completed results.

Persisted failed receipts include private `terminal_failure` evidence only when
execution was never entered or a typed refusal proves a terminal outcome. These
receipts remain failed and evictable after restart. An unnegotiated/invalid
traffic flush or a known full volatile traffic queue is a retryable refusal and
cannot become a permanent uncertain obligation. A successful flush still keeps
its exact original barrier. Legacy ambiguous failures and unsuccessful completion
durability barriers remain uncertain. Private terminal evidence never enters
`command.result` or `jobs.list`.

## Recovery

`job_loader.go` checks a bounded regular file before reading and uses no-follow,
nonblocking open plus descriptor identity checks. Journals below 2 MiB undergo
strict identity validation before exact-number decoding. Older oversized journals
up to 16 MiB use `job_recovery.go` to read only bounded identities and timestamps.
A complete array, unique IDs and final EOF are required; duplicate/case-aliased
metadata, trailing input and I/O uncertainty fail closed. The total read limit
includes whitespace and bounds even one large scalar. Discarded containers are
streamed without a full object tree.

Before retiring redundant native-owned receipts or compacting ambiguous history,
`job_evidence.go` preserves the exact original bytes in a private, content-addressed
sibling with file/directory barriers. Existing evidence is verified and synced
before reuse. The primary is replaced atomically only after preservation succeeds.
Real certificate/update/firewall/flush obligations remain protected. Restart does
not create repeated evidence copies for the same content.

Corrupt/unscannable/unwritable history, conflicting evidence, or a missing primary
with surviving evidence fences generic durable mutations and exposes a bounded
`journal.recovery` observation. Ordinary startup, repeatable reconciliation and
native hourly credit work continue. Genuine settlement dependencies remain
pending. Do not clear evidence or accounting to bypass a native recovery fence.

`job_bounds.go` uses Go 1.27's streaming JSON writer with v1 options and bounded
buffers; `jsontext` supplies the recovery decoder. No serializer dependency or
state schema is added. Extend command classification with each new protocol
action, retaining financial/native obligations in their authoritative store.

Regression coverage includes full/corrupt histories, more than 128 repeated DDNS
failures, native receipt retirement, independent executor lanes, exact argument
binding, byte/count bounds, intent/completion failures, cancelled lock waits,
partial side effects, blocked disk I/O, restart replay and original evidence.
Standard-library references: [streaming serialization](https://pkg.go.dev/encoding/json/v2#MarshalWrite)
and [JSON token decoding](https://pkg.go.dev/encoding/json/jsontext#Decoder).
