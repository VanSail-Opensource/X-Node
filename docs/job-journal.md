# Bounded command receipts

`Jobs.Start` reserves one existing utility worker and registers its ID/command
without filesystem I/O. The worker persists an uncertain intent before any
durable mutation executes, then replaces it with the result. File and directory
barriers must succeed before execution. Completion-write failure preserves the
intent across restart; cancellation and errors after execution remain uncertain
because external/native side effects may already exist.

`job_journal.go` serializes worker-only writes using `persistMu`. Bounded state
copies use the short registry mutex, which never owns disk I/O. Traffic ACKs,
new admissions, `jobs.list`, `update.status` and volatile controls remain
independent of a blocked journal write. Existing execution slots and queues are
reused; no network call is introduced by receipt persistence.

Durable receipts and volatile observations each retain at most 128 entries and
strictly less than 2 MiB of serialized JSON. Individual retained results are at
most 64 KiB. Protected uncertain identities cannot be evicted by observations or
new mutations; exhausting that capacity refuses execution. IDs remain globally
unique beyond the bounded completed-receipt window. Result data retains exact
JSON integers. Native read results can still use the existing 16 MiB transport
frame limit, with envelope headroom; large reads are returned but not retained.
Oversized mutation outcomes become small uncertain receipts rather than false
completed results.

`job_privacy.go` derives observation classification from the protocol action map,
including firewall/certificate status. Validation, update checks, speed tests and
existing volatile IP/session/lease controls remain off disk. Their independent
state and epoch policies remain authoritative. Observed client source-IP and
machine-metric payloads never enter the command journal.

`job_loader.go` stats before reading. Journals below 2 MiB undergo strict identity
validation before exact-number decoding. Older oversized journals up to 16 MiB
use `job_recovery.go` to read only bounded identities and timestamps. All their
durable mutations become uncertain. Legacy failures/cancellations also remain
uncertain because their records do not prove absence of side effects. A complete array, unique IDs and final EOF
are required; duplicate/case-aliased metadata, trailing input and I/O uncertainty
fail closed. The 16 MiB total limit includes whitespace and bounds even a single
large JSON scalar; discarded containers are streamed without a full object tree.

Newly persisted failed receipts include private `terminal_failure` evidence only
when execution was never entered or a typed refusal proves a terminal outcome.
These receipts remain failed and evictable after restart, so rejected stale hourly
sessions cannot fill the journal with artificial obligations. The field never
enters `command.result` or `jobs.list`. Legacy failures without this evidence,
oversized recovery, and unsuccessful completion durability barriers remain
uncertain. Duplicate, case-aliased or contradictory terminal evidence fails closed.

Before compaction, `job_evidence.go` preserves the original bytes in a private,
content-addressed sibling with file/directory barriers. Existing evidence is
verified and synced before reuse. The primary is replaced atomically only after
that succeeds. Corrupt/unscannable/unwritable history, conflicting evidence, or
a missing primary with surviving evidence fences durable utilities and exposes
a bounded `journal.recovery` observation. Ordinary agent/runtime startup and
background accounting continue; genuine settlement dependencies remain pending.
Do not clear evidence or accounting to bypass this fence. Reviewed native proof
is required before operator repair of unresolved receipt identities.

`job_bounds.go` uses Go 1.27's streaming JSON writer with v1 options and bounded
buffers; `jsontext` supplies the recovery decoder. No serializer dependency or
state schema is added. Extend command classification with each new protocol
action, retaining only financial/native obligations that require durability.

Hosted regressions cover byte/count limits, large policy reads, exact integers,
intent/completion failures, cancellation, partial side effects, blocked disk I/O,
restart replay, corrupt/oversized/missing primary files and preserved evidence.
No local automated suite runs. Standard-library references:
[streaming serialization](https://pkg.go.dev/encoding/json/v2#MarshalWrite) and
[JSON token decoding](https://pkg.go.dev/encoding/json/jsontext#Decoder).
