# Durable state and volatile traffic

`store.go` atomically persists credentials, desired/accepted configuration,
revisions, bans and IP blocks. `desired.go` stages validated activation targets;
acceptance clears them. `connection_controls.go` excludes connection-derived
admission decisions from durable snapshots. `configuration.go` provides bounded
configuration copies and metadata without copying traffic or credentials.
Recovery checks the state file's type and 64 MiB size limit before opening it,
uses a nonblocking no-follow open, verifies the opened file identity, and caps
the read to reject concurrent growth. Invalid files, FIFOs and symlinks
are rejected without changing their evidence. Atomic writes acknowledge success only after the containing
directory sync and close succeed; a rename with an uncertain durability barrier
does not publish a fresh in-memory authorization view.

`dns_migration.go` normalizes both accepted and staged legacy resolver settings
in memory during `Open`, before bootstrap or configuration readers see them.
It delegates to the public protocol migration and does not rewrite the state
file just for DNS, alter identities/revisions or clear accounting. A later normal
configuration persistence includes the normalized node snapshot.

`authorization.go` publishes detached `AuthorizationView` snapshots containing
users, scoped IP blocks, the durable authorization revision and a process-local
monotonic publication sequence. `AuthorizeView` validates identity replacements
against the original users and atomically transfers IP restrictions before
installing the new authorization. The sequence starts at one after opening the
store and is never serialized or shared with traffic counters. Failed writes
return no publication; consumers reject delayed views by sequence.

`ip_blocks.go` checks each positive command subject against its captured
credential/accounting identity and current eligible inbounds under the store
lock. Unknown, removed, inactive or changed subjects cannot mutate a restriction.
Global scope remains explicit. Error-only `Authorize`/`BlockIP` wrappers retain
existing call shapes, including key-only scoped unblocks. Conditional batch
expiry rechecks persisted deadlines, so an older sweep cannot erase an extension;
an unchanged sweep returns a zero view without cloning or writing state.

These operations use the existing copy-on-write persistence boundary. Registry
publication happens after disk work, without a shared agent lock spanning I/O.
`authorization_test.go`, `authorization_failure_test.go` and `ip_blocks_test.go`
cover restart, merge/global preservation, detached views, stale subjects,
conditional expiry, failed writes and publication order. Pure replacement and
block mapping helpers belong to `protocol`; no account-relinking UI or stored
publication sequence is introduced.

`traffic_memory.go` owns a separate boot-scoped buffer that never enters `Data`.
`accounting.go` validates a complete capture before mutation, coalesces matching
period/minute samples and records bounded overflow loss observations. It retains
at most 8192 accumulation entries, 64 reports and a conservative 32 MiB queued
allocation allowance. `traffic.go` exposes immutable head copies and matching
ACK retirement. New capture/flush/report/ACK paths never write disk. Queue
pressure returns `ErrTrafficBusy` for a retryable barrier; durable state remains
available. Agent admission does not stop because traffic was lost.

`traffic_legacy.go` seals only already persisted pre-upgrade accumulation with
its original agent/sequence. Existing pending/backlog identities drain before
new boot streams. Historical ACK retirement remains durable; failures preserve
the old head. A process restart loses new uncommitted usage and creates a new
stream ID. The master records gaps and settles surviving committed usage.

`traffic_memory_test.go` covers file stability, configuration-write isolation,
restart loss, capacity, loss markers, blocked paths and allocation measurements.
`traffic_upgrade_test.go` protects historical IDs and durable retirement.
`accounting_test.go`, `store_test.go` and `reporting_test.go` cover immutable
replay, periods, overflow atomicity, ordinary state durability and metadata cost.
All automated verification runs in hosted CI.

`AddAccountingWithHourly` accepts native accounting and hourly admission history
under the same lock, after native validation. `accounting_hourly.go` retains raw
owner/enrollment/period/day/generation deltas in a separate 8192-entry accumulation
bank; it cannot consume native billing space. Invalid, overflowing or omitted
hourly records increment `dropped_hourly_samples` rather than halt legacy access.
Both banks enter one immutable boot-stream report, share the conservative 32 MiB
queue bound, and retire through its existing matching ACK. Returned sample slices
are detached. Admission history remains volatile and never enters `Data`; exact
financial byte reservations and final proofs belong to `hourly.CreditStore`.
`accounting_hourly_test.go` and `accounting_hourly_bounds_test.go` cover atomic
retry, independent loss, immutable replay, queue accounting and disk isolation.

`ddns.go` and `ddns_changes.go` retain the independent private 1 MiB DDNS journal.
It preserves at most 1024 unacknowledged changes and successful job snapshots
across restart/rollback, deduplicates generation changes and never contains
traffic or source-IP telemetry. `ddns_test.go` covers durable failure paths.
