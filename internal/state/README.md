# Durable state and volatile traffic

`store.go` atomically persists credentials, desired/accepted configuration,
revisions, bans and IP blocks. `desired.go` stages validated activation targets;
acceptance clears them. `connection_controls.go` excludes connection-derived
admission decisions from durable snapshots. `configuration.go` provides bounded
configuration copies and metadata without copying traffic or credentials.

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

`ddns.go` and `ddns_changes.go` retain the independent private 1 MiB DDNS journal.
It preserves at most 1024 unacknowledged changes and successful job snapshots
across restart/rollback, deduplicates generation changes and never contains
traffic or source-IP telemetry. `ddns_test.go` covers durable failure paths.
