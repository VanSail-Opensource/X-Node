# Logical sessions

Summary `TotalConnections` derives all logically open client flows from the same
locked registry, including idle flows and excluding transit. It adds no persistent
state and never feeds connection limits. Logical close removes its contribution
while unfinished native handlers retain their accounting/capacity reservations.

The registry atomically reserves shared per-user TCP/UDP connections and active
IPs. Authentication labels bind credentials and inbound configuration epochs.
`registry.go` owns admission/release and current limit projections; `accounting.go`
keeps a separate native-handler lifetime and period counter after logical release.

Each period counter carries its first lease's process-local generation. The
sampler keys its baseline by that generation, so removing and restoring the same
authorization cannot compare a fresh counter with a retired counter. Pruning
requires the persisted generation and exact byte snapshot with no remaining
handlers; bytes arriving during a durable write remain available to the next
capture. Generations never enter the database or wire protocol.

`AcquireTracked`/`Finish` bracket actual Xray dispatch. Period changes retain
previous counters until all native handlers and sampling finish. `Quiesce` adds a
temporary admission fence and returns its release after handlers drain. Cached
`valid_until` deadlines deny new sessions immediately and close established
sessions on the next one-second control tick.

Rates use actual elapsed seconds and payload bytes. Configured normal/burst Mbps
remain a separate policy projection. Connection and source-IP snapshots are
transient. Hosted cases cover quota races, expiry, counters and quiescence.

`period_barrier.go` finishes revoked period handlers without closing renewed streams.
`period_barrier_test.go` covers late old bytes, active-period rejection and renewal continuity in hosted CI.

`activity.go` samples per-lease payload counters without an idle grace period. Summaries, active IPs, lists and local connection limits share that snapshot; close invalidations remove closed flows immediately. Hard capacity remains reserved until both logical close and native completion. `transit.go` authenticates master-only peer credentials: transit skips connection/IP admission counts and volatile global blocks while retaining expiry, restrictions, speed policies and exact owner-period accounting. Hosted regressions live in `activity_test.go`.

`source_whitelist.go` binds exact canonical IPs to the authenticated user's
credentials, including transit. Registry replacement closes leases whose address
was removed. `source_whitelist_test.go` and `whitelist_transit_test.go` cover
source isolation, immediate revocation and preserved non-Reality country checks.
