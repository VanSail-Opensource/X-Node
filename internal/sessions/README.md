# Logical sessions

`hourly.go` captures immutable owner generation, enrollment, principal and period
bindings at member admission and attaches one controller flow after releasing the
registry lock. Authenticated transit retains normal accounting and skips this
additional gate. `hourly_authorization.go` publishes complete authorization views
with a monotonic process-local sequence, outside the registry lock because native
interrupt callbacks close leases. New hourly admission requires acknowledgment of
the current publication; a rejected snapshot closes existing hourly leases.
Controller replacement and late attachment cannot restore a closed lease.
`hourly_test.go` and `hourly_authorization_test.go` cover missing controllers,
transit, stale publications, failed publication, immutable binding and renewal.

`authorization.go` publishes committed users and IP blocks together using a
process-local monotonic store sequence. Delayed publications cannot restore old
authorization or restrictions. `identity.go` transfers leases only after the
shared protocol validator proves the replacement; `ip_subject.go` binds drops to
the captured credential/period. See `docs/ip-block-authorization.md` for ordering,
restart, expiry and accounting constraints.

Summary `TotalConnections` derives all logically open client flows from the same
locked registry, including idle flows and excluding transit. It adds no persistent
state. A per-user client reservation counter enforces connection limits under
the admission lock. Logical close removes its contribution
while unfinished native handlers retain their accounting/capacity reservations.

The registry atomically reserves shared per-user TCP/UDP connections and active
IPs. Authentication labels bind credentials and inbound configuration epochs.
`transit.go` precomputes member, transit and authorized replacement labels when
users or listener epochs change; admission performs a bounded map lookup while
the registry lock still protects the atomic reservation.
Hosted `BenchmarkIdentityLookup` compares the original repeated credential
derivation with the cached lookup for the same member and transit bindings.
`registry.go` owns admission; `lease.go` owns logical close/release and payload
accounting; `snapshot.go` provides current limit projections. Shared state types
live in `types.go`. `accounting.go`
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
Each lease retains its original principal/period accounting key when verified
identity replacement moves its live principal. Principal and period barriers
include handlers still writing that original key, close them, and wait for their
native completion. Newly admitted replacement leases remain independent.
`accounting_identity_barrier_test.go` covers delayed barriers and late payload
accounting after identity replacement.

`activity.go` samples per-lease payload counters without an idle grace period.
Active connection/IP telemetry and lists share that snapshot; admission and
limit status instead use atomically reserved logically open client flows,
including idle flows. Close releases a client slot exactly once; native-handler
capacity and accounting remain reserved until completion. `transit.go`
authenticates master-only peer credentials: transit skips client connection/IP
counts and volatile global blocks while retaining expiry, restrictions, speed
policies and exact owner-period accounting. Hosted regressions in
`connection_limits_test.go`, `registry_test.go` and `activity_test.go` cover
concurrent TCP/UDP admission, idle samples, transit exclusion, policy/replacement
continuity and duplicate close/finish. Real Xray TCP/mux cases live in
`internal/kernel/xray/connection_limits_test.go`.

`source_whitelist.go` binds exact canonical IPs to the authenticated user's
credentials, including transit. Registry replacement closes leases whose address
was removed. `source_whitelist_test.go` and `whitelist_transit_test.go` cover
source isolation, immediate revocation and preserved non-Reality country checks.

Active IPs are always present in sampled activity projections. Reporting never changes admission policy, and idle total-open counts remain independent of sampled byte activity.

`AcquireTrackedWithHourlyFence` adds a native connection interruption used only
by the controller's hourly flow fence, outside the registry lock. Ordinary lease
completion retains shared mux transports; legacy/transit never attach this hook.
The original tracked accounting barrier and exact-once close semantics remain.
`ExpireUsers` delegates hourly expiry to the controller's current authorization
check, so maintenance cannot bypass the native transport fence or revoke a newer
renewal when a previously queued paid-boundary timer finally runs.

`activity_history.go` retains a volatile two-hour history of at most 16,384
user/IP observations plus at most 16,384 pending brief-flow keys. Closing or
finishing an unsampled payload flow records pending evidence; only the next
configured sample publishes it. Internal transit is excluded. Idle samples and
repeated report publication never refresh an observation's time or counter.
Capacity evicts old records with a saturating dropped-observation counter, and
clock rollback discards future history. No packet adds history or takes a new
lock. `activity_history_test.go` covers brief flows, idle repetition, private
snapshots, expiry, capacity and rollback. The bank never enters persisted state.
