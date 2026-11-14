# Hourly admission controller

`Controller` owns memory-only account buckets, grants, demand hints and accepted
payload counters. All identities for the same owner and account generation share
one bucket on this node, in both directions. Protocol types are the only project
dependency. Persistence and orchestration are separate from payload admission.

`ApplyAuthorization` publishes immutable enrollment/principal/period bindings.
`OpenFlow` attaches one native interrupt hook; `Flow.Close` never calls that hook.
`TryAcquire` reserves actual buffer capacity, and `Permit.Begin` synchronously
validates current authorization, session, original demand deadline, UTC day and
paid boundary before consuming quota exactly once. A native writer error after
Begin never refunds admitted bytes. Completion only releases handoff resources.
Previously admitted native/kernel-buffered bytes can drain after admission stops;
this contract does not promise a physical wire cutoff.

The controller locks authorization before the individual owner. No controller
lock is held during native interrupt hooks, disk operations or drain waits.
Paid expiry and authorization revocation fence idle flows as well as active
ones. Missing rate grants pause reduced-rate admission, while previously
installed full-speed credit can still authorize its exact reserved bytes. A
credit-only permit has no rate lease and expires at the earlier paid/UTC-day
boundary. Credit-only flows survive rate expiry/shrink without borrowing
reduced-rate capacity. An affected rate-dependent handoff still interrupts its
shared native flow, including a simultaneous credit-backed handoff in the
opposite direction.
Session changes fence both kinds of authority. Control retirement
and shrink interrupt only flows with affected started native handoffs, and rate/session
drains wait for those hooks and handoffs. Idle connections can resume afterward.
Permits retain their original bucket incarnation, so late callbacks cannot mutate
a new session/day bucket. Token buckets start empty; held permits count against
burst capacity and grant refreshes never create fresh tokens.

`PendingDemand` retains each nonce's original monotonic deadline when resending
fresh demand counters. `DemandWake` is a one-slot hint, including low-credit edges;
credit refill is independent of the two-second central rate allocator. Hints and
reservations never authorize purchases by themselves. `CreditProgress` reports
cumulative confirmed admission, including payload whose later delivery failed.

Only durable store-issued, one-shot markers can install credits. `FreezeCredit`
and `PrepareSeal` retain old-session totals for durable proof. This financial
admission barrier freezes the credit and cancels unstarted reservations without
closing a flow or waiting for delivery: successful `Begin` already consumed its
bytes irrevocably. It is separate from native rate/session drains. After successful
store sealing, `ForgetCredit` removes only the controller's credit object; its
marker cannot activate again. Samples remain independent. `Samples` returns
cumulative directional snapshots with process-local counter generations and real
first/last admission timestamps. Call `PruneSamples` with the original snapshot
only after its immutable copy entered the existing traffic journal; active
current-day counters and changed/recreated generations are retained.

Owner, flow, permit, credit and sample retention are bounded. Capacity failures
reject hourly work without erasing financial evidence or changing legacy traffic.
The focused `controller_*_test.go` cases cover shared quota, writer failure,
concurrency, grants, idle expiry, drains, burst conservation, atomic datagrams,
UTC midnight, capacity and counter pruning. They run in hosted CI.
`offline_credit_test.go` additionally covers bounded offline use, exhausted credit,
rate expiry, purchased expiry, one-shot accounting and atomic datagram boundaries.

`CreditStore.SealAbsent` accepts a complete expected installation from the
authenticated master. It proves unused bytes only when the exact issue sequence
is absent from all retained records/tombstones above the durable retirement floor.
The proof and high-water fence persist before return, with no activation marker.
Known active credit still requires controller freezing; known final partitions
are replayed exactly. ACK tombstone compaction advances `retired_through`, below
which missing evidence remains uncertain. Each write includes a canonical
whole-journal SHA-256 checksum, so omission of a non-highest record fails closed
before absence proofs are enabled. Older files without the checksum or floor
start conservatively at their existing high-water mark and persist that upgrade
before becoming healthy. Reordering, compaction, restart,
scope conflicts, cancellation and persistence failures have focused hosted cases.

`CreditStore` persists one private 0600 journal in the 0700 state directory,
with checked file and parent-directory durability barriers. The serialized bound
is 2 MiB, with at most 1,024 obligations and 1,024 acknowledged replay tombstones.
Install sequence high-water marks survive tombstone compaction. Unacknowledged
obligations are never evicted to make room for new credit.

An install returns process-local, original-scope, one-shot authority. Sealing
persists the exact frozen admitted/unused partition before emitting it;
`SealUnclaimed` atomically excludes controller admission before returning wholly
unused credit. Restart converts unsealed reservations into durable unknown
proofs without usable markers. It never invents usage or unused balances.
Acknowledgments retire only the matching final digest. Corruption, capacity and
I/O failures preserve the original evidence and disable hourly access alone.

`RequiresCompatibleBinary` validates the retained journal for upgrade and
rollback checks without opening a live store or recovering obligations. Any
issued sequence requires hourly-aware binaries even after ACK compaction. An
absent or pristine journal does not impose that requirement. The compatibility
tests verify that inspection preserves live activation and the original bytes.
