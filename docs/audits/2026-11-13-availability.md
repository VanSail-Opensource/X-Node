# X-Node availability and efficiency follow-up — 2026-11-13

## Scope

This follow-up starts from merged main
`41f04f945454282e3bfd6dde7e638bd29cfb9b0f`. It builds on the complete tracked-file
inventory and review in [the preceding audit](2026-11-12-report.md), then traces
the requested availability, failure isolation, storage, validation and retirement
requirements across the current agent and its Carpool integration. The preceding
manifest describes its own exact snapshot; it is not represented as a manifest
of this later tree. Changed implementation, callers, recovery paths and regression
fixtures were reviewed together. This report covers the X-Node side; the companion
Carpool audit covers SQL, commerce, admin/member layout and browser interaction.

No production host, provider account, customer database, live firewall or signing
key was used. The local agent integration limitation is recorded below.

## Coverage of the requested areas

| Area | Review and result |
| --- | --- |
| Queue failure and pressure | Reviewed command admission, all worker classes, journal capacity, cancellation and transport lanes. Added independent credit/status capacity, early unknown-command rejection, repeatable receipt isolation, immutable traffic replay coalescing and stale-reset draining. |
| Feature availability | Reviewed synchronization, native runtime, DDNS, geodata, firewall sync, inspection and financial credit ownership. Long downloads and generic receipt recovery no longer fence unrelated credit/status/reconciliation. Invalid old utility settings cannot veto user-only authorization changes. |
| Failed X-Node tasks | Reproduced the relevant capacity conditions with full/corrupt histories and more than 128 DDNS failures. Repeatable failures remain bounded live results; actual uncertain irreversible operations keep their own recovery barrier. |
| Database read/write pressure | X-Node uses private files rather than SQL. Removed duplicate generic writes for native-owned/idempotent work and the repeated directory fsync. Carpool separately audits SQL reads, transactions, batches and retention. |
| Unnecessary storage | Repeatable DDNS/reload/versioned-sync and hourly commands no longer create redundant generic disk receipts. Exact credit, traffic barrier, update, certificate and transactional firewall evidence remains durable. Original retired receipts are preserved once by content identity. |
| Master down or restarting | Reviewed cached ordinary authorization/native runtime and hourly accepted authority. Ordinary serving configuration survives control loss; already installed reserved byte credits remain usable within their original authority bounds. Reconnection creates the new-session fence. New real-stream and agent-level regressions cover these transitions in hosted CI. |
| Protocol efficiency | Identical queued traffic reports retain one copy per immutable identity; conflicting content is rejected. User deltas preserve user order, avoiding native rebuilds caused solely by randomized map iteration. Current public schemas remove inert DNS/telemetry fields. |
| Input validation and domain coverage | Added DDNS source, family, lookup, interface, TTL and owned-name checks; IDNA/apex/wildcard/service labels are covered. Reject ambiguous user deltas, unknown commands and malformed command objects before ambiguous execution. |
| Frontend layout | X-Node's generated documentation retains its existing responsive layout and is regenerated successfully. The companion Carpool work reviews the actual administration/member layouts with browser evidence; no new X-Node layout change is claimed. |
| Counter-intuitive UX | The API documentation now explains mandatory active-IP reporting, removed settings, distinct executor capacity, definite refusal versus uncertainty and native receipt ownership. Companion admin changes expose DDNS field errors and manual zone entry when discovery is unavailable. |
| Performance and efficiency | Audited locking, synchronization work, queue bounds and disk barriers. Network asset preparation runs outside the activation lock, cancelled waiters release workers, duplicate traffic frames and redundant fsyncs are eliminated, and user-only updates avoid unrelated validation. |
| Business loopholes | Preserved exact financial identities and uncertain mutation evidence. Offline continuity consumes only already reserved bytes and never extends shared reduced-rate grants or paid/day/session limits. Malformed requests cannot create protected uncertainty before any possible side effect. |
| Retired code/backward compatibility | Removed live DNS mode/upstreams compatibility, inert active-IP input, unused native preparation wrapper and duplicate write wrapper. Only bounded private saved-state recovery and immutable financial/recovery evidence remain where removing them would break offline upgrades or settlement. |

## Findings and implementation

### AV-01 — Failed repeatable work could exhaust the global mutation journal

The generic journal retains at most 128 protected uncertain mutation identities.
Scheduled DDNS failures, runtime reloads, versioned synchronization and hourly
commands previously used that same intent/result journal even though they were
repeatable or had a stronger native replay store. A sufficiently long provider
failure could therefore prevent unrelated later work.

`job_privacy.go` now assigns persistence to the store that owns the operation.
DDNS SET/discovery, runtime/geodata reconciliation, versioned firewall ban/GeoIP
updates and confirmation use bounded live replay. Hourly install/seal/ACK uses
the durable credit store's reservation, issue sequence and exact proof identity.
The generic journal retains certificate, update, transactional firewall apply
and exact traffic flush obligations. Full/corrupt generic history does not fence
the independent native operations. The old exact file is archived before redundant
receipts are retired; genuinely unresolved mutations remain protected.

Live request IDs still suppress duplicates and now bind normalized argument
digests without persisting their contents. Canonicalization retains exact JSON
numbers, rejects duplicate keys, bounds nesting and preserves native case-alias
interpretation. Deliberately retry a terminal failed operation with a new command
ID; retain native financial/version identities when replaying after restart.

Evidence: `job_availability_test.go`, `command_args_test.go`, existing job
execution/restart/evidence/terminal-failure tests. Their durable-operation fixtures
now use commands that actually retain the generic journal; the intent-before-effect,
uncertain-completion and exact-number assertions are retained.

### AV-02 — Unsupported and malformed commands could create false uncertainty

Unsupported names formerly reached worker admission before dispatch rejection.
Typed decode or native-policy validation failures inside a durable command also
looked like uncertain partial mutations despite occurring before any side effect.

The dispatcher rejects unsupported commands and malformed argument objects before
admission. Proven `firewall.apply`, `update.install` and `traffic.flush` input
refusals are typed terminal failures. A full volatile traffic queue is a known
retryable refusal; a completed flush still keeps its original exact barrier.
Actual provider, storage, native activation or partial mutation failures retain
the appropriate uncertainty. More than 128 malformed persistent requests cannot
consume the protected capacity needed by later valid operations.

### AV-03 — Independent features shared long-running worker capacity

Two bulk/network utilities could occupy the normal workers while urgent control
used its own slot. Credit installation/proof acknowledgment and bounded status
reads still competed with bulk work. Credit operations and inspection now each
have one separate bounded executor. Ordinary utilities retain two workers and
urgent controls retain one; overflow returns a busy response instead of allocating
an unbounded queue. Immediate `jobs.list`/`update.status` remain available.

Terminal results previously became visible before the worker released its slot.
A fast follow-up could therefore receive a busy response after the prior command
had completed. Workers now finalize durable or volatile receipt bookkeeping and
encode the bounded result, release their slot once, then offer the result to the
nonblocking transport queue. An idempotent deferred release covers early exits.
The transport still bounds completion frames and never waits on a socket from
this callback; no additional publisher queue or durable record is created.
`job_completion_test.go` reproduces immediate same-lane successor admission from
the result callback across successful, uncertain, refused, cancelled and failed
journal-write outcomes without changing their receipt semantics.

Native/provider locks now accept operation context. A cancelled DDNS job or
superseded activation no longer waits for another operation merely to release
its worker. DDNS's 30-second timeout includes lock waiting.

Scheduled geodata downloads use a private stage outside the native activation
lock. Only verified adoption and candidate publication own the lock. Adoption
validates recovery references and preserves serving/rollback generations before
retiring unrelated assets. Failed/cancelled downloads retain the last candidate.

Evidence: executor pressure and cancelled-wait tests, `utility_availability_test.go`,
and `internal/geodata/adopt_test.go`. Required same-resource commit/settlement
serialization remains; independent worker capacity does not permit concurrent
unsafe writes to one authoritative store.

### AV-04 — Replayed traffic could fill the outbound lane while offline

The reporter repeatedly offers its immutable unacknowledged head. Previously,
each offer occupied another of the 16 retained traffic-frame slots, exhausting
the lane and requesting reconnects before useful backlog could drain. The lane
now coalesces exact identity/content duplicates without recording drops. Reusing
an identity with changed bytes is rejected and requests resynchronization.

Reset notifications belonging to a failed/offline connection are drained before
opening its replacement. The durable owner still reoffers unacknowledged traffic;
coalescing neither acknowledges nor replaces financial content.

Evidence: `traffic_pressure_test.go` covers 128 offers of every distinct queued
report, exact ordering/byte accounting, conflicting identities and a live socket
reconnection that drains its retained results without stale-reset churn.

### AV-05 — Control loss unnecessarily retired already accepted hourly credit

A transient disconnect previously cleared local session authority and caused
installed reserved credit to retire even when no successful replacement session
existed. Transport negotiation and retained local authority are now separate.
Failed reconnects preserve accepted authority; a successful new or incompatible
session fences the old scope, and overall client shutdown clears it.

Credit-only permits consume already installed, durably reserved bytes independently
of the short dynamic rate lease. Paid-through, day, store health, session and
reservation limits still apply. No new credit is created offline. Reduced-rate
leases remain bounded by their original deadlines and are never extended merely
because the master is unavailable. Exhausting reserved bytes cannot authorize
unbudgeted service from the global shared-rate allocator.

Evidence: hourly offline-credit/controller/transport tests,
`hourly_offline_test.go`, and `master_outage_stream_test.go`. The latter maintains
real ordinary paid VLESS streams, admits another stream while the master refuses
reconnects, then verifies both survive a replacement connection without a native
rebuild. Agent-loop fixtures require the hosted Unix-socket-capable runner.

### AV-06 — DDNS validation was incomplete and deltas could hide ambiguity

DDNS now requires an enabled address source, a correct fixed address family, and
an interface or HTTPS source for automatic discovery. Interface and URL syntax
are checked before execution. TTL is bounded to 0–2147483647 seconds before
duration conversion, matching the effective TTL range in
[RFC 2181 section 8](https://www.rfc-editor.org/rfc/rfc2181.html#section-8).

Zone/name normalization covers the apex (`@`), absolute or in-zone names,
case/trailing-dot normalization, IDNA and Unicode dot separators, leading
wildcards and underscore DNS owner labels. Whitespace/control/URL punctuation,
overlong labels/names, invalid source families and out-of-zone suffixes reject
before lookup/provider I/O. `DDNSJob.Validate()` is shared through the public
protocol alias so the companion master does not reimplement these rules.

User deltas now reject duplicate, nonpositive and contradictory remove/upsert
identities before map application. Existing user order is preserved. User-only
messages validate the updated authorization/native auxiliary bindings without
revalidating unchanged failed utilities from old accepted snapshots. New full
configuration remains strict. Cached native boot already validates native consumers
without allowing an old bad DDNS task to veto ordinary serving configuration.
The companion master retains invalid historical job settings for repair and
isolates them from publication with explicit per-job warnings.

Evidence: protocol DDNS/domain/delta tables, DNS no-I/O rejection tests and
`user_delta_test.go`'s invalid-old-DDNS authorization regression.

### AV-07 — Retired settings remained in active contracts

The live `DNSPolicy` now contains only `redirect`; native `xray.dns.servers` owns
resolver selection. `dns.mode` and ignored `dns.upstreams` are rejected on new
input. The inert `telemetry.include_active_ips` switch is also removed; sampled
active-IP reporting was already mandatory. Current schemas, examples and reference
pages now describe the effective behavior.

The bounded private state reader alone recognizes historical DNS metadata from
accepted and staged snapshots. It preserves any effective SmartDNS loopback fallback
and explicit native servers, without changing identity, revisions, accounting or
staged/accepted ownership. Boot requires no extra write. The next ordinary write
produces only current fields. The companion Carpool saved-settings adapters apply
the corresponding encrypted-document recovery; public writes remain strict.

Unused `prepareNative` and `writeJobFile` wrappers are removed. Durable publication
uses `state.AtomicWrite` directly, avoiding an extra directory fsync on every intent
and result. The job loader now also uses nonblocking/no-follow descriptor checks.
Live chronological schedules, supported port representations and financial
evidence are not mislabeled dead merely because a historical format exists.

## Verification and rollout

Locally completed checks include the full race suites for protocol, DNS, geodata,
state, hourly, transport and native Xray; 51 focused agent journal/utility/native
validation tests; and focused reruns for the final malformed-command, cached-DDNS
authorization, cancellation and canonical replay changes. `go vet ./...`,
`go mod verify`, schema generation/validation and documentation generation passed.
Documentation generation produced 85 pages and 39 schema-validated examples.
Linux amd64 and arm64 builds also passed (`CGO_ENABLED=0 go build ./...`).

The complete local `internal/agent` run was attempted. Agent-loop fixtures failed
at `listen unix .../status.sock: socket: operation not permitted`; the supported
escalation request was rejected because this workspace disables sandbox approvals.
No test was weakened or rerouted to bypass that restriction. Full race/native
agent integration, signed architecture artifacts and disposable Debian firewall
gates must pass on the published head before merge/release. Earlier green commits
do not validate a later release target.

This changes the public protocol package shape. Upgrade the companion master
using the matching X-Node commit before rolling out agents that reject retired
fields. Stored-only adapters preserve accepted state; they do not re-enable
retired public settings. Genuine uncertain financial/native obligations still
require their own evidence and cannot be cleared to increase availability.
