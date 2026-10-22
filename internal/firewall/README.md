# Host firewall

This module owns the complete Linux host firewall. The agent's serialized jobs
call `Manager.Apply`, `Confirm`, `EnableConfirmedDNS`, and `Migrate`. The local
`xnodectl` commands call `RollbackID`, `RestoreFile`, and `RestoreOriginal`.

## Native engine

`Backend` is the injectable kernel boundary. Its Linux implementation compiles
`protocol.FirewallPolicy` into typed google/nftables chains, rules, named
counters, interval address sets, port sets, and dynamic timeout sets. Native
Netlink is local kernel I/O; it does not make external API requests.

Policy compilation is separate from ordered rule reconciliation and set deltas.
Rule userdata contains stable semantic IDs; expression comparison detects changes
even when an ID remains the same. Kernel-assigned set IDs are excluded from that
comparison. Overlapping CIDRs are normalized with netipx without enumerating IPs.
New rules are inserted relative to retained handles, preserving packet order.

All changes, including removal of foreign tables, are buffered and committed by
one `Conn.Flush`. Kernel rejection leaves the previous ruleset intact. Ordinary
updates reuse dynamic sets, preserving ban expirations and per-source meters, and
reuse named counters. Incompatible live set definitions fail before commit rather
than discarding state. There is no conntrack connection quota; the session module
enforces proxy connection limits. This design follows ngrok/firewall_toolkit's
rule/set separation without importing its managers or intermediate flushes.

## Transactions and recovery

Every operation takes the manager mutex and a cross-process filesystem lock.
Lock acquisition and Netlink I/O observe cancellation and bounded deadlines.
Before changing sysctls or live policy, apply saves a complete `nft list ruleset`
snapshot, previous boot files and policy, forwarding state, and a private pending
record. Tables owned by iptables-nft cannot be expressed in that snapshot,
because nft rejects every `xt match`/`xt target` statement; `compat.go` removes
them from the native file and captures each one with `iptables-nft-save -t`.
Recovery replays the native snapshot first and then restores those tables with
the matching iptables front end, so UFW rules survive rollback and uninstall.
Unsupported ownership families fail the transaction before any mutation instead
of producing a snapshot that cannot be replayed. An independent 45-second
systemd timer runs `xnodectl firewall-rollback`;
its service retries failed recovery. The master confirms the transaction ID after
checking connectivity. Reusing the current ID with different inputs fails.

Known atomic rejections restore metadata/sysctls; service-state recovery also
replays the snapshot after restoring owners, because service actions can change rules.
Cancellation or an ambiguous missing acknowledgment triggers full snapshot
recovery using a separate cancellation-independent context. `RecoveryTimeout`
defaults to the 30-second production budget; only disposable software-emulated
hosts extend it for slow systemd/UFW startup. Recovery leaves the
transaction pending if restoration fails, so the watchdog can retry. Late
confirmation and stale watchdog IDs cannot replay obsolete snapshots.

## Persistence, migration, and lifecycle

Confirmed `policy.json` is authoritative. Disk records retain legacy flat fields
and add an internal engine version; public pending/status results expose only
`Pending`. Legacy confirmed records can carry `status: pending`, because the old
writer saved them before updating status. The separate current transaction is
checked first when recovering a crash.

Confirmation replaces the managed `/etc/nftables.conf` with a comment, installs
`x-node-firewall.service` after nftables and before the agent, and adds an agent
dependency drop-in. Previous files are restored if migration fails. Binary
upgrades must be confirmed before persistent migration. Cached startup migrates
the previously confirmed policy without changing its redirect intent. The
`native_firewall_v1` capability prevents subsequent unsafe binary downgrades.

`ownership.go` and `service_state.go` snapshot nftables/UFW service ownership
before mutation. After atomic policy installation, takeover masks UFW and
explicitly disables its rules, including CLI-enabled enforcement with an
inactive oneshot unit. Confirmation enables/starts nftables with the managed
comment-only boot file; `x-node-firewall.service` runs after nftables and UFW.
An independent rollback restores service/config state before replaying the full
kernel snapshot, so a service start/stop cannot overwrite recovered rules.
Original ownership remains available for uninstall; repeated unmanaged restores
are inert. `host_firewall_ownership_v1` prevents downgrades that lose this recovery
contract, and `xtables_compat_snapshot_v1` covers hosts whose original snapshot
needed iptables-owned tables. Portable hosted coverage lives in `ownership_test.go`
with its runner in `ownership_fixtures_test.go`.

Boot restoration and agent startup recover unconfirmed transactions and reconcile
the confirmed policy through Go, with DNS redirection disabled. Legacy DNS output chains are reconciled empty, even for cached redirect intent.
DNS interception belongs exclusively to authenticated Xray traffic. An
agent startup restore also supports upgrades from the old service ordering.

The `nft` executable remains necessary for complete arbitrary-ruleset snapshots,
legacy rollback, diagnostics, and uninstall. Uninstall restores `original.nft`
and original forwarding sysctls, removes the dependency drop-in and confirmed
policy, and retains other private state unless purge was requested.

## Verification and extension

Portable manager fixtures inject `Backend` and `host.Runner`; Linux fixtures cover
compilation, expression changes, order, and set boundaries. The disposable Debian
VM fixture verifies real packets, live-state retention, watchdog recovery after
the applying subprocess exits, reboot ordering, and uninstall. Never execute the
privileged fixture on a developer host. Keep new policy settings in the existing
protocol/schema, and extend the compiler rather than adding another executor.

The deprecated redirect argument remains readable for upgrade compatibility; it never installs DNS NAT rules.

## Master-authorized bans and reports

`ban_state.go`, `guard_runtime.go` and `detection.go` separate observations from
restrictions. Default detection is three hits in 24 hours; no detector can add
a ban. `nflog_linux.go` reads Linux NFLOG group 100 using bounded header-only
packet copies, without parsing kernel text logs. Xray supplies public inbound
observations. Disabled rules do not report; blacklist hits extend existing
authorized deadlines without creating fresh detection reports.

`ban_sync.go`, `ban_snapshot.go`, `ban_update.go` and `ban_validation.go` implement
ordered snapshots, source references and immediate deltas. Master versions and
absolute deadlines prevent stale retries from reviving older state. Sources stay
compact CIDRs. Repeated generations preserve local extensions; a new generation
can shorten a restriction. Exact exemptions bypass blacklist lookup only and
never bypass ordinary port, invalid-packet or forwarding checks.

`ban_journal.go`, `ban_persistence.go` and `ban_writes.go` use private gzip
checkpoints plus a bounded append journal. Changes fsync before command success.
A stable event namespace and monotonic sequence allow replay-safe master cursors.
Acknowledged events and expired records are pruned; torn final journal members
are removed without losing committed records. Compaction epochs prevent stale
journal replay, and expiry acknowledgments cannot remove a newer source.

`ban_backend.go`, `ban_sets_linux.go`, `ban_rules_linux.go`, `source_sets_linux.go`
and `ban_other.go` bind durable state to native sets. Large source generations
are populated while unreferenced through bounded transactions, then selected
atomically. Immediate ban/exemption updates use independent revisions and are
not queued behind inventory population. Source lookup chains survive ordinary
policy reconciliation. All restrictions match inbound/original direction;
outbound connections and their reply packets remain usable. Boot restoration
replays remaining lifetimes before the agent starts.

`ban_status.go` exposes memory-only status. `guard_test.go`,
`guard_persistence_test.go` and `guard_snapshot_test.go` provide hosted regressions
for threshold windows, command authority, shortening, replay, torn tails,
compaction, source references, stale generations and exact IPv6 exemptions.

`guard_runtime.go` keeps observation processing active while native inventories stage. Per-namespace monotonic event IDs and master versions reject replay and stale state; event reports use the protocol's shared 256-event batch limit and remain queued until acknowledged. Dynamic restrictions and source generations use separate kernel revisions. Existing agent/renderer lifecycle files retain their native-core orchestration; new firewall responsibilities are isolated here.

`geoip_linux.go` compiles master-resolved IPv4/IPv6 prefix intervals into silent source drops scoped to non-REALITY listeners. Drops run before stateful accepts and detector hooks, never use NFLOG, and participate in the same atomic reconciliation, confirmation and rollback as the rest of the policy. Empty sets retire old country restrictions.

## Bounded source storage and delivery

`source_records.go`, `source_merge.go` and `source_walk.go` keep source ranges in
private fixed-width files. Sorting retains roughly one MiB of records plus
bounded merge readers; overlaps and adjacent ranges merge without enumerating
addresses. `source_sync.go`/`source_stage.go` publish metadata only after all
files are durable. `source_load.go` streams old gzip snapshots into this format.
The old snapshot stays readable by the rollback binary until upgrade confirmation.

`bulk_lock.go`, `source_cleanup.go` and `source_retention.go` serialize writers and
remove scratch/unused generations. Bulk storage, including staging/runs, has a
2 GiB ceiling and a 16 MiB filesystem reserve. `memory_admission_linux.go`
requires kernel-set staging headroom; admission errors preserve active rules.
`range_sets_linux.go` populates unreferenced sets in 512-element transactions.

`geoip_sync.go`/`geoip_sets_linux.go` implement `firewall.geoip.sync`: the master
uploads at most 256 resolved prefixes per chunk, then config carries a verified
generation reference. This is gated by `source_geoip_stream_v1`. Feed transfer
requires `disk_firewall_sources_v1`; desired bulk content never enters live
snapshots or telemetry copies.

Dynamic snapshots use separate staging and reserved utility admission. A retry
of an already committed desired version cannot shorten locally extended bans.
Dynamic replay also bypasses dirty source preparation; interrupted source work
must never occupy the reserved control slot during a dynamic retry.
`exemption_ranges_linux.go` compiles overlapping CIDR grants into timed disjoint
intervals without extending a shorter outer grant. Exact member IP grants retain
their scope. CIDRs require `firewall_cidr_exemptions_v1` and a compatible rollback
binary. See the [official nftables set contract](https://netfilter.org/projects/nftables/manpage.html).

Hosted portable/race regressions cover million-prefix working memory, recovery,
references, expiry and retries. The disposable host fixture measures real RSS,
checks urgent updates during bulk synchronization, and exercises country/CIDR
sets and independent exemption expiry. These checks do not run on developer hosts.

`stage_retention.go` retires day-old transfer cursors before their data, removing
at most 64 bulk scratch files per pass under the existing source/host locks.
Recent cursors protect all chunks; committed and rollback ranges are never stage
cleanup candidates. Upgrade-pending or uncertain retention states defer cleanup.

Free-space admission inspects the bulk directory's actual filesystem, including
separate mounts. The Debian/nftables-on hosted VM explicitly enables million-prefix
RSS/urgent-ban checks and real low-space mount/2 GiB quota recovery fixtures;
the other ownership/distribution cases retain their existing recovery coverage.

## Capacity and hot-path retries (v2.0.10)

Policy reconciliation creates `banned_v4_v2`/`banned_v6_64_v2` with 1,048,576
entries each, switches rules, then deletes unreferenced legacy sets in the same
atomic transaction. Startup restores durable bans. Master admission caps one
million restrictions; source refreshes reserve at most 48,576 additional entries.
Enforcement selects master bans before source refreshes, then later deadlines,
with deterministic ties and dropped accounting. `ban_capacity.go` owns these
limits and the 1-second to 1-minute enforcement retry delay. Explicit master and
source commands bypass the periodic deadline; success clears it.

Only blacklist observations consult `source_lookup.go`. Sorted source IDs make
attribution deterministic. A revision owns at most 32 MiB of resident ranges,
4 MiB of sparse indexes, bounded last-block caches, and cached file handles/sizes.
Repeated hits reuse blocks; generation changes and shutdown close handles.
Bulk sorting uses one MiB plus bounded readers, handles ten million IP/CIDR
records without expansion, and reserves up to 2 GiB disk for staging, output,
and rollback. Free-space failures retain the active generation. The 256 MiB
inventory-processing budget excludes kernel set allocations and independent
Xray/session and dynamic-master-state workloads. Hosted `source_scale_test.go`
checks ten million mixed host/CIDR records and peak heap; capacity/retry/lookup
regressions run in hosted Quality, never as local automated suites.

Startup also trims older durable master/source overflow before enforcing and
commits the compacted snapshot once. `ban_capacity_restore_test.go` covers
upgrade/reopen durability, master preservation and later-deadline retention.

`protected.go` and `protected_linux.go` project trusted managed-node addresses
and active member whitelist IPs into memory-only timed kernel exemptions.
Replacement removes stale shared-IP protection while preserving another member's
active entry. Geolocation rules stay ahead of member ban bypass. `detection.go`
sends bounded journaled count deltas below thresholds; the master owns windows
and bans. Disabled probe protection silently drops matching/closed-port traffic.
