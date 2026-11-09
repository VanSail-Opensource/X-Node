# X-Node v2.0.28

Fixes Hysteria inbound activation. The managed-inbound observation wrapper
replaced the concrete `*hysteria.Server` that xray-core's TCP worker inspects
before injecting the QUIC transport validator, so every `protocol: "hysteria"`
listener failed with `transport/internet/hysteria: validator is nil`. Hysteria
inbounds now stay unwrapped and retain native user management and accounting
enforcement; inbound observation events (firewall rule evidence) are not
produced for Hysteria flows. Listener failures also retain the underlying Xray
error in the runtime result instead of a bare summary, so the master receives
the actionable cause. See [kernel notes](../internal/kernel/xray/README.md).

# X-Node v2.0.25

Adds `certificate_lifecycle_v1`: typed, queued ACME issue/renew commands with
durable replay, bounded progress and revision/profile/fingerprint activation
fences. Desired failed profiles remain visible. Certificate status reads stay
responsive during network work and distinguish acquired material from the exact
serving certificate, including partial activation failures. Optional-email ACME
runs without terminal prompts; automatic renewals retain agent lifetime. No PEM,
private paths, provider credentials or raw provider errors enter results.
See [certificate lifecycle](certificates.md) for command and recovery contracts.

# X-Node v2.0.24

Retires resolver selection: DNS interception always uses native Xray DNS.
Deprecated `dns.mode` values remain accepted for compatibility. Legacy SmartDNS
interception without explicit native DNS servers is migrated to an explicit
`127.0.0.1` Xray upstream before parsing, bootstrap and native preparation.
Existing native DNS servers retain precedence. The formerly ignored
`dns.upstreams` field remains ignored; no host resolver configuration or service
is changed. Cached accepted and desired configurations migrate in memory,
preserving authorization, accounting and original state-file contents.

# X-Node v2.0.23

Adds negotiated `native_firewall_port_ranges_v1` support for compact TCP, UDP
and SSH allow ranges, range-to-single forwarding and deterministic equal-length
range-to-range forwarding. Native interval sets keep allow ranges compact;
typed service maps preserve exact forwarding offsets without allocating one
rule per port or choosing arbitrary target ports. Map updates and cleanup share
the existing atomic apply/confirm/rollback transaction. Persisted desired,
confirmed and rollback policies prevent replacement with a range-blind binary.

Masters must gate range delivery on the capability and use the matching public
protocol package. Existing singleton fields and legacy singleton policies remain
readable. Hosted regressions include boundary normalization, map updates,
downgrade protection and real TCP/UDP IPv4/IPv6 packet checks in disposable VMs.

# X-Node v2.0.22

Separates historical hourly traffic receipts from live hourly admission.
Supporting masters advertise `X-XNode-Hourly-Accounting: v1` on each connection,
allowing whole immutable mixed native/hourly reports to replay after a credit
storage failure disables hourly access. Ordinary accounting can continue;
grants, authorization and financial mutations retain their healthy admission
requirements. The receipt flag clears on disconnect and failed connection, and
unknown masters still receive no stripped or relabeled historical reports.

# X-Node v2.0.21

Adds the independently negotiated `hourly_account_limits_v1` capability for
shared member-ingress accounting, centrally reserved full-speed byte credits,
and one account speed bucket across its hourly identities. Transit traffic
does not consume this additional allowance or speed ceiling. The master must
support the complete contract before enabling hourly sales.

Session-bound grants use original demand deadlines, monotonic sequences and
empty initial token buckets. Missing authority pauses idle and waiting streams;
fresh grants resume them without restoring stale capacity. Paid expiry and
authorization revocation close native transports, including idle connections.
Rate redistribution drains started handoffs before releasing allocations.

Private, bounded credit journals retain exact obligations, immutable proofs,
replay tombstones and compaction evidence with checked durability barriers and
whole-document integrity. Successful admission consumes bytes once; financial
sealing preserves that consumption without interrupting an active transfer.
Restart retains unknown obligations rather than inventing unused credit.
Unhealthy journals or changed agent identities disable hourly support while
legacy service continues. Existing purchases require no conversion.

See the [hourly contract](hourly-account-limits.md) for units, negotiation,
accounting boundaries and coordinated rollout requirements.

# X-Node v2.0.20

Hardens the privileged process boundary: native Xray environment keys are
validated before preparation or side effects, and privileged utilities receive
a minimal fixed environment. Connection limits reserve live non-transit client
flows atomically, including idle TCP/UDP and mux streams; sampled activity
remains telemetry, while native-handler capacity and accounting keep their
separate completion lifetimes.

Bounds command receipts by serialized bytes and isolates volatile observations
from durable mutation history. Workers persist execution intent before mutation;
unfinished or uncertain outcomes remain protected across replay and restart.
Oversized legacy journals preserve their original evidence before bounded
metadata recovery rather than replaying uncertain commands. Large observations
can still return within the existing wire limit without entering retained
history.

Validates privileged HTTPS requests and every redirect hop, retaining exact
origin and credential boundaries with a narrow GitHub release-asset CDN
exception. User-scoped IP blocks move only with verified credential/accounting
identity replacements; authorization and restrictions publish together, stale
IP controls cannot follow numeric aliases, and late accounting remains attached
to its original period.

Signed publication now uses protected-main provenance and the exact successful
canonical Quality run. Build, sign and publish stages are isolated, version tags
are immutable, and both architecture bundles, manifests and signatures are
verified before publication. Repository policy changes and signing-key rotation
remain separate operations; redirects and diagnostics do not expose credentials.

Updates Xray to upstream v26.10.31 at
`a4a3dff5b20c2faae567b742c172c7b95e75c083`, including its default MPTCP security
mitigation, `golang.org/x/net` to v0.62.0, and `go4.org/netipx` to
`3075585bcbeb7a9f042662e543b03efe900018be`. Go 1.27.3 and the reviewed nftables,
DigitalOcean provider and YAML pseudo-version pins are retained. The reachable
Brotli dependency is fixed at v1.2.8. See [dependency evidence](dependency-security.md)
for source links and validation boundaries.

Validates the new XHTTP HTTP/2 settings before opening listeners, including
effective extra/download settings, so a malformed reload retains the serving
listener and existing accounted streams.

# X-Node v2.0.19

Adds negotiated Zstandard level-6 report framing with one reused worker and
bounded encoding/decompression. Sampling of active IPs, connection counts and
throughput follows the master's sample interval; reporting follows its separate
report interval. Expensive host maintenance remains on an independent cadence.
Actual sampled IP activity carries timestamps and bounded observation history.

New traffic accumulation and pending reports stay in bounded memory, without
telemetry or traffic spooling on disconnection. Boot-scoped streams identify
replay, gaps and conflicts; surviving usage is committed before acknowledgement.
Existing durable traffic journals drain with their original identities. Upgrade
the panel before agents: new boot-scoped traffic needs a compatible master.
Credentials, configuration, ordinary command receipts and committed financial
accounting retain their durable behavior.

Adds `volatile_firewall_leases_v1` and private, batched
`firewall.leases.update` commands. A separate indexed, memory-only bank enforces
exact IPv4/IPv6 blacklist exemptions with absolute kernel expiry, epoch/generation
replay handling and recovery of unexpired kernel deadlines after agent restart.
Broader bans, manual/paid grants and member admission remain independent. Lease
IP payloads are excluded from durable command history and firewall snapshots.

Replaces periodic status-file writes with a permission-restricted Unix socket
queried by `xnodectl`. Hosted regressions cover disconnected memory bounds,
framing/cadence, replay/conflict handling, lease expiry and both Debian firewall
VM configurations. This release requires coordinated panel support for the new
traffic and automatic lease capabilities.

# X-Node v2.0.18

Updates the pinned Xray core to upstream v26.10.29 (commit `0afec66085a8`),
including its `go-proxyproto` v0.16.0 dependency. This brings upstream fixes for
WebSocket normal-close handling, DNS hijacked-reply buffering, Linux IPv6
process routing, file-loader symlink handling and bounded Geodata downloads.
Native configuration, mux/XUDP lifecycle, accounting, revocation and wire
capabilities remain unchanged.

Managed REALITY inbounds now report rejected proxy credentials and malformed
traffic. REALITY TCP listeners also report clear pre-handshake probes after
fallback forwarding finishes; upstream XHTTP/gRPC pre-handshake errors remain
unavailable. Authenticated closures are excluded.

Admission caches credential and listener-epoch identities between policy
updates, and duplicate firewall acknowledgments no longer rewrite the journal.
Firewall kernel updates retain their existing revision fencing and unlocked
execution; hosted checks exercise stale completion and compare both hot paths.

# X-Node v2.0.17

Moves report encoding and status-file persistence off the control actor into one
bounded coalescing worker. Value-only state metadata avoids copying credentials
and the traffic journal for routine reports and authenticated reconnects.
Reporting defaults to two seconds when omitted; saved intervals remain effective.
Socket/process/GPU scans use an independent ten-second sampling cadence.

Matching traffic acknowledgements immediately advance sealed replay batches;
duplicate acknowledgements perform no disk writes. Ordered inbound saturation
forces authenticated reconnect instead of silently dropping commands or ACKs.
Exact accounting, command receipts, state ordering and existing wire negotiation
remain compatible. Hosted regressions include replay, overflow and metadata
allocation comparisons.

# X-Node v2.0.16

Adds `open_connections_v1` telemetry: total open client TCP/UDP flows are reported
separately from traffic-active connections, including idle flows and excluding
internal transit hops. Logical close clears the total immediately. Legacy and
compact telemetry carry the same observations. Connection limits, sampled
activity, accounting and admission controls retain their existing behavior.
The extension requires an echoed WebSocket handshake header, preserving strict
older masters even when snapshots were queued before reconnect.

# X-Node v2.0.15

Fixes accounting counter reuse after authorization removal and restoration.
Process-local counter generations prevent false regressions and undercounting;
snapshot-aware pruning preserves final bytes arriving during durable writes.
Admission-stop diagnostics now include the redacted underlying storage error.

Adds negotiated numerical compute, one calculation per agent, bounded zstd result
transport and cancellation on disconnect, deadline or resource pressure. Legacy
masters retain the existing transport behavior. No financial or authorization
mutation is delegated to agents.

# X-Node v2.0.14

Isolates bounded command, traffic, telemetry and log delivery lanes while keeping
one WebSocket writer. Disposable telemetry coalesces to the newest snapshot;
durable traffic replay and acknowledgments retain their existing order.

Negotiates compact authoritative telemetry and fast per-message deflate for
reports of at least 1 KiB. Older panels receive the legacy uncompressed format
when negotiation is absent. Expanded frames are bounded before decoding; source
IP collection remains opt-in and exact accounting is unchanged. Hosted socket
fixtures measured a 98.13% wire-byte reduction for representative telemetry.

Adds the reserved Built-in DDNS provider for IPv4/IPv6 discovery without public
DNS publication or provider credentials. VanSail owns host bindings separately.
Successful generated jobs retain acknowledged address-change events in a bounded
private journal, replay after reconnect and preserve the last valid discovery on
failure. Both capability and upgrade-header negotiation gate this extension;
older panels and agents retain their existing behavior. Publish compatible panel
support before enabling these formats or configuring Built-in jobs.

# X-Node v2.0.13

Adds credential-bound Telegram identity rekeys and exact-IP member whitelist
admission, including revocation of existing sessions after address removal.
Managed-node and member source protection are reconciled before acknowledgment.
Probe-disabled rules silently drop matching traffic. Probe-enabled agents send
bounded count deltas for master aggregation and enforce only master bans.

Normal reload rechecks external material and applies incremental changes while
retaining unchanged listeners and sessions. Explicit forced recovery remains
available. Whitelist and firewall updates avoid native rebuilding. Hosted reload
benchmarks compare normal operation against the previous forced baseline.
New extensions are capability-gated; authorization and accounting barriers remain
in force throughout preparation, supersession and activation.

# X-Node v2.0.12

Includes the merged Xray v26.10.17 upgrade and derives reported core versions from
that dependency. Supported routing/account/outbound updates retain the serving
core and unrelated streams. Effective listener epochs exclude global routing.

Native section and validation caches avoid repeated compilation. Controls,
utility and firewall-only changes bypass Xray preparation; identical firewall
policies retain their durable confirmation/rollback identity. Explicit reloads
and unsupported core changes retain validated reconstruction and current
revocation/accounting semantics. Hosted comparison artifacts document work and
listener interruption; see `docs/hot-reload.md` for exact boundaries.

# X-Node v2.0.11

Applies the dynamic/source ban storage budgets when upgrading old durable state,
retaining master restrictions and later-expiring entries. Startup commits the
trimmed snapshot before enforcement, so old source-refresh overflow cannot remain
resident indefinitely. Includes all v2.0.10 capacity, backoff and indexed lookup fixes.

# X-Node v2.0.10

Raises versioned dynamic ban sets to 1,048,576 entries and atomically retires
legacy sets after rule migration. Master restrictions take priority over bounded
source refreshes. Persistent kernel failures back off from one second to one
minute; explicit commands still retry immediately.

Blacklist attribution uses bounded resident or sparse indexes and cached file
handles and blocks. Other observations skip source files. Source processing
supports ten million compact IP/CIDR records with a bounded working set and a
2 GiB disk ceiling covering staging and rollback generations.

# X-Node v2.0.9

Firewall event frames now share a 256-event limit with the master protocol.
Remaining durable reports stay queued until the master commits and acknowledges
their IDs, preventing accumulated observations from being rejected indefinitely.

# X-Node v2.0.8

Upgrade recovery now records a durable transaction exposed by `update.status`
under `update_transaction_v1`. Lock contention is bounded to five seconds and
honors cancellation, disposable downloads are cleaned under transaction
ownership, and corrupt or unreadable state fails closed instead of appearing
idle. A failed result-journal write makes a completed mutation uncertain and
replays the recorded outcome without executing it twice. Commands have explicit
acceptance and execution deadlines; on `activation_commands_v1` agents,
`runtime.reload` and `geodata.refresh` complete only after validated activation
and otherwise retain the previous runtime.

Country ranges now stream into bounded private storage: at most 256 prefixes per
chunk, fixed-width range files merged while streaming, a 512 MiB bulk ceiling
plus a 16 MiB filesystem reserve, and 512-element nftables set transactions.
Dynamic bans, traffic barriers and firewall confirmation reserve an urgent
utility slot during bulk synchronization. Overlapping CIDR exemptions compile to
timed disjoint intervals without extending a shorter grant, while exact
member-IP grants keep their scope. Masters must require `source_geoip_stream_v1`,
`disk_firewall_sources_v1` and `firewall_cidr_exemptions_v1` before enabling
those paths.

Certificate profiles may omit a domain for administrator-owned local PEM files
under `node_file_certificates_v1`, with each read bounded to one MiB. Certificate
and geodata preparation stage candidates and publish them only after activation;
cleanup retains active and previous generations, removes at most 64 abandoned
cache or download directories per pass, and never deletes administrator-owned
inputs. A geosite miss may trigger one verified refresh instead of downloading on
every retry.

Pins google/nftables so commit flushes consume coalesced rule echo replies,
fixing `unknown(2566)` failures on hosts that emit multiple netlink notifications
per batch. Abandoned certificate, firewall, geodata and update artifacts are
removed while active and rollback dependencies are preserved. Upgrades validate
required persisted or staged capabilities against both replacement and rollback
binaries. Hosted Debian coverage adds low-disk recovery, boot firewall
restoration and urgent controls during bulk synchronization.

# X-Node v2.0.7

Fixes self-upgrade deadlock by keeping status reads independent of the installer
and submitting self-restarts without waiting for the service stop job. Both
signed agent and CLI binaries are replaced together. Validated pending listener
configuration survives an occupied port and restart, with bounded retries and
joined activation shutdown. Successful activation includes firewall setup.

Takes control of existing nftables/UFW ownership with durable service/config
backups. Confirmation enables nftables, disables and masks competing UFW, and
restores the confirmed native policy after reboot. Watchdog rollback and uninstall
restore original enforcement and service state. Hosted disposable Debian and
Ubuntu cases cover already-on/disabled nftables, enabled UFW, packet handling,
reboot, rollback and uninstall. Production checks remain Linux/capability based.

Snapshots now separate tables owned by iptables-nft, which nft cannot replay,
and capture each one with its own iptables front end. Rollback and uninstall
restore those tables after the native ruleset, so UFW rules survive recovery
instead of leaving the transaction pending. Hosts whose original snapshot
contains such tables require `xtables_compat_snapshot_v1` to block unsafe
downgrades.

Includes v2.0.6 sampled byte-activity counts, authenticated uncounted transit legs,
master-resolved silent source GeoIP drops, managed domain blocks, and completion
based geosite refresh intervals. Signed-upgrade compatibility now retains those
capabilities for both accepted and pending desired configuration.

# X-Node v2.0.5

Separates firewall detection from durable, master-authorized nftables bans.
Adds configurable report thresholds, public Xray inbound observations excluding
REALITY, NFLOG reporting, compact proxy-source snapshots, exact-IP exemptions,
local repeat-hit refresh and acknowledged expiry events. Only inbound/original
traffic is restricted; outbound traffic and reply packets are preserved.
Compressed ban state and replay cursors survive reboot. Large source sets stage
without blocking immediate ban/unban updates. New masters negotiate the
`firewall_control_v1` capability before enabling report frames.

# X-Node v2.0.4

DNS interception now applies inside Xray only to managed authenticated traffic.
Core resolver queries bypass interception; loopback and public port-53 upstreams
are supported. Host-wide DNS NAT and SmartDNS lifecycle management are removed.
Existing resolver services remain externally managed. Startup and installation
verify operational dependencies without requiring a distribution or OS version.
The master must require `xray_scoped_dns_v1` before enabling interception; signed
upgrades retain the capability when cached configuration depends on it.

# X-Node v2.0.3

Removes the remaining Debian-only runtime checks from the agent, CLI and updater.
Ubuntu 24.04 can now complete token-based bootstrap and start the agent. The
installer still requires apt-get, systemd and Linux amd64/arm64, and verifies
version-bound signed manifests and binary hashes before running downloads.

A hosted Ubuntu 24.04 regression runs the compiled CLI configuration command and
verifies the private bootstrap file. The privileged destructive fixture retains
its Debian 13 and disposable-VM checks. Use this release's installer and binaries;
v2.0.2's CLI and agent still reject Ubuntu even with a newer shell installer.

# X-Node v2.0.2

Publishes version-bound signed amd64 and arm64 artifacts for the native VanSail
Carpool control plane. The authenticated WebSocket protocol, accounting-period
barriers, private monitoring identities, typed node commands and embedded Xray
configuration interface remain compatible with the panel's pinned public packages.

Includes the systemd watchdog timer accuracy correction. Subscription templates,
commerce settlement and member routing editors remain master-side features; they
do not add local operational configuration or a second control transport.

# X-Node v2.0.1

The managed firewall now reconciles policy with native nftables transactions.
Incremental updates retain unchanged rule handles, counters, timed bans and
meters. An independent systemd watchdog still restores the previous policy
unless the master confirms the change.

# X-Node v1.0.1

Maintenance release with no runtime behavior changes. Refreshes signed amd64 and arm64 artifacts from the latest main commit.

# X-Node v1.0.0

Debian 13 redesign with one embedded Xray runtime, multiple tagged inbounds and an authenticated WebSocket control contract.

- Removes Xboard REST, sing-box, Docker and legacy deployment modes.
- Adds atomic user admission, TCP/UDP logical limits, credential/configuration generations and session revocation.
- Adds private cached operation, acknowledged traffic replay and native Xray configuration support.
- Adds remote certificates/DDNS, optional SmartDNS, verified Geodata generations, guarded nftables/forwarding, metrics/logs, peer probes and torrent user bans.
- Publishes amd64/arm64 binaries with a Minisign-authenticated SHA-256 manifest and rollback-aware updates.

The production master is separate. Follow the migration and protocol documentation before installation. Xray v26.10.10 is an upstream prerelease tag pinned by commit.

