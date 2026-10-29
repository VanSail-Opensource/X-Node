# X-Node v2.0.16

Adds `open_connections_v1` telemetry: total open client TCP/UDP flows are reported
separately from traffic-active connections, including idle flows and excluding
internal transit hops. Logical close clears the total immediately. Legacy and
compact telemetry carry the same observations. Connection limits, sampled
activity, accounting and admission controls retain their existing behavior.

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
