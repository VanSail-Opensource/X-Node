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
