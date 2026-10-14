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
