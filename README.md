# X-Node

X-Node is a Linux agent that embeds Xray and receives its configuration from a master over one authenticated WebSocket. One process manages multiple tagged inbounds. It runs as a systemd service and ships Linux amd64 and arm64 binaries.

The master server is a separate application. X-Node defines its versioned contract and includes integration fixtures and a runnable example master. It uses a new protocol and does not connect to the Xboard API.

## Features

- WSS bearer authentication, one socket writer, bounded queues, reconnect backoff and snapshot reconciliation.
- Full and incremental user synchronization, explicit empty snapshots, credential rotation and immediate session revocation.
- Shared per-user active-IP, logical TCP/UDP connection and speed limits across inbounds.
- Master-controlled `block_new`, current connection summaries, paginated session details and targeted connection closure.
- Requested user/IP reports, exact source-IP drops/temporary blocks, and explicit `limited` status/rejection reasons.
- Native Xray configuration, DNS, logging, Observatory/balancers, FakeDNS, reverse routing and verified Geodata downloads.
- Shared certificate profiles, ACME HTTP/DNS challenges, supplied/file/self-signed certificates, provider credentials and DDNS.
- Xray-scoped DNS interception with independent loopback or public resolvers.
- Complete nftables ownership, probe protection, IPv4/IPv6 bans, explicit allowlists and TCP/UDP port forwarding with rollback.
- Machine metrics, bounded redacted log reports, peer-proxy speedtests and temporary user bans for classified BitTorrent traffic.
- Private cached operation and acknowledged traffic replay, signed binary updates and rollback.

Xray is pinned to upstream `v26.10.10` by commit. Upstream marks this tag as prerelease. Managed inbounds support VLESS, VMess, Trojan, Shadowsocks, Hysteria 2, authenticated SOCKS/mixed and HTTP; native outbound configuration remains available. Protocol-specific settings and credentials are validated by the pinned core.

## Installation

Download and review the installer from this repository, then run it on an apt-based Linux host with systemd, including Debian 13 and Ubuntu 24.04:

```sh
curl -fsSLo install.sh https://raw.githubusercontent.com/VanSail-Opensource/X-Node/main/install.sh
sudo bash install.sh --master-url wss://master.example.com/v1/agents/connect
```

The installer asks for the token without echoing it. For automation, use `--token-stdin`. Credentials are never required in process arguments. Release manifests and binaries are signature/hash checked before any downloaded binary is executed.

Installation checks the required package manager, service manager and architecture rather than a distribution name or version. The agent, CLI and updater also accept Linux without a distribution/version gate. Package repositories must provide the installer dependencies, including `minisign` ([Ubuntu 24.04 universe](https://packages.ubuntu.com/en/noble/misc/minisign)). Hosted Ubuntu 24.04 checks exercise CLI bootstrap after token entry; privileged firewall/reboot integration remains covered on Debian 13.

Only two local fields are required in `/etc/x-node/bootstrap.json`:

```json
{
  "master_url": "wss://master.example.com/v1/agents/connect",
  "token": "private-machine-credential"
}
```

`XNODE_MASTER_URL` and `XNODE_TOKEN` may supply connection bootstrap through the process environment. The agent generates its identity under `/var/lib/x-node`. Operational settings arrive over WebSocket.

On first startup, the service waits for an authoritative snapshot. On subsequent starts it restores the last accepted configuration and latest authorization state, then reconnects. An unavailable master retains cached users and configured limits until their authorization expiry. Connection-derived controls remain in memory and are cleared after an agent restart.

## Local administration

```sh
xnodectl status
xnodectl service logs
xnodectl service restart
xnodectl upgrade --check
xnodectl upgrade --version v1.0.0
xnodectl rollback
xnodectl uninstall
```

`uninstall --purge` also removes bootstrap, certificates and private state. Standard uninstall retains private state and restores the original nftables snapshot when X-Node managed the firewall.

## Master integration

Go masters can use `github.com/VanSail-Opensource/X-Node/pkg/protocol` for the
agent's exact wire contract. Accounting-aware masters negotiate period-tagged
traffic, flush barriers, measured byte rates, cached authorization expiry and
member proxy guards; see the protocol before adopting these optional fields.

Read [the protocol](docs/protocol.md), [OpenAPI](docs/openapi.json), [AsyncAPI](docs/asyncapi.json), and [JSON schemas](docs/schemas/config.schema.json). Build the detailed searchable static reference with `python3 scripts/build_docs.py`; deploy `docs-site/dist` to Cloudflare Pages using [these settings](docs-site/README.md). The OpenAPI document describes the actual WebSocket upgrade; application operations are frames, not REST endpoints.

Every envelope has `v: 1`, a `type`, an optional request `id`, and `data`. State mutations carry `revision`; incremental changes also carry `base_revision`. The server supplies `users: []` to remove every user. Omitted or null user arrays are invalid.

Start with [the VLESS example](examples/remote-vless.json) or [the TLS/DDNS example](examples/remote-tls.json). Inbound tags identify listeners; there are no node IDs or separate machine/node modes. Native inbound account lists are generated from managed users. The agent owns email labels, statistics and admission wiring.

Limits count distinct source addresses and authenticated logical streams, rather than underlying transport sockets. Streams inside mux transports count separately; a UDP association occupies a slot until the core closes/expires it. NAT clients sharing an address share an active-IP slot. IPv4-mapped IPv6 addresses are normalized.

Local admission is atomic. Cross-machine totals use reports and master `block_new` decisions, so simultaneous admissions on different machines can briefly exceed a global total. Cached decisions remain active during a master outage.

Bandwidth has a normal rate (`speed_limit_mbps`) and an always enforced burst ceiling (`burst_speed_limit_mbps`). After traffic exceeds the normal rate for `speed_limit_after_seconds` consecutive seconds (default 10), the normal cap applies. Bursts resume after `speed_limit_reset_seconds` below the normal rate (default 1). Upload and download share the policy across all sessions and inbounds. Omitting the burst rate retains a fixed normal cap; zero normal and burst rates disable throttling. `users.speed` reports the active rate and whether the normal cap is active.

Client source addresses stay out of periodic reports unless the master enables `telemetry.include_active_ips`. The `users.active_ips` command returns both user IDs and current source addresses. `ips.control` can drop matching sessions, block new ones temporarily, or do both; scope it to one user or every user sharing the address. Temporary IP blocks survive restart.

Per-user status includes `limited` and its reason. Admission failures also emit a structured rejection event. An active-IP threshold limits new addresses; it allows another connection from an existing address when the connection quota permits it.

## Utilities and persistence

Certificate profiles with the same configuration share a manager. DDNS owns explicit `(zone, name, A/AAAA)` record sets and leaves other names/types alone. Provider capability errors are reported through the command channel.

Geodata assets stream to private staging files, are hash checked when hashes are provided, and are activated as one immutable generation. The previous generation remains available for rollback. Refresh scheduling is owned by the agent.

Firewall management owns the entire host ruleset through typed Go nftables transactions. SSH ports are retained, kernel-validated updates preserve live bans/meters/counters, and a separate systemd timer restores the previous rules unless the master confirms the transaction within 45 seconds. Confirmed JSON policy is restored through Go after nftables at boot; `nft` remains available for snapshots, legacy recovery, and uninstall. Proxy connection limits are enforced in the agent; no conntrack connection quota is generated. Legacy host-wide DNS redirection is removed; user DNS is routed inside Xray.

With DNS interception enabled, configure native Xray DNS servers, including loopback or public port-53 upstreams. Only managed user inbounds are intercepted. Core-generated queries use a reserved internal route and cannot re-enter interception. Existing SmartDNS installations remain externally managed; the agent never installs, configures or stops them.

BitTorrent classification blocks the detected flow, closes the user's sessions, and bans new sessions for ten minutes by default. This uses Xray's protocol classification and does not inspect arbitrary encrypted application payloads. Expiry is persisted and reported.

Traffic sampled from logical sessions is journaled before transmission. A report ID identifies an immutable batch; the master must deduplicate it and acknowledge it before removal. Bytes between the last sample and an abrupt process/power failure may be lost. State and traffic journals have a 64 MiB cap; exhaustion pauses admission and closes the runtime instead of discarding recorded traffic.

Logs use a bounded buffer and report dropped entries. Machine metrics are produced by one sampler, so multiple readers do not consume each other's network baselines. GPU data is included when the appropriate driver interfaces are present.

Daily stable-release checks are enabled after configuration arrives. Automatic installation requires the master update policy. Xray dependency updates are reviewable PRs; routine patch/minor dependency updates can auto-merge after the quality gate.

## Development

Use the Go version pinned in `go.mod`. The project structure and engineering rules are in [AGENTS.md](AGENTS.md).

```sh
go test -race ./...
go vet ./...
go mod verify
go run ./cmd/schema
python3 -m pip install -r scripts/requirements.txt
python3 scripts/check_schema.py
make build
```

`scripts/debian-vm.sh` runs privileged integration in a disposable Debian 13 VM. It does not modify the developer host's nftables rules. CI runs race tests, native Xray regressions, schema checks, vulnerability scanning, cross builds and Debian host checks as independent jobs.

Runtime packages:

| Package | Responsibility |
| --- | --- |
| `internal/protocol`, `internal/transport` | Typed messages, schemas, authentication and socket lifecycle |
| `internal/state`, `internal/sessions` | Durable state, journal, atomic admission and session control |
| `internal/kernel/xray`, `internal/agent` | Native runtime integration and serialized desired state |
| `internal/cert`, `internal/dns`, `internal/geodata` | Certificate profiles, DDNS, resolver probes and asset lifecycle |
| `internal/firewall`, `internal/host` | Native atomic firewall reconciliation, JSON boot policy, and typed Linux operations; see `internal/firewall/README.md` and `internal/host/README.md` |
| `internal/monitor`, `internal/nlog` | Shared metrics sampling and redacted logs |
| `internal/speedtest`, `internal/update` | Isolated peer probes and verified releases; see `internal/update/README.md` for self-restart and transaction constraints |

Build helpers under `cmd` generate schemas, sign releases, configure repository automation and run isolated host fixtures. Only `x-node` and `xnodectl` are installed.

## Migration and licensing

See [migration](docs/migration.md), [supported native fields](docs/features.md), and [the upstream review ledger](docs/upstream-review.md).

MPL-2.0. Required third-party attributions are in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
