# X-Node engineering guidance

X-Node is a Debian 13 binary agent with one embedded Xray runtime. All master control uses one authenticated WebSocket; provider and artifact traffic may use their native protocols.

## Architecture

- `cmd/x-node`: agent entry point; `cmd/xnodectl`: local deployment commands.
- `internal/protocol`: versioned wire types and validation.
- `internal/state`: private durable snapshots and acknowledged traffic journal.
- `internal/sessions`: atomic user admission, session registry, counters and revocation.
- `internal/kernel/xray`: native config rendering and public Xray integration.
- `internal/agent`: serialized synchronization and utility jobs.
- `internal/cert`, `internal/dns`, `internal/firewall`, `internal/geodata`, `internal/monitor`, `internal/update`: utilities.
- `docs`, `examples`, `scripts`, `.github`: contract, examples, checks and release workflows.

## Standards

Use gofmt, explicit errors, context cancellation and immutable snapshots. Never log tokens, credentials, certificate keys or raw master messages. Never access Xray's private registry or wrap mux-facing pipe readers. User revocation is authoritative even when a subsequent runtime update fails. Synchronize check-and-reserve operations and release reservations exactly once.

Keep local configuration limited to connection bootstrap. New operational settings belong in the protocol and its JSON schemas. Validate native configuration before changing listeners. Keep privileged commands typed and use argument arrays rather than shell interpolation.

## Verification

Run `go test -race ./...`, `go vet ./...`, `go mod verify`, schema checks and Linux amd64/arm64 builds. Exercise real Xray streams for lifecycle changes. Privileged installation/firewall checks run in disposable Debian 13 VMs, never on the developer's host. Do not replace or delete user-owned untracked files such as Task.md.

Release binaries require a signed manifest. Test signing keys must never enter production trust roots. Preserve required MPL/MIT notices when adapting reference code.

Connection-derived `block_new` controls remain in memory. The agent advertises `volatile_connection_controls_v1`; cached authorization keeps credentials, expiry and accounting periods, but never resurrects a historical global connection decision after restart.
