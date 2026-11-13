# Master WebSocket transport

`hourly.go` independently negotiates operational hourly enforcement through an
exact format/session echo. Disconnect immediately clears wire negotiation but
retains the already accepted local authority session: reduced-rate leases keep
their original deadline, and centrally reserved byte credit remains spendable
within its paid/UTC-day boundaries. Failed reconnects cannot renew either limit.
A successful new handshake fences the old session, including a master that no
longer supports hourly admission. Disable and client shutdown revoke authority
synchronously. `hourly_accounting.go` separately accepts the exact
response header `X-XNode-Hourly-Accounting: v1`, so historical traffic receipts
remain available when local hourly credit storage disables admission. A current
live-v1 negotiation also establishes receipt compatibility for older supporting
masters. Disconnect and failed reconnect clear this connection-local flag;
local admission disable does not. `hourly_message.go` suppresses live hourly
frames without admission support and whole hourly-containing immutable traffic
batches without receipt compatibility; stale demand/ack frames
cannot cross sessions, while durable proofs retain their old installation
binding for replay. `hourly_test.go` and `hourly_fallback_test.go` cover handshake,
socket teardown, capability disable and preservation of accounting on fallback.
`hourly_accounting*_test.go` covers exact/malformed headers, TLS replay and failed
upgrades; the agent's matching regression preserves mixed reports across a real
storage-disable reconnect without restoring hourly access.

`X-XNode-Open-Connections: v1` independently negotiates total open client counts.
`Client.OpenConnections()` resets on disconnect; the serialized writer strips
the extension from queued legacy/compact snapshots for older strict masters.
`open_connections_test.go` covers negotiation, queued reconnect fallback, both
formats, and unchanged traffic-active counts.

`X-XNode-DDNS-Changes: acknowledged-v1` independently negotiates durable DDNS
change delivery. `Client.DDNSChanges()` is connection-local; `message.go` drops
an old queued extension after reconnecting to a legacy master, leaving its
journal event unacknowledged for later replay. `ddns_test.go` covers both peers.

`Client.Run` owns reconnection, the authenticated handshake, one reader and one
writer. `Client.Send` retains its existing public interface; callers never write
the socket directly. `connection.go` owns connection/read lifetime, while
`writer.go` handles control frames and drains the bounded lanes.

Connection upgrade headers negotiate compact telemetry independently from
compression. The accepted format is connection-local atomic state; reconnect
clears it, and the writer converts a previously queued compact snapshot when the
new master requires legacy JSON. `message.go` owns this fallback and report-only
per-message compression at 1 KiB using Gorilla's fast, context-free deflate.
`ReadMessagePayload` limits expanded input before parsing. `telemetry_wire_test.go`
measures actual client socket bytes, including WebSocket framing, and checks
uncompressed legacy fallback plus exact large accounting integers. Hosted CI
publishes its measurement output as the `telemetry-wire` artifact.

`lanes.go` stores commands (64 frames/32 MiB), ordered journal traffic (16 frames/
32 MiB), the newest telemetry snapshot (one frame/16 MiB), and disposable events
including logs (64 frames/4 MiB). Budgets include envelope allowance. One weighted
round serves two command frames and one of each remaining class; ping, pong,
cancellation and reconnect controls are checked between every data write.

Telemetry replacement is intentional and counted as discarded transport data.
Accepted traffic batches never replace each other. On durable-lane overflow,
`Send` returns false and requests reconnect/resynchronization; the state journal
retains unacknowledged batches and replays them in the existing order. The
transport never acknowledges, persists, rewrites or settles traffic itself.

`lanes_test.go` checks saturation fairness, latest-snapshot semantics, durable
overflow and byte-budget release. Existing WSS tests cover authentication and
serialized concurrent producers. Automated regressions run only in hosted CI
for this delivery; local verification uses static checks and permitted builds.

An overflowing ordered inbound queue closes the connection to trigger authenticated reconciliation, rather than silently losing a command or acknowledgement. `overflow_test.go` verifies disconnect at saturation.

`report_frame_test.go` covers negotiated binary reports and legacy text fallback.
`message.go` chooses framing at the serialized writer after each handshake, so
queued reports follow the current peer's capabilities. `client.go` reuses one
encoder across reconnects and closes it when Run exits; no reporting path spools
to disk. Binary report writes explicitly disable permessage-deflate.

Boot-scoped traffic has its own handshake. Serialized writing suppresses new stream reports to legacy masters, retaining old journal framing and IDs. This never converts volatile traffic into legacy sequences. Both kinds share the bounded existing traffic lane.

`telemetry_extensions.go` strips sampling timestamps and IP history unless this
connection accepted `X-XNode-Activity: observations-v1`. The handshake is
independent of Zstandard, compact format and total-open counts. `activity_test.go`
covers queued newer snapshots reconnecting to legacy/full/compact masters and
negotiation reset on disconnect.
