# Master WebSocket transport

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
