# Master protocol package

`hourly.go` exports optional hourly user/grant/sample and credit-obligation wire
types plus pure validators/digests. `hourly_schema.go` exposes `HourlySchemas`
without importing enforcement or persistence. Negotiate both hourly upgrade
headers and check the hello capability before admitting hourly plans. The detailed
contract is `docs/hourly-account-limits.md`.

`OpenConnectionsCapability` gates `UserMetrics.TotalConnections` (compact `o`).
These totals include idle client flows; existing `Connections` remains the sampled
traffic-active count used for limits. Treat totals from older agents as unknown.

`ActivityObservationsCapability` and its independent upgrade header gate actual
sample timestamps and at most 16,384 recent user/IP observations. `ValidateActivity`
checks full snapshots as strictly as compact expansion. IP history stays volatile;
publication/replay does not refresh observation timestamps or decimal counters.

`CompactTelemetry` and `ExpandTelemetry` map negotiated compact snapshots to the
same internal report types. Empty snapshots replace prior observations, and
normalization rejects duplicate users and invalid counters/rates. Transport
headers and hello capability constants define connection-local negotiation.
`ReadMessagePayload` bounds expanded input without importing a WebSocket library.

This public package exposes the same versioned wire types, strict decoders,
configuration validation, account labels and schemas used by the agent.
Masters can import it without depending on private implementation packages.
`types.go` provides contract aliases; `codec.go` provides validation and codec
entry points. Domain state, networking and runtime lifecycles remain outside
this package. Pin an agent revision and negotiate optional capabilities before
transmitting new fields.

`AuxiliaryInboundTags` identifies native `dokodemo-door` / `tunnel` utility
listeners for capability negotiation. They accept no managed user bindings or
account lists and require `native_auxiliary_inbounds_v1` on the receiving agent.

Public firewall aliases include rules, bans, exact exemptions, source generations,
status and acknowledged event batches. IPv4 learned bans are exact; IPv6 learned
bans use /64. Event sequence suffixes are fixed-width decimal values inside a
stable namespace. Source references reuse node generations without retransmitting
unchanged inventories.

`GeoIPChunk` and optional SourceGeoIPPolicy.reference support capability-gated country uploads outside configuration frames. ExemptionPrefix/ExemptionKey canonicalize IP/CIDR grants while retaining exact IPv6 /128 semantics separately from /64 ban granularity.

`CommandTimeout(name)` exposes the native execution deadline shared by master and agent. Delivery acceptance is bounded separately to 30 seconds.

`types.go` also exports `RuntimeReloadArgs` for capability-gated normal reload
and explicit forced recovery, without introducing another command transport.

## Negotiated compressed reports

`report_frame.go` exposes `report_zstd_l6_v1` and `X-XNode-Reports: zstd-l6-v1`.
A master echoes this offer before an updated agent uses binary report frames.
The first four bytes are 58 4e 5a 01 (XNZ and binary version 1), followed by a
four-byte big-endian decoded JSON length, then independent Zstandard data with
checksum. The JSON envelope and payload schemas remain unchanged. Controls,
commands, acknowledgements and agent.hello remain text frames. Never combine
binary report framing with WebSocket permessage-deflate. Legacy peers retain
bounded text/deflate decoding.

Level 6 uses EncoderLevelFromZstd(6), one reused encoder worker, a 1 MiB window
and low-memory operation. Decoders use one worker, enforce both the declared
length and the 16 MiB decoded cap, and bound compressed input separately. Idle
scratch buffers retain at most 512 KiB; larger buffers are disposable. These
codecs never touch the filesystem. `report_frame_test.go` covers malformed sizes,
checksums, expansion bounds and retained memory; its hosted benchmark measures
round trips over 10,000 synthetic observations.

`traffic_stream.go` exposes independent boot-stream negotiation and canonical report identity validation. Traffic report/barrier aliases carry stream and legacy replay references; dropped samples signal bounded-memory loss without a fabricated byte count.

Automatic firewall leases use `AutomaticLeaseCapability`, `AutomaticLeaseCommand`,
`AutomaticLeaseUpdate` and `AutomaticLeaseAck`. `AutomaticLeaseAddress` canonicalizes
public IPv4/IPv6 addresses with shared conservative reserved-range exclusions.
Lease payloads and receipt data are volatile; masters must use their existing
per-node outbound queue without durable command history.
