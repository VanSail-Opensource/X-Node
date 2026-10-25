# Master protocol package

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
