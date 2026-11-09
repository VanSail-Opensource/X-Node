# Embedded Xray runtime

`hourly_permit.go` waits for account-wide native admission using cancellation,
controller change notifications and rate deadlines. `hourly_buffers.go`,
`hourly_reader.go` and `hourly_writer.go` hand off exactly the permit's real
payload bytes. Stream tails retain their ordering and final read error; UDP
buffers retain packet boundaries and metadata, including empty packets. A packet
larger than 16 KiB is rejected before admission. Writer ownership transfers even
on failure: only the unhanded tail is released. Successful `Begin` consumes quota
and records separate raw hourly samples; delivery failure never refunds it.
Legacy metering remains unchanged. Chained outbounds reuse one logical flow, and
the wrappers remain exclusively outbound-facing, preserving mux pipe readers.

An unstarted permit cancelled by grant refresh is reacquired with its original
buffer and datagram metadata intact; only successful `Begin` admits bytes.
Native revocation cancels the lease and interrupts both original link endpoints.
Controller fencing also closes the authenticated inbound connection when Xray
provides it, because socket-backed VLESS buffer wrappers may not forward close.
Paid/auth revocation closes even idle connections. Grant/session loss and rate
shrink retain authorized idle/waiting flows, pausing payload until fresh control;
only already-started native handoffs need interruption and a rate drain.
Financial credit sealing freezes admission without interrupting delivery.
Mux children inherit one authenticated principal and connection. Ordinary flow
completion keeps that connection open for its healthy siblings; legacy/transit
flows never use the additional hourly transport fence.
This controls admission and draining inside the runtime; it does not promise
that already-admitted operating-system/network bytes disappear at a deadline.
Hosted `hourly_reader_test.go`, `hourly_writer_test.go` and their
`hourly_test_helpers_test.go` cover slicing, EOF, cancellation, packet metadata
and write-error ownership. `hourly_native_helpers_test.go`,
`hourly_native_test.go` and `hourly_expiry_test.go` exercise real TCP/mux and
UDP/XUDP, exact raw admissions, idle control pause/resume, credit rollover during
blocked delivery and strict idle paid-boundary closure.

`xhttp_validation_test.go` sends real XHTTP traffic while rejecting malformed
direct, `extra` and nested-download HTTP/2 settings. Forced invalid reloads must
preserve the serving listener, existing streams, new admission and accounted
traffic. Early checks are shared with public validation through the protocol.

`connection_limits_test.go` exercises real TCP and mux streams: an idle first
flow still denies a second, existing traffic survives, and closing allows a new
flow. Each logical dispatch uses the existing atomic session reservation.

`environment_test.go` verifies that rejected native environment input cannot
partially mutate the privileged process. Environment rules are shared through
the protocol validator; see `docs/process-environment.md`.

`config.go` validates native documents with the pinned core and expands managed
account lists. `runtime.go` owns listener activation, account-only updates and
safe fallback with current authorization. `bridge.go` wraps native outbound
dispatch to enforce member admission, expiry, revocation and exact traffic
accounting. Client probes use `client.go` and the public core interfaces.

`auxiliary.go` publishes an immutable, atomically replaced allowlist for native
`dokodemo-door` / `tunnel` utility listeners. Only unauthenticated flows from
these explicitly configured listener tags bypass member accounting. They cannot
receive managed accounts; user-bound proxy listeners always retain admission
and accounting enforcement. Utility listener changes are part of normal native
configuration reconciliation, while member changes leave unchanged utilities
running. The master must negotiate `native_auxiliary_inbounds_v1`.

`auxiliary_test.go` exercises real forwarding through both core aliases and
checks that managed revocation neither restarts utility listeners nor charges
their bytes to a member. `runtime_test.go`, `streams_test.go` and
`shadowsocks_accounts_test.go` cover actual managed streams, accounting barriers,
credential rotation, expiry and SS-2022 authentication in hosted Linux CI.
Stream assertions wait for successful server writes to publish their counters;
receiving a response on the client can precede that publication.

`dns.go` adds authenticated-inbound-only port-53 routing and a reserved core DNS
identity. Internal queries use their own freedom outbound with explicit local
resolver access. No DNS listener is opened and no host packet is redirected.
`dns_test.go` exercises real VLESS TCP/UDP queries against a controlled resolver,
including one-query loop prevention. These regressions run in hosted Quality.

Resolver mode is retired. `PrepareCached` first applies the protocol's
`Config.NormalizeDNS` compatibility migration; legacy loopback behavior becomes
an explicit native server before rendering. `dns.go` requires native servers
when interception is enabled and contains no mode-dependent fallback. The
deprecated upstream list remains inert. `dns_migration_test.go` covers this
boundary without starting host services.

`inbound_config.go` and `inbound_observer.go` wrap public native proxy interfaces,
retaining public user-management methods and existing listener update behavior.
They classify unauthenticated probes, malformed input and rejected credentials,
including REALITY, while excluding authenticated shutdowns. `reality_observation.go`
also recognizes explicit failures logged before the TCP proxy handler runs.
REALITY XHTTP and gRPC discard pre-handshake errors inside the upstream listener,
so those failures cannot be observed by the public Xray log handler. No mux-facing
reader or private registry is inspected. Hosted regressions send an empty TCP
connection, a plain HTTP GET and a malformed TLS record to a real REALITY TCP
listener. The upstream error does not distinguish these payloads; each is reported
as `xray_tcp_probe` after fallback forwarding ends. A valid TLS ClientHello with
an unconfigured server name exercises camouflage forwarding and `xray_invalid`.

`transit.go` expands owner-scoped peer accounts with separate credential generations and managed authentication labels. `domain_blocks.go` inserts the master domain block rule before all native/system rules with a reserved block outbound. Agent validation refuses unresolved IP geodata and mixed REALITY/source-filter sockets before listener activation.

`reload_test.go` verifies forced reload validates before stopping the serving runtime and rebuilds unchanged native documents. The optional reload flag on `Runtime.Apply` retains account-only updates and activation fallback.

Incremental configuration is described in repository path `docs/hot-reload.md`. `sections.go` retains immutable static,
inbound, outbound and routing protobufs. Effective listener identities include
certificate bytes and never include global routing. `live.go` stages public
outbound handlers and quiesces only affected registry flows; `routing_update.go`
uses native rule replacement or a safe suffix append. Unsupported immutable,
default-outbound, mux/chain and observer changes reconstruct after preparation.
`statistics.go` exposes memory-only build/rebuild counters for hosted regressions.
`client_prepared.go` caches one immutable client configuration, never a live core.

`live_stream_test.go`, `outbound_stream_test.go` and `sections_test.go` cover real
TCP/mux/UDP continuity, scoped outbound replacement and section/matcher work.
The hosted benchmark compares cold/cached preparation and forced/live application.
`balancer_reload_test.go` verifies public selector forwarding and live balancer
changes. The managed manager serializes upstream selector-cache access with
handler additions/removals.

`reload_benchmark_test.go` compares unchanged normal reload to the previous
forced behavior. `live_stream_test.go` checks unchanged TCP/mux sessions across
repeated normal reload, using the same runtime application path as the agent.
