# Embedded Xray runtime

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

`dns.go` adds authenticated-inbound-only port-53 routing and a reserved core DNS
identity. Internal queries use their own freedom outbound with explicit local
resolver access. No DNS listener is opened and no host packet is redirected.
`dns_test.go` exercises real VLESS TCP/UDP queries against a controlled resolver,
including one-query loop prevention. These regressions run in hosted Quality.

`inbound_config.go` and `inbound_observer.go` wrap public native proxy interfaces,
retaining public user-management methods and existing listener update behavior.
They classify unauthenticated probes, malformed input and rejected credentials,
including REALITY, while excluding authenticated shutdowns. `reality_observation.go`
also recognizes explicit failures logged before the TCP proxy handler runs.
REALITY XHTTP and gRPC discard pre-handshake errors inside the upstream listener,
so those failures cannot be observed by the public Xray log handler. No mux-facing
reader or private registry is inspected. Hosted regressions cover classification
and a real managed TCP probe.

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
