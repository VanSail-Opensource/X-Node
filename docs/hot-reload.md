# Incremental Xray configuration

The agent uses the pinned Xray dependency in `go.mod`. Compilation means native
configuration/matcher construction; no configuration action compiles a binary.
Signed binaries are built only in release delivery.

## Delivery checklist

- [x] Preserve core upgrade 3103519 and derive reported versions from the core.
- [x] Reuse immutable native sections and prepared activation candidates.
- [x] Apply registry, utility, firewall and supported routing changes separately.
- [x] Preserve unchanged listeners and scoped accounting/revocation barriers.
- [x] Add hosted real-stream, invalidation and compilation-count regressions.

Release acceptance requires hosted Quality, signed artifacts and the compatible
panel pin. Their terminal results are recorded with the delivered release.

## Constraints

All activation uses the existing serialized executor. Authorization is applied
before native activation and never rolled back. Active/last candidate caches are
memory-only, and synthetic validation material never becomes an activation
candidate. Core construction mutates the global system dialer, so the serving
instance is never accompanied by a second complete candidate instance.

`runtime.reload` rechecks external dependencies. Changes that do not alter an
active receiver use incremental application. The legacy `{"force":true}`
form behaves identically and does not restart an unchanged runtime. A valid
enforced transition that cannot apply live falls back to a cold reload of
embedded Xray. Deliberate access revocation, firewall rules, and other policy
effects still apply. Signed binary upgrades and rollbacks restart X-Node itself.

## Action and configuration consumers

| Input/action | Consumer and native work |
| --- | --- |
| Status, metrics, logs, lists, traffic ACK/flush | Observability/journal; no native builder |
| User limits, expiry, accounting period, block-new, blocked ports, IP controls | Registry; unchanged native accounts reused |
| User IDs/credentials/transit accounts/inbound bindings | Changed inbound account builder and public user manager |
| Providers, DDNS, updates, telemetry | Utility/sampler; referenced certificate providers also invalidate preparation |
| Firewall rules, source GeoIP, bans, forwarding | Existing firewall transaction; identical pending ID or confirmed policy reused |
| Native inbounds and certificate bindings/material | Eligible VLESS and Trojan proxy changes reuse the listener. Compatible additions stage on unused endpoints. Changes to active receiver settings or compiled TLS material can rebuild embedded Xray after preflight |
| Native outbounds and MemberOutbounds guards | Eligible handler additions, replacements, and direct Carpool member route retirement apply live. The dispatcher pins its chosen handler for in-flight traffic. Unsafe replacement or removal is refused |
| Native routing and BlockedDomains | Changed native routing; safe suffix append retains existing matchers |
| Torrent enablement | Generated routing/outbound and affected sniffing settings |
| Torrent ban duration | Dispatch bridge atomic value only |
| Geodata interval/cron | Existing schedule; no native compilation |
| Geodata URL/hash/generation, explicit refresh | Prepare verified generation; only actual dependent sections rebuild |
| Native DNS and session policy levels | Native preparation and in-process replacement |
| Routing strategy/script | Prepared with native routing rules and balancers |
| Other static core fields, including system-level counters | A valid change without a live application path uses a cold Xray reload |
| Unchanged resend/reconnect | Reuse active sections; absent/unhealthy runtime reconstructs |
| config.validate, client previews/probes | Separate validation/client candidate; no serving listener changes |
| runtime.reload | Recheck material, apply incrementally where supported, and permit an explicit retry after a failed cold cutover. The legacy `force` argument does not change this behavior |
| Binary install/rollback | Explicit process restart |

The classifier begins with all configuration fields, removing only known
non-core fields. Unknown future fields therefore require native preparation.
Hosted exhaustiveness tests require every protocol command and configuration
field to receive an explicit consumer. Protocol validation and authorization are
always performed, including on cache hits.

Rule replacement reuses unchanged compiled rule definitions when available
and publishes native rules atomically. Outbound changes are subject to live
application checks for affected mux/reverse/dialer chains, observers and
untracked utility flows.
Direct member-route additions and edits can remove and reintroduce an outbound
during the Carpool authorization transition. Dispatch sees a coherent pair of
routing rules and outbound handlers and retains the exact handler selected by
an in-flight decision. Retired handlers are not selected by new decisions.
This does not bypass credential revocation. Configurations with scripting,
TUN, native API, reverse, or balancers and observers that can select a removed
handler remain conservative.
The dependency graph includes XHTTP's independent download transport after
native alias, `extra` and socket-penetration selection. Case-insensitive native
field names cannot bypass cycle checks or live application restrictions.
The agent uses cold reload for gRPC and Hysteria listener additions that cannot
use live staging. The embedded gRPC receiver reports bind failures
synchronously. Hysteria needs its concrete native QUIC validator and therefore
cannot share the live staging gate.

## Cold reload and recovery

Effective changes to active receivers, including compiled TLS certificates and
keys, trigger a full reload of embedded Xray after validation. Other valid
changes that cannot be hot-reloaded use the same recovery path. X-Node probes
compatible new endpoints that do not overlap serving listeners. Validation
and these probes cannot guarantee every bind will succeed.

X-Node stops the old core before starting the replacement. This can interrupt
connections and briefly stop new admissions, but does not restart the X-Node
process or change its boot ID. Failed native startup restores the previous
compiled configuration when possible, including the original certificate
bytes even if the source files have changed. Interrupted connections cannot be
restored. Automatic reconciliation does not repeat a failed disruptive cutover
of the same effective native configuration. Correct the configuration or run
`runtime.reload` to retry explicitly.

At process startup, X-Node attempts the persisted pending configuration first.
If activation fails, it tries to serve the last accepted listeners while
retaining and retrying the pending revision. Restoring accepted listeners does
not roll back authoritative authorization or mark the pending revision applied.

Native protobufs are immutable snapshots; core construction receives a clone.
Each runtime/validator keeps only active/latest candidates. Cached client
configuration is a single bounded entry; every probe still owns a separate core.
Certificate/asset preparation and validation proofs are invalidated by content,
not file modification timestamps. Synthetic validation material is never reused
for real activation.

Hosted Quality publishes `reload-benchmark` with cold/cached preparation at 1 and
1000 users and rule application. Logs report application mode, actual
native/section/matcher builders, reconstruction count and listener-gap duration.
Preparation happens while serving.

The `incremental_reload_v1` capability identifies incremental reload support.
Whitelist and firewall-only changes update admission/guards without native
preparation.
Hosted `BenchmarkRuntimeReload` reports timing, allocations, runtime builds and
listener-gap data.
