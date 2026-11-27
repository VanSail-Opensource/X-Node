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

`runtime.reload` rechecks external dependencies and uses incremental
application. The optional legacy `{"force":true}` form also rechecks material
without restarting the serving runtime. An unsupported live transition fails
without restarting the runtime or replacing its working configuration.
This protects connection availability during reloads. It does not override
deliberate access revocation, firewall rules, or other policy changes.
Validation of the candidate configuration alone does not prove that a
transition from the current runtime can happen live.
Initial startup and recovery with no serving runtime are separate from
reloading a running instance. Signed binary upgrades and rollbacks still
restart X-Node. Production fleet updates are separate from code delivery.

## Action and configuration consumers

| Input/action | Consumer and native work |
| --- | --- |
| Status, metrics, logs, lists, traffic ACK/flush | Observability/journal; no native builder |
| User limits, expiry, accounting period, block-new, blocked ports, IP controls | Registry; unchanged native accounts reused |
| User IDs/credentials/transit accounts/inbound bindings | Changed inbound account builder and public user manager |
| Providers, DDNS, updates, telemetry | Utility/sampler; referenced certificate providers also invalidate preparation |
| Firewall rules, source GeoIP, bans, forwarding | Existing firewall transaction; identical pending ID or confirmed policy reused |
| Native inbounds and certificate bindings/material | Eligible VLESS and Trojan proxy changes reuse the listener. Compatible additions stage on unused endpoints. Changes that would require replacing a running receiver are refused |
| Native outbounds and MemberOutbounds guards | Eligible new/default-handler changes apply live with existing flow handlers retained. Unsafe replacement or removal is refused |
| Native routing and BlockedDomains | Changed native routing; safe suffix append retains existing matchers |
| Torrent enablement | Generated routing/outbound and affected sniffing settings |
| Torrent ban duration | Dispatch bridge atomic value only |
| Geodata interval/cron | Existing schedule; no native compilation |
| Geodata URL/hash/generation, explicit refresh | Prepare verified generation; only actual dependent sections rebuild |
| Native DNS and session policy levels | Native preparation and in-process replacement |
| Routing strategy/script | Prepared with native routing rules and balancers |
| Other static core fields, including system-level counters | Transitions without a live application path are rejected while serving |
| Unchanged resend/reconnect | Reuse active sections; absent/unhealthy runtime reconstructs |
| config.validate, client previews/probes | Separate validation/client candidate; no serving listener changes |
| runtime.reload | Recheck material, reuse native sections and unchanged listeners; the legacy `force` argument does not restart a serving runtime |
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
The dependency graph includes XHTTP's independent download transport after
native alias, `extra` and socket-penetration selection. Case-insensitive native
field names cannot bypass cycle checks or live application restrictions.
The agent also refuses receiver and certificate changes on an active listener
when Xray has no safe way to replace that listener in place. In that case,
the agent reports a failed activation and continues to serve the old material.
It also refuses gRPC and Hysteria listener additions while serving. Xray's
gRPC listener does not return asynchronous bind failures and its Hysteria
transport requires a native validator that cannot share the staging gate.

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
