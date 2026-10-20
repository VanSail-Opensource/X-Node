# Incremental Xray configuration

The agent uses the merged Xray v26.10.17 dependency. Compilation means native
configuration/matcher construction; no configuration action compiles a binary.
Signed binaries are built only in release delivery.

## Delivery checklist

- [x] Preserve core upgrade 3103519 and derive reported versions from the core.
- [x] Reuse immutable native sections and prepared activation candidates.
- [x] Apply registry, utility, firewall and supported routing changes separately.
- [x] Preserve unchanged listeners and scoped accounting/revocation barriers.
- [x] Add hosted real-stream, invalidation and compilation-count regressions.
- [ ] Verify hosted Quality, signed artifacts and compatible panel delivery.

## Constraints

All activation uses the existing serialized executor. Authorization is applied
before native activation and never rolled back. Active/last candidate caches are
memory-only, and synthetic validation material never becomes an activation
candidate. Core construction mutates the global system dialer, so the serving
instance is never accompanied by a second complete candidate instance.

Explicit `runtime.reload` reconstructs the runtime after external dependencies
are checked. Configuration reconciliation and unchanged geodata refresh do not
implicitly request a forced reconstruction. Production fleet updates are separate
from code/release delivery.

## Action and configuration consumers

| Input/action | Consumer and native work |
| --- | --- |
| Status, metrics, logs, lists, traffic ACK/flush | Observability/journal; no native builder |
| User limits, expiry, accounting period, block-new, blocked ports, IP controls | Registry; unchanged native accounts reused |
| User IDs/credentials/transit accounts/inbound bindings | Changed inbound account builder and public user manager |
| Providers, DDNS, updates, telemetry | Utility/sampler; referenced certificate providers also invalidate preparation |
| Firewall rules, source GeoIP, bans, forwarding | Existing firewall transaction; identical pending ID or confirmed policy reused |
| Native inbounds and certificate bindings/material | Changed listeners; content hashes form admission epochs |
| Native outbounds and MemberOutbounds guards | Changed outbounds validated; supported changes quiesce only affected flows |
| Native routing and BlockedDomains | Changed native routing; safe suffix append retains existing matchers |
| Torrent enablement | Generated routing/outbound and affected sniffing settings |
| Torrent ban duration | Dispatch bridge atomic value only |
| Geodata interval/cron | Existing schedule; no native compilation |
| Geodata URL/hash/generation, explicit refresh | Prepare verified generation; only actual dependent sections rebuild |
| DNS/other static core fields, routing strategy/script | Native component build and runtime reconstruction |
| Unchanged resend/reconnect | Reuse active sections; absent/unhealthy runtime reconstructs |
| config.validate, client previews/probes | Separate validation/client candidate; no serving listener changes |
| runtime.reload, binary install/rollback | Explicit reconstruction/restart, with prepared configuration reuse |

The classifier begins with all configuration fields, removing only known
non-core fields. Unknown future fields therefore require native preparation.
Hosted exhaustiveness tests require every protocol command and configuration
field to receive an explicit consumer. Protocol validation and authorization are
always performed, including on cache hits.

Rule replacement recompiles the native table's matchers because the public core
API exposes atomic table replacement, not reusable private matcher objects.
Only a strict suffix append with unchanged balancers/strategy/script reuses the
previous matchers. Outbound changes involving affected mux/reverse/dialer chains,
default changes or configured observers use reconstruction. Replacement/removal
on nodes with untracked utility flows also reconstructs; additions remain live.

Native protobufs are immutable snapshots; core construction receives a clone.
Each runtime/validator keeps only active/latest candidates. Cached client
configuration is a single bounded entry; every probe still owns a separate core.
Certificate/asset preparation and validation proofs are invalidated by content,
not file modification timestamps. Synthetic validation material is never reused
for real activation.

Hosted Quality publishes `reload-benchmark` with cold/cached preparation at 1 and
1000 users and live/forced rule application. Logs report application mode, actual
native/section/matcher builders, reconstruction count and listener-gap duration.
The gap is measured around stop/start only; preparation happens while serving.
