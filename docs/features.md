# Native Xray capability inventory

Pinned upstream tag: `v26.10.10`, commit `701af60772cda123492f86e383e1fdba066614a9`.

The renderer keeps native root objects and validates them with the pinned Xray loader. Root fields are checked against upstream `infra/conf.Config`, so a new unsupported root field produces a clear validation failure.

| Native field | Handling |
| --- | --- |
| `inbounds` | Tagged managed listeners; accounts, identity labels and admission are generated |
| `outbounds` | Native protocol/settings/streamSettings/mux/proxySettings/targetStrategy preserved; tags and dependency cycles checked |
| `routing` | Rules, domain strategy and balancers preserved; required torrent/DNS rules precede supplied rules |
| `dns` | Native built-in resolver preserved |
| `log` | Native log settings preserved; events also enter bounded redacted reports |
| `policy`, `stats` | Native settings preserved with required per-user accounting enabled |
| `observatory`, `burstObservatory` | Native connection observations preserved |
| `fakeDns`, `reverse`, `version` | Native objects preserved |
| `geodata` | Verified geosite.dat domain generations; completion-based hour intervals or retained legacy cron; GeoIP is master-resolved |
| `env` | Native Xray environment options; asset location is managed by the agent |
| `api`, `metrics` | Native core objects; node-to-master operations remain WSS frames |
| `transport` | Upstream-deprecated global transport configuration is rejected by the selected core |

TLS/REALITY, XHTTP, TCP/WebSocket/gRPC, socket options, sniffing and fallback settings stay in the native inbound/outbound objects. Unsupported protocol fields fail core validation rather than creating a listener with partial settings.

Current upstream Freedom behavior blocks private destinations by default for managed proxy protocols. Local integration fixtures use explicit `finalRules` allowing loopback. Operators configuring private-network forwarding through Xray must set their intended native final rules.

Machine metrics cover Debian host/CPU details, per-core usage, load, memory/swap, mount usage, disk I/O, interface addresses and counters/rates, TCP/UDP counts, process count, uptime/virtualization, Go heap/GC/goroutines, NVIDIA and AMD driver metrics when available. Missing collectors report unavailable status.
