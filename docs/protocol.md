# WebSocket protocol v1

Optional capabilities `traffic_periods_v1`, `measured_user_rates`,
`authorization_expiry`, and `member_outbound_guards` identify the accounting-aware
agent. Masters must verify capabilities before supplying the corresponding
optional configuration fields. Go masters can import `pkg/protocol`.
Hello's `upgrade_pending` marks an unconfirmed binary upgrade. First adoption of
managed extensions is rejected until cached runtime activation confirms that
upgrade, preventing an older watchdog binary from dropping new state on rollback.

Accounting-aware users carry `accounting_period` and an optional RFC3339
`valid_until`. Expiry remains effective while disconnected. Traffic reports keep
their legacy totals and additionally carry `samples` with user ID, accounting
period, UTC `from`/`through`, and exact uploaded/downloaded bytes. For these users,
bill samples rather than adding both representations. Period IDs are master-owned
and must never be reused. Timestamp granularity is one second.

`users.rates[userID]` supplies measured `upload_bytes_per_second`,
`download_bytes_per_second`, and `sample_seconds`. These are payload byte rates;
`users.speed` still describes decimal Mbps policy limits, not measured throughput.

The `traffic.flush` command accepts optional `user_id` and `quiesce`.
With quiescence, block new admission first; the agent closes matching sessions and
waits for their native handlers before capture. The result contains `agent_id`,
the sealed journal `sequence`, `through`, and `quiesced`. The master must commit
reports through that sequence before settling or resetting the old period.
Outstanding batches stay immutable and queued barrier batches survive restart.

`member_outbounds` lists generated member proxy tags. Their endpoints must be
literal public IPs; the master resolves/validates hostnames before compilation
and retains TLS SNI separately. Agent checks reject private, mapped private,
reserved, scoped, and DNS-rebinding endpoints. Member socket overrides and
unvalidated chains are rejected. Managed SS-2022 supports AES-128/256 methods:
server keys stay on inbound settings and native user accounts omit `method`.

Session/IP scans and metrics/history reads are not written to utility history.
Signed installs and rollbacks reject binaries whose version metadata lacks
capabilities required by cached authorization or pending accounting journals.

The agent connects to the configured WSS URL with `Authorization: Bearer <token>` and the `x-node.v1` subprotocol. Authentication, agent enrollment and authorization are the master's responsibility. The agent never places its credential in the URL.

```json
{"v":1,"type":"state.sync","id":"snapshot-1","revision":1,"data":{"xray":{"inbounds":[]},"users":[]}}
```

The agent sends `agent.hello` before other frames on a new socket, then `state.request`. Hello identifies the persisted agent, fresh process boot ID, binary/core versions, applied revision and capabilities. WebSocket Ping/Pong frames keep the connection alive.

## State

| Master frame | Payload | Semantics |
| --- | --- | --- |
| `state.sync` | Complete remote configuration | Authoritative baseline; `users` is required even when empty |
| `config.apply` | Complete remote configuration | Replace configuration with an exact `base_revision` |
| `users.sync` | `{"users": [...]}` | Replace authorization |
| `users.delta` | `{"upsert": [...], "remove": [1]}` | Apply additions/replacements/removals |
| `user.controls` | `{"users":[{"id":1,"block_new":true}]}` | Change admission while retaining established eligible streams |

Revisions increase monotonically. A delta must name the current authorization revision as its base. Gaps trigger `state.request`; stale frames produce an error. Repeated full snapshots at the successfully applied revision are acknowledged without reapplying. The master must advance the revision for corrected configuration.

`state.accepted` acknowledges persisted authorization. `state.applied` acknowledges runtime activation. `state.failed` reports an activation failure; its authorization revocations remain effective. Readiness and synchronization are separate telemetry fields. User-only changes use runtime user managers when available. Listener/global changes may close affected sessions.

Users have a positive ID, credentials, eligible `inbound_tags`, and optional `active_ip_limit`, `connection_limit`, `speed_limit_mbps`, and `block_new`. Zero limits mean no configured user quota. `uuid` is used for protocol defaults; `credentials[tag]` supplies a native client/account object. The agent generates email/level and authenticated SOCKS/HTTP usernames. Transport identities bind credentials and inbound/configuration generations to prevent old mux sessions bypassing revocation.

## Reports

Bandwidth settings are shared per user across upload/download and all inbounds. `speed_limit_mbps` is the normal rate; `burst_speed_limit_mbps` is the hard ceiling, always enforced. Sustained throughput above normal for `speed_limit_after_seconds` (default 10) activates the normal cap. Throughput below 90% of normal for `speed_limit_reset_seconds` (default 1) restores bursts; this small hysteresis prevents oscillation at the enforced rate. Consecutive durations use one-second windows and actual elapsed time, independent of report intervals. A below-normal window resets the high-traffic streak. Omitting the burst ceiling retains the fixed normal rate. `users.speed[userID]` reports `normal_mbps`, `burst_mbps`, `active_mbps`, and `limited` (normal cap active).

```json
{"id":1,"uuid":"550e8400-e29b-41d4-a716-446655440000","inbound_tags":["vless"],"speed_limit_mbps":100,"burst_speed_limit_mbps":500,"speed_limit_after_seconds":10,"speed_limit_reset_seconds":1}
```

`telemetry.report` is an authoritative current snapshot containing agent/boot IDs, timestamp, liveness/readiness, revisions, per-user connection counts and limit status, rejection counters, machine metrics and certificate status. Missing users in its current online set have zero active sessions; the master must replace that set rather than merge indefinitely.

User source IPs are omitted by default. Request a one-time report with `users.active_ips`, or opt into periodic IP sets with `telemetry.include_active_ips: true`. Each requested record carries `user_id`, canonical `source_ip`, and its current connection count.

Per-user `users.status[userID]` reports `limited: true/false`, `reason`, and `scope`. A full active-IP quota has scope `new_ip`: existing IPs can still create streams when the connection quota allows it. `block_new` and connection quotas have scope `new_connection`. Each rejected admission also emits `admission.rejected` with `user_id`, `limited: true`, `reason` and `scope`; `source_ip` appears only when periodic IP reporting is enabled. Reasons include `ineligible`, `block_new`, `torrent_ban`, `ip_temp_block`, `blocked_port`, `connection_limit`, `active_ip_limit`, and `storage_backpressure`.

`traffic.report` contains `{id, traffic}`, with `traffic[userID] = [upload_bytes, download_bytes]`. The batch ID is stable across retries and process restarts. Deduplicate it before billing, then send:

```json
{"v":1,"type":"traffic.ack","data":{"id":"agent-id:sequence"}}
```

Only the matching pending batch is retired. Status and logs are disposable snapshots; traffic is acknowledged durable data. `logs.report` supplies timestamped entries and a dropped-entry count. Secrets are redacted before console, file forwarding and remote report serialization.

## Commands

```json
{"v":1,"type":"command","id":"operation-1","data":{"name":"connections.list","args":{"limit":100}}}
```

Commands emit `command.accepted`, optional `command.progress`, and `command.result`. Results contain `id`, `command`, `status`, optional `data/error`, and completion time. Two utility workers run concurrently. The last 128 completed results are retained across restart for request-ID deduplication; IDs must remain unique beyond this window.

| Command | Arguments |
| --- | --- |
| `connections.list` | `after`, `limit` (default 100, maximum 1000); cursor is the last returned session ID |
| `connections.close` | Session `id`, or `user_id` plus optional `inbound_tag` |
| `users.active_ips` | Optional `user_id`; omission requests current active source addresses for all users |
| `ips.control` | `source_ip`, optional `user_id`, and `drop`, `block_seconds` or `unblock` |
| `metrics.get`, `certificates.get`, `jobs.list`, `firewall.status`, `update.check` | Empty object |
| `runtime.reload` | Empty object; queues runtime reconstruction |
| `ddns.run` | `job_id` from the accepted configuration |
| `geodata.refresh` | Empty object; refresh then reconstruct using the new generation |
| `speedtest` | `peer_outbound`, HTTPS `download_url`/`upload_url`, optional `max_bytes`/`timeout_seconds` |
| `firewall.apply` | `policy`, optional `dns_redirect` |
| `firewall.confirm` | `transaction_id` from `firewall.pending` or the apply result |
| `update.install` | Optional stable `version` |
| `update.rollback` | Empty object |

Cancellation uses `command.cancel` with `{id: operation-id}`. Completed operations remain queryable; cancellation cannot undo a mutation already accepted by an external provider.

IP controls target exact client source addresses, normalized so IPv4-mapped IPv6 equals IPv4. An omitted/zero `user_id` targets every user at that address. `drop: true` closes current matching logical sessions. `block_seconds: 1..604800` rejects new matching sessions until a persisted deadline; existing sessions remain unless drop is also requested. `unblock: true` clears that scoped ban. Drop-only does not create a ban.

```json
{"v":1,"type":"command","id":"ip-action-1","data":{"name":"ips.control","args":{"source_ip":"192.0.2.10","user_id":42,"drop":true,"block_seconds":600}}}
```

Firewall transactions default to 45 seconds. The master must confirm using the existing or re-established socket after testing connectivity. An independent systemd watchdog restores both live rules and persisted policy if confirmation is absent.

Speedtests use a separate outbound-only Xray client and transfer HTTPS payloads through the peer. They default to three request-latency samples, at most 32 MiB download, 8 MiB upload and 60 seconds total. The transfer bound can reach 64 MiB and timeout 120 seconds. Test credentials and HTTP endpoints are supplied and managed by the master.

`torrent.detected` reports `user_id` and ban deadline. `torrent.expired` reports expiry. `block_new` controls and per-machine connection reports implement approximate global totals; no per-admission master reservation is performed.

## Operational settings

The configuration schema describes provider credentials, certificate profiles, inbound certificate references, DDNS jobs, resolver policy, firewall policy, outbound port ranges, asset hashes, telemetry, torrent policy and update policy. Operational defaults are one-second sampling, five-second reporting, five-minute DDNS refresh, ten-minute torrent bans and disabled automatic binary installation.

The agent owns Geodata downloads and suppresses the core's duplicate downloader. Native `geodata.assets` filenames stay inside the managed asset directory; cron and download outbound selection are honored. SHA-256 hashes are supplied through `asset_hashes[file]`.
