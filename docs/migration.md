# Migration from Xboard-Node

This is a new control-plane contract. Existing Xboard, Hiddify, node/machine IDs, REST endpoints, local standalone users and multi-instance YAML are removed.

1. Implement the documented master WSS endpoint and persist monotonic agent revisions.
2. Convert listeners into native Xray inbounds with stable tags. Remove native account arrays; send users and eligibility separately.
3. Convert sing-box-only protocols/settings to protocols supported by the pinned Xray core. Unsupported managed inbound protocols fail validation.
4. Move certificate/provider credentials, routing, DNS, telemetry intervals and limits into remote configuration.
5. Install the Linux binary service on an apt-based systemd host (including Debian 13 or Ubuntu 24.04) and provide only connection bootstrap locally.
6. Deduplicate traffic batch IDs and acknowledge them. Replace current online snapshots and send per-user `block_new` decisions.

Preserve the generated agent identity and private state when upgrading. Removing that state creates a new identity and loses legacy traffic journals and durable hourly credit evidence. New traffic uses bounded, memory-only boot streams: a restart loses usage not yet committed by the master. Upgrade the master before enabling `traffic_stream_v1`; settle surviving committed usage and retain gap/loss evidence. Credential rotation is authoritative even when an unrelated native configuration fails; send a corrected snapshot with a higher revision.

Firewall ownership is complete. Configure allowed services/forwarding explicitly,
then confirm the apply transaction over WSS. DNS interception belongs to Xray
user routing. Resolver selection and the ignored upstream list are removed
from the live contract. Send only `dns.redirect` and explicit native
`xray.dns.servers`. The private snapshot reader preserves a historical accepted
or staged SmartDNS loopback fallback during offline boot; new input cannot use
`dns.mode` or `dns.upstreams`. Existing explicit native servers win. The next
ordinary state write removes these retired fields without changing revisions,
accounting identity or staged-versus-accepted configuration. Host services stay
externally managed.

## Native firewall engine

Existing firewall policies and command arguments remain compatible. The Go
backend adopts the existing X-Node table and retains compatible live bans,
per-source meters, and counters. Conflicting set definitions fail without flushing
state. External tables are removed atomically with the policy update.

After binary-upgrade confirmation, firewall confirmation (or cached-policy
migration) installs native boot restoration. Confirmed JSON replaces the generated
nft script as the source of truth. The managed nftables config becomes a comment;
the X-Node restore unit runs after nftables and before the agent. Previous unit,
config, policy, and forwarding files participate in rollback. Legacy pending
transactions and original nft snapshots remain recoverable.

An unconfirmed transaction is rolled back at agent startup or reboot. Legacy
host DNS NAT is removed; managed-user interception follows native Xray DNS. Once
native boot persistence is confirmed, binary upgrades/rollbacks require
`native_firewall_v1`; older binaries cannot safely restore the new boot layout.

Native `dokodemo-door` / `tunnel` utility listeners are preserved separately from
managed member inbounds. They require `native_auxiliary_inbounds_v1` and cannot
contain user/account arrays. `internal/protocol/auxiliary.go` validates this
boundary; `internal/kernel/xray/auxiliary.go` publishes the immutable utility
allowlist to native dispatch. Real forwarding and revocation checks are in
`internal/kernel/xray/auxiliary_test.go`, with protocol isolation and downgrade
coverage in `internal/protocol/auxiliary_test.go` and
`internal/update/compatibility_test.go`.
