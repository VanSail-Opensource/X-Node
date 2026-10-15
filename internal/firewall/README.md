# Host firewall

This module owns the complete Debian host firewall. The agent's serialized jobs
call `Manager.Apply`, `Confirm`, `EnableConfirmedDNS`, and `Migrate`. The local
`xnodectl` commands call `RollbackID`, `RestoreFile`, and `RestoreOriginal`.

## Native engine

`Backend` is the injectable kernel boundary. Its Linux implementation compiles
`protocol.FirewallPolicy` into typed google/nftables v0.3.0 chains, rules, named
counters, interval address sets, port sets, and dynamic timeout sets. Native
Netlink is local kernel I/O; it does not make external API requests.

Policy compilation is separate from ordered rule reconciliation and set deltas.
Rule userdata contains stable semantic IDs; expression comparison detects changes
even when an ID remains the same. Kernel-assigned set IDs are excluded from that
comparison. Overlapping CIDRs are normalized with netipx without enumerating IPs.
New rules are inserted relative to retained handles, preserving packet order.

All changes, including removal of foreign tables, are buffered and committed by
one `Conn.Flush`. Kernel rejection leaves the previous ruleset intact. Ordinary
updates reuse dynamic sets, preserving ban expirations and per-source meters, and
reuse named counters. Incompatible live set definitions fail before commit rather
than discarding state. There is no conntrack connection quota; the session module
enforces proxy connection limits. This design follows ngrok/firewall_toolkit's
rule/set separation without importing its managers or intermediate flushes.

## Transactions and recovery

Every operation takes the manager mutex and a cross-process filesystem lock.
Lock acquisition and Netlink I/O observe cancellation and bounded deadlines.
Before changing sysctls or live policy, apply saves a complete `nft list ruleset`
snapshot, previous boot files and policy, forwarding state, and a private pending
record. An independent 45-second systemd timer runs `xnodectl firewall-rollback`;
its service retries failed recovery. The master confirms the transaction ID after
checking connectivity. Reusing the current ID with different inputs fails.

Known atomic rejections restore metadata/sysctls without replaying the snapshot.
Cancellation or an ambiguous missing acknowledgment triggers full snapshot
recovery using a separate cancellation-independent context. Recovery leaves the
transaction pending if restoration fails, so the watchdog can retry. Late
confirmation and stale watchdog IDs cannot replay obsolete snapshots.

## Persistence, migration, and lifecycle

Confirmed `policy.json` is authoritative. Disk records retain legacy flat fields
and add an internal engine version; public pending/status results expose only
`Pending`. Legacy confirmed records can carry `status: pending`, because the old
writer saved them before updating status. The separate current transaction is
checked first when recovering a crash.

Confirmation replaces the managed `/etc/nftables.conf` with a comment, installs
`x-node-firewall.service` after nftables and before the agent, and adds an agent
dependency drop-in. Previous files are restored if migration fails. Binary
upgrades must be confirmed before persistent migration. Cached startup migrates
the previously confirmed policy without changing its redirect intent. The
`native_firewall_v1` capability prevents subsequent unsafe binary downgrades.

Boot restoration and agent startup recover unconfirmed transactions and reconcile
the confirmed policy through Go, with DNS redirection disabled. The agent enables
redirection only after both loopback families answer TCP and UDP DNS probes. An
agent startup restore also supports upgrades from the old service ordering.

The `nft` executable remains necessary for complete arbitrary-ruleset snapshots,
legacy rollback, diagnostics, and uninstall. Uninstall restores `original.nft`
and original forwarding sysctls, removes the dependency drop-in and confirmed
policy, and retains other private state unless purge was requested.

## Verification and extension

Portable manager fixtures inject `Backend` and `host.Runner`; Linux fixtures cover
compilation, expression changes, order, and set boundaries. The disposable Debian
VM fixture verifies real packets, live-state retention, watchdog recovery after
the applying subprocess exits, reboot ordering, and uninstall. Never execute the
privileged fixture on a developer host. Keep new policy settings in the existing
protocol/schema, and extend the compiler rather than adding another executor.
