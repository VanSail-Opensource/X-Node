# Signed binary upgrades

`manager.go` verifies the signed release manifest, stages and validates both the
agent and CLI, journals their replacement, and arms an independent rollback
timer before changing either executable. Mutation uses the process mutex and
host file lock. `compatibility.go` and `firewall_compatibility.go` reject binaries
that cannot retain current accounting, authorization or firewall state.
Host firewall service takeover additionally requires `host_firewall_ownership_v1`
when its original-service recovery journal is present. Snapshotted iptables-nft
tables additionally require `xtables_compat_snapshot_v1` whenever the original
compatibility record exists, because older binaries would flush them without
restoring the rules nft cannot express.

Transaction observers read the atomically replaced journal without joining the
installer. Self-restarts use `systemctl --no-block`: waiting for the service job
would wait for the calling process to exit. Confirmation is durable before the
rollback timer is stopped. Rollback restores both binaries before submitting the
same asynchronous restart.

Hosted cases in `restart_test.go` exercise main-loop observations during an
install lock and reentrant status reads during rollback. Signature and capability
regressions remain in the adjacent verification and compatibility tests. These
tests use a fake host runner and never mutate the developer host's services.
The shell installer delegates existing installations to its newly verified CLI,
which reads the installed agent's version. It never reuses an obsolete installed
CLI's platform gate or compares the upgrade target against the staged CLI itself.

`locking.go` bounds process/file-lock contention to five seconds and honors cancellation. All service work is submitted after both locks exit. The timer executes the newly installed CLI. Old-host mitigation is documented in `../../docs/upgrade-recovery.md`.

Compatibility checks enumerate every detected persisted capability, including
staged configurations. `persisted_compatibility_test.go` guards disk sources,
CIDR exemptions, streamed country generations and domain-free file certificates
against unsafe replacement or rollback binaries.

`cleanup.go` removes disposable `.new` downloads under transaction ownership on
install exit and confirmation/startup. Installed binaries, both `.old` rollback
dependencies and private journals remain protected. Corrupt transactions fail
closed before installation or cleanup.
Unreadable transactions report unavailable and retain the pending compatibility
fence; status inspection never converts corrupt recovery state into idle.
