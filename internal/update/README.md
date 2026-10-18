# Signed binary upgrades

`manager.go` verifies the signed release manifest, stages and validates both the
agent and CLI, journals their replacement, and arms an independent rollback
timer before changing either executable. Mutation uses the process mutex and
host file lock. `compatibility.go` and `firewall_compatibility.go` reject binaries
that cannot retain current accounting, authorization or firewall state.

Transaction observers read the atomically replaced journal without joining the
installer. Self-restarts use `systemctl --no-block`: waiting for the service job
would wait for the calling process to exit. Confirmation is durable before the
rollback timer is stopped. Rollback restores both binaries before submitting the
same asynchronous restart.

Hosted cases in `restart_test.go` exercise main-loop observations during an
install lock and reentrant status reads during rollback. Signature and capability
regressions remain in the adjacent verification and compatibility tests. These
tests use a fake host runner and never mutate the developer host's services.
