# Disposable Linux host checks

This binary refuses to run outside Debian 13 / Ubuntu 24.04 or without
`/etc/x-node-fixture-vm`. `scripts/debian-vm.sh` creates that marker only inside an
ephemeral VM, installs the fixture in `/usr/local/libexec`, and invokes it across
a real reboot. The developer host's firewall is never modified.

The default phase creates two network namespaces connected by dual-stack veth
links. Python standard-library echo servers exercise allowed and closed input
ports and TCP/UDP DNAT/masquerading for IPv4 and IPv6. Native nftables queries
check retained rule handles, timed bans, meters, and foreign-table removal.
Loopback DNS fixtures check readiness and actual TCP/UDP output redirection.

The `--abandon` subprocess applies a policy and exits without confirmation. The
parent waits 45 seconds from process exit plus the bounded 30-second recovery
and 15 seconds of process/scheduler tolerance
for the independent systemd watchdog to restore the previous policy. If it does
not, the fixture reports timer/service state, journal entries and pending state.
After reboot, `--after-reboot` checks live native restoration, disabled DNS before
readiness, and a real uninstall restoring the original firewall. The surrounding
script verifies a fresh SSH connection survives the reboot.

Dependencies are the installed agent/CLI binaries, iproute2, nftables, systemd,
Python 3, and the same Go DNS/nftables libraries as the agent. Extend packet or
kernel assertions in the corresponding small source files; preserve the VM guard
and the two-phase reboot contract.

`ownership.go` retains the exact disposable marker/platform guard, prepares
already-on nftables, disabled nftables, or Ubuntu UFW baselines, and checks
takeover, reboot and uninstall ownership. The CI matrix runs all three cases
in separate disposable VMs. The VM script verifies the official Debian SHA512
or Ubuntu SHA256 image checksum before boot; no privileged fixture runs locally.
`startup.go` waits for the actual agent process after its firewall dependencies
finish, with a bounded deadline and unit-journal diagnostics.

The aggregate fixture has a 12-minute budget for software-emulated UFW/Python and
iptables process startup. `commands.go` reports utility name, duration and context
expiry without printing arguments. Only `Manager.RecoveryTimeout` is extended for
the fixture: restoring UFW ownership needs more than the production 30-second
recovery budget when systemd runs under TCG. Agent transactions, the 45-second
watchdog and the watchdog's default recovery budget remain unchanged and are
still exercised by the fixture.

`firewall_control.go` validates real NFLOG reporting without autonomous bans,
master-authorized nftables restrictions, repeated-hit refresh, exact IPv6
exemptions and outbound/reply preservation. It leaves an authoritative ban and
compact source generation for reboot verification. These destructive checks
remain confined to the marked disposable VM.

The VM harness bounds reboot SSH channels and probes independently of connection setup. OpenSSH keepalives detect a rebooted guest that cannot close its old forwarded TCP stream. A four-minute reboot deadline reports the guest serial log instead of consuming the workflow timeout.
