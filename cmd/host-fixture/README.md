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
parent waits 45 seconds from process exit plus 15 seconds of scheduler tolerance
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

`firewall_control.go` validates real NFLOG reporting without autonomous bans,
master-authorized nftables restrictions, repeated-hit refresh, exact IPv6
exemptions and outbound/reply preservation. It leaves an authoritative ban and
compact source generation for reboot verification. These destructive checks
remain confined to the marked disposable VM.
