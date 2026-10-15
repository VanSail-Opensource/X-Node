# Disposable Debian host checks

This binary refuses to run outside Debian 13 or without
`/etc/x-node-fixture-vm`. `scripts/debian-vm.sh` creates that marker only inside an
ephemeral VM, installs the fixture in `/usr/local/libexec`, and invokes it across
a real reboot. The developer host's firewall is never modified.

The default phase creates two network namespaces connected by dual-stack veth
links. Python standard-library echo servers exercise allowed and closed input
ports and TCP/UDP DNAT/masquerading for IPv4 and IPv6. Native nftables queries
check retained rule handles, timed bans, meters, and foreign-table removal.
Loopback DNS fixtures check readiness and actual TCP/UDP output redirection.

The `--abandon` subprocess applies a policy and exits without confirmation. The
parent observes the independent systemd watchdog restoring the previous policy.
After reboot, `--after-reboot` checks live native restoration, disabled DNS before
readiness, and a real uninstall restoring the original firewall. The surrounding
script verifies a fresh SSH connection survives the reboot.

Dependencies are the installed agent/CLI binaries, iproute2, nftables, systemd,
Python 3, and the same Go DNS/nftables libraries as the agent. Extend packet or
kernel assertions in the corresponding small source files; preserve the VM guard
and the two-phase reboot contract.
