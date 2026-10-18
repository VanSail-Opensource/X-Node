# Linux host utilities

`Commands.Run` implements the `Runner` interface with context-bound process
execution and argument arrays. It never starts a shell and returns sanitized
command failures. Callers supply their existing typed command policy.

`CheckRequirements` verifies Linux amd64/arm64, root, required utilities, running
systemd and readable nftables kernel state for agent startup and upgrades. The
CLI can configure a private bootstrap using `CheckLinux` without host mutations.
The installer skips package installation when its dependencies already exist;
apt-get is an optional dependency installer rather than an OS compatibility gate.

`CheckDebian` remains a legacy fixture-only helper. The destructive
`cmd/host-fixture` now requires an exact disposable marker and Debian 13 or
Ubuntu 24.04; production operations use `CheckLinux` and capability checks.

`lock_linux.go` provides process-scoped file locking for durable operations;
`lock_other.go` supplies the non-Linux build boundary. Live host behavior belongs
in the systemd, firewall, DNS and update modules rather than this command runner.

The hosted Ubuntu 24.04 CLI bootstrap regression exercises the signed-release
CLI source after token input and verifies the bootstrap contents and mode 0600
without starting an agent or changing host services. Privileged Debian 13 and
Ubuntu 24.04 VM integration covers nftables/UFW takeover and reboot recovery.
