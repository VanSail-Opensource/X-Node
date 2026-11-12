# Linux host utilities

`Commands.Run` implements the `Runner` interface with context-bound process
execution and argument arrays. It never starts a shell and returns sanitized
command failures. Callers supply their existing typed command policy.

`environment.go` fixes named executable resolution to system directories and
passes only PATH/LANG/LC_ALL. Signature-verified absolute update paths remain
supported. `environment_test.go` checks actual child environment isolation and
PATH hijacking in hosted Linux CI. See `docs/process-environment.md`.

`CheckRequirements` verifies Linux amd64/arm64, root, required utilities, running
systemd and readable nftables kernel state for agent startup and upgrades. The
CLI can configure a private bootstrap using `CheckLinux` without host mutations.
The installer skips package installation when its dependencies already exist;
apt-get is an optional dependency installer rather than an OS compatibility gate.

The destructive `cmd/host-fixture` owns its exact disposable marker and Debian 13
or Ubuntu 24.04 gate; production operations use `CheckLinux` and capability
checks. The uncalled legacy Debian-only helper has been removed.

`lock_linux.go` provides process-scoped file locking for durable operations;
`lock_other.go` supplies the non-Linux build boundary. Live host behavior belongs
in the systemd, firewall, DNS and update modules rather than this command runner.

The hosted Ubuntu 24.04 CLI bootstrap regression exercises the signed-release
CLI source after token input and verifies the bootstrap contents and mode 0600
without starting an agent or changing host services. Privileged Debian 13 and
Ubuntu 24.04 VM integration covers nftables/UFW takeover and reboot recovery.
