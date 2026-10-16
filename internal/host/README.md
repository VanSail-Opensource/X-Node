# Linux host utilities

`Commands.Run` implements the `Runner` interface with context-bound process
execution and argument arrays. It never starts a shell and returns sanitized
command failures. Callers supply their existing typed command policy.

`CheckLinux` is the platform gate for agent startup, `xnodectl` and binary updates.
It accepts Linux without reading a distribution name or version. The installer
separately requires apt-get, systemd and a supported binary architecture.

`CheckDebian` is reserved for the destructive `cmd/host-fixture` program. Its
Debian 13 check and the fixture's disposable-VM marker protect privileged CI;
production operations must use `CheckLinux`.

`lock_linux.go` provides process-scoped file locking for durable operations;
`lock_other.go` supplies the non-Linux build boundary. Live host behavior belongs
in the systemd, firewall, DNS and update modules rather than this command runner.

The hosted Ubuntu 24.04 CLI bootstrap regression exercises the signed-release
CLI source after token input and verifies the bootstrap contents and mode 0600
without starting an agent or changing host services. Debian 13 privileged VM
integration covers the existing firewall and reboot recovery paths.
