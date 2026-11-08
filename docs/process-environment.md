# Privileged process boundary

Embedded Xray and the root agent share one process. `protocol.ValidateNativePolicies`
checks the environment before asset fetching, certificate preparation or native
building. Only the explicitly reviewed `XRAY_*` options in
`internal/protocol/xray_environment.go` are accepted. Values must be bounded
strings without NUL. Arbitrary variables, including loader, executable-search,
language-runtime and Go runtime controls, are rejected rather than filtered.
The native validator and activation use the same policy, including cached
validation and persisted configuration paths. Managed asset injection remains
agent-owned. No new persistence or wire fields are required.

`host.Commands.Run` resolves named tools using a fixed system installation path
and constructs a fresh environment containing only PATH, LANG and LC_ALL.
Absolute executable paths remain available to typed, signature-verified update
and rollback callers. Shell evaluation is never used. Optional GPU probes use
this same runner. Utility errors remain sanitized and contexts bound execution.

Hosted regressions cover malicious/malformed keys and values, rejection before
dependency access or partial environment application, PATH hijacking and actual
child-process environment isolation. No privileged utilities or automated tests
run on the developer host. The allowlist must be reviewed when updating Xray;
upstream accepting a variable does not automatically authorize it in a root agent.

References: [Xray environment semantics](https://xtls.github.io/en/config/env.html)
and [Go process environment and path lookup](https://pkg.go.dev/os/exec).
