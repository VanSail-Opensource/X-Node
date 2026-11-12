# Managed certificate profiles

`lifecycle.go` acquires per-profile leases, then runs typed issue/renew actions
outside metadata/status locks. `acme_lifecycle.go` uses public CertMagic APIs,
shared storage coordination and a headless PreChecker; renewal lifetime remains
the agent lifetime. `profile_status.go` publishes all actor-declared desired
profiles. `profile_serving.go` records exact prepared fingerprints immediately
after runtime success, independently from accepted state and manager renewal.
`prepared_candidate.go` fences manual activation to immutable acquired bytes.
Managers are immutable per complete `ProfileKey`. Configuration changes select a
new pooled manager; the retired direct `Manager.Reconfigure` path and its partial
fingerprint are removed. `cert_test.go` checks the live pool identity, including
provider credentials, challenge port, propagation delay and startup timeout.

The preparation mutex serializes cache creation/cleanup, with cancellable waits;
manager operation gates are per profile. Long ACME calls never own metadata or
status mutexes. Cleanup retains leased managers and actual runtime material.
See `docs/certificates.md` for wire, privacy and uncertain-replay contracts.

`profiles.go` prepares shared managers and immutable material. Desired profile
status is published independently from serving status. Node-file profiles reload
bounded local PEM files on preparation;
their host files remain administrator-owned and are never removed by cleanup.
`file_material.go` limits each local certificate/key read to one MiB.

`material_cleanup.go` protects material and ACME storage for current and previous
distinct generations. Startup seeds protection from accepted private state.
Cleanup stops unused managers first and only removes owned hexadecimal cache
directories. Repeated no-op applies do not discard rollback material.

`material_candidates.go` retires managers/material from abandoned preparations.
`RetainRuntime` protects material immediately after runtime application, including
when later firewall/state work fails before `Commit`. Cleanup never touches
administrator-owned input paths and removes at most 64 cache directories per pass.

`validation.go` supplies temporary local/self-signed material for native
preflight. It validates actual file/content profiles without opening ACME
listeners, mutating DNS, or publishing active profile status. Issuance and renewal
belong to activation, with provider adapters in `dnsproviders`.

The custom Vultr adapter uses `httpguard.ExactOrigin` so bearer requests cannot
follow a different host/port or an HTTPS downgrade. Hosted coverage is in
`dnsproviders/vultr_redirect_test.go`; see `docs/http-redirects.md`.
