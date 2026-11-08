# Dependency security evidence

## v2.0.20 dependency refresh

The selected Xray security release is
[`v26.10.31`](https://github.com/XTLS/Xray-core/releases/tag/v26.10.31), resolved
to immutable commit
[`a4a3dff5b20c2faae567b742c172c7b95e75c083`](https://github.com/XTLS/Xray-core/commit/a4a3dff5b20c2faae567b742c172c7b95e75c083).
Upstream disables MPTCP by default as a security mitigation and withdrew
v26.10.29. Updating the embedded core does not update the host kernel.

The new XHTTP `h2Params` field is checked before certificate preparation or
listener activation. Upstream defers its JSON type check until after binding a
listener. The pure guard follows alias/`extra`/download-setting precedence and
uses Go's HTTP/2 types, with parity fixtures against the pinned native builder.
Malformed known types also reject in inactive transport settings; unknown fields
and node-local certificate placeholders retain their existing handling.

`golang.org/x/net` advances from v0.61.0 to
[`v0.62.0`](https://pkg.go.dev/golang.org/x/net@v0.62.0), the latest release
reported by the Go module proxy on 2026-11-08. `go4.org/netipx` advances from
`fdeea329fbba` to immutable commit
[`3075585bcbeb7a9f042662e543b03efe900018be`](https://github.com/go4org/netipx/commit/3075585bcbeb7a9f042662e543b03efe900018be).
The resolved module versions are
`github.com/xtls/xray-core v1.260327.1-0.20261031132019-a4a3dff5b20c` and
`go4.org/netipx v0.0.0-20260823151212-3075585bcbeb`.
The Go toolchain remains pinned to 1.27.3. The manifest and checksums record the
resolved module versions; a newer repository commit is not treated as a stable
release unless that dependency's release policy calls for an explicit pin.

These existing pseudo-versions are deliberate and remain unchanged:

| Module | Retained version | Reason |
| --- | --- | --- |
| `github.com/google/nftables` | `v0.3.1-0.20260430172505-f9b52ed2ba65` | Keeps the reviewed [userdata bounds fix](https://github.com/google/nftables/commit/f9b52ed2ba65) beyond the older tagged release. |
| `github.com/libdns/digitalocean` | `v0.0.0-20250606071607-dfa7af5c2e31` | Keeps the [libdns v1 provider implementation](https://github.com/libdns/digitalocean/commit/dfa7af5c2e31) required by the configured provider family. |
| `github.com/ghodss/yaml` | `v1.0.1-0.20220118164431-d8423dcdf344` | Retains the existing transitive [commit selection](https://github.com/ghodss/yaml/commit/d8423dcdf344) rather than rewinding it to an older tag. |

Do not bulk-apply `@latest` over intentional pins. Go's release selection may
prefer an older tagged revision over a newer reviewed pseudo-version. Resolve
the chosen upstream revision explicitly, preserve its checksum, and review the
resulting module graph; see the [Go module reference](https://go.dev/ref/mod#pseudo-versions).

Validation belongs to the exact-commit hosted Quality run: race/native lifecycle,
schema and vulnerability checks, amd64/arm64 builds, and both disposable Debian
firewall configurations. No local automated suite runs. A dependency edit is
not evidence of a passing scan or a published release. Update the panel's
protocol/native-validator pin only after the signed agent release and both
architecture bundles have been verified through the
[release provenance](release-provenance.md) and [bundle](release-bundle.md) gates.

## Earlier reachable Brotli remediation

The exact-commit Quality run for `95b419af6ba56a736cc8d46e9f1b5ab899e28b83`
reported reachable `GO-2026-6888` in `github.com/andybalholm/brotli` v1.2.3.
The hosted scanner identifies v1.2.7 as the fixed boundary. The selected v1.2.8
is the latest stable module release observed on 2026-11-08 (published 2026-11-04),
with the existing Go API/module path and a Go 1.22 minimum. Checksums remain
verified through Go's module integrity mechanism. That focused remediation
changed neither Xray nor the intentional pseudo-version pins.

Quality reruns the complete race/native lifecycle, vulnerability, schema,
architecture build and disposable-host gates. No local automated suite runs.
Reference: [Go vulnerability record](https://pkg.go.dev/vuln/GO-2026-6888).
