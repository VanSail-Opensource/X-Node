# Dependency security evidence

The exact-commit Quality run for `95b419af6ba56a736cc8d46e9f1b5ab899e28b83`
reported reachable `GO-2026-6888` in `github.com/andybalholm/brotli` v1.2.3.
The hosted scanner identifies v1.2.7 as the fixed boundary. The selected v1.2.8
is the latest stable module release observed on 2026-11-08 (published 2026-11-04),
with the existing Go API/module path and a Go 1.22 minimum. Checksums remain
verified through Go's module integrity mechanism. No Xray or intentional
pseudo-version pin is changed by this focused remediation.

Quality reruns the complete race/native lifecycle, vulnerability, schema,
architecture build and disposable-host gates. No local automated suite runs.
Reference: [Go vulnerability record](https://pkg.go.dev/vuln/GO-2026-6888).
