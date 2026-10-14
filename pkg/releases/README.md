# Release verification

`verify.go` exposes the same embedded minisign trust key and version-bound
manifest validation used by automatic updates. A master verifies the official
SHA256SUMS and signature before accepting a migration binary.

`metadata.go` reports the current executable's SHA-256 and operating-system /
architecture. The agent includes this measurement in authenticated hello frames.
This is a compatibility check for trusted enrolled agents, not hardware attestation.
