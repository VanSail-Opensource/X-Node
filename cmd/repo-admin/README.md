# Repository administration

This operator CLI uses Git Credential Manager and GitHub's REST API for the
fixed X-Node repository. `main.go` handles flags and credentials; `client.go`
bounds responses, redacts errors, and uses `httpguard.ExactOrigin` for HTTPS and
redirect credential boundaries. API data is inspected in memory, not persisted.
`client_errors.go` limits diagnostic output to method/path and bounded 422
resource/field/code identifiers, excluding messages, values, and query strings.

`info`, `runs`, `jobs`, `releases` (`release`), and `workflow` are read-only.
`automerge` retains its existing repository setting operation. `protect-release`
(`protect`) reconciles policy and verifies observed postconditions.
`signing-secret` verifies that policy before sealing a key for the existing
release environment. It never configures branch or tag access.
`dispatch-release` verifies policy before dispatching the release workflow from
main with a stable version and an exact decimal Quality run ID.

Policy modules separate main-branch checks/reviews, environment preservation,
paginated inspection, and immutable tags. Tests use local TLS mock APIs only;
they are intended for hosted Quality, subject to the repository's local-suite
restriction. See [the operator contract](../../docs/repository-protection.md)
for commands, API details, provenance boundaries, and extension requirements.
