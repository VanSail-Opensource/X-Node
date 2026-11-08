# Repository release protection

`cmd/repo-admin` manages policy for `VanSail-Opensource/X-Node`. It uses Git
Credential Manager; tokens, private keys, request bodies, and API error bodies
are never printed. Requests use HTTPS and an exact-origin redirect guard.
Errors identify the HTTP method, public path without its query, and protection
module. Bounded 422 diagnostics may include only validated resource/field/code
identifiers; validation messages, values, and raw response text remain hidden.

## Commands

Run from the repository root. Flags precede the operation:

```sh
go run ./cmd/repo-admin info
go run ./cmd/repo-admin workflow
go run ./cmd/repo-admin -run-id 123 jobs
go run ./cmd/repo-admin protect-release
go run ./cmd/repo-admin -key-file /private/release.key signing-secret
go run ./cmd/repo-admin -version v2.0.20 -run-id 123 dispatch-release
```

`protect` aliases `protect-release`. `release` aliases read-only `releases`.
`runs`, `jobs`, `info`, `releases`, and `workflow` retain bounded JSON output.
`workflow` observes canonical Quality workflow `383872953` at
`.github/workflows/ci.yml`. `automerge` retains its existing operation.

`protect-release` changes settings only; it never uploads a signing key or
dispatches a release. It applies and reads back each policy, then verifies all
three together. Repeating the operation does not create duplicate policies or
rulesets. Partial GitHub API failure leaves completed protection changes in
place and returns an error; GitHub offers no transaction across these endpoints.

## Main branch

The helper updates `/branches/main/protection`. Required status checks are
strict and bind these exact names to GitHub Actions app `15368`:

- Tests and schemas
- Debian binary amd64
- Debian binary arm64
- Vulnerability scan
- Host debian / nftables-on
- Host debian / nftables-off

Update requests contain `checks` without `contexts`. GitHub returns both on
reads but rejects an update containing both, even an empty `contexts` array,
with 422. Separate request/response types preserve legacy contexts by converting
them into check entries, retaining existing app bindings. This matches the
[primary integration report](https://github.com/integrations/terraform-provider-github/issues/1212).

Ordinary collaborators require an approving PR review. Existing higher review
counts, review restrictions, additional checks, push restrictions, linear
history and conversation settings are preserved. Force pushes and deletions
are disabled. Additional PR bypass allowances are cleared to retain ordinary
review requirements. `enforce_admins=false` deliberately retains administrators'
explicit direct-main push workflow; release signing must still independently
validate the exact successful canonical Quality run and main provenance.

## Signing environment

The existing `release` environment uses custom deployment policies with the
sole allowed entry `main`, type `branch`. Admin bypass is disabled. Existing
required reviewers, wait timer, and self-review settings are preserved and
verified; no new human approval requirement is introduced. Reviewer ordering
does not change policy meaning. Unknown protection types or unexpected
deployment patterns cause an error rather than deletion of unrelated settings.

The legacy `v*` tag policy is deleted by its discovered ID before adding main
when necessary. All list pages are inspected within a bounded maximum. The
helper requires explicit readback of `can_admins_bypass=false`: GitHub's REST
reference/OpenAPI currently omit this de facto update field, although the live
API and primary integration clients expose it. A 2xx response alone is not
proof that bypass protection was applied.

`signing-secret` requires all release protections to pass read-only inspection
before reading or uploading the key. It uses the environment's public key and
NaCl sealed-box encryption, then deletes the legacy repository-level copy.
It never recreates the `v*` deployment policy. Key rotation and policy changes
are separate operations.

## Immutable tags and dispatch

The repository-owned ruleset `Immutable release tags` targets `refs/tags/v*`
with active enforcement, empty exclusions and bypass actors, and only update
and deletion rules. Creation remains allowed. Existing rulesets outside this
managed name are preserved. Duplicate managed names or changed identities
cause an error; successful creation/update is followed by a full detail read.

`dispatch-release` accepts only stable `vX.Y.Z` versions and a positive signed
64-bit run ID. After policy verification it posts to
`/actions/workflows/release.yml/dispatches` with `ref=main` and string inputs
`version` and `quality_run_id`; decimal formatting preserves integer precision.
It does not create or move tags. The release workflow remains responsible for
checking tag/commit correspondence, successful Quality provenance, artifacts,
and signatures. A dispatched run is not a completed release.

GitHub settings can change concurrently between API calls. Every mutation
therefore needs its readback, and every signing/dispatch operation rechecks
policy. Changes to check names, workflow identity, tag ownership, or policy
shape must update the helper, release validator, documentation, and hosted
mock-API regressions together.

## Upstream contracts

- [Branch protection API](https://docs.github.com/en/rest/branches/branch-protection#update-branch-protection)
- [Environment API](https://docs.github.com/en/rest/deployments/environments#create-or-update-an-environment)
- [Deployment branch policies](https://docs.github.com/en/rest/deployments/branch-policies)
- [Repository rulesets](https://docs.github.com/en/rest/repos/rules#create-a-repository-ruleset)
- [Environment protection behavior](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments)
- [Primary environment update implementation](https://github.com/integrations/terraform-provider-github/blob/main/github/resource_github_repository_environment.go)
