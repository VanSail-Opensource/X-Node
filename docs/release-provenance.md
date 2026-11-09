# Release provenance

`scripts/release_provenance.py` proves which canonical commit a release may use.
It does not check out source, execute release assets, sign files, publish a
release, or change repository policy. The release workflow embeds this source
from its trusted `main` definition so tagged source cannot replace the gate.

Documentation-only pushes to `main` do not trigger the Quality workflow
(`paths-ignore` in `ci.yml`), so such a commit has no successful Quality run.
Tag a release on a commit that includes code or workflow changes; a tag on a
documentation-only commit is rejected by the quality gate.

Invoke it with `python3 scripts/release_provenance.py VERSION QUALITY_RUN_ID`.
The same source supports `python3 - VERSION QUALITY_RUN_ID` when embedded in a
workflow. `GH_TOKEN` authenticates fixed-origin GitHub API reads. Successful
execution prints only the peeled commit SHA; every failure prints one generic
message without API bodies, credentials, or request URLs.

## Required evidence

The invocation must run as `workflow_dispatch` on `refs/heads/main` in
`VanSail-Opensource/X-Node`, repository ID `1416770902`. Only stable
`vMAJOR.MINOR.PATCH` versions and explicit positive numeric run IDs are accepted.

The tag must exist as a commit or at most five content-addressed annotated tags.
Its reference is reread after collecting metadata; retargeting rejects the
snapshot. The commit must be an ancestor of the current protected `main` snapshot.
The branch summary must contain all six required Quality check contexts bound
to GitHub Actions application `15368`, with checks enforced for non-admins or all
actors. Missing app-bound check metadata rejects the release.

Quality must be active workflow ID `383872953`, named `Quality`, at exactly
`.github/workflows/ci.yml`. The explicitly selected run must be a successful,
completed `push` on canonical `main`, with canonical repository and head-repository
identities and the exact peeled tag commit. Its pinned run attempt must contain
exactly the six expected successful, completed jobs. Duplicates, extra jobs,
skipped jobs, foreign commits, and failed jobs reject the release. The run is
reread after collection so a concurrent rerun cannot substitute another attempt.

The managed `Immutable release tags` repository ruleset must actively prohibit
updates and deletion of `refs/tags/v*`, with no exclusions or creation rule.
Visible bypass actors must be an empty list. GitHub deliberately omits bypass
actors from callers without ruleset write access; an omitted field is accepted
only within the separate administrator-preflight trust model below.

## Policy setup and permission boundary

The workflow token reads branch summaries rather than requesting repository
administration access. These summaries prove enforced app-bound checks, but do
not expose every branch-protection setting. Before release dispatch, the
administrator helper applies and independently reads back the complete policy:
strict checks, review requirements, force-push/deletion restrictions, the exact
tag ruleset including an empty bypass list, and the protected release environment.
`dispatch-release` repeats that full policy verification immediately before
dispatch. The runtime gate does not claim to independently verify hidden fields.

The release workflow must repeat this gate before building, signing, and
publishing, and require the same resulting SHA at every phase. Signing must
remain isolated from executables and code supplied by the tag. Repository
administrators can change workflows and policies; this gate does not add a
second administrator credential to the signing job.

Publication explicitly uses `--latest=false`. The stable, signed version is
available by its exact tag while the compatible panel is pinned, deployed and
verified. Only then may the operator promote it to Latest for automatic agent
discovery. Publishing artifacts must not upgrade agents ahead of their master.
See the [GitHub CLI release options](https://cli.github.com/manual/gh_release_create).

## Interfaces and resource bounds

`validate_context(version, run_id, context)` validates invocation inputs.
`fetch_metadata(api, version, run_id, context)` collects snapshots through an
injected fixed-origin JSON getter. `validate_provenance(metadata)` is pure and
returns a SHA or raises `ProvenanceError`. These interfaces let hosted tests
exercise negative metadata without network access or signing credentials.

The client rejects redirects, uses a 20-second request timeout, and bounds JSON
responses to 2 MiB each and 8 MiB in total. Job and ruleset pagination stops after
ten pages of at most 100 entries; contradictory or incomplete counts reject rather
than hiding later results. Expected job names and canonical IDs are deliberate policy constants;
changing the Quality matrix requires updating the gate and administrator policy
together.

Upstream contracts: [workflow jobs](https://docs.github.com/en/rest/actions/workflow-jobs#list-jobs-for-a-workflow-run-attempt),
[branch metadata](https://docs.github.com/en/rest/branches/branches#get-a-branch),
[ruleset visibility](https://docs.github.com/en/rest/repos/rules#get-a-repository-ruleset),
and [secure Actions use](https://docs.github.com/en/actions/reference/security/secure-use).
