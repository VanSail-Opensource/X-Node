# Repository tooling

`release_provenance.py` reads bounded GitHub metadata and verifies the exact
canonical Quality run, protected-main ancestry and immutable tag policy.
`release_bundle.py` validates complete release file sets, streamed hashes, both
ELF architectures and pinned-key/version signatures. Neither executes payloads.
Their pure functions accept constructed data for hosted negative regressions.

The signing and publishing jobs run reviewed copies embedded in the main-branch
workflow, independently of the tag's checkout. After editing either canonical
validator, run `python scripts/sync_release_validators.py` to update those copies.
Its `--check` option is a static source-consistency check run early in Quality.
YAML anchors share each copy across isolated jobs. This intentional embedding
keeps tag-supplied executable code away from signing credentials; the workflow's
length reflects its self-contained security boundary.

See [release provenance](../docs/release-provenance.md),
[bundle validation](../docs/release-bundle.md) and
[repository policy](../docs/repository-protection.md) for APIs, resource bounds,
permissions and the administrator preflight. `test_release_*.py` run in hosted
Quality after installing the pinned `requirements.txt` schema dependencies.
The hosted Go signing compatibility regression uses only disposable keys.

`release_notes.py` selects the exact version section. `update_xray.py` resolves
reviewed stable upstream tags to immutable commits for a dependency pull request;
it must not replace intentional pseudo-versions with older proxy `latest` tags.
`check_schema.py` checks generated API contracts, and `build_docs.py` builds their
static documentation. Existing Linux/VM scripts own disposable host integration
checks. Local automated suites remain prohibited by the implementation plan.
