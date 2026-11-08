# Release bundle validation

`scripts/release_bundle.py` validates release artifacts using only the Python
standard library and the host's installed Minisign utility. It never imports,
extracts or executes an artifact, installer or downloaded executable.

The unsigned input directory must contain exactly `SHA256SUMS` and these six
payloads: `x-node-linux-amd64`, `x-node-linux-arm64`, `xnodectl-linux-amd64`,
`xnodectl-linux-arm64`, `install.sh` and `x-node-api-docs.zip`. Signed validation
additionally requires `SHA256SUMS.minisig`. Every entry must be a nonempty regular
file; symbolic links, directories, unexpected names and missing assets fail.
Payloads are bounded to 2 GiB each, the documentation archive to 128 MiB, and
the manifest and signature to 4 KiB each. Hashing streams files in 1 MiB chunks.

The manifest must contain each payload exactly once, using lowercase SHA-256,
two spaces and its exact basename. The validator rejects absolute paths,
traversal, duplicate entries, unknown entries, malformed hashes and hash
mismatches. All four binaries must have little-endian ELF64 executable or
position-independent executable headers with the correct amd64 or arm64 machine
identifier. This establishes the declared
architecture, not executable behavior or absence of malicious code.

```sh
python3 scripts/release_bundle.py dist --version v2.0.20
python3 scripts/release_bundle.py dist --version v2.0.20 --signed
```

Signed mode runs `minisign -V -H` with the production public key pinned in the
validator, then requires the authenticated comment to equal
`version:v2.0.20` exactly. There is no command-line trust-key override. The key
must match `internal/update/release.pub`; trusted key rotation changes both
sources together. A valid signature for another release or key fails.

The Python entry point is `validate_bundle(directory, version, signed=False)`;
validation errors raise `BundleError`, and filesystem failures remain `OSError`.
The CLI returns nonzero for either. Signature validation has a 30-second bound.
No network access is performed.

The isolated release jobs embed the canonical validator in a
`PY_RELEASE_BUNDLE` heredoc instead of executing source from a release tag.
Hosted tests compare that embedded copy byte-for-byte with the canonical source.
Changes therefore require updating the trusted workflow copy in the same commit.
Structural checks complement the workflow's protected-main provenance and exact
Quality-run admission checks; they do not replace those controls.

Hosted regression entry point:
`python3 -m unittest discover -s scripts -p test_release_bundle.py`.
The mandatory hosted Go regressions in `cmd/release-sign/compatibility_test.go`
verify Go-format private key and signature interoperability with the installed
Minisign utility in both directions. Disposable fixtures never alter the
production trust key or access a signing secret.
