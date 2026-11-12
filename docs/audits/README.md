# Repository audit records

This directory keeps completed audit findings and reproducible file coverage alongside the code they describe.

| Record | Contents |
| --- | --- |
| [2026-11-12 report](2026-11-12-report.md) | Whole-repository scope, XN-01–29 findings, fixes, validation and retained architecture/governance boundaries. |
| [2026-11-12 coverage](2026-11-12-coverage.json) | Every path at the original and reviewed snapshots, exact Git blob identities, change classification and review method. |

A coverage record names an immutable reviewed code commit. Later audit artifacts are outside that snapshot to avoid self-referential hashing. Code changes after a named snapshot require another review entry; CI results apply only to their exact commit.

Generated contracts are verified from reviewed generators and dependency locks by integrity checks. These methods are distinguished from full source reads. Historical compatibility and financial evidence are retained even when old execution paths are removed.
