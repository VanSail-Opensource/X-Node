#!/usr/bin/env python3
"""Extract exactly one version section from the cumulative release notes."""

import re
import sys
from pathlib import Path


def extract_notes(document: str, version: str) -> str:
    if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", version):
        raise ValueError("invalid release version")
    heading = f"# X-Node {version}"
    lines = document.splitlines(keepends=True)
    starts = [index for index, line in enumerate(lines) if line.rstrip("\r\n") == heading]
    if len(starts) != 1:
        raise ValueError("release notes must contain exactly one matching heading")
    start = starts[0]
    end = next((i for i in range(start + 1, len(lines)) if lines[i].startswith("# ")), len(lines))
    if not "".join(lines[start + 1:end]).strip():
        raise ValueError("release notes section is empty")
    return "".join(lines[start:end]).rstrip() + "\n"


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: release_notes.py vX.Y.Z", file=sys.stderr)
        return 2
    try:
        document = (Path(__file__).resolve().parent.parent / "docs" / "release-notes.md").read_text(encoding="utf-8")
        sys.stdout.write(extract_notes(document, sys.argv[1]))
    except (OSError, ValueError) as error:
        print(f"release notes: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
