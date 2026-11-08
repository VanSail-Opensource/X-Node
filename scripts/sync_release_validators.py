#!/usr/bin/env python3
"""Keep isolated release-job validators equal to their reviewed canonical source."""

import argparse
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
VALIDATORS = {"PROVENANCE": "release_provenance.py", "BUNDLE": "release_bundle.py"}


def synchronize(workflow):
    for name, filename in VALIDATORS.items():
        marker = "PY_RELEASE_" + name
        expression = re.compile(r"^([ ]+)[^\n]*<<'" + marker
                                + r"'[^\n]*\n(.*?)^\1" + marker + r"[ ]*$", re.M | re.S)
        matches = list(expression.finditer(workflow))
        if len(matches) != 1:
            raise ValueError("expected one isolated " + name.lower() + " validator")
        match = matches[0]
        source = (ROOT / "scripts" / filename).read_text(encoding="utf-8")
        if not source.endswith("\n"):
            raise ValueError("canonical source must end with a newline")
        body = "".join(match[1] + line if line.strip() else line
                       for line in source.splitlines(keepends=True))
        workflow = workflow[:match.start(2)] + body + workflow[match.end(2):]
    return workflow


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="check source consistency without writing")
    args = parser.parse_args()
    path = ROOT / ".github" / "workflows" / "release.yml"
    original = path.read_text(encoding="utf-8")
    try:
        updated = synchronize(original)
    except ValueError as error:
        parser.exit(1, str(error) + "\n")
    if args.check and original != updated:
        parser.exit(1, "release workflow validators differ from canonical source\n")
    if not args.check and original != updated:
        path.write_text(updated, encoding="utf-8", newline="\n")


if __name__ == "__main__":
    main()
