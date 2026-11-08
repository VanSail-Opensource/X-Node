#!/usr/bin/env python3
"""Validate release assets without importing or executing their contents."""

import argparse
from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import re
import stat
import struct
import subprocess

PUBLIC_KEY = "RWQ6HaDFAVc2u+yR4zuGuTn+wHojhxW7s7DxO1W22yj5r5yYwZgPt3qL"
MACHINES = {
    "x-node-linux-amd64": 62,
    "x-node-linux-arm64": 183,
    "xnodectl-linux-amd64": 62,
    "xnodectl-linux-arm64": 183,
}
PAYLOADS = frozenset((*MACHINES, "install.sh", "x-node-api-docs.zip"))
MANIFEST = "SHA256SUMS"
SIGNATURE = "SHA256SUMS.minisig"
MAX_PAYLOAD = 2 << 30
MAX_DOCS = 128 << 20
MAX_MANIFEST = 4096
MAX_SIGNATURE = 4096
STABLE_VERSION = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+", re.ASCII)


class BundleError(ValueError):
    """A release bundle failed a structural or cryptographic check."""


def _identity(info):
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns


@contextmanager
def _regular_file(path, limit):
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= limit:
        raise BundleError(f"invalid file type or size: {path.name}")
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        if _identity(before) != _identity(opened):
            raise BundleError(f"file changed while opening: {path.name}")
        yield stream
        if (_identity(opened) != _identity(os.fstat(stream.fileno()))
                or _identity(opened) != _identity(path.lstat())):
            raise BundleError(f"file changed during validation: {path.name}")


def _small_file(path, limit):
    with _regular_file(path, limit) as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise BundleError(f"file exceeds limit: {path.name}")
    return data


def _manifest_entries(raw):
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeDecodeError as error:
        raise BundleError("manifest is not ASCII") from error
    entries = {}
    for line in lines:
        match = re.fullmatch(r"([0-9a-f]{64})  ([a-zA-Z0-9.-]+)", line)
        if not match:
            raise BundleError("invalid manifest entry")
        digest, name = match.groups()
        if name not in PAYLOADS or name in entries:
            raise BundleError("unexpected or duplicate manifest entry")
        entries[name] = digest
    if entries.keys() != PAYLOADS:
        raise BundleError("manifest must list exactly six release payloads")
    return entries


def _payload_digest(path):
    limit = MAX_DOCS if path.name == "x-node-api-docs.zip" else MAX_PAYLOAD
    digest = hashlib.sha256()
    with _regular_file(path, limit) as stream:
        header = stream.read(64)
        if path.name in MACHINES:
            if (len(header) != 64 or header[:7] != b"\x7fELF\x02\x01\x01"
                    or struct.unpack_from("<H", header, 16)[0] not in (2, 3)
                    or struct.unpack_from("<H", header, 18)[0] != MACHINES[path.name]
                    or struct.unpack_from("<I", header, 20)[0] != 1
                    or struct.unpack_from("<H", header, 52)[0] != 64):
                raise BundleError(f"invalid ELF64 architecture: {path.name}")
        digest.update(header)
        total = len(header)
        while chunk := stream.read(1 << 20):
            total += len(chunk)
            if total > limit:
                raise BundleError(f"file exceeds limit: {path.name}")
            digest.update(chunk)
    return digest.hexdigest()


def _verify_signature(directory, version):
    raw = _small_file(directory / SIGNATURE, MAX_SIGNATURE)
    try:
        result = subprocess.run(
            ["minisign", "-V", "-H", "-P", PUBLIC_KEY,
             "-m", str(directory / MANIFEST), "-x", str(directory / SIGNATURE)],
            capture_output=True, check=False, timeout=30,
            env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise BundleError("minisign verification could not run") from error
    if result.returncode:
        raise BundleError("release signature verification failed")
    if raw != _small_file(directory / SIGNATURE, MAX_SIGNATURE):
        raise BundleError("signature changed during verification")
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeDecodeError as error:
        raise BundleError("signature is not ASCII") from error
    if len(lines) != 4 or lines[2] != "trusted comment: version:" + version:
        raise BundleError("signed release version differs")


def validate_bundle(directory: Path, version: str, signed: bool = False) -> None:
    """Require a complete, bounded, architecture-correct release bundle."""
    if not STABLE_VERSION.fullmatch(version):
        raise BundleError("expected a stable vMAJOR.MINOR.PATCH version")
    directory = Path(directory).absolute()
    if not stat.S_ISDIR(directory.lstat().st_mode):
        raise BundleError("bundle must be a regular directory")
    expected = PAYLOADS | {MANIFEST} | ({SIGNATURE} if signed else set())
    if {entry.name for entry in directory.iterdir()} != expected:
        raise BundleError("bundle contains missing or unexpected files")
    raw = _small_file(directory / MANIFEST, MAX_MANIFEST)
    entries = _manifest_entries(raw)
    if signed:
        _verify_signature(directory, version)
        if raw != _small_file(directory / MANIFEST, MAX_MANIFEST):
            raise BundleError("manifest changed during signature verification")
    for name, digest in entries.items():
        if _payload_digest(directory / name) != digest:
            raise BundleError(f"SHA-256 mismatch: {name}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--version", required=True)
    parser.add_argument("--signed", action="store_true")
    args = parser.parse_args()
    try:
        validate_bundle(args.directory, args.version, args.signed)
    except (BundleError, OSError) as error:
        parser.exit(1, f"release bundle rejected: {error}\n")
    print(f"Verified {'signed' if args.signed else 'unsigned'} release bundle {args.version}")


if __name__ == "__main__":
    main()
