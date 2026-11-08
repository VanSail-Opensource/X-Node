import hashlib
from pathlib import Path
import re
import struct
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import release_bundle as bundle

REPOSITORY = Path(__file__).resolve().parents[1]
VERSION = "v2.0.20"


def elf(machine):
    data = bytearray(64)
    data[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<H", data, 16, 2)
    struct.pack_into("<H", data, 18, machine)
    struct.pack_into("<I", data, 20, 1)
    struct.pack_into("<H", data, 52, 64)
    return bytes(data)


class ReleaseBundleTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.temporary = Path(temporary.name)
        self.directory = self.temporary / "bundle"
        self.directory.mkdir()
        for name, machine in bundle.MACHINES.items():
            (self.directory / name).write_bytes(elf(machine))
        (self.directory / "install.sh").write_bytes(b"#!/bin/sh\nexit 127\n")
        (self.directory / "x-node-api-docs.zip").write_bytes(b"PK\x05\x06" + bytes(18))
        self.manifest()

    def manifest(self, lines=None):
        if lines is None:
            lines = [hashlib.sha256((self.directory / name).read_bytes()).hexdigest()
                     + "  " + name for name in sorted(bundle.PAYLOADS)]
        (self.directory / bundle.MANIFEST).write_text("\n".join(lines) + "\n", encoding="ascii")

    def signature(self, version=VERSION):
        (self.directory / bundle.SIGNATURE).write_text(
            "untrusted comment: fixture\nAAAA\ntrusted comment: version:" + version
            + "\nAAAA\n", encoding="ascii")

    def reject(self, signed=False, version=VERSION):
        with self.assertRaises((bundle.BundleError, OSError)):
            bundle.validate_bundle(self.directory, version, signed)

    def test_unsigned_checks_all_four_binaries_without_executing_payloads(self):
        with mock.patch.object(bundle.subprocess, "run") as process:
            bundle.validate_bundle(self.directory, VERSION)
            for name, machine in bundle.MACHINES.items():
                data = bytearray(elf(machine))
                struct.pack_into("<H", data, 16, 3)
                (self.directory / name).write_bytes(data)
            self.manifest()
            bundle.validate_bundle(self.directory, VERSION)
        process.assert_not_called()

    def test_exact_file_set_rejects_missing_extra_nested_and_signed_assets(self):
        path = self.directory / "extra"
        for directory in (False, True):
            path.mkdir() if directory else path.write_bytes(b"extra")
            self.reject()
            path.rmdir() if directory else path.unlink()
        self.signature()
        self.reject()
        (self.directory / bundle.SIGNATURE).unlink()
        (self.directory / "install.sh").unlink()
        self.reject()

    def test_manifest_rejects_duplicate_missing_extra_and_unsafe_paths(self):
        lines = (self.directory / bundle.MANIFEST).read_text().splitlines()
        for invalid in (lines + [lines[0]], lines[:-1], [], lines + ["0" * 64 + "  extra"],
                        [lines[0].replace("  ", " *", 1)] + lines[1:],
                        ["0" * 64 + "  " + name for name in ("../install.sh", "/tmp/x", "a\\b")]):
            with self.subTest(lines=invalid):
                self.manifest(invalid)
                self.reject()

    def test_manifest_rejects_invalid_hex_and_non_ascii(self):
        path = self.directory / bundle.MANIFEST
        original = path.read_bytes()
        for raw in (b"z" + original[1:], original + b"\xff", original + b"\n"):
            path.write_bytes(raw)
            self.reject()

    def test_hash_mismatch(self):
        (self.directory / "install.sh").write_bytes(b"changed")
        self.reject()

    def test_each_architecture_and_elf_format_are_enforced_after_rehashing(self):
        for name, machine in bundle.MACHINES.items():
            for offset, value in ((16, 0), (18, 183 if machine == 62 else 62), (4, 1), (5, 2), (6, 0), (52, 0)):
                with self.subTest(name=name, offset=offset):
                    data = bytearray(elf(machine))
                    data[offset] = value
                    (self.directory / name).write_bytes(data)
                    self.manifest()
                    self.reject()
                    (self.directory / name).write_bytes(elf(machine))

    def test_regular_nonempty_files_and_all_size_bounds(self):
        for constant, limit in (("MAX_PAYLOAD", 63), ("MAX_DOCS", 21), ("MAX_MANIFEST", 10)):
            with mock.patch.object(bundle, constant, limit):
                self.reject()
        path = self.directory / "install.sh"
        path.write_bytes(b"")
        self.reject()
        path.unlink()
        path.mkdir()
        self.reject()

    def test_symlink_files_and_directory_are_rejected(self):
        path = self.directory / "install.sh"
        target = self.temporary / "installer"
        path.replace(target)
        try:
            path.symlink_to(target)
        except OSError as error:
            self.skipTest(f"symlinks unavailable: {error}")
        self.reject()
        alias = self.temporary / "alias"
        alias.symlink_to(self.directory, target_is_directory=True)
        with self.assertRaises(bundle.BundleError):
            bundle.validate_bundle(alias, VERSION)

    def test_signed_mode_pins_key_requires_hashed_signature_and_checks_version(self):
        self.signature()
        with mock.patch.object(bundle.subprocess, "run", return_value=SimpleNamespace(returncode=0)) as process:
            bundle.validate_bundle(self.directory, VERSION, True)
            arguments = process.call_args.args[0]
            self.assertEqual(arguments[:5], ["minisign", "-V", "-H", "-P", bundle.PUBLIC_KEY])
            self.assertEqual(process.call_args.kwargs["timeout"], 30)
            self.assertEqual(process.call_args.kwargs["env"],
                             {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"})
            self.signature("v2.0.19")
            self.reject(True)

    def test_signature_failures_missing_signature_timeout_and_size_fail_closed(self):
        self.reject(True)
        self.signature()
        with mock.patch.object(bundle.subprocess, "run", return_value=SimpleNamespace(returncode=1)):
            self.reject(True)
        with mock.patch.object(bundle.subprocess, "run", side_effect=subprocess.TimeoutExpired("minisign", 30)):
            self.reject(True)
        with mock.patch.object(bundle, "MAX_SIGNATURE", 5):
            self.reject(True)
        for version in ("v2.0.20-rc1", "2.0.20", "v2.0.20\n"):
            self.reject(version=version)

    def test_signature_mutation_cannot_change_verified_version(self):
        self.signature()
        def mutate(*args, **kwargs):
            self.signature("v2.0.19")
            return SimpleNamespace(returncode=0)
        with mock.patch.object(bundle.subprocess, "run", side_effect=mutate):
            self.reject(True)

    def test_embedded_validator_and_agent_trust_key_match_canonical_source(self):
        workflow = (REPOSITORY / ".github/workflows/release.yml").read_text()
        matches = list(re.finditer(r"^([ ]+)[^\n]*<<'PY_RELEASE_BUNDLE'[^\n]*\n(.*?)^\1PY_RELEASE_BUNDLE[ ]*$", workflow, re.M | re.S))
        self.assertEqual(len(matches), 1, "release workflow must embed exactly one canonical validator")
        indent, body = matches[0].groups()
        embedded = "".join(line[len(indent):] if line.startswith(indent) else line
                           for line in body.splitlines(keepends=True))
        self.assertEqual(embedded, (REPOSITORY / "scripts/release_bundle.py").read_text())
        self.assertEqual(bundle.PUBLIC_KEY, (REPOSITORY / "internal/update/release.pub").read_text().splitlines()[-1])


if __name__ == "__main__":
    unittest.main()
