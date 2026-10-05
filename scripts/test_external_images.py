"""Hostile-input and mutation regressions for the independent validation harness."""

import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

spec = importlib.util.spec_from_file_location(
    "external_images", Path(__file__).with_name("validate-external-images.py")
)
validator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validator)


class ExternalImageTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        for name in validator.FIXTURES:
            (self.root / name).write_bytes(b"fixture bytes")
        self.programs = {name: name for name in ("fsck.exfat", "ntfsinfo", "ntfsls", "ntfsfix")}

    def test_commands_are_unmounted_and_read_only(self):
        calls = []

        def run(command, **kwargs):
            calls.append(command)
            return subprocess.CompletedProcess(command, 0, "clean", "")

        report = validator.validate(self.root, self.programs, run)
        self.assertTrue(report["passed"])
        self.assertEqual(len(calls), 31)
        self.assertEqual(len(report["before_sha256"]), 29)
        self.assertEqual(report["before_sha256"], report["after_sha256"])
        for command in calls:
            self.assertEqual(Path(command[-1]).parent, self.root)
            if command[0] in ("fsck.exfat", "ntfsfix"):
                self.assertEqual(command[1], "-n")

    def test_tool_failure_still_detects_mutation(self):
        def run(command, **kwargs):
            if command[0] == "fsck.exfat":
                Path(command[-1]).write_bytes(b"changed bytes")
            return subprocess.CompletedProcess(command, 1, "", "injected failure")

        report = validator.validate(self.root, self.programs, run)
        self.assertFalse(report["passed"])
        self.assertTrue(any("bytes changed" in error for error in report["failures"]))
        self.assertTrue(any("validator failed" in error for error in report["failures"]))

    def test_missing_or_nonregular_fixture_prevents_all_tools(self):
        path = self.root / validator.FIXTURES[0]
        path.unlink()
        path.mkdir()

        def run(*args, **kwargs):
            self.fail("invalid corpus must be refused before external I/O")

        with self.assertRaises(ValueError):
            validator.validate(self.root, self.programs, run)

    def test_timeout_is_failed_evidence_with_post_hashes(self):
        def run(command, **kwargs):
            raise subprocess.TimeoutExpired(command, 120)

        report = validator.validate(self.root, self.programs, run)
        self.assertFalse(report["passed"])
        self.assertEqual(report["before_sha256"], report["after_sha256"])

    def test_hard_link_fixture_is_refused(self):
        path = self.root / validator.FIXTURES[0]
        os.link(path, self.root / "alias")
        with self.assertRaises(ValueError):
            validator.snapshot(self.root)

    def test_symbolic_link_fixture_is_refused(self):
        path = self.root / validator.FIXTURES[0]
        source = self.root / "link-source"
        path.rename(source)
        try:
            path.symlink_to(source)
        except OSError as error:
            self.skipTest(f"symbolic links unavailable on this host: {error}")
        with self.assertRaises(ValueError):
            validator.snapshot(self.root)


if __name__ == "__main__":
    unittest.main()
