"""Fail-closed independent large-directory namespace evidence tests."""

import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

spec = importlib.util.spec_from_file_location(
    "large_directory", Path(__file__).with_name("validate-large-directory.py"))
validator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validator)


class LargeDirectoryTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        for name in validator.FIXTURES:
            (self.root / name).write_bytes(b"image fixture")
        (self.root / validator.MANIFEST).write_bytes(validator.EXPECTED_MANIFEST)
        self.programs = {name: name for name in ("fsck.exfat", "ntfsinfo", "ntfsfix", "ntfsls", "ntfscat")}

    def reader(self, command, stdout_limit):
        if command[0] == "ntfsls":
            return 0, ("\n".join((".",) + tuple(reversed(validator.NAMES))) + "\n").encode("utf-8"), b""
        return 0, b"", b""

    def test_exact_directory_and_all_empty_payloads(self):
        calls = []

        def read(command, stdout_limit):
            calls.append((command, stdout_limit))
            return self.reader(command, stdout_limit)

        report = validator.validate(self.root, self.programs, read)
        self.assertTrue(report["passed"], report["failures"])
        self.assertEqual(len(report["checks"]), 132)
        self.assertEqual(report["before_sha256"], report["after_sha256"])
        self.assertEqual(len(report["before_sha256"]), 4)
        self.assertEqual(sum(limit == 0 for _, limit in calls), 128)
        self.assertEqual(calls[3][0], ["ntfsls", "-a", "-p", "/alpha", str(self.root / validator.TARGET)])
        self.assertTrue(all(command[-1].startswith("/alpha/") for command, _ in calls[4:]))

    def test_missing_duplicate_foreign_and_corrupt_listing_fail(self):
        for ordinal in (0, 64, 127):
            names = (".",) + tuple(name for i, name in enumerate(validator.NAMES) if i != ordinal)
            self.assert_listing_fails(("\n".join(names) + "\n").encode("utf-8"))
        valid = ("\n".join((".",) + validator.NAMES) + "\n").encode("utf-8")
        for extra in (b"foreign.bin\n", validator.NAMES[0].encode("utf-8") + b"\n", b".\n", b"\xff\n"):
            self.assert_listing_fails(valid + extra)
        self.assert_listing_fails(valid, code=5)

    def assert_listing_fails(self, output, code=0):
        def read(command, stdout_limit):
            return (code, output, b"") if command[0] == "ntfsls" else self.reader(command, stdout_limit)
        report = validator.validate(self.root, self.programs, read)
        self.assertFalse(report["passed"])
        self.assertFalse(report["checks"][3]["passed"])

    def test_missing_first_middle_last_payload_fails_despite_empty_output(self):
        for ordinal in (0, 64, 127):
            def read(command, stdout_limit):
                if command[-1] == "/alpha/" + validator.NAMES[ordinal]:
                    return 1, b"", b"not found"
                return self.reader(command, stdout_limit)
            report = validator.validate(self.root, self.programs, read)
            self.assertFalse(report["passed"])
            self.assertEqual(len(report["failures"]), 1)

    def test_nonempty_payload_and_timeout_fail(self):
        for value in (b"\x00", subprocess.TimeoutExpired("ntfscat", 30)):
            def read(command, stdout_limit):
                if command[0] == "ntfscat":
                    if isinstance(value, bytes):
                        return 0, value, b""
                    raise value
                return self.reader(command, stdout_limit)
            report = validator.validate(self.root, self.programs, read)
            self.assertFalse(report["passed"])
            self.assertEqual(report["before_sha256"], report["after_sha256"])

    def test_bad_manifest_prevents_all_tools(self):
        def read(*args, **kwargs):
            self.fail("bad manifest must prevent tools")
        valid = validator.EXPECTED_MANIFEST
        for data in (valid[:-1], valid.replace(b"entry-000", b"entry-001"), b"x" * 65537,
                     valid.replace(b"\t0\t", b"\t1\t"), valid + valid.splitlines()[0] + b"\n"):
            (self.root / validator.MANIFEST).write_bytes(data)
            report = validator.validate(self.root, self.programs, read)
            self.assertFalse(report["passed"])
            self.assertEqual(report["checks"], [])

    def test_failed_tool_cannot_hide_mutation(self):
        def read(command, stdout_limit):
            (self.root / validator.TARGET).write_bytes(b"mutated")
            raise OSError("reader failed")
        report = validator.validate(self.root, self.programs, read)
        self.assertFalse(report["passed"])
        self.assertTrue(any("bytes changed" in error for error in report["failures"]))

    def test_generalized_binary_reader_enforces_zero_and_large_caps(self):
        read = validator.helpers.read_payload
        with self.assertRaises(ValueError):
            read([sys.executable, "-c", "print('x')"], stdout_limit=0)
        code, output, _ = read([sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'x' * 20000)"],
                               stdout_limit=32768)
        self.assertEqual((code, len(output)), (0, 20000))
        for cap in (-1, 131073, "bad"):
            with self.assertRaises(ValueError):
                read(["must-not-launch"], stdout_limit=cap)


if __name__ == "__main__":
    unittest.main()
