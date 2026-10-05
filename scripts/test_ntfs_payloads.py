"""Independent payload gate regressions, including real bounded subprocess pipes."""

import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

spec = importlib.util.spec_from_file_location(
    "ntfs_payloads", Path(__file__).with_name("validate-ntfs-payloads.py"))
validator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validator)


def manifest(entries):
    return "".join(f"{path}\t{size}\t{digest}\n" for path, size, digest in entries)


class NtfsPayloadTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        for name in validator.FIXTURES:
            (self.root / name).write_bytes(b"regular fixture bytes")
        (self.root / validator.MANIFESTS[0]).write_bytes(manifest(validator.EDGE).encode("utf-8"))
        (self.root / validator.MANIFESTS[1]).write_bytes(manifest(validator.MISALIGNED).encode("utf-8"))
        # This mirrors only the exporter formula; expected digests come from the checker.
        self.streams = {
            "/readme.txt": (40, 14), "/alpha/Ωmega/fragmented.bin": (50, 6000),
            "/alpha/empty.dat": (60, 0), "/empty.zero": (40, 0),
            "/δelta/one.bin": (50, 1), "/δelta/sector-minus-one.bin": (60, 4095),
            "/δelta/sector.bin": (70, 4096), "/δelta/cluster-plus-one.bin": (80, 4097),
            "/δelta/深度/two-cluster-minus-one.bin": (90, 8191),
            "/δelta/深度/three-way-fragmented.bin": (100, 9000),
            "/" + "n" * 251 + ".bin": (110, 17),
            "/δelta/深度/rocket-🚀.bin": (120, 33), "/Straße.txt": (130, 65),
            "/relocated.bin": (140, 8192),
        }

    def reader(self, command):
        stream, size = self.streams[command[-1]]
        return 0, bytes((stream + i) % 251 for i in range(size)), b""

    def test_all_thirty_payloads_and_unicode_argv(self):
        calls = []

        def read(command):
            calls.append(command)
            return self.reader(command)

        report = validator.validate(self.root, "ntfscat", read)
        self.assertTrue(report["passed"], report["failures"])
        self.assertEqual(len(report["checks"]), 30)
        self.assertEqual(report["before_sha256"], report["after_sha256"])
        self.assertEqual(len(report["before_sha256"]), 8)
        self.assertIn("/δelta/深度/rocket-🚀.bin", [c[-1] for c in calls])
        self.assertTrue(all(len(c) == 3 and c[0] == "ntfscat" for c in calls))
        self.assertTrue(all(Path(c[1]).parent == self.root for c in calls))
        self.assertEqual(sum(check["expected_bytes"] == 0 for check in report["checks"]), 5)

    def test_corruption_truncation_and_trailing_bytes_fail(self):
        for mode in ("corrupt", "truncate", "extend"):
            with self.subTest(mode=mode):
                def read(command):
                    code, data, stderr = self.reader(command)
                    if command[-1] == "/readme.txt":
                        if mode == "corrupt":
                            data = bytes([data[0] ^ 1]) + data[1:]
                        elif mode == "truncate":
                            data = data[:-1]
                        else:
                            data += b"\x00"
                    return code, data, stderr

                report = validator.validate(self.root, "ntfscat", read)
                self.assertFalse(report["passed"])
                self.assertEqual(len(report["failures"]), 3)

    def test_empty_file_requires_successful_exit(self):
        def read(command):
            code, data, stderr = self.reader(command)
            return (7 if not data else code), data, stderr

        report = validator.validate(self.root, "ntfscat", read)
        self.assertFalse(report["passed"])
        self.assertEqual(len(report["failures"]), 5)

    def test_failed_tool_and_timeout_preserve_post_hashes(self):
        for failure in (OSError("missing reader"), subprocess.TimeoutExpired("ntfscat", 30)):
            def read(command):
                raise failure

            report = validator.validate(self.root, "ntfscat", read)
            self.assertFalse(report["passed"])
            self.assertEqual(len(report["checks"]), 30)
            self.assertEqual(report["before_sha256"], report["after_sha256"])

    def test_tool_failure_does_not_hide_image_mutation(self):
        def read(command):
            Path(command[1]).write_bytes(b"mutated by tool")
            return 1, b"", b"failure"

        report = validator.validate(self.root, "ntfscat", read)
        self.assertFalse(report["passed"])
        self.assertTrue(any("bytes changed" in item for item in report["failures"]))

    def test_malformed_manifest_prevents_every_reader(self):
        valid = manifest(validator.EDGE)
        malformed = [
            "", valid.rstrip("\n"), valid.replace("\n", "\r\n"),
            valid + valid.splitlines()[0] + "\n",
            valid.replace("/empty.zero", "/../empty.zero"),
            valid.replace("/empty.zero", "/δelta/one.bin"),
            valid.replace("\t0\t", "\t-1\t"),
            valid.replace("\t9000\t", "\t9001\t"),
            valid.replace("\t9000\t", "\t09000\t"),
            valid.replace(validator.EDGE[0][2], "not-a-hash"),
            valid.replace("/empty.zero", "/empty\x00.zero"),
            valid.replace("/empty.zero", "/empty\\zero"),
            "x" * (validator.MAX_MANIFEST + 1),
            valid.replace(validator.EDGE[0][2], "0" * 64),
        ]

        def read(command):
            self.fail("manifest rejection must precede ntfscat")

        path = self.root / validator.MANIFESTS[0]
        for data in malformed:
            with self.subTest(data=data[:60]):
                path.write_bytes(data.encode("utf-8"))
                report = validator.validate(self.root, "ntfscat", read)
                self.assertFalse(report["passed"])
                self.assertEqual(report["checks"], [])
                self.assertEqual(report["before_sha256"], report["after_sha256"])
        path.write_bytes(b"\xff\n")
        self.assertFalse(validator.validate(self.root, "ntfscat", read)["passed"])

    def test_nonregular_and_aliased_images_refused(self):
        path = self.root / validator.RICH_IMAGES[0]
        os.link(path, self.root / "alias")
        with self.assertRaises(ValueError):
            validator.validate(self.root, "ntfscat", self.reader)
        (self.root / "alias").unlink()
        path.unlink()
        path.mkdir()
        with self.assertRaises(ValueError):
            validator.validate(self.root, "ntfscat", self.reader)

    def test_report_creation_never_clobbers(self):
        path = self.root / "report.json"
        path.write_bytes(b"keep me")
        with self.assertRaises(FileExistsError):
            validator.write_report(path, {"passed": True})
        self.assertEqual(path.read_bytes(), b"keep me")

    def test_symbolic_link_image_is_refused(self):
        path = self.root / validator.RICH_IMAGES[0]
        target = self.root / "link-target"
        path.rename(target)
        try:
            path.symlink_to(target)
        except OSError as error:
            self.skipTest(f"symbolic links unavailable: {error}")
        with self.assertRaises(ValueError):
            validator.validate(self.root, "ntfscat", self.reader)

    def test_real_binary_stdout_is_preserved(self):
        code, output, stderr = validator.read_payload([
            sys.executable, "-c", "import sys; sys.stdout.buffer.write(bytes(range(256)))"])
        self.assertEqual(code, 0)
        self.assertEqual(output, bytes(range(256)))
        self.assertEqual(stderr, b"")

    def test_real_empty_stdout_failed_exit(self):
        code, output, _ = validator.read_payload([sys.executable, "-c", "raise SystemExit(9)"])
        self.assertEqual((code, output), (9, b""))

    def test_real_unicode_argv_and_binary_stdout(self):
        argument = "/δelta/深度/rocket-🚀.bin"
        code, output, _ = validator.read_payload([sys.executable, "-c",
            "import sys; sys.stdout.buffer.write(sys.argv[1].encode('utf-8'))", argument])
        self.assertEqual(code, 0)
        self.assertEqual(output, argument.encode("utf-8"))

    def test_real_stdout_and_stderr_overflow_are_bounded(self):
        for pipe, limit in (("stdout", 9000), ("stderr", 4096)):
            with self.subTest(pipe=pipe), self.assertRaises(ValueError):
                validator.read_payload([sys.executable, "-c",
                    f"import sys; sys.{pipe}.buffer.write(b'x' * {limit * 100})"])

    def test_real_hung_tool_is_killed(self):
        with self.assertRaises(subprocess.TimeoutExpired):
            validator.read_payload([sys.executable, "-c", "import time; time.sleep(60)"], timeout=0.2)


if __name__ == "__main__":
    unittest.main()
