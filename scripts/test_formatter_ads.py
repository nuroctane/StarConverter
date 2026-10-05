"""Hostile-path, storage and binary-content regression tests for formatter ADS evidence."""

import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

spec = importlib.util.spec_from_file_location(
    "formatter_ads", Path(__file__).with_name("validate-formatter-ads.py"))
validator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validator)


def storage_dump():
    return "".join(
        "Dumping attribute $DATA (0x80) from mft record 64 (0x40)\n"
        f"\tResident:\t {'Yes' if resident else 'No'}\n"
        f"\tName length:\t {len(name)} (0x{len(name):x})\n"
        + (f"\tAttribute name:\t '{name}'\n" if name else "")
        + f"\tData size:\t {size} (0x{size:x})\n"
        for name, size, _, resident in validator.STREAMS).encode("utf-8")


class FormatterAdsTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.workspace = Path(directory.name).resolve()
        self.programs = {name: name for name in validator.TOOLS}
        self.calls = []

    def runner(self, command, **kwargs):
        self.calls.append(command)
        self.assertGreater(kwargs["timeout"], 0)
        self.assertLessEqual(kwargs["stdout_limit"], 128 * 1024)
        if command[1] in ("-V", "--version"):
            return 0, b"tool 1.0\n", b""
        if command[0] == "ntfsinfo" and "-F" in command:
            return 0, storage_dump(), b""
        if command[0] == "ntfscat":
            name = command[2] if command[1] == "-n" else ""
            item = next(item for item in validator.STREAMS if item[0] == name)
            return 0, validator.payload(item[2], item[1]), b""
        if command[0] == "cli" and command[1] == "convert-image":
            with Path(command[3]).open("xb") as stream:
                stream.truncate(validator.IMAGE_BYTES)
            if "--escrow" in command:
                Path(command[-1]).write_bytes(b"escrow")
        return 0, b"checked\n", b""

    def validate(self, run=None):
        return validator.validate(self.workspace, "cli", self.programs, run or self.runner)

    def test_success_checks_storage_six_payloads_and_unchanged_sources(self):
        report = self.validate()
        self.assertTrue(report["passed"], report["failures"])
        self.assertEqual(len(report["payloads"]), 6)
        self.assertEqual(report["before_sha256"], report["after_sha256"])
        self.assertEqual(set(report["versions"]), set(validator.TOOLS) | {"starconverter"})
        self.assertEqual(set(report["storage"]), {"source", "restored"})
        case = Path(report["case_directory"])
        self.assertEqual(case.parent, self.workspace)
        self.assertTrue(case.is_dir())  # Artifacts remain available after completion.
        formatter = next(c for c in self.calls if c[0] == "mkntfs" and c[1] != "-V")
        self.assertEqual(formatter[1:-1], ["-F", "-Q", "-s", "512", "-c", "4096",
                                          "-p", "0", "-L", "SCADS"])
        self.assertNotIn("-T", formatter)
        self.assertEqual(len([c for c in self.calls if c[0] == "ntfscp" and c[1] != "-V"]), 3)
        exfat_checks = [c for c in self.calls if c[0] == "fsck.exfat"]
        self.assertEqual(len(exfat_checks), 1)
        self.assertEqual(exfat_checks[0], ["fsck.exfat", "-n", str(case / "exfat.img")])

    def test_no_tool_runs_for_unapproved_workspace(self):
        def run(*args, **kwargs):
            self.fail("no tool may run before workspace approval")

        with self.assertRaises(OSError):
            validator.validate(self.workspace / "missing", "cli", self.programs, run)
        path = self.workspace / "file"
        path.write_bytes(b"not a directory")
        with self.assertRaises(ValueError):
            validator.validate(path, "cli", self.programs, run)

    def test_symlink_workspace_is_refused_before_tools(self):
        path = self.workspace / "alias"
        try:
            path.symlink_to(self.workspace, target_is_directory=True)
        except OSError as error:
            self.skipTest(str(error))
        with self.assertRaises(ValueError):
            validator.validate(path, "cli", self.programs,
                               lambda *args, **kwargs: self.fail("unapproved path"))

    def test_formatter_length_change_prevents_population(self):
        def run(command, **kwargs):
            if command[0] == "mkntfs" and command[1] != "-V":
                Path(command[-1]).write_bytes(b"shortened")
            if command[0] == "ntfscp" and command[1] != "-V":
                self.fail("modified image must be rejected before population")
            return self.runner(command, **kwargs)

        report = self.validate(run)
        self.assertFalse(report["passed"])
        self.assertIn("unaliased regular fixture", report["failures"][0])

    def test_populator_hardlink_change_prevents_next_population(self):
        populated = 0

        def run(command, **kwargs):
            nonlocal populated
            if command[0] == "ntfscp" and command[1] != "-V":
                populated += 1
                self.assertEqual(populated, 1)
                path = Path(command[-3])
                os.link(path, path.parent / "alias.img")
            return self.runner(command, **kwargs)

        report = self.validate(run)
        self.assertFalse(report["passed"])
        self.assertEqual(populated, 1)

    def test_binary_corruption_and_failed_exit_fail_exact_step(self):
        for mode in ("corrupt", "exit"):
            def run(command, **kwargs):
                code, output, error = self.runner(command, **kwargs)
                if command[0] == "ntfscat" and command[1] == "-n":
                    if mode == "corrupt":
                        output = b"\xff" + output[1:]
                    else:
                        code = 5
                return code, output, error

            report = self.validate(run)
            self.assertFalse(report["passed"])
            self.assertIn("source-payload-sc-small", report["failures"][0])
            self.assertEqual(report["before_sha256"], report["after_sha256"])

    def test_storage_parser_rejects_missing_duplicate_and_wrong_storage(self):
        good = storage_dump()
        self.assertEqual(set(validator.parse_storage(good)), {"", "sc-small", "sc-large"})
        for bad in (b"", good + good, good.replace(b"Resident:\t No", b"Resident:\t Yes"),
                    good.replace(b"Data size:\t 8193", b"Data size:\t 8192"),
                    good.replace(b"8193 (0x2001)", b"8193 (0x2000)"),
                    good.replace(b"Name length:\t 8", b"Name length:\t 0"), b"\xff"):
            with self.subTest(bad=bad[:60]), self.assertRaises(ValueError):
                validator.parse_storage(bad)

    def test_storage_failure_cannot_pass_pipeline(self):
        def run(command, **kwargs):
            if command[0] == "ntfsinfo" and "-F" in command:
                return 0, b"unexpected storage output", b""
            return self.runner(command, **kwargs)

        report = self.validate(run)
        self.assertFalse(report["passed"])
        self.assertIn("source-storage", report["failures"][0])

    def test_restored_storage_forms_are_recorded_without_forcing_source_layout(self):
        def run(command, **kwargs):
            if command[0] == "ntfsinfo" and "-F" in command and command[-1].endswith("restored.img"):
                return 0, storage_dump().replace(b"Resident:\t Yes", b"Resident:\t No"), b""
            return self.runner(command, **kwargs)

        report = self.validate(run)
        self.assertTrue(report["passed"], report["failures"])
        self.assertFalse(report["storage"]["restored"]["sc-small"]["resident"])
        self.assertTrue(report["storage"]["source"]["sc-small"]["resident"])
        with self.assertRaises(ValueError):
            validator.parse_storage(storage_dump().replace(b"8193 (0x2001)", b"8192 (0x2000)"),
                                    require_source_forms=False)

    def test_manifest_mismatch_prevents_population(self):
        def run(command, **kwargs):
            if command[0] == "mkntfs" and command[1] != "-V":
                (Path(command[-1]).parent / "streams.tsv").write_bytes(b"forged manifest")
            if command[0] == "ntfscp" and command[1] != "-V":
                self.fail("forged manifest cannot authorize population")
            return self.runner(command, **kwargs)

        report = self.validate(run)
        self.assertFalse(report["passed"])
        self.assertIn("manifest differs", report["failures"][0])

    def test_conversion_failure_keeps_artifacts_and_hashes(self):
        def run(command, **kwargs):
            if command[0] == "cli" and command[1] == "convert-image":
                return 2, b"", b"unsupported source attribute"
            return self.runner(command, **kwargs)

        report = self.validate(run)
        self.assertFalse(report["passed"])
        self.assertIn("convert-to-exfat", report["failures"][0])
        self.assertIn("unsupported source attribute", report["failures"][0])
        self.assertEqual(report["before_sha256"], report["after_sha256"])
        self.assertTrue((Path(report["case_directory"]) / "source.img").exists())

    def test_failure_does_not_hide_mutation(self):
        def run(command, **kwargs):
            if command[0] == "cli" and command[1] == "convert-image":
                with Path(command[2]).open("r+b") as stream:
                    stream.write(b"unexpected mutation")
                return 2, b"", b"failed"
            return self.runner(command, **kwargs)

        report = self.validate(run)
        self.assertFalse(report["passed"])
        self.assertTrue(any("bytes changed: source.img" in x for x in report["failures"]))

    def test_tool_timeout_is_failed_evidence(self):
        def run(command, **kwargs):
            raise subprocess.TimeoutExpired(command, 120)

        report = self.validate(run)
        self.assertFalse(report["passed"])
        self.assertIn("version-mkntfs", report["failures"][0])

    def test_explicit_path_translation_never_touches_flags_or_names(self):
        translated = []

        def translate(path):
            translated.append(path)
            return str(path)

        report = validator.validate(self.workspace, "cli", self.programs, self.runner, translate)
        self.assertTrue(report["passed"], report["failures"])
        self.assertEqual([p.name for p in translated],
                         ["source.img", "exfat.img", "exfat.img.starconverter-escrow",
                          "exfat.img", "restored.img", "exfat.img.starconverter-escrow"])

    def test_report_is_create_new(self):
        path = self.workspace / "report.json"
        path.write_bytes(b"keep")
        with self.assertRaises(FileExistsError):
            validator.write_report(path, {})
        self.assertEqual(path.read_bytes(), b"keep")


if __name__ == "__main__":
    unittest.main()
