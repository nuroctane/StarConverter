#!/usr/bin/env python3
"""Fail-closed tests for deterministic CycloneDX release identity."""

from __future__ import annotations

import json
import pathlib
import subprocess
import sys
import tempfile
import unittest
import uuid


SCRIPT = pathlib.Path(__file__).with_name("canonicalize-cyclonedx.py")
REPOSITORY = "nuroctane/StarConverter"
COMMIT = "1" * 40
COMPONENT = "cli"


def document() -> dict[str, object]:
    return {
        "bomFormat": "CycloneDX",
        "components": [],
        "dependencies": [],
        "metadata": {"component": {"name": "starconverter-cli", "type": "application"}},
        "specVersion": "1.5",
        "version": 1,
    }


class CanonicalizeCycloneDxTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="starconverter-cdx-test-")
        self.root = pathlib.Path(self.temporary.name)
        self.sbom = self.root / "bom.cdx.json"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_script(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                str(self.sbom),
                "--repository",
                REPOSITORY,
                "--commit",
                COMMIT,
                "--component",
                COMPONENT,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )

    def test_serial_is_source_bound_deterministic_and_idempotent(self) -> None:
        self.sbom.write_text(json.dumps(document()), encoding="utf-8")
        self.assertEqual(self.run_script().returncode, 0)
        first = self.sbom.read_bytes()
        self.assertEqual(self.run_script().returncode, 0)
        self.assertEqual(self.sbom.read_bytes(), first)

        parsed = json.loads(first)
        identity = f"https://github.com/{REPOSITORY}/commit/{COMMIT}#sbom:{COMPONENT}"
        self.assertEqual(
            parsed["serialNumber"], f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, identity)}"
        )
        self.assertTrue(first.endswith(b"\n"))

    def test_foreign_serial_and_component_are_refused_without_rewrite(self) -> None:
        foreign = document()
        foreign["serialNumber"] = "urn:uuid:00000000-0000-5000-8000-000000000000"
        self.sbom.write_text(json.dumps(foreign), encoding="utf-8")
        before = self.sbom.read_bytes()
        self.assertNotEqual(self.run_script().returncode, 0)
        self.assertEqual(self.sbom.read_bytes(), before)

        wrong = document()
        wrong["metadata"] = {"component": {"name": "starconverter-core"}}
        self.sbom.write_text(json.dumps(wrong), encoding="utf-8")
        before = self.sbom.read_bytes()
        self.assertNotEqual(self.run_script().returncode, 0)
        self.assertEqual(self.sbom.read_bytes(), before)

    def test_duplicate_fields_and_noncanonical_profile_are_refused(self) -> None:
        self.sbom.write_text(
            '{"bomFormat":"CycloneDX","bomFormat":"CycloneDX","specVersion":"1.5"}',
            encoding="utf-8",
        )
        self.assertNotEqual(self.run_script().returncode, 0)

        invalid = document()
        invalid["specVersion"] = "1.6"
        self.sbom.write_text(json.dumps(invalid), encoding="utf-8")
        self.assertNotEqual(self.run_script().returncode, 0)

    def test_missing_file_is_refused(self) -> None:
        self.assertNotEqual(self.run_script().returncode, 0)


if __name__ == "__main__":
    unittest.main()
