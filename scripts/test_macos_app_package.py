#!/usr/bin/env python3
"""Regular-file tests for deterministic macOS app packaging and validation."""

from __future__ import annotations

import gzip
import io
import pathlib
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest


PACKAGE = pathlib.Path(__file__).with_name("package-macos-app.py")
VALIDATE = pathlib.Path(__file__).with_name("validate-macos-app.py")
EPOCH = 1_700_000_000
RELEASE_ID = "manual-0123456789ab"
VERSION = "0.1.0"
TARGET = "x86_64-apple-darwin"


def macho(cpu: int = 0x01000007) -> bytes:
    value = bytearray(64)
    value[:4] = b"\xcf\xfa\xed\xfe"
    struct.pack_into("<I", value, 4, cpu)
    return bytes(value)


class MacosAppPackageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="starconverter-macos-app-test-")
        self.root = pathlib.Path(self.temporary.name)
        self.repository = self.root / "repository"
        (self.repository / "docs").mkdir(parents=True)
        (self.repository / "LICENSE").write_bytes(b"license\n")
        (self.repository / "docs" / "RELEASE.md").write_bytes(b"release\n")
        self.executable = self.root / "starconverter-gui"
        self.executable.write_bytes(macho())

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def package(self, output: pathlib.Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(PACKAGE),
                "--gui-executable",
                str(self.executable),
                "--repository-root",
                str(self.repository),
                "--output-dir",
                str(output),
                "--release-id",
                RELEASE_ID,
                "--version",
                VERSION,
                "--target",
                TARGET,
                "--source-date-epoch",
                str(EPOCH),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )

    def validate(
        self, archive: pathlib.Path, inventory: pathlib.Path, mode: str
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(VALIDATE),
                str(archive),
                "--release-id",
                RELEASE_ID,
                "--version",
                VERSION,
                "--target",
                TARGET,
                "--source-date-epoch",
                str(EPOCH),
                "--repository-root",
                str(self.repository),
                mode,
                str(inventory),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )

    def test_reproducible_archives_and_inventory_round_trip(self) -> None:
        first_dir = self.root / "first"
        second_dir = self.root / "second"
        self.assertEqual(self.package(first_dir).returncode, 0)
        self.assertEqual(self.package(second_dir).returncode, 0)
        name = f"starconverter-{RELEASE_ID}-{TARGET}-macos-app.tar.gz"
        first = first_dir / name
        second = second_dir / name
        self.assertEqual(first.read_bytes(), second.read_bytes())

        inventory = self.root / f"{name}.inventory.json"
        self.assertEqual(self.validate(first, inventory, "--write-inventory").returncode, 0)
        self.assertEqual(self.validate(first, inventory, "--verify-inventory").returncode, 0)
        inventory.write_bytes(inventory.read_bytes() + b" ")
        self.assertNotEqual(self.validate(first, inventory, "--verify-inventory").returncode, 0)

    def test_existing_output_and_wrong_architecture_are_refused(self) -> None:
        output = self.root / "dist"
        self.assertEqual(self.package(output).returncode, 0)
        self.assertNotEqual(self.package(output).returncode, 0)
        self.executable.write_bytes(macho(0x0100000C))
        self.assertNotEqual(self.package(self.root / "wrong-architecture").returncode, 0)

    def test_signature_or_any_extra_member_is_refused(self) -> None:
        output = self.root / "dist"
        self.assertEqual(self.package(output).returncode, 0)
        name = f"starconverter-{RELEASE_ID}-{TARGET}-macos-app.tar.gz"
        archive = output / name
        with tarfile.open(archive, "r:gz") as source:
            entries = {
                item.name: (source.extractfile(item).read(), item.mode)
                for item in source.getmembers()
            }
        entries["StarConverter.app/Contents/_CodeSignature/CodeResources"] = (
            b"unexpected signature",
            0o644,
        )
        with archive.open("wb") as raw:
            with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=EPOCH) as compressed:
                with tarfile.open(
                    fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT
                ) as destination:
                    for member_name in sorted(entries):
                        data, mode = entries[member_name]
                        item = tarfile.TarInfo(member_name)
                        item.size = len(data)
                        item.mode = mode
                        item.uid = 0
                        item.gid = 0
                        item.mtime = EPOCH
                        destination.addfile(item, io.BytesIO(data))
        inventory = self.root / "should-not-exist.json"
        self.assertNotEqual(self.validate(archive, inventory, "--write-inventory").returncode, 0)
        self.assertFalse(inventory.exists())


if __name__ == "__main__":
    unittest.main()
