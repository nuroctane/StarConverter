#!/usr/bin/env python3
"""Regular-file tests for the portable release bundle validator."""

from __future__ import annotations

import gzip
import io
import pathlib
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
import zipfile


SCRIPT = pathlib.Path(__file__).with_name("validate-release-bundle.py")
EPOCH = 1_700_000_000
RELEASE_ID = "manual-0123456789ab"


def elf_x86_64() -> bytes:
    value = bytearray(64)
    value[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<H", value, 18, 62)
    return bytes(value)


def pe_x86_64() -> bytes:
    value = bytearray(128)
    value[:2] = b"MZ"
    struct.pack_into("<I", value, 0x3C, 64)
    value[64:68] = b"PE\0\0"
    struct.pack_into("<H", value, 68, 0x8664)
    return bytes(value)


class ReleaseBundleValidatorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="starconverter-bundle-test-")
        self.root = pathlib.Path(self.temporary.name)
        (self.root / "docs").mkdir()
        (self.root / "README.md").write_bytes(b"readme\n")
        (self.root / "LICENSE").write_bytes(b"license\n")
        (self.root / "docs" / "RELEASE.md").write_bytes(b"release\n")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def files(self, bundle: str, suffix: str, binary: bytes) -> dict[str, tuple[bytes, int]]:
        return {
            f"{bundle}/README.md": (b"readme\n", 0o644),
            f"{bundle}/LICENSE": (b"license\n", 0o644),
            f"{bundle}/RELEASE.md": (b"release\n", 0o644),
            f"{bundle}/starconverter{suffix}": (binary, 0o755),
            f"{bundle}/starconverter-gui{suffix}": (binary, 0o755),
        }

    def invoke(
        self,
        archive: pathlib.Path,
        target: str,
        inventory: pathlib.Path,
        mode: str,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                str(archive),
                "--release-id",
                RELEASE_ID,
                "--target",
                target,
                "--source-date-epoch",
                str(EPOCH),
                "--repository-root",
                str(self.root),
                mode,
                str(inventory),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )

    def make_zip(self, extra: bool = False) -> pathlib.Path:
        target = "x86_64-pc-windows-msvc"
        bundle = f"starconverter-{RELEASE_ID}-{target}"
        archive = self.root / f"{bundle}.zip"
        entries = self.files(bundle, ".exe", pe_x86_64())
        if extra:
            entries[f"{bundle}/unexpected.txt"] = (b"nope", 0o644)
        timestamp = list(time.gmtime(EPOCH)[:6])
        timestamp[5] -= timestamp[5] % 2
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as output:
            for name, (data, mode) in sorted(entries.items()):
                info = zipfile.ZipInfo(name, tuple(timestamp))
                info.create_system = 3
                info.external_attr = mode << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                output.writestr(info, data, compresslevel=9)
        return archive

    def make_tar_gz(self) -> pathlib.Path:
        target = "x86_64-unknown-linux-gnu"
        bundle = f"starconverter-{RELEASE_ID}-{target}"
        archive = self.root / f"{bundle}.tar.gz"
        entries = self.files(bundle, "", elf_x86_64())
        with archive.open("wb") as raw:
            with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=EPOCH) as compressed:
                with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as output:
                    for name, (data, mode) in sorted(entries.items()):
                        info = tarfile.TarInfo(name)
                        info.size = len(data)
                        info.mode = mode
                        info.uid = 0
                        info.gid = 0
                        info.uname = ""
                        info.gname = ""
                        info.mtime = EPOCH
                        output.addfile(info, io.BytesIO(data))
        return archive

    def test_zip_inventory_round_trip_and_tamper_refusal(self) -> None:
        archive = self.make_zip()
        inventory = self.root / f"{archive.name}.inventory.json"
        self.assertEqual(self.invoke(archive, "x86_64-pc-windows-msvc", inventory, "--write-inventory").returncode, 0)
        self.assertEqual(self.invoke(archive, "x86_64-pc-windows-msvc", inventory, "--verify-inventory").returncode, 0)
        inventory.write_bytes(inventory.read_bytes() + b" ")
        self.assertNotEqual(self.invoke(archive, "x86_64-pc-windows-msvc", inventory, "--verify-inventory").returncode, 0)

    def test_tar_gz_inventory_round_trip(self) -> None:
        archive = self.make_tar_gz()
        inventory = self.root / f"{archive.name}.inventory.json"
        self.assertEqual(self.invoke(archive, "x86_64-unknown-linux-gnu", inventory, "--write-inventory").returncode, 0)
        self.assertEqual(self.invoke(archive, "x86_64-unknown-linux-gnu", inventory, "--verify-inventory").returncode, 0)

    def test_unexpected_member_is_rejected(self) -> None:
        archive = self.make_zip(extra=True)
        inventory = self.root / "should-not-exist.json"
        self.assertNotEqual(self.invoke(archive, "x86_64-pc-windows-msvc", inventory, "--write-inventory").returncode, 0)
        self.assertFalse(inventory.exists())


if __name__ == "__main__":
    unittest.main()
