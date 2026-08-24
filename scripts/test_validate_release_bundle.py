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
VERSION = (0, 1, 0)


def elf_x86_64() -> bytes:
    value = bytearray(64)
    value[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<H", value, 18, 62)
    return bytes(value)


def align4(value: int) -> int:
    return (value + 3) & ~3


def utf16z(value: str) -> bytes:
    return (value + "\0").encode("utf-16-le")


def version_block(
    key: str,
    *,
    value: bytes = b"",
    value_type: int = 0,
    value_length: int | None = None,
    children: tuple[bytes, ...] = (),
) -> bytes:
    result = bytearray(struct.pack("<HHH", 0, 0, value_type) + utf16z(key))
    result.extend(b"\0" * (align4(len(result)) - len(result)))
    result.extend(value)
    for child in children:
        result.extend(b"\0" * (align4(len(result)) - len(result)))
        result.extend(child)
    if value_length is None:
        value_length = len(value) // 2 if value_type == 1 else len(value)
    struct.pack_into("<HH", result, 0, len(result), value_length)
    return bytes(result)


def version_resource(executable: str) -> bytes:
    internal_name, description = {
        "starconverter.exe": ("starconverter", "StarConverter command-line utility"),
        "starconverter-gui.exe": ("starconverter-gui", "StarConverter desktop utility"),
    }[executable]
    dotted = "0.1.0.0"
    strings = {
        "CompanyName": "Nur Octane",
        "FileDescription": description,
        "FileVersion": dotted,
        "InternalName": internal_name,
        "LegalCopyright": "Copyright (c) 2026 Nur Octane",
        "OriginalFilename": executable,
        "ProductName": "StarConverter",
        "ProductVersion": dotted,
    }
    string_children = tuple(
        version_block(key, value=utf16z(value), value_type=1)
        for key, value in strings.items()
    )
    string_table = version_block("040904b0", value_type=1, children=string_children)
    string_file_info = version_block("StringFileInfo", value_type=1, children=(string_table,))
    translation = version_block(
        "Translation", value=struct.pack("<HH", 0x0409, 0x04B0)
    )
    var_file_info = version_block("VarFileInfo", value_type=1, children=(translation,))
    fixed = struct.pack(
        "<13I",
        0xFEEF04BD,
        0x00010000,
        1,
        0,
        1,
        0,
        0x3F,
        0x02,
        0x00040004,
        0x01,
        0,
        0,
        0,
    )
    return version_block(
        "VS_VERSION_INFO",
        value=fixed,
        children=(string_file_info, var_file_info),
    )


def application_manifest(executable: str) -> bytes:
    internal_name = executable.removesuffix(".exe")
    return f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
<assemblyIdentity name="io.github.nuroctane.{internal_name}" processorArchitecture="*" type="win32" version="0.1.0.0" />
<description>StarConverter unsigned engineering pre-alpha</description>
<trustInfo xmlns="urn:schemas-microsoft-com:asm.v3"><security><requestedPrivileges><requestedExecutionLevel level="asInvoker" uiAccess="false" /></requestedPrivileges></security></trustInfo>
<compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1"><application><supportedOS Id="{{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}}" /></application></compatibility>
<application xmlns="urn:schemas-microsoft-com:asm.v3"><windowsSettings><longPathAware xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">true</longPathAware></windowsSettings></application>
</assembly>'''.encode()


def pe_x86_64(executable: str, *, subsystem: int | None = None) -> bytes:
    resources = ((16, version_resource(executable)), (24, application_manifest(executable)))
    section_rva = 0x1000
    section = bytearray(160)

    # Root -> resource type -> canonical id 1 -> en-US data entry.
    struct.pack_into("<HH", section, 12, 0, 2)
    for index, ((resource_type, payload), type_offset, id_offset, data_offset) in enumerate(
        zip(resources, (32, 56), (80, 104), (128, 144))
    ):
        struct.pack_into("<II", section, 16 + index * 8, resource_type, 0x80000000 | type_offset)
        struct.pack_into("<HHII", section, type_offset + 12, 0, 1, 1, 0x80000000 | id_offset)
        struct.pack_into("<HHII", section, id_offset + 12, 0, 1, 0x0409, data_offset)
        payload_offset = align4(len(section))
        section.extend(b"\0" * (payload_offset - len(section)))
        section.extend(payload)
        struct.pack_into(
            "<IIII", section, data_offset, section_rva + payload_offset, len(payload), 0, 0
        )

    raw_size = (len(section) + 0x1FF) & ~0x1FF
    section.extend(b"\0" * (raw_size - len(section)))
    pe_offset = 0x80
    optional_size = 240
    headers = bytearray(0x200)
    headers[:2] = b"MZ"
    struct.pack_into("<I", headers, 0x3C, pe_offset)
    headers[pe_offset : pe_offset + 4] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", headers, pe_offset + 4, 0x8664, 1, 0, 0, 0, optional_size, 0x22)
    optional = pe_offset + 24
    struct.pack_into("<H", headers, optional, 0x20B)
    struct.pack_into("<II", headers, optional + 32, 0x1000, 0x200)
    struct.pack_into("<II", headers, optional + 56, 0x2000, 0x200)
    struct.pack_into(
        "<H", headers, optional + 68, subsystem if subsystem is not None else (3 if executable == "starconverter.exe" else 2)
    )
    struct.pack_into("<I", headers, optional + 108, 16)
    struct.pack_into("<II", headers, optional + 128, section_rva, len(section))
    section_header = optional + optional_size
    headers[section_header : section_header + 8] = b".rsrc\0\0\0"
    struct.pack_into("<IIII", headers, section_header + 8, len(section), section_rva, raw_size, 0x200)
    struct.pack_into("<I", headers, section_header + 36, 0x40000040)
    return bytes(headers + section)


class ReleaseBundleValidatorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="starconverter-bundle-test-")
        self.root = pathlib.Path(self.temporary.name)
        (self.root / "docs").mkdir()
        (self.root / "README.md").write_bytes(b"readme\n")
        (self.root / "LICENSE").write_bytes(b"license\n")
        (self.root / "docs" / "RELEASE.md").write_bytes(b"release\n")
        (self.root / "Cargo.toml").write_text(
            '[workspace]\n\n[workspace.package]\nversion = "0.1.0"\n', encoding="utf-8"
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def files(
        self, bundle: str, suffix: str, binary: bytes, gui_binary: bytes | None = None
    ) -> dict[str, tuple[bytes, int]]:
        gui_binary = binary if gui_binary is None else gui_binary
        return {
            f"{bundle}/README.md": (b"readme\n", 0o644),
            f"{bundle}/LICENSE": (b"license\n", 0o644),
            f"{bundle}/RELEASE.md": (b"release\n", 0o644),
            f"{bundle}/starconverter{suffix}": (binary, 0o755),
            f"{bundle}/starconverter-gui{suffix}": (gui_binary, 0o755),
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

    def make_zip(
        self,
        extra: bool = False,
        cli_binary: bytes | None = None,
        gui_binary: bytes | None = None,
    ) -> pathlib.Path:
        target = "x86_64-pc-windows-msvc"
        bundle = f"starconverter-{RELEASE_ID}-{target}"
        archive = self.root / f"{bundle}.zip"
        entries = self.files(
            bundle,
            ".exe",
            cli_binary or pe_x86_64("starconverter.exe"),
            gui_binary or pe_x86_64("starconverter-gui.exe"),
        )
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

    def assert_windows_binary_rejected(
        self, *, cli_binary: bytes | None = None, gui_binary: bytes | None = None
    ) -> None:
        archive = self.make_zip(cli_binary=cli_binary, gui_binary=gui_binary)
        inventory = self.root / "should-not-exist.json"
        completed = self.invoke(
            archive, "x86_64-pc-windows-msvc", inventory, "--write-inventory"
        )
        self.assertNotEqual(completed.returncode, 0, completed.stdout)
        self.assertFalse(inventory.exists())

    def test_wrong_windows_subsystem_is_rejected(self) -> None:
        self.assert_windows_binary_rejected(
            gui_binary=pe_x86_64("starconverter-gui.exe", subsystem=3)
        )

    def test_windows_manifest_drift_is_rejected(self) -> None:
        binary = pe_x86_64("starconverter.exe").replace(b"longPathAware", b"fakePathAware")
        self.assert_windows_binary_rejected(cli_binary=binary)

    def test_windows_version_drift_is_rejected(self) -> None:
        binary = bytearray(pe_x86_64("starconverter.exe"))
        fixed = binary.find(struct.pack("<I", 0xFEEF04BD))
        self.assertGreaterEqual(fixed, 0)
        struct.pack_into("<I", binary, fixed + 8, 2)
        self.assert_windows_binary_rejected(cli_binary=bytes(binary))

    def test_windows_icon_resource_is_rejected(self) -> None:
        binary = bytearray(pe_x86_64("starconverter.exe"))
        struct.pack_into("<I", binary, 0x200 + 24, 3)
        self.assert_windows_binary_rejected(cli_binary=bytes(binary))

    def test_authenticode_directory_is_rejected(self) -> None:
        binary = bytearray(pe_x86_64("starconverter.exe"))
        optional_header = 0x80 + 24
        struct.pack_into("<II", binary, optional_header + 144, len(binary), 8)
        self.assert_windows_binary_rejected(cli_binary=bytes(binary))


if __name__ == "__main__":
    unittest.main()
