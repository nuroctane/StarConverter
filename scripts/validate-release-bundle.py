#!/usr/bin/env python3
"""Fail-closed validation for one StarConverter portable release archive."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
import tomllib
import zipfile
import xml.etree.ElementTree as ET


TARGETS = {
    "x86_64-pc-windows-msvc": (".zip", ".exe", "pe-x86_64"),
    "x86_64-unknown-linux-gnu": (".tar.gz", "", "elf-x86_64"),
    "x86_64-apple-darwin": (".tar.gz", "", "macho-x86_64"),
    "aarch64-apple-darwin": (".tar.gz", "", "macho-aarch64"),
}
MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
MAX_MEMBER_BYTES = 128 * 1024 * 1024
MAX_TOTAL_MEMBER_BYTES = 256 * 1024 * 1024
MAX_SOURCE_DATE_EPOCH = 0xFFFFFFFF
RT_ICON = 3
RT_GROUP_ICON = 14
RT_VERSION = 16
RT_MANIFEST = 24
WINDOWS_MANIFEST_DESCRIPTION = "StarConverter unsigned engineering pre-alpha"
WINDOWS_MANIFEST_SUPPORTED_OS = "{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"
WINDOWS_VERSION_STRINGS = {
    "CompanyName": "Nur Octane",
    "LegalCopyright": "Copyright (c) 2026 Nur Octane",
    "ProductName": "StarConverter",
}


class ValidationError(Exception):
    """A release archive violated its closed validation schema."""


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def expected_members(bundle: str, suffix: str) -> dict[str, int]:
    return {
        f"{bundle}/LICENSE": 0o644,
        f"{bundle}/README.md": 0o644,
        f"{bundle}/RELEASE.md": 0o644,
        f"{bundle}/starconverter{suffix}": 0o755,
        f"{bundle}/starconverter-gui{suffix}": 0o755,
    }


def align4(value: int) -> int:
    return (value + 3) & ~3


def expected_manifest_shape(internal_name: str, version: str) -> tuple:
    source = f"""<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
<assemblyIdentity name="io.github.nuroctane.{internal_name}" processorArchitecture="*" type="win32" version="{version}" />
<description>{WINDOWS_MANIFEST_DESCRIPTION}</description>
<trustInfo xmlns="urn:schemas-microsoft-com:asm.v3"><security><requestedPrivileges><requestedExecutionLevel level="asInvoker" uiAccess="false" /></requestedPrivileges></security></trustInfo>
<compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1"><application><supportedOS Id="{WINDOWS_MANIFEST_SUPPORTED_OS}" /></application></compatibility>
<application xmlns="urn:schemas-microsoft-com:asm.v3"><windowsSettings><longPathAware xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">true</longPathAware></windowsSettings></application>
</assembly>"""
    return xml_shape(ET.fromstring(source))


def xml_shape(element: ET.Element) -> tuple:
    return (
        element.tag,
        tuple(sorted(element.attrib.items())),
        (element.text or "").strip(),
        tuple(xml_shape(child) for child in element),
    )


def pe_resources(
    data: bytes, pe_header: int, optional_header: int, optional_size: int, name: str
) -> dict[int, list[bytes]]:
    if optional_size < 240 or optional_header + optional_size > len(data):
        raise ValidationError(f"{name} has a truncated PE32+ optional header")
    if struct.unpack_from("<H", data, optional_header)[0] != 0x20B:
        raise ValidationError(f"{name} is not PE32+")
    directory_count = struct.unpack_from("<I", data, optional_header + 108)[0]
    if directory_count <= 2:
        raise ValidationError(f"{name} has no resource directory")
    resource_rva, resource_size = struct.unpack_from(
        "<II", data, optional_header + 112 + (2 * 8)
    )
    if resource_rva == 0 or resource_size < 16:
        raise ValidationError(f"{name} has no resource directory")

    section_count = struct.unpack_from("<H", data, pe_header + 6)[0]
    sections = []
    section_offset = optional_header + optional_size
    if section_count == 0 or section_offset + section_count * 40 > len(data):
        raise ValidationError(f"{name} has an invalid PE section table")
    for index in range(section_count):
        entry = section_offset + index * 40
        virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from(
            "<IIII", data, entry + 8
        )
        sections.append((virtual_address, max(virtual_size, raw_size), raw_offset, raw_size))

    def rva_offset(rva: int, size: int) -> int:
        for virtual_address, span, raw_offset, raw_size in sections:
            relative = rva - virtual_address
            if 0 <= relative <= span and size <= raw_size and relative + size <= raw_size:
                offset = raw_offset + relative
                if offset + size <= len(data):
                    return offset
        raise ValidationError(f"{name} resource RVA is outside the PE sections")

    resource_offset = rva_offset(resource_rva, resource_size)

    def directory(relative: int) -> list[tuple[int, int]]:
        if relative < 0 or relative + 16 > resource_size:
            raise ValidationError(f"{name} has a truncated resource directory")
        offset = resource_offset + relative
        named, numeric = struct.unpack_from("<HH", data, offset + 12)
        count = named + numeric
        if count > 256 or relative + 16 + count * 8 > resource_size:
            raise ValidationError(f"{name} has an oversized resource directory")
        result = []
        for index in range(count):
            key, target = struct.unpack_from("<II", data, offset + 16 + index * 8)
            if key & 0x80000000:
                raise ValidationError(f"{name} contains a named resource")
            result.append((key, target))
        return result

    result: dict[int, list[bytes]] = {}
    for resource_type, type_target in directory(0):
        if not type_target & 0x80000000:
            raise ValidationError(f"{name} resource type does not point to a directory")
        for resource_id, id_target in directory(type_target & 0x7FFFFFFF):
            if resource_id != 1 or not id_target & 0x80000000:
                raise ValidationError(f"{name} resource id is not the canonical id 1")
            languages = directory(id_target & 0x7FFFFFFF)
            if len(languages) != 1:
                raise ValidationError(f"{name} resource has multiple languages")
            language, data_target = languages[0]
            if language != 0x0409 or data_target & 0x80000000:
                raise ValidationError(f"{name} resource language is not canonical en-US")
            relative = data_target
            if relative + 16 > resource_size:
                raise ValidationError(f"{name} has a truncated resource data entry")
            value_rva, value_size, code_page, reserved = struct.unpack_from(
                "<IIII", data, resource_offset + relative
            )
            if value_size == 0 or value_size > MAX_MEMBER_BYTES or reserved != 0:
                raise ValidationError(f"{name} has an invalid resource data entry")
            if code_page not in (0, 1200, 65001):
                raise ValidationError(f"{name} resource uses an unexpected code page")
            value_offset = rva_offset(value_rva, value_size)
            result.setdefault(resource_type, []).append(
                data[value_offset : value_offset + value_size]
            )
    return result


def read_utf16_key(data: bytes, offset: int, limit: int, name: str) -> tuple[str, int]:
    units = []
    while offset + 2 <= limit:
        unit = struct.unpack_from("<H", data, offset)[0]
        offset += 2
        if unit == 0:
            try:
                return bytes().join(struct.pack("<H", value) for value in units).decode(
                    "utf-16-le", errors="strict"
                ), offset
            except UnicodeDecodeError as error:
                raise ValidationError(f"{name} has an invalid UTF-16 version key") from error
        units.append(unit)
    raise ValidationError(f"{name} has an unterminated version key")


def version_block(data: bytes, offset: int, limit: int, name: str) -> dict:
    if offset + 6 > limit:
        raise ValidationError(f"{name} has a truncated VERSIONINFO block")
    length, value_length, value_type = struct.unpack_from("<HHH", data, offset)
    end = offset + length
    if length < 8 or end > limit:
        raise ValidationError(f"{name} has an invalid VERSIONINFO block length")
    key, after_key = read_utf16_key(data, offset + 6, end, name)
    value_offset = align4(after_key)
    value_size = value_length * 2 if value_type == 1 else value_length
    if value_offset + value_size > end:
        raise ValidationError(f"{name} has a truncated VERSIONINFO value")
    value = data[value_offset : value_offset + value_size]
    children = []
    child_offset = align4(value_offset + value_size)
    while child_offset + 2 <= end:
        if all(byte == 0 for byte in data[child_offset:end]):
            break
        child = version_block(data, child_offset, end, name)
        children.append(child)
        child_offset = align4(child_offset + child["length"])
    return {
        "children": children,
        "key": key,
        "length": length,
        "type": value_type,
        "value": value,
    }


def validate_version_resource(
    data: bytes, name: str, executable: str, version: tuple[int, int, int]
) -> None:
    root = version_block(data, 0, len(data), name)
    if root["length"] != len(data) or root["key"] != "VS_VERSION_INFO":
        raise ValidationError(f"{name} has a non-canonical VERSIONINFO root")
    if len(root["value"]) != 52:
        raise ValidationError(f"{name} has a malformed VS_FIXEDFILEINFO")
    fixed = struct.unpack("<13I", root["value"])
    major, minor, patch = version
    expected_ms = (major << 16) | minor
    expected_ls = patch << 16
    expected_fixed = (
        0xFEEF04BD,
        0x00010000,
        expected_ms,
        expected_ls,
        expected_ms,
        expected_ls,
        0x3F,
        0x02,
        0x00040004,
        0x01,
        0,
        0,
        0,
    )
    if fixed != expected_fixed:
        raise ValidationError(f"{name} has incorrect fixed version metadata")
    children = {child["key"]: child for child in root["children"]}
    if set(children) != {"StringFileInfo", "VarFileInfo"}:
        raise ValidationError(f"{name} has an unexpected VERSIONINFO child set")
    string_tables = children["StringFileInfo"]["children"]
    if len(string_tables) != 1 or string_tables[0]["key"] != "040904b0":
        raise ValidationError(f"{name} has a non-canonical VERSIONINFO string table")
    strings = {}
    for entry in string_tables[0]["children"]:
        if entry["type"] != 1 or len(entry["value"]) < 2:
            raise ValidationError(f"{name} has a malformed VERSIONINFO string")
        try:
            value = entry["value"].decode("utf-16-le", errors="strict")
        except UnicodeDecodeError as error:
            raise ValidationError(f"{name} has invalid VERSIONINFO text") from error
        if not value.endswith("\0") or "\0" in value[:-1] or entry["key"] in strings:
            raise ValidationError(f"{name} has a non-canonical VERSIONINFO string")
        strings[entry["key"]] = value[:-1]
    dotted = f"{major}.{minor}.{patch}.0"
    identity = {
        "starconverter.exe": (
            "starconverter",
            "StarConverter command-line utility",
        ),
        "starconverter-gui.exe": (
            "starconverter-gui",
            "StarConverter desktop utility",
        ),
    }
    internal_name, description = identity[executable]
    expected_strings = {
        **WINDOWS_VERSION_STRINGS,
        "FileDescription": description,
        "FileVersion": dotted,
        "InternalName": internal_name,
        "OriginalFilename": executable,
        "ProductVersion": dotted,
    }
    if strings != expected_strings:
        raise ValidationError(f"{name} has incorrect version strings")
    variables = children["VarFileInfo"]["children"]
    if (
        len(variables) != 1
        or variables[0]["key"] != "Translation"
        or variables[0]["type"] != 0
        or variables[0]["value"] != struct.pack("<HH", 0x0409, 0x04B0)
    ):
        raise ValidationError(f"{name} has incorrect VERSIONINFO translation metadata")


def validate_windows_binary(
    data: bytes, name: str, executable: str, version: tuple[int, int, int]
) -> None:
    if len(data) < 64 or data[:2] != b"MZ":
        raise ValidationError(f"{name} is not a PE executable")
    pe_header = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_header + 24 > len(data) or data[pe_header : pe_header + 4] != b"PE\0\0":
        raise ValidationError(f"{name} has an invalid PE header")
    if struct.unpack_from("<H", data, pe_header + 4)[0] != 0x8664:
        raise ValidationError(f"{name} is not PE x86-64")
    optional_size = struct.unpack_from("<H", data, pe_header + 20)[0]
    optional_header = pe_header + 24
    if optional_size < 152 or optional_header + optional_size > len(data):
        raise ValidationError(f"{name} has a truncated PE32+ optional header")
    directory_count = struct.unpack_from("<I", data, optional_header + 108)[0]
    if directory_count <= 4:
        raise ValidationError(f"{name} has no Authenticode directory slot")
    certificate_offset, certificate_size = struct.unpack_from(
        "<II", data, optional_header + 112 + (4 * 8)
    )
    if certificate_offset != 0 or certificate_size != 0:
        raise ValidationError(f"{name} must be unsigned in the engineering channel")
    resources = pe_resources(data, pe_header, optional_header, optional_size, name)
    if RT_ICON in resources or RT_GROUP_ICON in resources:
        raise ValidationError(f"{name} unexpectedly contains icon artwork")
    if set(resources) != {RT_VERSION, RT_MANIFEST}:
        raise ValidationError(f"{name} has an unexpected PE resource type set")
    if len(resources[RT_VERSION]) != 1 or len(resources[RT_MANIFEST]) != 1:
        raise ValidationError(f"{name} has duplicate required PE resources")
    expected_subsystem = 3 if executable == "starconverter.exe" else 2
    if struct.unpack_from("<H", data, optional_header + 68)[0] != expected_subsystem:
        raise ValidationError(f"{name} has the wrong Windows subsystem")
    validate_version_resource(resources[RT_VERSION][0], name, executable, version)
    manifest = resources[RT_MANIFEST][0].strip(b" \t\r\n")
    if len(manifest) > 64 * 1024 or b"<!DOCTYPE" in manifest.upper():
        raise ValidationError(f"{name} has an unsafe application manifest")
    try:
        shape = xml_shape(ET.fromstring(manifest.decode("utf-8", errors="strict")))
    except (UnicodeDecodeError, ET.ParseError) as error:
        raise ValidationError(f"{name} has an invalid application manifest") from error
    dotted = f"{version[0]}.{version[1]}.{version[2]}.0"
    internal_name = executable.removesuffix(".exe")
    if shape != expected_manifest_shape(internal_name, dotted):
        raise ValidationError(f"{name} application manifest differs from policy")


def validate_binary(
    data: bytes,
    expected: str,
    name: str,
    executable: str | None = None,
    version: tuple[int, int, int] | None = None,
) -> None:
    if expected == "pe-x86_64":
        if executable is None or version is None:
            raise ValidationError(f"{name} is missing Windows identity policy")
        validate_windows_binary(data, name, executable, version)
        return
    if expected == "elf-x86_64":
        if (
            len(data) < 20
            or data[:4] != b"\x7fELF"
            or data[4] != 2
            or data[5] != 1
            or struct.unpack_from("<H", data, 18)[0] != 62
        ):
            raise ValidationError(f"{name} is not little-endian ELF x86-64")
        return
    if expected.startswith("macho-"):
        if len(data) < 8 or data[:4] != b"\xcf\xfa\xed\xfe":
            raise ValidationError(f"{name} is not little-endian 64-bit Mach-O")
        expected_cpu = 0x01000007 if expected.endswith("x86_64") else 0x0100000C
        if struct.unpack_from("<I", data, 4)[0] != expected_cpu:
            raise ValidationError(f"{name} has the wrong Mach-O CPU type")
        return
    raise ValidationError(f"unsupported binary profile: {expected}")


def read_zip(
    archive: pathlib.Path, expected: dict[str, int], epoch: int
) -> dict[str, bytes]:
    expected_time = list(time.gmtime(max(epoch, 315532800))[:6])
    expected_time[5] -= expected_time[5] % 2
    with zipfile.ZipFile(archive) as source:
        if source.comment:
            raise ValidationError("ZIP archive comment must be empty")
        entries = source.infolist()
        names = [entry.filename for entry in entries]
        if len(names) != len(set(names)):
            raise ValidationError("ZIP contains duplicate member names")
        if set(names) != set(expected):
            raise ValidationError("ZIP member inventory does not match the release schema")
        result = {}
        total_size = 0
        for entry in entries:
            if entry.is_dir() or entry.flag_bits & 1:
                raise ValidationError(f"invalid ZIP member type or encryption: {entry.filename}")
            if entry.create_system != 3 or entry.extra or entry.comment:
                raise ValidationError(f"non-canonical ZIP metadata: {entry.filename}")
            if entry.compress_type != zipfile.ZIP_DEFLATED:
                raise ValidationError(f"unexpected ZIP compression: {entry.filename}")
            mode = (entry.external_attr >> 16) & 0xFFFF
            if mode != expected[entry.filename]:
                raise ValidationError(f"wrong ZIP mode: {entry.filename}")
            if tuple(entry.date_time) != tuple(expected_time):
                raise ValidationError(f"wrong ZIP timestamp: {entry.filename}")
            if entry.file_size > MAX_MEMBER_BYTES:
                raise ValidationError(f"oversized ZIP member: {entry.filename}")
            total_size += entry.file_size
            if total_size > MAX_TOTAL_MEMBER_BYTES:
                raise ValidationError("ZIP expands beyond the release size limit")
            result[entry.filename] = source.read(entry)
        return result


def read_tar_gz(
    archive: pathlib.Path, expected: dict[str, int], epoch: int
) -> dict[str, bytes]:
    with archive.open("rb") as raw:
        header = raw.read(10)
    if len(header) != 10 or header[:3] != b"\x1f\x8b\x08":
        raise ValidationError("archive is not gzip")
    if (
        header[3] != 0
        or struct.unpack_from("<I", header, 4)[0] != epoch
        or header[8] != 2
        or header[9] != 255
    ):
        raise ValidationError("gzip header is not canonical")
    with tarfile.open(archive, mode="r:gz") as source:
        entries = source.getmembers()
        names = [entry.name for entry in entries]
        if len(names) != len(set(names)):
            raise ValidationError("tar contains duplicate member names")
        if set(names) != set(expected):
            raise ValidationError("tar member inventory does not match the release schema")
        result = {}
        total_size = 0
        for entry in entries:
            if not entry.isfile() or entry.linkname:
                raise ValidationError(f"invalid tar member type: {entry.name}")
            if (
                entry.mode != expected[entry.name]
                or entry.uid != 0
                or entry.gid != 0
                or entry.uname
                or entry.gname
                or int(entry.mtime) != epoch
                or entry.pax_headers
            ):
                raise ValidationError(f"non-canonical tar metadata: {entry.name}")
            if entry.size > MAX_MEMBER_BYTES:
                raise ValidationError(f"oversized tar member: {entry.name}")
            total_size += entry.size
            if total_size > MAX_TOTAL_MEMBER_BYTES:
                raise ValidationError("tar expands beyond the release size limit")
            extracted = source.extractfile(entry)
            if extracted is None:
                raise ValidationError(f"could not read tar member: {entry.name}")
            result[entry.name] = extracted.read()
        return result


def canonical_inventory(
    archive: pathlib.Path,
    bundle: str,
    release_id: str,
    target: str,
    epoch: int,
    expected: dict[str, int],
    contents: dict[str, bytes],
) -> bytes:
    document = {
        "archive": archive.name,
        "archiveSha256": sha256_file(archive),
        "archiveSize": archive.stat().st_size,
        "bundleRoot": bundle,
        "members": [
            {
                "mode": f"{expected[name]:04o}",
                "path": name,
                "sha256": sha256_bytes(contents[name]),
                "size": len(contents[name]),
            }
            for name in sorted(expected)
        ],
        "releaseId": release_id,
        "schemaVersion": 1,
        "sourceDateEpoch": epoch,
        "target": target,
    }
    return (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()


def validate(args: argparse.Namespace) -> None:
    archive = args.archive.resolve()
    repository = args.repository_root.resolve()
    if args.target not in TARGETS:
        raise ValidationError(f"unsupported target: {args.target}")
    if (
        not args.release_id
        or len(args.release_id) > 128
        or any(character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-" for character in args.release_id)
    ):
        raise ValidationError("release id contains unsafe characters")
    archive_suffix, exe_suffix, binary_profile = TARGETS[args.target]
    try:
        workspace_version_text = tomllib.loads(
            (repository / "Cargo.toml").read_text(encoding="utf-8")
        )["workspace"]["package"]["version"]
        workspace_version = tuple(int(part) for part in workspace_version_text.split("."))
    except (KeyError, OSError, tomllib.TOMLDecodeError, UnicodeError, ValueError) as error:
        raise ValidationError("repository has an invalid workspace version") from error
    if len(workspace_version) != 3 or any(not 0 <= part <= 0xFFFF for part in workspace_version):
        raise ValidationError("workspace version is outside the Windows version range")
    bundle = f"starconverter-{args.release_id}-{args.target}"
    if archive.name != f"{bundle}{archive_suffix}" or not archive.is_file():
        raise ValidationError("archive name does not match release identity")
    if archive.stat().st_size > MAX_ARCHIVE_BYTES:
        raise ValidationError("archive exceeds the release size limit")
    if args.source_date_epoch < 315532800 or args.source_date_epoch > MAX_SOURCE_DATE_EPOCH:
        raise ValidationError("source epoch is outside the portable archive range")
    expected = expected_members(bundle, exe_suffix)
    if archive_suffix == ".zip":
        contents = read_zip(archive, expected, args.source_date_epoch)
    else:
        contents = read_tar_gz(archive, expected, args.source_date_epoch)

    source_files = {
        f"{bundle}/README.md": repository / "README.md",
        f"{bundle}/LICENSE": repository / "LICENSE",
        f"{bundle}/RELEASE.md": repository / "docs" / "RELEASE.md",
    }
    for member, source in source_files.items():
        if not source.is_file() or contents[member] != source.read_bytes():
            raise ValidationError(f"packaged source document differs: {member}")
    for executable in (f"starconverter{exe_suffix}", f"starconverter-gui{exe_suffix}"):
        member = f"{bundle}/{executable}"
        validate_binary(
            contents[member], binary_profile, member, executable, workspace_version
        )

    inventory = canonical_inventory(
        archive,
        bundle,
        args.release_id,
        args.target,
        args.source_date_epoch,
        expected,
        contents,
    )
    if args.write_inventory:
        destination = args.write_inventory.resolve()
        if destination.exists() and destination.read_bytes() != inventory:
            raise ValidationError("existing inventory differs from canonical inventory")
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(inventory)
    if args.verify_inventory:
        if not args.verify_inventory.is_file() or args.verify_inventory.read_bytes() != inventory:
            raise ValidationError("published inventory differs from canonical inventory")

    if args.smoke_cli:
        cli_name = f"starconverter{exe_suffix}"
        with tempfile.TemporaryDirectory(prefix="starconverter-release-smoke-") as temporary:
            executable = pathlib.Path(temporary) / cli_name
            executable.write_bytes(contents[f"{bundle}/{cli_name}"])
            executable.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
            completed = subprocess.run(
                [str(executable), "demo"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=30,
                check=False,
            )
            if completed.returncode != 0 or b"[READ-ONLY]" not in completed.stdout:
                raise ValidationError("packaged CLI smoke test failed")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("archive", type=pathlib.Path)
    parser.add_argument("--release-id", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--source-date-epoch", required=True, type=int)
    parser.add_argument("--repository-root", required=True, type=pathlib.Path)
    inventory = parser.add_mutually_exclusive_group(required=True)
    inventory.add_argument("--write-inventory", type=pathlib.Path)
    inventory.add_argument("--verify-inventory", type=pathlib.Path)
    parser.add_argument("--smoke-cli", action="store_true")
    return parser.parse_args()


def main() -> int:
    try:
        validate(parse_args())
    except (OSError, subprocess.SubprocessError, tarfile.TarError, zipfile.BadZipFile, ValidationError) as error:
        print(f"release bundle validation failed: {error}", file=sys.stderr)
        return 1
    print("release bundle validation passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
