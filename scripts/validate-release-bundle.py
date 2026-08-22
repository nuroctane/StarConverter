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
import zipfile


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


def validate_binary(data: bytes, expected: str, name: str) -> None:
    if expected == "pe-x86_64":
        if len(data) < 64 or data[:2] != b"MZ":
            raise ValidationError(f"{name} is not a PE executable")
        header = struct.unpack_from("<I", data, 0x3C)[0]
        if header + 6 > len(data) or data[header : header + 4] != b"PE\0\0":
            raise ValidationError(f"{name} has an invalid PE header")
        if struct.unpack_from("<H", data, header + 4)[0] != 0x8664:
            raise ValidationError(f"{name} is not PE x86-64")
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
        validate_binary(contents[member], binary_profile, member)

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
