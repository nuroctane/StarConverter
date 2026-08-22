#!/usr/bin/env python3
"""Fail-closed validation for an unsigned StarConverter macOS app archive."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import plistlib
import re
import struct
import sys
import tarfile


TARGET_CPUS = {
    "x86_64-apple-darwin": 0x01000007,
    "aarch64-apple-darwin": 0x0100000C,
}
SAFE_ID = re.compile(r"[A-Za-z0-9._-]{1,128}\Z")
SEMVER = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\Z")
MIN_EPOCH = 315532800
MAX_EPOCH = 0xFFFFFFFF
MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
MAX_MEMBER_BYTES = 128 * 1024 * 1024
MAX_TOTAL_MEMBER_BYTES = 256 * 1024 * 1024


class ValidationError(Exception):
    """A macOS engineering app violated its closed validation schema."""


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def plist_bytes(version: str) -> bytes:
    document = {
        "CFBundleDevelopmentRegion": "en",
        "CFBundleDisplayName": "StarConverter",
        "CFBundleExecutable": "starconverter-gui",
        "CFBundleIdentifier": "io.github.nuroctane.StarConverter",
        "CFBundleInfoDictionaryVersion": "6.0",
        "CFBundleName": "StarConverter",
        "CFBundlePackageType": "APPL",
        "CFBundleShortVersionString": version,
        "CFBundleVersion": version,
        "LSApplicationCategoryType": "public.app-category.utilities",
        "NSHighResolutionCapable": True,
    }
    return plistlib.dumps(document, fmt=plistlib.FMT_XML, sort_keys=True)


def expected_members() -> dict[str, int]:
    root = "StarConverter.app/Contents"
    return {
        f"{root}/Info.plist": 0o644,
        f"{root}/MacOS/starconverter-gui": 0o755,
        f"{root}/Resources/LICENSE": 0o644,
        f"{root}/Resources/RELEASE.md": 0o644,
    }


def read_archive(
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
            raise ValidationError("app archive contains duplicate member names")
        if set(names) != set(expected):
            raise ValidationError("app archive member inventory does not match the closed schema")
        result = {}
        total_size = 0
        for entry in entries:
            if not entry.isfile() or entry.linkname:
                raise ValidationError(f"invalid app archive member type: {entry.name}")
            if (
                entry.mode != expected[entry.name]
                or entry.uid != 0
                or entry.gid != 0
                or entry.uname
                or entry.gname
                or int(entry.mtime) != epoch
                or entry.pax_headers
            ):
                raise ValidationError(f"non-canonical app archive metadata: {entry.name}")
            if entry.size > MAX_MEMBER_BYTES:
                raise ValidationError(f"oversized app archive member: {entry.name}")
            total_size += entry.size
            if total_size > MAX_TOTAL_MEMBER_BYTES:
                raise ValidationError("app archive expands beyond the size limit")
            extracted = source.extractfile(entry)
            if extracted is None:
                raise ValidationError(f"could not read app archive member: {entry.name}")
            result[entry.name] = extracted.read()
    return result


def validate_macho(data: bytes, target: str) -> None:
    if len(data) < 8 or data[:4] != b"\xcf\xfa\xed\xfe":
        raise ValidationError("app executable is not a little-endian 64-bit Mach-O")
    if struct.unpack_from("<I", data, 4)[0] != TARGET_CPUS[target]:
        raise ValidationError("app executable CPU type does not match the release target")


def canonical_inventory(
    archive: pathlib.Path,
    release_id: str,
    target: str,
    version: str,
    epoch: int,
    expected: dict[str, int],
    contents: dict[str, bytes],
) -> bytes:
    document = {
        "archive": archive.name,
        "archiveSha256": sha256_file(archive),
        "archiveSize": archive.stat().st_size,
        "artifactKind": "macos-application-bundle",
        "bundleRoot": "StarConverter.app",
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
        "distributionSigned": False,
        "sourceDateEpoch": epoch,
        "target": target,
        "version": version,
    }
    return (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()


def validate(args: argparse.Namespace) -> None:
    if not SAFE_ID.fullmatch(args.release_id):
        raise ValidationError("release id contains unsafe characters")
    if not SEMVER.fullmatch(args.version):
        raise ValidationError("version must be an unadorned three-component semantic version")
    if args.target not in TARGET_CPUS:
        raise ValidationError("unsupported macOS app target")
    if not MIN_EPOCH <= args.source_date_epoch <= MAX_EPOCH:
        raise ValidationError("source epoch is outside the portable archive range")

    archive = args.archive.resolve()
    expected_name = (
        f"starconverter-{args.release_id}-{args.target}-macos-app.tar.gz"
    )
    if archive.name != expected_name or not archive.is_file() or archive.is_symlink():
        raise ValidationError("archive name or type does not match the app identity")
    if archive.stat().st_size > MAX_ARCHIVE_BYTES:
        raise ValidationError("app archive exceeds the size limit")

    expected = expected_members()
    contents = read_archive(archive, expected, args.source_date_epoch)
    root = "StarConverter.app/Contents"
    canonical_plist = plist_bytes(args.version)
    if contents[f"{root}/Info.plist"] != canonical_plist:
        raise ValidationError("Info.plist differs from the closed unsigned-app profile")
    try:
        parsed_plist = plistlib.loads(contents[f"{root}/Info.plist"])
    except plistlib.InvalidFileException as error:
        raise ValidationError("Info.plist is not a valid property list") from error
    if parsed_plist["CFBundleExecutable"] != "starconverter-gui":
        raise ValidationError("CFBundleExecutable does not identify the packaged GUI")

    repository = args.repository_root.resolve()
    sources = {
        f"{root}/Resources/LICENSE": repository / "LICENSE",
        f"{root}/Resources/RELEASE.md": repository / "docs" / "RELEASE.md",
    }
    for member, source in sources.items():
        if not source.is_file() or contents[member] != source.read_bytes():
            raise ValidationError(f"packaged source document differs: {member}")
    validate_macho(contents[f"{root}/MacOS/starconverter-gui"], args.target)

    inventory = canonical_inventory(
        archive,
        args.release_id,
        args.target,
        args.version,
        args.source_date_epoch,
        expected,
        contents,
    )
    if args.write_inventory:
        destination = args.write_inventory.resolve()
        if destination.exists() and destination.read_bytes() != inventory:
            raise ValidationError("existing app inventory differs from canonical inventory")
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(inventory)
    if args.verify_inventory:
        if not args.verify_inventory.is_file() or args.verify_inventory.read_bytes() != inventory:
            raise ValidationError("published app inventory differs from canonical inventory")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("archive", type=pathlib.Path)
    parser.add_argument("--release-id", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--source-date-epoch", required=True, type=int)
    parser.add_argument("--repository-root", required=True, type=pathlib.Path)
    inventory = parser.add_mutually_exclusive_group(required=True)
    inventory.add_argument("--write-inventory", type=pathlib.Path)
    inventory.add_argument("--verify-inventory", type=pathlib.Path)
    return parser.parse_args()


def main() -> int:
    try:
        validate(parse_args())
    except (OSError, tarfile.TarError, ValidationError) as error:
        print(f"macOS app validation failed: {error}", file=sys.stderr)
        return 1
    print("macOS app validation passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
