#!/usr/bin/env python3
"""Build a deterministic, deliberately unsigned StarConverter macOS app bundle."""

from __future__ import annotations

import argparse
import gzip
import io
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
MAX_EXECUTABLE_BYTES = 128 * 1024 * 1024


class PackageError(Exception):
    """A requested engineering bundle is unsafe or malformed."""


def info_plist(version: str) -> bytes:
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


def validate_macho(data: bytes, target: str) -> None:
    if len(data) < 8 or data[:4] != b"\xcf\xfa\xed\xfe":
        raise PackageError("GUI input is not a little-endian 64-bit Mach-O executable")
    if struct.unpack_from("<I", data, 4)[0] != TARGET_CPUS[target]:
        raise PackageError("GUI Mach-O CPU type does not match the requested target")


def archive_bytes(entries: dict[str, tuple[bytes, int]], epoch: int) -> bytes:
    raw = io.BytesIO()
    with gzip.GzipFile(
        filename="", mode="wb", fileobj=raw, mtime=epoch, compresslevel=9
    ) as compressed:
        with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as output:
            for name in sorted(entries):
                data, mode = entries[name]
                info = tarfile.TarInfo(name)
                info.size = len(data)
                info.mode = mode
                info.uid = 0
                info.gid = 0
                info.uname = ""
                info.gname = ""
                info.mtime = epoch
                output.addfile(info, io.BytesIO(data))
    return raw.getvalue()


def package(args: argparse.Namespace) -> pathlib.Path:
    if not SAFE_ID.fullmatch(args.release_id):
        raise PackageError("release id contains unsafe characters")
    if not SEMVER.fullmatch(args.version):
        raise PackageError("version must be an unadorned three-component semantic version")
    if args.target not in TARGET_CPUS:
        raise PackageError("only the two supported macOS targets can become app bundles")
    if not MIN_EPOCH <= args.source_date_epoch <= MAX_EPOCH:
        raise PackageError("source epoch is outside the portable archive range")

    executable = args.gui_executable.resolve()
    repository = args.repository_root.resolve()
    output_dir = args.output_dir.resolve()
    if not executable.is_file() or executable.is_symlink():
        raise PackageError("GUI input must be a regular, non-symlink file")
    if executable.stat().st_size > MAX_EXECUTABLE_BYTES:
        raise PackageError("GUI input exceeds the engineering bundle size limit")
    binary = executable.read_bytes()
    validate_macho(binary, args.target)

    license_file = repository / "LICENSE"
    release_guide = repository / "docs" / "RELEASE.md"
    if not license_file.is_file() or not release_guide.is_file():
        raise PackageError("LICENSE and docs/RELEASE.md are required bundle resources")

    root = "StarConverter.app/Contents"
    entries = {
        f"{root}/Info.plist": (info_plist(args.version), 0o644),
        f"{root}/MacOS/starconverter-gui": (binary, 0o755),
        f"{root}/Resources/LICENSE": (license_file.read_bytes(), 0o644),
        f"{root}/Resources/RELEASE.md": (release_guide.read_bytes(), 0o644),
    }
    name = f"starconverter-{args.release_id}-{args.target}-macos-app.tar.gz"
    destination = output_dir / name
    if destination.exists():
        raise PackageError(f"refusing to replace existing output: {destination}")
    output_dir.mkdir(parents=True, exist_ok=True)
    with destination.open("xb") as output:
        output.write(archive_bytes(entries, args.source_date_epoch))
    return destination


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--gui-executable", required=True, type=pathlib.Path)
    parser.add_argument("--repository-root", required=True, type=pathlib.Path)
    parser.add_argument("--output-dir", required=True, type=pathlib.Path)
    parser.add_argument("--release-id", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--source-date-epoch", required=True, type=int)
    return parser.parse_args()


def main() -> int:
    try:
        destination = package(parse_args())
    except (OSError, PackageError, tarfile.TarError) as error:
        print(f"macOS app packaging failed: {error}", file=sys.stderr)
        return 1
    print(destination)
    return 0


if __name__ == "__main__":
    sys.exit(main())
