#!/usr/bin/env python3
"""Independent, unmounted read-only checks of the generated regular image corpus."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import stat
import subprocess


EXFAT_IMAGES = (
    "exfat-structural-recommended-upcase.img",
    "exfat-rich-namespace-payload.img",
    "converted-rich-ntfs-to-exfat.img",
    "converted-rich-ntfs-to-exfat-windows-partition.img",
    "exfat-edge-corpus.img",
    "converted-edge-ntfs-to-exfat.img",
    "converted-misaligned-ntfs-to-exfat.img",
)
NTFS_IMAGES = (
    "ntfs-structural-activation-blocked.img",
    "ntfs-structural-64k-cluster.img",
    "ntfs-rich-namespace-payload.img",
    "converted-rich-exfat-to-ntfs.img",
    "converted-rich-exfat-to-ntfs-windows-partition.img",
    "ntfs-edge-corpus.img",
    "converted-edge-exfat-to-ntfs.img",
    "ntfs-misaligned-8k-payload.img",
)
SIDECARS = tuple(
    name + ".starconverter-escrow"
    for name in EXFAT_IMAGES + NTFS_IMAGES
    if name.startswith("converted-")
)
SUPPORT_FILES = (
    "exfat-structural-validation.vhd",
    "ntfs-structural-validation.vhd",
    "converted-rich-exfat-to-ntfs-windows.vhd",
    "converted-rich-ntfs-to-exfat-windows.vhd",
    "rich-fixture-manifest.txt",
    "edge-corpus-manifest.tsv",
    "misaligned-relocation-manifest.tsv",
)
FIXTURES = EXFAT_IMAGES + NTFS_IMAGES + SIDECARS + SUPPORT_FILES


def snapshot(root: Path) -> dict[str, str]:
    """Reject missing/special/linked inputs before handing paths to external readers."""
    result = {}
    for name in FIXTURES:
        path = root / name
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ValueError(f"fixture must be an unaliased regular file: {path}")
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        result[name] = digest.hexdigest()
    return result


def commands(root: Path, programs: dict[str, str]) -> list[list[str]]:
    checks = [[programs["fsck.exfat"], "-n", str(root / name)] for name in EXFAT_IMAGES]
    for name in NTFS_IMAGES:
        image = str(root / name)
        checks.extend((
            [programs["ntfsinfo"], "-m", image],
            [programs["ntfsls"], "-a", "-l", "-R", "-p", "/", image],
            [programs["ntfsfix"], "-n", image],
        ))
    return checks


def validate(root: Path, programs: dict[str, str], run=subprocess.run) -> dict:
    root = root.resolve(strict=True)
    before = snapshot(root)
    results = []
    failures = []
    for command in commands(root, programs):
        try:
            completed = run(command, capture_output=True, text=True, encoding="utf-8",
                            errors="replace", timeout=120, check=False)
            results.append({
                "command": command,
                "exit_code": completed.returncode,
                "stdout": completed.stdout,
                "stderr": completed.stderr,
            })
            if completed.returncode != 0:
                failures.append(f"validator failed: {' '.join(command)}")
        except (OSError, subprocess.TimeoutExpired) as error:
            results.append({"command": command, "error": str(error)})
            failures.append(f"validator could not complete: {' '.join(command)}")
    # Check even after a failed validator; never hide mutation behind an earlier tool error.
    try:
        after = snapshot(root)
        failures.extend(f"fixture bytes changed: {name}" for name in before if before[name] != after[name])
    except (OSError, ValueError) as error:
        after = {}
        failures.append(f"post-validation fixture inspection failed: {error}")
    return {
        "schema": "starconverter.external-unmounted.v1",
        "scope": "regular-image structural checks; no mount or activation qualification",
        "passed": not failures,
        "before_sha256": before,
        "after_sha256": after,
        "checks": results,
        "failures": failures,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture_root", type=Path)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    programs = {}
    for name in ("fsck.exfat", "ntfsinfo", "ntfsls", "ntfsfix"):
        program = shutil.which(name)
        if program is None:
            parser.error(f"required independent validator not found: {name}")
        programs[name] = program
    report = validate(args.fixture_root, programs)
    # Reports are create-new evidence; no existing image, sidecar, or report is overwritten.
    with args.report.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write("\n")
    print(f"{'PASS' if report['passed'] else 'FAIL'}: {len(report['checks'])} independent checks; "
          f"{len(report['before_sha256'])} fixture hashes; report {args.report}")
    for failure in report["failures"]:
        print(failure)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
