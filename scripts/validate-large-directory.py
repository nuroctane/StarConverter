#!/usr/bin/env python3
"""Independently traverse a generated multi-level NTFS directory without mounting."""

import argparse
from collections import Counter
import hashlib
import importlib.util
from pathlib import Path
import shutil
import subprocess

spec = importlib.util.spec_from_file_location(
    "ntfs_payload_helpers", Path(__file__).with_name("validate-ntfs-payloads.py"))
helpers = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helpers)

SOURCE = "exfat-large-directory.img"
TARGET = "converted-large-directory-exfat-to-ntfs.img"
MANIFEST = "large-directory-manifest.tsv"
FIXTURES = (SOURCE, TARGET, TARGET + ".starconverter-escrow", MANIFEST)
NAMES = tuple(f"entry-{ordinal:03}-Ωmega-深度-rocket-🚀-{'n' * 96}.bin"
              for ordinal in range(128))
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
EXPECTED_MANIFEST = "".join(f"/alpha/{name}\t0\t{EMPTY_SHA256}\n" for name in NAMES).encode("utf-8")


def snapshot(root):
    hashes = {}
    for name in FIXTURES:
        path = root / name
        helpers.regular(path)
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        hashes[name] = digest.hexdigest()
    return hashes


def validate(root, programs, read=helpers.read_payload):
    root = root.resolve(strict=True)
    before = snapshot(root)
    checks, failures = [], []
    try:
        with (root / MANIFEST).open("rb") as stream:
            manifest = stream.read(65537)
        if manifest != EXPECTED_MANIFEST:
            raise ValueError("manifest differs from bounded deterministic directory corpus")
        commands = [
            ("source-structure", [programs["fsck.exfat"], "-n", str(root / SOURCE)], 32768),
            ("target-structure", [programs["ntfsinfo"], "-m", str(root / TARGET)], 32768),
            ("target-structure", [programs["ntfsfix"], "-n", str(root / TARGET)], 32768),
            ("directory-names", [programs["ntfsls"], "-a", "-p", "/alpha", str(root / TARGET)], 32768),
        ]
        commands += [("empty-payload", [programs["ntfscat"], str(root / TARGET), "/alpha/" + name], 0)
                     for name in NAMES]
        for kind, command, limit in commands:
            result = {"kind": kind, "command": command, "passed": False}
            try:
                code, output, stderr = read(command, stdout_limit=limit)
                result.update(exit_code=code, stdout_bytes=len(output),
                              stdout_sha256=hashlib.sha256(output).hexdigest(),
                              stderr=stderr[:4096].decode("utf-8", errors="replace"))
                passed = code == 0
                if kind == "directory-names":
                    names = output.decode("utf-8", errors="strict").splitlines()
                    # NTFS-3G synthesizes '.', while root-parent '..' is filtered as metadata.
                    passed = passed and Counter(names) == Counter(NAMES + (".",))
                    result["observed_names"] = names
                elif kind == "empty-payload":
                    passed = passed and output == b""
                else:
                    result["stdout"] = output.decode("utf-8", errors="replace")
                result["passed"] = passed
                if not passed:
                    failures.append(f"independent check failed: {command}")
            except (OSError, ValueError, UnicodeError, subprocess.TimeoutExpired) as error:
                result["error"] = str(error)
                failures.append(f"independent reader failed: {command}: {error}")
            checks.append(result)
    except (OSError, ValueError) as error:
        failures.append(f"manifest rejected: {error}")
    finally:
        try:
            after = snapshot(root)
            failures.extend(f"fixture bytes changed: {name}" for name in before if before[name] != after[name])
        except (OSError, ValueError) as error:
            after = {}
            failures.append(f"post-validation fixture inspection failed: {error}")
    return {"schema": "starconverter.large-directory.v1", "passed": not failures,
            "scope": "unmounted generated directory namespace and empty payloads; no activation qualification",
            "expected_names": list(NAMES), "before_sha256": before, "after_sha256": after,
            "checks": checks, "failures": failures}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture_root", type=Path)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    programs = {}
    for name in ("fsck.exfat", "ntfsinfo", "ntfsfix", "ntfsls", "ntfscat"):
        programs[name] = shutil.which(name)
        if programs[name] is None:
            parser.error(f"independent reader missing: {name}")
    report = validate(args.fixture_root, programs)
    helpers.write_report(args.report, report)
    print(f"{'PASS' if report['passed'] else 'FAIL'}: {len(report['checks'])} large-directory checks")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
