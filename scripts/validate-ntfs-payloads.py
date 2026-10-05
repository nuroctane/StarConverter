#!/usr/bin/env python3
"""Check generated NTFS logical payloads using ntfscat, without mounting images."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import stat
import subprocess
import threading

MAX_PAYLOAD = 9000
MAX_MANIFEST = 16 * 1024
RICH_IMAGES = (
    "ntfs-rich-namespace-payload.img",
    "converted-rich-exfat-to-ntfs.img",
    "converted-rich-exfat-to-ntfs-windows-partition.img",
)
EDGE_IMAGES = ("ntfs-edge-corpus.img", "converted-edge-exfat-to-ntfs.img")
MISALIGNED_IMAGE = "ntfs-misaligned-8k-payload.img"
MANIFESTS = ("edge-corpus-manifest.tsv", "misaligned-relocation-manifest.tsv")
FIXTURES = RICH_IMAGES + EDGE_IMAGES + (MISALIGNED_IMAGE,) + MANIFESTS


def payload(stream: int, size: int) -> bytes:
    return bytes((stream + offset) % 251 for offset in range(size))


def entry(path: str, stream: int, size: int) -> tuple[str, int, str]:
    return path, size, hashlib.sha256(payload(stream, size)).hexdigest()


RICH = (entry("/readme.txt", 40, 14),
        entry("/alpha/Ωmega/fragmented.bin", 50, 6000),
        entry("/alpha/empty.dat", 60, 0))
EDGE = (
    entry("/empty.zero", 40, 0), entry("/δelta/one.bin", 50, 1),
    entry("/δelta/sector-minus-one.bin", 60, 4095),
    entry("/δelta/sector.bin", 70, 4096),
    entry("/δelta/cluster-plus-one.bin", 80, 4097),
    entry("/δelta/深度/two-cluster-minus-one.bin", 90, 8191),
    entry("/δelta/深度/three-way-fragmented.bin", 100, 9000),
    entry("/" + "n" * 251 + ".bin", 110, 17),
    entry("/δelta/深度/rocket-🚀.bin", 120, 33), entry("/Straße.txt", 130, 65),
)
MISALIGNED = (entry("/relocated.bin", 140, 8192),)


def regular(path: Path) -> None:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise ValueError(f"fixture must be an unaliased regular file: {path}")


def snapshot(root: Path) -> dict[str, str]:
    hashes = {}
    for name in FIXTURES:
        path = root / name
        regular(path)
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        hashes[name] = digest.hexdigest()
    return hashes


def parse_manifest(path: Path, expected_count: int) -> tuple:
    regular(path)
    with path.open("rb") as stream:
        data = stream.read(MAX_MANIFEST + 1)
    if len(data) > MAX_MANIFEST:
        raise ValueError("manifest exceeds byte limit")
    text = data.decode("utf-8", errors="strict")
    if not text.endswith("\n") or "\r" in text:
        raise ValueError("manifest must use complete LF-terminated records")
    lines = text.splitlines()
    if len(lines) != expected_count:
        raise ValueError("manifest file count differs from expected corpus")
    entries, paths = [], set()
    for line in lines:
        fields = line.split("\t")
        if len(fields) != 3:
            raise ValueError("manifest record must have three TSV fields")
        name, size, digest = fields
        if (not name.startswith("/") or "\\" in name
                or any(part in ("", ".", "..") for part in name[1:].split("/"))
                or any(ord(char) < 32 or ord(char) == 127 for char in name)
                or len(name.encode("utf-8")) > 4096 or name in paths):
            raise ValueError("invalid or duplicate manifest path")
        if not re.fullmatch(r"0|[1-9][0-9]{0,3}", size) or int(size) > MAX_PAYLOAD:
            raise ValueError("invalid or oversized manifest payload")
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError("invalid manifest SHA256")
        paths.add(name)
        entries.append((name, int(size), digest))
    return tuple(entries)


def read_payload(command: list[str], timeout: float = 30,
                 stdout_limit: int = MAX_PAYLOAD) -> tuple[int, bytes, bytes]:
    """Drain binary pipes within strict caps; kill overflow and hung readers."""
    if not isinstance(stdout_limit, int) or not 0 <= stdout_limit <= 128 * 1024:
        raise ValueError("invalid reader stdout limit")
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               stdin=subprocess.DEVNULL)
    outputs = [b"", b""]
    errors = []

    def drain(index, pipe, limit):
        try:
            outputs[index] = pipe.read(limit + 1)
            if len(outputs[index]) > limit:
                errors.append(ValueError("ntfscat output exceeds byte limit"))
                process.kill()
        except OSError as error:
            errors.append(error)
        finally:
            pipe.close()

    threads = [threading.Thread(target=drain, args=(0, process.stdout, stdout_limit), daemon=True),
               threading.Thread(target=drain, args=(1, process.stderr, 4096), daemon=True)]
    for thread in threads:
        thread.start()
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
        raise
    finally:
        for thread in threads:
            thread.join(timeout=1)
    if any(thread.is_alive() for thread in threads):
        raise ValueError("ntfscat pipe reader did not finish")
    if errors:
        raise errors[0]
    return process.returncode, outputs[0], outputs[1]


def validate(root: Path, program: str, read=read_payload) -> dict:
    root = root.resolve(strict=True)
    before = snapshot(root)
    checks, failures = [], []
    try:
        edge = parse_manifest(root / MANIFESTS[0], 10)
        misaligned = parse_manifest(root / MANIFESTS[1], 1)
        if edge != EDGE or misaligned != MISALIGNED:
            raise ValueError("manifest differs from deterministic fixture expectations")
        cases = ([(image, RICH) for image in RICH_IMAGES]
                 + [(image, edge) for image in EDGE_IMAGES]
                 + [(MISALIGNED_IMAGE, misaligned)])
        for image, entries in cases:
            for path, size, digest in entries:
                command = [program, str(root / image), path]
                result = {"image": image, "path": path, "expected_bytes": size,
                          "expected_sha256": digest, "command": command, "passed": False}
                try:
                    code, output, stderr = read(command)
                    if not isinstance(output, bytes) or len(output) > MAX_PAYLOAD:
                        raise ValueError("reader returned invalid or oversized binary output")
                    actual = hashlib.sha256(output).hexdigest()
                    result.update(exit_code=code, actual_bytes=len(output), actual_sha256=actual,
                                  stderr=stderr[:4096].decode("utf-8", errors="replace"))
                    result["passed"] = code == 0 and len(output) == size and actual == digest
                    if not result["passed"]:
                        failures.append(f"payload check failed: {image} {path}")
                except (OSError, ValueError, subprocess.TimeoutExpired) as error:
                    result["error"] = str(error)
                    failures.append(f"payload reader failed: {image} {path}: {error}")
                checks.append(result)
    except (OSError, ValueError, UnicodeError) as error:
        failures.append(f"manifest rejected: {error}")
    finally:
        try:
            after = snapshot(root)
            failures.extend(f"fixture bytes changed: {name}" for name in before
                            if before[name] != after[name])
        except (OSError, ValueError) as error:
            after = {}
            failures.append(f"post-validation fixture inspection failed: {error}")
    return {"schema": "starconverter.ntfs-logical-payloads.v1", "passed": not failures,
            "scope": "unmounted regular images; logical bytes only, no activation qualification",
            "before_sha256": before, "after_sha256": after,
            "checks": checks, "failures": failures}


def write_report(path: Path, report: dict) -> None:
    with path.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write("\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture_root", type=Path)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    program = shutil.which("ntfscat")
    if program is None:
        parser.error("required independent reader not found: ntfscat")
    report = validate(args.fixture_root, program)
    write_report(args.report, report)
    print(f"{'PASS' if report['passed'] else 'FAIL'}: {len(report['checks'])} NTFS payload checks")
    for failure in report["failures"]:
        print(failure)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
