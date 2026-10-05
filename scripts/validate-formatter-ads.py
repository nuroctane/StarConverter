#!/usr/bin/env python3
"""Independent formatter-origin ADS roundtrip on a fresh, unmounted regular image."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile

spec = importlib.util.spec_from_file_location(
    "ntfs_payload_reader", Path(__file__).with_name("validate-ntfs-payloads.py"))
reader = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reader)

IMAGE_BYTES = 64 * 1024 * 1024
TOOLS = ("mkntfs", "ntfscp", "ntfscat", "ntfsinfo", "ntfsfix", "fsck.exfat")
STREAMS = (("", 14, 40, True), ("sc-small", 16, 50, True),
           ("sc-large", 8193, 60, False))


def payload(seed: int, length: int) -> bytes:
    return bytes((seed + offset) % 251 for offset in range(length))


def linked(metadata) -> bool:
    return stat.S_ISLNK(metadata.st_mode) or bool(getattr(metadata, "st_file_attributes", 0) & 0x400)


def approve_workspace(workspace: Path) -> Path:
    workspace = workspace.absolute()
    for path in (workspace, *workspace.parents):
        if linked(path.lstat()):
            raise ValueError(f"linked workspace component refused: {path}")
    if not workspace.is_dir():
        raise ValueError("workspace must be an existing ordinary directory")
    return workspace.resolve(strict=True)


def regular(path: Path, size: int | None = None, identity=None):
    metadata = path.lstat()
    if (linked(metadata) or not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
            or (size is not None and metadata.st_size != size)
            or (identity is not None and (metadata.st_dev, metadata.st_ino) != identity)):
        raise ValueError(f"file is not the expected unaliased regular fixture: {path}")
    return metadata.st_dev, metadata.st_ino


def image_guard(path: Path, case: Path, identity=None):
    approve_workspace(case)
    if path.parent != case or path.resolve(strict=True).parent != case:
        raise ValueError("image escaped its fresh case directory")
    return regular(path, IMAGE_BYTES, identity)


def digest(path: Path) -> str:
    regular(path)
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def manifest_bytes() -> bytes:
    return "".join(f"/payload.bin\t{name or '-'}\t{size}\t"
                   f"{'resident' if resident else 'nonresident'}\t"
                   f"{hashlib.sha256(payload(seed, size)).hexdigest()}\n"
                   for name, size, seed, resident in STREAMS).encode("utf-8")


def validate_manifest(path: Path) -> None:
    regular(path)
    with path.open("rb") as stream:
        data = stream.read(4097)
    if len(data) > 4096 or data != manifest_bytes():
        raise ValueError("ADS manifest differs from the three deterministic stream expectations")


def parse_storage(output: bytes, require_source_forms: bool = True) -> dict:
    """Read NTFS-3G ntfsinfo.c attribute headers, refusing ambiguity or missing evidence."""
    text = output.decode("utf-8", errors="strict")
    found = {}
    for block in re.split(r"(?m)^Dumping attribute ", text)[1:]:
        if not block.startswith("$DATA (0x80) from mft record "):
            continue
        resident = re.findall(r"(?m)^\s*Resident:\s+(Yes|No)\s*$", block)
        names = re.findall(r"(?m)^\s*Attribute name:\s+'([^']*)'\s*$", block)
        name_lengths = re.findall(r"(?m)^\s*Name length:\s+(\d+) \(0x([0-9a-f]+)\)\s*$", block)
        sizes = re.findall(r"(?m)^\s*Data size:\s+(\d+) \(0x([0-9a-f]+)\)\s*$", block)
        if len(resident) != 1 or len(sizes) != 1 or len(name_lengths) != 1:
            raise ValueError("incomplete or ambiguous ntfsinfo $DATA storage header")
        length = int(name_lengths[0][0])
        size = int(sizes[0][0])
        if length != int(name_lengths[0][1], 16) or size != int(sizes[0][1], 16):
            raise ValueError("ntfsinfo decimal and hexadecimal size evidence disagree")
        if (length == 0 and names) or (length != 0 and len(names) != 1):
            raise ValueError("ntfsinfo stream name disagrees with name-length evidence")
        name = names[0] if names else ""
        if name in found:
            raise ValueError("duplicate or continued ntfsinfo $DATA stream")
        if length != len(name.encode("utf-16-le")) // 2:
            raise ValueError("ntfsinfo stream name length mismatch")
        found[name] = {"resident": resident[0] == "Yes", "bytes": size}
    expected = {name: {"resident": resident, "bytes": size}
                for name, size, _, resident in STREAMS}
    if set(found) != set(expected) or any(found[name]["bytes"] != value["bytes"]
                                          for name, value in expected.items()):
        raise ValueError(f"ADS stream names or sizes differ from expectations: {found}")
    if require_source_forms and found != expected:
        raise ValueError(f"ADS storage differs from required resident/nonresident forms: {found}")
    return found


def validate(workspace: Path, cli: str, programs: dict[str, str], run=reader.read_payload,
             translate=None) -> dict:
    workspace = approve_workspace(workspace)  # No external tool runs before path approval.
    case = Path(tempfile.mkdtemp(prefix="formatter-ads-", dir=workspace)).resolve(strict=True)
    source, exfat, restored = (case / name for name in ("source.img", "exfat.img", "restored.img"))
    escrow = case / "exfat.img.starconverter-escrow"
    manifest = case / "streams.tsv"
    report = {"schema": "starconverter.formatter-ads.v1", "passed": False,
              "scope": "fresh unmounted regular-image ADS roundtrip; no activation qualification",
              "case_directory": str(case), "checks": [], "failures": [], "versions": {},
              "before_sha256": {}, "after_sha256": {}, "storage": {}, "payloads": []}
    step = "create-source"
    identities = {}

    def execute(label, command, limit=64 * 1024):
        nonlocal step
        step = label
        check = {"step": label, "command": command, "passed": False}
        report["checks"].append(check)
        try:
            code, output, error = run(command, timeout=120, stdout_limit=limit)
            check.update(exit_code=code, stdout=output.decode("utf-8", errors="replace")
                         if limit != reader.MAX_PAYLOAD else None,
                         stderr=error.decode("utf-8", errors="replace"))
            if code != 0:
                raise ValueError(f"tool exited {code}: {error.decode('utf-8', errors='replace')}")
            if len(output) > limit or len(error) > 4096:
                raise ValueError("tool output exceeds declared bound")
            check["passed"] = True
            return output
        except (OSError, ValueError, subprocess.TimeoutExpired) as failure:
            check["error"] = str(failure)
            raise

    def cli_path(path):
        if translate is not None:
            return translate(path)
        if os.name != "nt" and cli.lower().endswith(".exe"):
            result = execute(f"translate-{path.name}", ["wslpath", "-w", str(path)], 4096)
            value = result.decode("utf-8", errors="strict").strip()
            if not re.fullmatch(r"[A-Za-z]:\\[^\r\n\x00]+", value):
                raise ValueError("wslpath did not produce a Windows filesystem path")
            return value
        return str(path)

    def payload_checks(image, label):
        image_guard(image, case, identities[image.name])
        output = execute(f"{label}-storage", [programs["ntfsinfo"], "-v", "-F",
                                             "/payload.bin", str(image)])
        report["storage"][label] = parse_storage(output, require_source_forms=label == "source")
        for name, size, seed, _ in STREAMS:
            command = [programs["ntfscat"]]
            if name:
                command += ["-n", name]
            command += [str(image), "/payload.bin"]
            actual = execute(f"{label}-payload-{name or 'unnamed'}", command, reader.MAX_PAYLOAD)
            expected = payload(seed, size)
            check = {"image": label, "stream": name, "bytes": len(actual),
                     "actual_sha256": hashlib.sha256(actual).hexdigest(),
                     "expected_sha256": hashlib.sha256(expected).hexdigest(),
                     "passed": actual == expected}
            report["payloads"].append(check)
            if not check["passed"]:
                raise ValueError(f"binary ADS content mismatch for {name or 'unnamed'}")

    try:
        with source.open("xb") as stream:
            stream.truncate(IMAGE_BYTES)
        identities[source.name] = image_guard(source, case)
        with manifest.open("xb") as stream:
            stream.write(manifest_bytes())
        validate_manifest(manifest)
        for tool in TOOLS:
            if tool == "fsck.exfat":
                continue  # exfatprogs 1.2.2 requires an image even with -V.
            execute(f"version-{tool}", [programs[tool], "-V"])
            evidence = report["checks"][-1]
            report["versions"][tool] = evidence["stdout"] + evidence["stderr"]
        report["versions"]["starconverter"] = execute("version-cli", [cli, "--version"]).decode(
            "utf-8", errors="replace")
        step = "approve-format-source"
        image_guard(source, case, identities[source.name])
        execute("format-source", [programs["mkntfs"], "-F", "-Q", "-s", "512", "-c", "4096",
                                  "-p", "0", "-L", "SCADS", str(source)])
        for name, size, seed, _ in STREAMS:
            step = f"approve-populate-{name or 'unnamed'}"
            payload_path = case / f"{name or 'unnamed'}.bin"
            with payload_path.open("xb") as stream:
                stream.write(payload(seed, size))
            regular(payload_path, size)
            validate_manifest(manifest)
            image_guard(source, case, identities[source.name])
            command = [programs["ntfscp"]]
            if name:
                command += ["-N", name]
            command += [str(source), str(payload_path), "/payload.bin"]
            execute(f"populate-{name or 'unnamed'}", command)
        step = "approve-populated-source"
        image_guard(source, case, identities[source.name])
        report["before_sha256"][source.name] = digest(source)
        payload_checks(source, "source")
        execute("source-structure", [programs["ntfsinfo"], "-m", str(source)])
        execute("source-readonly-check", [programs["ntfsfix"], "-n", str(source)])
        step = "approve-convert-to-exfat"
        image_guard(source, case, identities[source.name])
        execute("convert-to-exfat", [cli, "convert-image", cli_path(source), cli_path(exfat),
                                     "--to", "exfat", "--mode", "escrow", "--escrow", cli_path(escrow)])
        step = "approve-exfat-candidate"
        identities[exfat.name] = image_guard(exfat, case)
        regular(escrow)
        report["before_sha256"][exfat.name] = digest(exfat)
        report["before_sha256"][escrow.name] = digest(escrow)
        # exfatprogs prints its version during normal checking; -V suppresses the check.
        execute("exfat-readonly-check", [programs["fsck.exfat"], "-n", str(exfat)])
        evidence = report["checks"][-1]
        report["versions"]["fsck.exfat"] = evidence["stdout"] + evidence["stderr"]
        step = "approve-restore-to-ntfs"
        image_guard(exfat, case, identities[exfat.name])
        execute("restore-to-ntfs", [cli, "convert-image", cli_path(exfat), cli_path(restored),
                                    "--to", "ntfs", "--mode", "escrow", "--restore-escrow", cli_path(escrow)])
        step = "approve-restored-candidate"
        identities[restored.name] = image_guard(restored, case)
        report["before_sha256"][restored.name] = digest(restored)
        payload_checks(restored, "restored")
        execute("restored-structure", [programs["ntfsinfo"], "-m", str(restored)])
        execute("restored-readonly-check", [programs["ntfsfix"], "-n", str(restored)])
    except (OSError, ValueError, UnicodeError, subprocess.TimeoutExpired) as error:
        report["failures"].append(f"{step}: {error}")
    finally:
        for name, before in report["before_sha256"].items():
            try:
                path = case / name
                if name in identities:
                    image_guard(path, case, identities[name])
                after = digest(path)
                report["after_sha256"][name] = after
                if before != after:
                    report["failures"].append(f"fixture bytes changed: {name}")
            except (OSError, ValueError) as error:
                report["failures"].append(f"post-validation hash {name}: {error}")
    report["passed"] = not report["failures"] and len(report["payloads"]) == 6
    return report


def write_report(path: Path, report: dict) -> None:
    with path.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write("\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("workspace", type=Path)
    parser.add_argument("--cli", required=True)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    approve_workspace(args.workspace)
    programs = {name: shutil.which(name) for name in TOOLS}
    if any(path is None for path in programs.values()):
        parser.error("required independent formatter/readers missing from PATH")
    report = validate(args.workspace, args.cli, programs)
    write_report(args.report, report)
    print(f"{'PASS' if report['passed'] else 'FAIL'}: formatter-origin ADS; artifacts {report['case_directory']}")
    for failure in report["failures"]:
        print(failure)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
