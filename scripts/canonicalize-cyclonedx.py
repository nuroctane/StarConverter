#!/usr/bin/env python3
"""Add a deterministic, source-bound serial number to a CycloneDX JSON SBOM."""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import sys
import uuid


MAX_SBOM_BYTES = 16 * 1024 * 1024
REPOSITORY = re.compile(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}\Z")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
COMPONENT = re.compile(r"[a-z0-9-]{1,64}\Z")


class CanonicalizationError(Exception):
    """The supplied SBOM cannot enter the deterministic release profile."""


def rejecting_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise CanonicalizationError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def expected_serial(repository: str, commit: str, component: str) -> str:
    identity = f"https://github.com/{repository}/commit/{commit}#sbom:{component}"
    return f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, identity)}"


def canonicalize(path: pathlib.Path, repository: str, commit: str, component: str) -> str:
    if not REPOSITORY.fullmatch(repository):
        raise CanonicalizationError("repository must be an owner/name GitHub identity")
    if not COMMIT.fullmatch(commit):
        raise CanonicalizationError("commit must be a lowercase 40-character SHA-1")
    if not COMPONENT.fullmatch(component):
        raise CanonicalizationError("component contains unsafe characters")

    if path.is_symlink():
        raise CanonicalizationError("SBOM must be a regular, non-symlink file")
    path = path.resolve(strict=True)
    if not path.is_file():
        raise CanonicalizationError("SBOM must be a regular, non-symlink file")
    if path.stat().st_size > MAX_SBOM_BYTES:
        raise CanonicalizationError("SBOM exceeds the 16 MiB attestation limit")
    raw = path.read_bytes()
    try:
        document = json.loads(
            raw,
            object_pairs_hook=rejecting_object,
            parse_constant=lambda value: (_ for _ in ()).throw(
                CanonicalizationError(f"non-finite JSON number: {value}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CanonicalizationError("SBOM is not strict UTF-8 JSON") from error
    if not isinstance(document, dict):
        raise CanonicalizationError("SBOM root must be an object")
    if document.get("bomFormat") != "CycloneDX" or document.get("specVersion") != "1.5":
        raise CanonicalizationError("SBOM must use the pinned CycloneDX 1.5 profile")
    if document.get("version") != 1:
        raise CanonicalizationError("SBOM version must be the integer 1")
    metadata = document.get("metadata")
    primary = metadata.get("component") if isinstance(metadata, dict) else None
    if not isinstance(primary, dict) or primary.get("name") != f"starconverter-{component}":
        raise CanonicalizationError("SBOM primary component does not match the requested identity")
    if not isinstance(document.get("components"), list) or not isinstance(
        document.get("dependencies"), list
    ):
        raise CanonicalizationError("SBOM components and dependencies must be arrays")

    serial = expected_serial(repository, commit, component)
    existing = document.get("serialNumber")
    if existing is not None and existing != serial:
        raise CanonicalizationError("SBOM contains a foreign or random serial number")
    document["serialNumber"] = serial
    encoded = (json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()
    if len(encoded) > MAX_SBOM_BYTES:
        raise CanonicalizationError("canonical SBOM exceeds the 16 MiB attestation limit")

    temporary = path.with_name(f".{path.name}.canonical.tmp")
    descriptor = None
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            descriptor = None
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
    return serial


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("sbom", type=pathlib.Path)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--component", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        serial = canonicalize(args.sbom, args.repository, args.commit, args.component)
    except (CanonicalizationError, OSError) as error:
        print(f"CycloneDX canonicalization failed: {error}", file=sys.stderr)
        return 1
    print(serial)
    return 0


if __name__ == "__main__":
    sys.exit(main())
