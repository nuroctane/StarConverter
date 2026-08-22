# Portable release verification

StarConverter packages are **unsigned engineering pre-alpha builds**. They support read-only image
inspection, exact conversion preview, and copy-based conversion to a newly created regular image.
They do not authorize raw-device access or in-place filesystem activation. Do not use them as a
substitute for a backup, and do not dismiss an operating-system security warning until you have
verified the download and accepted the pre-alpha risk.

## Published files

A tag such as `v0.1.0` produces these deterministic names:

| Target | Archive |
| --- | --- |
| Windows x64 | `starconverter-v0.1.0-x86_64-pc-windows-msvc.zip` |
| Linux x64 | `starconverter-v0.1.0-x86_64-unknown-linux-gnu.tar.gz` |
| macOS Intel | `starconverter-v0.1.0-x86_64-apple-darwin.tar.gz` |
| macOS Apple Silicon | `starconverter-v0.1.0-aarch64-apple-darwin.tar.gz` |

Every archive contains the `starconverter` CLI, the `starconverter-gui` desktop executable,
`README.md`, `LICENSE`, and this release guide. The release also contains:

- one `<archive>.inventory.json` beside each archive, recording its digest, size, target, normalized
  build epoch, and the exact path, mode, size, and SHA-256 of every member;
- `ARCHIVE-SUBJECTS.txt` and `PROVENANCE-SUBJECTS.txt`, the immutable checksum inputs supplied to
  the SBOM and provenance attestation steps;
- `SHA256SUMS.txt`, covering every published file except the checksum file itself;
- separate CycloneDX 1.5 JSON dependency manifests for the CLI, core, and GUI;
- a SLSA build-provenance Sigstore bundle; and
- three Sigstore bundles binding the portable archives to the CLI, core, and GUI SBOMs.

A manual workflow run uses `manual-<12-character-commit>` in place of the tag and only retains a
GitHub Actions artifact. It does not create a GitHub Release.

## Verify the bytes

Download `SHA256SUMS.txt` and the desired archive into the same directory. On Linux:

```bash
grep "  starconverter-v0.1.0-x86_64-unknown-linux-gnu.tar.gz$" SHA256SUMS.txt \
  | sha256sum --check --strict
```

On macOS:

```bash
expected="$(awk '/starconverter-v0.1.0-aarch64-apple-darwin.tar.gz$/ { print $1 }' SHA256SUMS.txt)"
actual="$(shasum -a 256 starconverter-v0.1.0-aarch64-apple-darwin.tar.gz | awk '{ print $1 }')"
test -n "$expected" && test "$actual" = "$expected"
```

On Windows PowerShell:

```powershell
$name = 'starconverter-v0.1.0-x86_64-pc-windows-msvc.zip'
$expected = (Select-String -LiteralPath SHA256SUMS.txt -Pattern "  $([regex]::Escape($name))$").Line.Split()[0]
$actual = (Get-FileHash -LiteralPath $name -Algorithm SHA256).Hash.ToLowerInvariant()
if (-not $expected -or $actual -ne $expected) { throw 'StarConverter checksum mismatch' }
```

A checksum from the same release detects corruption, but by itself does not establish who produced
the release. Verify the GitHub attestation as the authenticity check.

The adjacent inventory is a deterministic, machine-readable description of the archive rather
than an additional trust root. Its `archiveSha256` must match the archive, and its member list must
exactly contain the two executables plus `README.md`, `LICENSE`, and `RELEASE.md`. CI rejects extra,
duplicate, encrypted, linked, wrong-architecture, or non-canonical members and refuses inventory
drift. It then extracts only the packaged CLI into a temporary directory and runs the read-only
`demo` smoke test. This tests the bytes inside the archive, not merely the build-tree executable.

## Verify provenance and SBOM attestations

With GitHub CLI installed and authenticated if the repository requires it:

```bash
gh attestation verify starconverter-v0.1.0-x86_64-unknown-linux-gnu.tar.gz \
  --repo nuroctane/StarConverter \
  --signer-workflow nuroctane/StarConverter/.github/workflows/release.yml
```

This checks the artifact digest, Sigstore signature, GitHub workflow identity, and repository. The
release also ships the bundles for explicit or offline-policy verification:

```bash
gh attestation verify starconverter-v0.1.0-x86_64-unknown-linux-gnu.tar.gz \
  --repo nuroctane/StarConverter \
  --signer-workflow nuroctane/StarConverter/.github/workflows/release.yml \
  --bundle starconverter-v0.1.0-provenance.sigstore.json
```

The provenance bundle covers all archives, their canonical inventory documents, and the standalone
SBOM documents. `PROVENANCE-SUBJECTS.txt` preserves that exact subject set; it is not replaced when
the final release checksum file is assembled. Each `*-sbom.sigstore.json` bundle binds all four
archives to the named CycloneDX document using the exact subjects in `ARCHIVE-SUBJECTS.txt`. CI
verifies every subject against the freshly generated offline bundle before upload. The JSON SBOMs
describe dependencies for all Cargo targets so platform-conditional dependencies are not silently
omitted.

## Signing and operating-system warnings

The executables are not Authenticode-signed, Apple Developer ID-signed, or notarized. Windows
SmartScreen and macOS Gatekeeper may therefore warn or block. That warning is expected, but it is
not proof that a file is safe. First compare its SHA-256 and verify its GitHub attestation. Avoid
system-wide security-policy changes; if you choose to run a verified build, use the narrow,
per-application review flow offered by the operating system.

Linux archives are built on Ubuntu 24.04 and dynamically use the host graphics/window libraries.
They are intended for compatible x86-64 glibc desktop systems, not as universal static Linux
binaries. macOS packages target macOS 15 runners. Windows packages target 64-bit MSVC Windows.

These are portable archives, not installed applications: there is no MSI/MSIX, signed `.app`/DMG,
PKG, AppImage, DEB, or RPM, and no upgrade, uninstall, file-association, Start-menu, or application
bundle integration testing. CI smoke-tests the packaged CLI because launching and assessing the GUI
requires a native interactive session. Signed native packages and installed-package tests remain
release blockers for any claim beyond the unsigned engineering pre-alpha channel.

## Reproducibility boundary

The workflow reduces accidental variance by:

- using Rust 1.95.0 and `cargo build --locked`;
- selecting explicit runner operating systems and target triples;
- disabling incremental compilation and remapping the workspace source path;
- deriving archive and SBOM timestamps from the source commit;
- sorting archive entries and normalizing archive ownership, modes, and gzip headers; and
- independently reopening each archive, checking its exact schema, and emitting a canonical JSON
  member inventory before it can leave the platform build job; and
- pinning cargo-cyclonedx 0.5.9 and checking the downloaded generator's SHA-256 before use.

The project does **not** yet claim independently reproducible, byte-for-byte native binaries.
GitHub-hosted runner images, system linkers, SDKs, and native desktop dependencies can change while
the runner label remains the same. `SHA256SUMS.txt` identifies the exact published bytes; it is not
evidence that a later rebuild must have the same digest.

For a comparison build, check out the exact commit recorded in the provenance, install Rust 1.95.0,
and build both packages with the locked dependency graph and the matching target:

```bash
cargo +1.95.0 build --locked --release --target x86_64-unknown-linux-gnu \
  --package starconverter-cli --package starconverter-gui
```

Compare unpacked binaries and SBOMs as well as the outer archive. Any mismatch is unresolved until
the toolchain, runner image, linker, SDK, environment, and archive inputs have been accounted for.

## Maintainer release gate

1. Confirm CI is green for the intended commit and the completion matrix still describes the
   pre-alpha capability boundary accurately.
2. Confirm `Cargo.toml` contains the intended workspace version.
3. Create an annotated or signed tag named exactly `v<workspace-version>` and push that tag. The
   workflow rejects aliases, slashed tags, version mismatches, and commits not reachable from
   `origin/main`.
4. Let every build, packaged-byte smoke test, inventory, SBOM, checksum, and attestation job finish.
   Do not publish local replacement files under the same version.
5. Download one published archive and its inventory, verify the archive with
   `gh attestation verify`, compare its digest to both `SHA256SUMS.txt` and `archiveSha256`, and
   smoke-test it without granting raw-device access.

The workflow uploads into a draft, confirms that every expected asset name is present, and only
then publishes the pre-release. It refuses to overwrite an existing GitHub Release. An interrupted
upload remains a draft for maintainer review. Correct a bad published release with a new version
and a documented explanation instead of silently replacing previously published bytes.
