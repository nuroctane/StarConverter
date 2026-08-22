# Security policy

StarConverter will eventually handle raw block devices. A defect can cause permanent data loss even
when it is not a conventional security vulnerability.

Do not test unpublished write paths on a device containing valuable data. Use disposable image files
until the physical-device gate in `docs/SAFETY.md` has been explicitly satisfied.

Report vulnerabilities and data-integrity defects privately to `nuroctane@gmail.com`. Include the
StarConverter commit, operating system, source and target filesystem geometry, an anonymized planner
report, and the smallest reproducible image when possible. Do not attach personal disk images.

The `Dependency security` workflow scans both Rust lockfiles with pinned `cargo-audit` and scans the
Go laboratory with pinned `govulncheck` on dependency changes and every Monday. Vulnerabilities and
yanked Rust packages fail the build. The current `RUSTSEC-2026-0192` unmaintained warning is not a
vulnerability: `ttf-parser 0.25.1` arrives through `eframe -> winit -> sctk-adwaita -> ab_glyph`.
It remains visible in every audit and must be reassessed when that GUI dependency chain updates.
Dependabot also proposes weekly Cargo, Go module, and GitHub Actions updates; those proposals must
pass the same cross-platform, parser-fuzz, packaging, and dependency-security checks as human work.
