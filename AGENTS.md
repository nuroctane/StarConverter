# Agent instructions

## Safety boundary

StarConverter operates on filesystem images and, eventually, physical block devices. Treat every
write path as destructive until it has passed the image-only crash-consistency suite.

- Raw-device writes are forbidden until the support gate in `docs/SAFETY.md` is satisfied.
- Never infer a target device from drive order. Require a stable device identifier and a second,
  human-readable confirmation.
- Refuse dirty, mounted, system, encrypted, dynamic, pooled, or otherwise unsupported volumes.
- A conversion implementation is incomplete without rollback and injected-crash tests.
- Keep filesystem parsing separate from mutation. Analysis must remain usable without elevation.

## Architecture

- `crates/starconverter-core`: pure Rust planning, capability, and safety model.
- `crates/starconverter-cli`: scriptable frontend; analysis-only in the scaffold phase.
- `crates/starconverter-gui`: native Rust desktop frontend.
- `lab`: Go image-matrix and crash-test tooling.
- `docs`: architecture, safety, design system, and roadmap sources of truth.

## Ship / push / deploy (mandatory)

When the user says **ship**, **push**, **deploy**, **put on main**, **release**, **publish**, or similar:

1. Read and execute `C:\Users\david\.agents\SHIP.md`.
2. Or run `powershell -File $env:USERPROFILE\.agents\ship.ps1 -Repo StarConverter [-Message "..."]`.
3. Skill: `ship-deploy`.

Pipeline: commit on Laboratory `main` -> push `origin main` -> backup 7z to
`D:\BACKUP\CODE Backups\StarConverter\`.

Never bare-push without backup. Report the commit, remote ref, and full backup path.
