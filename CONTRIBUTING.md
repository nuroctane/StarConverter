# Contributing

StarConverter values correctness over breadth. Start with an image-backed reproducer and a failing
test. Any mutation change must document its invariants, commit point, rollback behavior, and results
under injected interruption.

Before submitting work:

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cd lab
go test ./...
```

Raw-device support is not an acceptable shortcut for missing image-level coverage. Read
`docs/ARCHITECTURE.md`, `docs/SAFETY.md`, and `docs/DESIGN_SYSTEM.md` first.
