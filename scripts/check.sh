#!/usr/bin/env sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_root"

echo '[ STARCONVERTER :: CHECK ]'
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo check --manifest-path ./fuzz/Cargo.toml --bins

if command -v go >/dev/null 2>&1; then
  unformatted=$(gofmt -l ./lab)
  test -z "$unformatted" || { echo "Go files need formatting: $unformatted" >&2; exit 1; }
  (cd lab && go test ./...)
else
  echo '[WARN] Go toolchain missing; lab checks skipped locally.' >&2
fi

echo '[READY] all available checks passed'
