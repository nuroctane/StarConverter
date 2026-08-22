# StarConverter parser fuzzing

These `cargo-fuzz` targets exercise only StarConverter's pure, in-memory
filesystem parsers and versioned escrow decoder. They do not open paths, images,
volumes, or devices. Every target rejects inputs above a small explicit cap
before invoking a parser.

Install nightly and `cargo-fuzz`, then run all targets from the repository root:

```text
rustup toolchain install nightly
cargo install cargo-fuzz --locked
cargo +nightly fuzz build
cargo +nightly fuzz run boot_sectors -- -max_len=131072
```

Replace `boot_sectors` with any target listed in `fuzz/Cargo.toml`. The CI smoke
job runs every target for a fixed number of iterations; longer local campaigns
should retain any minimized regression input under `fuzz/corpus/<target>/`.
