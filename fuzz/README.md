# Telemetry parser fuzzing

These are developer-only `cargo-fuzz` targets. They are deliberately kept in
a nested workspace and do not add a dependency to the shipped core, Android
application, or verify-only update crate.

## Prerequisites

Install the Rust nightly toolchain and cargo-fuzz:

```powershell
rustup toolchain install nightly
cargo +nightly install cargo-fuzz
```

## Run

From the repository root:

```powershell
cargo +nightly fuzz run parse_proc_net_tcp
cargo +nightly fuzz run parse_tasklist_csv
cargo +nightly fuzz run parse_netstat
cargo +nightly fuzz run parse_reg_query
```

Each target ignores inputs above 1 MiB so a single fuzz input cannot create an
unbounded test allocation. The harnesses currently assert the most basic
robustness property: arbitrary byte input, including invalid UTF-8, must not
panic. This is an initial harness, not evidence that the parsers are correct,
bounded in all internal allocations, or free of semantic parsing bugs.

Run fuzzers for a recorded duration and retain any crash corpus and regression
test. Before production, add explicit limits inside parser APIs themselves,
not only in these harnesses, and add structured semantic invariants for each
format.
