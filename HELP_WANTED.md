# Help wanted

Jay Squad Sec is open to contributions. Below is the hardening work that would make it stronger, roughly in order of impact. Pick anything, comment on (or open) an issue so others know you are on it, and see [CONTRIBUTING.md](CONTRIBUTING.md) to get started.

Found a vulnerability instead? Please report it privately, see [SECURITY.md](SECURITY.md).


### Release builds instead of a committed binary

**High impact.** `bin-linux-x86_64/jaysec-agent` is a prebuilt binary in git, which nobody can verify against the source. Build it in CI and publish it as a release asset with a SHA-256 checksum (and ideally a build provenance attestation), then drop the binary from the repo.

### Fuzz the event parsers

**Medium.** Add `cargo fuzz` targets for the code that parses sensor input.

### Clippy with warnings as errors

**Good first issue.** Add `cargo clippy -- -D warnings` to CI and fix what it reports.
