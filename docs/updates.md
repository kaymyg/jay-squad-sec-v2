# Signed rule updates

Jay Squad Sec runs offline. The only thing it ever accepts from outside is a
**rules patch**, and only if it carries a valid ed25519 signature from the
builder's private key. Patches change **detection data only** (risk weights,
policy thresholds, decay half-life). Engine code is never patched, so an update
has no code-injection surface.

## What this guarantees

- **Authenticity.** A patch is applied only if it verifies against the builder
  public key compiled into the product. The private key never ships.
- **Product binding.** A patch signed for one product (e.g. the Android app)
  is rejected by another (e.g. the desktop agent).
- **No downgrade or replay.** A patch must be strictly newer than the
  installed version.
- **Detection cannot be switched off by an update, even a validly signed
  one.** On-device validation enforces semantic bounds, not just signs:
  - threat indicators: weight in [1, 100] (none can be silenced);
  - neutral high-volume events (file writes, network connects, process
    start/exit): [0, 5] (no risk laundering, no mass false positives);
  - good evidence (signed binary, stable tick): [-20, 0] (being signed cannot
    cancel an injection + credential-theft chain);
  - half-life in [10 s, 1 h];
  - 5 <= monitor < restrict < suspend < block <= 400, each step at least 5;
  - reachability: the five strongest indicators must sum to at least block_at.

  A property test runs a full attack chain through the engine under defaults
  and the most lenient configs validation accepts, and requires Block in every
  case. The risk and observer functions also fail closed (NaN escalates to
  Block / maximum observation) even when handed an unvalidated config.
- **Tamper-evident installed state.** The installed state is the signed patch
  itself, re-verified on every load. Editing it on disk, or dropping in a file
  signed by another key, has no effect. Both the current and previous state
  are verified and the **highest verified version wins**, so swapping an older
  genuine patch into the current slot does not downgrade the rules; falling
  back to the previous state is reported as a possible-tampering warning.
- **Hostile storage directory.** State paths must be regular files: symlinks,
  FIFOs and directories are refused without being opened (no reading through a
  planted link, no hang on a FIFO). Temp files are unique and created
  exclusively, so a planted symlink cannot redirect a write elsewhere.
- **Version floor.** Each build can set a minimum accepted rules version
  (`MIN_RULES_VERSION` in the agent); patches below it are rejected and stored
  states below it ignored.
- **Crash safety.** Installs are atomic (temp file, fsync, rename, directory
  fsync). A crash leaves either the complete old state or the complete new one.
- **Minimal footprint.** Shipped builds are verify-only: one external crate
  (`ed25519-compact`), no RNG, no signing code.

## What this does NOT guarantee

A signature proves a patch was authorised by whoever holds the private key.
It does not, on its own:

- protect a device that is already compromised at the OS or kernel level;
- stop runtime code injection into the running app (that is a platform and
  app-hardening problem, tracked separately);
- protect the private key itself: if the key leaks, an attacker can sign
  patches. Keep it offline and backed up securely;
- fully stop a downgrade by someone who can **delete or overwrite** files in
  the state directory: removing the current state falls back one step to the
  previous verified patch (with a tamper warning); removing both reverts to
  compiled-in defaults. Every outcome is rules the builder actually signed,
  all passing validation. `MIN_RULES_VERSION` bounds how far back this can go
  (raise it each release); platform storage protection (Android app-private
  storage) and a hardware-backed high-water mark (Android Keystore, planned)
  are the remaining controls;
- support two processes applying updates to one state directory at once
  (applies are serialized within a process only);
- replace independent security testing.

## Builder workflow (offline machine)

Build the tools once: `cargo build --release --manifest-path tools/signer/Cargo.toml`
(binaries in `tools/signer/target/release/`).

```
# 1. One-time: generate the signing keypair. Keep the .key offline.
jaysec-keygen --out signing.key --pub signing.pub
#    Paste the printed BUILDER_PUBLIC_KEY constant into the product
#    (EMBEDDED_PUBLIC_KEY in the agent) for release builds.

# 2. Author rules as text (every key required; validation errors are exact).
jaysec-rules export-defaults rules.txt
$EDITOR rules.txt
jaysec-rules compile rules.txt rules.bin

# 3. Sign for a specific product and a strictly increasing version
#    (1 ..= 4294967295; the signer refuses anything else).
jaysec-sign --key signing.key --product jay-squad-sec-agent \
            --version 1 --payload rules.bin --out rules-v1.jssp

# 4. Self-check exactly as the device will, then inspect contents.
jaysec-verify --pub signing.pub --product jay-squad-sec-agent --current 0 --patch rules-v1.jssp
jaysec-rules show rules-v1.jssp
```

## Device side (desktop agent)

```
agent --update-dir STATE_DIR --apply-patch rules-v1.jssp   # verify + install
agent --update-dir STATE_DIR                               # load verified rules
```

Development builds without an embedded key also accept `--pubkey-file`. Once
`EMBEDDED_PUBLIC_KEY` is set, `--pubkey-file` is ignored, so whoever controls
the command line cannot substitute their own key.

## Files

| Component | Location |
|---|---|
| Rules model and validation | `core/src/rules.rs` |
| Signature verification and patch format | `update/` |
| Atomic, self-authenticating install | `apply/` |
| Builder tools (never shipped) | `tools/signer/` |
