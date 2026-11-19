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
- **Detection cannot be switched off by an update.** On-device validation
  rejects any rules where a threat indicator weight is not positive, where a
  high-volume neutral event (file writes, network connects, process start or
  exit) is negative (that would let a process launder its own risk score), or
  where thresholds are not finite and strictly increasing.
- **Tamper-evident installed state.** The installed state is the signed patch
  itself, re-verified on every load. Editing it on disk, or dropping in a file
  signed by another key, has no effect: the product falls back to the previous
  verified state, then to the compiled-in defaults.
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
- stop a downgrade if an attacker can **delete** the app's state files: the
  product reverts to compiled-in defaults (version 0), after which an older,
  genuinely builder-signed patch could be re-applied. That can only install
  rules the builder actually signed, all of which pass validation, but it is a
  downgrade. Platform storage protection (Android app-private storage) is the
  control here;
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

# 3. Sign for a specific product and a strictly increasing version (>= 1).
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
