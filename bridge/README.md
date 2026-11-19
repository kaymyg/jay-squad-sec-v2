# Android bridge scaffold

This is a Rust C-ABI boundary intended to be wrapped by a future Kotlin/JNI
module. It is **not yet a complete JNI bridge** and is not part of the root
Cargo workspace until its ABI, lifecycle, and concurrency contracts are
reviewed and compiled in the Android NDK build.

## Current ABI v2

- `jss_bridge_abi_version`: returns ABI version 2.
- `jss_engine_new`: creates an alert-only engine handle.
- `jss_engine_submit_event`: accepts bounded byte buffers, validates the
  event through the protocol crate, and serializes access to the engine.
- `jss_engine_free`: releases the opaque handle.

## Hardening included in this branch

- Replaced unbounded NUL-terminated C strings with explicit pointer/length
  byte buffers and strict maximum lengths (kind 64 bytes, identity 512 bytes,
  detail limited by the protocol's 4 KiB limit).
- Rejects invalid UTF-8, empty required fields, zero PID and zero process
  generation before the event reaches the engine.
- Uses a mutex to serialize concurrent event submissions per handle and
  returns an explicit error if the mutex is poisoned.
- Keys process identity by `(pid, process_generation)`, so PID reuse can be
  represented without silently reusing the previous process identity.
- Removes the identity mapping after a process-exit event.
- Contains Rust panics at the C ABI boundary.

## FFI safety contract that remains

A raw-pointer C ABI cannot defend against an invalid pointer supplied by a
hostile caller. The caller must provide readable buffers for the declared
lengths, pass a live handle, and prevent `jss_engine_free` from racing with
in-flight calls. The Kotlin wrapper must own the handle exactly once, serialize
close against submissions, and never expose this ABI to untrusted native code.

The Android adapter must provide a monotonically increasing process
generation and canonical package identity including the signing-certificate
digest. A PID alone is not a durable process identity.

## Required before Android integration

1. Add a generated C header and JNI registration layer.
2. Implement a Kotlin `Closeable` owner with synchronized close/submission.
3. Add native tests for malformed buffers, maximum lengths, PID reuse,
   concurrent submissions and close lifecycle.
4. Return structured decisions and incident IDs rather than discarding tick
   output.
5. Cross-compile for supported Android ABIs with the Android NDK and run
   integration tests on physical, non-rooted devices.
6. Fuzz the FFI boundary and review pointer/ownership assumptions independently.
7. Keep alert-only behaviour as the default. Do not enable unsupported Android
   process killing or arbitrary permission revocation.

This branch is a hardened scaffold, not a working Android app or a claim that
the FFI is production-safe.
