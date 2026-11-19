# Android bridge scaffold

This is a Rust C-ABI boundary intended to be wrapped by a future Kotlin/JNI
module. It is **not yet a complete JNI bridge** and is not part of the root
Cargo workspace until its ABI, lifecycle, and concurrency contracts are
reviewed and compiled in the Android NDK build.

## Initial ABI

- jss_bridge_abi_version: ABI compatibility check.
- jss_engine_new: creates an alert-only engine handle.
- jss_engine_submit_event: validates an event through the protocol crate.
- jss_engine_free: releases the opaque handle.

## Required before Android integration

1. Replace PID-only identity with Android package identity, signing-certificate
   digest and process lifecycle generation, handling PID reuse.
2. Define Kotlin ownership using a single Closeable wrapper and prevent
   double-free/use-after-free.
3. Serialize calls per handle or add a reviewed synchronization strategy.
4. Add bounded C-string length checks before decoding. The current scaffold
   assumes caller-provided NUL termination and must not be exposed directly to
   untrusted native callers.
5. Return structured decisions and incident IDs rather than discarding tick output.
6. Add JNI registration, Android NDK cross-compilation, ABI tests and fuzzing
   of all FFI inputs before release.
7. Keep alert-only behaviour as the default. Do not enable unsupported Android
   process killing or arbitrary permission revocation.

This scaffold establishes module boundaries; it is not a working Android app
or production-safe FFI.
