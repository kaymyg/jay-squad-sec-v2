# Android bridge (ABI v3)

The boundary between the Android app and the Rust security engine. It has
two front doors over one implementation:

- **JNI** for the Kotlin wrapper (`jvm/kotlin/.../JaySquadSecEngine.kt`),
  via the native methods declared in `jvm/src/.../NativeBridge.java`;
- a **C ABI** (`jss_*`) for native callers and tests.

It is kept out of the root Cargo workspace (it builds as its own workspace)
until it is cross-compiled with the Android NDK.

## Ownership contract

Handles are **opaque registry IDs**, not pointers. A global registry maps IDs
to reference-counted engines, and IDs are never reused (0 is invalid). Every
call looks its handle up and holds its own reference for the length of the
call. As a result:

| Caller mistake | Result |
|---|---|
| Double close | `ERR_BAD_HANDLE` |
| Use after close | `ERR_BAD_HANDLE` (JNI `takeAlerts`: `null`) |
| Close while other threads are inside calls | Safe: the handle stops resolving at once and the engine is dropped when the last in-flight call returns |
| Bogus or zero handle | `ERR_BAD_HANDLE` |

The Kotlin wrapper adds an idempotent, thread-safe `close()` and maps error
codes to exceptions. Close it explicitly or with `use { }`. There is no
GC-based cleanup, because `java.lang.ref.Cleaner` needs Android API 33. A
leaked engine only holds one engine slot until the app process ends; it is
never unsafe.

The one obligation left on a caller applies only to the **C ABI**: a buffer
passed as pointer and length must be readable for that length during the
call. The JNI path copies Java arrays itself (`GetByteArrayRegion`, after a
length check), so it has no such obligation.

## Trusted time

Each engine runs on its own monotonic clock. The caller's `at_ms` is checked
and kept on the event as information, but never drives risk decay. Trusting
it let a single far-future timestamp decay every process's risk to zero
(found in review; a regression test covers it).

## Identity and process lifecycle

Events are keyed by `(pid, process_generation)`. The Android adapter must
**increase** the generation whenever a PID is reused, and must supply a
canonical package identity (package name plus signing-certificate digest).

- A live `(pid, generation)` can never change identity. The attempt returns
  `ERR_IDENTITY_MISMATCH` and is recorded as an alert.
- One PID is one live process. A new generation retires the old one, because
  Android often kills processes without any exit event. A `process_exit` also
  retires the identity. Either way the engine's state for it is dropped, so a
  reused PID never inherits the previous process's risk.
- A retired generation, or any lower one, is refused with
  `ERR_STALE_GENERATION` and recorded as an alert, so a retired process can't
  come back with a clean score or a new identity.
- When the identity table is full, the **lowest-risk, least recently active**
  identity is evicted (with an alert), never the suspicious ones. A full table
  can't switch detection off.

## Bounds

| Limit | Value | When reached |
|---|---|---|
| Live engines per process | 8 | `new` returns 0 |
| Live identities per engine | 4096 | Lowest-risk idle identity evicted, with an alert |
| Retired PIDs remembered per engine | 65,536 | Oldest forgotten first |
| Queued alert lines per engine | 256 | Oldest dropped; next `take` starts with a `[bridge] N alerts dropped` line |
| Alert line length | 1024 bytes | Truncated at a char boundary |
| Package identity / kind / detail | 512 / 64 / 4096 bytes | `ERR_INVALID` |
| Engine audit ledger | 1024 entries (ring, in `core`) | Oldest dropped; consumers use sequence numbers |

All text input must be valid UTF-8 without control characters. Detail is also
checked for bidi-override and zero-width characters by the protocol crate.

## Error codes

`OK 0`, `ERR_NULL 1`, `ERR_INVALID 2`, `ERR_PANIC 3`, `ERR_POISONED 4`,
`ERR_CAPACITY 5`, `ERR_IDENTITY_MISMATCH 6`, `ERR_BAD_HANDLE 7`,
`ERR_BUFFER_TOO_SMALL 8`, `ERR_STALE_GENERATION 9`. A panic inside the bridge is caught and reported
as `ERR_PANIC`, never unwound into the JVM or a C caller. A poisoned engine
lock makes only that handle unusable.

## Alerts

Engines are always alert-only. `take_alerts` returns newline-separated UTF-8
lines, oldest first, and never splits a line. Lines that don't fit stay
queued for the next call. The C ABI needs a buffer of at least
`MIN_ALERT_BUFFER` (1025) bytes; JNI raises smaller requests to that.

## Testing

```
cargo test --manifest-path bridge/Cargo.toml   # Rust: C ABI + JNI table pin
bridge/jvm/run-jvm-test.sh                     # live JVM, -Xcheck:jni
```

The JVM test loads the real shared library and calls the same native methods
the Android app calls. It covers detection flowing out to Java, double close,
use after close, closing under 8 concurrent submitting threads (20 rounds),
null arrays, hostile input, identity changes, capacity, and the three
detection-bypass findings from review (far-future timestamp, revived
generation, capacity exhausted by missed exits). Android's runtime uses the
same JNI ABI.

Each review regression test was checked to fail when its bug is put back.

## Not done yet

- Cross-compile with the Android NDK (arm64-v8a, armeabi-v7a, x86_64) and run
  on physical, non-rooted devices. Not possible in the current build
  environment: no NDK.
- Compile `JaySquadSecEngine.kt` in the Android project. No `kotlinc` was
  available here; the JNI methods it wraps are tested from Java.
- Return structured decisions and incident IDs instead of alert text.
- Load verified rule updates through the bridge (the `apply` crate exists;
  it isn't wired into the bridge yet).
- Fuzz the C ABI and get an independent review of the unsafe code.
- Keep alert-only as the default. Do not enable Android process killing or
  arbitrary permission revocation, which ordinary apps cannot do.
