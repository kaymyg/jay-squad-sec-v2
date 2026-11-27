package com.jaysquadsec.bridge;

/**
 * Raw JNI declarations for the Rust bridge (ABI v3). App code should use the
 * Kotlin {@code JaySquadSecEngine} wrapper, not this class directly.
 *
 * <p>Handles are opaque registry IDs, not pointers: a stale, freed or bogus
 * handle returns {@link #ERR_BAD_HANDLE} (or 0/null) and can never corrupt
 * memory. All byte arrays are copied by the native side.
 */
public final class NativeBridge {
    private NativeBridge() {}

    public static final int OK = 0;
    public static final int ERR_NULL = 1;
    public static final int ERR_INVALID = 2;
    public static final int ERR_PANIC = 3;
    public static final int ERR_POISONED = 4;
    public static final int ERR_CAPACITY = 5;
    public static final int ERR_IDENTITY_MISMATCH = 6;
    public static final int ERR_BAD_HANDLE = 7;
    public static final int ERR_BUFFER_TOO_SMALL = 8;
    public static final int ERR_STALE_GENERATION = 9;

    /** ABI version this Java/Kotlin code was written against. */
    public static final int EXPECTED_ABI = 3;

    /** Returns a handle, or 0 if the engine limit is reached. */
    public static native long nativeNew(long bootNonce);

    /** Returns OK, or ERR_BAD_HANDLE if already freed. Safe concurrently. */
    public static native int nativeFree(long handle);

    public static native int nativeSubmit(
            long handle, int pid, long generation,
            byte[] packageIdentity, byte[] kind, byte[] detail, long atMs);

    /** Newline-separated UTF-8 alert lines; empty if none; null on error. */
    public static native byte[] nativeTakeAlerts(long handle, int maxBytes);

    public static native int nativeAbiVersion();
}
