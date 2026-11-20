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
    public static final int ERR_UPDATE_NOT_CONFIGURED = 10;
    public static final int ERR_UPDATE_REJECTED = 11;

    /** ABI version this Java/Kotlin code was written against. */
    public static final int EXPECTED_ABI = 5;

    /** Returns a handle, or 0 if the engine limit is reached. */
    public static native long nativeNew(long bootNonce);

    /** Returns OK, or ERR_BAD_HANDLE if already freed. Safe concurrently. */
    public static native int nativeFree(long handle);

    public static native int nativeSubmit(
            long handle, int pid, long generation,
            byte[] packageIdentity, byte[] kind, byte[] detail, long atMs);

    /** Newline-separated UTF-8 alert lines; empty if none; null on error. */
    public static native byte[] nativeTakeAlerts(long handle, int maxBytes);

    /** Load persisted, builder-signed rules. Returns version, or a negative error code. */
    public static native long nativeLoadRules(long handle, byte[] storageDir);

    /** Verify, install and activate a signed data-only patch. Returns version, or a negative error code. */
    public static native long nativeApplyRules(long handle, byte[] storageDir, byte[] signedPatch);

    /** App-level observation (no process): app_signer_changed, sensitive_permission_granted, new_app_with_sensitive_access. */
    public static native int nativeSubmitAppEvent(long handle, byte[] packageIdentity, byte[] kind, byte[] detail);

    /** (action << 32) | score in thousandths, or a negative error code. Action: 0 Allow .. 4 Block. */
    public static native long nativeAppAssessment(long handle, byte[] packageIdentity);

    public static native int nativeAbiVersion();
}
