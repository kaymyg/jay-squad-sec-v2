package com.jaysquadsec.bridge

import java.nio.charset.StandardCharsets
import java.util.concurrent.atomic.AtomicLong

/**
 * App-facing handle to one alert-only Jay Squad Sec engine (bridge ABI v3).
 *
 * Ownership contract, enforced on both sides:
 * - The native handle is an opaque registry ID, never a pointer. Even if this
 *   class were misused, a stale handle yields an error, never memory corruption.
 * - [close] is idempotent and thread-safe, and may be called while other
 *   threads are inside [submit] or [takeAlerts]: those calls either complete
 *   normally or report [EngineClosedException]; the native side keeps the
 *   engine alive until in-flight calls finish.
 * - [close] must be called explicitly (or use `use { }`). There is deliberately
 *   no GC-based cleanup: `java.lang.ref.Cleaner` needs Android API 33, and GC
 *   timing is unreliable anyway. A leaked engine only holds one of the
 *   per-process engine slots until the app process ends; it is never unsafe.
 *
 * Works on any API level that can load the native library.
 *
 * NOTE: not compiled in the Rust repository's environment (no kotlinc). It is a
 * thin layer over [NativeBridge], whose JNI behaviour is covered by
 * bridge/jvm/test/BridgeTest.java. Build it in the Android project.
 */
class JaySquadSecEngine private constructor(handle: Long) : AutoCloseable {

    /** Native handle, or 0 once closed. */
    private val handle = AtomicLong(handle)

    /**
     * Submit one normalized observation.
     *
     * @param pid OS process id (> 0).
     * @param generation must increase whenever the OS reuses [pid] (> 0). A new
     *   generation retires the previous process on that pid.
     * @param packageIdentity canonical package name plus signing-certificate
     *   digest, e.g. "com.example.app:sha256:<hex>". Fixed for a live process.
     * @param kind canonical event kind, e.g. "network_connect".
     * @param detail bounded, control-character-free detail ("" if none).
     * @param atMs event time in milliseconds (>= 0). Informational only: the
     *   engine runs on its own monotonic clock, so a wrong or hostile timestamp
     *   cannot change risk decay.
     */
    fun submit(pid: Int, generation: Long, packageIdentity: String, kind: String, detail: String, atMs: Long) {
        val h = liveHandle()
        val code = NativeBridge.nativeSubmit(
            h, pid, generation, packageIdentity.utf8(), kind.utf8(), detail.utf8(), atMs,
        )
        throwIfError(code)
    }

    /** Remove and return queued alert lines, oldest first (empty if none). */
    fun takeAlerts(maxBytes: Int = DEFAULT_ALERT_BYTES): List<String> {
        val h = liveHandle()
        val bytes = NativeBridge.nativeTakeAlerts(h, maxBytes)
            ?: if (handle.get() == 0L) {
                throw EngineClosedException() // closed concurrently
            } else {
                throw IllegalStateException("security engine unavailable (internal failure)")
            }
        if (bytes.isEmpty()) return emptyList()
        return String(bytes, StandardCharsets.UTF_8).split('\n').filter { it.isNotEmpty() }
    }

    /** Idempotent, thread-safe; safe to call during in-flight calls. */
    override fun close() {
        val h = handle.getAndSet(0L)
        if (h != 0L) NativeBridge.nativeFree(h)
    }

    private fun liveHandle(): Long {
        val h = handle.get()
        if (h == 0L) throw EngineClosedException()
        return h
    }

    private fun throwIfError(code: Int) {
        when (code) {
            NativeBridge.OK -> Unit
            NativeBridge.ERR_BAD_HANDLE -> throw EngineClosedException()
            NativeBridge.ERR_INVALID, NativeBridge.ERR_NULL ->
                throw IllegalArgumentException("event rejected by the security engine")
            NativeBridge.ERR_IDENTITY_MISMATCH ->
                throw SecurityException("package identity changed for a live process")
            NativeBridge.ERR_STALE_GENERATION ->
                throw IllegalArgumentException("process generation is not newer than a retired one")
            NativeBridge.ERR_CAPACITY -> throw IllegalStateException("engine capacity reached")
            else -> throw IllegalStateException("security engine error $code")
        }
    }

    companion object {
        const val DEFAULT_ALERT_BYTES = 64 * 1024

        init {
            System.loadLibrary("jay_squad_sec_bridge")
            val abi = NativeBridge.nativeAbiVersion()
            check(abi == NativeBridge.EXPECTED_ABI) {
                "native bridge ABI $abi, expected ${NativeBridge.EXPECTED_ABI}"
            }
        }

        /** Create an engine, or throw if the per-process engine limit is reached. */
        fun create(bootNonce: Long): JaySquadSecEngine {
            val h = NativeBridge.nativeNew(bootNonce)
            if (h == 0L) throw IllegalStateException("could not create engine (limit reached)")
            return JaySquadSecEngine(h)
        }

        private fun String.utf8(): ByteArray = toByteArray(StandardCharsets.UTF_8)
    }
}

/** The engine was closed (possibly concurrently) before or during the call. */
class EngineClosedException : IllegalStateException("security engine is closed")
