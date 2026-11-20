package com.jaysquadsec.app

import com.jaysquadsec.bridge.JaySquadSecEngine
import com.jaysquadsec.bridge.NativeBridge

/**
 * Proves the native Rust engine is packaged, loads on this device's CPU and
 * makes decisions. It feeds a fixed synthetic sequence for a fake identity
 * (never a real app) to a private, throwaway engine and checks that the
 * engine escalates and raises alerts. Nothing is monitored or blocked.
 */
object EngineSelfTest {
    data class Result(val ok: Boolean, val summary: String, val alerts: List<String> = emptyList())

    private const val SYNTHETIC_IDENTITY = "selftest.jaysquadsec:sha256:00"
    private const val SYNTHETIC_PID = 999_999
    private val SEQUENCE = listOf("credential_access", "privilege_escalation", "persistence_write")

    fun run(): Result = try {
        JaySquadSecEngine.create(System.nanoTime()).use { engine ->
            SEQUENCE.forEachIndexed { i, kind ->
                engine.submit(SYNTHETIC_PID, 1L, SYNTHETIC_IDENTITY, kind, "self-test", i.toLong())
            }
            val alerts = engine.takeAlerts()
            val escalated = alerts.any { it.startsWith("[policy]") } &&
                alerts.any { it.startsWith("[ALERT]") }
            if (escalated) {
                Result(true, "Engine loaded (ABI v${NativeBridge.EXPECTED_ABI}); self-test passed", alerts)
            } else {
                Result(false, "Engine loaded but self-test did not escalate", alerts)
            }
        }
    } catch (missing: UnsatisfiedLinkError) {
        Result(false, "Native engine not packaged for this CPU: ${missing.message}")
    } catch (failure: Throwable) {
        // ExceptionInInitializerError (ABI mismatch) or an engine error.
        Result(false, "Engine unavailable: ${failure.cause?.message ?: failure.message}")
    }
}
