package com.jaysquadsec.app

import com.jaysquadsec.bridge.JaySquadSecEngine

/**
 * Runs the native engine over the unreviewed changes and returns its verdict
 * per app. App verdicts are a plain sum of observation weights with no time
 * decay, and a fresh engine is used each time, so the same changes always
 * give the same verdict: signals on the same app add up (for example a
 * changed certificate plus SMS access), and accepting or undoing a change
 * lowers the verdict at the next scan.
 *
 * Alert-only: the verdict is shown and used to word notifications; nothing is
 * blocked. Returns null if the engine is unavailable or fails, so the screen
 * can say so instead of silently showing nothing.
 */
object EngineVerdicts {
    data class Verdict(val actionOrdinal: Int, val score: Double) {
        val words: String get() = RiskWords.of(actionOrdinal)
        /** Rounded for display (truncation would show 14 for 14.999). */
        val shownScore: Int get() = kotlin.math.round(score).toInt()
        val high: Boolean get() = actionOrdinal >= 2
    }

    fun assess(
        changes: List<InventoryChange>,
        current: Map<String, AppFingerprint>,
    ): Map<String, Verdict>? {
        val byPackage = changes.groupBy { it.packageName }
            .mapValues { (_, list) -> list.flatMap(EngineEvents::of) }
            .filterValues { it.isNotEmpty() }
        if (byPackage.isEmpty()) return emptyMap()
        return try {
            JaySquadSecEngine.create(System.nanoTime()).use { engine ->
                byPackage.mapValues { (pkg, kinds) ->
                    val id = EngineEvents.identity(pkg, current[pkg]?.signers.orEmpty())
                    kinds.forEach { engine.submitAppEvent(id, it, "") }
                    val a = engine.appAssessment(id)
                    Verdict(a.action.ordinal, a.score)
                }
            }
        } catch (e: Exception) {
            null
        } catch (e: LinkageError) {
            // Library missing for this CPU, or ABI mismatch at load.
            null
        }
    }
}
