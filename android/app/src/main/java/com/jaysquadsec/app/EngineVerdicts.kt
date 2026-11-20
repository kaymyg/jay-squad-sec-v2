package com.jaysquadsec.app

import com.jaysquadsec.bridge.JaySquadSecEngine

/**
 * Runs the native engine over the unreviewed changes and returns its verdict
 * per app. A fresh engine is used for every assessment, so the result is a
 * deterministic function of the changes on screen: signals on the same app
 * add up (for example a changed certificate plus SMS access), and accepting
 * or undoing a change lowers the verdict at the next scan.
 *
 * Alert-only: the verdict is shown and used to word notifications; nothing is
 * blocked. If the engine is unavailable, no verdicts are returned and the app
 * works as before.
 */
object EngineVerdicts {
    data class Verdict(val actionOrdinal: Int, val score: Double) {
        val words: String get() = RiskWords.of(actionOrdinal)
        val high: Boolean get() = actionOrdinal >= 2
    }

    fun assess(
        changes: List<InventoryChange>,
        current: Map<String, AppFingerprint>,
    ): Map<String, Verdict> {
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
        } catch (t: Throwable) {
            emptyMap()
        }
    }
}
