package com.jaysquadsec.app

/**
 * Tracks generations only for processes that an authorised Android source
 * actually identifies. Android does not expose a complete third-party process
 * lifecycle to ordinary apps; this class must not be fed guessed process IDs.
 *
 * The caller supplies a stable start token obtained from its legitimate
 * observation source. A changed token or package identity allocates a newer
 * generation for that PID, matching the native bridge contract.
 */
class ProcessGenerationTracker {
    data class ProcessInstance(
        val pid: Int,
        val generation: Long,
        val packageIdentity: String,
    )

    private data class Seen(
        val startToken: String,
        val packageIdentity: String,
        val generation: Long,
    )

    private val lock = Any()
    private val current = mutableMapOf<Int, Seen>()
    private val highestGeneration = mutableMapOf<Int, Long>()

    fun observe(pid: Int, startToken: String, packageIdentity: String): ProcessInstance {
        require(pid > 0) { "pid must be positive" }
        require(startToken.isNotBlank()) { "start token is required" }
        require(packageIdentity.isNotBlank()) { "package identity is required" }

        synchronized(lock) {
            val previous = current[pid]
            if (previous != null &&
                previous.startToken == startToken &&
                previous.packageIdentity == packageIdentity
            ) {
                return ProcessInstance(pid, previous.generation, packageIdentity)
            }

            val next = Math.addExact(highestGeneration[pid] ?: 0L, 1L)
            highestGeneration[pid] = next
            current[pid] = Seen(startToken, packageIdentity, next)
            return ProcessInstance(pid, next, packageIdentity)
        }
    }

    fun retire(pid: Int) {
        synchronized(lock) { current.remove(pid) }
    }
}
