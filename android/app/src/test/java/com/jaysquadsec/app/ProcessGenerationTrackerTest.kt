package com.jaysquadsec.app

import org.junit.Assert.assertEquals
import org.junit.Test

class ProcessGenerationTrackerTest {
    @Test
    fun sameProcessObservationKeepsGeneration() {
        val tracker = ProcessGenerationTracker()
        val first = tracker.observe(123, "start-a", "com.example.app:sha256:abc")
        val again = tracker.observe(123, "start-a", "com.example.app:sha256:abc")
        assertEquals(first.generation, again.generation)
    }

    @Test
    fun reusedPidGetsNewGeneration() {
        val tracker = ProcessGenerationTracker()
        val first = tracker.observe(123, "start-a", "com.example.app:sha256:abc")
        val second = tracker.observe(123, "start-b", "com.example.app:sha256:abc")
        assertEquals(first.generation + 1, second.generation)
    }

    @Test
    fun identityChangeGetsNewGeneration() {
        val tracker = ProcessGenerationTracker()
        val first = tracker.observe(123, "start-a", "com.example.one:sha256:abc")
        val second = tracker.observe(123, "start-a", "com.example.two:sha256:def")
        assertEquals(first.generation + 1, second.generation)
    }

    @Test
    fun retiredPidDoesNotResetGeneration() {
        val tracker = ProcessGenerationTracker()
        val first = tracker.observe(123, "start-a", "com.example.app:sha256:abc")
        tracker.retire(123)
        val second = tracker.observe(123, "start-b", "com.example.app:sha256:abc")
        assertEquals(first.generation + 1, second.generation)
    }
}
