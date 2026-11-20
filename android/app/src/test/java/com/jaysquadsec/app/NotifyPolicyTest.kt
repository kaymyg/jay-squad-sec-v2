package com.jaysquadsec.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class NotifyPolicyTest {
    private val sms = "android.permission.READ_SMS"
    private val granted = InventoryChange.PermissionGranted("com.a.app", sms)
    private val signer = InventoryChange.SignerChanged("com.b.app", "a".repeat(64), "b".repeat(64))

    @Test
    fun newChangesAreNotifiedOnce() {
        val first = NotifyPolicy.decide(listOf(granted, signer), emptySet())
        assertEquals(2, first.toNotify.size)
        val second = NotifyPolicy.decide(listOf(granted, signer), first.ledger)
        assertTrue("no repeat notifications", second.toNotify.isEmpty())
    }

    @Test
    fun aChangeThatGoesAwayAndComesBackIsNotifiedAgain() {
        val l1 = NotifyPolicy.decide(listOf(granted), emptySet()).ledger
        val l2 = NotifyPolicy.decide(emptyList(), l1).ledger // undone or accepted
        assertTrue(l2.isEmpty())
        assertEquals(listOf<InventoryChange>(granted), NotifyPolicy.decide(listOf(granted), l2).toNotify)
    }

    @Test
    fun aDifferentNewSignerIsNotifiedEvenIfAnEarlierOneWas() {
        val l1 = NotifyPolicy.decide(listOf(signer), emptySet()).ledger
        val again = InventoryChange.SignerChanged("com.b.app", "a".repeat(64), "c".repeat(64))
        assertEquals(1, NotifyPolicy.decide(listOf(again), l1).toNotify.size)
    }

    @Test
    fun revocationsAndRemovalsAreNotNotified() {
        val d = NotifyPolicy.decide(
            listOf(InventoryChange.PermissionRevoked("com.a.app", sms), InventoryChange.AppRemoved("com.c.app")),
            emptySet(),
        )
        assertTrue(d.toNotify.isEmpty())
        assertEquals(2, d.ledger.size)
    }

    @Test
    fun ledgerRoundTripsAndRejectsGarbage() {
        val ledger = NotifyPolicy.decide(listOf(granted, signer), emptySet()).ledger
        assertEquals(ledger, NotifyPolicy.decode(NotifyPolicy.encode(ledger)))
        assertTrue(NotifyPolicy.decode("garbage\nx").isEmpty())
        assertTrue(NotifyPolicy.decode("").isEmpty())
    }
}
