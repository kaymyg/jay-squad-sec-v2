package com.jaysquadsec.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class InventoryBaselineTest {
    @get:Rule val tmp = TemporaryFolder()

    private val keyA = "a".repeat(64)
    private val keyB = "b".repeat(64)
    private val sms = "android.permission.READ_SMS"
    private val mic = "android.permission.RECORD_AUDIO"

    private fun fp(pkg: String, signers: String = keyA, vararg perms: String) =
        AppFingerprint(pkg, signers, perms.toSortedSet())

    private fun map(vararg apps: AppFingerprint) = apps.associateBy { it.packageName }

    @Test
    fun noChangesWhenIdentical() {
        val apps = map(fp("com.a.app", keyA, sms), fp("com.b.app"))
        assertTrue(InventoryDiff.compare(apps, apps).isEmpty())
    }

    @Test
    fun signerChangeIsDetectedAndRankedFirst() {
        val before = map(fp("com.bank.app", keyA), fp("com.x.app"))
        val after = map(fp("com.bank.app", keyB), fp("com.x.app"), fp("com.new.app"))
        val changes = InventoryDiff.compare(before, after)
        val first = changes.first()
        assertTrue(first is InventoryChange.SignerChanged)
        assertEquals("com.bank.app", first.packageName)
        assertTrue(changes.any { it is InventoryChange.AppAdded && it.packageName == "com.new.app" })
    }

    @Test
    fun unreadableSignerIsNeverReportedAsAChange() {
        val before = map(fp("com.a.app", ""))
        val after = map(fp("com.a.app", keyA))
        assertTrue(InventoryDiff.compare(before, after).isEmpty())
        assertTrue(InventoryDiff.compare(after, before).isEmpty())
    }

    @Test
    fun sensitiveGrantsAndRevocationsAreReported() {
        val before = map(fp("com.a.app", keyA, mic))
        val after = map(fp("com.a.app", keyA, sms))
        val changes = InventoryDiff.compare(before, after)
        assertEquals(2, changes.size)
        val granted = changes[0] as InventoryChange.PermissionGranted
        assertEquals(sms, granted.permission)
        val revoked = changes[1] as InventoryChange.PermissionRevoked
        assertEquals(mic, revoked.permission)
    }

    @Test
    fun removedAppsAreReported() {
        val changes = InventoryDiff.compare(map(fp("com.gone.app")), emptyMap())
        assertTrue(changes.single() is InventoryChange.AppRemoved)
    }

    @Test
    fun fingerprintKeepsOnlyGrantedSensitivePermissions() {
        val app = AppObservation(
            packageName = "com.a.app",
            label = "A",
            signerSha256 = keyA,
            permissions = listOf(
                PermissionObservation(sms, granted = true),
                PermissionObservation(mic, granted = false),
                PermissionObservation("android.permission.INTERNET", granted = true),
            ),
        )
        assertEquals(setOf(sms), AppFingerprint.of(app).sensitiveGranted)
    }

    @Test
    fun acceptingOnePackageLeavesOthersFlagged() {
        val before = map(fp("com.a.app", keyA), fp("com.b.app", keyA), fp("com.gone.app"))
        val now = map(fp("com.a.app", keyA, sms), fp("com.b.app", keyB))
        val accepted = InventoryDiff.acceptPackage(before, now, "com.a.app")
        val left = InventoryDiff.compare(accepted, now)
        assertTrue(left.none { it.packageName == "com.a.app" })
        assertTrue(left.any { it is InventoryChange.SignerChanged && it.packageName == "com.b.app" })
        assertTrue(left.any { it is InventoryChange.AppRemoved && it.packageName == "com.gone.app" })
        // Accepting a removal keeps a tombstone and stops reporting it.
        val dropped = InventoryDiff.acceptPackage(accepted, now, "com.gone.app")
        assertTrue(dropped.getValue("com.gone.app").removed)
        assertTrue(InventoryDiff.compare(dropped, now).none { it.packageName == "com.gone.app" })
    }

    @Test
    fun codecRoundTrips() {
        val apps = listOf(fp("com.a.app", "$keyA,$keyB", sms, mic), fp("com.b.app", ""))
        assertEquals(apps.associateBy { it.packageName }, BaselineCodec.decode(BaselineCodec.encode(apps)))
    }

    @Test
    fun codecRejectsTamperedOrMalformedInput() {
        val good = BaselineCodec.encode(listOf(fp("com.a.app", keyA, sms)))
        assertNull(BaselineCodec.decode(""))
        assertNull(BaselineCodec.decode(good.replace("v1", "v2")))
        assertNull(BaselineCodec.decode(good.replace(keyA, "zz")))
        assertNull(BaselineCodec.decode(good.replace(sms, "android.permission.INTERNET")))
        assertNull(BaselineCodec.decode(good + "com.a.app\t\t\n")) // duplicate package
        assertNull(BaselineCodec.decode(good + "bad line\n"))
        assertNull(BaselineCodec.decode(good + "../../etc\t\t\n"))
    }

    @Test
    fun storeSavesAtomicallyAndDetectsCorruption() {
        val store = BaselineStore(tmp.root)
        assertTrue(store.load() is BaselineStore.Loaded.Missing)
        val apps = listOf(fp("com.a.app", keyA, sms))
        store.save(apps)
        val loaded = store.load() as BaselineStore.Loaded.Ok
        assertTrue(loaded.recordedAtMs > 0)
        assertEquals(apps.associateBy { it.packageName }, loaded.apps)
        assertTrue("no temp files left", tmp.root.listFiles()!!.none { it.name.endsWith(".tmp") })
        tmp.root.resolve(BaselineStore.FILE).writeText("garbage")
        assertTrue(store.load() is BaselineStore.Loaded.Corrupt)
    }

    @Test
    fun acceptNeverReplacesAKnownSignerWithAnUnreadableOne() {
        val before = map(fp("com.a.app", keyA))
        val unreadable = map(fp("com.a.app", "", sms))
        val accepted = InventoryDiff.acceptPackage(before, unreadable, "com.a.app")
        assertEquals(keyA, accepted.getValue("com.a.app").signers)
        assertEquals(setOf(sms), accepted.getValue("com.a.app").sensitiveGranted)
        // A later reinstall with another key is still detected.
        val reinstalled = map(fp("com.a.app", keyB, sms))
        assertTrue(InventoryDiff.compare(accepted, reinstalled).single() is InventoryChange.SignerChanged)
    }

    @Test
    fun acceptPackagesTouchesOnlyTheListedApps() {
        val before = map(fp("com.a.app"), fp("com.b.app"), fp("com.c.app"))
        val now = map(fp("com.a.app", keyA, sms), fp("com.b.app", keyA, mic), fp("com.c.app", keyB))
        val accepted = InventoryDiff.acceptPackages(before, now, setOf("com.a.app", "com.b.app"))
        val left = InventoryDiff.compare(accepted, now)
        assertEquals(listOf("com.c.app"), left.map { it.packageName })
    }

    @Test
    fun hostileLabelsCannotForgeOrHideWarnings() {
        val bidi = "\u202Eppa.lieve\u202C"
        assertEquals("Notes No changes.", safeLabel("Notes\nNo changes."))
        assertTrue(safeLabel(bidi).none { it == '\u202E' || it == '\u202C' })
        assertTrue(safeLabel("x".repeat(500)).length <= 40)
        assertEquals("(no name)", safeLabel("\n\t\u200B"))
        val line = describe(InventoryChange.PermissionGranted("com.evil.x", sms), "Chrome\n" + "y".repeat(300))
        assertTrue("warning comes first", line.startsWith("READ_SMS access granted to "))
        assertTrue("package always shown", line.endsWith("(com.evil.x)"))
        assertTrue(line.length < 120)
        assertTrue('\n' !in line)
    }

    @Test
    fun notificationTitles() {
        assertEquals("Security alert", notificationTitle(listOf(InventoryChange.PermissionGranted("com.a.app", sms))))
        val two = listOf(InventoryChange.PermissionGranted("com.a.app", sms), InventoryChange.AppAdded("com.b.app", setOf(mic)))
        assertEquals("2 security alerts to review", notificationTitle(two))
    }

    @Test
    fun anAppThatHidesAndReturnsWithAnotherKeyIsStillCaught() {
        val before = map(fp("com.bank.app", keyA))
        val hidden = InventoryDiff.acceptPackage(before, emptyMap(), "com.bank.app")
        val back = map(fp("com.bank.app", keyB))
        val changes = InventoryDiff.compare(hidden, back)
        assertTrue(changes.first() is InventoryChange.SignerChanged)
        assertTrue(changes.any { it is InventoryChange.AppAdded })
        // Same key coming back is just a re-added app.
        val same = InventoryDiff.compare(hidden, map(fp("com.bank.app", keyA)))
        assertTrue(same.single() is InventoryChange.AppAdded)
        // Accepting it clears the tombstone.
        val accepted = InventoryDiff.acceptPackage(hidden, back, "com.bank.app")
        assertTrue(!accepted.getValue("com.bank.app").removed)
    }

    @Test
    fun tombstonesSurviveTheCodecAndAreValidated() {
        val apps = listOf(fp("com.a.app", keyA), AppFingerprint("com.gone.app", keyB, emptySet(), removed = true))
        val back = BaselineCodec.decode(BaselineCodec.encode(apps))!!
        assertTrue(back.getValue("com.gone.app").removed)
        // A tombstone without a signer, or with permissions, is malformed.
        assertNull(BaselineCodec.decode("jss-inventory-baseline v1\n~com.gone.app\t\t\n"))
        assertNull(BaselineCodec.decode("jss-inventory-baseline v1\n~com.gone.app\t$keyA\t$sms\n"))
    }

    @Test
    fun labelCleaningCoversSpacesMarksAndFillers() {
        assertEquals("a b", safeLabel("a" + "\u2003".repeat(30) + "b"))
        assertEquals("a b", safeLabel("a\u00A0b"))
        assertTrue(safeLabel("e" + "\u0301".repeat(38)).length <= 3)
        assertEquals("caf\u00e9", safeLabel("caf\u00e9"))
        assertEquals("(no name)", safeLabel("\u3164\u2800\u3164"))
    }

    @Test
    fun losingAccessIsAbsorbedAndRegrantingIsCaught() {
        val loc = "android.permission.ACCESS_FINE_LOCATION"
        val before = map(fp("com.android.chrome", keyA, loc, mic))
        val revoked = map(fp("com.android.chrome", keyA, mic))
        val (absorbed, n) = InventoryDiff.absorbRevocations(before, revoked)
        assertEquals(1, n)
        assertTrue("no review needed for a removal", InventoryDiff.compare(absorbed, revoked).isEmpty())
        // Granting it again later is new access and is reported.
        val regranted = map(fp("com.android.chrome", keyA, loc, mic))
        val again = InventoryDiff.compare(absorbed, regranted).single()
        assertTrue(again is InventoryChange.PermissionGranted)
        assertTrue(NotifyPolicy.notifiable(again))
        // Unchanged inputs report nothing absorbed.
        assertEquals(0, InventoryDiff.absorbRevocations(absorbed, revoked).second)
    }

    @Test
    fun changesMapToEngineEventsOnlyWhenRiskRises() {
        assertEquals(listOf("app_signer_changed"), EngineEvents.of(InventoryChange.SignerChanged("com.a", keyA, keyB)))
        assertEquals(listOf("sensitive_permission_granted"), EngineEvents.of(InventoryChange.PermissionGranted("com.a", sms)))
        assertEquals(
            listOf("new_app_with_sensitive_access", "sensitive_permission_granted", "sensitive_permission_granted"),
            EngineEvents.of(InventoryChange.AppAdded("com.a", setOf(sms, mic))),
        )
        assertTrue(EngineEvents.of(InventoryChange.AppAdded("com.a", emptySet())).isEmpty())
        assertTrue(EngineEvents.of(InventoryChange.AppRemoved("com.a")).isEmpty())
        assertTrue(EngineEvents.of(InventoryChange.PermissionRevoked("com.a", sms)).isEmpty())
    }

    @Test
    fun engineIdentityIsBoundedAndSignerSpecific() {
        val many = List(6) { "c".repeat(64) }.joinToString(",")
        val id = EngineEvents.identity("com." + "a".repeat(250), many)
        assertTrue(id.length < 512)
        assertTrue(EngineEvents.identity("com.a", keyA) != EngineEvents.identity("com.a", keyB))
        assertTrue(EngineEvents.identity("com.a", keyA).startsWith("com.a:sha256:"))
    }

    @Test
    fun riskWordsMatchEngineActions() {
        assertEquals(listOf("Low", "Watch", "High", "Very high", "Critical"), (0..4).map(RiskWords::of))
        assertEquals("Critical", RiskWords.of(99))
        assertEquals("High risk: Bank (fake)", notificationTitle(listOf(InventoryChange.PermissionGranted("com.a", sms)), "Bank\n(fake)"))
    }
}
