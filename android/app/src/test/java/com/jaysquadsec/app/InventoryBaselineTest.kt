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
        // Accepting a removal drops it from the baseline.
        val dropped = InventoryDiff.acceptPackage(accepted, now, "com.gone.app")
        assertTrue("com.gone.app" !in dropped)
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
        assertTrue(!tmp.root.resolve("${BaselineStore.FILE}.tmp").exists())
        tmp.root.resolve(BaselineStore.FILE).writeText("garbage")
        assertTrue(store.load() is BaselineStore.Loaded.Corrupt)
    }
}
