package com.jaysquadsec.app

/**
 * Pure, platform-independent baseline and change detection for the visible
 * app inventory. No Android imports, so it is fully unit-tested on the JVM.
 *
 * Only facts the app can observe without special access are compared: the
 * package, its current signer set and which SENSITIVE runtime permissions are
 * granted. Grant flags for runtime ("dangerous") permissions are reliable;
 * special app-ops (overlay, install-unknown-apps, all-files) are not reported
 * through these flags, so they are deliberately not in the list.
 */
object SensitivePermissions {
    val ALL: Set<String> = setOf(
        "android.permission.READ_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.SEND_SMS",
        "android.permission.RECEIVE_MMS",
        "android.permission.READ_CALL_LOG",
        "android.permission.WRITE_CALL_LOG",
        "android.permission.PROCESS_OUTGOING_CALLS",
        "android.permission.READ_CONTACTS",
        "android.permission.WRITE_CONTACTS",
        "android.permission.GET_ACCOUNTS",
        "android.permission.RECORD_AUDIO",
        "android.permission.CAMERA",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.ACCESS_BACKGROUND_LOCATION",
        "android.permission.BODY_SENSORS",
        "android.permission.READ_PHONE_STATE",
        "android.permission.READ_PHONE_NUMBERS",
        "android.permission.CALL_PHONE",
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.READ_MEDIA_IMAGES",
        "android.permission.READ_MEDIA_VIDEO",
        "android.permission.READ_MEDIA_AUDIO",
        "android.permission.READ_CALENDAR",
        "android.permission.ACTIVITY_RECOGNITION",
    )

    fun shortName(permission: String): String = permission.substringAfterLast('.')
}

/** What the baseline remembers about one app. */
data class AppFingerprint(
    val packageName: String,
    /** Sorted, comma-joined SHA-256 digests; empty if unavailable. */
    val signers: String,
    val sensitiveGranted: Set<String>,
) {
    companion object {
        fun of(app: AppObservation) = AppFingerprint(
            packageName = app.packageName,
            signers = app.signerSha256.orEmpty(),
            sensitiveGranted = app.permissions
                .filter { it.granted && it.name in SensitivePermissions.ALL }
                .map { it.name }
                .toSortedSet(),
        )
    }
}

sealed class InventoryChange(val packageName: String) {
    /** Higher is more important; used only for display order. */
    abstract val severity: Int

    class AppAdded(packageName: String, val sensitive: Set<String>) : InventoryChange(packageName) {
        override val severity get() = if (sensitive.isEmpty()) 1 else 2
    }

    class AppRemoved(packageName: String) : InventoryChange(packageName) {
        override val severity get() = 0
    }

    /**
     * Same package name, different signing certificate. Android refuses an
     * in-place update signed by another key unless the developer rotated it,
     * so this means the app was reinstalled from a different source or its
     * key was rotated. The strongest signal this screen can show.
     */
    class SignerChanged(packageName: String, val before: String, val after: String) :
        InventoryChange(packageName) {
        override val severity get() = 4
    }

    class PermissionGranted(packageName: String, val permission: String) : InventoryChange(packageName) {
        override val severity get() = 3
    }

    class PermissionRevoked(packageName: String, val permission: String) : InventoryChange(packageName) {
        override val severity get() = 0
    }
}

object InventoryDiff {
    /** Deterministic: ordered by severity (highest first), then package, then detail. */
    fun compare(baseline: Map<String, AppFingerprint>, current: Map<String, AppFingerprint>): List<InventoryChange> {
        val out = mutableListOf<InventoryChange>()
        for ((pkg, now) in current) {
            val before = baseline[pkg]
            if (before == null) {
                out += InventoryChange.AppAdded(pkg, now.sensitiveGranted)
                continue
            }
            // An empty signer means "could not read", not "unsigned": never
            // report a change against an unknown value.
            if (before.signers.isNotEmpty() && now.signers.isNotEmpty() && before.signers != now.signers) {
                out += InventoryChange.SignerChanged(pkg, before.signers, now.signers)
            }
            (now.sensitiveGranted - before.sensitiveGranted).forEach {
                out += InventoryChange.PermissionGranted(pkg, it)
            }
            (before.sensitiveGranted - now.sensitiveGranted).forEach {
                out += InventoryChange.PermissionRevoked(pkg, it)
            }
        }
        for (pkg in baseline.keys - current.keys) out += InventoryChange.AppRemoved(pkg)
        return out.sortedWith(
            compareByDescending<InventoryChange> { it.severity }
                .thenBy { it.packageName }
                .thenBy { detail(it) },
        )
    }

    private fun detail(c: InventoryChange): String = when (c) {
        is InventoryChange.PermissionGranted -> c.permission
        is InventoryChange.PermissionRevoked -> c.permission
        else -> ""
    }
}

/**
 * Line-based baseline format, version 1. Package names, hex digests and
 * permission names never contain tabs or newlines, and every field is
 * validated on read, so a corrupted or tampered file is rejected as a whole
 * (the caller then re-baselines and says so) instead of being half-trusted.
 *
 *   jss-inventory-baseline v1
 *   <package>\t<signers>\t<perm,perm,...>
 */
object BaselineCodec {
    private const val HEADER = "jss-inventory-baseline v1"
    private const val MAX_APPS = 10_000
    private val PACKAGE = Regex("^[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z0-9_]+)+$")
    private val SIGNERS = Regex("^([0-9a-f]{64}(,[0-9a-f]{64})*)?$")

    fun encode(apps: Collection<AppFingerprint>): String = buildString {
        append(HEADER).append('\n')
        apps.sortedBy { it.packageName }.forEach { a ->
            append(a.packageName).append('\t')
                .append(a.signers).append('\t')
                .append(a.sensitiveGranted.sorted().joinToString(","))
                .append('\n')
        }
    }

    /** Returns null for anything malformed. */
    fun decode(text: String): Map<String, AppFingerprint>? {
        val lines = text.split('\n').dropLastWhile { it.isEmpty() }
        if (lines.firstOrNull() != HEADER || lines.size - 1 > MAX_APPS) return null
        val out = LinkedHashMap<String, AppFingerprint>()
        for (line in lines.drop(1)) {
            val f = line.split('\t')
            if (f.size != 3) return null
            val (pkg, signers, perms) = f
            if (!PACKAGE.matches(pkg) || !SIGNERS.matches(signers) || pkg in out) return null
            val granted = if (perms.isEmpty()) emptySet() else perms.split(',').toSet()
            if (!SensitivePermissions.ALL.containsAll(granted)) return null
            out[pkg] = AppFingerprint(pkg, signers, granted.toSortedSet())
        }
        return out
    }
}
