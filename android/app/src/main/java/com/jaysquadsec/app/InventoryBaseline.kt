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
    /**
     * Tombstone: the app was removed or hid itself and the user accepted
     * that. Its signer is kept, so if it comes back signed by another key
     * that is still reported (and notified) as a signer change.
     */
    val removed: Boolean = false,
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
            if (before == null || before.removed) {
                out += InventoryChange.AppAdded(pkg, now.sensitiveGranted)
                if (before != null && before.signers.isNotEmpty() && now.signers.isNotEmpty() &&
                    before.signers != now.signers
                ) {
                    out += InventoryChange.SignerChanged(pkg, before.signers, now.signers)
                }
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
        for (pkg in baseline.keys - current.keys) {
            if (baseline.getValue(pkg).removed.not()) out += InventoryChange.AppRemoved(pkg)
        }
        return out.sortedWith(
            compareByDescending<InventoryChange> { it.severity }
                .thenBy { it.packageName }
                .thenBy { detail(it) },
        )
    }

    /**
     * Accept every change for one package only: its baseline entry becomes
     * what is observed now (or is dropped if the app is gone). All other
     * packages keep their old baseline, so their changes stay flagged.
     */
    fun acceptPackage(
        baseline: Map<String, AppFingerprint>,
        current: Map<String, AppFingerprint>,
        packageName: String,
    ): Map<String, AppFingerprint> = acceptPackages(baseline, current, setOf(packageName))

    /**
     * Accept the listed packages only. A signer that could not be read in
     * this scan never overwrites the known one: otherwise accepting would
     * silently disable signer-change detection for that app.
     */
    fun acceptPackages(
        baseline: Map<String, AppFingerprint>,
        current: Map<String, AppFingerprint>,
        packageNames: Set<String>,
    ): Map<String, AppFingerprint> {
        val out = LinkedHashMap(baseline)
        for (pkg in packageNames) {
            val now = current[pkg]
            val before = baseline[pkg]
            out[pkg] = when {
                now == null -> {
                    // Keep a tombstone with the known signer; nothing worth keeping otherwise.
                    if (before != null && before.signers.isNotEmpty()) {
                        before.copy(sensitiveGranted = emptySet(), removed = true)
                    } else {
                        out.remove(pkg)
                        continue
                    }
                }
                now.signers.isEmpty() && before != null -> now.copy(signers = before.signers, removed = false)
                else -> now.copy(removed = false)
            }
        }
        return out
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
 *   ~<package>\t<signers>\t          (tombstone: accepted removal)
 */
object BaselineCodec {
    private const val HEADER = "jss-inventory-baseline v1"
    private const val MAX_APPS = 10_000
    private val PACKAGE = Regex("^[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z0-9_]+)+$")
    private val SIGNERS = Regex("^([0-9a-f]{64}(,[0-9a-f]{64})*)?$")

    fun encode(apps: Collection<AppFingerprint>): String = buildString {
        append(HEADER).append('\n')
        apps.sortedBy { it.packageName }.forEach { a ->
            if (a.removed) append('~')
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
            val (field0, signers, perms) = f
            val removed = field0.startsWith("~")
            val pkg = field0.removePrefix("~")
            if (!PACKAGE.matches(pkg) || !SIGNERS.matches(signers) || pkg in out) return null
            val granted = if (perms.isEmpty()) emptySet() else perms.split(',').toSet()
            if (!SensitivePermissions.ALL.containsAll(granted)) return null
            if (removed && (signers.isEmpty() || granted.isNotEmpty())) return null
            out[pkg] = AppFingerprint(pkg, signers, granted.toSortedSet(), removed)
        }
        return out
    }
}

/**
 * Stable identity of a change, so each one is notified once. Stored as a
 * SHA-256 hex digest: fixed length whatever the package name or signer list.
 */
fun InventoryChange.key(): String {
    val raw = rawKey()
    val digest = java.security.MessageDigest.getInstance("SHA-256").digest(raw.toByteArray(Charsets.UTF_8))
    return digest.joinToString("") { "%02x".format(it) }
}

private fun InventoryChange.rawKey(): String = when (this) {
    is InventoryChange.AppAdded -> "added|$packageName"
    is InventoryChange.AppRemoved -> "removed|$packageName"
    is InventoryChange.SignerChanged -> "signer|$packageName|$after"
    is InventoryChange.PermissionGranted -> "granted|$packageName|$permission"
    is InventoryChange.PermissionRevoked -> "revoked|$packageName|$permission"
}

/**
 * Decides what to notify. Only changes not announced before are returned, and
 * the ledger keeps only keys of changes still present: once a change is
 * accepted or undone it is forgotten, so if it happens again it is announced
 * again. See [notifiable] for what may interrupt the user.
 */
object NotifyPolicy {
    /**
     * @property toNotify changes never announced before (non-empty means post).
     * @property unreviewed every notifiable change still present, highest
     *   severity first: what the notification shows, so a new post never
     *   hides an earlier, still-unhandled alert.
     * @property ledger keys of every change still present.
     */
    data class Decision(
        val toNotify: List<InventoryChange>,
        val unreviewed: List<InventoryChange>,
        val ledger: Set<String>,
    )

    /**
     * Notify ONLY when an app gains sensitive access or is swapped: a
     * signing-certificate change, a newly granted sensitive permission, or a
     * new app that already holds one. Plain new apps, removals and
     * revocations are shown in the app but never interrupt the user.
     */
    fun notifiable(c: InventoryChange): Boolean = when (c) {
        is InventoryChange.SignerChanged, is InventoryChange.PermissionGranted -> true
        is InventoryChange.AppAdded -> c.sensitive.isNotEmpty()
        is InventoryChange.AppRemoved, is InventoryChange.PermissionRevoked -> false
    }

    fun decide(changes: List<InventoryChange>, ledger: Set<String>): Decision {
        val present = changes.map { it.key() }.toSet()
        val unreviewed = changes.filter(::notifiable).sortedByDescending { it.severity }
        val fresh = unreviewed.filter { it.key() !in ledger }
        return Decision(fresh, unreviewed, present)
    }

    /**
     * Ledger to save after a check. A change counts as announced only if the
     * notification was actually posted; otherwise (notifications off, channel
     * blocked, post failed) the old entries are kept but pruned, so the change
     * is announced once notifications work again.
     */
    fun ledgerAfter(decision: Decision, old: Set<String>, posted: Boolean): Set<String> =
        if (decision.toNotify.isEmpty() || posted) decision.ledger else old.intersect(decision.ledger)

    private const val HEADER = "jss-notified v2"
    private const val MAX_KEYS = 20_000

    fun encode(ledger: Set<String>): String =
        (listOf(HEADER) + ledger.sorted()).joinToString("\n", postfix = "\n")

    /** Malformed input yields an empty ledger: worst case, a change is announced twice. */
    fun decode(text: String): Set<String> {
        val lines = text.split('\n').filter { it.isNotEmpty() }
        if (lines.firstOrNull() != HEADER || lines.size > MAX_KEYS) return emptySet()
        val hex = Regex("^[0-9a-f]{64}$")
        return lines.drop(1).filter { hex.matches(it) }.toSet()
    }
}
