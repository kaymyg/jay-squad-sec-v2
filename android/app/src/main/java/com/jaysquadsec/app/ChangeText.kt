package com.jaysquadsec.app

/**
 * App labels come from OTHER apps and are untrusted: they may contain
 * newlines, bidi overrides or hundreds of characters to forge or hide text.
 * Strip control, format and separator characters, collapse whitespace and cap
 * the length. Pure Kotlin, unit-tested.
 */
internal fun safeLabel(raw: String?, max: Int = 40): String {
    val cleaned = buildString {
        raw.orEmpty().forEach { c ->
            when (Character.getType(c).toByte()) {
                Character.CONTROL, Character.FORMAT, Character.LINE_SEPARATOR,
                Character.PARAGRAPH_SEPARATOR, Character.SURROGATE, Character.PRIVATE_USE,
                Character.UNASSIGNED -> append(' ')
                else -> append(c)
            }
        }
    }.trim().replace(Regex("\\s+"), " ")
    if (cleaned.isEmpty()) return "(no name)"
    return if (cleaned.length <= max) cleaned else cleaned.take(max - 1).trimEnd() + "…"
}

/**
 * User-facing wording for a change, shared by the screen and notifications.
 * The fixed warning text comes FIRST and the untrusted name last, always with
 * the package name, so a label can neither push the warning out of view nor
 * pass itself off as another app.
 */
internal fun describe(change: InventoryChange, label: String?): String {
    val who = "${safeLabel(label)} (${change.packageName})"
    return when (change) {
        is InventoryChange.SignerChanged ->
            "Signing certificate changed: reinstalled from a different source or key rotated. " +
                "Check where it came from: $who"
        is InventoryChange.PermissionGranted ->
            "${SensitivePermissions.shortName(change.permission)} access granted to $who"
        is InventoryChange.AppAdded ->
            if (change.sensitive.isEmpty()) {
                "New app: $who"
            } else {
                "New app with ${change.sensitive.joinToString { SensitivePermissions.shortName(it) }}: $who"
            }
        is InventoryChange.PermissionRevoked ->
            "${SensitivePermissions.shortName(change.permission)} access removed from $who"
        is InventoryChange.AppRemoved -> "Removed or hidden: $who"
    }
}

/** Notification title that does not overstate a plain new app. */
internal fun notificationTitle(changes: List<InventoryChange>): String = when {
    changes.size > 1 -> "${changes.size} unreviewed security changes"
    changes.single() is InventoryChange.SignerChanged ||
        changes.single() is InventoryChange.PermissionGranted ||
        (changes.single() as? InventoryChange.AppAdded)?.sensitive?.isNotEmpty() == true -> "Security alert"
    else -> "New app installed"
}
