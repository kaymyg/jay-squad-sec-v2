package com.jaysquadsec.app

/**
 * App labels come from OTHER apps and are untrusted: they may contain
 * newlines, bidi overrides or hundreds of characters to forge or hide text.
 * Strip control, format and separator characters, collapse whitespace and cap
 * the length. Pure Kotlin, unit-tested.
 */
// Characters that render as blank but are not classed as spaces.
private val BLANK_FILLERS = setOf('\u115F', '\u1160', '\u2800', '\u3164', '\uFFA0')

internal fun safeLabel(raw: String?, max: Int = 40): String {
    var marks = 0
    val cleaned = buildString {
        raw.orEmpty().forEach { c ->
            val type = Character.getType(c).toByte()
            when {
                c in BLANK_FILLERS -> append(' ')
                type == Character.CONTROL || type == Character.FORMAT ||
                    type == Character.LINE_SEPARATOR || type == Character.PARAGRAPH_SEPARATOR ||
                    type == Character.SPACE_SEPARATOR || type == Character.SURROGATE ||
                    type == Character.PRIVATE_USE || type == Character.UNASSIGNED -> {
                    marks = 0
                    append(' ')
                }
                // Real scripts use a mark or two per letter; stacks are a
                // spoofing trick that draws over neighbouring lines.
                type == Character.NON_SPACING_MARK || type == Character.ENCLOSING_MARK ||
                    type == Character.COMBINING_SPACING_MARK -> {
                    if (++marks <= 2) append(c)
                }
                else -> {
                    marks = 0
                    append(c)
                }
            }
        }
    }.let(::collapseSpaces)
    if (cleaned.isEmpty()) return "(no name)"
    return if (cleaned.length <= max) cleaned else cleaned.take(max - 1).trimEnd() + "…"
}

/**
 * Collapse runs of whitespace (any Unicode space) to one space and trim.
 * Plain code, not a regex: Android's regex engine rejects flags such as
 * (?U) that desktop Java accepts, which crashed the app on a real phone.
 */
internal fun collapseSpaces(text: String): String {
    val out = StringBuilder(text.length)
    var pendingSpace = false
    for (c in text) {
        if (Character.isWhitespace(c) || Character.isSpaceChar(c)) {
            pendingSpace = out.isNotEmpty()
        } else {
            if (pendingSpace) out.append(' ')
            pendingSpace = false
            out.append(c)
        }
    }
    return out.toString()
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

/** Notifications only ever carry sensitive-access or swapped-app alerts. */
internal fun notificationTitle(changes: List<InventoryChange>, highRiskLabel: String? = null): String = when {
    // The engine rated an app High or above: lead with that app.
    highRiskLabel != null -> "High risk: ${safeLabel(highRiskLabel)}"
    changes.size == 1 -> "Security alert"
    else -> "${changes.size} security alerts to review"
}

/**
 * How to undo the changes for one app. Switching a permission off undoes a
 * grant; a new app or a changed signing certificate is only undone by
 * uninstalling (or accepted with Accept).
 */
internal fun rejectLabel(changes: List<InventoryChange>): String =
    if (changes.any { it is InventoryChange.AppAdded || it is InventoryChange.SignerChanged }) {
        "Reject: uninstall"
    } else {
        "Reject: turn off"
    }

internal fun rejectHint(changes: List<InventoryChange>): String = when {
    changes.any { it is InventoryChange.SignerChanged } ->
        "To reject, uninstall this app in its settings and reinstall it from a trusted store."
    changes.any { it is InventoryChange.AppAdded } ->
        "To reject, uninstall it in its settings. Switching its permissions off is not enough: " +
            "a new app stays listed until it is removed or accepted."
    changes.any { it is InventoryChange.PermissionGranted } ->
        "To reject, switch the listed permission off in its settings. This clears when you come back."
    else -> "Accept to clear."
}
