package com.jaysquadsec.app

/** User-facing wording for a change, shared by the screen and notifications. */
internal fun describe(change: InventoryChange, name: String): String = when (change) {
    is InventoryChange.SignerChanged ->
        "Signing certificate changed: $name. It was reinstalled from a different source " +
            "or its developer rotated the key. Check where it came from."
    is InventoryChange.PermissionGranted ->
        "New access: $name can now use ${SensitivePermissions.shortName(change.permission)}"
    is InventoryChange.AppAdded ->
        if (change.sensitive.isEmpty()) {
            "New app: $name"
        } else {
            "New app: $name, with ${change.sensitive.joinToString { SensitivePermissions.shortName(it) }}"
        }
    is InventoryChange.PermissionRevoked ->
        "Access removed: $name no longer has ${SensitivePermissions.shortName(change.permission)}"
    is InventoryChange.AppRemoved -> "Removed or hidden: $name"
}
