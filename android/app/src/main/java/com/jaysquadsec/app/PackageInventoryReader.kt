package com.jaysquadsec.app

import android.content.Context
import android.content.Intent
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.content.pm.ResolveInfo
import android.os.Build
import java.security.MessageDigest

data class PermissionObservation(
    val name: String,
    val granted: Boolean,
)

data class AppObservation(
    val packageName: String,
    val label: String,
    val signerSha256: String?,
    val permissions: List<PermissionObservation>,
)

/**
 * Reads only packages visible through Android package-visibility rules.
 * The manifest declares launcher-intent visibility, not QUERY_ALL_PACKAGES.
 */
class PackageInventoryReader(context: Context) {
    private val packageManager = context.packageManager

    fun readLaunchableApps(): List<AppObservation> {
        val launcherIntent = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
        val resolved = queryLauncherActivities(launcherIntent)
        val packageNames = resolved.mapNotNull { it.activityInfo?.packageName }.toSortedSet()

        return packageNames.mapNotNull { packageName ->
            runCatching { readPackage(packageName) }.getOrNull()
        }.sortedBy { it.label.lowercase() }
    }

    private fun queryLauncherActivities(intent: Intent): List<ResolveInfo> =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            packageManager.queryIntentActivities(
                intent,
                PackageManager.ResolveInfoFlags.of(0),
            )
        } else {
            @Suppress("DEPRECATION")
            packageManager.queryIntentActivities(intent, 0)
        }

    private fun readPackage(packageName: String): AppObservation {
        val info = getPackageInfo(packageName)
        val appInfo = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            packageManager.getApplicationInfo(
                packageName,
                PackageManager.ApplicationInfoFlags.of(0),
            )
        } else {
            @Suppress("DEPRECATION")
            packageManager.getApplicationInfo(packageName, 0)
        }

        val requested = info.requestedPermissions.orEmpty()
        val flags = info.requestedPermissionsFlags.orEmpty()
        val permissions = requested.mapIndexed { index, name ->
            PermissionObservation(
                name = name,
                granted = flags.getOrNull(index)
                    ?.and(PackageInfo.REQUESTED_PERMISSION_GRANTED) == PackageInfo.REQUESTED_PERMISSION_GRANTED,
            )
        }

        return AppObservation(
            packageName = packageName,
            label = packageManager.getApplicationLabel(appInfo).toString(),
            signerSha256 = signingCertificateDigest(info),
            permissions = permissions,
        )
    }

    private fun getPackageInfo(packageName: String): PackageInfo {
        val flags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            PackageManager.GET_PERMISSIONS or PackageManager.GET_SIGNING_CERTIFICATES
        } else {
            @Suppress("DEPRECATION")
            PackageManager.GET_PERMISSIONS or PackageManager.GET_SIGNATURES
        }
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            packageManager.getPackageInfo(packageName, PackageManager.PackageInfoFlags.of(flags.toLong()))
        } else {
            @Suppress("DEPRECATION")
            packageManager.getPackageInfo(packageName, flags)
        }
    }

    private fun signingCertificateDigest(info: PackageInfo): String? {
        val signatures = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            info.signingInfo?.apkContentsSigners
        } else {
            @Suppress("DEPRECATION")
            info.signatures
        } ?: return null

        if (signatures.isEmpty()) return null
        // Preserve the complete current signer set; do not collapse a
        // multi-signer package to whichever certificate happens to be first.
        return signatures.map { signature ->
            val digest = MessageDigest.getInstance("SHA-256").digest(signature.toByteArray())
            digest.joinToString("") { byte -> "%02x".format(byte) }
        }.sorted().joinToString(",")
    }
}
