package com.jaysquadsec.app

import android.Manifest
import android.app.ActivityManager
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : ComponentActivity() {
    /** Bumped on every resume, so returning from Settings rescans. */
    private val resumeTick = mutableIntStateOf(0)

    private val notifyAsk = registerForActivityResult(ActivityResultContracts.RequestPermission()) {
        resumeTick.intValue++
    }

    override fun onResume() {
        super.onResume()
        // A force stop cancels scheduled jobs; re-arm on every visit (idempotent).
        ChangeCheckJob.schedule(applicationContext)
        resumeTick.intValue++
    }

    private fun backgroundRestricted(): Boolean =
        Build.VERSION.SDK_INT >= 28 &&
            getSystemService(ActivityManager::class.java)?.isBackgroundRestricted == true

    /** Android lets only the user change another app's permissions or remove it. */
    private fun openAppSettings(packageName: String) {
        runCatching {
            startActivity(
                Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.fromParts("package", packageName, null))
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
            )
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Accept is a trust decision: ignore touches while another app's
        // window covers ours (tapjacking), and hide such overlays on 12+.
        window.decorView.filterTouchesWhenObscured = true
        if (Build.VERSION.SDK_INT >= 31) window.setHideOverlayWindows(true)
        ChangeCheck.cleanStaleTemps(applicationContext.filesDir)
        val inventory = PackageInventoryReader(applicationContext)
        val baselineStore = BaselineStore(applicationContext.filesDir)
        ChangeCheckJob.schedule(applicationContext)
        if (savedInstanceState == null && !Notifier.canNotify(this)) {
            notifyAsk.launch(Manifest.permission.POST_NOTIFICATIONS)
        }

        setContent {
            MaterialTheme(colorScheme = lightColorScheme()) {
                Surface(modifier = Modifier.fillMaxSize()) {
                    var apps by remember { mutableStateOf<List<AppObservation>>(emptyList()) }
                    var loading by remember { mutableStateOf(true) }
                    var error by remember { mutableStateOf<String?>(null) }
                    var engine by remember { mutableStateOf<EngineSelfTest.Result?>(null) }
                    var changes by remember { mutableStateOf<List<InventoryChange>>(emptyList()) }
                    var baselineNote by remember { mutableStateOf<String?>(null) }
                    var baselineApps by remember { mutableStateOf<Map<String, AppFingerprint>>(emptyMap()) }
                    // Fingerprints of the scan that produced `changes`: assigned together
                    // with it, and read at action time (not captured), so Accept always
                    // saves exactly what was displayed.
                    var currentFp by remember { mutableStateOf<Map<String, AppFingerprint>>(emptyMap()) }
                    val labels = remember(apps) { apps.associate { it.packageName to it.label } }
                    val scope = rememberCoroutineScope()
                    // One refresh or accept at a time; a new refresh cancels the old one.
                    val uiMutex = remember { Mutex() }
                    // Bumped each time a scan is published; Accept only applies to the
                    // snapshot that was on screen when it was tapped.
                    var snapshot by remember { mutableStateOf(0) }
                    val refreshJob = remember { arrayOfNulls<Job>(1) }

                    suspend fun refresh() {
                        loading = true
                        error = null
                        try {
                            val scanned = withContext(Dispatchers.IO) { inventory.readLaunchableApps() }
                            val current = scanned.map { AppFingerprint.of(it) }
                            var base: Map<String, AppFingerprint> = current.associateBy { it.packageName }
                            val (found, note) = withContext(Dispatchers.IO) {
                                when (val stored = baselineStore.load()) {
                                    is BaselineStore.Loaded.Missing -> {
                                        baselineStore.save(current)
                                        emptyList<InventoryChange>() to ("Baseline recorded for ${current.size} apps. " +
                                            "Future scans will report changes against it.")
                                    }
                                    is BaselineStore.Loaded.Corrupt -> {
                                        baselineStore.save(current)
                                        emptyList<InventoryChange>() to ("The saved baseline was unreadable (corrupted or altered), " +
                                            "so a new one was recorded. Changes before now cannot be shown.")
                                    }
                                    is BaselineStore.Loaded.Ok -> {
                                        base = stored.apps
                                        InventoryDiff.compare(
                                            stored.apps,
                                            current.associateBy { it.packageName },
                                        ) to "Compared with baseline of ${stored.apps.size} apps recorded " +
                                            java.text.DateFormat.getDateTimeInstance(
                                                java.text.DateFormat.MEDIUM,
                                                java.text.DateFormat.SHORT,
                                            ).format(java.util.Date(stored.recordedAtMs)) + "." 
                                    }
                                }
                            }
                            // Publish one consistent snapshot.
                            apps = scanned
                            currentFp = current.associateBy { it.packageName }
                            changes = found
                            baselineNote = note
                            baselineApps = base
                            snapshot++
                        } catch (cancelled: CancellationException) {
                            throw cancelled
                        } catch (failure: Exception) {
                            error = failure.message ?: "Inventory scan failed"
                        } finally {
                            loading = false
                        }
                    }

                    LaunchedEffect(Unit) {
                        engine = withContext(Dispatchers.Default) { EngineSelfTest.run() }
                    }
                    fun requestRefresh() {
                        refreshJob[0]?.cancel()
                        refreshJob[0] = scope.launch { uiMutex.withLock { refresh() } }
                    }

                    fun accept(packages: Set<String>, note: String?) {
                        val shownSnapshot = snapshot
                        scope.launch {
                            uiMutex.withLock {
                                // A newer scan replaced what the user saw: do not accept
                                // changes they have not seen; the new list is on screen.
                                if (snapshot != shownSnapshot) return@withLock
                                try {
                                    val updated = InventoryDiff.acceptPackages(baselineApps, currentFp, packages)
                                    withContext(Dispatchers.IO) { baselineStore.save(updated.values) }
                                    baselineApps = updated
                                    changes = InventoryDiff.compare(updated, currentFp)
                                    if (note != null) baselineNote = note
                                } catch (cancelled: CancellationException) {
                                    throw cancelled
                                } catch (failure: Exception) {
                                    error = "Could not save: ${failure.message ?: "storage error"}"
                                }
                            }
                        }
                    }

                    LaunchedEffect(resumeTick.intValue) { requestRefresh() }

                    Column(
                        modifier = Modifier.fillMaxSize().padding(20.dp),
                        verticalArrangement = Arrangement.spacedBy(12.dp),
                    ) {
                        Text("Jay Squad Sec", style = MaterialTheme.typography.headlineMedium)
                        Text(
                            "Local Android security foundation",
                            style = MaterialTheme.typography.bodyMedium,
                        )
                        Card(modifier = Modifier.fillMaxWidth()) {
                            Column(Modifier.padding(16.dp)) {
                                Text("Protection status", style = MaterialTheme.typography.titleMedium)
                                Spacer(Modifier.height(6.dp))
                                Text("Alert-only: watches for app changes")
                                Text(
                                    "Nothing is blocked and nothing leaves the phone. " +
                                        "No network monitoring yet.",
                                    style = MaterialTheme.typography.bodySmall,
                                )
                                Spacer(Modifier.height(8.dp))
                                Text("Background checks", style = MaterialTheme.typography.titleSmall)
                                val tick = resumeTick.intValue
                                val last = remember(tick) { ChangeCheck.lastRunMs(applicationContext) }
                                val lastError = remember(tick) { ChangeCheck.lastError(applicationContext) }
                                val notifyOk = remember(tick) { Notifier.canNotify(applicationContext) }
                                val restricted = remember(tick) { backgroundRestricted() }
                                Text(
                                    "About every hour, alerts by notification. Last check: " +
                                        (last?.let {
                                            java.text.DateFormat.getDateTimeInstance(
                                                java.text.DateFormat.MEDIUM,
                                                java.text.DateFormat.SHORT,
                                            ).format(java.util.Date(it))
                                        } ?: "not yet"),
                                    style = MaterialTheme.typography.bodySmall,
                                )
                                if (lastError != null) {
                                    Text(
                                        "The last background check failed ($lastError). It will retry.",
                                        color = MaterialTheme.colorScheme.error,
                                        style = MaterialTheme.typography.bodySmall,
                                    )
                                } else if (last != null && System.currentTimeMillis() - last > 3L * 60 * 60 * 1000) {
                                    Text(
                                        "The background check has not run for over 3 hours. Android may be " +
                                            "stopping it: set Battery to No restriction in this app's settings.",
                                        color = MaterialTheme.colorScheme.error,
                                        style = MaterialTheme.typography.bodySmall,
                                    )
                                }
                                if (!notifyOk) {
                                    Text(
                                        "Notifications are off, so changes only show here. " +
                                            "Turn them on in this app's settings.",
                                        color = MaterialTheme.colorScheme.error,
                                        style = MaterialTheme.typography.bodySmall,
                                    )
                                }
                                if (restricted) {
                                    Text(
                                        "Android is restricting this app in the background, so checks may not run. " +
                                            "In this app's settings, set Battery to No restriction.",
                                        color = MaterialTheme.colorScheme.error,
                                        style = MaterialTheme.typography.bodySmall,
                                    )
                                }
                                if (!notifyOk || restricted) {
                                    OutlinedButton(onClick = { openAppSettings(packageName) }) {
                                        Text("Open this app's settings")
                                    }
                                }
                                Spacer(Modifier.height(8.dp))
                                Text("Security engine", style = MaterialTheme.typography.titleSmall)
                                val result = engine
                                Text(
                                    result?.summary ?: "Checking native engine...",
                                    color = if (result != null && !result.ok) {
                                        MaterialTheme.colorScheme.error
                                    } else {
                                        MaterialTheme.colorScheme.onSurface
                                    },
                                    style = MaterialTheme.typography.bodySmall,
                                )
                            }
                        }
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                        ) {
                            Text("Visible launchable apps: ${apps.size}")
                            Button(
                                enabled = !loading,
                                onClick = { requestRefresh() },
                            ) { Text("Refresh") }
                        }
                        Text(
                            "Android limits which installed packages ordinary apps can see. " +
                                "This list is not a complete device inventory.",
                            style = MaterialTheme.typography.bodySmall,
                        )
                        if (!loading && error == null) {
                            Card(modifier = Modifier.fillMaxWidth()) {
                                Column(Modifier.padding(16.dp)) {
                                    Text("Changes since baseline", style = MaterialTheme.typography.titleMedium)
                                    Spacer(Modifier.height(6.dp))
                                    baselineNote?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
                                    if (changes.isEmpty() && baselineNote?.startsWith("Compared") != false) {
                                        Text("No changes.", style = MaterialTheme.typography.bodySmall)
                                    }
                                    val byPackage = changes.groupBy { it.packageName }
                                    byPackage.entries.take(6).forEach { (pkg, pkgChanges) ->
                                        Spacer(Modifier.height(8.dp))
                                        pkgChanges.forEach { change ->
                                            Text(
                                                describe(change, labels[pkg]),
                                                color = if (change.severity >= 3) {
                                                    MaterialTheme.colorScheme.error
                                                } else {
                                                    MaterialTheme.colorScheme.onSurface
                                                },
                                                style = MaterialTheme.typography.bodySmall,
                                            )
                                        }
                                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                            Button(onClick = { accept(setOf(pkg), null) }) { Text("Accept") }
                                            if (pkg in currentFp) {
                                                OutlinedButton(onClick = { openAppSettings(pkg) }) {
                                                    Text("Reject: open settings")
                                                }
                                            }
                                        }
                                    }
                                    if (byPackage.size > 6) {
                                        Text("+ ${byPackage.size - 6} more apps with changes", style = MaterialTheme.typography.bodySmall)
                                    }
                                    if (changes.isNotEmpty()) {
                                        Spacer(Modifier.height(6.dp))
                                        Text(
                                            "Reject opens the app's settings: switch the permission off or uninstall " +
                                                "the app there. The warning clears once the change is undone. " +
                                                "Android does not let one app change another app's permissions.",
                                            style = MaterialTheme.typography.bodySmall,
                                        )
                                        // Only what is on screen: never accept changes the user has not seen.
                                        val shown = byPackage.keys.take(6).toSet()
                                        OutlinedButton(onClick = {
                                            accept(shown, "Accepted changes for ${shown.size} apps.")
                                        }) { Text(if (byPackage.size > 6) "Accept these ${shown.size}" else "Accept all") }
                                    }
                                }
                            }
                        }
                        if (loading) {
                            CircularProgressIndicator()
                        } else if (error != null) {
                            Text("Could not read inventory: $error", color = MaterialTheme.colorScheme.error)
                        } else {
                            LazyColumn(
                                modifier = Modifier.weight(1f),
                                contentPadding = PaddingValues(bottom = 16.dp),
                                verticalArrangement = Arrangement.spacedBy(8.dp),
                            ) {
                                items(apps, key = { it.packageName }) { app ->
                                    Card(modifier = Modifier.fillMaxWidth()) {
                                        Column(Modifier.padding(12.dp)) {
                                            Text(safeLabel(app.label, 60), style = MaterialTheme.typography.titleSmall)
                                            Text(app.packageName, style = MaterialTheme.typography.bodySmall)
                                            Text(
                                                "Signer SHA-256: ${app.signerSha256 ?: "unavailable"}",
                                                style = MaterialTheme.typography.bodySmall,
                                            )
                                            if (app.permissions.isNotEmpty()) {
                                                Spacer(Modifier.height(6.dp))
                                                Text("Requested permissions", style = MaterialTheme.typography.labelMedium)
                                                app.permissions.take(5).forEach { permission ->
                                                    Text(
                                                        "${if (permission.granted) "Granted" else "Not granted"}: ${safeLabel(permission.name, 80)}",
                                                        style = MaterialTheme.typography.bodySmall,
                                                    )
                                                }
                                                if (app.permissions.size > 5) {
                                                    Text("+ ${app.permissions.size - 5} more")
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
