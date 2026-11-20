package com.jaysquadsec.app

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
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
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val inventory = PackageInventoryReader(applicationContext)
        val baselineStore = BaselineStore(applicationContext.filesDir)

        setContent {
            MaterialTheme(colorScheme = lightColorScheme()) {
                Surface(modifier = Modifier.fillMaxSize()) {
                    var apps by remember { mutableStateOf<List<AppObservation>>(emptyList()) }
                    var loading by remember { mutableStateOf(true) }
                    var error by remember { mutableStateOf<String?>(null) }
                    var engine by remember { mutableStateOf<EngineSelfTest.Result?>(null) }
                    var changes by remember { mutableStateOf<List<InventoryChange>>(emptyList()) }
                    var baselineNote by remember { mutableStateOf<String?>(null) }
                    val labels = remember(apps) { apps.associate { it.packageName to it.label } }
                    val scope = rememberCoroutineScope()

                    suspend fun refresh() {
                        loading = true
                        error = null
                        try {
                            val scanned = withContext(Dispatchers.IO) { inventory.readLaunchableApps() }
                            apps = scanned
                            val current = scanned.map { AppFingerprint.of(it) }
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
                            changes = found
                            baselineNote = note
                        } catch (failure: Exception) {
                            error = failure.message ?: "Inventory scan failed"
                        } finally {
                            loading = false
                        }
                    }

                    LaunchedEffect(Unit) {
                        engine = withContext(Dispatchers.Default) { EngineSelfTest.run() }
                    }
                    LaunchedEffect(Unit) { refresh() }

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
                                Text("Inventory-only preview")
                                Text(
                                    "No background monitoring or network blocking is active.",
                                    style = MaterialTheme.typography.bodySmall,
                                )
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
                                onClick = { scope.launch { refresh() } },
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
                                    changes.take(8).forEach { change ->
                                        val name = labels[change.packageName] ?: change.packageName
                                        Text(
                                            describe(change, name),
                                            color = if (change.severity >= 3) {
                                                MaterialTheme.colorScheme.error
                                            } else {
                                                MaterialTheme.colorScheme.onSurface
                                            },
                                            style = MaterialTheme.typography.bodySmall,
                                        )
                                    }
                                    if (changes.size > 8) Text("+ ${changes.size - 8} more", style = MaterialTheme.typography.bodySmall)
                                    if (changes.isNotEmpty()) {
                                        Spacer(Modifier.height(6.dp))
                                        Button(onClick = {
                                            scope.launch {
                                                withContext(Dispatchers.IO) {
                                                    baselineStore.save(apps.map { AppFingerprint.of(it) })
                                                }
                                                changes = emptyList()
                                                baselineNote = "Changes accepted as the new baseline (${apps.size} apps)."
                                            }
                                        }) { Text("Accept as new baseline") }
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
                                            Text(app.label, style = MaterialTheme.typography.titleSmall)
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
                                                        "${if (permission.granted) "Granted" else "Not granted"}: ${permission.name}",
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

private fun describe(change: InventoryChange, name: String): String = when (change) {
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
