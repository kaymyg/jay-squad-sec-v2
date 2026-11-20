package com.jaysquadsec.app

import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.job.JobInfo
import android.app.job.JobParameters
import android.app.job.JobScheduler
import android.app.job.JobService
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import java.io.File
import java.io.FileOutputStream
import java.util.concurrent.Executors

/**
 * One background inventory check: compare with the baseline and notify about
 * changes not announced before. Runs entirely on the device; reads only what
 * the foreground screen reads; never changes the baseline except to create
 * the first one (or replace an unreadable one, which is itself announced).
 */
object ChangeCheck {
    private const val LEDGER_FILE = "notified.v1"
    private const val LAST_RUN_FILE = "last-check"
    private val lock = Any()

    fun run(context: Context) {
        synchronized(lock) {
            val dir = context.filesDir
            val store = BaselineStore(dir)
            val apps = PackageInventoryReader(context).readLaunchableApps()
            val current = apps.map { AppFingerprint.of(it) }
            val labels = apps.associate { it.packageName to it.label }
            when (val stored = store.load()) {
                is BaselineStore.Loaded.Missing -> store.save(current)
                is BaselineStore.Loaded.Corrupt -> {
                    store.save(current)
                    Notifier.show(
                        context,
                        "Saved baseline was unreadable",
                        "It was corrupted or altered, so a new baseline was recorded. Open the app to review.",
                        emptyList(),
                    )
                }
                is BaselineStore.Loaded.Ok -> {
                    val changes = InventoryDiff.compare(stored.apps, current.associateBy { it.packageName })
                    val ledgerFile = File(dir, LEDGER_FILE)
                    val ledger = runCatching {
                        if (ledgerFile.isFile && ledgerFile.length() < 2_000_000) {
                            NotifyPolicy.decode(ledgerFile.readText())
                        } else {
                            emptySet()
                        }
                    }.getOrDefault(emptySet())
                    val decision = NotifyPolicy.decide(changes, ledger)
                    if (decision.toNotify.isNotEmpty()) {
                        val lines = decision.toNotify.map { describe(it, labels[it.packageName] ?: it.packageName) }
                        val title = if (lines.size == 1) "Security change found" else "${lines.size} security changes found"
                        Notifier.show(context, title, lines.first(), lines)
                    }
                    atomicWrite(dir, LEDGER_FILE, NotifyPolicy.encode(decision.ledger))
                }
            }
            atomicWrite(dir, LAST_RUN_FILE, System.currentTimeMillis().toString())
        }
    }

    /** Time of the last completed background check, or null if none yet. */
    fun lastRunMs(context: Context): Long? =
        runCatching { File(context.filesDir, LAST_RUN_FILE).readText().trim().toLong() }.getOrNull()

    private fun atomicWrite(dir: File, name: String, text: String) = synchronized(BaselineStore.WRITE_LOCK) {
        val tmp = File.createTempFile("$name.", ".tmp", dir)
        try {
            FileOutputStream(tmp).use { it.write(text.toByteArray(Charsets.UTF_8)); it.fd.sync() }
            tmp.renameTo(File(dir, name))
        } finally {
            if (tmp.exists()) tmp.delete()
        }
    }
}

/** Android's scheduler starts this; it is not exported and requires BIND_JOB_SERVICE. */
class ChangeCheckJob : JobService() {
    private val executor = Executors.newSingleThreadExecutor()

    override fun onStartJob(params: JobParameters): Boolean {
        executor.execute {
            runCatching { ChangeCheck.run(applicationContext) }
            jobFinished(params, false)
        }
        return true
    }

    override fun onStopJob(params: JobParameters): Boolean = true

    override fun onDestroy() {
        executor.shutdown()
        super.onDestroy()
    }

    companion object {
        private const val JOB_ID = 4201
        private const val PERIOD_MS = 60L * 60 * 1000
        private const val FLEX_MS = 15L * 60 * 1000

        /** Idempotent: keeps an existing schedule. Persisted across reboots. */
        fun schedule(context: Context) {
            val scheduler = context.getSystemService(JobScheduler::class.java) ?: return
            if (scheduler.allPendingJobs.any { it.id == JOB_ID }) return
            val job = JobInfo.Builder(JOB_ID, ComponentName(context, ChangeCheckJob::class.java))
                .setPeriodic(PERIOD_MS, FLEX_MS)
                .setPersisted(true)
                .build()
            scheduler.schedule(job)
        }
    }
}

object Notifier {
    private const val CHANNEL = "security-changes"
    private const val ID = 1

    fun canNotify(context: Context): Boolean =
        Build.VERSION.SDK_INT < 33 ||
            context.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED

    fun show(context: Context, title: String, text: String, lines: List<String>) {
        if (!canNotify(context)) return
        val nm = context.getSystemService(NotificationManager::class.java) ?: return
        nm.createNotificationChannel(
            NotificationChannel(CHANNEL, "Security changes", NotificationManager.IMPORTANCE_DEFAULT).apply {
                description = "New apps, changed signing certificates and new sensitive access"
                lockscreenVisibility = Notification.VISIBILITY_PRIVATE
            },
        )
        // Explicit, immutable intent to our own activity: no other app can
        // redirect or alter it.
        val open = PendingIntent.getActivity(
            context,
            0,
            Intent(context, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        // Lock screen shows only this; details need the phone unlocked.
        val publicVersion = Notification.Builder(context, CHANNEL)
            .setSmallIcon(R.drawable.ic_stat_shield)
            .setContentTitle("Jay Squad Sec")
            .setContentText(title)
            .build()
        val style = Notification.InboxStyle()
        lines.take(6).forEach { style.addLine(it) }
        if (lines.size > 6) style.setSummaryText("+ ${lines.size - 6} more")
        val n = Notification.Builder(context, CHANNEL)
            .setSmallIcon(R.drawable.ic_stat_shield)
            .setContentTitle(title)
            .setContentText(text)
            .setStyle(if (lines.size > 1) style else Notification.BigTextStyle().bigText(text))
            .setVisibility(Notification.VISIBILITY_PRIVATE)
            .setPublicVersion(publicVersion)
            .setContentIntent(open)
            .setAutoCancel(true)
            .build()
        runCatching { nm.notify(ID, n) }
    }
}
