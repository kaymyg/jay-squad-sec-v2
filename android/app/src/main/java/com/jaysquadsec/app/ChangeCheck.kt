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
    private const val LAST_ERROR_FILE = "last-check-error"
    private val lock = Any()

    fun run(context: Context) {
        synchronized(lock) {
            val dir = context.filesDir
            cleanStaleTemps(dir)
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
                    var posted = false
                    if (decision.unreviewed.isEmpty()) Notifier.cancel(context)
                    if (decision.toNotify.isNotEmpty()) {
                        // Show every unreviewed change, not only the new ones,
                        // so this post never hides an earlier unhandled alert.
                        val lines = decision.unreviewed.map { describe(it, labels[it.packageName]) }
                        posted = Notifier.show(context, notificationTitle(decision.unreviewed), lines.first(), lines)
                    }
                    atomicWrite(dir, LEDGER_FILE, NotifyPolicy.encode(NotifyPolicy.ledgerAfter(decision, ledger, posted)))
                }
            }
            atomicWrite(dir, LAST_RUN_FILE, System.currentTimeMillis().toString())
            File(dir, LAST_ERROR_FILE).delete()
        }
    }

    /** Called by the job when [run] throws, so the screen can say so honestly. */
    fun recordFailure(context: Context, failure: Throwable) {
        runCatching {
            atomicWrite(context.filesDir, LAST_ERROR_FILE, failure.javaClass.simpleName.take(60))
        }
    }

    /** Short reason the last background check failed, or null. */
    fun lastError(context: Context): String? =
        runCatching { File(context.filesDir, LAST_ERROR_FILE).readText().trim().take(60) }
            .getOrNull()?.filter { it.isLetterOrDigit() }?.ifEmpty { null }

    /** Time of the last completed background check, or null if none yet. */
    fun lastRunMs(context: Context): Long? =
        runCatching { File(context.filesDir, LAST_RUN_FILE).readText().trim().toLong() }.getOrNull()

    private fun atomicWrite(dir: File, name: String, text: String) = synchronized(BaselineStore.WRITE_LOCK) {
        val tmp = File.createTempFile("$name.", ".tmp", dir)
        try {
            FileOutputStream(tmp).use { it.write(text.toByteArray(Charsets.UTF_8)); it.fd.sync() }
            if (!tmp.renameTo(File(dir, name))) throw java.io.IOException("could not save $name")
        } finally {
            if (tmp.exists()) tmp.delete()
        }
    }

    /** Remove temp files left by a process that died mid-write (older than a minute). */
    fun cleanStaleTemps(dir: File) = synchronized(BaselineStore.WRITE_LOCK) {
        val cutoff = System.currentTimeMillis() - 60_000
        dir.listFiles()?.filter { it.isFile && it.name.endsWith(".tmp") && it.lastModified() < cutoff }
            ?.forEach { it.delete() }
    }
}

/** Android's scheduler starts this; it is not exported and requires BIND_JOB_SERVICE. */
class ChangeCheckJob : JobService() {
    private val executor = Executors.newSingleThreadExecutor()

    override fun onStartJob(params: JobParameters): Boolean {
        executor.execute {
            runCatching { ChangeCheck.run(applicationContext) }
                .onFailure { ChangeCheck.recordFailure(applicationContext, it) }
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
            if (scheduler.getPendingJob(JOB_ID) != null) return
            val job = JobInfo.Builder(JOB_ID, ComponentName(context, ChangeCheckJob::class.java))
                .setPeriodic(PERIOD_MS, FLEX_MS)
                .setPersisted(true)
                .build()
            scheduler.schedule(job)
        }
    }
}

object Notifier {
    // Channel settings are fixed once created, so a behaviour change needs a
    // new ID; the old channel is deleted.
    private const val CHANNEL = "security-alerts"
    private const val OLD_CHANNEL = "security-changes"
    private const val ID = 1

    /** Permission granted, notifications enabled for the app, and our channel not blocked. */
    fun canNotify(context: Context): Boolean {
        if (Build.VERSION.SDK_INT >= 33 &&
            context.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            return false
        }
        val nm = context.getSystemService(NotificationManager::class.java) ?: return false
        if (!nm.areNotificationsEnabled()) return false
        val channel = nm.getNotificationChannel(CHANNEL)
        return channel == null || channel.importance != NotificationManager.IMPORTANCE_NONE
    }

    /** Remove our alert once nothing is left to review. */
    fun cancel(context: Context) {
        runCatching { context.getSystemService(NotificationManager::class.java)?.cancel(ID) }
    }

    /** Returns true only if the notification was actually posted. */
    fun show(context: Context, title: String, text: String, lines: List<String>): Boolean {
        if (!canNotify(context)) return false
        val nm = context.getSystemService(NotificationManager::class.java) ?: return false
        // If the user had blocked the old channel, keep the new one blocked:
        // replacing a channel must never silently turn alerts back on.
        val oldBlocked = nm.getNotificationChannel(OLD_CHANNEL)?.importance == NotificationManager.IMPORTANCE_NONE
        nm.deleteNotificationChannel(OLD_CHANNEL)
        // HIGH: a small banner at the top for a few seconds, then it stays in
        // the shade. Never full screen (no full-screen intent is used).
        // Sound: the phone's default notification tone.
        nm.createNotificationChannel(
            NotificationChannel(
                CHANNEL,
                "Security alerts",
                if (oldBlocked) NotificationManager.IMPORTANCE_NONE else NotificationManager.IMPORTANCE_HIGH,
            ).apply {
                description = "An app gained sensitive access (SMS, microphone, camera, location...) " +
                    "or its signing certificate changed"
                lockscreenVisibility = Notification.VISIBILITY_PRIVATE
                setSound(
                    android.provider.Settings.System.DEFAULT_NOTIFICATION_URI,
                    android.media.AudioAttributes.Builder()
                        .setUsage(android.media.AudioAttributes.USAGE_NOTIFICATION)
                        .setContentType(android.media.AudioAttributes.CONTENT_TYPE_SONIFICATION)
                        .build(),
                )
                enableVibration(true)
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
            .setCategory(Notification.CATEGORY_STATUS)
            .setColor(0xFF1E88E5.toInt())
            .setAutoCancel(true)
            .build()
        // Re-check now that the channel exists: it may have been created blocked.
        if (!canNotify(context)) return false
        return runCatching { nm.notify(ID, n) }.isSuccess
    }
}
