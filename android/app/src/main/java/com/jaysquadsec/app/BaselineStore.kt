package com.jaysquadsec.app

import java.io.File
import java.io.FileOutputStream

/**
 * Persists the inventory baseline in app-private storage (excluded from
 * backup and device transfer). Writes are atomic: temp file, fsync, rename.
 */
class BaselineStore(private val dir: File) {
    sealed class Loaded {
        object Missing : Loaded()
        object Corrupt : Loaded()
        class Ok(val apps: Map<String, AppFingerprint>, val recordedAtMs: Long) : Loaded()
    }

    private val file get() = File(dir, FILE)

    fun load(): Loaded {
        val f = file
        if (!f.exists()) return Loaded.Missing
        if (!f.isFile || f.length() > MAX_BYTES) return Loaded.Corrupt
        val apps = runCatching { BaselineCodec.decode(f.readText(Charsets.UTF_8)) }.getOrNull()
        return if (apps == null) Loaded.Corrupt else Loaded.Ok(apps, f.lastModified())
    }

    /**
     * The screen and the background check may both save; one process-wide
     * lock and a unique temp file per write keep them from interleaving.
     */
    fun save(apps: Collection<AppFingerprint>) = synchronized(WRITE_LOCK) {
        dir.mkdirs()
        val tmp = File.createTempFile("$FILE.", ".tmp", dir)
        try {
            FileOutputStream(tmp).use { out ->
                out.write(BaselineCodec.encode(apps).toByteArray(Charsets.UTF_8))
                out.fd.sync()
            }
            if (!tmp.renameTo(file)) throw java.io.IOException("could not save inventory baseline")
        } finally {
            if (tmp.exists()) tmp.delete()
        }
    }

    companion object {
        const val FILE = "inventory-baseline.v1"
        val WRITE_LOCK = Any()
        private const val MAX_BYTES = 4L * 1024 * 1024
    }
}
