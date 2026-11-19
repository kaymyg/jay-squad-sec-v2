import com.jaysquadsec.bridge.NativeBridge;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Exercises the real JNI boundary in a live JVM: the same native methods the
 * Android app calls. Run with -ea. Exits non-zero on any failure.
 */
public final class BridgeTest {
    private static final byte[] APP = utf8("com.example.app:sha256:ab12");
    private static int passed = 0;

    static byte[] utf8(String s) { return s.getBytes(StandardCharsets.UTF_8); }

    static void check(boolean cond, String what) {
        if (!cond) throw new AssertionError("FAILED: " + what);
    }

    static int submit(long h, int pid, long gen, byte[] ident, String kind, String detail, long at) {
        return NativeBridge.nativeSubmit(h, pid, gen, ident, utf8(kind), utf8(detail), at);
    }

    static String drain(long h) {
        StringBuilder sb = new StringBuilder();
        while (true) {
            byte[] chunk = NativeBridge.nativeTakeAlerts(h, 0); // raised to the minimum
            check(chunk != null, "take on live handle");
            if (chunk.length == 0) return sb.toString();
            String s = new String(chunk, StandardCharsets.UTF_8);
            check(s.endsWith("\n"), "chunk ends on a line boundary");
            sb.append(s);
        }
    }

    static void run(String name, Runnable r) {
        r.run();
        passed++;
        System.out.println("  ok  " + name);
    }

    public static void main(String[] args) throws Exception {
        System.loadLibrary("jay_squad_sec_bridge");
        System.out.println("BridgeTest (JNI, live JVM " + System.getProperty("java.version") + ")");

        run("abi version matches", () ->
            check(NativeBridge.nativeAbiVersion() == NativeBridge.EXPECTED_ABI, "abi"));

        run("detection flows out through JNI", () -> {
            long h = NativeBridge.nativeNew(7);
            check(h != 0, "new");
            String[] chain = {"unsigned_module_load", "rwx_alloc", "privilege_escalation",
                              "remote_thread_injection", "credential_access"};
            for (int i = 0; i < chain.length; i++) {
                check(submit(h, 4242, 1, APP, chain[i], "", 1000 + 100L * i) == NativeBridge.OK, chain[i]);
            }
            String alerts = drain(h);
            check(alerts.contains("BLOCKED"), "block alert reached Java: " + alerts);
            check(alerts.contains("alert-only"), "alert-only mode");
            check(NativeBridge.nativeFree(h) == NativeBridge.OK, "free");
        });

        run("double close and use-after-close are errors, not crashes", () -> {
            long h = NativeBridge.nativeNew(7);
            check(NativeBridge.nativeFree(h) == NativeBridge.OK, "first free");
            check(NativeBridge.nativeFree(h) == NativeBridge.ERR_BAD_HANDLE, "double free");
            check(submit(h, 1, 1, APP, "file_write", "", 1) == NativeBridge.ERR_BAD_HANDLE, "use after free");
            check(NativeBridge.nativeTakeAlerts(h, 4096) == null, "take after free");
            check(NativeBridge.nativeFree(0) == NativeBridge.ERR_BAD_HANDLE, "zero handle");
            check(NativeBridge.nativeFree(-1) == NativeBridge.ERR_BAD_HANDLE, "bogus handle");
        });

        run("null arrays and hostile input are rejected", () -> {
            long h = NativeBridge.nativeNew(7);
            check(NativeBridge.nativeSubmit(h, 1, 1, null, utf8("file_write"), utf8(""), 1)
                  == NativeBridge.ERR_NULL, "null identity");
            check(NativeBridge.nativeSubmit(h, 1, 1, APP, utf8("file_write"), null, 1)
                  == NativeBridge.ERR_NULL, "null detail");
            check(submit(h, -5, 1, APP, "file_write", "", 1) == NativeBridge.ERR_INVALID, "negative pid");
            check(submit(h, 1, -1, APP, "file_write", "", 1) == NativeBridge.ERR_INVALID, "negative generation");
            check(submit(h, 1, 1, APP, "file_write", "", -1) == NativeBridge.ERR_INVALID, "negative time");
            check(submit(h, 1, 1, APP, "nope", "", 1) == NativeBridge.ERR_INVALID, "unknown kind");
            check(submit(h, 1, 1, APP, "file_write", "x‮y", 1) == NativeBridge.ERR_INVALID, "bidi");
            check(submit(h, 1, 1, new byte[100_000], "file_write", "", 1)
                  == NativeBridge.ERR_INVALID, "oversized identity");
            check(NativeBridge.nativeSubmit(h, 1, 1, new byte[] {(byte) 0xFF}, utf8("file_write"),
                  utf8(""), 1) == NativeBridge.ERR_INVALID, "invalid UTF-8");
            NativeBridge.nativeFree(h);
        });

        run("identity of a live process cannot change", () -> {
            long h = NativeBridge.nativeNew(7);
            check(submit(h, 99, 1, APP, "file_write", "", 1) == NativeBridge.OK, "first");
            check(submit(h, 99, 1, utf8("com.attacker:sha256:ff"), "file_write", "", 2)
                  == NativeBridge.ERR_IDENTITY_MISMATCH, "swap identity");
            NativeBridge.nativeFree(h);
        });

        run("close while 8 threads are submitting (x20)", () -> {
            for (int round = 0; round < 20; round++) {
                long h = NativeBridge.nativeNew(7);
                CyclicBarrier start = new CyclicBarrier(9);
                AtomicReference<Throwable> failure = new AtomicReference<>();
                List<Thread> threads = new ArrayList<>();
                for (int t = 0; t < 8; t++) {
                    final int pid = 100 + t;
                    Thread th = new Thread(() -> {
                        try {
                            start.await();
                            for (int i = 0; i < 300; i++) {
                                int c = submit(h, pid, 1, APP, "network_connect", "example.org:443", i);
                                if (c != NativeBridge.OK && c != NativeBridge.ERR_BAD_HANDLE)
                                    throw new AssertionError("unexpected code " + c);
                                NativeBridge.nativeTakeAlerts(h, 4096);
                            }
                        } catch (Throwable e) { failure.compareAndSet(null, e); }
                    });
                    threads.add(th);
                    th.start();
                }
                try { start.await(); } catch (Exception e) { throw new RuntimeException(e); }
                Thread.yield();
                check(NativeBridge.nativeFree(h) == NativeBridge.OK, "free while busy");
                for (Thread th : threads) {
                    try { th.join(); } catch (InterruptedException e) { throw new RuntimeException(e); }
                }
                check(failure.get() == null, "worker: " + failure.get());
                check(submit(h, 1, 1, APP, "file_write", "", 1) == NativeBridge.ERR_BAD_HANDLE, "dead after free");
            }
        });

        run("engine capacity enforced across JNI", () -> {
            long[] hs = new long[8];
            for (int i = 0; i < hs.length; i++) { hs[i] = NativeBridge.nativeNew(i); check(hs[i] != 0, "new " + i); }
            check(NativeBridge.nativeNew(99) == 0, "over capacity");
            for (long h : hs) NativeBridge.nativeFree(h);
            long h = NativeBridge.nativeNew(1);
            check(h != 0, "capacity freed");
            NativeBridge.nativeFree(h);
        });

        System.out.println("BridgeTest: " + passed + " passed, 0 failed");
    }
}
