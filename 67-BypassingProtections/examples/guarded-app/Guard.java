/*
 * examples/guarded-app/Guard.java
 *
 * The Java tier of the demonstration app's protection stack.
 *
 * WHAT THIS FILE IS FOR
 *   Chapter 67 argues that every client-side control, however it is
 *   implemented, collapses into the same five-stage pipeline:
 *
 *       input  ->  read  ->  verdict  ->  branch  ->  gated code
 *
 *   This class is that pipeline written out longhand so you can put a
 *   breakpoint on each stage. Each Signal below names the seam it is attacked
 *   at, in a field called `seam`, and the app prints that field. When you
 *   defeat a control you should be able to say which seam you attacked without
 *   guessing.
 *
 * WHAT THIS FILE IS NOT
 *   It is NOT a template for a real application. It is deliberately naive in
 *   ways a real hardened app is not:
 *     - the verdict is a plain Java object with public fields
 *     - the branch is a single `if`
 *     - the gated code is reachable without the branch
 *     - every signal has a readable string constant next to it
 *   Chapter 38 (Tamper Detection) owns the question of how to build these
 *   properly. This file exists to be broken.
 *
 * AUTHORISED USE
 *   This is an app you build. Attack it freely. Do not carry the techniques
 *   the labs teach on it to an application you neither own nor are contracted
 *   to test.
 */
package com.pentest.ch67.guarded;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.os.Debug;
import android.os.Process;
import android.util.Log;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;

public final class Guard {

    public static final String TAG = "CH67Guard";

    /* ------------------------------------------------------------------ */
    /* The five seams, named once so that every log line can quote them.   */
    /* ------------------------------------------------------------------ */

    public static final String SEAM_INPUT   = "S1-input";
    public static final String SEAM_READ    = "S2-read";
    public static final String SEAM_VERDICT = "S3-verdict";
    public static final String SEAM_BRANCH  = "S4-branch";
    public static final String SEAM_GATED   = "S5-gated";

    /* ------------------------------------------------------------------ */
    /* Response policies.                                                  */
    /*                                                                     */
    /* Each control below reacts differently ON PURPOSE. A real app would  */
    /* pick one. This app picks five, because the death signature is the   */
    /* only evidence a triager has when the process dies before it can be  */
    /* asked anything, and the five are genuinely distinguishable in       */
    /* `dumpsys activity exit-info`. See ../../scripts/bypass-triage.py.   */
    /* ------------------------------------------------------------------ */

    public enum Response {
        /** Do nothing but record. The honest default for telemetry. */
        REPORT,
        /** System.exit(42). exit-info: reason=1 EXIT_SELF, status=42. */
        EXIT_SELF,
        /** Process.killProcess(myPid()). exit-info: reason=2 SIGNALED, sig 9. */
        SIGKILL_SELF,
        /** Throw. exit-info: reason=4 CRASH, plus a Java stack in logcat. */
        THROW,
        /** Native abort(). exit-info: reason=5 CRASH_NATIVE, SIGABRT. */
        NATIVE_ABORT,
        /** Keep running, quietly produce wrong answers. The nastiest one. */
        POISON
    }

    /* ------------------------------------------------------------------ */
    /* A signal: one thing the app looks at, and what it decided.          */
    /* ------------------------------------------------------------------ */

    public static final class Signal {
        public final String id;
        public final String seam;      // where the READ happens, in seam terms
        public final int weight;
        public final Response response;
        public boolean fired;
        public String detail = "";

        Signal(String id, String seam, int weight, Response response) {
            this.id = id;
            this.seam = seam;
            this.weight = weight;
            this.response = response;
        }
    }

    /* ------------------------------------------------------------------ */
    /* A verdict: the boolean the whole chapter is about.                  */
    /* ------------------------------------------------------------------ */

    public static final class Verdict {
        public final List<Signal> signals = new ArrayList<Signal>();
        public int score;
        public boolean trusted;
        public String firstFired = "none";

        public String describe() {
            StringBuilder sb = new StringBuilder();
            sb.append("trusted=").append(trusted)
              .append(" score=").append(score)
              .append(" first=").append(firstFired)
              .append("\n");
            for (Signal s : signals) {
                sb.append(s.fired ? "  [FIRED] " : "  [ ok  ] ")
                  .append(s.id)
                  .append("  seam=").append(s.seam)
                  .append("  weight=").append(s.weight)
                  .append("  policy=").append(s.response);
                if (s.detail.length() > 0) sb.append("  (").append(s.detail).append(")");
                sb.append("\n");
            }
            return sb.toString();
        }
    }

    /** Anything at or above this refuses to run. */
    public static final int DENY_THRESHOLD = 50;

    private Guard() { }

    /* ================================================================== */
    /* The pipeline                                                        */
    /* ================================================================== */

    /**
     * Stage 2 and stage 3: perform every read, then compute one verdict.
     *
     * Note what this method does NOT do: it does not act. Separating the
     * verdict from the branch is good engineering AND it is the seam that
     * makes a one-line bypass possible. Both statements are true at once, and
     * chapter 67 section 5.4 is about living with that.
     */
    public static Verdict evaluate(Context ctx) {
        return evaluate(ctx, null);
    }

    /**
     * @param simulate comma-separated signal ids to mark as fired regardless of
     *                 what the read returned.
     *
     * WHAT `simulate` IS, STATED PLAINLY
     *   It is the app lying to itself, on purpose, so that a reader with a
     *   stock unrooted phone can still see what each response looks like from
     *   the outside. Most of these controls cannot be made to fire honestly
     *   without root or a live Frida server, and a death signature you have
     *   only read about is a death signature you cannot recognise at 2am.
     *
     *   It is NOT a bypass, it is NOT how the controls are defeated in any lab
     *   in this chapter, and every measurement in the chapter's prose states
     *   whether it was taken with a real trigger or a simulated one. Two of
     *   the seven signals - build.debuggable and frida.port27042 - can be made
     *   to fire for real with no root at all, and those are the ones the
     *   chapter's headline measurements use.
     */
    public static Verdict evaluate(Context ctx, String simulate) {
        Verdict v = new Verdict();

        v.signals.add(checkDebuggerAttached());
        v.signals.add(checkDebuggableFlag(ctx));
        v.signals.add(checkTracerPid());
        v.signals.add(checkFridaPort());
        v.signals.add(checkFridaThreadNames());
        v.signals.add(checkMapsForInjectedLibraries());
        v.signals.add(checkSuOnDisk());

        if (simulate != null && simulate.length() > 0) {
            for (String want : simulate.split(",")) {
                String id = want.trim();
                for (Signal s : v.signals) {
                    if (!s.id.equals(id)) continue;
                    s.fired = true;
                    s.detail = "SIMULATED (see Guard.evaluate javadoc) " + s.detail;
                    Log.w(TAG, "simulating signal " + id);
                }
            }
        }

        for (Signal s : v.signals) {
            if (s.fired) {
                v.score += s.weight;
                if ("none".equals(v.firstFired)) v.firstFired = s.id;
            }
        }
        v.trusted = v.score < DENY_THRESHOLD;
        Log.i(TAG, "verdict computed at seam " + SEAM_VERDICT + "\n" + v.describe());
        return v;
    }

    /**
     * Stage 4: the branch. One `if`. This is the most attractive hook in the
     * app and, for exactly that reason, usually the wrong one to take - see
     * chapter 67 section 3.7.
     */
    public static void enforce(Verdict v) {
        if (v.trusted) {
            Log.i(TAG, "branch " + SEAM_BRANCH + ": trusted, continuing");
            return;
        }
        Signal worst = null;
        for (Signal s : v.signals) {
            if (!s.fired) continue;
            if (worst == null || s.weight > worst.weight) worst = s;
        }
        Response r = (worst == null) ? Response.REPORT : worst.response;
        Log.w(TAG, "branch " + SEAM_BRANCH + ": UNTRUSTED, policy=" + r
                + " driven by " + (worst == null ? "?" : worst.id));
        react(r);
    }

    /**
     * The response. Read this next to scripts/bypass-triage.py: each arm here
     * has a matching signature there, and the mapping between the two is the
     * whole trick of attributing a death you did not see happen.
     */
    public static void react(Response r) {
        switch (r) {
            case REPORT:
                return;

            case EXIT_SELF:
                Log.w(TAG, "response=EXIT_SELF");
                // Flush the log before we go: logcat is the triager's only
                // witness and an unflushed line is a line that never existed.
                try { Thread.sleep(120); } catch (InterruptedException ignored) { }
                System.exit(42);
                return;

            case SIGKILL_SELF:
                Log.w(TAG, "response=SIGKILL_SELF");
                try { Thread.sleep(120); } catch (InterruptedException ignored) { }
                Process.killProcess(Process.myPid());
                return;

            case THROW:
                Log.w(TAG, "response=THROW");
                throw new SecurityException("CH67: integrity verdict was UNTRUSTED");

            case NATIVE_ABORT:
                Log.w(TAG, "response=NATIVE_ABORT");
                try { Thread.sleep(120); } catch (InterruptedException ignored) { }
                NativeGuard.abortNow();     // no-op if the .so is absent
                // If the native library was not packaged, fall through to a
                // response that definitely works, so the app never silently
                // continues after deciding not to.
                System.exit(43);
                return;

            case POISON:
                Log.w(TAG, "response=POISON (nothing visible will happen)");
                Vault.poison();
                return;
        }
    }

    /* ================================================================== */
    /* The individual reads - stage 2                                      */
    /* ================================================================== */

    /**
     * Debug.isDebuggerConnected() asks ART whether a JDWP debugger is
     * attached. It is NOT a ptrace check and does not read TracerPid; the two
     * catch different attackers, which is why both are here.
     *
     * Fires without root: `adb shell am set-debug-app -w <pkg>` then attach
     * jdb. See labs/lab-01.
     */
    static Signal checkDebuggerAttached() {
        Signal s = new Signal("debugger.jdwp", SEAM_READ, 60, Response.EXIT_SELF);
        try {
            boolean connected = Debug.isDebuggerConnected();
            boolean waiting = Debug.waitingForDebugger();
            s.fired = connected || waiting;
            s.detail = "connected=" + connected + " waiting=" + waiting;
        } catch (Throwable t) {
            s.detail = "read failed: " + t;
        }
        return s;
    }

    /**
     * The app's own FLAG_DEBUGGABLE. A release build is not debuggable; a
     * repackaged build very often is, because the attacker added the flag to
     * make jdb work. This is the cheapest tamper signal in Android and it is
     * also the one a five-second manifest edit removes.
     */
    static Signal checkDebuggableFlag(Context ctx) {
        Signal s = new Signal("build.debuggable", SEAM_INPUT, 55, Response.NATIVE_ABORT);
        try {
            ApplicationInfo ai = ctx.getApplicationInfo();
            s.fired = (ai.flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0;
            s.detail = "flags=0x" + Integer.toHexString(ai.flags);
        } catch (Throwable t) {
            s.detail = "read failed: " + t;
        }
        return s;
    }

    /**
     * TracerPid in /proc/self/status is non-zero while some process is
     * ptrace-attached. Frida's default injection ptraces briefly and then
     * detaches, so this catches a live gdb/lldb far more reliably than it
     * catches Frida.
     */
    static Signal checkTracerPid() {
        Signal s = new Signal("debugger.tracerpid", SEAM_READ, 60, Response.THROW);
        BufferedReader r = null;
        try {
            r = new BufferedReader(new FileReader("/proc/self/status"));
            String line;
            while ((line = r.readLine()) != null) {
                if (!line.startsWith("TracerPid:")) continue;
                int pid = Integer.parseInt(line.substring(10).trim());
                s.fired = pid != 0;
                s.detail = "TracerPid=" + pid;
                break;
            }
        } catch (Throwable t) {
            s.detail = "read failed: " + t;
        } finally {
            closeQuietly(r);
        }
        return s;
    }

    /**
     * The classic anti-Frida check: is anything listening on 27042?
     *
     * Fires without root and without frida-server: `adb reverse tcp:27042
     * tcp:<anything>` creates a real listener on the device's loopback that
     * this connect() succeeds against. That is how lab-01 measures it.
     *
     * It is also the weakest of the anti-Frida checks, because
     * `frida-server -l 127.0.0.1:1337` defeats it with no bypass at all.
     */
    static Signal checkFridaPort() {
        final Signal s = new Signal("frida.port27042", SEAM_INPUT, 50, Response.SIGKILL_SELF);

        /*
         * MEASURED, THE HARD WAY: this connect() must not run on the main
         * thread. StrictMode's default policy for a modern targetSdk throws
         * NetworkOnMainThreadException, and the first build of this app died
         * during onCreate with a Java crash that looked exactly like a control
         * firing - reason=4 CRASH in exit-info, dead before any UI.
         *
         * That is worth more than the check it broke. An app can die for
         * reasons that have nothing to do with its protections, and a triage
         * tool that assumes every early death is a control is wrong. Read the
         * stack trace before you believe the exit reason;
         * ../../scripts/bypass-triage.py prints both for this reason.
         */
        Thread t = new Thread(new Runnable() {
            @Override public void run() {
                Socket sock = null;
                try {
                    sock = new Socket();
                    sock.connect(new InetSocketAddress("127.0.0.1", 27042), 250);
                    s.fired = true;
                    s.detail = "connect() to 127.0.0.1:27042 succeeded";
                } catch (IOException e) {
                    s.detail = "refused: " + e.getClass().getSimpleName();
                } catch (Throwable other) {
                    s.detail = "probe failed: " + other;
                } finally {
                    if (sock != null) try { sock.close(); } catch (IOException ignored) { }
                }
            }
        }, "ch67-portprobe");
        t.start();
        try {
            t.join(1500);
        } catch (InterruptedException e) {
            s.detail = "probe interrupted";
        }
        return s;
    }

    /**
     * Frida's agent runs threads with recognisable names. /proc/self/task/N/comm
     * is readable by the process itself with no permission at all.
     */
    static Signal checkFridaThreadNames() {
        Signal s = new Signal("frida.threadnames", SEAM_READ, 70, Response.SIGKILL_SELF);
        try {
            File task = new File("/proc/self/task");
            File[] tids = task.listFiles();
            if (tids == null) { s.detail = "task dir unreadable"; return s; }
            for (File t : tids) {
                String comm = readFirstLine(new File(t, "comm"));
                if (comm == null) continue;
                if (comm.contains("gum-js") || comm.contains("gmain")
                        || comm.contains("frida") || comm.contains("pool-frida")
                        || comm.contains("gdbus")) {
                    s.fired = true;
                    s.detail = "thread " + t.getName() + " named '" + comm + "'";
                    return s;
                }
            }
            s.detail = tids.length + " threads, none suspicious";
        } catch (Throwable t) {
            s.detail = "read failed: " + t;
        }
        return s;
    }

    /**
     * /proc/self/maps lists every mapped file. An injected agent is a mapped
     * file. This is the check that survives renaming the frida-server binary,
     * because the agent's PATH is what appears, not the server's.
     */
    static Signal checkMapsForInjectedLibraries() {
        Signal s = new Signal("frida.maps", SEAM_READ, 70, Response.POISON);
        BufferedReader r = null;
        try {
            r = new BufferedReader(new FileReader("/proc/self/maps"));
            String line;
            int lines = 0;
            while ((line = r.readLine()) != null) {
                lines++;
                String low = line.toLowerCase();
                if (low.contains("frida") || low.contains("gum-js")
                        || low.contains("gadget") || low.contains("linjector")
                        || low.contains("/data/local/tmp/")) {
                    s.fired = true;
                    s.detail = "mapping: " + line.trim();
                    return s;
                }
            }
            s.detail = lines + " mappings, none suspicious";
        } catch (Throwable t) {
            s.detail = "read failed: " + t;
        } finally {
            closeQuietly(r);
        }
        return s;
    }

    /**
     * One root signal, present so the app has a control that will NOT fire on
     * a stock device. "Control present, did not fire" is a distinct triage
     * outcome from "control absent", and a tool that cannot tell them apart is
     * not a triage tool.
     *
     * Root detection proper is chapter 37's subject, not this chapter's.
     */
    static Signal checkSuOnDisk() {
        Signal s = new Signal("root.su", SEAM_INPUT, 40, Response.EXIT_SELF);
        String[] paths = {
            "/system/bin/su", "/system/xbin/su", "/sbin/su",
            "/system/sbin/su", "/vendor/bin/su", "/data/local/bin/su",
            "/data/local/xbin/su", "/data/adb/magisk"
        };
        StringBuilder found = new StringBuilder();
        for (String p : paths) {
            if (new File(p).exists()) {
                s.fired = true;
                if (found.length() > 0) found.append(",");
                found.append(p);
            }
        }
        s.detail = s.fired ? ("found " + found) : (paths.length + " paths, none present");
        return s;
    }

    /* ================================================================== */
    /* helpers                                                             */
    /* ================================================================== */

    private static String readFirstLine(File f) {
        BufferedReader r = null;
        try {
            r = new BufferedReader(new FileReader(f));
            String s = r.readLine();
            return s == null ? null : s.trim();
        } catch (Throwable t) {
            return null;
        } finally {
            closeQuietly(r);
        }
    }

    private static void closeQuietly(BufferedReader r) {
        if (r == null) return;
        try { r.close(); } catch (IOException ignored) { }
    }
}
