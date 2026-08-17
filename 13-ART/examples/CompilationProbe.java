package com.artlab.probe;

import android.app.Activity;
import android.content.pm.ApplicationInfo;
import android.os.Build;
import android.os.Bundle;
import android.os.Debug;
import android.util.Log;
import android.widget.ScrollView;
import android.widget.TextView;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.lang.reflect.Method;

/**
 * CompilationProbe — an app that reports its own ART runtime state.
 *
 * WHAT IT DEMONSTRATES
 *   Everything chapter 13 describes from the outside, observed from the inside
 *   of a running app. Useful as a teaching aid, and genuinely useful as a
 *   diagnostic when you are handed a device and want to know what state its
 *   runtime is in without adb.
 *
 *   It reports:
 *     - which ART artifacts exist for this app, and their sizes
 *     - whether this process is debuggable (which forces interpretation)
 *     - heap configuration and current usage
 *     - VMRuntime internals reached by reflection
 *     - whether a debugger or method tracing is active (i.e. deoptimized)
 *     - the boot class path, which shows the APEX/Mainline split
 *
 * HOW TO RUN
 *   Drop into any Android project as the launcher Activity, build, install.
 *   Output goes to the screen and to logcat under the tag ARTPROBE.
 *
 *     adb logcat -s ARTPROBE
 *
 * WHY REFLECTION
 *   Several of the interesting values live behind @hide APIs. On modern
 *   Android these are subject to non-SDK interface restrictions, so some
 *   lookups will fail — that failure is itself informative and is reported
 *   rather than swallowed. See ../README.md section 3.15 on access_flags_
 *   and the hidden-API bits.
 *
 * NOTE
 *   This reads only its OWN state. It requires no permissions and no root.
 */
public class CompilationProbe extends Activity {

    private static final String TAG = "ARTPROBE";
    private final StringBuilder report = new StringBuilder();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        TextView tv = new TextView(this);
        tv.setTextSize(11f);
        tv.setPadding(24, 24, 24, 24);
        ScrollView sv = new ScrollView(this);
        sv.addView(tv);
        setContentView(sv);

        buildReport();

        String text = report.toString();
        tv.setText(text);
        for (String line : text.split("\n")) {
            Log.i(TAG, line);
        }
    }

    private void section(String title) {
        report.append("\n== ").append(title).append(" ==\n");
    }

    private void kv(String key, Object value) {
        report.append(String.format("  %-34s %s%n", key, value));
    }

    private void buildReport() {
        report.append("ART RUNTIME PROBE\n");

        probeBuild();
        probeProcessState();
        probeArtifacts();
        probeHeap();
        probeVmRuntime();
        probeInstrumentation();
        probeBootClassPath();
        probeInterpretationHint();
    }

    // ------------------------------------------------------------------ //

    private void probeBuild() {
        section("PLATFORM");
        kv("Android release", Build.VERSION.RELEASE);
        kv("API level", Build.VERSION.SDK_INT);
        kv("Security patch", Build.VERSION.SECURITY_PATCH);
        kv("Fingerprint", Build.FINGERPRINT);
        kv("Supported ABIs", java.util.Arrays.toString(Build.SUPPORTED_ABIS));

        // The VM name distinguishes ART from the long-dead Dalvik.
        kv("java.vm.name", System.getProperty("java.vm.name"));
        kv("java.vm.version", System.getProperty("java.vm.version"));
    }

    private void probeProcessState() {
        section("THIS PROCESS");
        ApplicationInfo ai = getApplicationInfo();

        boolean debuggable = (ai.flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0;
        kv("package", getPackageName());
        kv("uid", ai.uid);
        kv("pid", android.os.Process.myPid());
        kv("debuggable", debuggable);

        if (debuggable) {
            report.append("    NOTE: a debuggable process forces interpretation in many\n");
            report.append("          paths and enables CheckJNI. Runtime behaviour here is\n");
            report.append("          NOT representative of a release build.\n");
        }

        kv("sourceDir", ai.sourceDir);
        kv("nativeLibraryDir", ai.nativeLibraryDir);
        kv("dataDir", ai.dataDir);
    }

    private void probeArtifacts() {
        section("ART ARTIFACTS ON DISK");

        String apkPath = getApplicationInfo().sourceDir;
        File apk = new File(apkPath);
        File dir = apk.getParentFile();

        if (dir == null) {
            report.append("  could not resolve the APK's directory\n");
            return;
        }

        kv("APK", apk.getName() + "  (" + apk.length() + " bytes)");

        File oatRoot = new File(dir, "oat");
        if (!oatRoot.isDirectory()) {
            report.append("  no oat/ directory visible from this process\n");
            report.append("  (normal — the app usually cannot read it)\n");
            return;
        }

        File[] isaDirs = oatRoot.listFiles();
        if (isaDirs == null) {
            report.append("  oat/ exists but is not readable by this process\n");
            return;
        }

        for (File isa : isaDirs) {
            report.append("  ISA: ").append(isa.getName()).append("\n");
            File[] files = isa.listFiles();
            if (files == null) {
                report.append("    (not readable)\n");
                continue;
            }
            for (File f : files) {
                report.append(String.format("    %-16s %,12d bytes%n",
                        f.getName(), f.length()));
                if (f.getName().endsWith(".odex")) {
                    report.append("      ^ despite the name this is an OAT file (ELF)\n");
                } else if (f.getName().endsWith(".vdex")) {
                    report.append("      ^ this is where the DEX bytecode actually lives\n");
                } else if (f.getName().endsWith(".art")) {
                    report.append("      ^ app image: present only under compiling filters\n");
                }
            }
        }
    }

    private void probeHeap() {
        section("HEAP");
        Runtime rt = Runtime.getRuntime();

        kv("max heap (heapgrowthlimit)", fmt(rt.maxMemory()));
        kv("total allocated", fmt(rt.totalMemory()));
        kv("free within total", fmt(rt.freeMemory()));
        kv("used", fmt(rt.totalMemory() - rt.freeMemory()));

        // Native heap is a different arena entirely — see README section 3.21.
        kv("native heap size", fmt(Debug.getNativeHeapSize()));
        kv("native heap allocated", fmt(Debug.getNativeHeapAllocatedSize()));
        kv("native heap free", fmt(Debug.getNativeHeapFreeSize()));

        report.append("    The 'dalvik heap' (managed) and the native heap are separate.\n");
        report.append("    ArtMethod structures live in NATIVE memory, which is exactly\n");
        report.append("    why the GC never moves them and why they are stable to patch.\n");
    }

    /**
     * VMRuntime exposes several genuinely useful internals, but it is @hide.
     * On modern Android the non-SDK interface restrictions may block these
     * lookups — which is itself worth observing.
     */
    private void probeVmRuntime() {
        section("VMRuntime (via reflection, @hide)");
        try {
            Class<?> vmRuntimeClass = Class.forName("dalvik.system.VMRuntime");
            Method getRuntime = vmRuntimeClass.getDeclaredMethod("getRuntime");
            getRuntime.setAccessible(true);
            Object vmRuntime = getRuntime.invoke(null);

            tryInvoke(vmRuntimeClass, vmRuntime, "vmLibrary",
                      "VM library (libart.so expected)");
            tryInvoke(vmRuntimeClass, vmRuntime, "vmVersion", "VM version");
            tryInvoke(vmRuntimeClass, vmRuntime, "vmInstructionSet", "instruction set");
            tryInvoke(vmRuntimeClass, vmRuntime, "is64Bit", "64-bit");
            tryInvoke(vmRuntimeClass, vmRuntime, "isCheckJniEnabled", "CheckJNI enabled");
            tryInvoke(vmRuntimeClass, vmRuntime, "isNativeDebuggable", "native debuggable");
            tryInvoke(vmRuntimeClass, vmRuntime, "isJavaDebuggable", "java debuggable");
            tryInvoke(vmRuntimeClass, vmRuntime, "getTargetSdkVersion", "target SDK");

        } catch (Throwable t) {
            report.append("  unavailable: ").append(t.getClass().getSimpleName())
                  .append(": ").append(t.getMessage()).append("\n");
            report.append("  (non-SDK interface restrictions may be blocking this —\n");
            report.append("   see README section 3.15 on hidden-API bits in access_flags_)\n");
        }
    }

    private void tryInvoke(Class<?> cls, Object target, String name, String label) {
        try {
            Method m = cls.getDeclaredMethod(name);
            m.setAccessible(true);
            kv(label, m.invoke(target));
        } catch (Throwable t) {
            kv(label, "<blocked: " + t.getClass().getSimpleName() + ">");
        }
    }

    /**
     * Detect whether the runtime is currently instrumented. When a debugger is
     * attached or method tracing is active, ART deoptimizes and switches to the
     * slow switch interpreter — see README sections 3.13 and 3.20.
     */
    private void probeInstrumentation() {
        section("INSTRUMENTATION / DEOPTIMIZATION");

        kv("Debug.isDebuggerConnected()", Debug.isDebuggerConnected());
        kv("Debug.waitingForDebugger()", Debug.waitingForDebugger());

        // TracerPid in /proc/self/status is non-zero when ptrace-attached.
        // This is the single most common anti-debug check; see chapter 38.
        String tracerPid = readTracerPid();
        kv("/proc/self/status TracerPid", tracerPid);
        if (!"0".equals(tracerPid) && !"?".equals(tracerPid)) {
            report.append("    A tracer is attached (debugger, Frida, or strace).\n");
            report.append("    The runtime is very likely deoptimized right now.\n");
        }

        // A crude timing probe. A method this trivial should be compiled and
        // effectively free; a large figure suggests interpretation.
        long start = System.nanoTime();
        long acc = 0;
        for (int i = 0; i < 1_000_000; i++) {
            acc += trivial(i);
        }
        long elapsed = System.nanoTime() - start;
        kv("1M trivial() calls", (elapsed / 1_000_000) + " ms  (acc=" + acc + ")");
        report.append("    Rough guide: single-digit ms suggests compiled code;\n");
        report.append("    tens or hundreds of ms suggests interpretation.\n");
        report.append("    This is exactly the signal timing-based anti-debug uses.\n");
    }

    /** Deliberately trivial so the compiler will inline it if it compiles at all. */
    private static int trivial(int x) {
        return x & 0x7;
    }

    private String readTracerPid() {
        try (BufferedReader r = new BufferedReader(new FileReader("/proc/self/status"))) {
            String line;
            while ((line = r.readLine()) != null) {
                if (line.startsWith("TracerPid:")) {
                    return line.substring("TracerPid:".length()).trim();
                }
            }
        } catch (Exception ignored) { }
        return "?";
    }

    private void probeBootClassPath() {
        section("BOOT CLASS PATH");
        String bcp = System.getenv("BOOTCLASSPATH");
        if (bcp == null) {
            report.append("  BOOTCLASSPATH not visible from this process\n");
            return;
        }
        String[] entries = bcp.split(":");
        kv("entry count", entries.length);
        int apex = 0, system = 0;
        for (String e : entries) {
            if (e.startsWith("/apex/")) apex++;
            else system++;
        }
        kv("from /apex (Mainline)", apex);
        kv("from /system", system);
        report.append("  first few entries:\n");
        for (int i = 0; i < Math.min(6, entries.length); i++) {
            report.append("    ").append(entries[i]).append("\n");
        }
        report.append("  The /apex entries are Mainline modules updated independently\n");
        report.append("  of the OS. Their checksums are recorded in every OAT file, so\n");
        report.append("  a module update invalidates all compiled artifacts.\n");
    }

    private void probeInterpretationHint() {
        section("BOTTOM LINE");
        report.append("  To make Java hooks land reliably against this app:\n\n");
        report.append("    adb shell cmd package compile -m verify -f ")
              .append(getPackageName()).append("\n");
        report.append("    adb shell am force-stop ").append(getPackageName()).append("\n\n");
        report.append("  To restore normal performance afterwards:\n\n");
        report.append("    adb shell cmd package compile -m speed-profile -f ")
              .append(getPackageName()).append("\n");
    }

    private static String fmt(long bytes) {
        if (bytes < 1024) return bytes + " B";
        if (bytes < 1024 * 1024) return String.format("%.1f KB", bytes / 1024.0);
        return String.format("%.1f MB", bytes / (1024.0 * 1024.0));
    }
}
