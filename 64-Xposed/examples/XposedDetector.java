// examples/XposedDetector.java
//
// THE DETECTION SURFACE THAT OUTLIVED THE FRAMEWORK.
//
// This is the class that is still shipping in real applications in 2026,
// years after the framework it looks for stopped being installable. Every
// check below was copied, in shape, from advice that circulated between
// roughly 2014 and 2018 and has been reprinted ever since. It is presented
// here as a SPECIMEN, not as a recommendation -- read the verdict comment
// above each method before you copy anything out of it.
//
// WHY THIS FILE EXISTS IN A PENTESTING REPOSITORY
//   1. You will find code shaped like this in APKs you assess. Recognising it
//      and knowing what it is worth is a deliverable.
//   2. It is the positive ground truth for scripts/xposed-detection-scan.py.
//      A detector validated only against clean samples has not been validated;
//      compiling this file gives the scanner something it MUST find.
//   3. Six of the eight checks below are dead against a device running
//      LSPosed, and two are dead against everything. Chapter 64 section 5
//      argues that from measurement; this is the code the argument is about.
//
// PROVENANCE OF THE VERDICTS
//   Verdicts marked [MEASURED] were established on an sdk_gphone16k_x86_64
//   AVD, Android 15 / API 35, rooted with Magisk 30.7 -- see README section
//   7.1. Verdicts marked [STRUCTURAL] follow from how the frameworks are
//   built and are argued rather than measured.
//
// COMPILE
//   ../scripts/build-classic-module.sh --with-detector
//   (builds out of tree; nothing lands in the repository)
//
// AUTHORISED TESTING ONLY. This is defensive code. Ship the parts of it that
// survive section 5's critique, and report rather than block.

package com.pentest.ch64.detector;

import android.content.Context;
import android.content.pm.PackageManager;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.List;

/**
 * A specimen Xposed detector, with each check's real value recorded next to it.
 *
 * <p>The class deliberately keeps every check as a separate method returning a
 * {@link Signal} rather than folding them into one boolean. That is not style:
 * a detector that returns one boolean cannot tell you WHICH signal fired, and
 * an integrity report that cannot say which signal fired is not evidence.
 */
public final class XposedDetector {

    /** One check's outcome, plus enough context to argue about it later. */
    public static final class Signal {
        public final String name;
        public final boolean fired;
        public final String detail;

        Signal(String name, boolean fired, String detail) {
            this.name = name;
            this.fired = fired;
            this.detail = detail;
        }

        @Override public String toString() {
            return (fired ? "FIRED  " : "quiet  ") + name + "  " + detail;
        }
    }

    private XposedDetector() { }

    // -----------------------------------------------------------------
    // CHECK 1 -- can this process resolve the Xposed API?
    //
    // VERDICT: [STRUCTURAL] The only check on this list that is worth
    // shipping. It asks about THIS PROCESS rather than about the device, so
    // it is not defeated by hiding files, and it is true of classic Xposed
    // and of LSPosed alike -- both put de.robv.android.xposed on a class
    // loader the app can reach, because modules are written against it.
    //
    // It is still defeatable: a module can hook ClassLoader.loadClass and
    // throw ClassNotFoundException for this exact name. See 63-LSPosed
    // section 5.5, which shows that hook in four lines. The honest framing is
    // that this check raises cost; it does not create a boundary.
    //
    // NOTE THE THREE-ARGUMENT FORM. Class.forName(name) resolves against the
    // CALLER's class loader, which is usually what you want; the explicit
    // form with initialize=false is used here so that resolving the class
    // does not run its static initialiser, which would be an observable act
    // performed by the detector itself.
    // -----------------------------------------------------------------
    public static Signal apiVisibleInProcess(ClassLoader cl) {
        final String[] names = {
            "de.robv.android.xposed.XposedBridge",
            "de.robv.android.xposed.XposedHelpers",
            "de.robv.android.xposed.XC_MethodHook",
            "de.robv.android.xposed.IXposedHookLoadPackage",
        };
        for (String n : names) {
            try {
                Class.forName(n, false, cl);
                return new Signal("api-visible-in-process", true, n);
            } catch (ClassNotFoundException expected) {
                // clean, for this name
            } catch (Throwable t) {
                // A LinkageError here is itself interesting: the name resolved
                // to something that would not link. Record it, do not swallow it.
                return new Signal("api-visible-in-process", true,
                        n + " -> " + t.getClass().getName());
            }
        }
        return new Signal("api-visible-in-process", false, "none of 4 names resolved");
    }

    // -----------------------------------------------------------------
    // CHECK 2 -- is there a hook dispatcher between us and our caller?
    //
    // VERDICT: [STRUCTURAL] Genuinely informative, and the best of the
    // stack-based checks, because it does not depend on any file existing.
    // If a method of ours is hooked, the framework's dispatcher is on the
    // call stack by construction -- that is what "before, then the original,
    // then after" MEANS.
    //
    // Two real weaknesses. It only fires while a HOOKED method is executing,
    // so where you call it matters more than what it looks for. And
    // Throwable.getStackTrace is itself hookable.
    //
    // The classic-Xposed frame to look for is XposedBridge.handleHookedMethod;
    // LSPosed's is an LSPlant-generated class whose name contains "LSPHooker".
    // A detector that knows only the first is a detector written before 2019.
    // -----------------------------------------------------------------
    public static Signal foreignFrameOnStack() {
        final String[] fragments = {
            "de.robv.android.xposed",     // classic Xposed and LSPosed's compat layer
            "handleHookedMethod",         // XposedBridge's generic dispatcher
            "LSPHooker",                  // LSPlant's generated hook class
            "org.lsposed",                // the manager and daemon
            "com.elderdrivers.riru",      // EdXposed
        };
        StackTraceElement[] trace = new Throwable().getStackTrace();
        for (StackTraceElement e : trace) {
            String c = e.getClassName();
            for (String f : fragments) {
                if (c.contains(f)) {
                    return new Signal("foreign-frame-on-stack", true,
                            c + "." + e.getMethodName());
                }
            }
        }
        return new Signal("foreign-frame-on-stack", false,
                trace.length + " frames, none foreign");
    }

    // -----------------------------------------------------------------
    // CHECK 3 -- is XposedBridge.jar on the system partition?
    //
    // VERDICT: [MEASURED, DEAD] This is the single most-copied Xposed check
    // in existence and on a modern device it can only ever return false.
    //
    //   * Classic Xposed put this file there. Classic Xposed does not run
    //     above API 27.
    //   * LSPosed NEVER creates it. EdXposed never created it.
    //   * On the API 35 AVD used for this chapter the path is ENOENT even to
    //     root, and /system is a read-only verified mount, so nothing could
    //     have written it.
    //
    // Keeping this check costs nothing and buys nothing, which is exactly why
    // nobody deletes it. It is the clearest example in this chapter of a
    // control that survives because it is cheap rather than because it works.
    // -----------------------------------------------------------------
    public static Signal bridgeJarOnSystem() {
        final String[] paths = {
            "/system/framework/XposedBridge.jar",
            "/system/lib/libxposed_art.so",
            "/system/lib64/libxposed_art.so",
            "/system/lib/libxposed_dalvik.so",
            "/system/xposed.prop",
        };
        List<String> found = new ArrayList<>();
        for (String p : paths) {
            if (new File(p).exists()) { found.add(p); }
        }
        return new Signal("bridge-jar-on-system", !found.isEmpty(),
                found.isEmpty() ? "none of " + paths.length + " classic paths" : found.toString());
    }

    // -----------------------------------------------------------------
    // CHECK 4 -- has app_process been replaced?
    //
    // VERDICT: [MEASURED, DEAD AGAINST LSPOSED] This is the check that is
    // actually ABOUT chapter 64's mechanism, and it is the most interesting
    // failure on the list, because it was RIGHT once.
    //
    // Classic Xposed replaced /system/bin/app_process with its own build.
    // Comparing its size or hash against a known-good value detected that.
    //
    // On the API 35 AVD, measured:
    //     /system/bin/app_process -> app_process64   (a symlink)
    //     /system/bin/app_process64  51616 bytes, -rwxr-xr-x root:shell
    //
    // Two things break the check today. First, LSPosed leaves this file
    // byte-identical, so a match proves nothing about hooking. Second, there
    // is no stable expected value: the size differs per build, per release
    // and per architecture, so any hard-coded constant is wrong on most
    // devices. An app shipping a baseline for this file is shipping a
    // false-positive generator.
    //
    // NOTE the deliberate absence of a hard-coded size below. Chapter 64
    // section 11 lists inventing one as a developer mistake.
    // -----------------------------------------------------------------
    public static Signal appProcessLooksReplaced() {
        File f = new File("/system/bin/app_process");
        if (!f.exists()) {
            // Not an error: on many images this name is a symlink that an app
            // cannot stat, and "cannot see it" is not "it is missing".
            return new Signal("app-process-replaced", false, "not visible from this uid");
        }
        long len = f.length();
        // The only defensible statement is a relative one: report the value,
        // let a server that has population data decide whether it is odd.
        return new Signal("app-process-replaced", false,
                "size=" + len + " (reported, NOT judged -- no defensible baseline exists)");
    }

    // -----------------------------------------------------------------
    // CHECK 5 -- is a known manager package installed?
    //
    // VERDICT: [STRUCTURAL, DEAD] Broken three separate ways.
    //
    //   * LSPosed's manager is frequently not an installed launcher app at
    //     all, and its package name can be randomised (63-LSPosed section 3.3).
    //   * From API 30, package visibility means getPackageInfo throws
    //     NameNotFoundException for a package you did not declare in
    //     <queries> EVEN WHEN IT IS INSTALLED. So this returns false on a
    //     device where the app plainly exists.
    //   * de.robv.android.xposed.installer has not been installable since
    //     API 27.
    //
    // The API 30 point is the one people miss: the check does not merely fail
    // to detect, it fails in a way that looks like a clean result.
    // -----------------------------------------------------------------
    public static Signal managerPackageInstalled(Context ctx) {
        final String[] packages = {
            "de.robv.android.xposed.installer",   // classic Xposed Installer
            "org.meowcat.edxposed.manager",       // EdXposed
            "org.lsposed.manager",                // LSPosed
            "io.va.exposed",                      // VirtualXposed
            "me.weishu.exp",                      // TaiChi
        };
        PackageManager pm = ctx.getPackageManager();
        for (String p : packages) {
            try {
                pm.getPackageInfo(p, 0);
                return new Signal("manager-package-installed", true, p);
            } catch (PackageManager.NameNotFoundException expected) {
                // Could mean absent. Could mean invisible. Cannot tell.
            }
        }
        return new Signal("manager-package-installed", false,
                "0 of " + packages.length + " -- BUT API 30+ package visibility "
                + "makes a negative here meaningless without a <queries> entry");
    }

    // -----------------------------------------------------------------
    // CHECK 6 -- is our own class-loader graph the shape we built it?
    //
    // VERDICT: [STRUCTURAL] Real, and better than most published advice.
    // Loading foreign DEX into a process requires a loader, and that loader
    // is visible from inside the process. Classic Xposed did NOT need one --
    // its jar was on the boot class path -- so this check is a case of a
    // modern signal that would have MISSED the framework it is named after.
    //
    // That asymmetry is worth stating in a report: the checks that work
    // against LSPosed and the checks that worked against Xposed are almost
    // disjoint sets.
    // -----------------------------------------------------------------
    public static Signal foreignClassLoader(ClassLoader start, String ownApkPath) {
        List<String> foreign = new ArrayList<>();
        for (ClassLoader cl = start; cl != null; cl = cl.getParent()) {
            String s = String.valueOf(cl);
            // A PathClassLoader prints its dexPath. A loader whose path is not
            // our own APK, and is not the boot loader, is somebody else's code.
            if (s.contains(".apk") && ownApkPath != null && !s.contains(ownApkPath)) {
                foreign.add(s.length() > 160 ? s.substring(0, 160) + "..." : s);
            }
        }
        return new Signal("foreign-class-loader", !foreign.isEmpty(),
                foreign.isEmpty() ? "loader chain clean" : foreign.toString());
    }

    // -----------------------------------------------------------------
    // CHECK 7 -- does our own memory map name a hooking framework?
    //
    // VERDICT: [MEASURED, PARTIAL] /proc/self/maps is readable by the process
    // itself with no permission, always. Classic Xposed's libxposed_art.so
    // would have appeared here by name.
    //
    // Against LSPosed it is much weaker: LSPosed asks Magisk to dlclose its
    // module library after specialisation precisely so it does not remain
    // mapped, and the module's DEX arrives through a class loader rather than
    // as a named mapping.
    //
    // What DOES survive on a Magisk device, measured by 63-LSPosed on this
    // same AVD, is three mounts in /proc/self/mountinfo whose source is
    // literally "magisk". That proves the SUBSTRATE, not the framework --
    // which are different questions, and a detector that answers the first
    // while claiming the second is wrong.
    // -----------------------------------------------------------------
    public static Signal ownMapsNameFramework() {
        final String[] fragments = { "libxposed", "lspd", "lsposed", "edxp", "riru" };
        try (BufferedReader r = new BufferedReader(new FileReader("/proc/self/maps"))) {
            String line;
            while ((line = r.readLine()) != null) {
                String low = line.toLowerCase();
                for (String f : fragments) {
                    if (low.contains(f)) {
                        return new Signal("own-maps-names-framework", true, line.trim());
                    }
                }
            }
        } catch (Exception e) {
            return new Signal("own-maps-names-framework", false, "unreadable: " + e);
        }
        return new Signal("own-maps-names-framework", false, "no framework mapping");
    }

    // -----------------------------------------------------------------
    // CHECK 8 -- the environment-variable check nobody remembers writing.
    //
    // VERDICT: [MEASURED, DEAD] Some very old advice reads CLASSPATH or
    // BOOTCLASSPATH looking for XposedBridge.jar, because classic Xposed's
    // modified app_process appended it. It is included here for completeness
    // and because you WILL find it in old code -- not because it can fire.
    // Nothing appends to BOOTCLASSPATH on a modern device, and an app process
    // inherits the environment Zygote had.
    // -----------------------------------------------------------------
    public static Signal bootClassPathMentionsBridge() {
        String bcp = System.getenv("BOOTCLASSPATH");
        String cp = System.getenv("CLASSPATH");
        boolean hit = (bcp != null && bcp.contains("XposedBridge"))
                   || (cp != null && cp.contains("XposedBridge"));
        return new Signal("bootclasspath-mentions-bridge", hit,
                "BOOTCLASSPATH len=" + (bcp == null ? -1 : bcp.length()));
    }

    // -----------------------------------------------------------------
    // The whole battery. Note what this method does NOT do: it does not
    // return a boolean, and it does not block.
    //
    // Chapter 64 section 5.5 and 63-LSPosed section 5.5 both argue the same
    // point from different evidence: an in-process check can always in
    // principle be defeated, because the checker and the checked share an
    // address space. What changes the outcome rather than the cost is
    // sending the SIGNALS somewhere the attacker is not, and letting a server
    // decide against a nonce the client did not choose.
    // -----------------------------------------------------------------
    public static List<Signal> collect(Context ctx, String ownApkPath) {
        List<Signal> out = new ArrayList<>();
        ClassLoader cl = XposedDetector.class.getClassLoader();
        out.add(apiVisibleInProcess(cl));
        out.add(foreignFrameOnStack());
        out.add(bridgeJarOnSystem());
        out.add(appProcessLooksReplaced());
        if (ctx != null) { out.add(managerPackageInstalled(ctx)); }
        out.add(foreignClassLoader(cl, ownApkPath));
        out.add(ownMapsNameFramework());
        out.add(bootClassPathMentionsBridge());
        return out;
    }
}
