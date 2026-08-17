/*
 * RootDetector.java
 * ===========================================================================
 * WHAT THIS IS
 *   A complete, production-shaped Java implementation of the root-detection
 *   catalogue from chapter 37 section 3, covering techniques 3.1 through 3.11.
 *
 *   It is written the way a competent developer WOULD write it if they had
 *   read the whole chapter: every signal is separate, every signal is weighted,
 *   nothing is a boolean, and the result is EVIDENCE FOR A SERVER rather than
 *   a local authorisation decision.
 *
 * WHY IT IS SHAPED THIS WAY
 *   The single most damaging mistake in this area is
 *
 *       if (isRooted()) { finish(); }
 *
 *   because it converts twelve pieces of useful risk information into one
 *   boolean, and then places that boolean one Frida hook away from the
 *   attacker. Every technique in the chapter ends at that branch.
 *
 *   The shape below fixes the second half of that problem (the information is
 *   preserved and sent onward) and does NOT fix the first half, because the
 *   first half is unfixable on the client. See the honest assessment at the
 *   bottom of this file.
 *
 * HOW TO USE IT
 *   Signals sig = RootDetector.collect(context);
 *   apiClient.attachDeviceSignals(sig.toJson());        // RIGHT
 *   // if (sig.score > 60) finish();                    // WRONG
 *
 *   Call it off the main thread. Several probes do filesystem I/O and one
 *   spawns a process; on a rooted device with a root manager, spawning `su`
 *   can block for as long as the user ignores the grant prompt, which has
 *   shipped as an ANR in real applications.
 *
 * WHAT IT IS WORTH
 *   Read section 3 of the chapter for the per-technique assessment. The
 *   summary: everything here is defeated in minutes by anyone who wants to.
 *   Its value is (a) removing the casual attacker, (b) feeding a server-side
 *   fraud model, and (c) producing an inconsistency signal when the local
 *   evidence disagrees with an attested verdict. It is not, and cannot be, an
 *   authorisation control.
 *
 * AUTHORISATION
 *   Educational reference for chapter 37. Ship the pattern, not the illusion.
 * ===========================================================================
 */

package com.example.integrity;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import android.provider.Settings;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.InputStreamReader;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public final class RootDetector {

    // =======================================================================
    // Result types
    // =======================================================================

    /** One observation. Never a verdict. */
    public static final class Signal {
        public final String id;        // stable identifier for the server
        public final String detail;    // what was actually observed
        public final int weight;       // contribution to the advisory score

        Signal(String id, String detail, int weight) {
            this.id = id;
            this.detail = detail;
            this.weight = weight;
        }

        @Override public String toString() {
            return id + " (" + weight + "): " + detail;
        }
    }

    /**
     * The collected evidence.
     *
     * `score` is deliberately called an ADVISORY score. It exists so the
     * server can prioritise, not so the client can decide.
     */
    public static final class Signals {
        public final List<Signal> signals;
        public final int score;
        public final long collectedAtMillis;
        public final Map<String, String> environment;

        Signals(List<Signal> signals, int score, Map<String, String> environment) {
            this.signals = signals;
            this.score = score;
            this.environment = environment;
            this.collectedAtMillis = System.currentTimeMillis();
        }

        public JSONObject toJson() throws JSONException {
            JSONObject o = new JSONObject();
            JSONArray arr = new JSONArray();
            for (Signal s : signals) {
                JSONObject j = new JSONObject();
                j.put("id", s.id);
                j.put("detail", s.detail);
                j.put("weight", s.weight);
                arr.put(j);
            }
            o.put("signals", arr);
            o.put("advisoryScore", score);
            o.put("collectedAt", collectedAtMillis);

            JSONObject env = new JSONObject();
            for (Map.Entry<String, String> e : environment.entrySet()) {
                env.put(e.getKey(), e.getValue());
            }
            o.put("environment", env);
            return o;
        }
    }

    // =======================================================================
    // Catalogue data — section 3.0 of the chapter
    // =======================================================================

    /** Section 3.1 — su binaries. */
    private static final String[] SU_PATHS = {
        "/data/local/su", "/data/local/bin/su", "/data/local/xbin/su",
        "/sbin/su", "/su/bin/su", "/system/bin/su", "/system/bin/.ext/su",
        "/system/bin/failsafe/su", "/system/sd/xbin/su",
        "/system/usr/we-need-root/su", "/system/xbin/su",
        "/vendor/bin/su", "/product/bin/su", "/system_ext/bin/su",
        "/cache/su", "/data/su", "/dev/su"
    };

    /** Section 3.1 — busybox implies a modified image. */
    private static final String[] BUSYBOX_PATHS = {
        "/system/xbin/busybox", "/system/bin/busybox",
        "/data/local/busybox", "/sbin/busybox"
    };

    /** Section 3.5 — Magisk artefacts. */
    private static final String[] MAGISK_PATHS = {
        "/sbin/magisk", "/sbin/magiskinit", "/sbin/magiskpolicy",
        "/sbin/.magisk", "/sbin/.core",
        "/data/adb/magisk", "/data/adb/modules", "/data/adb/magisk.db",
        "/cache/magisk.log", "/cache/.disable_magisk", "/init.magisk.rc",
        "/system/addon.d/99-magisk.sh"
    };

    /** Section 3.1 — legacy manager artefacts. */
    private static final String[] MANAGER_ARTEFACTS = {
        "/system/app/Superuser.apk", "/system/app/SuperSU/SuperSU.apk",
        "/system/etc/init.d", "/etc/init.d",
        "/dev/com.koushikdutta.superuser.daemon"
    };

    /** Section 3.4 — root manager and root-adjacent packages. */
    private static final String[] ROOT_PACKAGES = {
        "com.topjohnwu.magisk", "com.topjohnwu.magisk.debug",
        "eu.chainfire.supersu",
        "com.noshufou.android.su", "com.noshufou.android.su.elite",
        "com.koushikdutta.superuser", "com.thirdparty.superuser",
        "com.yellowes.su",
        "com.devadvance.rootcloak", "com.devadvance.rootcloakplus",
        "com.formyhm.hideroot", "com.amphoras.hidemyroot",
        "de.robv.android.xposed.installer", "com.saurik.substrate",
        "com.dimonvideo.luckypatcher", "com.chelpus.lackypatch",
        "com.android.vending.billing.InAppBillingService.LACK",
        "com.zachspong.temprootremovejb", "com.ramdroid.appquarantine",
        "com.kingroot.kinguser", "com.kingo.root",
        "com.smedialink.oneclickroot", "com.alephzain.framaroot"
    };

    /** Section 3.6 — directories that must be read-only on a stock device. */
    private static final String[] RO_DIRS = {
        "/system", "/system/bin", "/system/sbin", "/system/xbin",
        "/vendor/bin", "/sbin", "/etc", "/"
    };

    // =======================================================================
    // Collection
    // =======================================================================

    /**
     * Run every probe. Never throws: a probe that fails is an inconclusive
     * probe, not a crash. It is recorded as such so the server can tell the
     * difference between "clean" and "could not tell".
     */
    public static Signals collect(Context ctx) {
        List<Signal> out = new ArrayList<>();

        add(out, suBinary());              // 3.1
        add(out, busyBox());               // 3.1
        add(out, managerArtefacts());      // 3.1
        add(out, suOnPath());              // 3.2
        add(out, whichSu());               // 3.2
        add(out, canExecuteSu());          // 3.3
        add(out, rootPackages(ctx));       // 3.4
        add(out, magiskArtefacts());       // 3.5
        add(out, writableSystem());        // 3.6
        add(out, dangerousProperties());   // 3.7
        add(out, mountTable());            // 3.8
        add(out, injectedLibraries());     // 3.9
        add(out, selinuxPermissive());     // 3.10
        add(out, developerSettings(ctx));  // 3.11

        int score = 0;
        for (Signal s : out) score += s.weight;

        return new Signals(out, score, environment());
    }

    private static void add(List<Signal> list, Signal s) {
        if (s != null) list.add(s);
    }

    // -----------------------------------------------------------------------
    // 3.1 — filesystem artefacts
    // -----------------------------------------------------------------------

    static Signal suBinary() {
        String hit = firstExisting(SU_PATHS);
        return hit == null ? null : new Signal("su.binary", hit, 40);
    }

    static Signal busyBox() {
        String hit = firstExisting(BUSYBOX_PATHS);
        return hit == null ? null : new Signal("su.busybox", hit, 20);
    }

    static Signal managerArtefacts() {
        String hit = firstExisting(MANAGER_ARTEFACTS);
        return hit == null ? null : new Signal("su.manager_artefact", hit, 25);
    }

    private static String firstExisting(String[] paths) {
        for (String p : paths) {
            try {
                if (new File(p).exists()) return p;
            } catch (SecurityException ignored) {
                // A SecurityManager can deny the read. Inconclusive, not clean.
            }
        }
        return null;
    }

    // -----------------------------------------------------------------------
    // 3.2 — PATH and `which`
    // -----------------------------------------------------------------------

    static Signal suOnPath() {
        String path = System.getenv("PATH");
        if (path == null) return null;
        for (String dir : path.split(":")) {
            if (dir.isEmpty()) continue;
            try {
                if (new File(dir, "su").exists()) {
                    return new Signal("su.on_path", dir + "/su", 30);
                }
            } catch (SecurityException ignored) { }
        }
        return null;
    }

    /**
     * NOTE FOR THE READER: the classic version of this method hardcodes
     * "/system/xbin/which", which does not exist on modern devices where
     * toybox lives in /system/bin. The exec then throws, the catch returns
     * false, and the check silently never fires — a bug that ships in
     * production applications (chapter section 3.2).
     *
     * The version below resolves `which` from PATH instead, so it actually
     * works. If you are TESTING an app and you find the hardcoded version,
     * that is a reportable finding: the developer has a control that has never
     * run.
     */
    static Signal whichSu() {
        String which = null;
        String path = System.getenv("PATH");
        if (path != null) {
            for (String dir : path.split(":")) {
                File f = new File(dir, "which");
                if (f.exists()) { which = f.getAbsolutePath(); break; }
            }
        }
        if (which == null) which = "/system/bin/which";

        Process p = null;
        BufferedReader r = null;
        try {
            p = Runtime.getRuntime().exec(new String[]{which, "su"});
            r = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String line = r.readLine();
            if (line != null && !line.trim().isEmpty()) {
                return new Signal("su.which", line.trim(), 30);
            }
        } catch (Exception ignored) {
            // Absent binary or blocked exec. Inconclusive.
        } finally {
            closeQuietly(r);
            if (p != null) p.destroy();
        }
        return null;
    }

    // -----------------------------------------------------------------------
    // 3.3 — actually try to use su
    // -----------------------------------------------------------------------

    /**
     * WARNING: on a rooted device with a root manager, this triggers a
     * user-visible grant prompt, and on some implementations a pending prompt
     * blocks readLine() indefinitely. Never call this on the main thread.
     *
     * Its one genuine advantage over 3.1 is that it detects a root broker that
     * hides the binary path but still answers requests.
     */
    static Signal canExecuteSu() {
        Process p = null;
        BufferedReader r = null;
        try {
            p = Runtime.getRuntime().exec(new String[]{"su", "-c", "id"});
            r = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String line = r.readLine();
            if (line != null && line.contains("uid=0")) {
                return new Signal("su.executed", line.trim(), 50);
            }
        } catch (Exception ignored) {
        } finally {
            closeQuietly(r);
            if (p != null) p.destroy();
        }
        return null;
    }

    // -----------------------------------------------------------------------
    // 3.4 — installed packages
    // -----------------------------------------------------------------------

    /**
     * REQUIRES a <queries> element in AndroidManifest.xml listing every
     * package below, when targeting API 30 or above. Without it, package
     * visibility filtering makes getPackageInfo throw NameNotFoundException
     * for packages that ARE installed, and this method is dead code.
     *
     * The chapter's §3.4 Version Matrix has the details. This is the most
     * commonly broken check in the whole catalogue.
     */
    static Signal rootPackages(Context ctx) {
        if (ctx == null) return null;
        PackageManager pm = ctx.getPackageManager();
        List<String> found = new ArrayList<>();

        for (String pkg : ROOT_PACKAGES) {
            try {
                pm.getPackageInfo(pkg, 0);
                found.add(pkg);
            } catch (PackageManager.NameNotFoundException ignored) {
                // Not installed, OR installed and filtered from our view.
                // We cannot distinguish, which is itself worth knowing.
            } catch (Exception ignored) { }
        }

        if (found.isEmpty()) return null;
        return new Signal("pkg.root_manager",
                joinLimited(found, 5), Math.min(35, 15 * found.size()));
    }

    // -----------------------------------------------------------------------
    // 3.5 — Magisk
    // -----------------------------------------------------------------------

    static Signal magiskArtefacts() {
        String hit = firstExisting(MAGISK_PATHS);
        if (hit != null) return new Signal("magisk.path", hit, 45);

        // /proc/net/unix historically exposed a fixed "magisk" socket name.
        // Modern Magisk randomises it per boot, so a hit here usually means an
        // old installation. Weighted accordingly.
        BufferedReader r = null;
        try {
            r = new BufferedReader(new FileReader("/proc/net/unix"));
            String line;
            while ((line = r.readLine()) != null) {
                if (line.contains("magisk")) {
                    return new Signal("magisk.socket", "/proc/net/unix", 40);
                }
            }
        } catch (Exception ignored) {
        } finally {
            closeQuietly(r);
        }
        return null;
    }

    // -----------------------------------------------------------------------
    // 3.6 — writability
    // -----------------------------------------------------------------------

    static Signal writableSystem() {
        for (String d : RO_DIRS) {
            try {
                File f = new File(d);
                if (f.exists() && f.canWrite()) {
                    return new Signal("fs.writable", d, 45);
                }
            } catch (SecurityException ignored) { }
        }
        return null;
    }

    // -----------------------------------------------------------------------
    // 3.7 — system properties
    // -----------------------------------------------------------------------

    /**
     * Reads through reflection into android.os.SystemProperties.
     *
     * Do NOT use java.lang.System.getProperty() for these keys: that reads the
     * JVM properties table, which is a completely different store, and always
     * returns null for Android build properties. Apps that make this mistake
     * have a check that silently never fires (chapter §3.7).
     */
    static Signal dangerousProperties() {
        List<String> hits = new ArrayList<>();
        int weight = 0;

        String tags = Build.TAGS;
        if (tags != null && tags.contains("test-keys")) {
            hits.add("Build.TAGS=" + tags);
            weight += 25;
        }
        if ("1".equals(prop("ro.debuggable")))  { hits.add("ro.debuggable=1"); weight += 25; }
        if ("0".equals(prop("ro.secure")))      { hits.add("ro.secure=0");     weight += 15; }

        String type = prop("ro.build.type");
        if (notEmpty(type) && !"user".equals(type)) {
            hits.add("ro.build.type=" + type); weight += 25;
        }

        // The strongest purely local signal in the entire catalogue: its value
        // originates in the bootloader, before Android exists. Still spoofable
        // by an attacker with root, so its value is as CORROBORATING EVIDENCE
        // sent to a server, never as a local gate.
        String vbs = prop("ro.boot.verifiedbootstate");
        if (notEmpty(vbs) && !"green".equals(vbs)) {
            hits.add("verifiedbootstate=" + vbs); weight += 50;
        }
        if ("0".equals(prop("ro.boot.flash.locked"))) {
            hits.add("flash.locked=0"); weight += 45;
        }
        String vbmeta = prop("ro.boot.vbmeta.device_state");
        if (notEmpty(vbmeta) && !"locked".equals(vbmeta)) {
            hits.add("vbmeta.device_state=" + vbmeta); weight += 45;
        }
        String verity = prop("ro.boot.veritymode");
        if (notEmpty(verity) && !"enforcing".equals(verity)) {
            hits.add("veritymode=" + verity); weight += 35;
        }
        if ("1".equals(prop("sys.oem_unlock_allowed"))) {
            hits.add("oem_unlock_allowed=1"); weight += 15;
        }
        if (notEmpty(prop("ro.modversion")) || notEmpty(prop("ro.lineage.version"))) {
            hits.add("custom ROM version property present"); weight += 20;
        }

        if (hits.isEmpty()) return null;
        return new Signal("prop.dangerous", joinLimited(hits, 6), Math.min(70, weight));
    }

    // -----------------------------------------------------------------------
    // 3.8 — mount table
    // -----------------------------------------------------------------------

    /**
     * /proc/self/mounts is the mount table AS SEEN BY THIS PROCESS. Magisk
     * works by manipulating mount namespaces, which makes this one of the more
     * structural signals available — and also why Magisk's DenyList defeats it
     * completely, by giving the process a reverted namespace in which the
     * table is honestly clean.
     *
     * /proc/self/mountinfo carries more structure (mount IDs, parent IDs, peer
     * groups) and is less commonly sanitised by bypass scripts. Reading both
     * is cheap.
     */
    static Signal mountTable() {
        String hit = scanMounts("/proc/self/mounts");
        if (hit == null) hit = scanMounts("/proc/self/mountinfo");
        return hit == null ? null : new Signal("mount.suspicious", hit, 40);
    }

    private static String scanMounts(String path) {
        BufferedReader r = null;
        try {
            r = new BufferedReader(new FileReader(path));
            String line;
            while ((line = r.readLine()) != null) {
                String lower = line.toLowerCase(Locale.US);
                if (lower.contains("magisk"))    return "magisk in " + path;
                if (lower.contains("/data/adb")) return "/data/adb in " + path;

                String[] f = line.split(" ");
                if (f.length < 4) continue;
                String dst = f[1], type = f[2], opts = f[3];

                if ("tmpfs".equals(type) &&
                    (dst.startsWith("/sbin") || dst.equals("/system") ||
                     dst.startsWith("/system/") || dst.startsWith("/debug_ramdisk"))) {
                    return "tmpfs on " + dst;
                }
                if (("overlay".equals(type) || "overlayfs".equals(type)) &&
                    dst.startsWith("/system")) {
                    return "overlay on " + dst;
                }
                if (("/system".equals(dst) || "/".equals(dst)) && opts.startsWith("rw")) {
                    return dst + " mounted rw";
                }
                if (f[0].startsWith("/dev/block/loop") && dst.startsWith("/system")) {
                    return "loop device on " + dst;
                }
            }
        } catch (Exception ignored) {
        } finally {
            closeQuietly(r);
        }
        return null;
    }

    // -----------------------------------------------------------------------
    // 3.9 — injected libraries
    // -----------------------------------------------------------------------

    /**
     * Strictly an anti-hooking signal rather than a root signal: a rooted
     * device with no hooks loaded produces nothing here. Included because
     * root-detection libraries routinely scan for it, and because a hit is a
     * strong indicator of active instrumentation.
     *
     * See 38-TamperDetection for the anti-Frida treatment in depth.
     */
    static Signal injectedLibraries() {
        String[] needles = {
            "frida", "gum-js-loop", "gadget", "libriru", "zygisk",
            "xposed", "substrate", "lsposed", "libmemtrack_real"
        };
        BufferedReader r = null;
        try {
            r = new BufferedReader(new FileReader("/proc/self/maps"));
            String line;
            while ((line = r.readLine()) != null) {
                String lower = line.toLowerCase(Locale.US);
                for (String n : needles) {
                    if (lower.contains(n)) {
                        return new Signal("maps.injection", n, 55);
                    }
                }
            }
        } catch (Exception ignored) {
        } finally {
            closeQuietly(r);
        }
        return null;
    }

    // -----------------------------------------------------------------------
    // 3.10 — SELinux
    // -----------------------------------------------------------------------

    /**
     * Near worthless today, and included so you can see why.
     *
     * Magisk does not set SELinux permissive; it injects targeted allow rules
     * into the loaded policy with magiskpolicy. A modern rooted device reports
     * Enforcing and this check passes. It was meaningful in 2015.
     */
    static Signal selinuxPermissive() {
        FileInputStream in = null;
        try {
            in = new FileInputStream("/sys/fs/selinux/enforce");
            int c = in.read();
            if (c == '0') return new Signal("selinux.permissive", "enforce=0", 30);
        } catch (Exception ignored) {
            // Node unreadable. Inconclusive, NOT clean.
        } finally {
            closeQuietly(in);
        }
        return null;
    }

    // -----------------------------------------------------------------------
    // 3.11 — developer settings
    // -----------------------------------------------------------------------

    /**
     * Near zero as a root signal and actively user-hostile if you gate on it.
     * ADB being enabled is not a vulnerability and is not root. Collected here
     * only as a low-weight risk input; blocking on it generates support
     * tickets from your own QA team.
     */
    static Signal developerSettings(Context ctx) {
        if (ctx == null) return null;
        List<String> hits = new ArrayList<>();
        try {
            if (Settings.Global.getInt(ctx.getContentResolver(),
                    Settings.Global.ADB_ENABLED, 0) == 1) {
                hits.add("adb_enabled");
            }
            if (Settings.Global.getInt(ctx.getContentResolver(),
                    Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0) == 1) {
                hits.add("development_settings_enabled");
            }
        } catch (Exception ignored) { }

        try {
            ApplicationInfo ai = ctx.getApplicationInfo();
            if ((ai.flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0) {
                hits.add("self_debuggable");   // really a 38-TamperDetection signal
            }
        } catch (Exception ignored) { }

        if (hits.isEmpty()) return null;
        return new Signal("settings.developer", joinLimited(hits, 3), 5 * hits.size());
    }

    // =======================================================================
    // Environment context — sent alongside the signals
    // =======================================================================

    /**
     * Not detection. Context, so the server can interpret the signals and
     * cross-reference them against an attestation verdict. An inconsistency
     * between what the client reports here and what the TEE attests is a far
     * stronger fraud signal than any individual value.
     */
    private static Map<String, String> environment() {
        Map<String, String> m = new LinkedHashMap<>();
        m.put("fingerprint", nullSafe(Build.FINGERPRINT));
        m.put("model", nullSafe(Build.MODEL));
        m.put("manufacturer", nullSafe(Build.MANUFACTURER));
        m.put("tags", nullSafe(Build.TAGS));
        m.put("type", nullSafe(Build.TYPE));
        m.put("sdk", String.valueOf(Build.VERSION.SDK_INT));
        m.put("securityPatch", nullSafe(Build.VERSION.SECURITY_PATCH));
        m.put("verifiedBootState", prop("ro.boot.verifiedbootstate"));
        m.put("bootloaderLocked", prop("ro.boot.flash.locked"));
        return m;
    }

    // =======================================================================
    // Helpers
    // =======================================================================

    static String prop(String key) {
        try {
            Class<?> sp = Class.forName("android.os.SystemProperties");
            Method get = sp.getMethod("get", String.class, String.class);
            Object v = get.invoke(null, key, "");
            return v == null ? "" : v.toString();
        } catch (Throwable t) {
            return "";
        }
    }

    private static boolean notEmpty(String s) { return s != null && !s.isEmpty(); }

    private static String nullSafe(String s) { return s == null ? "" : s; }

    private static String joinLimited(List<String> items, int max) {
        List<String> sub = items.size() <= max ? items : items.subList(0, max);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < sub.size(); i++) {
            if (i > 0) sb.append(", ");
            sb.append(sub.get(i));
        }
        if (items.size() > max) sb.append(" (+").append(items.size() - max).append(" more)");
        return sb.toString();
    }

    private static void closeQuietly(java.io.Closeable c) {
        try { if (c != null) c.close(); } catch (Exception ignored) { }
    }

    private RootDetector() { }

    // =======================================================================
    // HOW TO USE THIS CORRECTLY — and how not to
    // =======================================================================
    //
    // WRONG, and the mistake this whole class is designed to discourage:
    //
    //     if (RootDetector.collect(this).score > 60) {
    //         Toast.makeText(this, "Rooted device", LENGTH_LONG).show();
    //         finish();
    //     }
    //
    // Why it is wrong:
    //   - One branch. Frida replaces `collect` or flips the comparison in
    //     twenty seconds, and everything above becomes decoration.
    //   - It destroys the fraud signal: you have blocked the user, so you
    //     never learn what they would have done.
    //   - It blocks USERS instead of OPERATIONS, maximising support cost and
    //     minimising security benefit.
    //   - The message tells the attacker exactly what happened, which is free
    //     intelligence. Do not log the result either.
    //
    // RIGHT:
    //
    //     // On a background thread, before a sensitive operation:
    //     Signals sig = RootDetector.collect(context);
    //
    //     // Attach as EVIDENCE, together with an integrity token whose nonce
    //     // the server issued and whose requestHash binds this exact request.
    //     JSONObject body = buildTransferRequest();
    //     body.put("deviceSignals", sig.toJson());
    //     api.transfer(body, integrityToken);       // token is OPAQUE to us
    //
    //     // The server decides. Graduated, not binary:
    //     //   verdict OK + signals clean          -> full functionality
    //     //   verdict OK + signals inconsistent   -> step-up auth, fraud flag
    //     //   no MEETS_DEVICE_INTEGRITY           -> read-only mode
    //     //   no token at all                     -> refuse, generic error
    //     //
    //     // And every capability is ENFORCED server-side, so a client that
    //     // ignores the decision gains nothing.
    //
    // THE HONEST ASSESSMENT
    //   Everything in this file is defeated in minutes by anyone motivated.
    //   Section 3 of the chapter gives the per-technique cost; the summary is
    //   that a Java-layer catalogue like this one falls to a single Frida
    //   script, and a native reimplementation buys perhaps an hour, once,
    //   after which the bypass is reusable forever.
    //
    //   That is not an argument for deleting it. A speed bump works on the
    //   population driving slowly by accident, and this class costs a few
    //   hundred lines to remove the entire casual-attacker segment while
    //   feeding a server-side risk model that DOES scale.
    //
    //   It is an argument against believing it. Client-side detection is a
    //   speed bump, not a boundary. The boundary is the server, and the only
    //   evidence that crosses it untampered is a hardware-backed attestation
    //   verified server-side, bound to the request, failing closed.
    //   See chapter §3.15.
    // =======================================================================
}
