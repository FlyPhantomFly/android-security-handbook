/*
 * IntegrityGate.java
 * ---------------------------------------------------------------------------
 * PURPOSE
 *   The self-integrity gate for the chapter 38 demonstration app. It runs seven
 *   checks, each of which reports a RESULT plus the EVIDENCE it based that
 *   result on, and returns a report rather than a boolean.
 *
 *   Returning a report instead of a boolean is the single most important design
 *   decision in this file, and it is a teaching decision as much as an
 *   engineering one:
 *
 *     - As a LEARNER, you need to see which check fired and what it saw.
 *       `boolean isTampered()` tells you nothing and is the reason most
 *       real-world integrity code is impossible to debug.
 *     - As a DEFENDER, a single boolean is one branch, and one branch is one
 *       instruction to flip. Section 5.6 of the chapter README explains why
 *       "many checks, one boolean" collapses to the security of that boolean.
 *
 *   This file deliberately does NOT harden itself. It has readable method
 *   names, plaintext string constants and a single obvious call site, because
 *   its job is to be understood and then attacked in labs 01 and 04. A
 *   production version of this design is discussed in README section 5.7 and
 *   sketched in ../LayeredTamperDetector.java; the honest server-side answer is
 *   in ../ServerVerifiedIntegrity.java.
 *
 * BUILD
 *   Built by ../build.sh, which generates a sibling class:
 *
 *       final class ExpectedSignature { static final String SHA256 = "..."; }
 *
 *   holding the SHA-256 of the DER encoding of the signing certificate that
 *   build.sh generated. Nothing is hardcoded in the repository, because a
 *   repository must never contain a keystore or a key.
 *
 * WHAT THIS WILL *NOT* TELL YOU
 *   * It will NOT tell you the device is honest. Every value read below comes
 *     from an API the attacker can hook, on a device the attacker owns.
 *   * It will NOT detect root. That is chapter 37's subject, and this file
 *     deliberately contains no root check so that the boundary stays clean.
 *   * It will NOT survive a determined attacker for more than a few minutes.
 *     It is not supposed to. It is supposed to make the cheap attack cost
 *     something and to make the expensive attack visible.
 *
 * AUTHORISED TESTING ONLY. Build it, install it, attack it, uninstall it.
 * ---------------------------------------------------------------------------
 */

package com.pentest.ch38.integrity;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.content.pm.SigningInfo;
import android.os.Build;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Locale;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

public final class IntegrityGate {

    // -----------------------------------------------------------------------
    // Result model
    // -----------------------------------------------------------------------

    /**
     * The verdict of one check.
     *
     * PASS      the check ran and saw what it expected
     * FAIL      the check ran and saw something it did not expect
     * UNKNOWN   the check could not run on this device or API level, which is
     *           NOT the same as passing. Conflating the two is the single most
     *           common bug in integrity code: a checker that returns "clean"
     *           because it could not read /proc is worse than no checker,
     *           because it produces false confidence.
     */
    public enum Verdict { PASS, FAIL, UNKNOWN }

    public static final class CheckResult {
        public final String id;        // stable identifier, e.g. "D1"
        public final String name;      // human name
        public final Verdict verdict;
        public final String evidence;  // what the check actually observed

        CheckResult(String id, String name, Verdict verdict, String evidence) {
            this.id = id;
            this.name = name;
            this.verdict = verdict;
            this.evidence = evidence;
        }

        @Override
        public String toString() {
            return id + "  " + pad(name, 34) + verdict + "\n        " + evidence;
        }

        private static String pad(String s, int n) {
            StringBuilder b = new StringBuilder(s);
            while (b.length() < n) b.append(' ');
            return b.toString();
        }
    }

    // -----------------------------------------------------------------------
    // Entry point
    // -----------------------------------------------------------------------

    /**
     * Run every check and return the results in a stable order.
     *
     * Note what this method does NOT do: it does not decide anything. It does
     * not call System.exit(), it does not show a dialog, and it does not set a
     * flag that the rest of the app consults. Deciding is the caller's job, and
     * in a real application the caller should be the SERVER. See README 5.8.
     */
    public static List<CheckResult> runAll(Context ctx) {
        List<CheckResult> out = new ArrayList<>();
        out.add(checkOwnSignature(ctx));      // D1
        out.add(checkDebuggableFlag(ctx));    // D2
        out.add(checkInstaller(ctx));         // D3
        out.add(checkDexIdentity(ctx));       // D4
        out.add(checkTracerPid());            // D5
        out.add(checkFridaPort());            // D6
        out.add(checkOwnMaps());              // D7
        return out;
    }

    // =======================================================================
    // D1 - self-signature verification
    // =======================================================================

    /*
     * WHAT IT PROVES
     *   That the APK this process was loaded from was signed by the key whose
     *   certificate hashes to EXPECTED. Nothing more. In particular it does NOT
     *   prove the code is unmodified, because a repackager who re-signs with
     *   their OWN key produces an APK that is internally consistent - it is
     *   just consistent with a different key.
     *
     *   That is the whole value of this check, stated precisely: an attacker
     *   who modifies one byte of the APK MUST re-sign it, because the v2/v3
     *   signature covers the file (see 10-APK-Internals section 6.5). Android
     *   will refuse to install an APK whose signature does not verify. So the
     *   attacker cannot keep the original signature, and the certificate the
     *   app sees at runtime therefore changes. The check converts "was this
     *   file modified" - which the app cannot answer - into "who signed the
     *   file I am running from" - which the platform answers for it.
     *
     * WHERE THE ANSWER COMES FROM
     *   PackageManager.getPackageInfo() is a Binder call into
     *   system_server's PackageManagerService. The certificate returned was
     *   captured at INSTALL time, when the platform verified it, and is stored
     *   in /data/system/packages.xml. The app is not parsing its own APK here;
     *   it is asking the platform what the platform recorded.
     *
     * THE HOLE
     *   The answer arrives over Binder, is unmarshalled into a Java object, and
     *   is compared by code inside the app process. Every one of those steps is
     *   inside the attacker's blast radius. See scripts/which-check-fired.js.
     */
    static CheckResult checkOwnSignature(Context ctx) {
        final String id = "D1", name = "self-signature";
        final String expected = ExpectedSignature.SHA256;

        try {
            PackageManager pm = ctx.getPackageManager();
            String pkg = ctx.getPackageName();
            Signature[] sigs;
            String source;

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                // API 28+. GET_SIGNING_CERTIFICATES (0x08000000) is the modern
                // flag. It returns a SigningInfo object rather than a bare
                // array, and the distinction matters: SigningInfo knows about
                // key ROTATION (APK Signature Scheme v3), so it can tell you
                // the certificate in force today AND the history of certificates
                // that endorsed it.
                PackageInfo pi = pm.getPackageInfo(pkg, PackageManager.GET_SIGNING_CERTIFICATES);
                SigningInfo si = pi.signingInfo;
                if (si == null) {
                    return new CheckResult(id, name, Verdict.UNKNOWN, "signingInfo was null");
                }
                if (si.hasMultipleSigners()) {
                    // Multiple CURRENT signers: an APK signed by several keys at
                    // once. Rare, and worth reporting rather than silently
                    // taking element 0.
                    sigs = si.getApkContentsSigners();
                    source = "getApkContentsSigners (multi-signer)";
                } else {
                    // Single signer, possibly rotated. getSigningCertificateHistory()
                    // returns the lineage, oldest first, current last.
                    sigs = si.getSigningCertificateHistory();
                    source = "getSigningCertificateHistory";
                }
            } else {
                // API 21-27. GET_SIGNATURES (0x00000040) is deprecated from
                // API 28 for a real reason: on a rotated app it returns only
                // the ORIGINAL signer, so an app that rotates its key and ships
                // a GET_SIGNATURES self-check will keep passing after rotation
                // - and an app that hardcodes the NEW hash will start failing
                // on old devices. Both directions are live bugs.
                @SuppressWarnings("deprecation")
                PackageInfo pi = pm.getPackageInfo(pkg, PackageManager.GET_SIGNATURES);
                @SuppressWarnings("deprecation")
                Signature[] legacy = pi.signatures;
                sigs = legacy;
                source = "GET_SIGNATURES (legacy)";
            }

            if (sigs == null || sigs.length == 0) {
                return new CheckResult(id, name, Verdict.UNKNOWN, "no signatures returned");
            }

            // Compare against every certificate in the set. On a rotated app
            // the lineage contains the old key too, and an app that only
            // compares the last element will reject its own past self.
            StringBuilder seen = new StringBuilder();
            boolean match = false;
            for (int i = 0; i < sigs.length; i++) {
                String h = sha256Hex(sigs[i].toByteArray());
                if (seen.length() > 0) seen.append(", ");
                seen.append(h.substring(0, 16)).append("...");
                if (constantTimeEquals(h, expected)) match = true;
            }

            String ev = source + " -> " + sigs.length + " cert(s): " + seen
                      + " | expected " + expected.substring(0, 16) + "...";
            return new CheckResult(id, name, match ? Verdict.PASS : Verdict.FAIL, ev);

        } catch (PackageManager.NameNotFoundException e) {
            // Cannot happen for one's own package on a sane device. If it does,
            // something is very wrong, and UNKNOWN is the honest answer.
            return new CheckResult(id, name, Verdict.UNKNOWN, "NameNotFoundException: " + e.getMessage());
        } catch (RuntimeException e) {
            return new CheckResult(id, name, Verdict.UNKNOWN, "unexpected: " + e);
        }
    }

    // =======================================================================
    // D2 - debuggable flag
    // =======================================================================

    /*
     * WHAT IT PROVES
     *   That ApplicationInfo.FLAG_DEBUGGABLE (0x00000002) is set on THIS
     *   package. That flag lets a JDWP debugger attach to the process, and
     *   `run-as` read its private data directory.
     *
     *   It proves nothing about the DEVICE. A device with ro.debuggable=1 makes
     *   every app debuggable without changing any app's manifest, and that is
     *   the case this check misses entirely. Reading ro.debuggable is a
     *   different check with a different meaning; do not conflate them.
     *
     * WHY IT BELONGS IN A TAMPER CHAPTER AND NOT AN ANTI-DEBUG ONE
     *   The realistic way this flag becomes set is that somebody decompiled the
     *   APK, added android:debuggable="true" to the manifest, and re-signed. So
     *   in practice a FAIL here is a REPACKAGING signal that happens to be
     *   expressed as a debug signal - and D1 will have fired too.
     */
    static CheckResult checkDebuggableFlag(Context ctx) {
        final String id = "D2", name = "debuggable flag";
        ApplicationInfo ai = ctx.getApplicationInfo();
        boolean dbg = (ai.flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0;
        String ev = "ApplicationInfo.flags=0x" + Integer.toHexString(ai.flags)
                  + " FLAG_DEBUGGABLE=" + dbg;
        return new CheckResult(id, name, dbg ? Verdict.FAIL : Verdict.PASS, ev);
    }

    // =======================================================================
    // D3 - installer package
    // =======================================================================

    /*
     * WHAT IT PROVES
     *   Which package the platform recorded as having installed this one. If it
     *   is "com.android.vending", the app arrived through Google Play.
     *
     *   This is the WEAKEST check in the file and it is here so you can see
     *   exactly how weak. `pm install -i com.android.vending` sets the string
     *   to anything the installer claims, and on API 30 and below any app
     *   holding INSTALL_PACKAGES could do the same. It is an anti-fraud
     *   telemetry signal, not a security control.
     *
     * VERSION NOTE, MEASURED
     *   getInstallerPackageName() is deprecated from API 30 in favour of
     *   getInstallSourceInfo(), which returns an InstallSourceInfo carrying
     *   THREE names: initiating, originating and installing. Sideloaded apps
     *   frequently return null from the legacy call, and null must be treated
     *   as UNKNOWN, not as FAIL - a debug build installed over adb is not a
     *   tampered build.
     */
    static CheckResult checkInstaller(Context ctx) {
        final String id = "D3", name = "installer package";
        try {
            PackageManager pm = ctx.getPackageManager();
            String pkg = ctx.getPackageName();
            String installer;
            String source;

            if (Build.VERSION.SDK_INT >= 30) {
                installer = pm.getInstallSourceInfo(pkg).getInstallingPackageName();
                source = "getInstallSourceInfo().getInstallingPackageName()";
            } else {
                @SuppressWarnings("deprecation")
                String legacy = pm.getInstallerPackageName(pkg);
                installer = legacy;
                source = "getInstallerPackageName()";
            }

            String ev = source + " -> " + (installer == null ? "null" : installer);
            if (installer == null) {
                // Sideloaded. Honest answer: UNKNOWN.
                return new CheckResult(id, name, Verdict.UNKNOWN, ev + " (sideloaded)");
            }
            boolean fromPlay = "com.android.vending".equals(installer);
            return new CheckResult(id, name, fromPlay ? Verdict.PASS : Verdict.UNKNOWN, ev);
        } catch (PackageManager.NameNotFoundException e) {
            return new CheckResult(id, name, Verdict.UNKNOWN, "NameNotFoundException");
        } catch (RuntimeException e) {
            return new CheckResult(id, name, Verdict.UNKNOWN, "unexpected: " + e);
        }
    }

    // =======================================================================
    // D4 - DEX identity
    // =======================================================================

    /*
     * WHAT IT PROVES
     *   Very little on its own, and the reason is the most useful thing in this
     *   file.
     *
     *   This check opens the app's own APK as a zip and reports the CRC-32 and
     *   uncompressed size that the ZIP CENTRAL DIRECTORY records for
     *   classes.dex. A classic "DEX CRC check" hardcodes that value and
     *   compares.
     *
     *   Against a repackager, it adds NOTHING that D1 does not already give
     *   you: any modification to classes.dex invalidates the v2/v3 signature,
     *   so the attacker re-signs, so D1 fires anyway.
     *
     *   Against a v1-ONLY app it is different, because v1 (JAR) signing does not
     *   cover the zip structure at all - see 10-APK-Internals section 6.5. And
     *   against a RUNTIME patcher it is different again: an attacker who
     *   modifies the in-memory DEX, or who loads a second DEX with
     *   InMemoryDexClassLoader, changes nothing on disk, so this check passes
     *   while the app is thoroughly owned.
     *
     *   Note also that the CRC is read from the central directory - which is
     *   metadata, not the file. It is a claim about the file, made by the file.
     *   A stronger version hashes the decompressed bytes; it costs real time on
     *   a multi-megabyte DEX and lab 01 measures that cost.
     *
     * WHY NO HARDCODED EXPECTED VALUE HERE
     *   Because there cannot be one, and the reason is worth internalising: the
     *   expected CRC of classes.dex cannot be compiled INTO classes.dex. Adding
     *   the constant changes the file the constant describes. That is the
     *   BOOTSTRAP PROBLEM, and every real implementation solves it by putting
     *   the expected value somewhere the hash does not cover - a native library,
     *   an asset injected after dexing, or a server. README section 3.5 works
     *   through all three.
     */
    static CheckResult checkDexIdentity(Context ctx) {
        final String id = "D4", name = "dex identity";
        String apkPath = ctx.getApplicationInfo().sourceDir;
        ZipFile zf = null;
        try {
            zf = new ZipFile(apkPath);
            StringBuilder sb = new StringBuilder();
            int n = 0;
            for (Enumeration<? extends ZipEntry> e = zf.entries(); e.hasMoreElements(); ) {
                ZipEntry ze = e.nextElement();
                String nm = ze.getName();
                if (nm.startsWith("classes") && nm.endsWith(".dex")) {
                    n++;
                    if (sb.length() > 0) sb.append("; ");
                    sb.append(nm)
                      .append(" crc=").append(String.format(Locale.US, "%08x", ze.getCrc()))
                      .append(" size=").append(ze.getSize());
                }
            }
            if (n == 0) {
                return new CheckResult(id, name, Verdict.UNKNOWN, "no classes*.dex in " + apkPath);
            }
            // Reported, not judged. See the comment above.
            return new CheckResult(id, name, Verdict.UNKNOWN, sb + "  (reported, no baseline compiled in)");
        } catch (IOException e) {
            return new CheckResult(id, name, Verdict.UNKNOWN, "IOException: " + e.getMessage());
        } finally {
            if (zf != null) { try { zf.close(); } catch (IOException ignored) { } }
        }
    }

    // =======================================================================
    // D5 - TracerPid
    // =======================================================================

    /*
     * WHAT IT PROVES
     *   That some process is currently ptrace-attached to this one.
     *
     *   /proc/self/status is generated by the kernel on read, in
     *   fs/proc/array.c. The TracerPid line holds the PID of the process that
     *   is ptrace-attached, or 0. A Java debugger (JDWP) does NOT use ptrace, so
     *   this does not see Android Studio's debugger; a native debugger (gdb,
     *   lldb) does, and so does frida-server when it injects by ptrace.
     *
     *   It is a genuine signal with a genuinely narrow meaning. It says
     *   "somebody is ptracing me RIGHT NOW". It says nothing about whether the
     *   process was traced a second ago and detached, and nothing about a
     *   hooking framework that does not use ptrace at all - LSPosed, for
     *   instance, or a Frida Gadget compiled into the app.
     *
     * MEASURED ON THE CHAPTER'S DEVICE
     *   i9000S, Android 13 / API 33: an ordinary untraced shell process reports
     *       TracerPid:      0
     *   and the field is present on every process, readable without any
     *   permission, because a process may always read its own /proc entry.
     */
    static CheckResult checkTracerPid() {
        final String id = "D5", name = "TracerPid";
        BufferedReader r = null;
        try {
            r = new BufferedReader(new FileReader("/proc/self/status"));
            String line;
            while ((line = r.readLine()) != null) {
                if (line.startsWith("TracerPid:")) {
                    String v = line.substring("TracerPid:".length()).trim();
                    int pid;
                    try { pid = Integer.parseInt(v); }
                    catch (NumberFormatException nfe) {
                        return new CheckResult(id, name, Verdict.UNKNOWN, "unparsable: " + line);
                    }
                    String ev = "TracerPid=" + pid;
                    return new CheckResult(id, name, pid == 0 ? Verdict.PASS : Verdict.FAIL, ev);
                }
            }
            return new CheckResult(id, name, Verdict.UNKNOWN, "no TracerPid line in /proc/self/status");
        } catch (IOException e) {
            return new CheckResult(id, name, Verdict.UNKNOWN, "IOException: " + e.getMessage());
        } finally {
            if (r != null) { try { r.close(); } catch (IOException ignored) { } }
        }
    }

    // =======================================================================
    // D6 - Frida default port
    // =======================================================================

    /*
     * WHAT IT PROVES
     *   That something is listening on 127.0.0.1:27042 and accepted a TCP
     *   connection. frida-server binds that port by DEFAULT.
     *
     *   The word "default" is doing all the work. `frida-server -l 0.0.0.0:1337`
     *   moves it, and that is a documented, one-flag change. So this check
     *   costs the attacker exactly one command-line flag, which makes it the
     *   canonical example of a check with a real mechanism and almost no value.
     *
     *   It is included precisely so you can see the difference between a check
     *   that is WRONG and a check that is CHEAP TO EVADE. This one is correct.
     *   It is just worth about ten seconds of an attacker's time.
     *
     * NOTE ON BLOCKING
     *   The connect() is done with a 120 ms timeout on a background thread by
     *   the caller. An integrity check that blocks the main thread on network
     *   I/O is a bug, and on Android it is a crash: NetworkOnMainThreadException
     *   since API 11. MainActivity runs the whole gate off the main thread for
     *   this reason.
     */
    static CheckResult checkFridaPort() {
        final String id = "D6", name = "frida default port";
        final int port = 27042;
        Socket s = new Socket();
        try {
            s.connect(new InetSocketAddress("127.0.0.1", port), 120);
            return new CheckResult(id, name, Verdict.FAIL, "connected to 127.0.0.1:" + port);
        } catch (IOException e) {
            // Connection refused is the expected, healthy answer.
            return new CheckResult(id, name, Verdict.PASS,
                    "127.0.0.1:" + port + " -> " + e.getClass().getSimpleName());
        } finally {
            try { s.close(); } catch (IOException ignored) { }
        }
    }

    // =======================================================================
    // D7 - /proc/self/maps scan
    // =======================================================================

    /*
     * WHAT IT PROVES
     *   That a mapping whose backing path or anon name matches a known
     *   instrumentation artefact is present in this process's address space.
     *
     *   /proc/<pid>/maps is generated by fs/proc/task_mmu.c on read. Each line
     *   is one VMA: address range, permissions, offset, device, inode, and the
     *   path of the backing file if there is one. Frida's agent is injected as
     *   a library, so historically it appears by name; Frida also creates
     *   anonymous executable mappings for its code, and an anonymous mapping
     *   with rwx or with an x permission and no backing file is unusual in a
     *   normal Android process.
     *
     *   This is one of the more expensive checks to evade properly, because the
     *   attacker must either rename the artefacts, load them differently, or
     *   hook the reads. It is still evadable - hooking open("/proc/self/maps")
     *   is a two-line Frida script, and section 6 of the README shows exactly
     *   that.
     *
     * WHY THE JAVA VERSION IS THE WEAK VERSION
     *   Reading a file from Java goes through java.io.FileReader -> libcore
     *   BlockGuardOs -> Posix -> libc open(). Every layer is hookable, and the
     *   Java layer is the easiest of them. The native tier of the same check
     *   lives in ../tamper_check.c and runs in JNI_OnLoad, before any of this
     *   class exists.
     */
    static CheckResult checkOwnMaps() {
        final String id = "D7", name = "maps scan";
        final String[] needles = {
            "frida", "gum-js-loop", "gmain", "linjector", "frida-agent", "re.frida"
        };
        BufferedReader r = null;
        int lines = 0, anonExec = 0;
        List<String> hits = new ArrayList<>();
        try {
            r = new BufferedReader(new FileReader("/proc/self/maps"));
            String line;
            while ((line = r.readLine()) != null) {
                lines++;
                String lower = line.toLowerCase(Locale.US);
                for (String needle : needles) {
                    if (lower.contains(needle)) { hits.add(needle); break; }
                }
                // Executable mapping with no backing path. Count it; do not
                // judge on it alone. ART's JIT code cache produces these
                // legitimately, which is exactly why "rwx page found" is a
                // false-positive machine on Android.
                int sp = line.indexOf(' ');
                if (sp > 0 && line.length() > sp + 4) {
                    String perms = line.substring(sp + 1, sp + 5);
                    boolean exec = perms.charAt(2) == 'x';
                    boolean backed = line.trim().endsWith("]") || line.lastIndexOf('/') > sp;
                    if (exec && !backed) anonExec++;
                }
            }
        } catch (IOException e) {
            return new CheckResult(id, name, Verdict.UNKNOWN, "IOException: " + e.getMessage());
        } finally {
            if (r != null) { try { r.close(); } catch (IOException ignored) { } }
        }

        String ev = lines + " mappings, " + anonExec + " anonymous executable, hits=" + hits;
        return new CheckResult(id, name, hits.isEmpty() ? Verdict.PASS : Verdict.FAIL, ev);
    }

    // =======================================================================
    // Helpers
    // =======================================================================

    static String sha256Hex(byte[] data) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] d = md.digest(data);
            StringBuilder sb = new StringBuilder(d.length * 2);
            for (byte b : d) sb.append(String.format(Locale.US, "%02x", b));
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is mandatory on every Android device. If this throws, the
            // platform is not Android.
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    /**
     * Constant-time string comparison.
     *
     * Honest note: against a LOCAL attacker this buys nothing at all - they can
     * read the constant out of the DEX in one command. It is here because the
     * same helper in a server-side verifier DOES matter, and because writing
     * `expected.equals(actual)` in security code trains the wrong reflex.
     * README section 11.1 explains when this is theatre and when it is not.
     */
    static boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null) return false;
        if (a.length() != b.length()) return false;
        int diff = 0;
        for (int i = 0; i < a.length(); i++) diff |= a.charAt(i) ^ b.charAt(i);
        return diff == 0;
    }

    private IntegrityGate() { }
}
