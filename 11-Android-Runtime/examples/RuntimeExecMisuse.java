/*
 * ============================================================================
 *  RuntimeExecMisuse.java  —  Chapter 11, Android Runtime
 * ============================================================================
 *
 *  WHAT THIS DOES
 *  --------------
 *  java.lang.Runtime is the managed-code door out of the managed world. Every
 *  Android app has one Runtime object (Runtime.getRuntime()), and its exec()
 *  family forks a new Linux process. So does java.lang.ProcessBuilder, which is
 *  the same machinery with a nicer API - internally both end up in
 *  java.lang.ProcessImpl / java.lang.UNIXProcess and finally in a fork/exec
 *  pair of syscalls performed by libcore's native helper.
 *
 *  This file contains, side by side and clearly labelled:
 *
 *    [VULNERABLE 1] command injection: attacker-controlled text concatenated
 *                   into a string that is handed to a shell.
 *    [VULNERABLE 2] the same bug wearing a ProcessBuilder costume.
 *    [VULNERABLE 3] root detection via exec("su") - not a memory-safety bug,
 *                   but a security control that does not work, which is worse
 *                   because people trust it.
 *    [FIXED 1..3]   the hardened versions, with the reasoning.
 *
 *  HOW TO RUN IT
 *  -------------
 *  This is a library-style class: no Activity, no UI. Drop it into a project
 *  and call the methods, or paste the individual methods into whatever app you
 *  are testing.
 *
 *      # host shell - add the file to a project, then from your own code:
 *      #   Log.i("exec", RuntimeExecMisuse.fixedPing("8.8.8.8"));
 *      ./gradlew installDebug
 *      adb logcat -s RuntimeExecMisuse:I
 *
 *  To watch the child processes appear while you experiment:
 *
 *      # adb shell
 *      ps -A | grep -E 'sh|ping|toolbox'
 *
 *  To see the syscalls for real (needs root or a debuggable app on a
 *  userdebug/eng build):
 *
 *      # adb shell as root
 *      strace -f -e trace=execve,clone,fork -p $(pidof com.example.runtimelab)
 *
 *  PREREQUISITES
 *  -------------
 *   - minSdk 21+. No permissions are required to call exec(): forking a child
 *     is not permission-gated, it is UID-gated. The child inherits your UID.
 *   - INTERNET permission only if you actually run the ping example.
 *
 *  THE ONE SENTENCE TO REMEMBER
 *  ----------------------------
 *  Runtime.exec() is not a privilege escalation and not a sandbox escape: the
 *  child process inherits your UID, your SELinux domain (untrusted_app) and
 *  your seccomp filter. It is dangerous for exactly one reason - it lets an
 *  attacker who controls a string control an argv, and on Android an argv can
 *  reach a shell.
 * ============================================================================
 */

package com.example.runtimelab;

import android.util.Log;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

public final class RuntimeExecMisuse {

    private static final String TAG = "RuntimeExecMisuse";

    private RuntimeExecMisuse() {
        // Utility class.
    }

    // ========================================================================
    //  [VULNERABLE 1]  Classic command injection through Runtime.exec(String)
    // ========================================================================
    /**
     * A "network diagnostics" feature: the user types a hostname, the app pings
     * it and shows the output. The hostname arrives from an EditText, or - much
     * worse and very common - from an exported Activity's Intent extra, a
     * deep link, or a WebView JavaScript bridge. Assume it is attacker-supplied.
     *
     * TWO separate mistakes are stacked here, and you need to be able to name
     * both:
     *
     *  MISTAKE A - the single-String overload.
     *      Runtime.exec(String) does NOT run a shell. It splits the string on
     *      whitespace with a StringTokenizer and execs argv[0]. Developers
     *      routinely believe this overload gives them shell semantics, write
     *      commands with pipes and redirects, find that they do not work, and
     *      then "fix" it by adding an explicit shell - which is mistake B.
     *      The naive splitting is itself a bug: a host of "a b" becomes two
     *      arguments.
     *
     *  MISTAKE B - explicitly invoking sh -c with a concatenated string.
     *      Now the attacker's text is parsed by a shell. Every shell
     *      metacharacter becomes an operator:
     *          ;   &&   ||   |   `cmd`   $(cmd)   >   <   &   newline
     *      Input "8.8.8.8; id > /data/data/<pkg>/files/pwn" runs `id` as your
     *      app's UID and writes into your private storage. Input using $(...)
     *      can exfiltrate file contents through the hostname of a subsequent
     *      request. On a rooted device, or in an app that is itself privileged,
     *      the impact scales with the privilege of the process.
     *
     * Severity in a report: this is command injection (CWE-78). If the entry
     * point is exported, it is remote/cross-app code execution in the app's UID
     * and normally rated High to Critical.
     */
    public static String vulnerablePing(String userSuppliedHost) throws IOException {
        // VULNERABLE: string concatenation into a shell command line.
        String command = "ping -c 1 " + userSuppliedHost;

        // VULNERABLE: handing the concatenated string to a real shell.
        Process p = Runtime.getRuntime().exec(new String[]{"/system/bin/sh", "-c", command});

        String out = readAll(p.getInputStream());
        Log.i(TAG, "vulnerablePing output: " + out);
        return out;
    }

    // ========================================================================
    //  [VULNERABLE 2]  The same bug, wearing a ProcessBuilder costume
    // ========================================================================
    /**
     * ProcessBuilder is often recommended as "the safe alternative", and it is
     * safer - but only because its natural API is a list of arguments. The
     * moment you put a shell at argv[0] and a concatenated string at argv[2],
     * ProcessBuilder is exactly as injectable as Runtime.exec(). The safety
     * comes from NOT USING A SHELL, not from the class name.
     *
     * Note redirectErrorStream(true): merging stderr into stdout is convenient,
     * and it also means error messages (which frequently echo attacker input or
     * leak paths) end up in whatever the app displays or logs.
     */
    public static String vulnerableArchive(String userSuppliedFileName) throws IOException {
        List<String> argv = new ArrayList<>();
        argv.add("/system/bin/sh");
        argv.add("-c");
        // VULNERABLE: attacker text lands inside a shell word.
        argv.add("tar czf /sdcard/backup.tgz " + userSuppliedFileName);

        ProcessBuilder pb = new ProcessBuilder(argv);
        pb.redirectErrorStream(true);
        Process p = pb.start();

        String out = readAll(p.getInputStream());
        Log.i(TAG, "vulnerableArchive output: " + out);
        return out;
    }

    // ========================================================================
    //  [VULNERABLE 3]  Root detection by exec("su")
    // ========================================================================
    /**
     * This is in every "security SDK" you will ever reverse. The idea: if we can
     * spawn `su`, the device is rooted, so refuse to run.
     *
     * Why it is not a security control:
     *
     *  1. The check runs INSIDE the process it is trying to protect. On a rooted
     *     device the attacker controls that process completely. One Frida line
     *     makes this method return false forever:
     *
     *         var Rt = Java.use('java.lang.Runtime');
     *         Rt.exec.overload('java.lang.String').implementation = function (cmd) {
     *             if (cmd.indexOf('su') !== -1) {
     *                 // Pretend the binary does not exist. The caller's catch
     *                 // block turns this into "not rooted".
     *                 throw Java.use('java.io.IOException').$new('No such file');
     *             }
     *             return this.exec(cmd);
     *         };
     *
     *     You cannot verify the integrity of your own environment from inside
     *     that environment. This is not an implementation flaw; it is the
     *     definition of the situation.
     *
     *  2. It produces false negatives on real rooted devices. Magisk and similar
     *     tools deliberately hide the `su` binary from unprivileged processes
     *     and from PATH, so the exec simply fails on a thoroughly rooted phone.
     *
     *  3. It produces false positives. Some custom ROMs and emulator images ship
     *     an `su` that any process can invoke without granting anything, so
     *     legitimate users get locked out.
     *
     *  4. It burns a process fork and can hang. Notice this version never sets a
     *     timeout and never closes the streams: on a device where `su` prompts
     *     and waits, waitFor() blocks a thread forever. If that thread is the
     *     main thread, you have shipped an ANR.
     *
     * Root detection has a legitimate use as a RISK SIGNAL reported to a server
     * alongside other telemetry. It is not an access control. See chapter 37 for
     * the full treatment; this file only shows why the exec-based variant is
     * both weak and badly written.
     */
    public static boolean vulnerableIsRooted() {
        Process p = null;
        try {
            // VULNERABLE (as a security control): trivially hooked, unreliable,
            // and here also missing a timeout and stream cleanup.
            p = Runtime.getRuntime().exec("su");
            int rc = p.waitFor();               // may block forever
            return rc == 0;
        } catch (Exception e) {
            return false;
        } finally {
            // Even the cleanup is a lesson: a Process holds three file
            // descriptors. Leak enough of them and the app dies with EMFILE.
            if (p != null) {
                p.destroy();
            }
        }
    }

    // ========================================================================
    //  [FIXED 1]  No shell, argv array, strict allowlist validation
    // ========================================================================
    /**
     * Four independent defences, in order of importance:
     *
     *  1. DO NOT USE A SHELL. We exec /system/bin/ping directly. With no shell
     *     in the picture, ';' and '$(...)' are just bytes in argv[2]. This alone
     *     removes command injection; everything below is defence in depth.
     *
     *  2. USE THE ARRAY OVERLOAD. exec(String[]) passes the array to execve as
     *     argv with no re-splitting, so an argument containing spaces stays one
     *     argument. Never build a command as one string.
     *
     *  3. VALIDATE WITH AN ALLOWLIST, NOT A BLOCKLIST. Blocklists of "dangerous
     *     characters" fail forever: someone always forgets a newline, a
     *     backtick, a $IFS trick, or a Unicode homoglyph. Here we accept only
     *     RFC-1123-shaped hostnames and dotted-quad IPv4. Anything else is
     *     rejected before a process is created.
     *
     *  4. USE AN ABSOLUTE PATH. Executing "ping" searches PATH; executing
     *     "/system/bin/ping" cannot be redirected by an inherited environment.
     *     We also refuse to run if the binary is missing rather than falling
     *     back to a shell.
     *
     * And the real fix, when it is available: do not exec at all. For ping-like
     * reachability use java.net.InetAddress.isReachable(); for file listing use
     * java.io.File; for zipping use java.util.zip. Every one of those runs
     * in-process with no argv and no shell. Reaching for exec() on Android is
     * almost always a sign that a platform API was not found.
     */
    private static final Pattern SAFE_HOST = Pattern.compile(
            "^(?=.{1,253}$)([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)"
          + "(\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$");

    public static String fixedPing(String userSuppliedHost) throws IOException {
        // FIXED (defence 3): allowlist validation, fail closed.
        if (userSuppliedHost == null || !SAFE_HOST.matcher(userSuppliedHost).matches()) {
            throw new IllegalArgumentException("rejected host: not a valid hostname/IP");
        }

        // FIXED (defence 4): absolute path, existence checked.
        File ping = new File("/system/bin/ping");
        if (!ping.canExecute()) {
            throw new IOException("ping binary unavailable; refusing to fall back to a shell");
        }

        // FIXED (defences 1 and 2): no shell anywhere, argv as an array.
        ProcessBuilder pb = new ProcessBuilder(
                ping.getAbsolutePath(), "-c", "1", "-W", "2", userSuppliedHost);
        pb.redirectErrorStream(true);

        // Do not inherit a caller-controlled environment. Clearing it removes a
        // whole family of tricks that rely on LD_PRELOAD, LD_LIBRARY_PATH,
        // PATH or IFS - all of which are inherited by the child by default.
        pb.environment().clear();

        Process p = pb.start();
        try {
            // FIXED: always bound the wait. waitFor(long, TimeUnit) exists since
            // API 26; on older devices run the wait on a background thread with
            // your own watchdog instead of blocking indefinitely.
            String out = readAll(p.getInputStream());
            boolean finished = p.waitFor(5, TimeUnit.SECONDS);
            if (!finished) {
                p.destroy();               // SIGTERM
                throw new IOException("ping timed out");
            }
            Log.i(TAG, "fixedPing exit=" + p.exitValue());
            return out;
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();   // never swallow an interrupt
            p.destroy();
            throw new IOException("interrupted", ie);
        } finally {
            closeQuietly(p.getInputStream());
            closeQuietly(p.getOutputStream());
            closeQuietly(p.getErrorStream());
        }
    }

    // ========================================================================
    //  [FIXED 2]  The archive example without a shell
    // ========================================================================
    /**
     * The vulnerable version needed a shell only for convenience. Here the file
     * name never becomes shell syntax, and we additionally canonicalise the path
     * and require it to stay inside a directory we own - which kills the second
     * bug hiding in the original: path traversal ("../../databases/app.db").
     *
     * Note the ordering: canonicalise FIRST, then compare prefixes. Comparing
     * before canonicalising is the classic mistake, because "safe/../../etc"
     * starts with "safe/".
     */
    public static String fixedArchive(File baseDir, String userSuppliedFileName)
            throws IOException {
        File requested = new File(baseDir, userSuppliedFileName);

        String canonicalBase = baseDir.getCanonicalPath() + File.separator;
        String canonicalReq = requested.getCanonicalPath();
        if (!canonicalReq.startsWith(canonicalBase)) {
            throw new IllegalArgumentException("path traversal rejected: " + userSuppliedFileName);
        }
        if (!requested.isFile()) {
            throw new IllegalArgumentException("not a regular file");
        }

        // FIXED: argv array, absolute binary path, no shell. Even if the file
        // name is literally  "; rm -rf /"  it is one harmless argv element.
        ProcessBuilder pb = new ProcessBuilder(
                "/system/bin/toybox", "tar", "czf",
                new File(baseDir, "backup.tgz").getAbsolutePath(),
                canonicalReq);
        pb.environment().clear();
        pb.redirectErrorStream(true);
        Process p = pb.start();
        try {
            return readAll(p.getInputStream());
        } finally {
            closeQuietly(p.getInputStream());
            closeQuietly(p.getOutputStream());
            closeQuietly(p.getErrorStream());
            p.destroy();
        }
    }

    // ========================================================================
    //  [FIXED 3]  Honest root signalling instead of exec("su")
    // ========================================================================
    /**
     * "Fixed" here means: no longer pretending to be an access control, no
     * longer forking a process, no longer able to hang, and honest about what it
     * measures. It reports OBSERVATIONS. The decision belongs on a server, where
     * the attacker does not control the code, and it should be one input among
     * many (attestation, behavioural signals, account risk).
     *
     * Note that a determined attacker on a rooted device hooks this method too.
     * That is fine and expected - the point is that we no longer BET security on
     * it. Compare with the vulnerable version, which gates access on a boolean
     * that the attacker owns.
     *
     * For an actual hardware-rooted trust signal use the Play Integrity API or a
     * key attestation certificate chain from the Android KeyStore (chapters 49
     * and 50): those are verified off-device against a Google/vendor root, so
     * the answer does not depend on code the attacker can rewrite.
     */
    public static String observeRootIndicators() {
        StringBuilder sb = new StringBuilder();

        // Static filesystem observations. Cheap, no fork, no hang. Each one is
        // individually defeatable; none is treated as authoritative.
        String[] suspectPaths = {
                "/system/bin/su", "/system/xbin/su", "/sbin/su",
                "/system/app/Superuser.apk", "/data/local/tmp/frida-server"
        };
        for (String path : suspectPaths) {
            File f = new File(path);
            // exists() on a path we cannot stat returns false; that is an
            // observation too, and we record it as such rather than as "clean".
            sb.append(path).append('=').append(f.exists()).append(';');
        }

        // Build fingerprint hints (test-keys, userdebug builds). Again: signals.
        sb.append("tags=").append(android.os.Build.TAGS).append(';');
        sb.append("type=").append(android.os.Build.TYPE).append(';');

        Log.i(TAG, "root indicators: " + sb);
        return sb.toString();   // send to the server; do not branch on it locally
    }

    // ========================================================================
    //  Helpers
    // ========================================================================

    /**
     * Reads a child's stdout fully.
     *
     * WHY THIS MATTERS: a child process writes into a pipe with a small kernel
     * buffer (64 KiB is typical). If the parent calls waitFor() without draining
     * the pipe, the child blocks on write(), the parent blocks on wait(), and
     * you have a deadlock that looks like a random ANR in production. Always
     * drain before, or concurrently with, waiting.
     */
    private static String readAll(InputStream in) throws IOException {
        StringBuilder sb = new StringBuilder();
        BufferedReader r = new BufferedReader(
                new InputStreamReader(in, Charset.forName("UTF-8")));
        String line;
        while ((line = r.readLine()) != null) {
            sb.append(line).append('\n');
        }
        return sb.toString();
    }

    private static void closeQuietly(java.io.Closeable c) {
        if (c == null) {
            return;
        }
        try {
            c.close();
        } catch (IOException ignored) {
            // Closing on a cleanup path; nothing useful to do with the failure.
        }
    }
}

/*
 * ============================================================================
 *  HOW A PENTESTER FINDS THIS, AND WHAT TO WRITE IN THE REPORT
 * ============================================================================
 *
 *  STATIC - in Smali, exec and ProcessBuilder are unmistakable:
 *
 *      # host shell, after: apktool d target.apk -o out/
 *      grep -rn "Ljava/lang/Runtime;->exec" out/
 *      grep -rn "Ljava/lang/ProcessBuilder;-><init>" out/
 *      grep -rn "Ljava/lang/ProcessBuilder;->start" out/
 *
 *  Then walk backwards from the call site to find where the string is built. A
 *  nearby StringBuilder;->append chain feeding into exec() is the signature of
 *  concatenation, which is the signature of injection. ../scripts/find-dynamic-loading.py
 *  automates the search half of this.
 *
 *  DYNAMIC - hook both sinks and print every argv:
 *
 *      # host shell
 *      frida -U -f com.example.runtimelab -l ../scripts/runtime-recon.js
 *
 *  Then drive the UI, or fire the exported component yourself:
 *
 *      # adb shell
 *      am start -n com.example.runtimelab/.SomeExportedActivity --es host '8.8.8.8; id'
 *
 *  If `id` output appears, you have proof of execution, not just a code smell -
 *  which is the difference between an Informational and a High finding.
 *
 *  IMPACT WORDING THAT SURVIVES A DEVELOPER'S PUSHBACK:
 *  "The command runs as the application's UID, so it can read and modify every
 *  file in the app's private data directory, including its databases and its
 *  authentication tokens, and can make network requests with the app's
 *  identity. It does not require root and it does not require the device to be
 *  compromised. The only precondition is reaching the entry point that supplies
 *  the string."
 *
 *  OWASP MASVS mapping: MASVS-CODE (code quality / injection sinks) and
 *  MASVS-PLATFORM (exported components as the delivery path). MASTG contains
 *  dedicated tests for both the injection sink and the exported-component
 *  reachability half.
 * ============================================================================
 */
