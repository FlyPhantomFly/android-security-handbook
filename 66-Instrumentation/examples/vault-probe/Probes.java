// examples/vault-probe/Probes.java
//
// Small reflection and filesystem helpers used by VaultProbe.
//
// Everything here is written with REFLECTION ONLY and never with a compile-time
// dependency on the target application. That is deliberate twice over:
//
//   1. It is what an assessment actually looks like. You do not have the target's
//      source, you have its DEX, and you address its members by name.
//   2. It keeps the test APK free of the target's classes. If the test APK
//      shipped a copy of com.pentest.ch66.vault.VaultStore, you would be reading
//      YOUR copy's static field, not the target's, and every result would be a
//      confident lie. See chapter 66 section 11.2.
//
// AUTHORISED TESTING ONLY.

package com.pentest.ch66.probe;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;

final class Probes {

    private Probes() {
    }

    /**
     * Read a static field of an arbitrary class by name, using the supplied
     * ClassLoader. Returns a printable description, never throws.
     *
     * The ClassLoader argument matters more than it looks. Passing the
     * instrumentation context's loader resolves the target's classes through the
     * PARENT link that ActivityThread.initInstrumentation() set up; passing the
     * probe's own loader would work here only because of that same link.
     */
    static String readStaticField(ClassLoader cl, String className, String fieldName) {
        try {
            Class<?> c = Class.forName(className, true, cl);
            Field f = c.getDeclaredField(fieldName);
            f.setAccessible(true);
            Object v = f.get(null);
            return String.valueOf(v);
        } catch (Throwable t) {
            return "ERROR " + t.getClass().getSimpleName() + ": " + t.getMessage();
        }
    }

    /** Write a static field by name. Returns "ok" or an error description. */
    static String writeStaticField(ClassLoader cl, String className, String fieldName,
                                   Object value) {
        try {
            Class<?> c = Class.forName(className, true, cl);
            Field f = c.getDeclaredField(fieldName);
            f.setAccessible(true);
            f.set(null, value);
            return "ok";
        } catch (Throwable t) {
            return "ERROR " + t.getClass().getSimpleName() + ": " + t.getMessage();
        }
    }

    /** Invoke a no-argument static method by name. */
    static String callStaticNoArg(ClassLoader cl, String className, String methodName) {
        try {
            Class<?> c = Class.forName(className, true, cl);
            Method m = c.getDeclaredMethod(methodName);
            m.setAccessible(true);
            return String.valueOf(m.invoke(null));
        } catch (Throwable t) {
            return "ERROR " + t.getClass().getSimpleName() + ": " + t.getMessage();
        }
    }

    /**
     * Attempt to read a path and report the OUTCOME, not merely a boolean.
     *
     * This repository has measured, in three chapters independently, that
     * File.exists() collapses ENOENT and EACCES to the same false. Anything that
     * reports a path check as a boolean is discarding the only bit that matters.
     * So this returns one of:
     *
     *   READ:<n> bytes   the read succeeded
     *   ABSENT           the parent was listable and the entry is not there
     *   DENIED:<msg>     the open failed with a permission error
     *   ERROR:<msg>      anything else
     */
    static String probePath(String path) {
        File f = new File(path);
        try (FileInputStream in = new FileInputStream(f)) {
            byte[] buf = new byte[4096];
            int n = in.read(buf);
            return "READ:" + Math.max(n, 0);
        } catch (IOException e) {
            String m = String.valueOf(e.getMessage());
            if (m.contains("Permission denied") || m.contains("EACCES")) {
                return "DENIED:" + m;
            }
            if (m.contains("No such file") || m.contains("ENOENT")) {
                return "ABSENT:" + m;
            }
            if (m.contains("Is a directory") || m.contains("EISDIR")) {
                // A directory that opened is a directory we are allowed to reach.
                return "DIR:" + (f.list() == null ? "unlistable" : f.list().length + " entries");
            }
            return "ERROR:" + m;
        } catch (Throwable t) {
            return "ERROR:" + t.getClass().getSimpleName() + " " + t.getMessage();
        }
    }

    /** Read a whole small file as text, or return an error description. */
    static String readText(String path, int maxChars) {
        StringBuilder sb = new StringBuilder();
        try (BufferedReader r = new BufferedReader(
                new InputStreamReader(new FileInputStream(path), StandardCharsets.UTF_8))) {
            int c;
            while ((c = r.read()) != -1 && sb.length() < maxChars) {
                sb.append((char) c);
            }
            return sb.toString().trim();
        } catch (Throwable t) {
            return "ERROR:" + t.getClass().getSimpleName() + " " + t.getMessage();
        }
    }

    /**
     * Try to reach a hidden (non-SDK) API by reflection and report what the
     * runtime said. On a device with hidden-API enforcement active this returns
     * a NoSuchMethodException or an access warning; with
     * `am instrument --no-hidden-api-checks` the same call succeeds. That
     * difference is the whole reason the flag exists.
     */
    static String reflectHidden(String className, String methodName, String arg) {
        try {
            Class<?> c = Class.forName(className);
            Method m = c.getDeclaredMethod(methodName, String.class);
            m.setAccessible(true);
            Object v = m.invoke(null, arg);
            return "OK:" + v;
        } catch (Throwable t) {
            Throwable root = t.getCause() != null ? t.getCause() : t;
            return "BLOCKED:" + root.getClass().getSimpleName() + " " + root.getMessage();
        }
    }

    /**
     * Count the declared methods and fields the runtime is willing to SHOW us on
     * a class, and report whether a particular member name is among them.
     *
     * This is the honest way to measure hidden-API enforcement, and it is much
     * better than trying one member and hoping it is denylisted. ART implements
     * the restriction inside the reflection APIs themselves: a blocked member is
     * filtered out of getDeclaredMethods()/getDeclaredFields() entirely, so
     * getDeclaredMethod() reports NoSuchMethodException for something that is
     * plainly in the DEX. Greylisted ("unsupported") members are NOT filtered --
     * they are returned with a logcat warning. So the count is a number that
     * moves when enforcement is lifted, and a single lookup usually is not.
     *
     * Format: "methods=<n> fields=<m> has:<name>=<true|false>"
     */
    static String memberCensus(String className, String memberName) {
        try {
            Class<?> c = Class.forName(className);
            Method[] ms = c.getDeclaredMethods();
            java.lang.reflect.Field[] fs = c.getDeclaredFields();
            boolean has = false;
            for (Method m : ms) {
                if (m.getName().equals(memberName)) {
                    has = true;
                    break;
                }
            }
            return "methods=" + ms.length + " fields=" + fs.length
                    + " has:" + memberName + "=" + has;
        } catch (Throwable t) {
            return "ERROR:" + t.getClass().getSimpleName() + " " + t.getMessage();
        }
    }

    /**
     * Run a shell command through UiAutomation and return its first 200
     * characters of output on one line.
     *
     * UiAutomation.executeShellCommand() does NOT run the command in this
     * process. The system runs it, and the identity it runs under is the shell
     * uid, not ours. That is the whole point of measuring it here: if this works
     * from a process running as an app uid, then an instrumentation is holding
     * two vantages at once, and every "prove it from the app, not the shell"
     * result in this repository needs a footnote for instrumented processes.
     */
    static String execShell(android.app.UiAutomation ua, String cmd) {
        android.os.ParcelFileDescriptor pfd = null;
        try {
            pfd = ua.executeShellCommand(cmd);
            try (java.io.InputStream in =
                         new android.os.ParcelFileDescriptor.AutoCloseInputStream(pfd)) {
                StringBuilder sb = new StringBuilder();
                byte[] buf = new byte[512];
                int n;
                while ((n = in.read(buf)) > 0 && sb.length() < 400) {
                    sb.append(new String(buf, 0, n, StandardCharsets.UTF_8));
                }
                String s = sb.toString().replace('\n', '|').replace('\r', ' ').trim();
                return s.length() > 200 ? s.substring(0, 200) : s;
            }
        } catch (Throwable t) {
            return "ERROR:" + t.getClass().getSimpleName() + " " + t.getMessage();
        } finally {
            if (pfd != null) {
                try {
                    pfd.close();
                } catch (IOException ignored) {
                    // Already closed by AutoCloseInputStream on the happy path.
                }
            }
        }
    }

    /** Print a ClassLoader parent chain, one entry per element. */
    static String classLoaderChain(ClassLoader cl) {
        StringBuilder sb = new StringBuilder();
        int depth = 0;
        while (cl != null && depth < 8) {
            if (depth > 0) {
                sb.append(" -> ");
            }
            sb.append(cl.toString().replace('\n', ' '));
            cl = cl.getParent();
            depth++;
        }
        return sb.toString();
    }
}
