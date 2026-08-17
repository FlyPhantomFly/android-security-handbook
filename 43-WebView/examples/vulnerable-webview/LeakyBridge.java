// examples/vulnerable-webview/LeakyBridge.java
//
// The Java object exposed to page JavaScript by
// VulnerableWebViewActivity's addJavascriptInterface call.
//
// READ THIS FIRST, because it is the point of the whole example:
//
//   Every method below carries @android.webkit.JavascriptInterface. From API 17
//   onward that annotation is what makes a method callable from JavaScript --
//   without it, the method is invisible to the page. Before API 17 there was no
//   annotation and EVERY public method of the bridged object was exposed,
//   including the ones inherited from java.lang.Object. That inheritance is what
//   made the pre-17 situation catastrophic rather than merely dangerous:
//   `getClass()` is public on every object, so page script could reach
//   `AndroidBridge.getClass().getClassLoader().loadClass("java.lang.Runtime")`
//   and from there `Runtime.getRuntime().exec(...)`. Arbitrary command execution
//   from one line of JavaScript.
//
//   The annotation closed that specific hole. It closed nothing else. The
//   methods below are annotated, they are exactly the methods the developer
//   meant to expose, and they still hand a web page the app's session token and
//   the contents of its private files. The bug is the bridge, not the missing
//   annotation.
//
// Everything a bridge method does, it does:
//   - in the host app's process
//   - as the host app's Linux UID
//   - with the host app's granted permissions
//   - with the host app's SELinux domain
// The renderer sandbox (an isolatedProcess, see ../../../21-App-Sandbox/README.md)
// protects the system from a Chromium memory-corruption bug. It does NOT protect
// the app from its own bridge: the bridge call is a deliberate, designed hop
// across that boundary, marshalled from the renderer into the browser process
// and then into app code.

package com.pentest.ch43.vuln;

import android.content.ContentResolver;
import android.content.Context;
import android.net.Uri;
import android.util.Log;
import android.webkit.JavascriptInterface;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;

public class LeakyBridge {

    static final String TAG = "CH43VULN";

    private final Context ctx;

    LeakyBridge(Context ctx) {
        this.ctx = ctx;
    }

    /**
     * The classic. A "convenience" accessor so the web page can show a signed-in
     * header without a round trip. It hands the session token to whatever is
     * rendering, which -- once the URL is attacker-controlled -- is the attacker.
     */
    @JavascriptInterface
    public String getSessionToken() {
        Log.i(TAG, "bridge: getSessionToken()");
        return readFileRaw(new File(ctx.getFilesDir(),
                VulnerableWebViewActivity.SECRET_FILE).getAbsolutePath());
    }

    /**
     * An unconstrained file reader. Nobody writes this on purpose; it arrives as
     * "let the page load its own cached assets" and grows a parameter.
     *
     * There is no path canonicalisation, so `../` works, and no allow-list, so
     * every file the app's UID can read is reachable -- its own databases and
     * shared_prefs included.
     */
    @JavascriptInterface
    public String readFile(String path) {
        Log.i(TAG, "bridge: readFile(" + path + ")");
        return readFileRaw(path);
    }

    /**
     * Reaching a ContentProvider from JavaScript, through Java.
     *
     * Note there are TWO paths from a web page to a provider, and they are
     * different mechanisms with different mitigations:
     *
     *   1. This method: the page calls a bridge that calls ContentResolver.
     *      Mitigation: do not expose it.
     *   2. `fetch("content://...")` straight from script, with no bridge at all,
     *      because WebSettings.setAllowContentAccess defaults to TRUE.
     *      Mitigation: setAllowContentAccess(false).
     *
     * Both resolve as THIS app. Chapter 27 owns what is on the other end.
     */
    @JavascriptInterface
    public String readContent(String uri) {
        Log.i(TAG, "bridge: readContent(" + uri + ")");
        try {
            ContentResolver cr = ctx.getContentResolver();
            InputStream in = cr.openInputStream(Uri.parse(uri));
            if (in == null) {
                return "ERR: no stream";
            }
            String out = slurp(in);
            in.close();
            return out;
        } catch (Exception e) {
            return "ERR: " + e;
        }
    }

    /**
     * Looks harmless. It is a device fingerprint delivered to any page the
     * WebView renders -- including third-party ad and analytics frames, which is
     * how bridges leak without anybody being attacked at all.
     */
    @JavascriptInterface
    public String deviceInfo() {
        return "{\"model\":\"" + android.os.Build.MODEL
                + "\",\"sdk\":" + android.os.Build.VERSION.SDK_INT
                + ",\"serialish\":\"" + android.os.Build.FINGERPRINT + "\"}";
    }

    /**
     * A public method with NO annotation.
     *
     * On API 17 and above this is NOT reachable from JavaScript, and that is
     * worth proving to yourself in the lab rather than believing: call
     * `AndroidBridge.notExposed()` from the page and watch it come back
     * undefined. On API 16 and below it would have been reachable, along with
     * getClass(), hashCode(), toString(), notify(), and wait().
     */
    public String notExposed() {
        return "if you can read this from JavaScript, the annotation gate is broken";
    }

    // ----------------------------------------------------------------------- //

    private String readFileRaw(String path) {
        try {
            FileInputStream in = new FileInputStream(path);
            String out = slurp(in);
            in.close();
            return out;
        } catch (Exception e) {
            return "ERR: " + e;
        }
    }

    private String slurp(InputStream in) throws Exception {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        byte[] chunk = new byte[4096];
        int n;
        int total = 0;
        while ((n = in.read(chunk)) > 0 && total < 262144) {
            buf.write(chunk, 0, n);
            total += n;
        }
        return new String(buf.toByteArray(), "UTF-8");
    }
}
