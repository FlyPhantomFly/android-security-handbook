// examples/webview-probe/ProbeActivity.java
//
// The measurement app. Everything in ../../README.md section 3.4 -- the table of
// WebSettings defaults by targetSdkVersion -- was produced by running this, not
// by reading documentation. Run it yourself on your own device before you quote
// that table, because the answers depend on the installed WebView version, which
// updates independently of the OS.
//
// HOW IT WORKS, AND WHY THAT IS INTERESTING
//
//   WebSettings defaults are not constants. Several of them are chosen at
//   WebView construction time from the HOST APP's targetSdkVersion:
//
//       WebView -> WebViewChromiumFactoryProvider -> WebViewChromium
//               -> ContentSettingsAdapter / AwSettings
//
//   AwSettings' constructor reads the target SDK from the application context.
//   Which means an app cannot normally see more than one row of the table: its
//   own targetSdkVersion is fixed at build time.
//
//   `ApplicationInfo.targetSdkVersion` is a plain public int field on a mutable
//   object that the app owns a reference to. So this probe assigns to it, builds
//   a fresh WebView, reads every getter, and repeats. Seventeen rows, one
//   install, no Frida.
//
//   That this works AT ALL is itself a measured result, and it is the one worth
//   remembering: the value is read per-WebView at construction, not cached in a
//   static at process start. It also tells you something operationally -- an
//   attacker with code execution in the app process, or an instrumentation
//   framework, can flip these defaults for WebViews created afterwards.
//
//   The mutation is local to this process and is restored before the probe
//   finishes. It does not touch the package manager, other apps, or anything on
//   disk.
//
// BUILD AND RUN
//   # host
//   ../build.sh --install
//   adb logcat -c
//   adb shell am start -n com.pentest.ch43.probe/.ProbeActivity
//   adb logcat -d -s CH43PROBE:I
//
// WHAT THIS WILL *NOT* TELL YOU
//   - What any OTHER app's WebView is configured to. It measures DEFAULTS, which
//     is the half that static analysis cannot see. For a specific app, run
//     ../../scripts/webview-audit.py on its APK and ../../scripts/trace-webview.js
//     against the running process.
//   - What the defaults are on a different WebView version. Record the version
//     the probe prints alongside every number you take from it.
//   - Anything about settings with no public getter. setSafeBrowsingEnabled has
//     one only from API 26; where a getter is missing the row prints "n/a"
//     rather than a guess.

package com.pentest.ch43.probe;

import android.app.Activity;
import android.os.Build;
import android.os.Bundle;
import android.util.Log;
import android.webkit.WebSettings;
import android.webkit.WebView;

public class ProbeActivity extends Activity {

    static final String TAG = "CH43PROBE";

    /**
     * The targetSdkVersion values to sweep. They are chosen around the API levels
     * where a WebView default is documented or rumoured to change: 16
     * (JELLY_BEAN, the file-URL origin flags), 21 (LOLLIPOP, mixed content), 26
     * (O, Safe Browsing), 30 (R, setAllowFileAccess). The rest are controls --
     * rows that should NOT differ from their neighbours, which is how you notice
     * when they do.
     */
    static final int[] TARGETS = {
        14, 15, 16, 17, 18, 19, 21, 23, 24, 26, 28, 29, 30, 31, 33, 34, 35
    };

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);

        Log.i(TAG, "BEGIN");
        Log.i(TAG, "device sdk_int=" + Build.VERSION.SDK_INT
                + " release=" + Build.VERSION.RELEASE);

        // The WebView version is NOT the OS version. WebView ships as a Mainline
        // module and updates through the Play Store, so a phone on Android 11 can
        // be running a Chromium from years later. Record both, always.
        try {
            android.content.pm.PackageInfo pi = WebView.getCurrentWebViewPackage();
            Log.i(TAG, "webview pkg=" + pi.packageName + " version=" + pi.versionName
                    + " code=" + pi.versionCode);
        } catch (Throwable t) {
            Log.i(TAG, "webview pkg lookup failed: " + t);
        }

        final int realTarget = getApplicationInfo().targetSdkVersion;
        Log.i(TAG, "manifest targetSdk=" + realTarget);
        Log.i(TAG, "HDR,targetSdk,js,fileAccess,fileFromFile,universalFromFile,contentAccess,"
                + "domStorage,mixedContent,database,safeBrowsing,jsOpenWindows,mediaGesture,"
                + "cacheMode,blockNetworkLoads,loadsImagesAutomatically");

        for (int t : TARGETS) {
            try {
                getApplicationInfo().targetSdkVersion = t;
                WebView w = new WebView(this);
                WebSettings s = w.getSettings();
                StringBuilder sb = new StringBuilder("ROW,");
                sb.append(t).append(',')
                  .append(s.getJavaScriptEnabled()).append(',')
                  .append(s.getAllowFileAccess()).append(',')
                  .append(s.getAllowFileAccessFromFileURLs()).append(',')
                  .append(s.getAllowUniversalAccessFromFileURLs()).append(',')
                  .append(s.getAllowContentAccess()).append(',')
                  .append(s.getDomStorageEnabled()).append(',')
                  .append(s.getMixedContentMode()).append(',')
                  .append(s.getDatabaseEnabled()).append(',')
                  .append(safeBrowsing(s)).append(',')
                  .append(s.getJavaScriptCanOpenWindowsAutomatically()).append(',')
                  .append(s.getMediaPlaybackRequiresUserGesture()).append(',')
                  .append(s.getCacheMode()).append(',')
                  .append(s.getBlockNetworkLoads()).append(',')
                  .append(s.getLoadsImagesAutomatically());
                Log.i(TAG, sb.toString());
                w.destroy();
            } catch (Throwable e) {
                Log.i(TAG, "ROW," + t + ",ERROR," + e);
            }
        }

        getApplicationInfo().targetSdkVersion = realTarget;

        // The user agent is not a setting, but it is a finding often enough to be
        // worth printing. Note the `wv` token, which identifies the request as
        // coming from a WebView rather than Chrome, and note the build
        // fingerprint, which is device-identifying and goes to every server the
        // WebView contacts.
        try {
            WebView w = new WebView(this);
            Log.i(TAG, "UA=" + w.getSettings().getUserAgentString());
            w.destroy();
        } catch (Throwable e) {
            Log.i(TAG, "UA lookup failed: " + e);
        }
        try {
            Log.i(TAG, "defaultUA=" + WebSettings.getDefaultUserAgent(this));
        } catch (Throwable e) {
            Log.i(TAG, "defaultUA lookup failed: " + e);
        }

        Log.i(TAG, "END");
        finish();
    }

    /** getSafeBrowsingEnabled exists only from API 26. Say "n/a", never guess. */
    static String safeBrowsing(WebSettings s) {
        try {
            return String.valueOf(s.getSafeBrowsingEnabled());
        } catch (Throwable t) {
            return "n/a";
        }
    }
}
