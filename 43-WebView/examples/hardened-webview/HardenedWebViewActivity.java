// examples/hardened-webview/HardenedWebViewActivity.java
//
// The counterpart to ../vulnerable-webview/VulnerableWebViewActivity.java. Same
// app, same feature -- render a remote page and let it talk to a little bit of
// app functionality -- with every defect fixed, and each fix annotated with the
// [Vn] tag it answers.
//
// The point of reading these two files side by side is that the hardened version
// is not longer, cleverer, or slower. It is the same code with different
// arguments and one method NOT overridden. Almost every WebView finding in the
// field is a default that was changed, or a callback that was written when it
// should have been left alone.
//
// Build with ../build.sh.

package com.pentest.ch43.safe;

import android.app.Activity;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;
import android.webkit.WebResourceRequest;
import android.webkit.WebResourceResponse;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.LinearLayout;
import android.widget.TextView;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

public class HardenedWebViewActivity extends Activity {

    static final String TAG = "CH43SAFE";

    /**
     * The only hosts this WebView is allowed to navigate to. An exact-match set
     * of HOSTS, not a substring list of URLs. Compare hosts; never compare URLs.
     */
    static final Set<String> ALLOWED_HOSTS = new HashSet<String>(Arrays.asList(
            "lab.example.com",
            "static.lab.example.com"));

    static final String DEFAULT_URL = "https://lab.example.com/start";

    private WebView web;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        TextView banner = new TextView(this);
        banner.setText("CH43 hardened WebView");
        root.addView(banner);

        web = new WebView(this);
        root.addView(web);
        setContentView(root);

        // [V10 fixed] Remote debugging only in a debuggable build.
        //
        // Reading FLAG_DEBUGGABLE off the live ApplicationInfo is better than
        // BuildConfig.DEBUG: it reflects what the installed APK actually declares,
        // so a release build cannot accidentally carry a debug constant. When this
        // is false, no @<process>_devtools_remote socket is created, and
        // `cat /proc/net/unix | grep devtools` on the device shows nothing.
        boolean debuggable =
                (getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0;
        WebView.setWebContentsDebuggingEnabled(debuggable);

        WebSettings s = web.getSettings();

        // [V1 kept] JavaScript stays on. This page needs it, and turning it off
        // is not the remediation for anything below -- it is a different product.
        // What makes it safe is that nothing attacker-controlled reaches the
        // WebView, and that there is no bridge for script to call.
        s.setJavaScriptEnabled(true);

        // [V3/V4/V5 fixed] Every file:// relaxation off, explicitly.
        //
        // setAllowFileAccess defaults to false only from targetSdk 30. Writing it
        // explicitly means the app keeps the safe value if somebody later lowers
        // targetSdkVersion -- which happens, and which silently re-enables it.
        // The other two default to false from targetSdk 16; write them anyway,
        // for the same reason and because they cost one line each.
        s.setAllowFileAccess(false);
        s.setAllowFileAccessFromFileURLs(false);
        s.setAllowUniversalAccessFromFileURLs(false);

        // [V6 fixed] content:// access OFF.
        //
        // This is the single most valuable line in the file, because it is the
        // one nobody writes. The default is TRUE at every targetSdkVersion
        // measured (14 through 35, WebView 150, Android 11 / API 30). Leaving it
        // alone means page script can fetch content:// URIs and every provider
        // this app can read answers as though the app asked.
        s.setAllowContentAccess(false);

        // [V7 fixed] No mixed content. This is also the default from targetSdk 21,
        // and is written explicitly for the same reason as the file flags.
        s.setMixedContentMode(WebSettings.MIXED_CONTENT_NEVER_ALLOW);

        // DOM storage is on because the app uses it. Note where it lands:
        // app_webview/Local Storage/ inside the private data directory, in plain
        // text. Do not put a token there.
        s.setDomStorageEnabled(true);

        // Safe Browsing is on by default; asserting it stops a future
        // <meta-data android:name="android.webkit.WebView.EnableSafeBrowsing"
        //            android:value="false"/> in the manifest from quietly winning.
        s.setSafeBrowsingEnabled(true);

        // [V2 fixed] NO BRIDGE.
        //
        // There is no addJavascriptInterface call in this file. If the product
        // genuinely needs page-to-app communication, the modern answer is
        // WebViewCompat.addWebMessageListener from androidx.webkit, which takes an
        // explicit allow-list of origins:
        //
        //     WebViewCompat.addWebMessageListener(
        //         web, "appBridge",
        //         new HashSet<>(Arrays.asList("https://lab.example.com")),
        //         listener);
        //
        // The origin allow-list is enforced by Chromium before the message
        // crosses, which is the guarantee addJavascriptInterface has never
        // offered: an addJavascriptInterface object is visible to EVERY document
        // the WebView loads, including third-party iframes and ad frames.

        web.setWebViewClient(new StrictWebViewClient());

        // [V11 fixed] The Intent is treated as a REQUEST, not as the answer.
        //
        // The Activity is still exported with a BROWSABLE filter -- deep links are
        // a feature. What changed is that the URL is validated before it is used,
        // and rejected to a safe default rather than loaded.
        String url = DEFAULT_URL;
        Intent intent = getIntent();
        if (intent != null && intent.getData() != null) {
            String requested = intent.getData().getQueryParameter("url");
            if (requested != null && isAllowed(Uri.parse(requested))) {
                url = requested;
            } else if (requested != null) {
                Log.w(TAG, "rejected deep-link URL: " + requested);
            }
        }
        web.loadUrl(url);
    }

    /**
     * [V9 fixed] Parse, then compare the HOST, exactly, case-folded, against a set.
     *
     * The four checks below each defeat a bypass that a String.contains() version
     * would have allowed:
     *
     *   scheme must be https   -- stops http://, file://, content://, javascript:,
     *                             data: and intent: from ever being considered
     *   userInfo must be empty -- stops https://lab.example.com&#64;attacker.invalid/
     *   host must be non-null  -- stops opaque URIs, which have no host at all
     *   exact set membership   -- stops lab.example.com.attacker.invalid and
     *                             ?x=lab.example.com
     */
    static boolean isAllowed(Uri uri) {
        if (uri == null) {
            return false;
        }
        String scheme = uri.getScheme();
        if (scheme == null || !scheme.equalsIgnoreCase("https")) {
            return false;
        }
        if (uri.getUserInfo() != null) {
            return false;
        }
        String host = uri.getHost();
        if (host == null) {
            return false;
        }
        return ALLOWED_HOSTS.contains(host.toLowerCase(Locale.ROOT));
    }

    class StrictWebViewClient extends WebViewClient {

        // [V8 fixed] onReceivedSslError IS NOT OVERRIDDEN.
        //
        // That absence is the fix, and it is worth saying out loud because a
        // reviewer scanning for a fix will not see one. The base implementation
        // in android.webkit.WebViewClient calls handler.cancel() and the load
        // fails, which is exactly right: a certificate error means nobody the
        // device trusts vouched for this server.
        //
        // If you are tempted to override it "just to show a nicer error", note
        // that you can do that in onReceivedError, and that every real-world
        // override this repository has measured either proceeds unconditionally
        // or branches on something that is not the certificate.
        //
        // The one legitimate reason to override it is to pin: compare
        // error.getCertificate() against a certificate you shipped and proceed
        // only on an exact match. That is chapter 36's subject
        // (../../../36-CertificatePinning/README.md), it is easy to get wrong,
        // and it is not what most overrides in the wild are doing.

        /**
         * The navigation gate. Everything off the allow-list is refused; nothing
         * is handed to an external browser implicitly, because
         * `startActivity(new Intent(ACTION_VIEW, uri))` on an unvalidated URI is
         * how a WebView finding turns into an Intent finding.
         */
        @Override
        public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
            Uri uri = request.getUrl();
            if (isAllowed(uri)) {
                return false;       // false = not handled here, let the WebView load it
            }
            Log.w(TAG, "blocked navigation: " + uri);
            return true;            // true  = handled (by refusing), do not load
        }

        /**
         * A second, independent gate that catches SUBRESOURCES.
         *
         * shouldOverrideUrlLoading only sees top-level navigations. Images,
         * scripts, XHR and iframe loads never reach it. Returning an empty
         * response here refuses them.
         *
         * This runs on a Chromium background thread, not the UI thread, and it
         * runs for every single resource -- keep it cheap and keep it free of
         * app state that is not thread-safe.
         */
        @Override
        public WebResourceResponse shouldInterceptRequest(WebView view,
                                                          WebResourceRequest request) {
            Uri uri = request.getUrl();
            if (isAllowed(uri)) {
                return null;        // null = "I am not intercepting, fetch normally"
            }
            Log.w(TAG, "blocked subresource: " + uri);
            return new WebResourceResponse("text/plain", "utf-8", null);
        }
    }
}
