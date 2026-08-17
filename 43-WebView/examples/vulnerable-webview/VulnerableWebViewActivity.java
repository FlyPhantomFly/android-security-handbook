// examples/vulnerable-webview/VulnerableWebViewActivity.java
//
// A DELIBERATELY VULNERABLE WebView host. Build it with ../build.sh and install
// it on a device you own. Do not ship anything resembling this.
//
// Every defect below is one that appears in real, shipped apps. Each is marked
// with a [Vn] tag; ../README.md and ../../README.md section 9 explain them, and
// the hardened counterpart in ../hardened-webview/ fixes them one for one.
//
//   [V1]  javaScriptEnabled(true) with attacker-reachable content
//   [V2]  addJavascriptInterface -- a Java bridge exposed to page script
//   [V3]  allowFileAccess(true) re-enabled after the API 30 default flipped
//   [V4]  allowFileAccessFromFileURLs(true)
//   [V5]  allowUniversalAccessFromFileURLs(true)
//   [V6]  allowContentAccess left at its default (true) with JS on
//   [V7]  setMixedContentMode(MIXED_CONTENT_ALWAYS_ALLOW)
//   [V8]  onReceivedSslError -> handler.proceed()   <-- the one no XML can stop
//   [V9]  shouldOverrideUrlLoading allow-list written with String.contains()
//   [V10] setWebContentsDebuggingEnabled(true) unconditionally
//   [V11] the URL comes straight from an exported BROWSABLE Intent
//
// The Activity seeds a fake session token into its private data directory on
// first run, so the file-read and bridge-read demonstrations have something real
// to steal. Nothing here touches anything outside the app's own sandbox.

package com.pentest.ch43.vuln;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.net.http.SslError;
import android.os.Bundle;
import android.util.Log;
import android.webkit.SslErrorHandler;
import android.webkit.WebResourceRequest;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.LinearLayout;
import android.widget.TextView;

import java.io.File;
import java.io.FileOutputStream;

public class VulnerableWebViewActivity extends Activity {

    static final String TAG = "CH43VULN";

    /** Where the fake secret lives. The bridge and the file:// tricks both target it. */
    static final String SECRET_FILE = "session.txt";

    /** The page loaded when no URL is supplied. Ships in assets/. */
    static final String DEFAULT_URL = "file:///android_asset/home.html";

    private WebView web;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        seedSecret();

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        TextView banner = new TextView(this);
        banner.setText("CH43 vulnerable WebView -- lab app, do not ship");
        root.addView(banner);

        web = new WebView(this);
        root.addView(web);
        setContentView(root);

        // [V10] Remote debugging, unconditionally, in every build.
        //
        // This opens an abstract-namespace unix socket called
        // @com.pentest.ch43.vuln_devtools_remote. Abstract sockets have no
        // filesystem path and therefore no filesystem permissions: any process
        // that can reach the abstract namespace can attach a complete DevTools
        // session to this WebView -- read the DOM, evaluate script in the page,
        // and through that call every bridge method below.
        //
        // The correct form of this line is:
        //     if ((getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0)
        //         WebView.setWebContentsDebuggingEnabled(true);
        // See ../hardened-webview/HardenedWebViewActivity.java.
        WebView.setWebContentsDebuggingEnabled(true);

        WebSettings s = web.getSettings();

        // [V1] Script execution. On its own this is not a finding -- almost every
        // useful WebView needs it. It is the precondition that turns each of the
        // lines below into one.
        s.setJavaScriptEnabled(true);

        // [V3] file:// loading. The measured default at targetSdk 30 and above is
        // FALSE (see ../../README.md section 3.4). Setting it back to true is a
        // deliberate act, and it is the gate that [V4] and [V5] depend on.
        s.setAllowFileAccess(true);

        // [V4] A file:// document may XmlHttpRequest other file:// URLs. That
        // includes /data/data/com.pentest.ch43.vuln/files/session.txt.
        s.setAllowFileAccessFromFileURLs(true);

        // [V5] A file:// document may read ANY origin: https:// sites (with this
        // app's cookies), and content:// providers. This is the same-origin policy
        // switched off for local documents. It is the single worst WebSettings
        // value in this file.
        s.setAllowUniversalAccessFromFileURLs(true);

        // [V6] content:// access. Note what is NOT here: no call at all. The
        // measured default is TRUE at every targetSdkVersion from 14 to 35, so the
        // dangerous configuration is the one nobody wrote. Script in this WebView
        // can fetch content:// URIs, and the provider on the other end sees the
        // request as coming from this app.
        //   s.setAllowContentAccess(false);   <-- absent, on purpose

        // [V7] http:// subresources are permitted inside an https:// page. A
        // network attacker who can inject one <script src="http://..."> gets code
        // execution in the https origin. Chapter 44 governs whether the http
        // request is allowed to leave the device at all; this setting governs
        // whether Chromium is willing to mix the two in one document.
        s.setMixedContentMode(WebSettings.MIXED_CONTENT_ALWAYS_ALLOW);

        s.setDomStorageEnabled(true);

        // [V2] The bridge. Every method on LeakyBridge annotated
        // @JavascriptInterface becomes callable from page script as
        // AndroidBridge.name(). The annotation is REQUIRED from API 17 and it
        // narrows the exposed surface to the methods the developer marked -- it
        // does not make those methods safe. The risk is the bridge, not the
        // annotation.
        web.addJavascriptInterface(new LeakyBridge(this), "AndroidBridge");

        web.setWebViewClient(new SloppyWebViewClient());

        // [V11] The URL comes from an Intent this app exports with a BROWSABLE
        // filter, so any web page, any app, and `adb shell am start` can choose
        // what this WebView loads. Chapter 26 owns how the Intent gets here;
        // chapter 30 owns the Activity that receives it. This chapter owns what
        // happens next, which is everything above.
        String url = DEFAULT_URL;
        Intent intent = getIntent();
        if (intent != null && intent.getData() != null) {
            Uri data = intent.getData();
            String requested = data.getQueryParameter("url");
            if (requested != null) {
                url = requested;
            } else if (data.getScheme() != null
                    && (data.getScheme().equals("http") || data.getScheme().equals("https"))) {
                url = data.toString();
            }
        }
        Log.i(TAG, "loading " + url);
        web.loadUrl(url);
    }

    /** Write a plausible-looking secret so the exfiltration demos have a target. */
    private void seedSecret() {
        try {
            File f = new File(getFilesDir(), SECRET_FILE);
            if (!f.exists()) {
                FileOutputStream out = new FileOutputStream(f);
                out.write(("{\"user\":\"lab@example.invalid\","
                        + "\"session\":\"CH43{bridge_is_the_bug_not_the_annotation}\","
                        + "\"issued\":\"lab\"}").getBytes("UTF-8"));
                out.close();
            }
            Log.i(TAG, "secret at " + f.getAbsolutePath());
        } catch (Exception e) {
            Log.w(TAG, "could not seed secret: " + e);
        }
    }

    /**
     * The WebViewClient. Two defects, both extremely common.
     */
    class SloppyWebViewClient extends WebViewClient {

        /**
         * [V8] THE defect of this chapter.
         *
         * onReceivedSslError is called when Chromium's own chain validation
         * fails: expired certificate, wrong hostname, unknown issuer, anything.
         * The framework hands the app an SslErrorHandler and waits. Calling
         * proceed() tells Chromium to load the page anyway.
         *
         * Nothing in res/xml/network_security_config.xml can prevent this. Not
         * `cleartextTrafficPermitted="false"`, not a <pin-set>, not removing the
         * user trust anchor. The configuration file describes which certificates
         * are TRUSTED; this method describes what happens when NONE of them
         * vouched for the server, and the answer here is "load it anyway".
         *
         * The result is a WebView that accepts any certificate from any host --
         * which is to say, no transport security at all, in a widget that will
         * happily run the attacker's JavaScript and call every bridge method
         * above.
         *
         * The correct implementation is to not override this method. The default
         * cancels. See ../hardened-webview/HardenedWebViewActivity.java.
         */
        @Override
        public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error) {
            Log.w(TAG, "SSL error ignored: primaryError=" + error.getPrimaryError()
                    + " url=" + error.getUrl());
            handler.proceed();
        }

        /**
         * [V9] A navigation allow-list written with String.contains().
         *
         * The intent is "only load our own domain". What it actually permits:
         *
         *   https://lab.example.com.attacker.invalid/   -- the string appears in
         *                                                 a hostname the attacker
         *                                                 controls
         *   https://attacker.invalid/?x=lab.example.com -- the string appears in
         *                                                 the query
         *   https://lab.example.com@attacker.invalid/   -- userinfo; the host is
         *                                                 attacker.invalid
         *
         * Parse the URI and compare the HOST, exactly, against a set. Never
         * substring-match a URL.
         */
        @Override
        public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
            String url = request.getUrl().toString();
            if (url.contains("lab.example.com")) {
                return false;           // false = "I did not handle it, load it"
            }
            Log.i(TAG, "navigation allowed anyway: " + url);
            return false;               // and everything else loads too
        }
    }
}
