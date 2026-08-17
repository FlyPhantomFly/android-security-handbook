/*
 * detect-webview-oauth.js — decide, in one run, whether an app performs its OAuth flow inside an
 * embedded WebView (a finding) or in an external user agent such as a Custom Tab (correct).
 *
 * WHAT IT DOES
 *   Watches both sides of the question at once:
 *     - Every WebView navigation whose URL looks like an authorisation endpoint.
 *     - Every Custom Tab / ACTION_VIEW launch, so you can see the correct pattern when it happens.
 *   When it catches a WebView flow it also instruments the capabilities that make it dangerous, so
 *   the report contains a demonstration rather than an assertion:
 *     - WebSettings.setJavaScriptEnabled / addJavascriptInterface
 *     - WebView.evaluateJavascript  (this is how a hosting app reads the password field)
 *     - WebViewClient.shouldInterceptRequest / shouldOverrideUrlLoading
 *     - CookieManager.getCookie  (this is how a hosting app reads the IdP session)
 *   Each hit prints a Java stack trace so you can name WHICH class opened the WebView even when the
 *   app is obfuscated and the class is called `a.b.c`.
 *
 * WHY IT IS A FINDING
 *   A WebView is a view inside the app's own process. The app can read the DOM including the
 *   password field, read every request body, read the identity provider's session cookie, and
 *   inject JavaScript into the IdP's origin. The user sees no address bar, so a pixel-perfect fake
 *   login page is indistinguishable from the real one. RFC 8252 s8.12 prohibits embedded user
 *   agents for exactly these reasons.
 *
 *   The finding is NOT "the app stole the password". The finding is that the architecture places
 *   the user's identity-provider credential inside the trust boundary of the client, defeating the
 *   purpose of federated authentication and making credential theft undetectable.
 *
 * USAGE
 *   host $ frida -U -f com.example.target -l detect-webview-oauth.js
 *   host $ frida -U -n com.example.target -l detect-webview-oauth.js
 *
 *   Then perform a login. The verdict prints as it happens; type verdict() in the REPL for a
 *   summary at any time.
 *
 * SAFETY
 *   Read-only. It observes and prints. It never harvests a credential; the point is to demonstrate
 *   that the app COULD, not to do it.
 *
 * Chapter 45 — OAuth 2.0 and OpenID Connect on Android, section 3.9
 */

'use strict';

var AUTH_URL_RE = /authorize|oauth|openid|\/auth\?|connect\/authorize|signin|\/sso\b|login\?/i;

var state = {
    webviewAuthUrls: [],
    externalAuthUrls: [],
    dangerousCalls: [],
    jsEnabled: false,
    jsInterfaces: []
};

function line(ch) { return new Array(79).join(ch || '-'); }

function banner(t) { console.log('\n' + line('=') + '\n  ' + t + '\n' + line('=')); }

function stackTrace(limit) {
    try {
        var Log = Java.use('android.util.Log');
        var Exception = Java.use('java.lang.Exception');
        return Log.getStackTraceString(Exception.$new())
            .split('\n')
            .filter(function (l) {
                // Drop the Frida and reflection frames that are never interesting.
                return !/frida|com\.android\.internal\.os|java\.lang\.reflect|dalvik\.system/i.test(l);
            })
            .slice(1, (limit || 10) + 1)
            .map(function (l) { return '      ' + l.trim(); })
            .join('\n');
    } catch (e) {
        return '      <stack unavailable>';
    }
}

function verdict() {
    banner('VERDICT');

    if (state.webviewAuthUrls.length > 0) {
        console.log('  RESULT: EMBEDDED USER AGENT (WebView) — this is a FINDING.\n');
        console.log('  Authorisation URLs observed inside a WebView:');
        state.webviewAuthUrls.forEach(function (u) { console.log('    - ' + u); });

        console.log('\n  Dangerous capabilities exercised on that WebView:');
        if (state.dangerousCalls.length === 0) {
            console.log('    (none observed — but availability is the finding, not use)');
        } else {
            state.dangerousCalls.forEach(function (d) { console.log('    - ' + d); });
        }
        console.log('\n  JavaScript enabled : ' + state.jsEnabled);
        if (state.jsInterfaces.length) {
            console.log('  JS bridges exposed : ' + state.jsInterfaces.join(', '));
            console.log('    -> a JS bridge on a page you do not control is a second, separate');
            console.log('       finding. See chapter 43-WebView.');
        }

        console.log('\n  REPORT TEXT:');
        console.log('    The application renders the identity provider\'s authentication page');
        console.log('    inside an embedded WebView that it owns. This places the user\'s');
        console.log('    identity-provider credential inside the trust boundary of the client,');
        console.log('    defeating the purpose of federated authentication and making credential');
        console.log('    theft undetectable. The user is additionally shown no address bar and');
        console.log('    therefore cannot distinguish the genuine login page from a replica.');
        console.log('    RFC 8252 section 8.12 prohibits embedded user agents.');
        console.log('\n    Remediation: use androidx.browser CustomTabsIntent, or AppAuth-Android,');
        console.log('    which refuses to run the flow in a WebView at all.');
    } else if (state.externalAuthUrls.length > 0) {
        console.log('  RESULT: EXTERNAL USER AGENT — correct pattern.\n');
        console.log('  Authorisation URLs handed to an external browser:');
        state.externalAuthUrls.forEach(function (u) { console.log('    - ' + u); });
        console.log('\n  The login page renders in the browser\'s process, under the browser\'s');
        console.log('  UID, with the browser\'s cookie jar. The app sandbox prevents this app');
        console.log('  from reading the DOM, the cookies or the typed password.');
        console.log('\n  Still to check: is the REDIRECT a verified App Link, and does the server');
        console.log('  enforce PKCE? Neither is visible from here. See labs 02 and 03.');
    } else {
        console.log('  No authorisation URL observed yet. Perform a login.');
        console.log('  If a login completed and nothing appeared, the flow may run in native code');
        console.log('  or in a cross-platform runtime (Flutter, React Native, Unity). Check');
        console.log('  libflutter.so / index.android.bundle / the assemblies. See section 6.5.');
    }
    console.log(line('=') + '\n');
}

rpc.exports = { verdict: verdict };
global.verdict = verdict;

Java.perform(function () {

    banner('WebView-vs-CustomTab OAuth detector — chapter 45 section 3.9');
    console.log('  Perform a login now. Type verdict() at any time.');

    // -----------------------------------------------------------------------
    // The finding: an authorisation URL loaded into a WebView.
    // -----------------------------------------------------------------------
    var WebView = Java.use('android.webkit.WebView');

    function flagWebViewNavigation(url, how) {
        if (!AUTH_URL_RE.test(url)) return;
        if (state.webviewAuthUrls.indexOf(url) === -1) state.webviewAuthUrls.push(url);
        banner('!! OAUTH FLOW INSIDE A WEBVIEW — FINDING  (' + how + ')');
        console.log('  ' + url);
        console.log('\n  called from:\n' + stackTrace(12));
        console.log('\n  The hosting app can now read the password field with five lines of code.');
    }

    WebView.loadUrl.overload('java.lang.String').implementation = function (url) {
        flagWebViewNavigation(url, 'loadUrl');
        return this.loadUrl(url);
    };
    WebView.loadUrl.overload('java.lang.String', 'java.util.Map').implementation =
        function (url, headers) {
            flagWebViewNavigation(url, 'loadUrl+headers');
            if (AUTH_URL_RE.test(url)) console.log('  headers: ' + headers);
            return this.loadUrl(url, headers);
        };
    try {
        WebView.postUrl.implementation = function (url, data) {
            flagWebViewNavigation(url, 'postUrl');
            return this.postUrl(url, data);
        };
    } catch (e) { /* ignore */ }
    try {
        WebView.loadDataWithBaseURL.implementation = function (base, data, mime, enc, hist) {
            if (base !== null && AUTH_URL_RE.test(base)) {
                flagWebViewNavigation(base, 'loadDataWithBaseURL');
            }
            return this.loadDataWithBaseURL(base, data, mime, enc, hist);
        };
    } catch (e) { /* ignore */ }

    // -----------------------------------------------------------------------
    // The correct pattern: an authorisation URL handed to an external browser.
    // Custom Tabs are launched as an ACTION_VIEW Intent with Custom Tab extras.
    // -----------------------------------------------------------------------
    function flagExternal(intent, how) {
        try {
            var d = intent.getData();
            if (d === null) return;
            var url = d.toString();
            if (!AUTH_URL_RE.test(url)) return;
            if (state.externalAuthUrls.indexOf(url) === -1) state.externalAuthUrls.push(url);

            var isCustomTab = false;
            try {
                isCustomTab = intent.hasExtra('android.support.customtabs.extra.SESSION') ||
                              intent.hasExtra('androidx.browser.customtabs.extra.SESSION');
            } catch (e) { /* ignore */ }

            banner('EXTERNAL USER AGENT — correct  (' +
                   (isCustomTab ? 'Custom Tab' : 'ACTION_VIEW to browser') + ', ' + how + ')');
            console.log('  ' + url);
            console.log('\n  The login page will render in the browser process, not this one.');
            console.log('  called from:\n' + stackTrace(8));
        } catch (e) { /* not every Intent has data */ }
    }

    var Activity = Java.use('android.app.Activity');
    Activity.startActivity.overload('android.content.Intent').implementation = function (i) {
        flagExternal(i, 'Activity.startActivity');
        return this.startActivity(i);
    };
    Activity.startActivity.overload('android.content.Intent', 'android.os.Bundle')
        .implementation = function (i, b) {
            flagExternal(i, 'Activity.startActivity+Bundle');
            return this.startActivity(i, b);
        };

    try {
        var CustomTabsIntent = Java.use('androidx.browser.customtabs.CustomTabsIntent');
        CustomTabsIntent.launchUrl.implementation = function (ctx, uri) {
            if (AUTH_URL_RE.test(uri.toString())) {
                if (state.externalAuthUrls.indexOf(uri.toString()) === -1) {
                    state.externalAuthUrls.push(uri.toString());
                }
                banner('EXTERNAL USER AGENT — Custom Tab (CustomTabsIntent.launchUrl)');
                console.log('  ' + uri.toString());
            }
            return this.launchUrl(ctx, uri);
        };
        console.log('[+] androidx CustomTabsIntent hooked');
    } catch (e) { /* androidx.browser not bundled */ }

    // -----------------------------------------------------------------------
    // The capabilities that make an embedded flow dangerous. Availability is the
    // finding; observing actual use turns it into a demonstration.
    // -----------------------------------------------------------------------
    try {
        var WebSettings = Java.use('android.webkit.WebSettings');
        WebSettings.setJavaScriptEnabled.implementation = function (enabled) {
            if (enabled) {
                state.jsEnabled = true;
                console.log('\n[capability] WebSettings.setJavaScriptEnabled(true)');
                console.log(stackTrace(6));
            }
            return this.setJavaScriptEnabled(enabled);
        };
    } catch (e) { /* ignore */ }

    try {
        WebView.addJavascriptInterface.implementation = function (obj, name) {
            state.jsInterfaces.push(name);
            console.log('\n[capability] addJavascriptInterface("' + name + '") -> ' +
                        obj.$className);
            console.log('  A JS bridge exposed to a page the app does not control is a separate');
            console.log('  finding. See chapter 43-WebView.');
            console.log(stackTrace(6));
            return this.addJavascriptInterface(obj, name);
        };
    } catch (e) { /* ignore */ }

    try {
        WebView.evaluateJavascript.implementation = function (script, cb) {
            var snippet = String(script).substring(0, 200).replace(/\s+/g, ' ');
            var suspicious = /password|input\[|document\.|value|cookie|form/i.test(snippet);
            var msg = 'evaluateJavascript: ' + snippet;
            if (suspicious) {
                state.dangerousCalls.push(msg);
                console.log('\n[!! capability USED] ' + msg);
                console.log('  This is the mechanism by which a hosting app reads a password field.');
                console.log(stackTrace(8));
            }
            return this.evaluateJavascript(script, cb);
        };
    } catch (e) { /* ignore */ }

    try {
        var CookieManager = Java.use('android.webkit.CookieManager');
        CookieManager.getCookie.implementation = function (url) {
            var cookie = this.getCookie(url);
            if (AUTH_URL_RE.test(String(url))) {
                var msg = 'CookieManager.getCookie("' + url + '")';
                state.dangerousCalls.push(msg);
                console.log('\n[!! capability USED] ' + msg);
                console.log('  The app is reading the identity provider\'s session cookie.');
                console.log(stackTrace(8));
            }
            return cookie;
        };
    } catch (e) { /* ignore */ }

    // WebViewClient callbacks are implemented by app subclasses, so hook the base class
    // and let the dispatcher catch overrides via Java.enumerateLoadedClasses if needed.
    try {
        var WebViewClient = Java.use('android.webkit.WebViewClient');
        WebViewClient.shouldOverrideUrlLoading.overload(
            'android.webkit.WebView', 'java.lang.String').implementation = function (v, url) {
                if (/[?&#](code|access_token|id_token|error)=/.test(url)) {
                    console.log('\n[!! REDIRECT CAUGHT IN WEBVIEW] ' + url);
                    console.log('  The app is reading the authorisation code out of a navigation');
                    console.log('  it fully controls. Nothing here is protected from the app.');
                    state.dangerousCalls.push('shouldOverrideUrlLoading saw the callback: ' + url);
                }
                return this.shouldOverrideUrlLoading(v, url);
            };
    } catch (e) { /* subclass may override without calling super */ }

    // Catch app subclasses of WebViewClient that never call super.
    Java.enumerateLoadedClasses({
        onMatch: function (name) {
            if (!/WebViewClient$|WebClient$|AuthWebView/i.test(name)) return;
            if (name.indexOf('android.webkit') === 0) return;
            try {
                var Klass = Java.use(name);
                if (Klass.shouldInterceptRequest) {
                    Klass.shouldInterceptRequest.overloads.forEach(function (ov) {
                        ov.implementation = function () {
                            var req = arguments[1];
                            try {
                                var u = req.getUrl ? req.getUrl().toString() : String(req);
                                if (AUTH_URL_RE.test(u) || /[?&#]code=/.test(u)) {
                                    console.log('\n[!! capability USED] ' + name +
                                        '.shouldInterceptRequest -> ' + u);
                                    console.log('  Every request the login page makes, including');
                                    console.log('  the credential POST, passes through app code.');
                                    state.dangerousCalls.push(
                                        name + '.shouldInterceptRequest saw ' + u);
                                }
                            } catch (e) { /* ignore */ }
                            return ov.apply(this, arguments);
                        };
                    });
                    console.log('[+] hooked ' + name + '.shouldInterceptRequest');
                }
            } catch (e) { /* not hookable */ }
        },
        onComplete: function () { }
    });

    console.log('\n[+] Hooks installed. Perform the login, then type verdict().\n');
});
