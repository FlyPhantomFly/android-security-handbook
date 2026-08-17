/*
 * oauth-flow-tracer.js — capture an entire Android OAuth 2.0 / OIDC flow from inside the app.
 *
 * WHAT IT DOES
 *   Hooks every layer an Android app can use to run an OAuth flow and prints, in order:
 *     1. The authorisation request URL leaving the app (Intent, Custom Tab, or WebView).
 *     2. The redirect/callback arriving back (Intent data, or a WebView navigation).
 *     3. The token exchange request and response (OkHttp 3.x/4.x, HttpURLConnection, Volley).
 *     4. AppAuth internals, which hand you the code_verifier directly.
 *     5. The PKCE primitives (SecureRandom + SHA-256) for hand-rolled implementations.
 *   At the end of each flow it prints a summary block with a ready-to-paste `curl` command for the
 *   PKCE ENFORCEMENT test described in chapter 45 section 7.5 — the only test that matters.
 *
 * USAGE
 *   host $ frida -U -f com.example.target -l oauth-flow-tracer.js
 *   host $ frida -U -n com.example.target -l oauth-flow-tracer.js        # attach to a running app
 *   host $ frida -U -f com.example.target -l oauth-flow-tracer.js -o flow.log
 *
 * OPTIONS  (edit CONFIG below)
 *   verbose      print every HTTP request, not just OAuth-looking ones
 *   dumpBodies   print request/response bodies
 *   stacks       print a Java stack trace for each event (find WHICH class opened the WebView)
 *
 * REQUIREMENTS
 *   frida-server running on the device, matching your frida-tools version.
 *
 * SAFETY
 *   Read-only. It observes and prints; it never modifies a request. Run it only against apps and
 *   accounts you are authorised to test — the output contains live credentials.
 *
 * Chapter 45 — OAuth 2.0 and OpenID Connect on Android
 */

'use strict';

// ---------------------------------------------------------------------------
// CONFIG
// ---------------------------------------------------------------------------
var CONFIG = {
    verbose: false,      // print all HTTP traffic, not just OAuth-looking URLs
    dumpBodies: true,    // print request and response bodies
    stacks: false        // print a Java stack trace for each event
};

var OAUTH_URL_RE = /authorize|oauth|openid|\/token|\/auth\?|connect\/|signin|sso|\/par\b/i;
var CALLBACK_RE = /[?&#](code|access_token|id_token|error)=/;

// Collected state for the summary block.
var flow = {
    authorizeUrl: null,
    codeChallenge: null,
    challengeMethod: null,
    state: null,
    nonce: null,
    clientId: null,
    redirectUri: null,
    scope: null,
    code: null,
    codeVerifier: null,
    tokenEndpoint: null,
    usedWebView: false
};

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------
function line(ch) { return new Array(79).join(ch || '-'); }

function banner(title) {
    console.log('\n' + line('=') + '\n  ' + title + '\n' + line('='));
}

function stack() {
    if (!CONFIG.stacks) return;
    try {
        var Log = Java.use('android.util.Log');
        var Exception = Java.use('java.lang.Exception');
        console.log('  stack:\n' + Log.getStackTraceString(Exception.$new())
            .split('\n').slice(0, 12).map(function (l) { return '    ' + l; }).join('\n'));
    } catch (e) { /* ignore */ }
}

/* Parse a query string (or fragment) into a plain object, URL-decoding values. */
function parseParams(url) {
    var out = {};
    var qs = '';
    var qi = url.indexOf('?');
    var fi = url.indexOf('#');
    if (qi >= 0) qs = url.substring(qi + 1);
    if (fi >= 0) qs = (qs ? qs + '&' : '') + url.substring(fi + 1);
    if (!qs) return out;
    qs.split('&').forEach(function (pair) {
        if (!pair) return;
        var eq = pair.indexOf('=');
        var k = eq < 0 ? pair : pair.substring(0, eq);
        var v = eq < 0 ? '' : pair.substring(eq + 1);
        try { v = decodeURIComponent(v.replace(/\+/g, ' ')); } catch (e) { /* keep raw */ }
        out[k] = v;
    });
    return out;
}

/* Parse an application/x-www-form-urlencoded body the same way. */
function parseForm(body) {
    return parseParams('?' + body);
}

function printParams(params, indent) {
    indent = indent || '  ';
    Object.keys(params).forEach(function (k) {
        var v = params[k];
        var flagText = '';
        if (k === 'code_challenge_method' && v.toLowerCase() === 'plain') {
            flagText = '   <-- WARNING: plain is a downgrade, see section 3.3';
        }
        if (k === 'response_type' && /token/.test(v)) {
            flagText = '   <-- WARNING: implicit grant';
        }
        if (k === 'grant_type' && v === 'password') {
            flagText = '   <-- WARNING: ROPC grant';
        }
        if (k === 'client_secret') {
            flagText = '   <-- WARNING: client secret from a mobile app';
        }
        console.log(indent + pad(k, 24) + ' = ' + v + flagText);
    });
}

function pad(s, n) {
    s = String(s);
    while (s.length < n) s += ' ';
    return s;
}

/* Record anything interesting we see so the summary can be built. */
function absorbAuthorize(url) {
    flow.authorizeUrl = url;
    var p = parseParams(url);
    flow.codeChallenge = p.code_challenge || flow.codeChallenge;
    flow.challengeMethod = p.code_challenge_method || flow.challengeMethod;
    flow.state = p.state || flow.state;
    flow.nonce = p.nonce || flow.nonce;
    flow.clientId = p.client_id || flow.clientId;
    flow.redirectUri = p.redirect_uri || flow.redirectUri;
    flow.scope = p.scope || flow.scope;
    return p;
}

function absorbCallback(url) {
    var p = parseParams(url);
    if (p.code) flow.code = p.code;
    return p;
}

function absorbTokenRequest(url, body) {
    flow.tokenEndpoint = url;
    var p = parseForm(body || '');
    if (p.code) flow.code = p.code;
    if (p.code_verifier) flow.codeVerifier = p.code_verifier;
    if (p.client_id) flow.clientId = p.client_id;
    if (p.redirect_uri) flow.redirectUri = p.redirect_uri;
    return p;
}

/* Print the actionable summary — the whole reason to run this script. */
function printSummary() {
    banner('FLOW SUMMARY');

    var checks = [
        ['state present', !!flow.state,
            flow.state ? ('yes (' + flow.state.length + ' chars)') : 'NO  <-- FINDING: CSRF exposure'],
        ['PKCE challenge sent', !!flow.codeChallenge,
            flow.codeChallenge ? 'yes' : 'NO  <-- client does not implement PKCE'],
        ['challenge method', flow.challengeMethod === 'S256',
            flow.challengeMethod || 'absent'],
        ['nonce present (OIDC)', !!flow.nonce, flow.nonce ? 'yes' : 'no'],
        ['redirect is https', /^https:/i.test(flow.redirectUri || ''),
            flow.redirectUri || 'unknown'],
        ['WebView used for flow', !flow.usedWebView,
            flow.usedWebView ? 'YES <-- FINDING: embedded user agent, RFC 8252 s8.12' : 'no']
    ];

    checks.forEach(function (c) {
        console.log('  ' + (c[1] ? '[ok]  ' : '[!!]  ') + pad(c[0], 24) + ' : ' + c[2]);
    });

    if (flow.scope) {
        console.log('\n  scopes requested: ' + flow.scope);
        console.log('  -> build a scope-to-feature table; unexplained rows are findings.');
    }

    if (flow.code && flow.codeVerifier && flow.tokenEndpoint) {
        console.log('\n' + line('-'));
        console.log('  PKCE ENFORCEMENT TEST (chapter 45 section 7.5)');
        console.log('  Each variant needs a FRESH code. Run A first as the control.');
        console.log(line('-'));
        var base = "curl -s -w '\\nHTTP %{http_code}\\n' -X POST '" + flow.tokenEndpoint + "' \\\n" +
                   "  -d grant_type=authorization_code \\\n" +
                   "  -d code='" + flow.code + "' \\\n" +
                   "  -d redirect_uri='" + (flow.redirectUri || '') + "' \\\n" +
                   "  -d client_id='" + (flow.clientId || '') + "'";
        console.log('\n# A - control, MUST succeed');
        console.log(base + " \\\n  -d code_verifier='" + flow.codeVerifier + "'");
        console.log('\n# B - verifier omitted, MUST return 400 invalid_grant');
        console.log(base);
        console.log('\n# C - verifier wrong, MUST return 400 invalid_grant');
        console.log(base + " \\\n  -d code_verifier='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'");
        console.log('\n  If B or C returns tokens: CRITICAL. PKCE is not enforced.');
    } else {
        console.log('\n  (No complete code + verifier + endpoint captured yet.)');
    }
    console.log(line('=') + '\n');
}

// Expose to the Frida REPL: type `summary()` at any time.
rpc.exports = { summary: printSummary };
global.summary = printSummary;

// ---------------------------------------------------------------------------
// Hooks
// ---------------------------------------------------------------------------
Java.perform(function () {

    banner('OAuth flow tracer active - chapter 45');
    console.log('  Type summary() in the Frida REPL at any time for the enforcement test.');

    // -----------------------------------------------------------------------
    // 1) The authorisation request leaving the app via an Intent.
    //    Covers Custom Tabs (CustomTabsIntent calls startActivity with an ACTION_VIEW Intent)
    //    and plain ACTION_VIEW to the browser.
    // -----------------------------------------------------------------------
    var Activity = Java.use('android.app.Activity');
    var Context = Java.use('android.content.ContextWrapper');

    function inspectOutgoingIntent(intent, source) {
        try {
            var d = intent.getData();
            if (d === null) return;
            var url = d.toString();
            if (!OAUTH_URL_RE.test(url)) return;
            banner('AUTHORIZATION REQUEST  (' + source + ')');
            console.log('  ' + url + '\n');
            printParams(absorbAuthorize(url));
            stack();
        } catch (e) { /* not every Intent has data */ }
    }

    Activity.startActivity.overload('android.content.Intent').implementation = function (i) {
        inspectOutgoingIntent(i, 'Activity.startActivity');
        return this.startActivity(i);
    };
    Activity.startActivity.overload('android.content.Intent', 'android.os.Bundle')
        .implementation = function (i, b) {
            inspectOutgoingIntent(i, 'Activity.startActivity+Bundle');
            return this.startActivity(i, b);
        };
    try {
        Context.startActivity.overload('android.content.Intent').implementation = function (i) {
            inspectOutgoingIntent(i, 'Context.startActivity');
            return this.startActivity(i);
        };
    } catch (e) { /* overload may not exist on all API levels */ }

    // -----------------------------------------------------------------------
    // 2) The callback arriving back into the app.
    // -----------------------------------------------------------------------
    Activity.getIntent.implementation = function () {
        var i = this.getIntent();
        try {
            var d = i.getData();
            if (d !== null) {
                var url = d.toString();
                if (CALLBACK_RE.test(url)) {
                    banner('CALLBACK RECEIVED  (' + this.getClass().getName() + ')');
                    console.log('  ' + url + '\n');
                    var p = absorbCallback(url);
                    printParams(p);
                    if (flow.state && p.state && p.state !== flow.state) {
                        console.log('\n  [!!] returned state does NOT match the state we sent.');
                    }
                    stack();
                }
            }
        } catch (e) { /* ignore */ }
        return i;
    };

    try {
        Activity.onNewIntent.overload('android.content.Intent').implementation = function (i) {
            try {
                var d = i.getData();
                if (d !== null && CALLBACK_RE.test(d.toString())) {
                    banner('CALLBACK via onNewIntent  (' + this.getClass().getName() + ')');
                    console.log('  ' + d.toString() + '\n');
                    printParams(absorbCallback(d.toString()));
                }
            } catch (e) { /* ignore */ }
            return this.onNewIntent(i);
        };
    } catch (e) { /* ignore */ }

    // -----------------------------------------------------------------------
    // 3) WebView — using one for the flow is itself a finding (RFC 8252 s8.12).
    // -----------------------------------------------------------------------
    try {
        var WebView = Java.use('android.webkit.WebView');
        WebView.loadUrl.overload('java.lang.String').implementation = function (url) {
            if (OAUTH_URL_RE.test(url)) {
                flow.usedWebView = true;
                banner('!! OAUTH FLOW INSIDE A WEBVIEW - FINDING');
                console.log('  ' + url);
                console.log('\n  The app hosts the identity provider login page inside its own');
                console.log('  process. It can read the DOM (including the password field), every');
                console.log('  request body, and the IdP session cookie. RFC 8252 s8.12 prohibits');
                console.log('  embedded user agents. See chapter 45 section 3.9.');
                absorbAuthorize(url);
                CONFIG.stacks = true; stack(); CONFIG.stacks = false;
            }
            return this.loadUrl(url);
        };
        WebView.loadUrl.overload('java.lang.String', 'java.util.Map').implementation =
            function (url, hdrs) {
                if (OAUTH_URL_RE.test(url)) {
                    flow.usedWebView = true;
                    banner('!! OAUTH FLOW INSIDE A WEBVIEW (with headers) - FINDING');
                    console.log('  ' + url);
                    console.log('  headers: ' + hdrs);
                    absorbAuthorize(url);
                }
                return this.loadUrl(url, hdrs);
            };
    } catch (e) { console.log('[i] WebView hooks unavailable: ' + e); }

    // -----------------------------------------------------------------------
    // 4) The token exchange over OkHttp (3.x and 4.x cover the large majority of apps).
    // -----------------------------------------------------------------------
    function dumpOkHttpRequest(req, tag) {
        try {
            var url = req.url().toString();
            if (!CONFIG.verbose && !OAUTH_URL_RE.test(url)) return;
            banner('HTTP ' + req.method() + '  ' + url + '   [' + tag + ']');

            var headers = req.headers();
            for (var h = 0; h < headers.size(); h++) {
                var name = headers.name(h);
                if (/authorization|dpop|cookie|content-type/i.test(name)) {
                    console.log('  ' + name + ': ' + headers.value(h));
                }
            }

            var body = req.body();
            if (body !== null && CONFIG.dumpBodies) {
                var Buffer = Java.use('okio.Buffer');
                var b = Buffer.$new();
                body.writeTo(b);
                var text = b.readUtf8();
                console.log('  body:');
                if (/=/.test(text) && !/^\s*[{[]/.test(text)) {
                    printParams(parseForm(text), '    ');
                    absorbTokenRequest(url, text);
                } else {
                    console.log('    ' + text);
                }
            }
            stack();
        } catch (e) { console.log('[i] request dump failed: ' + e); }
    }

    // OkHttp 4.x
    try {
        var RealCall4 = Java.use('okhttp3.internal.connection.RealCall');
        RealCall4.getOriginalRequest.implementation = function () {
            var req = this.getOriginalRequest();
            dumpOkHttpRequest(req, 'OkHttp4');
            return req;
        };
        console.log('[+] OkHttp 4.x hooked');
    } catch (e) { /* not present */ }

    // OkHttp 3.x
    try {
        var RealCall3 = Java.use('okhttp3.RealCall');
        RealCall3.execute.implementation = function () {
            dumpOkHttpRequest(this.request(), 'OkHttp3');
            var resp = this.execute();
            dumpOkHttpResponse(resp);
            return resp;
        };
        console.log('[+] OkHttp 3.x hooked');
    } catch (e) { /* not present */ }

    function dumpOkHttpResponse(resp) {
        try {
            var url = resp.request().url().toString();
            if (!CONFIG.verbose && !OAUTH_URL_RE.test(url)) return;
            console.log('  <- HTTP ' + resp.code());
            if (!CONFIG.dumpBodies) return;
            var peek = resp.peekBody(1024 * 64);
            var text = peek.string(Java.use('java.nio.charset.Charset').forName('UTF-8'));
            console.log('  response body:\n    ' + text.substring(0, 4000));
            annotateTokenResponse(text);
        } catch (e) { /* ignore */ }
    }

    function annotateTokenResponse(text) {
        try {
            var j = JSON.parse(text);
            if (!j.access_token && !j.id_token) return;
            console.log('\n  token response fields:');
            if (j.token_type) console.log('    token_type   = ' + j.token_type +
                (j.token_type.toLowerCase() === 'dpop' ? '   (sender-constrained, good)' : ''));
            if (j.expires_in) console.log('    expires_in   = ' + j.expires_in + 's' +
                (j.expires_in > 86400 ? '   <-- long-lived access token' : ''));
            if (j.refresh_token) console.log('    refresh_token present (length ' +
                j.refresh_token.length + ')');
            if (j.scope) console.log('    granted scope = ' + j.scope);
            if (j.id_token) decodeJwt(j.id_token, 'id_token');
            if (j.access_token && j.access_token.split('.').length === 3) {
                decodeJwt(j.access_token, 'access_token');
            }
        } catch (e) { /* not JSON */ }
    }

    function decodeJwt(tok, label) {
        try {
            var parts = tok.split('.');
            if (parts.length !== 3) return;
            var dec = function (s) {
                s = s.replace(/-/g, '+').replace(/_/g, '/');
                while (s.length % 4) s += '=';
                // Frida's JS runtime does not always expose atob; use Java.
                var B64 = Java.use('android.util.Base64');
                var bytes = B64.decode(s, 0);
                return Java.use('java.lang.String').$new(bytes).toString();
            };
            console.log('\n  ' + label + ' header : ' + dec(parts[0]));
            console.log('  ' + label + ' payload: ' + dec(parts[1]));
            var claims = JSON.parse(dec(parts[1]));
            if (label === 'id_token') {
                console.log('    -> aud   = ' + JSON.stringify(claims.aud) +
                    '   (must equal this app client_id at every consumer)');
                console.log('    -> iss   = ' + claims.iss);
                console.log('    -> sub   = ' + claims.sub + '   (key accounts on this, not email)');
                if (flow.nonce && claims.nonce !== flow.nonce) {
                    console.log('    [!!] nonce in id_token does not match the one sent.');
                }
            }
        } catch (e) { /* ignore */ }
    }

    // -----------------------------------------------------------------------
    // 5) HttpURLConnection — used by hand-rolled implementations.
    // -----------------------------------------------------------------------
    try {
        var URL = Java.use('java.net.URL');
        URL.openConnection.overload().implementation = function () {
            var u = this.toString();
            if (OAUTH_URL_RE.test(u)) {
                console.log('\n[HttpURLConnection] ' + u);
                if (/\/token/.test(u)) flow.tokenEndpoint = u;
                stack();
            }
            return this.openConnection();
        };
    } catch (e) { /* ignore */ }

    // -----------------------------------------------------------------------
    // 6) AppAuth — the shortcut. One hook yields code, code_verifier, client_id, redirect_uri.
    // -----------------------------------------------------------------------
    try {
        var TokenRequest = Java.use('net.openid.appauth.TokenRequest');
        TokenRequest.getRequestParameters.implementation = function () {
            var m = this.getRequestParameters();
            banner('AppAuth TokenRequest parameters');
            var text = m.toString();       // {grant_type=..., code=..., code_verifier=...}
            console.log('  ' + text);
            // Convert Java map text into our flow state.
            try {
                var keys = m.keySet().toArray();
                var obj = {};
                for (var i = 0; i < keys.length; i++) {
                    obj[keys[i].toString()] = String(m.get(keys[i]));
                }
                printParams(obj);
                if (obj.code) flow.code = obj.code;
                if (obj.code_verifier) flow.codeVerifier = obj.code_verifier;
                if (obj.client_id) flow.clientId = obj.client_id;
                if (obj.redirect_uri) flow.redirectUri = obj.redirect_uri;
            } catch (e) { /* map iteration differs across versions */ }
            console.log('\n  -> This is everything needed for the enforcement test. Type summary()');
            return m;
        };
        console.log('[+] AppAuth TokenRequest hooked');
    } catch (e) { /* AppAuth not in use */ }

    try {
        var AuthReq = Java.use('net.openid.appauth.AuthorizationRequest');
        AuthReq.toUri.implementation = function () {
            var u = this.toUri();
            banner('AppAuth AuthorizationRequest');
            console.log('  ' + u.toString() + '\n');
            printParams(absorbAuthorize(u.toString()));
            return u;
        };
    } catch (e) { /* ignore */ }

    // -----------------------------------------------------------------------
    // 7) PKCE primitives — for hand-rolled implementations with no AppAuth.
    //    A SHA-256 digest immediately before an /authorize request is almost always the challenge.
    // -----------------------------------------------------------------------
    try {
        var MessageDigest = Java.use('java.security.MessageDigest');
        MessageDigest.digest.overload().implementation = function () {
            var out = this.digest();
            try {
                if (this.getAlgorithm().toUpperCase().indexOf('SHA-256') >= 0) {
                    var B64 = Java.use('android.util.Base64');
                    // URL_SAFE(8) | NO_PADDING(1) | NO_WRAP(2) = 11
                    console.log('[pkce?] SHA-256 digest -> ' + B64.encodeToString(out, 11).trim());
                }
            } catch (e) { /* ignore */ }
            return out;
        };
    } catch (e) { /* ignore */ }

    // -----------------------------------------------------------------------
    // 8) Where do the tokens land? Catch the write, not just the value.
    // -----------------------------------------------------------------------
    try {
        var Editor = Java.use('android.app.SharedPreferencesImpl$EditorImpl');
        Editor.putString.implementation = function (key, value) {
            if (/token|auth|credential|jwt|refresh|access/i.test(key) ||
                (value !== null && /^eyJ[A-Za-z0-9_-]{10,}/.test(String(value)))) {
                console.log('\n[STORAGE] SharedPreferences.putString("' + key + '", ' +
                    (value === null ? 'null' : '"' + String(value).substring(0, 80) + '..."') + ')');
                console.log('  -> plaintext preferences are readable from a backup or a rooted');
                console.log('     device. See chapter 46-Tokens.');
                stack();
            }
            return this.putString(key, value);
        };
    } catch (e) { /* ignore */ }

    console.log('\n[+] All available hooks installed. Perform a login now.\n');
});
