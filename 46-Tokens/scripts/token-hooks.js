// token-hooks.js — watch every token an Android app writes, reads, sends, or verifies.
//
// PURPOSE
//   A storage sweep (scripts/token-storage-sweep.sh) tells you where a token ENDED UP.
//   This tells you what the app DID with it: which store it chose, whether the value was
//   encrypted before it was written, which header it went out in, whether the app
//   verifies an id_token it receives, and — the question that decides most findings —
//   whether the token survives a logout.
//
//   It hooks six surfaces, each of which can be disabled if it is too noisy:
//     1. SharedPreferences and EncryptedSharedPreferences  (where tokens live)
//     2. java.io / SQLite writes containing token material  (where else they live)
//     3. OkHttp / HttpURLConnection request headers          (how they are sent)
//     4. AccountManager                                      (the shared store)
//     5. JWT library entry points (JJWT, Nimbus, Auth0, AppAuth)  (how they are checked)
//     6. android.util.Log                                    (how they escape)
//
// USAGE
//   frida -U -f com.example.target -l token-hooks.js
//   frida -U -n com.example.target -l token-hooks.js          # attach to a running app
//   frida -U -f com.example.target -l token-hooks.js -o session.log
//
//   Configure by editing CONFIG below, or from the REPL:
//     rpc.exports.config({ redact: false })     // show tokens in full — see SAFETY
//     rpc.exports.summary()                     // print what has been seen so far
//     rpc.exports.dumpprefs()                   // re-read every prefs file right now
//
// REQUIREMENTS
//   Frida 16+, a frida-server running on the device as root, and a device you may
//   instrument. See 53-Frida for setup.
//
//   MEASURED, so you know what to expect: the device attached while this chapter was
//   written is an i9000S, Android 13 / API 33, and it is NOT rooted — `su` reports
//   "inaccessible or not found" — so it has no frida-server and this script could not be
//   executed against it. It is written against the documented APIs and the hook shapes
//   used throughout this repository (compare 45-OAuth/scripts/oauth-flow-tracer.js,
//   which was written for the same estate). Treat "runs clean" as unverified on that
//   device and verify on your own rooted one before relying on it in an engagement.
//
// WHAT THIS WILL NOT TELL YOU
//   * It will not see a token that never crosses one of the six hooked boundaries. An
//     app with its own JNI HTTP stack, its own storage layer, or a Flutter/React Native
//     bridge will produce a quiet log. A quiet log means "not observed here", never
//     "does not happen". Widen the hooks or fall back to the storage sweep.
//   * It will not tell you the token is stored INSECURELY. Seeing putString("token", ...)
//     tells you the value is in SharedPreferences; whether that matters depends on the
//     device's posture and the token's lifetime and scope. README section 5.10.
//   * It will not verify any signature. It reports what the app checked, not whether the
//     check was right.
//   * Hooking a Keystore-backed Cipher and reading plaintext is a DEMONSTRATION, not a
//     finding, unless what you recover is something the current user should not have.
//     That distinction is 49-KeyStore section 1.3 and it is the one most often got wrong.
//   * It changes the process it observes. An app with integrity checks may behave
//     differently under instrumentation — see 38-TamperDetection and 67.
//
// SAFETY
//   `redact: true` is the default. Tokens are printed as a prefix, a length and a SHA-256
//   prefix, which is enough to correlate two sightings of the same token without putting
//   a live credential in your terminal scrollback, your screen recording, or your report
//   screenshot. Turn it off deliberately and only for a token you minted yourself.
//
//   Chapter 46's standing rule: every token you handle is one you created. Do not run
//   this against an app signed into someone else's account, and do not run it against an
//   account of your own that has real value.
//
// Chapter 46 — Tokens

'use strict';

var CONFIG = {
    redact: true,            // print prefixes and hashes rather than whole tokens
    prefsHooks: true,
    fileHooks: true,
    networkHooks: true,
    accountHooks: true,
    jwtHooks: true,
    logHooks: true,
    stacks: false,           // print a Java stack trace for every hit (very noisy)
    minLength: 20            // ignore short strings; a token is not 8 characters
};

// A token-shaped value. Broad on purpose: an opaque token has no structure to match on,
// so the keyword list carries most of the weight and the JWT regex is the bonus.
var JWT_RE = /eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*/;
var KEY_RE = /(access|refresh|id|auth|session|bearer|api)[-_]?(token|key)|authorization|jwt|credential|AuthState/i;

var seen = {};               // fingerprint -> { count, first, contexts: [] }
var counters = { prefs: 0, file: 0, net: 0, account: 0, jwt: 0, log: 0 };

function sha256Prefix(s) {
    var md = Java.use('java.security.MessageDigest').getInstance('SHA-256');
    var bytes = md.digest(Java.use('java.lang.String').$new(s).getBytes('UTF-8'));
    var hex = '';
    for (var i = 0; i < 6 && i < bytes.length; i++) {
        hex += ('0' + (bytes[i] & 0xff).toString(16)).slice(-2);
    }
    return hex;
}

function fingerprint(value) {
    // Correlating sightings without storing the token is the whole trick. Two hits with
    // the same fingerprint are the same token; you can prove a value written to
    // SharedPreferences is the value sent in the Authorization header without ever
    // printing either one.
    try { return sha256Prefix(value); } catch (e) { return 'nohash'; }
}

function show(value) {
    if (value === null || value === undefined) return String(value);
    var s = String(value);
    if (!CONFIG.redact) return s;
    if (s.length <= 12) return s;
    return s.substring(0, 8) + '...[' + s.length + ' chars, sha256:' + fingerprint(s) + ']';
}

function interesting(key, value) {
    if (value === null || value === undefined) return false;
    var s = String(value);
    if (s.length < CONFIG.minLength) return false;
    return JWT_RE.test(s) || KEY_RE.test(String(key)) || KEY_RE.test(s);
}

function record(kind, context, value) {
    var fp = fingerprint(String(value));
    if (!seen[fp]) seen[fp] = { count: 0, first: kind, contexts: [] };
    seen[fp].count++;
    if (seen[fp].contexts.indexOf(context) === -1) seen[fp].contexts.push(context);
    counters[kind]++;
}

function stack() {
    if (!CONFIG.stacks) return '';
    var Log = Java.use('android.util.Log');
    var Exception = Java.use('java.lang.Exception');
    return '\n' + Log.getStackTraceString(Exception.$new());
}

function banner(text) {
    console.log('\n─── ' + text + ' ' +
                Array(Math.max(2, 66 - text.length)).join('─'));
}

Java.perform(function () {

    console.log('[*] token-hooks.js — chapter 46');
    console.log('[*] redaction is ' + (CONFIG.redact ? 'ON' : 'OFF — you are printing live credentials'));

    // ----------------------------------------------------------------------- //
    // 1. SharedPreferences.
    //
    // This is where most Android tokens live, because it is the path of least
    // resistance: one line, no schema, survives restarts. EncryptedSharedPreferences
    // (androidx.security.crypto) presents the SAME interface, so the hook catches both
    // and the interesting question becomes which implementation class is behind it —
    // printed below. If it says EncryptedSharedPreferences, the value on disk is Tink
    // ciphertext; if it says SharedPreferencesImpl, the value on disk is what you see.
    // ----------------------------------------------------------------------- //
    if (CONFIG.prefsHooks) {
        try {
            var Editor = Java.use('android.content.SharedPreferences$Editor');
            Editor.putString.implementation = function (key, value) {
                if (interesting(key, value)) {
                    var impl = this.$className;
                    banner('SharedPreferences write');
                    console.log('  key    ' + key);
                    console.log('  value  ' + show(value));
                    console.log('  via    ' + impl);
                    console.log('  NOTE   ' + (impl.indexOf('Encrypt') >= 0
                        ? 'Encrypted implementation: the DISK copy is ciphertext. Now go '
                          + 'and find the plaintext copy — chapter 33 section 5.4.'
                        : 'PLAINTEXT on disk. Grade it by reachability, not by presence.'));
                    console.log(stack());
                    record('prefs', 'prefs.put:' + key, value);
                }
                return this.putString(key, value);
            };
            Editor.putStringSet.implementation = function (key, value) {
                if (KEY_RE.test(String(key))) {
                    banner('SharedPreferences write (set)');
                    console.log('  key    ' + key);
                    record('prefs', 'prefs.putSet:' + key, String(value));
                }
                return this.putStringSet(key, value);
            };
            var Prefs = Java.use('android.content.SharedPreferences');
            Prefs.getString.implementation = function (key, def) {
                var out = this.getString(key, def);
                if (interesting(key, out)) {
                    console.log('[prefs read] ' + key + ' = ' + show(out));
                    record('prefs', 'prefs.get:' + key, out);
                }
                return out;
            };
            console.log('[+] SharedPreferences hooks installed');
        } catch (e) { console.log('[-] SharedPreferences: ' + e); }
    }

    // ----------------------------------------------------------------------- //
    // 2. Files and SQLite.
    //
    // Catches the app that writes its AuthState to a file, and the app that keeps a
    // session table. The SQLite hook watches the SQL text rather than the values,
    // because a bound parameter never appears in the statement — so treat this as a
    // pointer to a table worth reading on disk, not as a value dump.
    // ----------------------------------------------------------------------- //
    if (CONFIG.fileHooks) {
        try {
            var FOS = Java.use('java.io.FileOutputStream');
            FOS.write.overload('[B').implementation = function (buf) {
                try {
                    var s = Java.use('java.lang.String').$new(buf);
                    if (JWT_RE.test(s) || KEY_RE.test(s)) {
                        banner('file write containing token material');
                        var m = s.match(JWT_RE);
                        console.log('  bytes  ' + buf.length);
                        console.log('  match  ' + show(m ? m[0] : s.substring(0, 80)));
                        console.log(stack());
                        record('file', 'FileOutputStream.write', m ? m[0] : s);
                    }
                } catch (e) { /* binary content — expected and uninteresting */ }
                return this.write(buf);
            };
        } catch (e) { console.log('[-] FileOutputStream: ' + e); }

        try {
            var SQL = Java.use('android.database.sqlite.SQLiteDatabase');
            SQL.execSQL.overload('java.lang.String').implementation = function (sql) {
                if (KEY_RE.test(sql)) {
                    console.log('[sqlite] ' + sql.substring(0, 160));
                    console.log('         Note: bound parameters are NOT in this string.');
                    console.log('         Read the .db AND its -wal on disk; chapter 33');
                    console.log('         measured four "deleted" secrets alive in a WAL.');
                }
                return this.execSQL(sql);
            };
            console.log('[+] file and SQLite hooks installed');
        } catch (e) { console.log('[-] SQLiteDatabase: ' + e); }
    }

    // ----------------------------------------------------------------------- //
    // 3. Outbound headers.
    //
    // Where the token is actually used. Two things to watch for beyond the obvious:
    // an id_token being sent as a bearer credential (audience confusion — 45-OAuth
    // section 3.12), and a token sent to a host that is not the resource server.
    // ----------------------------------------------------------------------- //
    if (CONFIG.networkHooks) {
        try {
            var Builder = Java.use('okhttp3.Request$Builder');
            Builder.header.implementation = function (name, value) {
                if (/authorization|x-.*-token|dpop/i.test(name)) {
                    banner('outbound header');
                    console.log('  ' + name + ': ' + show(value));
                    if (/^bearer /i.test(String(value))) {
                        var raw = String(value).substring(7);
                        if (JWT_RE.test(raw)) {
                            try {
                                var payload = raw.split('.')[1];
                                console.log('  claims (UNVERIFIED, decoded locally):');
                                console.log('    ' + atobUrl(payload));
                            } catch (e) { /* not decodable */ }
                        }
                        record('net', 'okhttp.header:' + name, raw);
                    }
                    if (/^dpop/i.test(name)) {
                        console.log('  DPoP proof present — the token is sender-constrained.');
                        console.log('  Test the ENFORCEMENT: replay the same proof (jti reuse');
                        console.log('  must fail) and send the token with no proof at all.');
                    }
                }
                return this.header(name, value);
            };
            Builder.addHeader.implementation = function (name, value) {
                if (/authorization|dpop/i.test(name)) {
                    console.log('[header+] ' + name + ': ' + show(value));
                    record('net', 'okhttp.addHeader:' + name, String(value));
                }
                return this.addHeader(name, value);
            };
            console.log('[+] OkHttp hooks installed');
        } catch (e) { console.log('[-] OkHttp not present: ' + e); }

        try {
            var URLConn = Java.use('java.net.HttpURLConnection');
            URLConn.setRequestProperty.implementation = function (name, value) {
                if (/authorization|token|dpop/i.test(name)) {
                    console.log('[HttpURLConnection] ' + name + ': ' + show(value));
                    record('net', 'urlconn:' + name, String(value));
                }
                return this.setRequestProperty(name, value);
            };
            console.log('[+] HttpURLConnection hooks installed');
        } catch (e) { console.log('[-] HttpURLConnection: ' + e); }
    }

    // ----------------------------------------------------------------------- //
    // 4. AccountManager — tokens stored OUTSIDE the app's own sandbox.
    // ----------------------------------------------------------------------- //
    if (CONFIG.accountHooks) {
        try {
            var AM = Java.use('android.accounts.AccountManager');
            AM.setAuthToken.implementation = function (account, type, token) {
                banner('AccountManager.setAuthToken');
                console.log('  account ' + account.name.value + ' (' + account.type.value + ')');
                console.log('  type    ' + type);
                console.log('  token   ' + show(token));
                console.log('  NOTE    the token now lives in the system account database,');
                console.log('          not in this app. Who else can read it depends on the');
                console.log('          account type\'s signature and on GET_ACCOUNTS-class');
                console.log('          permissions. Enumerate the other apps declaring the');
                console.log('          same account type before deciding the severity.');
                record('account', 'AccountManager.setAuthToken:' + type, token);
                return this.setAuthToken(account, type, token);
            };
            console.log('[+] AccountManager hooks installed');
        } catch (e) { console.log('[-] AccountManager: ' + e); }
    }

    // ----------------------------------------------------------------------- //
    // 5. JWT libraries — what the app CHECKS.
    //
    // The distinction that matters is decode versus verify. Every library below has
    // both, the decode call is shorter, and the decode call is the vulnerability.
    // ----------------------------------------------------------------------- //
    if (CONFIG.jwtHooks) {
        [
            // Auth0 java-jwt: JWT.decode() does NOT verify. JWT.require(...).build().verify() does.
            ['com.auth0.jwt.JWT', 'decode', 'DECODE ONLY — no signature check happens here'],
            ['com.auth0.jwt.JWTVerifier', 'verify', 'verify — check which claims were required'],
            // JJWT: parsePlaintextClaims / parseClaimsJwt are the unsigned paths.
            ['io.jsonwebtoken.impl.DefaultJwtParser', 'parseClaimsJwt',
             'UNSIGNED parse — this method exists to read a JWT with no signature'],
            ['io.jsonwebtoken.impl.DefaultJwtParser', 'parseClaimsJws', 'signed parse'],
            // Nimbus
            ['com.nimbusds.jwt.SignedJWT', 'parse', 'parse only — verify() is separate'],
            ['com.nimbusds.jwt.SignedJWT', 'verify', 'verify'],
            ['com.nimbusds.jwt.PlainJWT', 'parse',
             'PLAIN JWT — this class exists specifically for alg=none'],
            // AppAuth
            ['net.openid.appauth.IdToken', 'from', 'AppAuth id_token parse'],
            ['net.openid.appauth.IdToken', 'validate', 'AppAuth id_token validate']
        ].forEach(function (spec) {
            try {
                var clazz = Java.use(spec[0]);
                if (!clazz[spec[1]]) return;
                clazz[spec[1]].overloads.forEach(function (ov) {
                    ov.implementation = function () {
                        banner('JWT library call: ' + spec[0] + '.' + spec[1]);
                        console.log('  ' + spec[2]);
                        for (var i = 0; i < arguments.length; i++) {
                            var a = arguments[i];
                            if (a !== null && typeof a !== 'undefined' &&
                                JWT_RE.test(String(a))) {
                                console.log('  arg[' + i + '] ' + show(a));
                                record('jwt', spec[0] + '.' + spec[1], String(a));
                            }
                        }
                        console.log(stack());
                        return ov.apply(this, arguments);
                    };
                });
                console.log('[+] hooked ' + spec[0] + '.' + spec[1]);
            } catch (e) { /* library absent — normal */ }
        });
        console.log('[*] If NOTHING above was hooked, the app either rolls its own JWT');
        console.log('    handling (grep the DEX for "eyJ", "split(\\".\\")" and');
        console.log('    Base64.decode) or does not parse tokens at all and simply');
        console.log('    forwards them — which is fine, and moves the whole question');
        console.log('    server-side.');
    }

    // ----------------------------------------------------------------------- //
    // 6. Logging — the most common escape route for a correctly-stored token.
    // ----------------------------------------------------------------------- //
    if (CONFIG.logHooks) {
        try {
            var Log = Java.use('android.util.Log');
            ['d', 'v', 'i', 'w', 'e'].forEach(function (level) {
                Log[level].overload('java.lang.String', 'java.lang.String')
                    .implementation = function (tag, msg) {
                    if (msg && (JWT_RE.test(msg) || /bearer /i.test(msg))) {
                        banner('TOKEN IN A LOG LINE — Log.' + level + '()');
                        console.log('  tag  ' + tag);
                        console.log('  msg  ' + show(msg));
                        console.log('  This is readable by anything with READ_LOGS, by any');
                        console.log('  crash reporter linked into the app, and by adb. It is');
                        console.log('  a finding on its own regardless of how well the token');
                        console.log('  is stored.');
                        record('log', 'Log.' + level + ':' + tag, msg);
                    }
                    return this[level](tag, msg);
                };
            });
            console.log('[+] Log hooks installed');
        } catch (e) { console.log('[-] Log: ' + e); }
    }

    console.log('\n[*] Ready. Drive the app: log in, use a feature, wait for a refresh,');
    console.log('    then log OUT and use the feature again. That last step is the test');
    console.log('    most people skip and it is where the finding usually is.');
    console.log('[*] rpc.exports.summary() prints the correlation table.\n');
});

function atobUrl(segment) {
    // Decode a base64url segment inside the target process, with no allocation of a
    // helper class per call. Purely for display; nothing here verifies anything.
    var Base64 = Java.use('android.util.Base64');
    var bytes = Base64.decode(segment, 8 /* URL_SAFE */ | 2 /* NO_PADDING */ | 1 /* NO_WRAP */);
    return Java.use('java.lang.String').$new(bytes);
}

rpc.exports = {
    config: function (opts) {
        Object.keys(opts || {}).forEach(function (k) { CONFIG[k] = opts[k]; });
        return CONFIG;
    },
    summary: function () {
        var lines = ['', 'Distinct token-shaped values observed: ' + Object.keys(seen).length, ''];
        Object.keys(seen).forEach(function (fp) {
            lines.push('  sha256:' + fp + '  seen ' + seen[fp].count + ' times');
            seen[fp].contexts.forEach(function (ctx) { lines.push('      ' + ctx); });
        });
        lines.push('');
        lines.push('A fingerprint appearing in BOTH a storage context and a network');
        lines.push('context proves the stored value is the credential in use — without');
        lines.push('either of them ever being printed. That is the evidence a report');
        lines.push('needs, and it is safe to paste into one.');
        lines.push('');
        lines.push('counters: ' + JSON.stringify(counters));
        var out = lines.join('\n');
        console.log(out);
        return out;
    },
    dumpprefs: function () {
        // Re-read every preferences file the app can see, right now. Useful after a
        // logout, to answer "did the app actually clear its tokens?"
        var result = [];
        Java.perform(function () {
            var ActivityThread = Java.use('android.app.ActivityThread');
            var ctx = ActivityThread.currentApplication().getApplicationContext();
            var dir = Java.use('java.io.File').$new(
                ctx.getApplicationInfo().dataDir.value + '/shared_prefs');
            var files = dir.listFiles();
            if (files === null) { result.push('no shared_prefs directory'); return; }
            for (var i = 0; i < files.length; i++) {
                var name = files[i].getName();
                result.push(name + '  (' + files[i].length() + ' bytes)');
            }
        });
        var out = result.join('\n');
        console.log(out);
        return out;
    }
};
