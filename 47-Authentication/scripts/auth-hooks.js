// 47-Authentication/scripts/auth-hooks.js
//
// PURPOSE
//   Recover an Android application's ENTIRE authentication design at runtime,
//   without decompiling it, by hooking the PLATFORM classes every app must go
//   through. Run it, use the app normally for two minutes, and read the log.
//
// USAGE
//   frida -U -f com.example.app -l scripts/auth-hooks.js          # spawn
//   frida -U -n com.example.app -l scripts/auth-hooks.js          # attach
//
//   By default it OBSERVES ONLY and modifies nothing. To make it act:
//
//   frida -U -f com.example.app -l scripts/auth-hooks.js \
//         -e 'FORCE_GATES=true'          # (see CONFIG below; edit the file)
//
//   RPC, for driving it from a Python harness:
//     rpc.exports.summary()      -> the inventory gathered so far
//     rpc.exports.setforce(bool) -> turn gate forcing on/off at runtime
//
// WHY IT HOOKS THE PLATFORM AND NOT THE APP
//   Every hook here targets a class in android.*, androidx.* or a very common
//   library. That is the single most transferable technique in chapter 47:
//
//     * Platform classes are NOT renamed by R8 or ProGuard.
//     * They cannot be inlined away from the app's perspective - they live in
//       a different DEX, loaded by a different class loader.
//     * They are identical in every app you will ever test, so one script works
//       everywhere and keeps working after the app is updated or rewritten.
//
//   Chapter 47 section 6.2 records why the alternative fails: patching an app's
//   own isLoggedIn() can be perfect and change nothing, because ART inlined it
//   or because the decision is made elsewhere. Chapters 18 and 65 both measured
//   exactly that - a hook or patch that installs, verifies, and has no effect.
//
// WHAT IT WILL NOT DO
//   It does not exfiltrate anything, does not write files, and TRUNCATES every
//   credential-shaped value it prints (see `redact`). An audit tool that prints
//   live bearer tokens puts them in your scrollback, in your screen recording,
//   and eventually in your report.
//
// AUTHORISED TESTING ONLY.

'use strict';

// ===========================================================================
// CONFIG
// ===========================================================================
var CONFIG = {
    // Observe only. Set true to make every credential-shaped getBoolean return
    // true - the fastest client-gate test there is. See the WARNING below.
    FORCE_GATES: false,

    // Print a stack trace for each first sighting of a hook. Extremely useful
    // for finding WHERE the app's session logic lives; very noisy.
    STACKS: false,

    // Values longer than this are truncated when printed.
    REDACT_AFTER: 12
};

// Keys that look like an authentication decision or a credential.
var GATE_RE  = /log(ged)?[_ ]?in|is[_ ]?auth|authenticated|has[_ ]?session|premium|is[_ ]?pro\b|subscrib|is[_ ]?admin|unlocked|activated/i;
var CRED_RE  = /token|session|cookie|password|passwd|secret|credential|refresh|bearer|jwt|otp|pin\b|auth/i;

// ===========================================================================
// Utilities
// ===========================================================================

var seen = {};          // dedupe key -> count
var inventory = {
    prefReads: {}, prefWrites: {}, accounts: [], windowFlags: [],
    comparisons: [], httpHeaders: {}, notes: []
};

function once(key) {
    if (seen[key]) { seen[key]++; return false; }
    seen[key] = 1;
    return true;
}

function redact(v) {
    if (v === null || v === undefined) return String(v);
    var s = String(v);
    if (s.length <= CONFIG.REDACT_AFTER) return JSON.stringify(s);
    return JSON.stringify(s.substring(0, CONFIG.REDACT_AFTER)) +
           '...<' + s.length + ' chars total>';
}

function log(tag, msg) {
    console.log('[' + tag + '] ' + msg);
}

function stack() {
    if (!CONFIG.STACKS) return;
    var Log = Java.use('android.util.Log');
    var Exception = Java.use('java.lang.Exception');
    console.log(Log.getStackTraceString(Exception.$new()));
}

function bump(bag, key) {
    bag[key] = (bag[key] || 0) + 1;
}

// ===========================================================================
// Hooks
// ===========================================================================

function hookSharedPreferences() {
    var Impl;
    try {
        Impl = Java.use('android.app.SharedPreferencesImpl');
    } catch (e) {
        log('warn', 'SharedPreferencesImpl not found: ' + e.message);
        return;
    }

    // --- reads --------------------------------------------------------------
    Impl.getBoolean.implementation = function (key, def) {
        var real = this.getBoolean(key, def);
        if (GATE_RE.test(key)) {
            bump(inventory.prefReads, key);
            if (once('gb:' + key)) {
                log('GATE', 'getBoolean(' + JSON.stringify(key) + ') = ' + real +
                            (CONFIG.FORCE_GATES ? '  -> FORCED true' : ''));
                stack();
            }
            if (CONFIG.FORCE_GATES) return true;
        }
        return real;
    };

    Impl.getString.overload('java.lang.String', 'java.lang.String')
        .implementation = function (key, def) {
        var real = this.getString(key, def);
        if (CRED_RE.test(key) && real !== null) {
            bump(inventory.prefReads, key);
            if (once('gs:' + key)) {
                log('CRED-READ', 'getString(' + JSON.stringify(key) + ') = ' + redact(real));
                stack();
            }
        }
        return real;
    };

    // --- writes -------------------------------------------------------------
    // This is the highest-value hook in the whole script. It finds the app's
    // credential store with no static analysis at all, and it survives string
    // encryption - the key is decrypted before it reaches this call.
    var Editor;
    try {
        Editor = Java.use('android.app.SharedPreferencesImpl$EditorImpl');
    } catch (e) {
        log('warn', 'EditorImpl not found: ' + e.message);
        return;
    }

    Editor.putString.implementation = function (key, value) {
        if (CRED_RE.test(key) || (value !== null && String(value).length > 40)) {
            bump(inventory.prefWrites, key);
            if (once('ps:' + key)) {
                log('CRED-WRITE', 'putString(' + JSON.stringify(key) + ', ' +
                                  redact(value) + ')');
                stack();
            }
        }
        return this.putString(key, value);
    };

    Editor.putBoolean.implementation = function (key, value) {
        if (GATE_RE.test(key)) {
            bump(inventory.prefWrites, key);
            if (once('pb:' + key)) {
                log('GATE-WRITE', 'putBoolean(' + JSON.stringify(key) + ', ' + value + ')');
            }
        }
        return this.putBoolean(key, value);
    };

    // `clear()` on logout. If you see this and NO network call, the logout is
    // client-side - chapter 47 section 5.7.
    Editor.clear.implementation = function () {
        log('LOGOUT?', 'SharedPreferences.clear() called - check whether a ' +
                       'revocation request accompanies it');
        stack();
        return this.clear();
    };
}

function hookAccountManager() {
    var AM;
    try {
        AM = Java.use('android.accounts.AccountManager');
    } catch (e) {
        return;
    }

    // What the app can ACTUALLY see, versus what its manifest claims. On API 26+
    // GET_ACCOUNTS grants nothing; visibility is controlled by the authenticator.
    // Chapter 47 measured 7 of 17 real apps still declaring the dead permission.
    AM.getAccounts.overload().implementation = function () {
        var accts = this.getAccounts();
        if (once('getAccounts')) {
            log('ACCOUNTS', 'getAccounts() returned ' + accts.length + ' account(s)');
            for (var i = 0; i < accts.length; i++) {
                var entry = accts[i].type.value + ' / ' + redact(accts[i].name.value);
                log('ACCOUNTS', '  ' + entry);
                inventory.accounts.push(entry);
            }
        }
        return accts;
    };

    // These land in /data/system_ce/<user>/accounts_ce.db in PLAINTEXT.
    ['peekAuthToken'].forEach(function (m) {
        try {
            AM[m].implementation = function (account, authTokenType) {
                var r = this[m](account, authTokenType);
                log('AM-TOKEN', m + '(type=' + authTokenType + ') -> ' + redact(r));
                return r;
            };
        } catch (e) { /* overload mismatch on some API levels */ }
    });

    try {
        AM.setPassword.implementation = function (account, password) {
            // The plaintext `password` column. Chapter 47 measured one real
            // authenticator on a shipping device using it, with a 352-character
            // value. If the app under test does this, it is a finding.
            log('AM-PASSWORD', 'setPassword() on type=' + account.type.value +
                               ' value=' + redact(password) +
                               '  <-- writes to a PLAINTEXT column on disk');
            stack();
            return this.setPassword(account, password);
        };
    } catch (e) { /* not present */ }
}

function hookWindowFlags() {
    // THE reason this hook exists: FLAG_SECURE is a compile-time constant that
    // javac inlines, so the identifier NEVER appears in the DEX. Chapter 47
    // section 3.10 proves this by compiling an Activity that provably sets it.
    // A static grep for FLAG_SECURE has a true-positive rate of ZERO.
    // This hook is the reliable detection, and it gives PER-SCREEN coverage.
    var FLAG_SECURE = 0x2000;
    var Window;
    try {
        Window = Java.use('android.view.Window');
    } catch (e) {
        return;
    }

    Window.setFlags.implementation = function (flags, mask) {
        if ((mask & FLAG_SECURE) !== 0) {
            var where = 'unknown';
            try {
                where = this.getContext().getClass().getName();
            } catch (e) { /* context may be null very early */ }
            var state = (flags & FLAG_SECURE) ? 'SET' : 'CLEARED';
            var entry = state + ' on ' + where;
            if (once('fs:' + entry)) {
                log('FLAG_SECURE', entry);
                inventory.windowFlags.push(entry);
            }
        }
        return this.setFlags(flags, mask);
    };

    log('info', 'FLAG_SECURE hook armed. Walk EVERY screen. Screens that never ' +
                'print a line never set the flag - that is the finding.');
}

function hookKeyguard() {
    var KM;
    try {
        KM = Java.use('android.app.KeyguardManager');
    } catch (e) {
        return;
    }
    ['isDeviceSecure', 'isKeyguardSecure'].forEach(function (m) {
        try {
            KM[m].overload().implementation = function () {
                var r = this[m]();
                if (once('kg:' + m)) {
                    log('KEYGUARD', m + '() = ' + r +
                        (r ? '' : '  <-- no device credential set; auth-bound ' +
                                  'Keystore keys cannot be generated on this device'));
                }
                return r;
            };
        } catch (e) { /* overload differences */ }
    });
}

function hookCredentialComparison() {
    // Finds on-device comparison of secrets. If the app compares a user-entered
    // code against a value it holds, the correct value is ON THE DEVICE and can
    // simply be read - which is far easier than patching anything.
    var Str = Java.use('java.lang.String');
    Str.equals.implementation = function (other) {
        var r = this.equals(other);
        try {
            var a = this.toString();
            if (other !== null) {
                var b = Java.cast(other, Str).toString();
                // Heuristic: both sides short and numeric == an OTP or PIN.
                if (a.length >= 4 && a.length <= 10 &&
                    /^[0-9]+$/.test(a) && /^[0-9]+$/.test(b) && a !== b) {
                    var entry = redact(a) + ' vs ' + redact(b) + ' -> ' + r;
                    if (once('eq:' + a + b)) {
                        log('COMPARE', 'String.equals ' + entry +
                                       '  <-- possible on-device OTP/PIN check');
                        inventory.comparisons.push(entry);
                        stack();
                    }
                }
            }
        } catch (e) { /* cast failures are normal and frequent */ }
        return r;
    };
    log('info', 'String.equals hook armed (numeric 4-10 char heuristic). This ' +
                'hook is HOT - expect a performance cost.');
}

function hookOkHttp() {
    // Where the credential is attached to a request. Optional: many apps do not
    // use OkHttp, and this must never be fatal.
    try {
        var Builder = Java.use('okhttp3.Request$Builder');
        Builder.header.overload('java.lang.String', 'java.lang.String')
            .implementation = function (name, value) {
            if (/^(authorization|cookie|x-.*(token|auth|session|device))/i.test(name)) {
                bump(inventory.httpHeaders, name.toLowerCase());
                if (once('hdr:' + name.toLowerCase())) {
                    log('HTTP-CRED', name + ': ' + redact(value));
                }
            }
            return this.header(name, value);
        };
        log('info', 'OkHttp header hook armed.');
    } catch (e) {
        log('info', 'OkHttp not present (this is normal) - use a proxy instead.');
        inventory.notes.push('okhttp absent');
    }
}

function hookWebViewCookies() {
    // A logout that clears OkHttp's jar and forgets CookieManager leaves a
    // working session behind in any WebView the app opens. Chapter 43 covers
    // WebView; this is the authentication consequence.
    try {
        var CM = Java.use('android.webkit.CookieManager');
        CM.setCookie.overload('java.lang.String', 'java.lang.String')
            .implementation = function (url, value) {
            if (once('ck:' + url)) {
                log('WEBVIEW-COOKIE', url + ' <- ' + redact(value));
            }
            return this.setCookie(url, value);
        };
        CM.removeAllCookies.overload('android.webkit.ValueCallback')
            .implementation = function (cb) {
            log('WEBVIEW-COOKIE', 'removeAllCookies() - good, logout is clearing ' +
                                  'the WebView jar too');
            return this.removeAllCookies(cb);
        };
    } catch (e) { /* WebView not loaded yet, or absent */ }
}

// ===========================================================================
// RPC
// ===========================================================================

rpc.exports = {
    summary: function () {
        return inventory;
    },
    setforce: function (v) {
        CONFIG.FORCE_GATES = !!v;
        return CONFIG.FORCE_GATES;
    }
};

// ===========================================================================
// Entry
// ===========================================================================

Java.perform(function () {
    console.log('');
    console.log('=== 47-Authentication / auth-hooks.js ===');
    console.log('mode: ' + (CONFIG.FORCE_GATES ? 'FORCING GATES' : 'observe only'));
    console.log('');

    hookSharedPreferences();
    hookAccountManager();
    hookWindowFlags();
    hookKeyguard();
    hookOkHttp();
    hookWebViewCookies();
    hookCredentialComparison();

    console.log('');
    console.log('Hooks armed. Now:');
    console.log('  1. log in');
    console.log('  2. visit every screen, especially any that shows a credential');
    console.log('  3. background and foreground the app (silent re-auth path)');
    console.log('  4. log out');
    console.log('');
    console.log('THEN, and this is the step that decides severity: replay one');
    console.log('authenticated request from curl, WITHOUT the app. If the server');
    console.log('serves it, nothing above is the finding - the endpoint is.');
    console.log('See README section 7.1.');
    console.log('');

    if (CONFIG.FORCE_GATES) {
        console.log('!!! FORCE_GATES is on. Every credential-shaped getBoolean now');
        console.log('!!! returns true. A screen that renders under these conditions');
        console.log('!!! proves NOTHING about the server. Confirm with a raw request.');
        console.log('');
    }
});
