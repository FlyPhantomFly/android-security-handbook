/*
 * 04-banking-session.js — a complete engagement script for a hardened app.
 *
 * THE SITUATION
 *   A banking-style app that refuses to run on a rooted device and pins its TLS
 *   certificates in three independent places. The goal is to get its traffic
 *   into an intercepting proxy without repackaging the APK.
 *
 * WHY THE ORDER MATTERS
 *   Root detection runs in Application.attachBaseContext, before any Activity
 *   exists, so its hooks must be installed at SCRIPT-LOAD time. Pinning is
 *   configured when the HTTP client is built, which is later, so it can be
 *   hooked more lazily. Getting this order wrong is the difference between a
 *   working session and "the app closes immediately".
 *
 *   This is failure mode 4 from ../README.md section 7.4.4, applied.
 *
 * WHAT IT DOES NOT DO
 *   It does not attempt to defeat SafetyNet or Play Integrity. Those verdicts
 *   are signed by Google and validated by the app's SERVER, so changing what
 *   the client sees changes nothing the server believes. If the app uses them,
 *   this script reports that fact rather than pretending. See
 *   ../../50-HardwareBackedSecurity/README.md.
 *
 * HOW TO RUN
 *   adb shell cmd package compile -m verify -f com.example.bank
 *   adb shell am force-stop com.example.bank
 *   adb shell settings put global http_proxy 192.168.1.10:8080
 *   frida -U -f com.example.bank -l 04-banking-session.js --no-pause
 *
 *   Afterwards:
 *   adb shell settings put global http_proxy :0
 *   adb shell cmd package compile --reset com.example.bank
 *
 * AUTHORISED TESTING ONLY. Test only applications you own or are contracted to
 * assess. Instrumenting a financial application you do not own is a criminal
 * offence in most jurisdictions.
 */

'use strict';

var report = { root: [], tls: [], observed: [], detected: [] };

function ok(cat, what) { report[cat].push(what); console.log('[+] ' + what); }
function note(what) { console.log('    ' + what); }

function tryUse(n) { try { return Java.use(n); } catch (e) { return null; } }

/* =========================================================================
 * STAGE 1 — root detection.
 * Installed FIRST and at script-load time, because it runs in
 * attachBaseContext before anything else in the app.
 * ========================================================================= */

Java.perform(function () {

    var ROOT_TOKENS = ['/su', 'busybox', 'magisk', 'supersu', 'superuser',
                       'daemonsu', '/system/app/Superuser.apk', 'xposed', 'ksud'];

    function rooty(s) {
        if (s === null || s === undefined) return false;
        var l = String(s).toLowerCase();
        for (var i = 0; i < ROOT_TOKENS.length; i++) {
            if (l.indexOf(ROOT_TOKENS[i]) !== -1) return true;
        }
        return /(^|\/)su($|\/)/.test(l);
    }

    /* 1a. File existence — the most common check ------------------------- */
    var File = tryUse('java.io.File');
    if (File !== null) {
        ['exists', 'canRead', 'canExecute', 'isFile'].forEach(function (m) {
            if (File[m] === undefined) return;
            try {
                File[m].implementation = function () {
                    var path;
                    try { path = this.getAbsolutePath(); } catch (e) { path = ''; }
                    if (rooty(path)) {
                        note('root: File.' + m + '(' + path + ') -> false');
                        return false;
                    }
                    return this[m]();
                };
                ok('root', 'java.io.File.' + m);
            } catch (e) { /* skip */ }
        });
    }

    /* 1b. Command execution ---------------------------------------------- */
    var Runtime = tryUse('java.lang.Runtime');
    if (Runtime !== null && Runtime.exec !== undefined) {
        try {
            Runtime.exec.overload('java.lang.String').implementation = function (cmd) {
                if (rooty(cmd) || cmd.indexOf('which ') === 0 || cmd === 'id') {
                    note('root: Runtime.exec(' + cmd + ') -> IOException');
                    throw Java.use('java.io.IOException')
                        .$new('Cannot run program "' + cmd +
                              '": error=2, No such file or directory');
                }
                return this.exec(cmd);
            };
            ok('root', 'java.lang.Runtime.exec(String)');
        } catch (e) { /* skip */ }

        try {
            Runtime.exec.overload('[Ljava.lang.String;').implementation = function (arr) {
                var joined = Java.array('java.lang.String', arr).join(' ');
                if (rooty(joined)) {
                    note('root: Runtime.exec([' + joined + ']) -> IOException');
                    throw Java.use('java.io.IOException').$new('error=2');
                }
                return this.exec(arr);
            };
            ok('root', 'java.lang.Runtime.exec(String[])');
        } catch (e) { /* skip */ }
    }

    /* 1c. Package queries -------------------------------------------------- */
    var PM = tryUse('android.app.ApplicationPackageManager');
    if (PM !== null && PM.getPackageInfo !== undefined) {
        try {
            PM.getPackageInfo.overload('java.lang.String', 'int').implementation =
                function (pkg, flags) {
                    if (/magisk|supersu|superuser|busybox|xposed|kernelsu/i.test(pkg)) {
                        note('root: getPackageInfo(' + pkg + ') -> NameNotFound');
                        throw Java.use(
                            'android.content.pm.PackageManager$NameNotFoundException'
                        ).$new(pkg);
                    }
                    return this.getPackageInfo(pkg, flags);
                };
            ok('root', 'PackageManager.getPackageInfo');
        } catch (e) { /* skip */ }
    }

    /* 1d. Build.TAGS ------------------------------------------------------- */
    var Build = tryUse('android.os.Build');
    if (Build !== null) {
        try {
            if (String(Build.TAGS.value).indexOf('test-keys') !== -1) {
                Build.TAGS.value = 'release-keys';
                ok('root', 'Build.TAGS -> release-keys');
            }
        } catch (e) { /* skip */ }
    }

    /* 1e. RootBeer, if bundled -------------------------------------------- */
    var RootBeer = tryUse('com.scottyab.rootbeer.RootBeer');
    if (RootBeer !== null) {
        ['isRooted', 'isRootedWithoutBusyBoxCheck', 'detectRootManagementApps',
         'detectPotentiallyDangerousApps', 'checkForSuBinary', 'checkForBusyBoxBinary',
         'detectTestKeys', 'checkForDangerousProps', 'checkForRWPaths',
         'checkForRootNative', 'checkForMagiskBinary'].forEach(function (m) {
            if (RootBeer[m] === undefined) return;
            try {
                RootBeer[m].implementation = function () {
                    note('root: RootBeer.' + m + '() -> false');
                    return false;
                };
            } catch (e) { /* skip */ }
        });
        ok('root', 'RootBeer neutralised');
    }
});

/* =========================================================================
 * STAGE 2 — TLS validation, every layer.
 *
 * Three INDEPENDENT mechanisms must be defeated. Defeating only the first
 * produces the classic symptom: the proxy shows the handshake, then the app
 * reports a network error.
 * ========================================================================= */

Java.perform(function () {

    /* 2a. SSLContext / X509TrustManager --------------------------------- */
    try {
        var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        var SSLContext = Java.use('javax.net.ssl.SSLContext');

        var TrustAll = Java.registerClass({
            name: 'com.frida.bank.TrustAll',
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function (chain, authType) {},
                checkServerTrusted: function (chain, authType) {
                    try {
                        if (chain !== null && chain.length > 0) {
                            note('tls: accepting ' + chain[0].getSubjectDN());
                        }
                    } catch (e) { note('tls: checkServerTrusted bypassed'); }
                },
                getAcceptedIssuers: function () { return []; }
            }
        });

        var managers = [TrustAll.$new()];

        SSLContext.init.overload(
            '[Ljavax.net.ssl.KeyManager;',
            '[Ljavax.net.ssl.TrustManager;',
            'java.security.SecureRandom'
        ).implementation = function (km, tm, sr) {
            note('tls: SSLContext.init -> permissive TrustManager');
            this.init(km, managers, sr);
        };
        ok('tls', 'LAYER 1  SSLContext.init');
    } catch (e) {
        console.log('[-] LAYER 1 failed: ' + e.message);
    }

    /* 2b. Conscrypt TrustManagerImpl ------------------------------------- */
    // Modern OkHttp calls this DIRECTLY, bypassing SSLContext.init entirely.
    var ArrayList = tryUse('java.util.ArrayList');
    ['com.android.org.conscrypt.TrustManagerImpl',
     'org.conscrypt.TrustManagerImpl'].forEach(function (name) {
        var TMI = tryUse(name);
        if (TMI === null) return;

        if (TMI.checkTrustedRecursive !== undefined) {
            (TMI.checkTrustedRecursive.overloads || []).forEach(function (ov) {
                try {
                    ov.implementation = function () {
                        note('tls: ' + name + '.checkTrustedRecursive bypassed');
                        return ArrayList.$new();
                    };
                } catch (e) { /* skip this overload */ }
            });
            ok('tls', 'LAYER 2  ' + name + '.checkTrustedRecursive');
        }

        if (TMI.verifyChain !== undefined) {
            (TMI.verifyChain.overloads || []).forEach(function (ov) {
                try {
                    ov.implementation = function (chain) {
                        note('tls: ' + name + '.verifyChain bypassed');
                        return chain;
                    };
                } catch (e) { /* skip */ }
            });
            ok('tls', 'LAYER 2  ' + name + '.verifyChain');
        }
    });

    /* 2c. OkHttp CertificatePinner --------------------------------------- */
    // This runs AFTER the trust manager has already accepted the chain.
    var CP = tryUse('okhttp3.CertificatePinner');
    if (CP !== null && CP.check !== undefined) {
        (CP.check.overloads || []).forEach(function (ov) {
            try {
                ov.implementation = function () {
                    var host = arguments.length > 0 ? String(arguments[0]) : '?';
                    note('tls: CertificatePinner.check(' + host + ') bypassed');
                    // void — returning IS accepting.
                };
            } catch (e) { /* skip */ }
        });
        ok('tls', 'LAYER 3  okhttp3.CertificatePinner.check');
    } else {
        console.log('[.] okhttp3.CertificatePinner not present');
    }

    /* 2d. network_security_config pin-set --------------------------------- */
    // Enforced by the platform; the app may not even know it is pinned.
    ['android.security.net.config.NetworkSecurityTrustManager',
     'android.security.net.config.RootTrustManager'].forEach(function (n) {
        var K = tryUse(n);
        if (K === null || K.checkServerTrusted === undefined) return;
        (K.checkServerTrusted.overloads || []).forEach(function (ov) {
            try {
                var rt = ov.returnType.className;
                ov.implementation = function () {
                    note('tls: ' + n + '.checkServerTrusted bypassed');
                    return rt === 'void' ? undefined
                                         : (ArrayList !== null ? ArrayList.$new() : null);
                };
            } catch (e) { /* skip */ }
        });
        ok('tls', 'LAYER 4  ' + n);
    });

    /* 2e. Detect what we cannot bypass ------------------------------------ */
    ['com.google.android.gms.safetynet.SafetyNetClient',
     'com.google.android.play.core.integrity.IntegrityManager',
     'com.appmattus.certificatetransparency.internal.verifier.CertificateTransparencyInterceptor']
        .forEach(function (n) {
            if (tryUse(n) !== null) {
                report.detected.push(n);
                console.log('[!] DETECTED ' + n);
            }
        });
});

/* =========================================================================
 * STAGE 3 — native TLS, in case the Java layers were all irrelevant.
 *
 * If every hook above reports success and the proxy still sees nothing, the
 * TLS stack is native. Run this pass again a few seconds after startup, since
 * networking libraries are often dlopen'd lazily.
 * ========================================================================= */

var NATIVE_KEEP = [];       /* GC anchor — ../README.md section 7.5 */

function nativeTlsPass() {
    var customVerifyCb = new NativeCallback(function (ssl, outAlert) {
        return 0;               // ssl_verify_ok
    }, 'int', ['pointer', 'pointer']);
    NATIVE_KEEP.push(customVerifyCb);

    var found = 0;
    Process.enumerateModules().forEach(function (m) {
        if (m.name.indexOf('libart') === 0) return;

        var sym = null;
        try {
            sym = m.findExportByName
                ? m.findExportByName('SSL_CTX_set_custom_verify')
                : Module.findExportByName(m.name, 'SSL_CTX_set_custom_verify');
        } catch (e) { sym = null; }
        if (sym === null) return;

        try {
            var orig = new NativeFunction(sym, 'void', ['pointer', 'int', 'pointer']);
            Interceptor.replace(sym, new NativeCallback(function (ctx, mode, cb) {
                note('tls: native SSL_CTX_set_custom_verify -> permissive');
                orig(ctx, 0, customVerifyCb);
            }, 'void', ['pointer', 'int', 'pointer']));
            ok('tls', 'LAYER 5  ' + m.name + '!SSL_CTX_set_custom_verify');
            found++;
        } catch (e) { /* skip */ }
    });

    if (found === 0) note('no native TLS symbols in currently loaded modules');
    return found;
}

/* =========================================================================
 * STAGE 4 — observation. Prove what the bypass unlocked.
 * ========================================================================= */

Java.perform(function () {
    var URL = tryUse('java.net.URL');
    if (URL !== null) {
        try {
            URL.openConnection.overload().implementation = function () {
                console.log('[net] ' + this.toString());
                report.observed.push(String(this.toString()));
                return this.openConnection();
            };
            ok('observed', 'java.net.URL.openConnection');
        } catch (e) { /* skip */ }
    }

    var Builder = tryUse('okhttp3.Request$Builder');
    if (Builder !== null) {
        try {
            Builder.build.implementation = function () {
                var req = this.build();
                try {
                    console.log('[net] ' + req.method() + ' ' + req.url());
                    report.observed.push(req.method() + ' ' + req.url());
                } catch (e) { /* older okhttp */ }
                return req;
            };
            ok('observed', 'okhttp3.Request.Builder.build');
        } catch (e) { /* skip */ }
    }
});

/* ------------------------------------------------------------- bootstrap */

console.log('');
console.log('==================================================');
console.log('  04-banking-session');
console.log('==================================================');

nativeTlsPass();

// Deferred pass: many apps dlopen their networking library lazily, so the
// first sweep finds nothing.
setTimeout(function () {
    console.log('[*] deferred native TLS pass');
    try { nativeTlsPass(); } catch (e) { console.log('[-] ' + e.message); }
}, 6000);

setTimeout(function () {
    console.log('');
    console.log('[*] SUMMARY');
    console.log('    root hooks : ' + report.root.length);
    console.log('    tls hooks  : ' + report.tls.length);
    console.log('    observers  : ' + report.observed.length);
    if (report.detected.length > 0) {
        console.log('    NOT bypassable client-side:');
        report.detected.forEach(function (d) { console.log('      - ' + d); });
    }
    console.log('');
    console.log('[*] If traffic still does not reach the proxy:');
    console.log('    1. confirm the device proxy is set and your host is reachable');
    console.log('    2. check logcat for "Certificate pinning failure"');
    console.log('    3. the stack may be native — see ../README.md section 7.10');
    console.log('');
}, 8000);
