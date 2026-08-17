/*
 * 36-CertificatePinning/scripts/pin-attribution.js
 *
 * PURPOSE
 *   Find out WHICH pin rejected a connection -- without disabling any of them.
 *
 *   The standard tool for pinning is a bypass: hook everything, return true
 *   everywhere, hope traffic appears. When it does, you have learned nothing
 *   about the app except that it is now broken. When it does NOT, you have
 *   learned even less, because "no traffic" is the same observation whether you
 *   missed a layer, the proxy is misconfigured, or the app never connected.
 *
 *   This script does the opposite. Every pin check is wrapped, not replaced:
 *
 *       result = original(args)          <- the real check still runs
 *       if it threw  -> report WHICH layer threw, with the chain it rejected
 *       rethrow                          <- the app behaves exactly as before
 *
 *   So the app keeps working (or keeps failing) precisely as it did, and you get
 *   a transcript naming the layer that made the decision, the host, and the pin
 *   value the server WOULD have needed. That transcript is the difference
 *   between "pinning bypass failed" and "OkHttp's pinner accepted; the native
 *   BoringSSL verify callback rejected".
 *
 *   It also prints, for every certificate it sees, the SPKI pin in OkHttp's own
 *   `sha256/BASE64` format. That is the single most useful line of output here:
 *   it is exactly what a developer would paste into a CertificatePinner or a
 *   <pin-set>, computed from the certificate actually presented.
 *
 * USAGE
 *   # Deoptimise first, or hooks on hot methods may not fire (53-Frida s7.4.1):
 *   adb shell cmd package compile -m verify -f com.example.app
 *
 *   # ALWAYS spawn. Pinning is configured during application startup; attaching
 *   # to a running process means the CertificatePinner already exists.
 *   frida -U -f com.example.app -l pin-attribution.js --no-pause
 *
 *   # Then exercise the app. With a proxy set, you see the rejection. WITHOUT a
 *   # proxy, run it anyway first: that gives you the baseline of which layers
 *   # run and ACCEPT on a good connection, which is what tells you the pin is
 *   # real rather than dead code.
 *
 *   # In the REPL, at any time:
 *   %resume
 *   // then:  rpc.exports.summary()   from a client, or just wait for the
 *   //        periodic summary printed every 30 seconds.
 *
 * REQUIREMENTS
 *   frida-server on the device (16.x tested), root or a repackaged app.
 *   Java (ART) process. Native attribution additionally needs the TLS library
 *   to export SSL_CTX_set_custom_verify / SSL_CTX_set_verify -- a fully static,
 *   stripped BoringSSL will not be visible here.
 *
 * WHAT THIS WILL NOT TELL YOU
 *   * It will not get your traffic through. It is deliberately non-destructive.
 *     Use ../../53-Frida/scripts/ssl-pinning-bypass.js once you know what to
 *     bypass -- and only on an app you are authorised to test.
 *   * It cannot see a pin implemented entirely inside a stripped, statically
 *     linked native TLS stack that exports nothing. Flutter is the common case:
 *     you will see "no native verify symbols" and must move to tracing
 *     SSL_read/SSL_write or the Dart HttpClient. See ../README.md section 3.7.
 *   * It cannot see a check the app never runs. If the app decided not to
 *     connect at all (no network, killed by a root check, an earlier crash),
 *     there is nothing to attribute. Confirm the app tried.
 *   * The SPKI it prints is the pin for the certificate PRESENTED. Behind a
 *     proxy that is the proxy's key, not the real server's. Compute the real
 *     one with ../scripts/spki-pin.sh against the live host.
 *   * A rejection reported at one layer does not prove the other layers WOULD
 *     have accepted. They may never have been reached.
 *   * Obfuscated builds that renamed okhttp3 classes will show nothing at
 *     layer 3. Absence at a layer is weak evidence; presence is strong.
 *
 * AUTHORISED TESTING ONLY. Observing is not bypassing, but the target still has
 * to be yours or in scope.
 */

'use strict';

var VERBOSE_ACCEPT = true;   /* log accepted checks too, not only rejections */
var SUMMARY_SECONDS = 30;

/* -------------------------------------------------------------- bookkeeping */

var stats = {};              /* layer -> {accept: n, reject: n, lastError: s} */
var seenPins = {};           /* 'sha256/...' -> subject string */
var installed = [];
var missing = [];

function bump(layer, outcome, err) {
    if (!stats[layer]) stats[layer] = { accept: 0, reject: 0, lastError: null };
    stats[layer][outcome]++;
    if (err) stats[layer].lastError = err;
}

function tryUse(name) {
    try { return Java.use(name); } catch (e) { return null; }
}

function ok(what) { installed.push(what); console.log('[+] watching ' + what); }
function no(what, why) { missing.push(what); console.log('[.] absent  ' + what + ' (' + why + ')'); }

function accepted(layer, detail) {
    bump(layer, 'accept');
    if (VERBOSE_ACCEPT) console.log('[ok  ] ' + layer + '  ' + (detail || ''));
}

function rejected(layer, detail, e) {
    var msg = '';
    try { msg = e && e.message ? e.message : String(e); } catch (x) { msg = '?'; }
    bump(layer, 'reject', msg);
    console.log('');
    console.log('################################################################');
    console.log('#  REJECTED BY: ' + layer);
    console.log('#  ' + (detail || ''));
    console.log('#  exception : ' + msg);
    console.log('################################################################');
    console.log('');
}

/* ---------------------------------------------------------- SPKI pin format
 *
 * OkHttp's pin is base64(SHA-256(SubjectPublicKeyInfo)). Note carefully WHAT is
 * hashed: not the certificate, but the DER-encoded SubjectPublicKeyInfo -- the
 * algorithm identifier plus the public key bit string. `PublicKey.getEncoded()`
 * on an X509Certificate's public key returns exactly that structure in "X.509"
 * format, which is why this three-line function produces byte-identical output
 * to `openssl x509 -pubkey | openssl pkey -pubin -outform der | sha256 | base64`.
 *
 * Hashing the SPKI rather than the whole certificate is the entire reason a pin
 * can survive certificate renewal: renewing re-signs the SAME key, so the SPKI
 * -- and therefore the pin -- does not change. See ../README.md section 3.4.
 */

var MessageDigest = null;
var Base64 = null;

function spkiPin(cert) {
    try {
        if (MessageDigest === null) MessageDigest = Java.use('java.security.MessageDigest');
        if (Base64 === null) Base64 = Java.use('android.util.Base64');
        var md = MessageDigest.getInstance('SHA-256');
        var der = cert.getPublicKey().getEncoded();
        var digest = md.digest(der);
        return 'sha256/' + Base64.encodeToString(digest, 2 /* NO_WRAP */);
    } catch (e) {
        return '(spki unavailable: ' + e.message + ')';
    }
}

function describeChain(chain) {
    /* chain may be a Java array or a java.util.List; handle both. */
    var out = [];
    try {
        var n = (chain.length !== undefined) ? chain.length : chain.size();
        for (var i = 0; i < n; i++) {
            var c = (chain.length !== undefined) ? chain[i] : chain.get(i);
            var subj = '?';
            try { subj = c.getSubjectDN().toString(); } catch (e) { }
            var pin = spkiPin(c);
            seenPins[pin] = subj;
            out.push('    [' + i + '] ' + pin + '   ' + subj);
        }
    } catch (e) {
        out.push('    (chain not enumerable: ' + e.message + ')');
    }
    return out.join('\n');
}

function chainSummary(chain, host) {
    var head = 'host=' + (host || '?');
    var body = describeChain(chain);
    return head + '\n' + body;
}

/* =========================================================================
 * LAYER 3 -- okhttp3.CertificatePinner
 *
 * Watched FIRST because it is the layer people mean when they say "the app
 * pins", and because its exception message is unambiguous: OkHttp prints the
 * pins it expected and the pins it computed, side by side, which is a complete
 * diagnosis in one string.
 * ========================================================================= */

function watchOkHttp() {
    var CP = tryUse('okhttp3.CertificatePinner');
    if (CP === null) { no('okhttp3.CertificatePinner', 'not on the classpath'); return; }

    var count = 0;
    ['check', 'check$okhttp'].forEach(function (m) {
        if (CP[m] === undefined) return;
        (CP[m].overloads || []).forEach(function (ov) {
            try {
                ov.implementation = function () {
                    var host = '?';
                    try { host = String(arguments[0]); } catch (e) { }
                    try {
                        var r = ov.apply(this, arguments);
                        accepted('L3 okhttp3.CertificatePinner.' + m, 'host=' + host);
                        return r;
                    } catch (e) {
                        /* OkHttp's message already contains expected vs found pins. */
                        rejected('L3 okhttp3.CertificatePinner.' + m, 'host=' + host, e);
                        throw e;          /* preserve app behaviour exactly */
                    }
                };
                count++;
            } catch (e) { /* unhookable overload */ }
        });
    });

    /* The configured pin set, read straight out of the object. This is the
     * answer to "what is it pinning?" and it is often easier than decompiling. */
    try {
        if (CP.pins !== undefined) {
            ok('okhttp3.CertificatePinner (' + count + ' method(s)); pin set readable');
        } else {
            ok('okhttp3.CertificatePinner (' + count + ' method(s))');
        }
    } catch (e) { ok('okhttp3.CertificatePinner (' + count + ' method(s))'); }

    /* CertificatePinner.Builder.add tells you the pins as they are configured,
     * which happens once, at startup -- hence the "always spawn with -f" rule. */
    var B = tryUse('okhttp3.CertificatePinner$Builder');
    if (B !== null && B.add !== undefined) {
        try {
            (B.add.overloads || []).forEach(function (ov) {
                ov.implementation = function () {
                    try {
                        var pattern = String(arguments[0]);
                        var pins = arguments[1];
                        var list = [];
                        for (var i = 0; i < pins.length; i++) list.push(String(pins[i]));
                        console.log('[cfg ] CertificatePinner.Builder.add("' + pattern +
                                    '", ' + list.join(', ') + ')');
                    } catch (e) { console.log('[cfg ] CertificatePinner.Builder.add(...)'); }
                    return ov.apply(this, arguments);
                };
            });
            ok('okhttp3.CertificatePinner$Builder.add (configuration trace)');
        } catch (e) { /* skip */ }
    }
}

/* =========================================================================
 * LAYER 2 -- Conscrypt TrustManagerImpl
 *
 * The platform's real trust manager. Modern OkHttp calls it directly rather
 * than through SSLContext, which is why a bypass that only handles layer 1
 * misses it. Here we only want to know whether it accepted, and what chain it
 * saw -- the chain print is what gives you the SPKI values.
 * ========================================================================= */

function watchConscrypt() {
    ['com.android.org.conscrypt.TrustManagerImpl',
     'org.conscrypt.TrustManagerImpl',
     'com.google.android.gms.org.conscrypt.TrustManagerImpl'].forEach(function (name) {

        var K = tryUse(name);
        if (K === null) { no(name, 'not present'); return; }

        var hooked = 0;
        ['checkServerTrusted', 'checkTrustedRecursive', 'verifyChain'].forEach(function (m) {
            if (K[m] === undefined) return;
            (K[m].overloads || []).forEach(function (ov) {
                try {
                    ov.implementation = function () {
                        var host = '';
                        try {
                            /* Several overloads carry the hostname as the 3rd arg. */
                            if (arguments.length >= 3 && typeof arguments[2] === 'string') {
                                host = String(arguments[2]);
                            }
                        } catch (e) { }
                        try {
                            var r = ov.apply(this, arguments);
                            if (VERBOSE_ACCEPT) {
                                var detail = 'host=' + (host || '?');
                                try {
                                    if (arguments[0] !== null) {
                                        detail = chainSummary(arguments[0], host);
                                    }
                                } catch (e) { }
                                accepted('L2 ' + name + '.' + m, detail);
                            } else {
                                bump('L2 ' + name + '.' + m, 'accept');
                            }
                            return r;
                        } catch (e) {
                            var d = 'host=' + (host || '?');
                            try { d = chainSummary(arguments[0], host); } catch (x) { }
                            rejected('L2 ' + name + '.' + m, d, e);
                            throw e;
                        }
                    };
                    hooked++;
                } catch (e) { /* skip overload */ }
            });
        });
        if (hooked > 0) ok(name + ' (' + hooked + ' method(s))');
    });
}

/* =========================================================================
 * LAYER 5 -- network_security_config <pin-set>
 *
 * Enforced by the platform. There is no app code involved, which is exactly
 * what makes it confusing: an app with no networking code of its own can still
 * refuse your proxy, and no amount of reading its DEX explains why.
 *
 * NetworkSecurityTrustManager throws when the pin set does not match. Its
 * message names the pins, so it is worth catching precisely.
 * ========================================================================= */

function watchNetworkSecurityConfig() {
    ['android.security.net.config.NetworkSecurityTrustManager',
     'android.security.net.config.RootTrustManager'].forEach(function (name) {

        var K = tryUse(name);
        if (K === null) { no(name, 'not present on this API level'); return; }

        var hooked = 0;
        ['checkServerTrusted', 'checkPins'].forEach(function (m) {
            if (K[m] === undefined) return;
            (K[m].overloads || []).forEach(function (ov) {
                try {
                    ov.implementation = function () {
                        try {
                            var r = ov.apply(this, arguments);
                            accepted('L5 ' + name + '.' + m, '');
                            return r;
                        } catch (e) {
                            var d = '';
                            try { d = chainSummary(arguments[0], ''); } catch (x) { }
                            rejected('L5 ' + name + '.' + m, d, e);
                            throw e;
                        }
                    };
                    hooked++;
                } catch (e) { /* skip */ }
            });
        });
        if (hooked > 0) ok(name + ' (' + hooked + ' method(s))');
    });
}

/* =========================================================================
 * LAYER 1 -- the app's OWN X509TrustManager, and X509TrustManagerExtensions
 *
 * This is where hand-rolled pins live. Enumerating loaded classes and testing
 * each for the interface is the only reliable way to find them: the class will
 * be called something like `a.b.c.d` after R8, and there is no fixed name to
 * look up.
 *
 * Cost note: enumerateLoadedClasses walks every loaded class. On a large app
 * that is thousands of entries and takes a moment. It is done ONCE, at startup,
 * deliberately -- and it is the reason this script wants -f rather than -p.
 * ========================================================================= */

function watchCustomTrustManagers() {
    var Ext = tryUse('android.net.http.X509TrustManagerExtensions');
    if (Ext !== null && Ext.checkServerTrusted !== undefined) {
        try {
            (Ext.checkServerTrusted.overloads || []).forEach(function (ov) {
                ov.implementation = function () {
                    var host = '?';
                    try { host = String(arguments[2]); } catch (e) { }
                    try {
                        var r = ov.apply(this, arguments);
                        accepted('L1b X509TrustManagerExtensions.checkServerTrusted',
                                 chainSummary(r, host));
                        return r;
                    } catch (e) {
                        var d = '';
                        try { d = chainSummary(arguments[0], host); } catch (x) { }
                        rejected('L1b X509TrustManagerExtensions.checkServerTrusted', d, e);
                        throw e;
                    }
                };
            });
            ok('android.net.http.X509TrustManagerExtensions');
        } catch (e) { no('X509TrustManagerExtensions', e.message); }
    } else {
        no('android.net.http.X509TrustManagerExtensions', 'not used');
    }

    var found = 0;
    try {
        Java.enumerateLoadedClassesSync().forEach(function (name) {
            /* Cheap filters first: the platform's own implementations are watched
             * separately, and synthetic classes cannot implement an interface. */
            if (name.indexOf('android.') === 0) return;
            if (name.indexOf('com.android.org.conscrypt') === 0) return;
            if (name.indexOf('java.') === 0 || name.indexOf('javax.') === 0) return;
            if (name.indexOf('com.frida.') === 0) return;

            var K = tryUse(name);
            if (K === null) return;
            var isTM = false;
            try {
                var ifaces = K.class.getInterfaces();
                for (var i = 0; i < ifaces.length; i++) {
                    var iname = ifaces[i].getName();
                    if (iname === 'javax.net.ssl.X509TrustManager' ||
                        iname === 'javax.net.ssl.TrustManager') { isTM = true; break; }
                }
            } catch (e) { return; }
            if (!isTM) return;
            if (K.checkServerTrusted === undefined) return;

            (K.checkServerTrusted.overloads || []).forEach(function (ov) {
                try {
                    ov.implementation = function () {
                        var host = '';
                        try {
                            if (arguments.length >= 3) host = String(arguments[2]);
                        } catch (e) { }
                        try {
                            var r = ov.apply(this, arguments);
                            accepted('L1 ' + name + '.checkServerTrusted',
                                     chainSummary(arguments[0], host));
                            return r;
                        } catch (e) {
                            var d = '';
                            try { d = chainSummary(arguments[0], host); } catch (x) { }
                            rejected('L1 ' + name + '.checkServerTrusted', d, e);
                            throw e;
                        }
                    };
                } catch (e) { /* skip */ }
            });
            found++;
            ok('custom TrustManager: ' + name);
        });
    } catch (e) {
        no('loaded-class enumeration', e.message);
    }
    if (found === 0) {
        no('custom X509TrustManager', 'none loaded YET -- rerun watchCustom() later');
    }
}

/* =========================================================================
 * LAYER 4 -- HostnameVerifier
 *
 * Not a pin, and included precisely because it is misattributed as one. A
 * hostname mismatch and a pin mismatch both surface to the user as "cannot
 * connect", and both surface to the developer as an SSLException. The
 * distinction matters: a hostname failure usually means your proxy generated a
 * certificate for the wrong SNI, which is YOUR bug, not the app's control.
 * ========================================================================= */

function watchHostnameVerifiers() {
    var found = 0;
    try {
        Java.enumerateLoadedClassesSync().forEach(function (name) {
            if (name.indexOf('com.frida.') === 0) return;
            var K = tryUse(name);
            if (K === null || K.verify === undefined) return;
            var isHV = false;
            try {
                var ifaces = K.class.getInterfaces();
                for (var i = 0; i < ifaces.length; i++) {
                    if (ifaces[i].getName() === 'javax.net.ssl.HostnameVerifier') {
                        isHV = true; break;
                    }
                }
            } catch (e) { return; }
            if (!isHV) return;

            (K.verify.overloads || []).forEach(function (ov) {
                try {
                    ov.implementation = function () {
                        var host = '?';
                        try { host = String(arguments[0]); } catch (e) { }
                        var r = ov.apply(this, arguments);
                        if (r === false) {
                            rejected('L4 ' + name + '.verify', 'host=' + host,
                                     { message: 'returned false (hostname mismatch) -- ' +
                                                'this is NOT a pin failure' });
                        } else {
                            accepted('L4 ' + name + '.verify', 'host=' + host);
                        }
                        return r;
                    };
                } catch (e) { /* skip */ }
            });
            found++;
        });
    } catch (e) { /* enumeration unavailable */ }
    if (found > 0) ok(found + ' HostnameVerifier implementation(s)');
    else no('HostnameVerifier', 'none loaded yet');
}

/* =========================================================================
 * LAYER 6/7 -- native TLS verification
 *
 * We do NOT replace the verify callback. We record:
 *   - that SSL_CTX_set_custom_verify / SSL_CTX_set_verify was called at all,
 *     and with which mode. Mode 0 is SSL_VERIFY_NONE: an app that installs a
 *     custom_verify callback with mode 0 is doing its verification INSIDE the
 *     callback, which is the classic native pin shape.
 *   - the callback address, so you can attach to it and see its return value.
 *
 * ssl_verify_result_t (BoringSSL): 0 = ssl_verify_ok, 1 = ssl_verify_invalid,
 * 2 = ssl_verify_retry. A callback returning 1 is the native pin rejecting.
 * ========================================================================= */

var NATIVE_KEEP = [];
var nativeCallbacksSeen = {};

function attachToVerifyCallback(addr, origin) {
    var key = addr.toString();
    if (nativeCallbacksSeen[key]) return;
    nativeCallbacksSeen[key] = true;
    try {
        Interceptor.attach(addr, {
            onLeave: function (retval) {
                var v = retval.toInt32();
                if (v === 0) {
                    accepted('L7 native verify callback @' + key + ' (' + origin + ')',
                             'ssl_verify_ok');
                } else {
                    rejected('L7 native verify callback @' + key + ' (' + origin + ')',
                             'callback returned ' + v +
                             ' (1 = ssl_verify_invalid, 2 = ssl_verify_retry)',
                             { message: 'native verification failed INSIDE the app\'s own ' +
                                        'callback -- no Java hook can change this' });
                }
            }
        });
        console.log('[+] attached to native verify callback @' + key + ' (' + origin + ')');
    } catch (e) {
        console.log('[-] could not attach to callback @' + key + ': ' + e.message);
    }
}

function watchNative() {
    var modules = Process.enumerateModules();
    var found = 0;

    modules.forEach(function (m) {
        if (m.name.indexOf('libart') === 0) return;

        [['SSL_CTX_set_custom_verify', 3], ['SSL_CTX_set_verify', 3],
         ['SSL_set_custom_verify', 3]].forEach(function (pair) {
            var sym = pair[0];
            var addr = null;
            try {
                addr = m.findExportByName ? m.findExportByName(sym)
                                          : Module.findExportByName(m.name, sym);
            } catch (e) { addr = null; }
            if (addr === null) return;

            try {
                Interceptor.attach(addr, {
                    onEnter: function (args) {
                        var mode = args[1].toInt32();
                        var cb = args[2];
                        console.log('[cfg ] ' + m.name + '!' + sym +
                                    '(ctx=' + args[0] + ', mode=' + mode +
                                    ', cb=' + cb + ')');
                        if (mode === 0 && !cb.isNull()) {
                            console.log('       mode=0 (SSL_VERIFY_NONE) WITH a callback: ' +
                                        'verification is happening inside the callback. ' +
                                        'That is the native-pin shape.');
                        }
                        if (!cb.isNull()) attachToVerifyCallback(cb, m.name + '!' + sym);
                    }
                });
                ok('native ' + m.name + '!' + sym);
                found++;
            } catch (e) {
                no(m.name + '!' + sym, e.message);
            }
        });
    });

    if (found === 0) {
        no('native TLS verify symbols',
           'none exported by any loaded module');
        console.log('    If the Java layers all ACCEPT and the proxy still sees nothing,');
        console.log('    the TLS stack is native and stripped. Flutter is the usual answer:');
        console.log('    check for libflutter.so / libapp.so, and see ../README.md s3.7.');
    }
}

/* ------------------------------------------------------------------ summary */

function summary() {
    var lines = [];
    lines.push('');
    lines.push('=================== pin attribution summary ===================');
    var any = false;
    Object.keys(stats).sort().forEach(function (layer) {
        any = true;
        var s = stats[layer];
        lines.push('  ' + layer);
        lines.push('      accepted ' + s.accept + '   rejected ' + s.reject +
                   (s.lastError ? ('   last: ' + s.lastError.substring(0, 90)) : ''));
    });
    if (!any) lines.push('  no pin check has run yet. Has the app made a request?');

    var pins = Object.keys(seenPins);
    if (pins.length > 0) {
        lines.push('');
        lines.push('  certificates observed, as pins you could configure:');
        pins.forEach(function (p) {
            lines.push('      ' + p + '   ' + seenPins[p]);
        });
        lines.push('');
        lines.push('  NOTE: behind a proxy these are the PROXY\'s keys. Compute the');
        lines.push('  real ones with spki-pin.sh against the live host.');
    }
    lines.push('==============================================================');
    lines.push('');
    var text = lines.join('\n');
    console.log(text);
    return text;
}

rpc.exports = {
    summary: summary,
    /* Re-run the enumerating watchers after the app has loaded more classes.
     * Custom TrustManagers are frequently loaded lazily, on the first request. */
    rescan: function () {
        Java.perform(function () {
            watchCustomTrustManagers();
            watchHostnameVerifiers();
        });
        watchNative();
        return 'rescan complete';
    }
};

/* ---------------------------------------------------------------- bootstrap */

Java.perform(function () {
    console.log('');
    console.log('==============================================================');
    console.log('  pin-attribution.js -- WATCH, do not bypass');
    console.log('  every check still runs; we only report who said no');
    console.log('==============================================================');
    console.log('');

    watchOkHttp();
    watchConscrypt();
    watchNetworkSecurityConfig();
    watchCustomTrustManagers();
    watchHostnameVerifiers();

    console.log('');
    console.log('[*] ' + installed.length + ' watcher(s) installed, ' +
                missing.length + ' layer(s) absent.');
    console.log('[*] Exercise the app. A rejection prints a boxed REJECTED BY block.');
    console.log('[*] Summary every ' + SUMMARY_SECONDS + 's, or call rpc.exports.summary().');
    console.log('');
});

/* Native last: enumerating modules is the slow step, and networking libraries
 * are often dlopen'd only after the first Activity is created. */
setTimeout(function () {
    try { watchNative(); } catch (e) { console.log('[-] native watch: ' + e.message); }
}, 1500);

setTimeout(function () {
    console.log('[*] deferred rescan (classes and modules loaded since startup)');
    try {
        Java.perform(function () {
            watchCustomTrustManagers();
            watchHostnameVerifiers();
        });
        watchNative();
    } catch (e) { console.log('[-] deferred rescan: ' + e.message); }
}, 8000);

setInterval(summary, SUMMARY_SECONDS * 1000);
