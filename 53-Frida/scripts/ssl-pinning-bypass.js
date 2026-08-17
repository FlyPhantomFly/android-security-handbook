/*
 * ssl-pinning-bypass.js — universal TLS validation / certificate pinning bypass.
 *
 * WHAT IT DOES
 *   Neutralises every layer at which an Android app can validate a server
 *   certificate. There are SIX independent layers, and defeating one is not
 *   enough — the classic symptom of a partial bypass is "Burp shows the
 *   handshake, then the app reports a network error".
 *
 *     1. javax.net.ssl.SSLContext / X509TrustManager  (HttpsURLConnection and
 *        anything built on SSLContext)
 *     2. Conscrypt TrustManagerImpl                    (the platform provider that
 *        newer OkHttp calls directly, bypassing layer 1)
 *     3. okhttp3.CertificatePinner                     (runs AFTER the trust
 *        manager has already accepted)
 *     4. javax.net.ssl.HostnameVerifier                (rejects on CN/SAN mismatch
 *        even when the chain is trusted)
 *     5. network_security_config <pin-set>             (enforced by the platform
 *        NetworkSecurityTrustManager, invisible in app code)
 *     6. Native TLS stacks                             (BoringSSL statically linked
 *        into Flutter / Cronet / a custom .so — no Java hook reaches these)
 *
 *   Plus best-effort coverage of common third-party stacks: Apache HttpClient,
 *   Volley, Retrofit's underlying client, Cordova/Ionic WebView, Xamarin,
 *   Appmattus CertificateTransparency, and the TrustKit library.
 *
 *   Every hook is independently guarded. A class that is not present on this
 *   device or in this app is reported and skipped — it is not an error.
 *
 * WHY IT WORKS
 *   All of these are decisions made by code running inside the app's own
 *   process. See ../README.md section 5 for why that is not a defensible place
 *   to make a trust decision, and ../../36-CertificatePinning/README.md for the
 *   layer-by-layer background.
 *
 * HOW TO RUN
 *   # Make hooks reliable first (see ../README.md section 7.4.1):
 *   adb shell cmd package compile -m verify -f com.example.app
 *   adb shell am force-stop com.example.app
 *
 *   # Point the device at your proxy:
 *   adb shell settings put global http_proxy 192.168.1.10:8080
 *
 *   # ALWAYS spawn with -f. Pinning is configured during startup (section 7.4.4).
 *   frida -U -f com.example.app -l ssl-pinning-bypass.js --no-pause
 *
 *   # Clean up afterwards:
 *   adb shell settings put global http_proxy :0
 *
 * TUNING
 *   Set VERBOSE to false to silence per-call logging once you have confirmed
 *   which layers are actually in use.
 *
 * AUTHORISED TESTING ONLY.
 */

'use strict';

var VERBOSE = true;

/* ------------------------------------------------------------------ utility */

var installed = [];
var skipped = [];

function ok(what) {
    installed.push(what);
    console.log('[+] ' + what);
}

function no(what, why) {
    skipped.push(what);
    if (VERBOSE) console.log('[.] skipped ' + what + ' (' + why + ')');
}

function log(msg) {
    if (VERBOSE) console.log('    ' + msg);
}

/*
 * Guarded class lookup. A missing class is the NORMAL case: no app uses all
 * six layers, and platform classes differ across API levels. Never let one
 * missing class abort the whole script.
 */
function tryUse(name) {
    try {
        return Java.use(name);
    } catch (e) {
        return null;
    }
}

/*
 * Guarded native symbol lookup that works on both Frida 16 and Frida 17.
 * Frida 17 reorganised the Module API; library code must handle both because
 * you do not control which version the operator installed.
 */
function resolveExport(moduleName, symbolName) {
    try {
        if (moduleName === null && typeof Module.getGlobalExportByName === 'function') {
            return Module.getGlobalExportByName(symbolName);
        }
    } catch (e) { /* fall through */ }

    try {
        if (typeof Process.findModuleByName === 'function' && moduleName !== null) {
            var m = Process.findModuleByName(moduleName);
            if (m !== null && typeof m.findExportByName === 'function') {
                var a = m.findExportByName(symbolName);
                if (a !== null) return a;
            }
        }
    } catch (e) { /* fall through */ }

    try {
        return Module.findExportByName(moduleName, symbolName);
    } catch (e) {
        return null;
    }
}

/* =========================================================================
 * LAYER 1 — SSLContext + X509TrustManager
 *
 * The platform builds an SSLContext from an array of TrustManagers. If we
 * substitute our own permissive TrustManager at init() time, every socket
 * created from that context accepts any chain.
 *
 * This covers HttpsURLConnection, older OkHttp, Retrofit-over-OkHttp when the
 * app supplies its own SSLContext, and most hand-rolled socket code.
 * ========================================================================= */

function layer1_sslContext() {
    var X509TrustManager = tryUse('javax.net.ssl.X509TrustManager');
    var SSLContext = tryUse('javax.net.ssl.SSLContext');

    if (X509TrustManager === null || SSLContext === null) {
        no('SSLContext / X509TrustManager', 'classes not found');
        return;
    }

    var TrustAll;
    try {
        TrustAll = Java.registerClass({
            name: 'com.frida.bypass.TrustAll',
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function (chain, authType) { /* accept */ },
                checkServerTrusted: function (chain, authType) {
                    if (VERBOSE && chain !== null && chain.length > 0) {
                        try {
                            log('checkServerTrusted bypassed: ' +
                                chain[0].getSubjectDN().toString());
                        } catch (e) { log('checkServerTrusted bypassed'); }
                    }
                },
                getAcceptedIssuers: function () { return []; }
            }
        });
    } catch (e) {
        no('TrustAll registerClass', e.message);
        return;
    }

    var managers = [TrustAll.$new()];

    // SSLContext.init has exactly one signature, but guard anyway: some
    // vendor images ship modified platform classes.
    try {
        SSLContext.init.overload(
            '[Ljavax.net.ssl.KeyManager;',
            '[Ljavax.net.ssl.TrustManager;',
            'java.security.SecureRandom'
        ).implementation = function (km, tm, sr) {
            log('SSLContext.init -> substituting permissive TrustManager');
            this.init(km, managers, sr);
        };
        ok('LAYER 1: SSLContext.init');
    } catch (e) {
        no('SSLContext.init', e.message);
    }

    // TrustManagerFactory.getTrustManagers is the other route to the same array.
    var TMF = tryUse('javax.net.ssl.TrustManagerFactory');
    if (TMF !== null) {
        try {
            TMF.getTrustManagers.implementation = function () {
                log('TrustManagerFactory.getTrustManagers -> permissive array');
                return managers;
            };
            ok('LAYER 1: TrustManagerFactory.getTrustManagers');
        } catch (e) {
            no('TrustManagerFactory.getTrustManagers', e.message);
        }
    }
}

/* =========================================================================
 * LAYER 2 — Conscrypt TrustManagerImpl
 *
 * Modern OkHttp obtains the platform TrustManagerImpl and calls
 * checkServerTrusted / checkTrustedRecursive on it DIRECTLY, without going
 * through SSLContext.init. Layer 1 alone therefore misses it entirely.
 *
 * The class lives in com.android.org.conscrypt on the platform and in
 * org.conscrypt when the app bundles its own copy. Method signatures vary by
 * API level, so every overload is attempted independently.
 * ========================================================================= */

function layer2_conscrypt() {
    var candidates = [
        'com.android.org.conscrypt.TrustManagerImpl',
        'org.conscrypt.TrustManagerImpl',
        'com.google.android.gms.org.conscrypt.TrustManagerImpl'
    ];

    var ArrayList = tryUse('java.util.ArrayList');
    if (ArrayList === null) {
        no('LAYER 2', 'java.util.ArrayList missing — impossible, aborting layer');
        return;
    }

    candidates.forEach(function (name) {
        var TMI = tryUse(name);
        if (TMI === null) { no(name, 'not present'); return; }

        // checkTrustedRecursive: the internal worker. Returning an empty list
        // means "this chain is fine". Several overloads exist across releases.
        if (TMI.checkTrustedRecursive !== undefined) {
            var overloads = TMI.checkTrustedRecursive.overloads || [TMI.checkTrustedRecursive];
            overloads.forEach(function (ov) {
                try {
                    ov.implementation = function () {
                        log(name + '.checkTrustedRecursive bypassed');
                        return ArrayList.$new();
                    };
                } catch (e) { /* skip this overload */ }
            });
            ok('LAYER 2: ' + name + '.checkTrustedRecursive (' + overloads.length + ' overload(s))');
        }

        // verifyChain: the API 24-27 name for essentially the same thing. It
        // returns the chain it was given, so echo the input back.
        if (TMI.verifyChain !== undefined) {
            var vOverloads = TMI.verifyChain.overloads || [TMI.verifyChain];
            vOverloads.forEach(function (ov) {
                try {
                    ov.implementation = function (untrustedChain) {
                        log(name + '.verifyChain bypassed');
                        return untrustedChain;
                    };
                } catch (e) { /* skip */ }
            });
            ok('LAYER 2: ' + name + '.verifyChain');
        }

        // checkServerTrusted: the public entry point.
        if (TMI.checkServerTrusted !== undefined) {
            var cOverloads = TMI.checkServerTrusted.overloads || [];
            cOverloads.forEach(function (ov) {
                try {
                    // Overloads that return List<X509Certificate> must return a
                    // list; the void ones must return nothing. Inspect the type.
                    var rt = ov.returnType.className;
                    ov.implementation = function () {
                        log(name + '.checkServerTrusted bypassed -> ' + rt);
                        if (rt === 'void') return;
                        return ArrayList.$new();
                    };
                } catch (e) { /* skip */ }
            });
            if (cOverloads.length > 0) {
                ok('LAYER 2: ' + name + '.checkServerTrusted (' + cOverloads.length + ')');
            }
        }
    });
}

/* =========================================================================
 * LAYER 3 — OkHttp CertificatePinner
 *
 * This is the pin check proper. It runs AFTER the trust manager has already
 * accepted the chain: OkHttp validates trust, then checks that one of the
 * chain's public-key hashes matches a configured pin. Defeating layers 1 and 2
 * without this one produces "Certificate pinning failure!" in logcat.
 *
 * R8 renames application classes but NOT library classes it is told to keep,
 * and okhttp3 is almost always kept. If it has been renamed, hook
 * `check` by signature instead — see class-enumerator.js.
 * ========================================================================= */

function layer3_okhttp() {
    var CP = tryUse('okhttp3.CertificatePinner');
    if (CP === null) { no('LAYER 3: okhttp3.CertificatePinner', 'not present'); return; }

    var hooked = 0;

    // `check` has several signatures across OkHttp 3.x and 4.x. Hook them all.
    if (CP.check !== undefined) {
        (CP.check.overloads || []).forEach(function (ov) {
            try {
                var args = ov.argumentTypes.map(function (t) { return t.className; });
                ov.implementation = function () {
                    var host = arguments.length > 0 ? String(arguments[0]) : '?';
                    log('CertificatePinner.check(' + host + ') bypassed [' +
                        args.join(', ') + ']');
                    // void return: simply returning IS accepting.
                };
                hooked++;
            } catch (e) { /* skip */ }
        });
    }

    // OkHttp 4 (Kotlin) also exposes check$okhttp.
    if (CP['check$okhttp'] !== undefined) {
        (CP['check$okhttp'].overloads || []).forEach(function (ov) {
            try {
                ov.implementation = function () {
                    log('CertificatePinner.check$okhttp bypassed');
                };
                hooked++;
            } catch (e) { /* skip */ }
        });
    }

    if (hooked > 0) ok('LAYER 3: okhttp3.CertificatePinner (' + hooked + ' method(s))');
    else no('LAYER 3: okhttp3.CertificatePinner', 'no hookable check method');

    // OkHttp's own trust chain cleaner, used when the app supplies a custom
    // TrustManager. Returning the input unchanged short-circuits the cleaning.
    ['okhttp3.internal.tls.OkHostnameVerifier',
     'okhttp3.internal.tls.BasicCertificateChainCleaner'].forEach(function (n) {
        var K = tryUse(n);
        if (K === null) return;
        if (K.verify !== undefined) {
            (K.verify.overloads || []).forEach(function (ov) {
                try {
                    ov.implementation = function () {
                        log(n + '.verify -> true');
                        return true;
                    };
                } catch (e) { /* skip */ }
            });
            ok('LAYER 3: ' + n + '.verify');
        }
        if (K.clean !== undefined) {
            (K.clean.overloads || []).forEach(function (ov) {
                try {
                    ov.implementation = function (chain, hostname) {
                        log(n + '.clean -> passthrough');
                        return chain;
                    };
                } catch (e) { /* skip */ }
            });
            ok('LAYER 3: ' + n + '.clean');
        }
    });
}

/* =========================================================================
 * LAYER 4 — HostnameVerifier
 *
 * Even with a trusted chain, the platform rejects a certificate whose CN/SAN
 * does not match the host. An intercepting proxy generates a certificate for
 * the right hostname, so this usually passes — but apps that implement a
 * strict custom verifier, or that verify a pinned CN, will still fail.
 * ========================================================================= */

function layer4_hostnameVerifier() {
    var HttpsURLConnection = tryUse('javax.net.ssl.HttpsURLConnection');
    var HostnameVerifier = tryUse('javax.net.ssl.HostnameVerifier');

    if (HostnameVerifier !== null) {
        try {
            var AllowAll = Java.registerClass({
                name: 'com.frida.bypass.AllowAllHostnames',
                implements: [HostnameVerifier],
                methods: {
                    verify: function (hostname, session) {
                        log('HostnameVerifier.verify(' + hostname + ') -> true');
                        return true;
                    }
                }
            });

            if (HttpsURLConnection !== null) {
                HttpsURLConnection.setDefaultHostnameVerifier.implementation = function (v) {
                    log('setDefaultHostnameVerifier -> permissive');
                    return this.setDefaultHostnameVerifier(AllowAll.$new());
                };
                HttpsURLConnection.setHostnameVerifier.implementation = function (v) {
                    log('setHostnameVerifier -> permissive');
                    return this.setHostnameVerifier(AllowAll.$new());
                };
                ok('LAYER 4: HttpsURLConnection hostname verifiers');
            }
        } catch (e) {
            no('LAYER 4: HostnameVerifier', e.message);
        }
    }

    // Hook every loaded implementation of HostnameVerifier, including the app's
    // own. Done lazily so it catches classes loaded after this script runs.
    try {
        var HV = tryUse('javax.net.ssl.HostnameVerifier');
        if (HV !== null) {
            Java.enumerateLoadedClasses({
                onMatch: function (name) {
                    if (name.indexOf('$') !== -1) return;          // skip synthetics
                    var K = tryUse(name);
                    if (K === null) return;
                    try {
                        var ifaces = K.class.getInterfaces();
                        for (var i = 0; i < ifaces.length; i++) {
                            if (ifaces[i].getName() === 'javax.net.ssl.HostnameVerifier') {
                                K.verify.implementation = function () { return true; };
                                ok('LAYER 4: ' + name + '.verify -> true');
                                break;
                            }
                        }
                    } catch (e) { /* not inspectable */ }
                },
                onComplete: function () {}
            });
        }
    } catch (e) { /* enumeration unavailable */ }
}

/* =========================================================================
 * LAYER 5 — network_security_config <pin-set>
 *
 * Declared in res/xml and enforced by the platform's
 * NetworkSecurityTrustManager. There is no app code to hook — the app may not
 * even know it is pinned. This is why a "pinning bypass" that only handles
 * OkHttp sometimes fails on an app with no OkHttp code at all.
 * ========================================================================= */

function layer5_networkSecurityConfig() {
    var candidates = [
        'android.security.net.config.NetworkSecurityTrustManager',
        'android.security.net.config.RootTrustManager'
    ];

    var ArrayList = tryUse('java.util.ArrayList');

    candidates.forEach(function (name) {
        var K = tryUse(name);
        if (K === null) { no(name, 'not present'); return; }

        if (K.checkServerTrusted !== undefined) {
            (K.checkServerTrusted.overloads || []).forEach(function (ov) {
                try {
                    var rt = ov.returnType.className;
                    ov.implementation = function () {
                        log(name + '.checkServerTrusted bypassed');
                        if (rt === 'void') return;
                        return ArrayList !== null ? ArrayList.$new() : null;
                    };
                } catch (e) { /* skip */ }
            });
            ok('LAYER 5: ' + name + '.checkServerTrusted');
        }

        // The pin check itself, when the platform separates it out.
        if (K.checkPins !== undefined) {
            (K.checkPins.overloads || []).forEach(function (ov) {
                try {
                    ov.implementation = function () {
                        log(name + '.checkPins bypassed');
                    };
                } catch (e) { /* skip */ }
            });
            ok('LAYER 5: ' + name + '.checkPins');
        }
    });

    // NetworkSecurityConfig.isCleartextTrafficPermitted — lets you see plain
    // HTTP through the proxy on apps that block it.
    var NSC = tryUse('android.security.net.config.NetworkSecurityConfig');
    if (NSC !== null && NSC.isCleartextTrafficPermitted !== undefined) {
        try {
            (NSC.isCleartextTrafficPermitted.overloads || []).forEach(function (ov) {
                ov.implementation = function () { return true; };
            });
            ok('LAYER 5: isCleartextTrafficPermitted -> true');
        } catch (e) { /* skip */ }
    }
}

/* =========================================================================
 * LAYER 6 — native TLS (BoringSSL / OpenSSL)
 *
 * Flutter, Cronet, React Native's native networking, Unity and any app with a
 * custom .so may perform TLS entirely in native code with a statically linked
 * BoringSSL. NO Java hook reaches these. The symptom is unmistakable: every
 * Java hook above reports success and Burp still sees nothing.
 *
 * Two entry points matter:
 *   SSL_CTX_set_custom_verify(ctx, mode, callback)  — modern BoringSSL
 *   SSL_CTX_set_verify(ctx, mode, callback)         — classic OpenSSL API
 *
 * Both take a callback; we install our own that always says "OK".
 * ========================================================================= */

var NATIVE_KEEP = [];    /* GC anchor — see ../README.md section 7.5 */

function layer6_native() {
    // ssl_verify_ok == 0 in BoringSSL's ssl_verify_result_t enum.
    var customVerifyCb = new NativeCallback(function (ssl, outAlert) {
        log('native SSL custom_verify -> ssl_verify_ok');
        return 0;
    }, 'int', ['pointer', 'pointer']);
    NATIVE_KEEP.push(customVerifyCb);

    // Classic OpenSSL verify callback: return 1 to accept.
    var classicVerifyCb = new NativeCallback(function (preverifyOk, x509ctx) {
        log('native SSL verify_callback -> 1');
        return 1;
    }, 'int', ['int', 'pointer']);
    NATIVE_KEEP.push(classicVerifyCb);

    // Search every loaded module, not just libssl.so: statically linked
    // BoringSSL means the symbol lives in the app's own library.
    var modules = Process.enumerateModules();
    var found = 0;

    modules.forEach(function (m) {
        // Skip the obvious noise to keep this fast.
        if (m.name.indexOf('libart') === 0 || m.name.indexOf('libc.so') === 0) return;

        var customVerify = null;
        try {
            customVerify = m.findExportByName
                         ? m.findExportByName('SSL_CTX_set_custom_verify')
                         : resolveExport(m.name, 'SSL_CTX_set_custom_verify');
        } catch (e) { customVerify = null; }

        if (customVerify !== null) {
            try {
                Interceptor.replace(customVerify, new NativeCallback(
                    function (ctx, mode, callback) {
                        // Call through to the real function with OUR callback
                        // and SSL_VERIFY_NONE (0).
                        var orig = new NativeFunction(customVerify, 'void',
                                                      ['pointer', 'int', 'pointer']);
                        log('SSL_CTX_set_custom_verify in ' + m.name +
                            ' mode=' + mode + ' -> permissive');
                        orig(ctx, 0, customVerifyCb);
                    }, 'void', ['pointer', 'int', 'pointer']));
                ok('LAYER 6: ' + m.name + '!SSL_CTX_set_custom_verify');
                found++;
            } catch (e) {
                no(m.name + '!SSL_CTX_set_custom_verify', e.message);
            }
        }

        var setVerify = null;
        try {
            setVerify = m.findExportByName
                      ? m.findExportByName('SSL_CTX_set_verify')
                      : resolveExport(m.name, 'SSL_CTX_set_verify');
        } catch (e) { setVerify = null; }

        if (setVerify !== null) {
            try {
                var origSetVerify = new NativeFunction(setVerify, 'void',
                                                       ['pointer', 'int', 'pointer']);
                Interceptor.replace(setVerify, new NativeCallback(
                    function (ctx, mode, cb) {
                        log('SSL_CTX_set_verify in ' + m.name +
                            ' mode=' + mode + ' -> SSL_VERIFY_NONE');
                        origSetVerify(ctx, 0 /* SSL_VERIFY_NONE */, classicVerifyCb);
                    }, 'void', ['pointer', 'int', 'pointer']));
                ok('LAYER 6: ' + m.name + '!SSL_CTX_set_verify');
                found++;
            } catch (e) {
                no(m.name + '!SSL_CTX_set_verify', e.message);
            }
        }
    });

    if (found === 0) {
        no('LAYER 6 (native TLS)',
           'no BoringSSL/OpenSSL verify symbols in any loaded module');
        log('If Java layers report success but the proxy still sees nothing,');
        log('the TLS stack may be statically linked and stripped. Use');
        log('native-tracer.js to find the handshake, or trace SSL_read/SSL_write.');
    }
}

/* =========================================================================
 * OPTIONAL — third-party stacks seen in the wild
 * ========================================================================= */

function extras() {
    // Appmattus Certificate Transparency — increasingly common, and it fails
    // AFTER a successful pin check, so it is easy to misattribute.
    ['com.appmattus.certificatetransparency.internal.verifier.CertificateTransparencyInterceptor',
     'com.appmattus.certificatetransparency.internal.verifier.CertificateTransparencyTrustManager']
        .forEach(function (n) {
            var K = tryUse(n);
            if (K === null) return;
            try {
                if (K.intercept !== undefined) {
                    // Not safely stubbable — log so the operator knows it exists.
                    ok('DETECTED: ' + n + ' (Certificate Transparency in use)');
                }
            } catch (e) { /* skip */ }
        });

    // TrustKit
    var TK = tryUse('com.datatheorem.android.trustkit.pinning.OkHostnameVerifier');
    if (TK !== null) {
        try {
            (TK.verify.overloads || []).forEach(function (ov) {
                ov.implementation = function () { return true; };
            });
            ok('EXTRA: TrustKit OkHostnameVerifier -> true');
        } catch (e) { no('TrustKit', e.message); }
    }

    // Apache HttpClient (legacy, still present in older enterprise apps)
    ['org.apache.http.conn.ssl.AbstractVerifier',
     'org.apache.http.conn.ssl.SSLSocketFactory'].forEach(function (n) {
        var K = tryUse(n);
        if (K === null) return;
        try {
            if (K.verify !== undefined) {
                (K.verify.overloads || []).forEach(function (ov) {
                    ov.implementation = function () { /* accept */ };
                });
                ok('EXTRA: ' + n + '.verify');
            }
        } catch (e) { /* skip */ }
    });

    // Cordova / Ionic WebView SSL errors
    var WVC = tryUse('android.webkit.WebViewClient');
    if (WVC !== null) {
        try {
            WVC.onReceivedSslError.overload(
                'android.webkit.WebView',
                'android.webkit.SslErrorHandler',
                'android.net.http.SslError'
            ).implementation = function (view, handler, error) {
                log('WebViewClient.onReceivedSslError -> proceed()');
                handler.proceed();
            };
            ok('EXTRA: WebViewClient.onReceivedSslError -> proceed');
        } catch (e) { no('WebViewClient.onReceivedSslError', e.message); }
    }
}

/* =========================================================================
 * OBSERVATION — prove the bypass worked
 * ========================================================================= */

function observeTraffic() {
    var URL = tryUse('java.net.URL');
    if (URL !== null) {
        try {
            URL.openConnection.overload().implementation = function () {
                console.log('[net] ' + this.toString());
                return this.openConnection();
            };
            ok('OBSERVE: java.net.URL.openConnection');
        } catch (e) { /* skip */ }
    }

    var Builder = tryUse('okhttp3.Request$Builder');
    if (Builder !== null) {
        try {
            Builder.build.implementation = function () {
                var req = this.build();
                try { console.log('[net] okhttp ' + req.method() + ' ' + req.url()); }
                catch (e) { /* older okhttp */ }
                return req;
            };
            ok('OBSERVE: okhttp3.Request.Builder.build');
        } catch (e) { /* skip */ }
    }
}

/* ------------------------------------------------------------- bootstrap */

Java.perform(function () {
    console.log('');
    console.log('==================================================');
    console.log('  ssl-pinning-bypass.js');
    console.log('  six-layer TLS validation bypass');
    console.log('==================================================');
    console.log('');

    layer1_sslContext();
    layer2_conscrypt();
    layer3_okhttp();
    layer4_hostnameVerifier();
    layer5_networkSecurityConfig();
    extras();
    observeTraffic();

    // Native layer last: it enumerates modules, which is the slowest step, and
    // some libraries are only dlopen'd after the first Activity starts.
    layer6_native();

    console.log('');
    console.log('[*] ' + installed.length + ' hook(s) installed, ' +
                skipped.length + ' skipped.');
    console.log('[*] Exercise the app now. If traffic still does not appear:');
    console.log('    - confirm the device proxy is set and reachable');
    console.log('    - re-run layer 6 after the app loads its libraries:');
    console.log('        setTimeout(layer6_native, 5000)');
    console.log('    - check logcat for "Certificate pinning failure"');
    console.log('');
});

/*
 * Re-run the native sweep after startup. Many apps dlopen their networking
 * library lazily, so the first pass finds nothing. This is cheap insurance.
 */
setTimeout(function () {
    console.log('[*] re-scanning modules for native TLS (deferred pass)');
    try { layer6_native(); } catch (e) { console.log('[-] deferred pass: ' + e.message); }
}, 6000);
