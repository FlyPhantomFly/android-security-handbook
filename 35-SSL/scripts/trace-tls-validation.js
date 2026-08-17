/*
 * trace-tls-validation.js -- see WHICH TLS validation an app actually performs.
 *
 * WHAT IT DOES
 *   Watches an app build its TLS machinery and answers one question that no
 *   amount of static analysis answers reliably:
 *
 *       when this app connects to a server, what does it actually check?
 *
 *   It reports, live:
 *
 *     CONSTRUCTION  every SSLContext.getInstance / init, every
 *                   TrustManagerFactory.init, and -- the part that matters --
 *                   the CLASS NAME of every TrustManager and HostnameVerifier
 *                   that gets installed. A platform class means the app
 *                   accepted the default. An app class means somebody wrote
 *                   their own, and you need to read it.
 *
 *     VALIDATION    every checkServerTrusted call: which TrustManager, the
 *                   chain it was handed, the authType, and -- critically --
 *                   whether it returned or threw. A TrustManager that never
 *                   throws is not validating. There is no boolean here:
 *                   returning IS accepting.
 *
 *     HOSTNAME      every HostnameVerifier.verify: which verifier, which
 *                   hostname, and what it returned. Chain validation and
 *                   hostname verification are SEPARATE steps, and apps break
 *                   them separately.
 *
 *     NEGOTIATION   the protocol version and cipher suite each socket
 *                   actually ended up with, plus the sets it was willing to
 *                   accept.
 *
 *     VERDICT       a summary, on demand, naming and classifying everything
 *                   seen.
 *
 *     ORACLE        on demand: hand every discovered TrustManager a
 *                   zero-length certificate chain. The X509TrustManager
 *                   contract requires IllegalArgumentException for that
 *                   input, and every conformant implementation throws it. A
 *                   "trust everything" TrustManager returns quietly, because
 *                   it never looks at its arguments. This needs no proxy, no
 *                   certificate and no network, which makes it the fastest
 *                   honest answer to "is this thing validating at all".
 *
 * HOW DISCOVERY WORKS, AND WHY IT IS NOT A CLASS SWEEP
 *   The obvious implementation -- enumerate every loaded class and reflect on
 *   each to see whether it implements X509TrustManager -- was the first
 *   version of this script, and it was wrong twice over. It calls Java.use on
 *   fifteen thousand classes, which is slow enough to matter, and it still
 *   misses the case you care about most, because an app's TrustManager is
 *   very often an anonymous inner class that is not loaded until the first
 *   request.
 *
 *   Instead, this script hooks the CHOKE POINTS through which every
 *   TrustManager must pass to be used at all -- SSLContext.init and
 *   TrustManagerFactory.getTrustManagers -- reads the class name off the live
 *   object, and wraps that exact class on the spot. An anonymous inner class
 *   called com.foo.Bar$3 is caught the moment it is installed, by name, with
 *   no guessing. A cheap name-filtered sweep runs as a backstop for stacks
 *   that build their trust machinery some other way.
 *
 * WHAT THIS SCRIPT DELIBERATELY DOES NOT DO
 *   It does not bypass anything. Nothing here is stubbed or forced to return
 *   true. That is on purpose: if you neutralise validation before you have
 *   measured it, you can no longer say what the app was doing, and "traffic
 *   appeared in Burp" stops being evidence of anything.
 *
 *   Bypass is a separate job with a separate tool. Use
 *   ../../53-Frida/scripts/ssl-pinning-bypass.js for that, and read
 *   ../../36-CertificatePinning/README.md for the layered background. This
 *   script will TELL you when an app pins -- it will not unpin it.
 *
 * HOW TO RUN
 *   # Make hooks land reliably (the JIT can inline a hot method out from
 *   # under you; forcing verify-only compilation stops that)
 *   adb shell cmd package compile -m verify -f com.example.app
 *
 *   # ALWAYS spawn. TLS machinery is usually built during startup, and an
 *   # attach arrives after the interesting constructor already ran.
 *   frida -U -f com.example.app -l trace-tls-validation.js
 *
 *   # then, in the Frida REPL, once you have exercised the app:
 *   [Device::app]-> verdict()
 *   [Device::app]-> oracle()
 *
 *   # non-interactive capture
 *   frida -U -f com.example.app -l trace-tls-validation.js -o trace.txt
 *
 * TUNING
 *   VERBOSE          false silences per-call lines and keeps the summary.
 *   DUMP_CHAINS      true prints every certificate of every presented chain.
 *                    Useful once, deafening thereafter.
 *   RESCAN_SECONDS   when to run the backstop sweep again for classes loaded
 *                    lazily. 0 disables it.
 *   SWEEP            false skips the name-filtered backstop sweep entirely
 *                    and relies only on the choke-point hooks.
 *
 * REQUIREMENTS
 *   Frida 14 or newer on host and device. A rooted device, or a repackaged
 *   debuggable app. Java-side only.
 *
 * WHAT THIS WILL *NOT* TELL YOU
 *   - Whether the app is SAFE. A perfect TrustManager talking to a server
 *     that accepts anonymous cipher suites is still broken. Run
 *     tls-posture.py against the endpoints as well.
 *   - Whether validation happened in NATIVE code. If the summary reports zero
 *     checkServerTrusted calls while the app is plainly online, the TLS stack
 *     is native -- a statically linked BoringSSL inside Flutter, Cronet,
 *     Unity or a custom .so. No Java hook reaches that. The script says so
 *     explicitly rather than implying the app performs no validation.
 *   - Which certificate the server actually sent. The chain printed here is
 *     the chain as the app RECEIVED it, which is the right thing for a trust
 *     question -- but a proxy in the path has already replaced it.
 *   - Whether a pin would have failed. Pin evaluation happens after trust
 *     evaluation and is chapter 36's subject.
 *   - Anything conclusive from silence. A TrustManager that never threw
 *     during your session is only interesting if you presented it something
 *     it should have rejected. That is what the deliberate-bad-certificate
 *     test in Lab 02 is for, and it is not optional.
 *
 * AUTHORISED TESTING ONLY.
 */

'use strict';

var VERBOSE = true;
var DUMP_CHAINS = false;
var RESCAN_SECONDS = 10;
var SWEEP = true;

/* ------------------------------------------------------------------ state */

var seenTrustManagers = {};      /* className -> record                     */
var seenHostnameVerifiers = {};  /* className -> record                     */
var seenContexts = {};           /* protocol  -> count                      */
var seenSockets = [];            /* negotiated protocol/cipher observations */
var pinningEvidence = [];        /* class names that indicate pin checking  */
var hookCount = 0;
var checkCalls = 0;

/*
 * Classes whose methods are already wrapped. Without this guard the deferred
 * rescan wraps the wrapper: every later call is counted twice and every log
 * line prints twice. That was visible the first time this ran against a real
 * app, which is the only reason the guard exists.
 */
var wrappedTrust = {};
var wrappedHostname = {};

function log(msg) {
    if (VERBOSE) console.log(msg);
}

function banner(msg) {
    console.log('');
    console.log('=== ' + msg + ' ===');
}

/*
 * Guarded class lookup. A missing class is the NORMAL case -- no app uses
 * every stack, and platform class names differ across API levels. A missing
 * class must never abort the script.
 *
 * MUST be called from inside Java.perform. Java.use on a thread that is not
 * attached to the VM does not raise a JavaScript error -- it takes the whole
 * process down, which looks exactly like the app crashing on its own.
 */
function tryUse(name) {
    try {
        return Java.use(name);
    } catch (e) {
        return null;
    }
}

/* Classes shipped by the platform or by Conscrypt. Anything NOT matching one
 * of these prefixes was written by the app or by a library it bundles, and
 * that is the distinction the whole report turns on. */
var PLATFORM_PREFIXES = [
    'android.security.net.config.',
    'android.net.',
    'android.webkit.',
    'com.android.org.conscrypt.',
    'org.conscrypt.',
    'com.google.android.gms.org.conscrypt.',
    /* The platform bundles its own repackaged OkHttp under com.android.okhttp
     * and uses it for HttpsURLConnection. Without this prefix, every app on
     * the device reports com.android.okhttp.internal.tls.OkHostnameVerifier as
     * "APP-SUPPLIED -- read it", which sends the reader off to decompile a
     * class the app never wrote. */
    'com.android.okhttp.',
    'javax.net.ssl.',
    'sun.security.ssl.',
    'com.android.internal.'
];

/* Not the platform, but well-understood, so the report can say "known
 * library" instead of "app code, go read it". */
var KNOWN_LIBRARY_PREFIXES = [
    'okhttp3.',
    'com.squareup.okhttp.',
    'org.apache.http.',
    'com.android.volley.',
    'retrofit2.',
    'io.ktor.',
    'com.datatheorem.android.trustkit.',
    'com.appmattus.certificatetransparency.'
];

/*
 * Class-name fragments that mean the app is doing PIN evaluation. Reported,
 * never touched -- pinning is 36-CertificatePinning's territory.
 *
 * NOTE what is deliberately ABSENT: NetworkSecurityTrustManager. It is the
 * platform class that WOULD enforce a <pin-set>, and it is loaded in every
 * app whether or not a single pin is configured. Listing it here made this
 * script report "this app pins" against 100% of targets, which is worse than
 * reporting nothing -- a checker that cries wolf gets ignored. Pins declared
 * in a network_security_config are found by reading the XML, which is
 * 44-NetworkSecurityConfig's job, not by the presence of a class.
 */
var PINNING_HINTS = [
    'CertificatePinner',
    'PinningTrustManager',
    'TrustKit',
    'certificatetransparency',
    'PublicKeyPinn'
];

/*
 * Name fragments used by the BACKSTOP sweep. This is a cheap string test
 * applied before any Java.use call, which is what keeps the sweep from
 * costing fifteen thousand class lookups. It will miss a TrustManager named
 * `com.foo.a.b.c` -- and that is acceptable, because such a class is caught
 * at SSLContext.init instead, by reading the class name off the live object.
 */
var SWEEP_HINTS = [
    'TrustManager', 'X509', 'Hostname', 'HostName', 'Verifier',
    'SSL', 'Ssl', 'Tls', 'TLS', 'CertificatePinner', 'TrustKit'
];

function classify(name) {
    for (var i = 0; i < PLATFORM_PREFIXES.length; i++) {
        if (name.indexOf(PLATFORM_PREFIXES[i]) === 0) return 'platform';
    }
    for (var j = 0; j < KNOWN_LIBRARY_PREFIXES.length; j++) {
        if (name.indexOf(KNOWN_LIBRARY_PREFIXES[j]) === 0) return 'library';
    }
    return 'app';
}

function notePinning(name) {
    for (var i = 0; i < PINNING_HINTS.length; i++) {
        if (name.indexOf(PINNING_HINTS[i]) !== -1) {
            if (pinningEvidence.indexOf(name) === -1) {
                pinningEvidence.push(name);
                console.log('[pin] ' + name + ' is present -- this app evaluates PINS.');
                console.log('      Pinning is chapter 36. This script will not touch it.');
            }
            return;
        }
    }
}

function tmRecord(name) {
    if (!seenTrustManagers[name]) {
        seenTrustManagers[name] = {
            name: name,
            origin: classify(name),
            calls: 0,
            threw: 0,
            returned: 0,
            emptyChainAccepted: null,
            installedVia: []
        };
        notePinning(name);
    }
    return seenTrustManagers[name];
}

function hvRecord(name) {
    if (!seenHostnameVerifiers[name]) {
        seenHostnameVerifiers[name] = {
            name: name,
            origin: classify(name),
            calls: 0,
            trueCount: 0,
            falseCount: 0,
            hosts: []
        };
        notePinning(name);
    }
    return seenHostnameVerifiers[name];
}

/* --------------------------------------------------------------- helpers */

function certLine(cert) {
    try {
        return cert.getSubjectDN().toString() +
               '   [issuer: ' + cert.getIssuerDN().toString() + ']';
    } catch (e) {
        return '(certificate not printable: ' + e.message + ')';
    }
}

function describeChain(chain) {
    if (chain === null) return '(null chain)';
    var n;
    try { n = chain.length; } catch (e) { return '(chain length unreadable)'; }
    if (n === 0) {
        return '(ZERO-LENGTH chain -- a conformant validator rejects this outright)';
    }
    var head;
    try { head = chain[0].getSubjectDN().toString(); }
    catch (e) { head = '(unreadable)'; }
    return n + ' cert(s), leaf = ' + head;
}

function dumpChain(chain, indent) {
    if (!DUMP_CHAINS || chain === null) return;
    try {
        for (var i = 0; i < chain.length; i++) {
            console.log(indent + '[' + i + '] ' + certLine(chain[i]));
        }
    } catch (e) { /* not enumerable */ }
}

function stackShort() {
    try {
        var Exception = Java.use('java.lang.Exception');
        var Log = Java.use('android.util.Log');
        var lines = Log.getStackTraceString(Exception.$new()).split('\n');
        var out = [];
        for (var i = 1; i < lines.length && out.length < 4; i++) {
            var l = lines[i].trim();
            if (l.indexOf('at java.lang.reflect') !== -1) continue;
            out.push(l);
        }
        return out.join('\n        ');
    } catch (e) {
        return '(stack unavailable)';
    }
}

/* ==========================================================================
 * WRAPPING
 * ========================================================================== */

/*
 * Wrap every checkServerTrusted overload on one class.
 *
 * The critical instrumentation detail is recording whether the call THREW.
 * X509TrustManager has no boolean return: returning normally is the accept
 * path and throwing CertificateException is the reject path. A TrustManager
 * never observed to throw, in a session where something invalid was
 * presented, is not validating.
 */
function wrapTrustManagerClass(className) {
    if (wrappedTrust[className]) return 0;

    var K = tryUse(className);
    if (K === null) return 0;
    if (K.checkServerTrusted === undefined) return 0;

    wrappedTrust[className] = true;
    var rec = tmRecord(className);
    var wrapped = 0;

    (K.checkServerTrusted.overloads || []).forEach(function (ov) {
        var argc = ov.argumentTypes.length;
        try {
            ov.implementation = function () {
                rec.calls++;
                checkCalls++;
                var chain = arguments.length > 0 ? arguments[0] : null;
                var authType = arguments.length > 1 ? arguments[1] : null;

                log('[chk] ' + className + '.checkServerTrusted(' + argc + ' args)');
                log('      chain    : ' + describeChain(chain));
                if (authType !== null) log('      authType : ' + authType);
                dumpChain(chain, '        ');

                try {
                    var result = ov.apply(this, arguments);
                    rec.returned++;
                    log('      RESULT   : returned normally == ACCEPTED');
                    return result;
                } catch (err) {
                    rec.threw++;
                    var m = '(no message)';
                    try { m = err.message || String(err); } catch (e2) { /* opaque */ }
                    log('      RESULT   : threw == REJECTED');
                    log('      reason   : ' + m.split('\n')[0]);
                    throw err;
                }
            };
            wrapped++;
        } catch (e) { /* this overload is not hookable; try the next */ }
    });

    if (wrapped > 0) {
        hookCount += wrapped;
        log('[+] tracing ' + className + '  (' + rec.origin + ', ' +
            wrapped + ' overload(s))');
        if (rec.origin === 'app') {
            log('      ^ APP-SUPPLIED. Read this class: it decides whether any');
            log('        certificate on earth is accepted.');
        }
    }
    return wrapped;
}

function wrapHostnameVerifierClass(className) {
    if (wrappedHostname[className]) return 0;

    var K = tryUse(className);
    if (K === null) return 0;
    if (K.verify === undefined) return 0;

    wrappedHostname[className] = true;
    var rec = hvRecord(className);
    var wrapped = 0;

    (K.verify.overloads || []).forEach(function (ov) {
        if (ov.returnType.className !== 'boolean') return;
        if (ov.argumentTypes.length !== 2) return;
        try {
            ov.implementation = function () {
                rec.calls++;
                var host = arguments.length > 0 ? String(arguments[0]) : '?';
                var out = ov.apply(this, arguments);
                if (out) { rec.trueCount++; } else { rec.falseCount++; }
                if (rec.hosts.indexOf(host) === -1 && rec.hosts.length < 40) {
                    rec.hosts.push(host);
                }
                log('[hv ] ' + className + '.verify("' + host + '") -> ' + out +
                    '   (' + rec.origin + ')');
                return out;
            };
            wrapped++;
        } catch (e) { /* skip overload */ }
    });

    if (wrapped > 0) {
        hookCount += wrapped;
        log('[+] tracing hostname verifier ' + className +
            '  (' + rec.origin + ')');
        if (rec.origin === 'app') {
            log('      ^ APP-SUPPLIED. `return true` is the classic bug and it');
            log('        looks identical to a correct verifier until you present');
            log('        a certificate for the WRONG host.');
        }
    }
    return wrapped;
}

/* Read the runtime class off a live object and wrap it. This is what catches
 * anonymous inner classes, which never appear under a guessable name. */
function wrapFromInstance(obj, via, kind) {
    if (obj === null || obj === undefined) return;
    var cn = null;
    try { cn = obj.$className; } catch (e) { /* dynamic proxy or opaque */ }
    if (cn === null || cn === undefined) {
        try { cn = obj.getClass().getName(); } catch (e) { return; }
    }
    if (!cn) return;

    var rec = (kind === 'hv') ? hvRecord(cn) : tmRecord(cn);
    if (rec.installedVia.indexOf === undefined) { /* hv records have no list */ }
    if (kind !== 'hv' && rec.installedVia.indexOf(via) === -1) {
        rec.installedVia.push(via);
    }

    if (kind === 'hv') {
        wrapHostnameVerifierClass(cn);
    } else {
        wrapTrustManagerClass(cn);
    }
}

/* ==========================================================================
 * 1. CONSTRUCTION -- the choke points every TrustManager must pass through
 * ========================================================================== */

function traceConstruction() {
    var SSLContext = tryUse('javax.net.ssl.SSLContext');
    if (SSLContext !== null) {
        try {
            SSLContext.getInstance.overload('java.lang.String').implementation =
                function (protocol) {
                    seenContexts[protocol] = (seenContexts[protocol] || 0) + 1;
                    log('[ctx] SSLContext.getInstance("' + protocol + '")');
                    return this.getInstance(protocol);
                };
            hookCount++;
        } catch (e) { /* signature absent */ }

        try {
            SSLContext.init.overload(
                '[Ljavax.net.ssl.KeyManager;',
                '[Ljavax.net.ssl.TrustManager;',
                'java.security.SecureRandom'
            ).implementation = function (km, tm, sr) {
                if (tm === null) {
                    log('[ctx] SSLContext.init(trustManagers = null)');
                    log('      null means "use the platform default": the app is NOT');
                    log('      overriding trust here.');
                } else {
                    log('[ctx] SSLContext.init with ' + tm.length + ' TrustManager(s)');
                    for (var i = 0; i < tm.length; i++) {
                        wrapFromInstance(tm[i], 'SSLContext.init', 'tm');
                    }
                    log('      called from:');
                    log('        ' + stackShort());
                }
                return this.init(km, tm, sr);
            };
            hookCount++;
        } catch (e) { /* vendor-modified platform class */ }
    }

    var TMF = tryUse('javax.net.ssl.TrustManagerFactory');
    if (TMF !== null) {
        try {
            TMF.init.overload('java.security.KeyStore').implementation = function (ks) {
                if (ks === null) {
                    log('[tmf] TrustManagerFactory.init(null) -- platform default store');
                } else {
                    var n = '?';
                    try { n = ks.size(); } catch (e) { /* not loaded yet */ }
                    log('[tmf] TrustManagerFactory.init(custom KeyStore, ' + n + ' entries)');
                    log('      A custom KeyStore here means the app has REPLACED the set');
                    log('      of trust anchors. That is trust configuration, not pinning,');
                    log('      and it is why your CA in the system store may be ignored.');
                }
                return this.init(ks);
            };
            hookCount++;
        } catch (e) { /* absent */ }

        try {
            TMF.getTrustManagers.implementation = function () {
                var tms = this.getTrustManagers();
                try {
                    for (var i = 0; i < tms.length; i++) {
                        wrapFromInstance(tms[i], 'TrustManagerFactory', 'tm');
                    }
                } catch (e) { /* opaque array */ }
                return tms;
            };
            hookCount++;
        } catch (e) { /* absent */ }
    }

    /* HostnameVerifier choke points. */
    var HUC = tryUse('javax.net.ssl.HttpsURLConnection');
    if (HUC !== null) {
        ['setDefaultHostnameVerifier', 'setHostnameVerifier'].forEach(function (m) {
            if (HUC[m] === undefined) return;
            try {
                HUC[m].implementation = function (v) {
                    log('[hv ] HttpsURLConnection.' + m + '(...)');
                    wrapFromInstance(v, m, 'hv');
                    return this[m](v);
                };
                hookCount++;
            } catch (e) { /* absent */ }
        });
    }

    var OkBuilder = tryUse('okhttp3.OkHttpClient$Builder');
    if (OkBuilder !== null) {
        if (OkBuilder.hostnameVerifier !== undefined) {
            try {
                OkBuilder.hostnameVerifier.implementation = function (v) {
                    log('[hv ] OkHttpClient.Builder.hostnameVerifier(...)');
                    wrapFromInstance(v, 'OkHttpClient.Builder', 'hv');
                    return this.hostnameVerifier(v);
                };
                hookCount++;
            } catch (e) { /* signature differs across OkHttp versions */ }
        }
        if (OkBuilder.sslSocketFactory !== undefined) {
            (OkBuilder.sslSocketFactory.overloads || []).forEach(function (ov) {
                try {
                    ov.implementation = function () {
                        log('[ctx] OkHttpClient.Builder.sslSocketFactory(' +
                            ov.argumentTypes.length + ' args)');
                        if (ov.argumentTypes.length === 2) {
                            wrapFromInstance(arguments[1], 'OkHttpClient.Builder', 'tm');
                        } else {
                            log('      one-argument form: OkHttp must DERIVE the trust');
                            log('      manager by reflection. Deprecated, and a common');
                            log('      source of "my custom trust manager is ignored".');
                        }
                        return ov.apply(this, arguments);
                    };
                    hookCount++;
                } catch (e) { /* skip */ }
            });
        }
    }
}

/* ==========================================================================
 * 2. BACKSTOP SWEEP -- name-filtered, so it is cheap
 * ========================================================================== */

function sweep() {
    if (!SWEEP) return 0;

    var names = [];
    try {
        names = Java.enumerateLoadedClassesSync();
    } catch (e) {
        console.log('[!] class enumeration unavailable: ' + e.message);
        return 0;
    }

    var TM_IFACE = 'javax.net.ssl.X509TrustManager';
    var HV_IFACE = 'javax.net.ssl.HostnameVerifier';
    var found = 0;

    names.forEach(function (name) {
        if (name.charAt(0) === '[') return;                   /* array types */
        if (name.indexOf('java.') === 0) return;
        if (wrappedTrust[name] || wrappedHostname[name]) return;

        /* Cheap string filter BEFORE any Java.use. This is the whole point. */
        var interesting = false;
        for (var i = 0; i < SWEEP_HINTS.length; i++) {
            if (name.indexOf(SWEEP_HINTS[i]) !== -1) { interesting = true; break; }
        }
        if (!interesting) return;

        var K = tryUse(name);
        if (K === null) return;

        var isTm = false, isHv = false;
        try {
            var c = K.class;
            while (c !== null && !(isTm && isHv)) {
                var ifaces = c.getInterfaces();
                for (var j = 0; j < ifaces.length; j++) {
                    var n = ifaces[j].getName();
                    if (n === TM_IFACE) isTm = true;
                    if (n === HV_IFACE) isHv = true;
                }
                c = c.getSuperclass();
            }
        } catch (e) { return; }

        if (isTm && wrapTrustManagerClass(name) > 0) found++;
        if (isHv && wrapHostnameVerifierClass(name) > 0) found++;
    });

    /* Always cover the platform implementations by name: they are loaded
     * lazily and may not have existed when the sweep ran. */
    ['android.security.net.config.RootTrustManager',
     'android.security.net.config.NetworkSecurityTrustManager',
     'com.android.org.conscrypt.TrustManagerImpl',
     'org.conscrypt.TrustManagerImpl'].forEach(function (name) {
        if (wrapTrustManagerClass(name) > 0) found++;
    });

    ['com.android.org.conscrypt.OkHostnameVerifier',
     'org.conscrypt.OkHostnameVerifier',
     'okhttp3.internal.tls.OkHostnameVerifier'].forEach(function (name) {
        if (wrapHostnameVerifierClass(name) > 0) found++;
    });

    return found;
}

/* ==========================================================================
 * 3. NEGOTIATION -- what the socket actually agreed to
 * ========================================================================== */

function traceNegotiation() {
    var SSLSocket = tryUse('javax.net.ssl.SSLSocket');
    if (SSLSocket === null || SSLSocket.startHandshake === undefined) return;

    try {
        SSLSocket.startHandshake.implementation = function () {
            var offeredProtocols = '(unreadable)';
            var offeredSuites = -1;
            try { offeredProtocols = this.getEnabledProtocols().join(', '); } catch (e) {}
            try { offeredSuites = this.getEnabledCipherSuites().length; } catch (e) {}

            this.startHandshake();

            var negotiated = '(none)';
            var suite = '(none)';
            var peer = '(no peer certificate)';
            try {
                var session = this.getSession();
                negotiated = session.getProtocol();
                suite = session.getCipherSuite();
                try {
                    var certs = session.getPeerCertificates();
                    if (certs !== null && certs.length > 0) {
                        peer = certs[0].getSubjectDN().toString();
                    }
                } catch (e) {
                    peer = '(peer certificates unavailable)';
                }
            } catch (e) { /* session not established */ }

            seenSockets.push({
                protocol: negotiated,
                cipher: suite,
                peer: peer,
                offeredProtocols: offeredProtocols,
                offeredSuites: offeredSuites
            });

            log('[tls] handshake complete');
            log('      offered  : ' + offeredProtocols +
                '   (' + offeredSuites + ' cipher suites)');
            log('      agreed   : ' + negotiated + ' / ' + suite);
            log('      peer     : ' + peer);
            if (offeredProtocols.indexOf('SSLv3') !== -1) {
                log('      NOTE: SSLv3 is in the OFFERED set. See README section 5.2.');
            }
        };
        hookCount++;
    } catch (e) { /* absent */ }
}

/* ==========================================================================
 * 4. WEBVIEW -- a different mechanism entirely, hooked for visibility only
 * ========================================================================== */

function traceWebView() {
    var WVC = tryUse('android.webkit.WebViewClient');
    if (WVC !== null && WVC.onReceivedSslError !== undefined) {
        try {
            WVC.onReceivedSslError.overload(
                'android.webkit.WebView',
                'android.webkit.SslErrorHandler',
                'android.net.http.SslError'
            ).implementation = function (view, handler, error) {
                var desc = '(unreadable)', url = '?';
                try { desc = error.toString(); } catch (e) {}
                try { url = error.getUrl(); } catch (e) {}
                console.log('[web] WebViewClient.onReceivedSslError');
                console.log('      url   : ' + url);
                console.log('      error : ' + desc);
                console.log('      The app is about to decide whether to proceed anyway.');
                return this.onReceivedSslError(view, handler, error);
            };
            hookCount++;
        } catch (e) { /* absent */ }
    }

    var Handler = tryUse('android.webkit.SslErrorHandler');
    if (Handler !== null && Handler.proceed !== undefined) {
        try {
            Handler.proceed.implementation = function () {
                console.log('[web] !! SslErrorHandler.proceed() CALLED');
                console.log('      The app has chosen to ignore a certificate error.');
                console.log('      This is the WebView equivalent of a trust-everything');
                console.log('      TrustManager, and it is a finding on its own.');
                return this.proceed();
            };
            hookCount++;
        } catch (e) { /* absent */ }
    }
}

/* ==========================================================================
 * 5. THE ORACLE
 *
 * Everything below runs INSIDE Java.perform. See the note on tryUse: calling
 * Java.use from an unattached thread kills the process silently.
 * ========================================================================== */

function runOracle() {
    Java.perform(function () {
        banner('ORACLE: zero-length chain fed to each TrustManager');
        console.log('X509TrustManager.checkServerTrusted must throw');
        console.log('IllegalArgumentException for a null or zero-length chain. Every');
        console.log('conformant implementation does. One that returns quietly never');
        console.log('looked at its argument, which means it never looks at any chain.');
        console.log('');

        if (tryUse('java.security.cert.X509Certificate') === null) {
            console.log('[-] java.security.cert.X509Certificate unavailable; cannot probe.');
            return;
        }

        var empty = Java.array('java.security.cert.X509Certificate', []);
        var tested = 0;

        Object.keys(seenTrustManagers).forEach(function (name) {
            var rec = seenTrustManagers[name];

            if (tryUse(name) === null) {
                console.log('  ' + name);
                console.log('      class no longer resolvable, skipped');
                return;
            }

            /* Use a LIVE instance. Constructing an app's TrustManager
             * ourselves can run arbitrary constructor code, and may not be
             * possible at all if it takes arguments. */
            var inst = null;
            try {
                Java.choose(name, {
                    onMatch: function (i) { inst = i; return 'stop'; },
                    onComplete: function () {}
                });
            } catch (e) { /* not on the heap */ }

            if (inst === null) {
                console.log('  ' + name);
                console.log('      no live instance on the heap, skipped');
                console.log('      (exercise the app first, then call oracle() again)');
                return;
            }

            var verdictLine;
            try {
                inst.checkServerTrusted(empty, 'RSA');
                verdictLine = 'RETURNED  -- accepted a ZERO-LENGTH chain. NOT VALIDATING.';
                rec.emptyChainAccepted = true;
            } catch (err) {
                var m = '';
                try { m = err.message || String(err); } catch (e) { m = '(opaque)'; }
                verdictLine = 'threw     -- ' + m.split('\n')[0];
                rec.emptyChainAccepted = false;
            }
            console.log('  ' + name + '   (' + rec.origin + ')');
            console.log('      ' + verdictLine);
            tested++;
        });

        if (tested === 0) {
            console.log('  Nothing to test yet. Exercise the app so its TrustManagers');
            console.log('  are constructed, then call oracle() again.');
        }
        console.log('');
        console.log('  LIMIT: a positive result proves THAT TrustManager is permissive.');
        console.log('  It does not prove the app is interceptable -- the app may not use');
        console.log('  it for the endpoint you care about, and a network_security_config');
        console.log('  pin-set is enforced somewhere else entirely. Confirm with the');
        console.log('  deliberate-bad-certificate test in Lab 02.');
        console.log('');
    });
}

/* ==========================================================================
 * 6. VERDICT
 * ========================================================================== */

function printVerdict() {
    banner('VERDICT');

    var tmNames = Object.keys(seenTrustManagers);
    var hvNames = Object.keys(seenHostnameVerifiers);

    console.log('TRUST MANAGERS SEEN: ' + tmNames.length);
    if (tmNames.length === 0) console.log('  none.');
    tmNames.forEach(function (n) {
        var r = seenTrustManagers[n];
        console.log('');
        console.log('  ' + n);
        console.log('      origin        : ' + r.origin +
            (r.origin === 'app' ? '   <-- WRITTEN BY THIS APP. READ IT.' : ''));
        console.log('      installed via : ' +
            (r.installedVia.length ? r.installedVia.join(', ') : '(not observed)'));
        console.log('      checkServerTrusted: ' + r.calls + ' call(s)  ' +
            '(accepted ' + r.returned + ', rejected ' + r.threw + ')');
        if (r.emptyChainAccepted === true) {
            console.log('      ORACLE        : accepted a ZERO-LENGTH chain.');
            console.log('                      This TrustManager performs no validation.');
        } else if (r.emptyChainAccepted === false) {
            console.log('      ORACLE        : rejected a zero-length chain (conformant).');
        }
        if (r.calls > 0 && r.threw === 0) {
            console.log('      NOTE          : never rejected anything this session. That');
            console.log('                      is only meaningful if you presented it');
            console.log('                      something it SHOULD reject. Run Lab 02.');
        }
    });

    console.log('');
    console.log('HOSTNAME VERIFIERS SEEN: ' + hvNames.length);
    if (hvNames.length === 0) {
        console.log('  none observed. The platform default may still have run inside');
        console.log('  Conscrypt without a separate HostnameVerifier object being used.');
    }
    hvNames.forEach(function (n) {
        var r = seenHostnameVerifiers[n];
        console.log('');
        console.log('  ' + n);
        console.log('      origin : ' + r.origin +
            (r.origin === 'app' ? '   <-- WRITTEN BY THIS APP. READ IT.' : ''));
        console.log('      verify : ' + r.calls + ' call(s), ' +
            r.trueCount + ' true, ' + r.falseCount + ' false');
        if (r.calls > 0 && r.falseCount === 0) {
            console.log('      NOTE   : returned true every time. A verifier whose whole');
            console.log('               body is `return true` looks EXACTLY like this.');
            console.log('               The only way to tell them apart is to present a');
            console.log('               certificate for the WRONG hostname -- Lab 02.');
        }
        if (r.hosts.length) {
            console.log('      hosts  : ' + r.hosts.slice(0, 10).join(', ') +
                (r.hosts.length > 10 ? '  (+' + (r.hosts.length - 10) + ' more)' : ''));
        }
    });

    console.log('');
    console.log('SSLCONTEXT PROTOCOLS REQUESTED:');
    var protos = Object.keys(seenContexts);
    if (protos.length === 0) console.log('  none observed.');
    protos.forEach(function (p) {
        var warn = '';
        if (p === 'SSL' || p === 'SSLv3' || p === 'TLSv1' || p === 'TLSv1.1') {
            warn = '   <-- deprecated protocol requested EXPLICITLY';
        } else if (p === 'TLS' || p === 'Default') {
            warn = '   (means "platform default", which is the right answer)';
        }
        console.log('  ' + p + ' x' + seenContexts[p] + warn);
    });

    console.log('');
    console.log('HANDSHAKES OBSERVED: ' + seenSockets.length);
    var combos = {};
    seenSockets.forEach(function (s) {
        var k = s.protocol + ' / ' + s.cipher;
        combos[k] = (combos[k] || 0) + 1;
    });
    Object.keys(combos).forEach(function (k) {
        console.log('  ' + k + '   x' + combos[k]);
    });

    if (pinningEvidence.length) {
        console.log('');
        console.log('PINNING EVIDENCE: ' + pinningEvidence.length + ' class(es)');
        pinningEvidence.forEach(function (p) { console.log('  ' + p); });
        console.log('  Trust validation is only the first gate here.');
        console.log('  Continue in 36-CertificatePinning.');
    }

    console.log('');
    if (checkCalls === 0 && seenSockets.length === 0) {
        console.log('NATIVE STACK NOTE');
        console.log('  Zero checkServerTrusted calls and zero Java handshakes were seen.');
        console.log('  If the app is plainly making network requests, its TLS is running');
        console.log('  in NATIVE code -- a statically linked BoringSSL inside Flutter,');
        console.log('  Cronet, Unity or a custom .so. No Java hook reaches that. Trace');
        console.log('  SSL_CTX_set_custom_verify / SSL_read / SSL_write instead; see');
        console.log('  ../../53-Frida/scripts/ssl-pinning-bypass.js layer 6 for the shape.');
        console.log('  This is a REAL RESULT. It is not "the app performs no validation".');
    }
    console.log('Reminder: this script observed and changed nothing. A clean report');
    console.log('still needs the deliberate-bad-certificate test to be evidence.');
    console.log('');
}

/* ------------------------------------------------------------- bootstrap */

Java.perform(function () {
    console.log('');
    console.log('==================================================');
    console.log('  trace-tls-validation.js');
    console.log('  observe TLS trust decisions -- bypass nothing');
    console.log('==================================================');
    console.log('');

    traceConstruction();
    traceNegotiation();
    traceWebView();
    var n = sweep();

    console.log('');
    console.log('[*] ' + hookCount + ' hook(s) installed; sweep wrapped ' + n + ' class(es).');
    console.log('[*] Exercise the app, then call:');
    console.log('        verdict()   what it actually validates');
    console.log('        oracle()    feed each TrustManager an empty chain');
    console.log('');
});

/*
 * Deferred rescan. TLS classes are very often loaded lazily -- the first
 * network call is what pulls in the trust machinery, and at spawn time none
 * of it exists. Without this, an app is regularly reported as having no
 * TrustManager at all when it simply had not made a request yet.
 */
if (RESCAN_SECONDS > 0) {
    setTimeout(function () {
        Java.perform(function () {
            var before = Object.keys(seenTrustManagers).length +
                         Object.keys(seenHostnameVerifiers).length;
            sweep();
            var after = Object.keys(seenTrustManagers).length +
                        Object.keys(seenHostnameVerifiers).length;
            if (after > before) {
                console.log('[*] deferred rescan found ' + (after - before) +
                            ' additional class(es) loaded since startup.');
            }
        });
    }, RESCAN_SECONDS * 1000);
}

rpc.exports = {
    verdict: function () { Java.perform(printVerdict); },
    oracle: function () { runOracle(); },
    rescan: function () { Java.perform(function () { sweep(); }); },
    /* Machine-readable, for a lab write-up or a diff between two runs. */
    dump: function () {
        return {
            trustManagers: seenTrustManagers,
            hostnameVerifiers: seenHostnameVerifiers,
            sslContexts: seenContexts,
            handshakes: seenSockets,
            pinningEvidence: pinningEvidence
        };
    }
};

/* Also expose the two useful calls as bare globals, because typing
 * `verdict()` in the Frida REPL is how they are actually used. */
globalThis.verdict = function () { Java.perform(printVerdict); };
globalThis.oracle = function () { runOracle(); };
globalThis.rescan = function () { Java.perform(function () { sweep(); }); };
