/*
 * nsc-runtime.js — ask the PLATFORM what network security policy it actually
 *                  built for this app, instead of inferring it from the XML.
 *
 * WHAT IT DOES
 *     Reads android.security.net.config.ApplicationConfig — the single object
 *     the whole mechanism collapses into at runtime — and prints:
 *
 *       * the manifest facts that decide how the XML was interpreted:
 *         targetSdkVersion, FLAG_DEBUGGABLE, FLAG_USES_CLEARTEXT_TRAFFIC and
 *         ApplicationInfo.networkSecurityConfigRes (the resource id, 0 when the
 *         app declares no config at all);
 *       * every per-domain configuration the platform built, with the hostname
 *         and whether subdomains are included;
 *       * for each: the effective cleartext verdict, the effective HSTS flag,
 *         the ORDERED list of certificate SOURCES (system store, user store,
 *         a bundled resource, a directory) with each entry's overridePins flag,
 *         and the pin-set with its pin count and expiry as a real date;
 *       * the default configuration, which is what every host that no
 *         domain-config matches gets;
 *       * how many certificates the system and user stores each hold right now;
 *       * the answer for the hostnames listed in CONFIG.hosts below, resolved
 *         through the platform's own matching rather than your reading of the
 *         file.
 *
 * WHY YOU NEED IT EVEN THOUGH YOU HAVE READ THE XML
 *     ./nsc-audit.py reads a file inside an APK. Six things happen between that
 *     file and the policy in force, and each of them can change the answer:
 *
 *       1. Inheritance. A <domain-config> that omits cleartextTrafficPermitted
 *          silently takes <base-config>'s, and <base-config> takes the
 *          platform's targetSdk-dependent default. The file shows an absence;
 *          this shows the value.
 *       2. <debug-overrides> is applied only when FLAG_DEBUGGABLE is set. The
 *          file cannot tell you whether it was.
 *       3. Split APKs and resource overlays can replace res/xml/* after build.
 *       4. An OEM can patch the framework. This device's vendor has patched
 *          activity starts and service starts already; assume nothing.
 *       5. An app can call ApplicationConfig.setDefaultInstance() itself.
 *       6. You may simply have resolved the wrong resource id.
 *
 *     When this and the static audit disagree, THIS is right and the
 *     disagreement is the finding.
 *
 * WHAT THIS WILL *NOT* TELL YOU
 *     - Whether the app obeys the policy. Everything here is what the platform
 *       will enforce for code that asks it. An app with a bundled BoringSSL, a
 *       Flutter/Dart:io HTTP client, a Cronet build with its own trust store, or
 *       its own X509TrustManager can ignore all of it. Only a packet capture
 *       settles that. See chapter 36, 36-CertificatePinning.
 *     - Whether a connection succeeded. This reads policy, it does not observe
 *       traffic. Set CONFIG.trace to additionally log the platform trust manager
 *       being invoked, which at least proves the policy is on the code path.
 *     - Anything about raw sockets. Nothing in this subsystem sees them.
 *     - Certificate pinning done in code. A pin count of 0 here means no
 *         <pin-set>; it does not mean "not pinned".
 *     - What the config file SAID. If the platform threw while parsing it, you
 *       get the default config and no error here. Run ./nsc-audit.py too, and
 *       watch logcat when the app first uses the network.
 *
 * HOW TO RUN
 *     # host — the app must already be running (spawn-time is fine too)
 *     frida -U -f com.example.app -l nsc-runtime.js
 *     frida -U -p $(adb shell pidof com.example.app) -l nsc-runtime.js
 *
 *     # host — also hook the trust manager so you see it being used
 *     # (set CONFIG.trace below, or drive it over rpc)
 *
 *     TO ASK ABOUT PARTICULAR HOSTNAMES, edit CONFIG.hosts at the top of this
 *     file. The frida CLI's -P/--parameters flag does NOT reach a plain agent
 *     script — `typeof parameters` is "undefined" under `frida -l script.js`,
 *     measured on frida-tools 16.1.6, so anything documented that way silently
 *     does nothing. This script reads `parameters` if it happens to exist (it
 *     does under frida-gadget) and otherwise uses CONFIG.
 *
 *     From your own harness, prefer rpc:
 *         script.exports_sync.dump({hosts: ['api.example.com'], trace: true})
 *
 *     On Windows set PYTHONIOENCODING=utf-8 before frida if any hostname in the
 *     config is non-ASCII, or the console codec will truncate the output.
 *
 * REQUIREMENTS
 *     frida-server on the device (root), frida 12+ on the host. Android 7
 *     (API 24) or newer — the android.security.net.config package does not
 *     exist below that, and the script says so rather than throwing.
 *
 *     Verified on a Redmi M2101K6P, MIUI 12.5, Android 11 / API 30, frida
 *     16.1.6. On that release NetworkSecurityConfig has no public hasPins() and
 *     ApplicationConfig exposes no getter for its per-domain table, so this
 *     script reads two private fields by reflection. Both reads are guarded and
 *     degrade to "unavailable" rather than aborting the dump.
 *
 * AUTHORISED TESTING ONLY.
 */

'use strict';

var NSC_PKG = 'android.security.net.config.';

/* ------------------------------------------------------------------------
 * EDIT THIS. The frida CLI does not pass -P/--parameters to a plain agent
 * script, so this object is how you configure the run.
 *   hosts : hostnames to resolve through the platform's own matching. Include
 *           at least one you expect a <domain-config> to match, one you expect
 *           it not to, and a literal IP address — the gaps in a policy are
 *           usually at exactly those three points.
 *   trace : hook NetworkSecurityTrustManager.checkServerTrusted so you can see
 *           whether the platform trust manager is on the app's code path.
 * ---------------------------------------------------------------------- */
var CONFIG = {
    hosts: ['example.com', 'localhost', '127.0.0.1', '10.0.2.2'],
    trace: false
};

function argOpts() {
    var opts = { hosts: CONFIG.hosts.slice(), trace: CONFIG.trace };
    /* frida-gadget DOES define a `parameters` global; the CLI does not. Read it
     * if it is there so the same file works in both harnesses. */
    try {
        // eslint-disable-next-line no-undef
        var p = (typeof parameters !== 'undefined') ? parameters : null;
        if (p && p.hosts) { opts.hosts = ('' + p.hosts).split(','); }
        if (p && p.trace) { opts.trace = true; }
    } catch (e) { /* ignore */ }
    return opts;
}

/* ------------------------------------------------------------------ util */

function line(s) { console.log(s); }

function hr(title) {
    line('');
    line('=== ' + title + ' ' + Array(Math.max(2, 62 - title.length)).join('='));
}

function field(className, fieldName) {
    /* Reflective private-field access, because the platform exposes no getter
     * for the two things a tester most wants: ApplicationConfig's per-domain
     * table and NetworkSecurityConfig's ordered list of certificate sources. */
    var f = Java.use(className).class.getDeclaredField(fieldName);
    f.setAccessible(true);
    return f;
}

function tryField(className, fieldName) {
    try { return field(className, fieldName); } catch (e) { return null; }
}

function msToDate(ms) {
    if (ms === null || ms === undefined) { return 'unknown'; }
    var n = Number(ms);
    /* PinSet.EMPTY_PINSET uses Long.MAX_VALUE for "never expires". */
    if (n >= 9007199254740991) { return 'never (Long.MAX_VALUE)'; }
    var d = new Date(n);
    var iso = d.toISOString().substring(0, 19) + 'Z';
    var days = Math.floor((n - Date.now()) / 86400000);
    if (days < 0) { return iso + '  *** EXPIRED ' + (-days) + ' days ago ***'; }
    return iso + '  (' + days + ' days away)';
}

function simpleName(obj) {
    try { return obj.getClass().getSimpleName(); } catch (e) { return '' + obj; }
}

/* --------------------------------------------------------------- the dump */

function dump(opts) {
    opts = opts || { hosts: [], trace: false };

    var ActivityThread = Java.use('android.app.ActivityThread');
    var app = ActivityThread.currentApplication();
    if (app === null) {
        line('[!] no Application object yet. If you spawned the process, this ' +
             'script ran before');
        line('    ActivityThread.handleBindApplication finished. Attach ' +
             'instead, or wrap this');
        line('    call in a setTimeout of a second or two.');
        return;
    }
    var ctx = app.getApplicationContext();
    var ai = ctx.getApplicationInfo();
    var flags = ai.flags.value;

    var FLAG_DEBUGGABLE = 1 << 1;               /* ApplicationInfo.FLAG_DEBUGGABLE */
    var FLAG_CLEARTEXT = 1 << 27;               /* FLAG_USES_CLEARTEXT_TRAFFIC   */

    hr('app');
    line('  package                       : ' + ctx.getPackageName());
    line('  targetSdkVersion              : ' + ai.targetSdkVersion.value);
    line('  ApplicationInfo.flags         : 0x' + (flags >>> 0).toString(16));
    line('  FLAG_DEBUGGABLE               : ' + ((flags & FLAG_DEBUGGABLE) !== 0) +
         '   <-- decides whether <debug-overrides> applies AT ALL');
    line('  FLAG_USES_CLEARTEXT_TRAFFIC   : ' + ((flags & FLAG_CLEARTEXT) !== 0) +
         '   <-- the manifest boolean; a config OVERRIDES it');
    try {
        var res = ai.networkSecurityConfigRes.value;
        line('  networkSecurityConfigRes      : 0x' + (res >>> 0).toString(16) +
             (res === 0 ? '   (no config declared - platform defaults apply)' : ''));
    } catch (e) {
        line('  networkSecurityConfigRes      : field not present on this release');
    }

    /* -------------------------------------------------- the trust stores */

    hr('certificate stores, as they are RIGHT NOW');
    [['SystemCertificateSource', '/system/etc/security/cacerts'],
     ['UserCertificateSource', '/data/misc/user/0/cacerts-added']].forEach(function (pair) {
        try {
            var src = Java.use(NSC_PKG + pair[0]).getInstance();
            line('  ' + pair[0] + ' : ' + src.getCertificates().size() +
                 ' certificate(s)   (' + pair[1] + ')');
        } catch (e) {
            line('  ' + pair[0] + ' : unavailable (' + e + ')');
        }
    });
    line('');
    line('  Both counts are read from the device you are on. On a rooted test');
    line('  device the SYSTEM count is frequently not the platform\'s: Magisk and');
    line('  APatch modules bind-mount a tmpfs over /system/etc/security/cacerts');
    line('  and add the proxy CA there. Check before you conclude anything about');
    line('  default trust:   adb shell "su -c \'mount | grep cacerts\'"');

    /* ------------------------------------------------- ApplicationConfig */

    var AC;
    try {
        AC = Java.use(NSC_PKG + 'ApplicationConfig');
    } catch (e) {
        hr('android.security.net.config is not present');
        line('  This device is below API 24, or the framework has been stripped.');
        line('  Nothing below can be measured. ' + e);
        return;
    }

    var appConfig = AC.getDefaultInstance();
    if (appConfig === null) {
        line('[!] ApplicationConfig.getDefaultInstance() is null. The provider ' +
             'has not installed');
        line('    a config yet. Make the app perform one network call and run ' +
             'this again.');
        return;
    }

    /* ensureInitialized() is private and lazy; any public call triggers it, and
     * until it runs the private mConfigs field is null. */
    try { appConfig.getConfigForHostname('example.com'); } catch (e) { /* ignore */ }

    var fConfigs = tryField(NSC_PKG + 'ApplicationConfig', 'mConfigs');
    var fDefault = tryField(NSC_PKG + 'ApplicationConfig', 'mDefaultConfig');
    var fRefs = tryField(NSC_PKG + 'NetworkSecurityConfig', 'mCertificatesEntryRefs');
    var fSource = tryField(NSC_PKG + 'CertificatesEntryRef', 'mSource');
    var fOverride = tryField(NSC_PKG + 'CertificatesEntryRef', 'mOverridesPins');

    var NSCfg = Java.use(NSC_PKG + 'NetworkSecurityConfig');
    var JList = Java.use('java.util.List');
    var JSet = Java.use('java.util.Set');
    var Domain = Java.use(NSC_PKG + 'Domain');
    var Pair = Java.use('android.util.Pair');
    var Base64 = Java.use('android.util.Base64');

    function describe(raw, label, indent) {
        var pad = indent || '  ';
        var cfg = Java.cast(raw, NSCfg);
        line(pad + label);
        line(pad + '    cleartextTrafficPermitted : ' +
             cfg.isCleartextTrafficPermitted());
        try {
            line(pad + '    hstsEnforced              : ' + cfg.isHstsEnforced());
        } catch (e) { /* not on every release */ }

        if (fRefs !== null) {
            try {
                var l = Java.cast(fRefs.get(raw), JList);
                var parts = [];
                for (var i = 0; i < l.size(); i++) {
                    var ref = l.get(i);
                    var src = fSource !== null ? simpleName(fSource.get(ref)) : '?';
                    var ov = fOverride !== null ? fOverride.get(ref) : '?';
                    parts.push(src + (String(ov) === 'true' ? ' [overridePins]' : ''));
                }
                line(pad + '    trust anchor sources      : ' +
                     (parts.length ? parts.join(', ') : '(none - NOTHING validates)'));
            } catch (e) {
                line(pad + '    trust anchor sources      : unavailable (' + e + ')');
            }
        }
        try {
            line(pad + '    trust anchors resolved    : ' +
                 cfg.getTrustAnchors().size() + ' certificate(s)');
        } catch (e) { /* resolving can be expensive; not fatal */ }

        try {
            var ps = cfg.getPins();
            var n = ps.pins.value.size();
            line(pad + '    pin-set                   : ' + n + ' pin(s)');
            if (n > 0) {
                line(pad + '    pin-set expiry            : ' +
                     msToDate(ps.expirationTime.value));
                var it = ps.pins.value.iterator();
                while (it.hasNext()) {
                    var pin = it.next();
                    var b64 = Base64.encodeToString(pin.digest.value, 2);
                    line(pad + '        ' + pin.digestAlgorithm.value + '/' + b64);
                }
            }
        } catch (e) {
            line(pad + '    pin-set                   : unavailable (' + e + ')');
        }
    }

    hr('per-domain configurations the platform built');
    var any = false;
    if (fConfigs === null) {
        line('  mConfigs is not readable on this release. Use ' +
             'getConfigForHostname() with --hosts instead.');
    } else {
        var rawSet = fConfigs.get(appConfig);
        if (rawSet === null) {
            line('  mConfigs is null: this app has NO <domain-config> at all.');
            line('  Every host gets the default configuration printed below.');
        } else {
            var it = Java.cast(rawSet, JSet).iterator();
            while (it.hasNext()) {
                any = true;
                var p = Java.cast(it.next(), Pair);
                var d = Java.cast(p.first.value, Domain);
                describe(p.second.value,
                         d.hostname.value +
                         (d.subdomainsIncluded.value ? '   (+ all subdomains)' : '   (exact host only)'));
            }
            if (!any) { line('  the set is empty'); }
        }
    }

    hr('default configuration  <-- every host no domain-config matches');
    if (fDefault !== null) {
        try {
            describe(fDefault.get(appConfig), '<base-config> or platform default');
        } catch (e) {
            line('  unavailable (' + e + ')');
        }
    }

    /* --------------------------------------------------- specific hosts */

    var hosts = opts.hosts && opts.hosts.length ? opts.hosts : CONFIG.hosts;
    hr('answers for specific hostnames (the platform\'s own matching)');
    line('  host                                 cleartext   anchors  pins  expiry');
    hosts.forEach(function (h) {
        h = ('' + h).trim();
        if (!h) { return; }
        try {
            var c = appConfig.getConfigForHostname(h);
            var pn = 0, exp = 'never';
            try {
                pn = c.getPins().pins.value.size();
                if (pn > 0) { exp = msToDate(c.getPins().expirationTime.value); }
            } catch (e) { /* ignore */ }
            var anchors = '?';
            try { anchors = '' + c.getTrustAnchors().size(); } catch (e) { /* ignore */ }
            line('  ' + pad(h, 36) + pad('' + c.isCleartextTrafficPermitted(), 12) +
                 pad(anchors, 9) + pad('' + pn, 6) + exp);
        } catch (e) {
            line('  ' + pad(h, 36) + 'ERROR ' + e);
        }
    });
    line('');
    line('  NetworkSecurityPolicy.isCleartextTrafficPermitted() (no host) : ' +
         Java.use('android.security.NetworkSecurityPolicy').getInstance()
             .isCleartextTrafficPermitted());
    line('  That no-argument form is what a library calls when it has not been');
    line('  told the hostname. It returns the DEFAULT config\'s verdict, so an app');
    line('  can be denied cleartext by it and still permitted for a named domain.');

    if (opts.trace) { installTrace(); }

    hr('what this does NOT prove');
    line('  Everything above is policy the platform WILL enforce for code that');
    line('  asks it. It is not evidence that this app asks. Capture packets.');
}

function pad(s, n) {
    s = '' + s;
    while (s.length < n) { s += ' '; }
    return s;
}

/* --------------------------------------------------- CONFIG.trace = true */

function installTrace() {
    hr('tracing the platform trust manager');
    try {
        var NSTM = Java.use('android.security.net.config.NetworkSecurityTrustManager');
        NSTM.checkServerTrusted.overload(
            '[Ljava.security.cert.X509Certificate;', 'java.lang.String',
            'java.lang.String').implementation = function (chain, authType, host) {
            var subject = '(empty chain)';
            try { subject = chain[0].getSubjectDN().toString(); } catch (e) { /* ignore */ }
            line('[trust] checkServerTrusted host=' + host +
                 ' authType=' + authType + ' leaf=' + subject);
            try {
                var r = this.checkServerTrusted(chain, authType, host);
                line('[trust]   -> accepted, chain length ' + r.size());
                return r;
            } catch (e) {
                line('[trust]   -> REJECTED: ' + e);
                throw e;
            }
        };
        line('  hooked NetworkSecurityTrustManager.checkServerTrusted(chain, ' +
             'authType, host)');
        line('  Every line it prints proves the platform trust manager is on ' +
             'the code path.');
        line('  SILENCE during a successful HTTPS request is itself a finding: ' +
             'the app is');
        line('  validating certificates somewhere else, and none of the config ' +
             'above applies');
        line('  to it.');
    } catch (e) {
        line('  could not hook: ' + e);
    }
}

/* ---------------------------------------------------------------- entry */

Java.perform(function () {
    var opts = argOpts();
    try {
        dump(opts);
    } catch (e) {
        line('[!] ' + e + '\n' + (e.stack || ''));
    }
});

rpc.exports = {
    dump: function (opts) {
        var out = [];
        var real = console.log;
        console.log = function (s) { out.push(s); real(s); };
        try {
            Java.perform(function () { dump(opts || { hosts: [], trace: false }); });
        } finally {
            console.log = real;
        }
        return out.join('\n');
    }
};
