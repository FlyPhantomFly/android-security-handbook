/*
 * apk-signature-hooks.js — watch, and optionally defeat, every Java-side route
 *                          an app uses to ask "who signed me?"
 *
 * WHAT IT DOES
 *   Runs inside the target process and instruments the whole self-signature
 *   API surface listed in ../cheatsheet.md section 25:
 *
 *     PackageManager.getPackageInfo(pkg, GET_SIGNATURES)        legacy, API 1+
 *     PackageManager.getPackageInfo(pkg, GET_SIGNING_CERTIFICATES)  API 28+
 *     PackageManager.getPackageInfo(pkg, PackageInfoFlags)      API 33+
 *     SigningInfo.getApkContentsSigners()                       API 28+
 *     SigningInfo.getSigningCertificateHistory()                API 28+
 *     PackageManager.hasSigningCertificate(...)                 API 28+
 *     PackageManager.checkSignatures(...)                       API 1+
 *     Signature.toByteArray() / toCharsString()
 *     MessageDigest.digest(byte[])   - reports digests taken over a Signature
 *     ZipFile / RandomAccessFile opened on the app's own sourceDir
 *
 *   In the default mode it changes NOTHING. It prints every call, the value
 *   returned, and the Java stack that led there, so that you can find the
 *   check in the decompiled code. That is normally what you want first:
 *   knowing there are four checks and where they live is worth more than
 *   silencing one of them.
 *
 *   Set MODE to "spoof" and it returns the ORIGINAL signing certificate
 *   regardless of how the APK is actually signed, so a re-signed build passes
 *   its own integrity test.
 *
 * WHY THIS EXISTS SEPARATELY FROM PATCHING
 *   Re-signing an APK breaks every binding that depends on the app's real
 *   identity - Play Integrity, App Check, signature-level permissions, API
 *   keys pinned to a fingerprint, App Links. See ../labs/lab-02, part 5. The
 *   rule that follows is: patch to understand, hook to observe. This script is
 *   the "hook to observe" half, and it runs against the ORIGINAL, untouched,
 *   still-validly-signed APK.
 *
 * WHAT THIS WILL *NOT* DO
 *   - Defeat a NATIVE check. An app that opens its own base.apk in C++, walks
 *     the ZIP, finds "APK Sig Block 42" and digests the certificate itself
 *     never calls any of these Java methods, so none of these hooks fire. The
 *     script tries to TELL you when that is happening (see WATCH_NATIVE_OPEN),
 *     but defeating it means Interceptor.attach on the native function or a
 *     static patch. See ../README.md section 11 and 65-Hooking.
 *   - Defeat a server-side check. Play Integrity and any backend that pins the
 *     signing certificate digest are decided outside this process. Nothing you
 *     do in the app can forge them; that is the design.
 *   - Find checks that have not run yet. A check inside a feature you have not
 *     opened produces no output. Drive the app.
 *   - Tell you the check was the reason the app misbehaved. Apps that detect
 *     tampering often degrade silently, minutes later, somewhere unrelated.
 *   - Survive obfuscation of the CALLERS. The framework methods are stable, so
 *     the hooks always land; the stack traces will be full of obfuscated names
 *     and you will have to map them yourself.
 *
 * HOW TO RUN
 *     # host - spawn the app with the hooks in place
 *     frida -U -f com.example.target -l apk-signature-hooks.js
 *
 *     # host - attach to a running app instead
 *     frida -U -n com.example.target -l apk-signature-hooks.js
 *
 *     # from the chapter directory, exactly as the chapter prints it
 *     frida -U -f com.example -l scripts/apk-signature-hooks.js
 *
 *   To spoof, first read the ORIGINAL certificate off the original APK:
 *
 *     # host
 *     python3 ../examples/parse_signing_block.py --dump-certs original.apk
 *     xxd -p signer0_cert0.der | tr -d '\n'
 *
 *   Paste that hex into ORIGINAL_CERT_HEX below and set MODE = "spoof".
 *   Note: Signature wraps the DER of the CERTIFICATE, which is exactly what
 *   that file contains, so no further conversion is needed.
 *
 * REQUIREMENTS
 *   Frida 15 or newer, a frida-server matching your device's ABI, and a device
 *   you are authorised to test. See ../../53-Frida/README.md.
 *
 * RELATED
 *   ../README.md section 14              hooking runtime signature checks
 *   ../README.md section 11              the native check this cannot reach
 *   ../labs/lab-02-unpack-modify-rebuild-resign.md   part 5
 *   ../examples/parse_signing_block.py   where the original certificate comes from
 *
 * AUTHORISED TESTING ONLY.
 */

'use strict';

// ---------------------------------------------------------------- config ---

// "observe" changes nothing and prints everything. Start here, always.
// "spoof"   returns ORIGINAL_CERT_HEX from every Java-side path.
var MODE = 'observe';

// DER bytes of the ORIGINAL signing certificate, as hex. Only used in spoof
// mode. Obtain with parse_signing_block.py --dump-certs on the original APK.
var ORIGINAL_CERT_HEX = '';

// Print a Java stack trace for every hit. Verbose, and the single most useful
// thing here: it tells you WHICH class does the check.
var SHOW_STACKS = true;

// Also watch for the app opening its own APK, which is what a native or
// hand-rolled check does before it parses the signing block itself.
var WATCH_SELF_APK = true;

// Attach to libc open()/openat() and report any path ending .apk. Noisy on
// some devices; the payoff is that it fires for checks written in C++ that no
// Java hook can see.
var WATCH_NATIVE_OPEN = false;

// ------------------------------------------------------------------------

var GET_SIGNATURES = 0x00000040;
var GET_SIGNING_CERTIFICATES = 0x08000000;

var CHECK_SIGNATURES_RESULTS = {
    '0': 'SIGNATURE_MATCH',
    '1': 'SIGNATURE_NEITHER_SIGNED',
    '-1': 'SIGNATURE_FIRST_NOT_SIGNED',
    '-2': 'SIGNATURE_SECOND_NOT_SIGNED',
    '-3': 'SIGNATURE_NO_MATCH',
    '-4': 'SIGNATURE_UNKNOWN_PACKAGE'
};

var hits = {};
var selfApkPath = null;

function log(msg) {
    console.log('[apk-sig] ' + msg);
}

function count(what) {
    hits[what] = (hits[what] || 0) + 1;
    return hits[what];
}

function stack() {
    if (!SHOW_STACKS) return '';
    try {
        var Log = Java.use('android.util.Log');
        var Exception = Java.use('java.lang.Exception');
        var trace = Log.getStackTraceString(Exception.$new());
        // Drop the frames inside the framework itself; the caller is what
        // you are looking for.
        var lines = trace.split('\n').filter(function (l) {
            return l.indexOf('android.app.ApplicationPackageManager') === -1 &&
                   l.indexOf('java.lang.Exception') === -1 &&
                   l.trim().length > 0;
        });
        return '\n        ' + lines.slice(0, 8).join('\n        ');
    } catch (e) {
        return '  (stack unavailable: ' + e + ')';
    }
}

function toHex(bytes) {
    var out = '';
    for (var i = 0; i < bytes.length; i++) {
        var b = bytes[i] & 0xff;
        out += (b < 16 ? '0' : '') + b.toString(16);
    }
    return out;
}

function sha256Of(byteArray) {
    try {
        var MessageDigest = Java.use('java.security.MessageDigest');
        var md = MessageDigest.getInstance('SHA-256');
        return toHex(md.digest(byteArray));
    } catch (e) {
        return '<digest failed: ' + e + '>';
    }
}

function originalSignature() {
    if (!ORIGINAL_CERT_HEX) {
        log('!! MODE is "spoof" but ORIGINAL_CERT_HEX is empty. Falling back ' +
            'to observe for this call. Read the header of this file.');
        return null;
    }
    var Signature = Java.use('android.content.pm.Signature');
    // Signature(String) parses a hex string of the certificate's DER bytes.
    return Signature.$new(ORIGINAL_CERT_HEX);
}

function spoofing() {
    return MODE === 'spoof' && ORIGINAL_CERT_HEX.length > 0;
}

// ------------------------------------------------------------------------

Java.perform(function () {

    log('mode = ' + MODE + (spoofing() ? '  (RETURNING THE ORIGINAL CERT)'
                                       : '  (observing only, nothing changed)'));

    // ---- where is our own APK, and what is its real signer? -------------
    try {
        var ActivityThread = Java.use('android.app.ActivityThread');
        var app = ActivityThread.currentApplication();
        if (app !== null) {
            var ctx = app.getApplicationContext();
            var ai = ctx.getApplicationInfo();
            selfApkPath = ai.sourceDir.value;
            log('sourceDir      : ' + selfApkPath);
            var splits = ai.splitSourceDirs.value;
            log('splitSourceDirs: ' + (splits === null ? 'none' : splits));
            log('package        : ' + ctx.getPackageName());
        }
    } catch (e) {
        log('could not read ApplicationInfo yet: ' + e);
    }

    // ---- getPackageInfo, all three overloads ----------------------------
    var APM = Java.use('android.app.ApplicationPackageManager');

    function describePackageInfo(info, pkg, flags, tag) {
        var wantLegacy = (flags & GET_SIGNATURES) !== 0;
        var wantModern = (flags & GET_SIGNING_CERTIFICATES) !== 0;
        if (!wantLegacy && !wantModern) return;

        var n = count(tag);
        log('#' + n + ' ' + tag + '(' + pkg + ', flags=0x' +
            (flags >>> 0).toString(16) + ')' +
            (wantLegacy ? '  GET_SIGNATURES' : '') +
            (wantModern ? '  GET_SIGNING_CERTIFICATES' : '') + stack());

        try {
            if (wantLegacy && info.signatures.value !== null) {
                var sigs = info.signatures.value;
                for (var i = 0; i < sigs.length; i++) {
                    log('    signatures[' + i + '] SHA-256 = ' +
                        sha256Of(sigs[i].toByteArray()));
                }
                if (spoofing()) {
                    var replacement = originalSignature();
                    if (replacement !== null) {
                        info.signatures.value = [replacement];
                        log('    -> replaced signatures[] with the original');
                    }
                }
            }
            if (wantModern && info.signingInfo.value !== null) {
                var si = info.signingInfo.value;
                var current = si.getApkContentsSigners();
                for (var j = 0; j < current.length; j++) {
                    log('    apkContentsSigners[' + j + '] SHA-256 = ' +
                        sha256Of(current[j].toByteArray()));
                }
                log('    hasMultipleSigners = ' + si.hasMultipleSigners());
                // The SigningInfo getters are hooked separately below, which
                // is where spoofing happens for this path - poking the private
                // mSigningDetails field works on some releases and not others.
            }
        } catch (e) {
            log('    (could not read: ' + e + ')');
        }
    }

    APM.getPackageInfo.overload('java.lang.String', 'int').implementation =
        function (pkg, flags) {
            var info = this.getPackageInfo(pkg, flags);
            describePackageInfo(info, pkg, flags, 'getPackageInfo');
            return info;
        };

    // API 33+ wraps the flags in a PackageInfoFlags object.
    try {
        APM.getPackageInfo.overload(
            'java.lang.String',
            'android.content.pm.PackageManager$PackageInfoFlags'
        ).implementation = function (pkg, flagsObj) {
            var info = this.getPackageInfo(pkg, flagsObj);
            var raw = 0;
            try { raw = flagsObj.getValue(); } catch (e) { /* keep 0 */ }
            describePackageInfo(info, pkg, raw, 'getPackageInfo[Flags]');
            return info;
        };
    } catch (e) {
        log('PackageInfoFlags overload not present (pre-API 33 device)');
    }

    // ---- SigningInfo getters -------------------------------------------
    try {
        var SigningInfo = Java.use('android.content.pm.SigningInfo');

        SigningInfo.getApkContentsSigners.implementation = function () {
            var real = this.getApkContentsSigners();
            var n = count('getApkContentsSigners');
            var digests = [];
            for (var i = 0; i < real.length; i++) {
                digests.push(sha256Of(real[i].toByteArray()));
            }
            log('#' + n + ' SigningInfo.getApkContentsSigners() -> ' +
                digests.join(', ') + stack());
            if (spoofing()) {
                var s = originalSignature();
                if (s !== null) {
                    log('    -> returning the original certificate instead');
                    return [s];
                }
            }
            return real;
        };

        SigningInfo.getSigningCertificateHistory.implementation = function () {
            var real = this.getSigningCertificateHistory();
            var n = count('getSigningCertificateHistory');
            log('#' + n + ' SigningInfo.getSigningCertificateHistory() -> ' +
                real.length + ' entr' + (real.length === 1 ? 'y' : 'ies') +
                '  (this is the v3 ROTATION LINEAGE, not just the current key)' +
                stack());
            if (spoofing()) {
                var s = originalSignature();
                if (s !== null) return [s];
            }
            return real;
        };
    } catch (e) {
        log('SigningInfo not available (pre-API 28 device): ' + e);
    }

    // ---- hasSigningCertificate -----------------------------------------
    try {
        APM.hasSigningCertificate.overload(
            'java.lang.String', '[B', 'int'
        ).implementation = function (pkg, cert, type) {
            var real = this.hasSigningCertificate(pkg, cert, type);
            var n = count('hasSigningCertificate');
            log('#' + n + ' hasSigningCertificate("' + pkg + '", ' +
                cert.length + ' bytes, type=' + type +
                (type === 0 ? ' CERT_INPUT_RAW_X509' : ' CERT_INPUT_SHA256') +
                ') -> ' + real +
                '\n        expected: ' + toHex(cert).substring(0, 64) + '...' +
                stack());
            if (spoofing() && !real) {
                log('    -> forcing true');
                return true;
            }
            return real;
        };
    } catch (e) {
        log('hasSigningCertificate(String,...) not hookable: ' + e);
    }

    // ---- checkSignatures ------------------------------------------------
    try {
        APM.checkSignatures.overload('java.lang.String', 'java.lang.String')
            .implementation = function (a, b) {
                var real = this.checkSignatures(a, b);
                var n = count('checkSignatures');
                log('#' + n + ' checkSignatures("' + a + '", "' + b + '") -> ' +
                    real + ' ' + (CHECK_SIGNATURES_RESULTS[String(real)] || '') +
                    stack());
                if (spoofing() && real !== 0) {
                    log('    -> forcing SIGNATURE_MATCH (0)');
                    return 0;
                }
                return real;
            };
    } catch (e) {
        log('checkSignatures not hookable: ' + e);
    }

    // ---- Signature.toByteArray / toCharsString --------------------------
    // Apps digest these. Watching them catches a check that reads the
    // signature by a route the hooks above missed.
    try {
        var Signature = Java.use('android.content.pm.Signature');
        Signature.toCharsString.implementation = function () {
            var real = this.toCharsString();
            var n = count('Signature.toCharsString');
            if (n <= 5) {
                log('#' + n + ' Signature.toCharsString() -> ' +
                    real.substring(0, 48) + '...' + stack());
            }
            return real;
        };
    } catch (e) {
        log('Signature.toCharsString not hookable: ' + e);
    }

    // ---- MessageDigest over signature bytes -----------------------------
    // The overwhelmingly common shape is
    //   MessageDigest.getInstance("SHA-256").digest(sig.toByteArray())
    // so a digest whose input starts with 0x30 0x82 (a DER SEQUENCE) is
    // almost certainly a certificate being hashed.
    try {
        var MD = Java.use('java.security.MessageDigest');
        MD.digest.overload('[B').implementation = function (input) {
            var out = this.digest(input);
            if (input !== null && input.length > 2 &&
                (input[0] & 0xff) === 0x30 && (input[1] & 0xff) === 0x82) {
                var n = count('MessageDigest.digest(cert)');
                log('#' + n + ' MessageDigest.digest() over ' + input.length +
                    ' bytes starting 30 82 - a DER certificate is being ' +
                    'hashed\n        result = ' + toHex(out) + stack());
                log('        Compare that against the value the app has ' +
                    'hardcoded. Search the DEX for it:\n' +
                    '        python3 ../../04-Java/scripts/dump-strings.py ' +
                    'target.apk --min-len 32 | grep -i <first 8 hex chars>');
            }
            return out;
        };
    } catch (e) {
        log('MessageDigest.digest not hookable: ' + e);
    }

    // ---- the app opening its own APK ------------------------------------
    if (WATCH_SELF_APK) {
        try {
            var ZipFile = Java.use('java.util.zip.ZipFile');
            ZipFile.$init.overload('java.lang.String').implementation =
                function (path) {
                    if (selfApkPath !== null && path === selfApkPath) {
                        log('!! ZipFile opened on the app\'s OWN APK (' + path +
                            ')\n        The app is parsing its own container. ' +
                            'That is a hand-rolled integrity check; none of ' +
                            'the PackageManager hooks above will see it.' +
                            stack());
                    }
                    return this.$init(path);
                };
        } catch (e) {
            log('ZipFile(String) not hookable: ' + e);
        }

        try {
            var RAF = Java.use('java.io.RandomAccessFile');
            RAF.$init.overload('java.lang.String', 'java.lang.String')
                .implementation = function (path, mode) {
                    if (path !== null && path.indexOf('.apk') !== -1) {
                        log('!! RandomAccessFile("' + path + '", "' + mode +
                            '")\n        Raw seeking inside an APK. Expect an ' +
                            'EOCD scan and an "APK Sig Block 42" lookup - see ' +
                            '../README.md section 11.' + stack());
                    }
                    return this.$init(path, mode);
                };
        } catch (e) {
            log('RandomAccessFile(String,String) not hookable: ' + e);
        }
    }

    log('Java-side hooks installed. Drive the app; every check that runs will ' +
        'print.');
    log('Press Ctrl-D (or type exit) in the Frida REPL for the hit summary.');
});

// ---- native open(), outside Java.perform --------------------------------
if (WATCH_NATIVE_OPEN) {
    ['open', 'openat'].forEach(function (fn) {
        var addr = Module.findExportByName('libc.so', fn);
        if (addr === null) return;
        Interceptor.attach(addr, {
            onEnter: function (args) {
                // openat(dirfd, path, ...) puts the path in args[1].
                var pathArg = (fn === 'openat') ? args[1] : args[0];
                try {
                    var path = pathArg.readUtf8String();
                    if (path && path.indexOf('.apk') !== -1) {
                        console.log('[apk-sig][native] ' + fn + '("' + path +
                            '")\n    from ' +
                            Thread.backtrace(this.context,
                                             Backtracer.ACCURATE)
                                .map(DebugSymbol.fromAddress)
                                .slice(0, 6)
                                .join('\n         '));
                        console.log('    A native read of an APK path is the ' +
                            'check no Java hook can see. Find the caller in ' +
                            'Ghidra, then Interceptor.attach it directly.');
                    }
                } catch (e) { /* unreadable pointer, ignore */ }
            }
        });
    });
}

// ---- callable from the REPL ---------------------------------------------
// In the Frida REPL:  %resume  then  rpc.exports.summary()
rpc.exports = {
    summary: function () {
        return hits;
    },
    setmode: function (mode) {
        MODE = mode;
        return 'mode is now ' + MODE;
    }
};
