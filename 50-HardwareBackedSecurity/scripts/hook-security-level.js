/*
 * hook-security-level.js — what security level is this app's key REALLY getting?
 *
 * PURPOSE
 *   Sits between an app and the Keystore and answers the one question a static reading of the
 *   app's source cannot: for every key this app creates, what did the hardware actually give it?
 *
 *   It hooks the whole KeyGenParameterSpec builder chain so you see every option the app asked
 *   for, then hooks the generation calls and reads KeyInfo back so you see what it got. The two
 *   are printed side by side. When they differ, that difference is the finding.
 *
 *   It also reports:
 *     - StrongBoxUnavailableException being thrown and, crucially, what the app does next
 *     - any SecretKeySpec construction, which means raw key bytes are in the app's heap
 *     - any KeyInfo / getSecurityLevel read the app performs itself (its ABSENCE is the finding)
 *     - device capability: FEATURE_STRONGBOX_KEYSTORE and FEATURE_HARDWARE_KEYSTORE
 *
 * USAGE
 *   frida -U -f com.target.app -l hook-security-level.js                 # spawn
 *   frida -U -n com.target.app -l hook-security-level.js                 # attach to running
 *   frida -U -f com.target.app -l hook-security-level.js -o keys.txt     # log to a file
 *
 *   Then drive the app: log in, enrol a biometric, open the feature you care about. Keys are
 *   usually created lazily on first use, so an app you never exercise will show you nothing.
 *
 * REQUIREMENTS
 *   frida-server running on the device (which in practice means root), frida-tools on the host,
 *   Android 6+ (API 23) for KeyGenParameterSpec. Tested against frida 16.x.
 *
 *   If you do NOT have root: you cannot use this script, but you are not stuck. Use
 *   ./probe-security-levels.sh, which needs neither root nor an installed app, to measure the
 *   DEVICE. It cannot measure the app - see ../labs/lab-01-measure-every-key-type.md for how
 *   far you can get without root.
 *
 * WHAT THIS WILL *NOT* TELL YOU
 *   - It will NOT tell you the key is safe. It reports metadata; see ../../49-KeyStore/README.md
 *     section 1.3 on why "hardware-backed" and "an attacker cannot use it" are different claims.
 *     If you can run this script at all, you already have code execution in the process and could
 *     use every one of these keys.
 *   - It will NOT see keys created before it attached. Spawn with -f rather than attaching if you
 *     care about startup keys.
 *   - It will NOT see keys created in native code through JNI reflection unless those calls go
 *     through the same framework classes (they usually do).
 *   - It cannot distinguish "the TEE refused" from "the framework refused". It prints the
 *     exception verbatim so that you can.
 *   - A SOFTWARE result is not automatically a finding. On a device with no secure Keystore it is
 *     the only possible result. The finding is a MISMATCH between what the app claims or requests
 *     and what it verified. See section 1.4 of the chapter README.
 *
 * SAFETY
 *   Read-only instrumentation. It changes no return value, creates no key, deletes no key, and
 *   writes nothing to the device. It prints key ALIASES and metadata, never key material - and
 *   for a Keystore key there is no key material to print.
 */

'use strict';

var TAG = '[ch50]';

function line(s) { console.log(TAG + ' ' + s); }
function rule() { console.log(TAG + ' ' + '-'.repeat(76)); }

function levelName(n) {
    switch (n) {
        case 0: return 'SOFTWARE';
        case 1: return 'TRUSTED_ENVIRONMENT';
        case 2: return 'STRONGBOX';
        case -1: return 'UNKNOWN';
        case -2: return 'UNKNOWN_SECURE';
        default: return 'UNRECOGNISED(' + n + ')';
    }
}

// Everything the app asked for, per builder instance. Keyed by the builder's identityHashCode so
// that two keys being built concurrently do not contaminate each other's record.
var asked = {};

function record(builder, key, value) {
    var id;
    try {
        id = Java.use('java.lang.System').identityHashCode(builder);
    } catch (e) {
        id = 0;
    }
    if (!asked[id]) asked[id] = {};
    asked[id][key] = value;
    return asked[id];
}

function askedFor(spec) {
    // The spec no longer carries the builder identity, so fall back to reading the spec itself.
    var out = {};
    try {
        out.alias = spec.getKeystoreAlias();
        out.purposes = spec.getPurposes();
        out.keySize = spec.getKeySize();
        out.userAuthRequired = spec.isUserAuthenticationRequired();
        try { out.strongBox = spec.isStrongBoxBacked(); } catch (e) { out.strongBox = 'n/a'; }
        try { out.authValidity = spec.getUserAuthenticationValidityDurationSeconds(); } catch (e) { }
        try { out.unlockedDeviceRequired = spec.isUnlockedDeviceRequired(); } catch (e) { }
        try { out.randomizedEncryptionRequired = spec.isRandomizedEncryptionRequired(); } catch (e) { }
        try {
            var chal = spec.getAttestationChallenge();
            out.attestationChallenge = (chal === null) ? null : bytesToHex(chal);
        } catch (e) { }
    } catch (e) {
        out.error = String(e);
    }
    return out;
}

function bytesToHex(arr) {
    var s = '';
    for (var i = 0; i < arr.length; i++) {
        s += ('0' + (arr[i] & 0xff).toString(16)).slice(-2);
    }
    return s;
}

// ---------------------------------------------------------------- the read-back

function reportSecret(secretKey, context) {
    Java.perform(function () {
        try {
            var SKF = Java.use('javax.crypto.SecretKeyFactory');
            var KeyInfo = Java.use('android.security.keystore.KeyInfo');
            var f = SKF.getInstance(secretKey.getAlgorithm(), 'AndroidKeyStore');
            var info = Java.cast(f.getKeySpec(secretKey, KeyInfo.class), KeyInfo);
            printInfo(info, secretKey, context);
        } catch (e) {
            line('  read-back FAILED (' + context + '): ' + e);
        }
    });
}

function reportPrivate(privateKey, context) {
    Java.perform(function () {
        try {
            var KF = Java.use('java.security.KeyFactory');
            var KeyInfo = Java.use('android.security.keystore.KeyInfo');
            var f = KF.getInstance(privateKey.getAlgorithm(), 'AndroidKeyStore');
            var info = Java.cast(f.getKeySpec(privateKey, KeyInfo.class), KeyInfo);
            printInfo(info, privateKey, context);
        } catch (e) {
            line('  read-back FAILED (' + context + '): ' + e);
        }
    });
}

function printInfo(info, key, context) {
    var level, via;
    try {
        level = info.getSecurityLevel();              // API 31+
        via = 'getSecurityLevel()';
    } catch (e) {
        level = info.isInsideSecureHardware() ? 1 : 0;  // API 23-30
        via = 'isInsideSecureHardware()';
    }
    rule();
    line('GOT   alias=' + info.getKeystoreAlias());
    line('      SECURITY LEVEL = ' + levelName(level) + '   [' + via + ']');
    line('      keySize=' + info.getKeySize()
         + ' userAuthRequired=' + info.isUserAuthenticationRequired()
         + ' authValidity=' + info.getUserAuthenticationValidityDurationSeconds() + 's');
    try {
        line('      authEnforcedByHardware='
             + info.isUserAuthenticationRequirementEnforcedBySecureHardware());
    } catch (e) { }
    try {
        line('      invalidatedByBiometricEnrollment='
             + info.isInvalidatedByBiometricEnrollment());
    } catch (e) { }

    // The single most useful sanity check in the whole script. A Keystore key has no bytes.
    try {
        var enc = key.getEncoded();
        if (enc !== null) {
            line('      !!! getEncoded() RETURNED ' + enc.length
                 + ' BYTES - THIS KEY IS NOT IN THE KEYSTORE AT ALL !!!');
        } else {
            line('      getEncoded()=null (correct for a Keystore key)');
        }
    } catch (e) { }

    if (level === 0) {
        line('      NOTE: SOFTWARE. Before calling this a finding, check whether this DEVICE can');
        line('            do better - run ./probe-security-levels.sh. If the device offers TEE');
        line('            and this key is software, that is the finding.');
    }
    rule();
}

// ---------------------------------------------------------------- hooks

Java.perform(function () {

    // ---- device capability, printed once so every log is self-describing -------------------
    try {
        var ActivityThread = Java.use('android.app.ActivityThread');
        var ctx = ActivityThread.currentApplication().getApplicationContext();
        var pm = ctx.getPackageManager();
        var sb = pm.hasSystemFeature('android.hardware.strongbox_keystore');
        var hk = pm.hasSystemFeature('android.hardware.hardware_keystore');
        rule();
        line('package                 : ' + ctx.getPackageName());
        line('FEATURE_STRONGBOX       : ' + sb);
        line('FEATURE_HARDWARE_KEYSTORE: ' + hk
             + '   (absent below API 31 regardless of the hardware - see chapter section 3.4)');
        var Build = Java.use('android.os.Build');
        var VERSION = Java.use('android.os.Build$VERSION');
        line('device                  : ' + Build.MODEL.value + ' API ' + VERSION.SDK_INT.value);
        rule();
    } catch (e) {
        line('capability probe failed (no application context yet?): ' + e);
    }

    // ---- every builder option the app sets ---------------------------------------------------
    var Builder = Java.use('android.security.keystore.KeyGenParameterSpec$Builder');

    Builder.$init.overload('java.lang.String', 'int').implementation = function (alias, purposes) {
        var r = record(this, 'alias', alias);
        r.purposes = purposes;
        line('ASK   new Builder(alias="' + alias + '", purposes=0x' + purposes.toString(16) + ')');
        return this.$init(alias, purposes);
    };

    function traceSetter(name, sig, describe) {
        try {
            var m = Builder[name].overload.apply(Builder[name], sig);
            m.implementation = function () {
                var args = Array.prototype.slice.call(arguments);
                line('ASK     .' + name + '(' + describe(args) + ')');
                record(this, name, args.join(','));
                return m.apply(this, args);
            };
        } catch (e) {
            // The method does not exist on this platform. That is itself information: see the
            // chapter's note on setMaxUsageCount throwing NoSuchMethodError on an API 30 device.
            line('note  Builder.' + name + ' not present on this platform');
        }
    }

    var id = function (a) { return a.join(', '); };

    traceSetter('setIsStrongBoxBacked', ['boolean'], function (a) {
        return a[0] + (a[0] ? '   <-- REQUESTING THE SECURE ELEMENT' : '');
    });
    traceSetter('setUserAuthenticationRequired', ['boolean'], function (a) {
        return a[0] + (a[0] ? '' : '   <-- key usable with NO authentication');
    });
    traceSetter('setUserAuthenticationParameters', ['int', 'int'], function (a) {
        return a[0] + 's, type=' + a[1]
            + (a[0] === 0 ? '   <-- PER-USE binding (strong)'
                          : '   <-- ' + a[0] + '-SECOND WINDOW: any code in this process may use'
                            + ' the key, with no prompt, for ' + a[0] + 's after any unlock');
    });
    traceSetter('setUserAuthenticationValidityDurationSeconds', ['int'], function (a) {
        return a[0] + (a[0] === -1 ? '   <-- per-use (deprecated form of the strong binding)'
                                   : '   <-- ' + a[0] + '-second window');
    });
    traceSetter('setUnlockedDeviceRequired', ['boolean'], id);
    traceSetter('setInvalidatedByBiometricEnrollment', ['boolean'], function (a) {
        return a[0] + (a[0] ? '' : '   <-- FINDING: new biometric enrolments will NOT invalidate');
    });
    traceSetter('setRandomizedEncryptionRequired', ['boolean'], function (a) {
        return a[0] + (a[0] ? '' : '   <-- FINDING: caller-supplied IV permitted');
    });
    traceSetter('setKeySize', ['int'], id);
    traceSetter('setBlockModes', ['[Ljava.lang.String;'], function (a) {
        var s = a[0].join('|');
        return s + (s.indexOf('ECB') >= 0 ? '   <-- FINDING: ECB' : '');
    });
    traceSetter('setDigests', ['[Ljava.lang.String;'], function (a) {
        var s = a[0].join('|');
        return s + (/SHA-1|MD5/.test(s) ? '   <-- weak digest permitted' : '');
    });
    traceSetter('setEncryptionPaddings', ['[Ljava.lang.String;'], function (a) { return a[0].join('|'); });
    traceSetter('setSignaturePaddings', ['[Ljava.lang.String;'], function (a) { return a[0].join('|'); });
    traceSetter('setAttestationChallenge', ['[B'], function (a) {
        if (a[0] === null) return 'null';
        var hex = bytesToHex(a[0]);
        var ascii = '';
        for (var i = 0; i < a[0].length; i++) {
            var c = a[0][i] & 0xff;
            ascii += (c >= 32 && c < 127) ? String.fromCharCode(c) : '.';
        }
        return a[0].length + ' bytes, hex=' + hex + ' ascii="' + ascii + '"'
            + '   <-- if this is CONSTANT across runs, attestation is replayable';
    });
    traceSetter('setMaxUsageCount', ['int'], id);

    // ---- what the app actually got ------------------------------------------------------------
    var KeyGenerator = Java.use('javax.crypto.KeyGenerator');
    KeyGenerator.generateKey.implementation = function () {
        var key = this.generateKey();
        try { reportSecret(key, 'KeyGenerator.generateKey'); } catch (e) { line('  ' + e); }
        return key;
    };

    var KeyPairGenerator = Java.use('java.security.KeyPairGenerator');
    KeyPairGenerator.generateKeyPair.implementation = function () {
        var pair = this.generateKeyPair();
        try { reportPrivate(pair.getPrivate(), 'KeyPairGenerator.generateKeyPair'); }
        catch (e) { line('  ' + e); }
        return pair;
    };

    // ---- the fallback path: does the app degrade correctly, or silently? ----------------------
    try {
        var SBUE = Java.use('android.security.keystore.StrongBoxUnavailableException');
        SBUE.$init.overload('java.lang.String').implementation = function (m) {
            rule();
            line('!!!   StrongBoxUnavailableException constructed: ' + m);
            line('      WATCH WHAT HAPPENS NEXT. Correct: a retry with setIsStrongBoxBacked(false)');
            line('      and everything else unchanged. Wrong: a SecretKeySpec, or a key with the');
            line('      auth binding quietly dropped.');
            rule();
            return this.$init(m);
        };
    } catch (e) {
        line('note  StrongBoxUnavailableException not present (API < 28)');
    }

    // ---- raw key bytes in the heap ------------------------------------------------------------
    try {
        var SKS = Java.use('javax.crypto.spec.SecretKeySpec');
        SKS.$init.overload('[B', 'java.lang.String').implementation = function (bytes, alg) {
            rule();
            line('!!!   SecretKeySpec(' + bytes.length + ' bytes, "' + alg + '")');
            line('      This key is NOT in the Keystore. Its bytes are in this process\'s heap.');
            line('      Follow where they came from - that source is the weakest link.');
            line('      (For the byte-level treatment see 49-KeyStore/scripts/hook-secretkeyspec.js)');
            rule();
            return this.$init(bytes, alg);
        };
    } catch (e) { }

    // ---- does the app check for itself? --------------------------------------------------------
    var sawSelfCheck = false;
    try {
        var KeyInfo = Java.use('android.security.keystore.KeyInfo');
        ['getSecurityLevel', 'isInsideSecureHardware'].forEach(function (name) {
            try {
                KeyInfo[name].implementation = function () {
                    var r = this[name]();
                    if (!sawSelfCheck) {
                        sawSelfCheck = true;
                        line('GOOD  the app reads KeyInfo.' + name + '() itself - it is checking.');
                    }
                    return r;
                };
            } catch (e) { }
        });
    } catch (e) { }

    setTimeout(function () {
        if (!sawSelfCheck) {
            rule();
            line('AUDIT after startup the app has NOT read KeyInfo.getSecurityLevel() or');
            line('      isInsideSecureHardware() even once. If it claims hardware-backed storage');
            line('      anywhere, that claim has never been verified on this device.');
            rule();
        }
    }, 15000);

    rule();
    line('hooks installed. Now DRIVE THE APP - log in, open the protected feature.');
    line('Keys are created lazily; an app you do not exercise will show you nothing.');
    rule();
});
