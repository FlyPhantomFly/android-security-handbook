/*
 * hook-keygenparameterspec.js — log exactly how every Keystore key is configured.
 *
 * WHAT IT DOES
 *   Hooks android.security.keystore.KeyGenParameterSpec$Builder and records
 *   every option the application sets on every key it creates during the run,
 *   in order, per alias. When build() is called it prints a complete policy
 *   summary and flags the settings that are findings.
 *
 *   It also hooks KeyProtection.Builder — the import-time policy object — and
 *   KeyPairGenerator/KeyGenerator.initialize/init, so that key creation is
 *   captured whichever route the app takes.
 *
 * WHY IT MATTERS
 *   This single hook answers four of the ten findings in section 5.2 in one run,
 *   with no code reading at all:
 *
 *     Finding 4  setUserAuthenticationRequired(false) — usually by OMISSION,
 *                because false is the DEFAULT. This script reports options that
 *                were never called, which is what makes it useful: you cannot
 *                grep for a method that is absent.
 *     Finding 5  setInvalidatedByBiometricEnrollment(false)
 *     Finding 7  setRandomizedEncryptionRequired(false) — enables IV reuse
 *     Finding 8  setIsStrongBoxBacked(true) followed by a silent downgrade
 *
 *   And it works through any obfuscation. R8 can rename every one of the app's
 *   own symbols; it cannot rename android.security.keystore.KeyGenParameterSpec
 *   or its setters, because those are platform classes the app does not own.
 *   Static analysis of an obfuscated APK is slow and uncertain here. This is
 *   fast and certain.
 *
 *   Pair it with enumerate-keystore.js. This script shows what the app ASKED
 *   FOR; that one shows what the device ACTUALLY PROVIDED. The gap between them
 *   is Finding 8 and Finding 9.
 *
 *   See ../README.md sections 3.5 and 7.2.
 *
 * HOW TO RUN
 *   # host — spawn, so you catch keys created during startup
 *   frida -U -f com.target.app -l hook-keygenparameterspec.js
 *
 *   # host — or attach to a running process
 *   frida -U -n com.target.app -l hook-keygenparameterspec.js
 *
 *   Then exercise the app: first launch, log in, enable biometrics, open the
 *   protected screen. Keys are frequently created lazily, so a hook installed at
 *   spawn and left running for a full session catches things a single screen
 *   never will.
 *
 *   From the REPL:
 *     kgps.report()      re-print the summary for every alias seen so far
 *     kgps.reset()       clear the record
 *
 * REQUIREMENTS
 *   frida-server on the device matching your host frida version. Android 6+
 *   (API 23) for KeyGenParameterSpec. Every hook is individually guarded, so
 *   builder methods that do not exist on the target's API level are skipped
 *   rather than aborting the script.
 *
 * SAFETY
 *   Read-only. Every hook logs and calls through unmodified. It changes no key
 *   policy and creates no keys.
 *
 * AUTHORISED TESTING ONLY.
 */

'use strict';

var kgps = {

    /* Per-alias record of every option set. */
    _specs: {},
    _seq: 0,

    PURPOSES: [
        [1,   'ENCRYPT'],
        [2,   'DECRYPT'],
        [4,   'SIGN'],
        [8,   'VERIFY'],
        [32,  'WRAP_KEY'],
        [64,  'AGREE_KEY'],
        [128, 'ATTEST_KEY']
    ],

    AUTH_TYPES: [
        [1, 'AUTH_BIOMETRIC_STRONG'],
        [2, 'AUTH_DEVICE_CREDENTIAL']
    ],

    decodeMask: function (mask, table) {
        var out = [];
        for (var i = 0; i < table.length; i++) {
            if ((mask & table[i][0]) !== 0) out.push(table[i][1]);
        }
        return out.length ? out.join('|') : '(none: ' + mask + ')';
    },

    arr: function (a) {
        if (a === null || a === undefined) return '(null)';
        try {
            var o = [];
            for (var i = 0; i < a.length; i++) o.push(a[i]);
            return o.join(', ');
        } catch (e) { return '(unreadable)'; }
    },

    hex: function (bytes) {
        if (bytes === null) return '(null)';
        try {
            var s = '';
            for (var i = 0; i < bytes.length && i < 64; i++) {
                var b = bytes[i] & 0xff;
                s += (b < 16 ? '0' : '') + b.toString(16);
            }
            return s + (bytes.length > 64 ? '… (' + bytes.length + ' bytes)' : '');
        } catch (e) { return '(unreadable)'; }
    },

    stack: function () {
        try {
            return Java.use('android.util.Log')
                .getStackTraceString(Java.use('java.lang.Exception').$new())
                .split('\n').slice(2, 10).join('\n');
        } catch (e) { return '  (no stack)'; }
    },

    /* ------------------------------------------------------------- recording */

    _rec: function (builder) {
        // Builder instances are Java objects; tag them so we can follow a chain
        // across many setter calls without relying on any Java-side identity.
        if (builder.__kgpsId === undefined) {
            builder.__kgpsId = ++this._seq;
            this._specs[builder.__kgpsId] = { alias: '(unknown)', opts: {}, order: [] };
        }
        return this._specs[builder.__kgpsId];
    },

    _set: function (builder, name, value) {
        var r = this._rec(builder);
        r.opts[name] = value;
        r.order.push(name);
        console.log('  [KGPS #' + builder.__kgpsId + ' ' + r.alias + '] ' +
                    name + ' = ' + value);
        return r;
    },

    /* ---------------------------------------------------------------- hooks */

    install: function () {
        var self = this;

        /* ---- KeyGenParameterSpec.Builder ------------------------------- */

        var B;
        try {
            B = Java.use('android.security.keystore.KeyGenParameterSpec$Builder');
        } catch (e) {
            console.log('[-] KeyGenParameterSpec$Builder not found — device below API 23?');
            return;
        }

        // Constructor: (alias, purposes)
        try {
            B.$init.overload('java.lang.String', 'int').implementation =
            function (alias, purposes) {
                var ret = this.$init(alias, purposes);
                var r = self._rec(this);
                r.alias = alias;
                r.opts.purposes = self.decodeMask(purposes, self.PURPOSES);
                console.log('');
                console.log('=== [KGPS #' + this.__kgpsId + '] new Builder ===');
                console.log('  alias    = ' + alias);
                console.log('  purposes = ' + r.opts.purposes + '  (0x' + purposes.toString(16) + ')');
                console.log(self.stack());
                return ret;
            };
        } catch (e) { console.log('[!] Builder.$init(String,int) hook failed: ' + e); }

        // Constructor: (spec, alias, purposes) — used by some copy paths.
        try {
            B.$init.overload('android.security.keystore.KeyGenParameterSpec',
                             'java.lang.String', 'int').implementation =
            function (spec, alias, purposes) {
                var ret = this.$init(spec, alias, purposes);
                var r = self._rec(this);
                r.alias = alias;
                r.opts.purposes = self.decodeMask(purposes, self.PURPOSES);
                console.log('=== [KGPS #' + this.__kgpsId + '] new Builder (copy) alias=' + alias);
                return ret;
            };
        } catch (e) { /* overload absent on this API level */ }

        // Every setter, each guarded independently.
        var setters = [
            ['setUserAuthenticationRequired',        'boolean'],
            ['setInvalidatedByBiometricEnrollment',  'boolean'],
            ['setRandomizedEncryptionRequired',      'boolean'],
            ['setIsStrongBoxBacked',                 'boolean'],
            ['setUnlockedDeviceRequired',            'boolean'],
            ['setUserPresenceRequired',              'boolean'],
            ['setUserConfirmationRequired',          'boolean'],
            ['setUserAuthenticationValidWhileOnBody','boolean'],
            ['setDevicePropertiesAttestationIncluded','boolean'],
            ['setKeySize',                           'int'],
            ['setUserAuthenticationValidityDurationSeconds', 'int'],
            ['setMaxUsageCount',                     'int']
        ];

        setters.forEach(function (s) {
            var name = s[0];
            try {
                B[name].overload(s[1]).implementation = function (v) {
                    self._set(this, name, v);
                    return this[name](v);
                };
            } catch (e) { /* not present on this API level — fine */ }
        });

        // String-varargs setters.
        ['setBlockModes', 'setEncryptionPaddings', 'setSignaturePaddings', 'setDigests']
        .forEach(function (name) {
            try {
                B[name].overload('[Ljava.lang.String;').implementation = function (v) {
                    self._set(this, name, self.arr(v));
                    return this[name](v);
                };
            } catch (e) { /* ignore */ }
        });

        // setUserAuthenticationParameters(int timeout, int type) — API 30+.
        try {
            B.setUserAuthenticationParameters.overload('int', 'int').implementation =
            function (timeout, type) {
                self._set(this, 'setUserAuthenticationParameters',
                    'timeout=' + timeout + 's, type=' + self.decodeMask(type, self.AUTH_TYPES));
                return this.setUserAuthenticationParameters(timeout, type);
            };
        } catch (e) { /* below API 30 */ }

        // setAttestationChallenge(byte[]).
        try {
            B.setAttestationChallenge.overload('[B').implementation = function (c) {
                self._set(this, 'setAttestationChallenge',
                    c === null ? 'null' : (c.length + ' bytes: ' + self.hex(c)));
                return this.setAttestationChallenge(c);
            };
        } catch (e) { /* ignore */ }

        // Date setters.
        ['setKeyValidityStart', 'setKeyValidityEnd',
         'setKeyValidityForOriginationEnd', 'setKeyValidityForConsumptionEnd',
         'setCertificateNotBefore', 'setCertificateNotAfter']
        .forEach(function (name) {
            try {
                B[name].overload('java.util.Date').implementation = function (d) {
                    self._set(this, name, d === null ? 'null' : d.toString());
                    return this[name](d);
                };
            } catch (e) { /* ignore */ }
        });

        // setAlgorithmParameterSpec — curve or RSA exponent.
        try {
            B.setAlgorithmParameterSpec.overload('java.security.spec.AlgorithmParameterSpec')
            .implementation = function (s) {
                self._set(this, 'setAlgorithmParameterSpec',
                    s === null ? 'null' : s.toString() + '  [' + s.$className + ']');
                return this.setAlgorithmParameterSpec(s);
            };
        } catch (e) { /* ignore */ }

        try {
            B.setAttestKeyAlias.overload('java.lang.String').implementation = function (a) {
                self._set(this, 'setAttestKeyAlias', a);
                return this.setAttestKeyAlias(a);
            };
        } catch (e) { /* below API 31 */ }

        // build() — the moment to summarise.
        try {
            B.build.implementation = function () {
                var r = self._rec(this);
                var spec = this.build();
                self.summarise(r, this.__kgpsId);
                return spec;
            };
        } catch (e) { console.log('[!] Builder.build hook failed: ' + e); }

        /* ---- KeyProtection.Builder — the IMPORT path -------------------- */

        try {
            var KP = Java.use('android.security.keystore.KeyProtection$Builder');
            KP.$init.overload('int').implementation = function (purposes) {
                console.log('');
                console.log('=== [KeyProtection] new Builder — THIS IS AN IMPORT PATH ===');
                console.log('  purposes = ' + self.decodeMask(purposes, self.PURPOSES));
                console.log('  *** An imported key means the PLAINTEXT KEY MATERIAL existed in');
                console.log('  *** this process. Find where it came from — that source is now');
                console.log('  *** the weakest link, and it is where you attack. Run');
                console.log('  *** hook-secretkeyspec.js to catch the material itself.');
                console.log(self.stack());
                return this.$init(purposes);
            };
        } catch (e) { /* ignore */ }

        /* ---- Generators — catch the moment of creation ------------------ */

        try {
            var KG = Java.use('javax.crypto.KeyGenerator');
            KG.getInstance.overload('java.lang.String', 'java.lang.String').implementation =
            function (alg, provider) {
                console.log('[gen] KeyGenerator.getInstance("' + alg + '", "' + provider + '")');
                return this.getInstance(alg, provider);
            };
            KG.getInstance.overload('java.lang.String').implementation = function (alg) {
                console.log('[gen] KeyGenerator.getInstance("' + alg + '")   <<< NO PROVIDER —');
                console.log('      this produces a SOFTWARE key that will live in the app heap.');
                console.log('      Follow it: where does the resulting SecretKey go?');
                console.log(self.stack());
                return this.getInstance(alg);
            };
        } catch (e) { /* ignore */ }

        try {
            var KPG = Java.use('java.security.KeyPairGenerator');
            KPG.getInstance.overload('java.lang.String', 'java.lang.String').implementation =
            function (alg, provider) {
                console.log('[gen] KeyPairGenerator.getInstance("' + alg + '", "' + provider + '")');
                return this.getInstance(alg, provider);
            };
        } catch (e) { /* ignore */ }

        /* ---- The silent-downgrade path ---------------------------------- */

        try {
            var SBUE = Java.use('android.security.keystore.StrongBoxUnavailableException');
            SBUE.$init.overload().implementation = function () {
                console.log('');
                console.log('*** StrongBoxUnavailableException THROWN ***');
                console.log('    The app asked for StrongBox and this device does not have it.');
                console.log('    WATCH WHAT HAPPENS NEXT. If the app retries without StrongBox');
                console.log('    and does not record which level it actually got, that is');
                console.log('    Finding 8 — a silent downgrade behind a hardware claim.');
                console.log('    Confirm with enumerate-keystore.js: ks.one("<alias>").');
                console.log(self.stack());
                return this.$init();
            };
        } catch (e) { /* class shape varies; not fatal */ }

        console.log('[+] Hooks installed.');
    },

    /* ------------------------------------------------------------ summarise */

    summarise: function (r, id) {
        var o = r.opts;
        var findings = [];

        console.log('');
        console.log('--- [KGPS #' + id + '] build() — FINAL POLICY for alias "' + r.alias + '" ---');
        Object.keys(o).forEach(function (k) {
            console.log('    ' + k.padEnd(42) + ' = ' + o[k]);
        });

        // --- Options NOT called. This is the part grep cannot do for you. ---
        var omitted = [];
        function check(name, meaning) {
            if (o[name] === undefined) omitted.push(name + '   (default: ' + meaning + ')');
        }
        check('setUserAuthenticationRequired',       'false — NO auth binding');
        check('setInvalidatedByBiometricEnrollment', 'true — invalidated on enrolment (good)');
        check('setRandomizedEncryptionRequired',     'true — caller IV forbidden (good)');
        check('setIsStrongBoxBacked',                'false — TEE, not StrongBox');
        check('setUnlockedDeviceRequired',           'false — usable while locked');
        check('setKeySize',                          'AES 128 / RSA 2048 / EC 256');

        if (omitted.length) {
            console.log('    --- NOT SET (defaults apply) ---');
            omitted.forEach(function (x) { console.log('    ' + x); });
        }

        // --- Findings -------------------------------------------------------
        var authReq = o.setUserAuthenticationRequired;
        if (authReq === undefined || authReq === false) {
            findings.push('NO AUTHENTICATION BINDING. This key is usable by any code in the ' +
                'process, at any time, with no user interaction. Whether that is a finding ' +
                'depends entirely on WHAT IT PROTECTS — go and find out.');
        }

        if (authReq === true) {
            var p = o.setUserAuthenticationParameters;
            var d = o.setUserAuthenticationValidityDurationSeconds;
            if (p !== undefined && /timeout=(\d+)s/.test(p)) {
                var t = parseInt(/timeout=(\d+)s/.exec(p)[1], 10);
                if (t > 0) {
                    findings.push('AUTH IS A ' + t + '-SECOND WINDOW, not per-use. Any ' +
                        'authentication in that window — including an unrelated device ' +
                        'unlock — authorises any use of this key. Per-use binding requires ' +
                        'timeout 0 AND a CryptoObject passed to BiometricPrompt.');
                }
                if (/AUTH_DEVICE_CREDENTIAL/.test(p) && !/AUTH_BIOMETRIC_STRONG/.test(p)) {
                    findings.push('AUTH_DEVICE_CREDENTIAL only — a shoulder-surfed PIN or ' +
                        'pattern satisfies this key.');
                }
            } else if (typeof d === 'number' && d > 0) {
                findings.push('AUTH IS A ' + d + '-SECOND WINDOW (legacy API), not per-use.');
            }
        }

        if (o.setInvalidatedByBiometricEnrollment === false) {
            findings.push('setInvalidatedByBiometricEnrollment(FALSE). An attacker who can ' +
                'reach the settings screen enrols their own biometric and inherits this key.');
        }

        if (o.setRandomizedEncryptionRequired === false) {
            findings.push('setRandomizedEncryptionRequired(FALSE). The caller may supply the ' +
                'IV. Now find out whether it does, and whether it is constant — a fixed IV ' +
                'with GCM is catastrophic, not merely weak.');
        }

        if (o.setBlockModes && /ECB/.test(o.setBlockModes)) {
            findings.push('BLOCK_MODE_ECB. ECB leaks plaintext structure. Immediate finding.');
        }

        if (o.setDigests && /(^|,\s*)(SHA1|MD5|NONE)(,|$)/.test(o.setDigests)) {
            findings.push('Weak or absent digest in ' + o.setDigests + '. DIGEST_NONE on an ' +
                'RSA signing key permits raw signing of attacker-chosen data.');
        }

        if (o.setEncryptionPaddings && /RSA_PKCS1/.test(o.setEncryptionPaddings)) {
            findings.push('RSA PKCS#1 v1.5 ENCRYPTION padding — Bleichenbacher-adjacent. ' +
                'Prefer OAEP.');
        }

        if (o.setAttestationChallenge !== undefined) {
            findings.push('ATTESTATION REQUESTED. Two things to check, and neither is on the ' +
                'device: (1) is the challenge SERVER-ISSUED, fresh and single-use, or is it a ' +
                'constant? A constant challenge is replayable and worthless. (2) Does the ' +
                'SERVER verify the chain, pin the Google ROOT, and read hardwareEnforced? ' +
                'See ../examples/04-verify-attestation.py.');
        }

        if (findings.length) {
            console.log('');
            findings.forEach(function (f) {
                console.log('    *** ' + f);
            });
        } else {
            console.log('');
            console.log('    No automatic flags. Confirm what the device ACTUALLY produced:');
            console.log('      frida -U -n <pkg> -l enumerate-keystore.js   then ks.one("' +
                        r.alias + '")');
            console.log('    A correctly configured key is a POSITIVE result. Report it.');
        }
        console.log('');
    },

    report: function () {
        var self = this;
        var ids = Object.keys(this._specs);
        if (ids.length === 0) {
            console.log('[*] No KeyGenParameterSpec.Builder seen yet.');
            console.log('    Keys are often created lazily. Exercise the app: first launch,');
            console.log('    log in, enable biometrics, open the protected screen.');
            console.log('    If nothing ever appears, the app may not use the Keystore at all —');
            console.log('    run hook-secretkeyspec.js.');
            return;
        }
        ids.forEach(function (id) { self.summarise(self._specs[id], id); });
    },

    reset: function () { this._specs = {}; this._seq = 0; console.log('[*] cleared'); },

    help: function () {
        console.log([
            '',
            'kgps.report()   re-print the policy summary for every alias seen',
            'kgps.reset()    clear the record',
            ''
        ].join('\n'));
    }
};

/* --------------------------------------------------------------- bootstrap */

Java.perform(function () {
    console.log('');
    console.log('=== hook-keygenparameterspec — Chapter 49 section 7.2 ===');
    console.log('[*] This shows what the app ASKS FOR. Run enumerate-keystore.js to see');
    console.log('[*] what the device ACTUALLY PROVIDED. The gap is Findings 8 and 9.');
    kgps.install();
    console.log('[+] Now exercise the app. Keys are frequently created lazily.');
    console.log('');
});
