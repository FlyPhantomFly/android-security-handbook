/*
 * enumerate-keystore.js — inventory every AndroidKeyStore key the app owns.
 *
 * WHAT IT DOES
 *   Loads the AndroidKeyStore, iterates every alias in the app's namespace, and
 *   for each one resolves a KeyInfo through the appropriate factory and prints
 *   its complete, as-created properties:
 *
 *     algorithm, key size, purposes (decoded from the bitmask), block modes,
 *     encryption/signature paddings, digests, origin (GENERATED / IMPORTED /
 *     DERIVED), security level (getSecurityLevel on API 31+, falling back to
 *     isInsideSecureHardware), isUserAuthenticationRequired, the auth validity
 *     duration, the auth type, isInvalidatedByBiometricEnrollment,
 *     isUnlockedDeviceRequired, validity dates, and — for asymmetric keys —
 *     whether the certificate chain carries an attestation extension.
 *
 *   It also flags, inline, the conditions that are findings.
 *
 * WHY IT MATTERS
 *   KeyGenParameterSpec is what the app ASKED FOR. KeyInfo is what the device
 *   ACTUALLY GAVE IT. They differ more often than anyone expects — a StrongBox
 *   request silently downgraded to TEE, or no hardware request at all on a
 *   device that then produced a software key. You cannot audit an app's key
 *   handling by reading its source; you have to read the key back on the real
 *   target hardware.
 *
 *   The output of this script is the raw material of the "Keystore inventory"
 *   table that belongs in every report where the client claims Keystore use:
 *
 *     | Alias      | Alg | Size | Purposes | Auth | Timeout | Sec level | Origin | Protects |
 *
 *   Note the last column. The script cannot fill it in — that is your job, and
 *   it is the column that turns an inventory into an assessment. An alias with
 *   no answer in that column is itself a finding: keys get created and never
 *   deleted, and the orphan from version 3.1 is usually the weak one.
 *
 *   See ../README.md sections 3.5, 3.8 and 7.3, and
 *   ../labs/lab-01-keystore-inventory.md.
 *
 * HOW TO RUN
 *   # host
 *   frida -U -f com.target.app -l enumerate-keystore.js
 *   frida -U -n com.target.app -l enumerate-keystore.js
 *
 *   Then from the REPL:
 *     ks.list()                 enumerate everything (also runs at startup)
 *     ks.one("alias")           full detail for one alias
 *     ks.table()                compact one-line-per-alias table for a report
 *     ks.watch()                log getKey()/aliases() calls as they happen
 *     ks.proveHandle("alias")   demonstrate that getEncoded() returns null
 *
 * REQUIREMENTS
 *   frida-server on the device, matching your host frida version. Android 6+
 *   (API 23) for symmetric keys; getSecurityLevel needs API 31+ and the script
 *   degrades to isInsideSecureHardware below that.
 *
 *   The app must be running and past Application.onCreate — the Keystore is
 *   loaded per-process. If you spawned with -f, wait for the UI before calling
 *   ks.list() manually.
 *
 * SCOPE
 *   This enumerates the keys in the TARGET APP'S namespace only, which for an
 *   ordinary app is its own UID. It cannot see another app's keys, and that is
 *   the platform working correctly. The exception worth checking is
 *   android:sharedUserId — two apps with one UID share one namespace:
 *     # adb shell
 *     dumpsys package com.target.app | grep -i sharedUser
 *
 * AUTHORISED TESTING ONLY.
 */

'use strict';

var ks = {

    /* ------------------------------------------------------------ constants */

    PURPOSES: [
        [1,   'ENCRYPT'],
        [2,   'DECRYPT'],
        [4,   'SIGN'],
        [8,   'VERIFY'],
        [32,  'WRAP_KEY'],
        [64,  'AGREE_KEY'],
        [128, 'ATTEST_KEY']
    ],

    ORIGINS: { 0: 'GENERATED', 1: 'IMPORTED', 2: 'IMPORTED', 3: 'DERIVED' },

    SEC_LEVELS: {
        '-2': 'UNKNOWN_SECURE',
        '-1': 'UNKNOWN  <-- treat as SOFTWARE',
        '0':  'SOFTWARE  <<< NOT hardware-backed',
        '1':  'TRUSTED_ENVIRONMENT',
        '2':  'STRONGBOX'
    },

    AUTH_TYPES: [
        [1, 'AUTH_BIOMETRIC_STRONG'],
        [2, 'AUTH_DEVICE_CREDENTIAL']
    ],

    ATTESTATION_OID: '1.3.6.1.4.1.11129.2.1.17',

    _sdk: 0,
    _findings: [],

    /* ---------------------------------------------------------------- utils */

    decodeMask: function (mask, table) {
        var out = [];
        for (var i = 0; i < table.length; i++) {
            if ((mask & table[i][0]) !== 0) out.push(table[i][1]);
        }
        return out.length ? out.join('|') : '(none: 0x' + mask.toString(16) + ')';
    },

    joinArray: function (arr) {
        if (arr === null || arr === undefined) return '(null)';
        try {
            var a = [];
            for (var i = 0; i < arr.length; i++) a.push(arr[i]);
            return a.length ? a.join(', ') : '(none)';
        } catch (e) { return '(unreadable)'; }
    },

    /*
     * Every property read is independently guarded. KeyInfo gained methods over
     * many API levels, and a NoSuchMethodError on one getter must not lose the
     * other twenty. This is the same discipline as any probe: record each
     * result, never abort on the first failure.
     */
    safe: function (fn, fallback) {
        try {
            var v = fn();
            return (v === null || v === undefined) ? (fallback || '(null)') : v;
        } catch (e) {
            return '(unavailable: ' + e.toString().split('\n')[0].substring(0, 60) + ')';
        }
    },

    line: function (k, v) { console.log('    ' + String(k).padEnd(38) + ': ' + v); },

    flag: function (alias, text) {
        console.log('    ' + '*** FINDING'.padEnd(38) + ': ' + text);
        this._findings.push(alias + ' — ' + text);
    },

    /* ----------------------------------------------------------------- init */

    init: function () {
        var self = this;
        Java.perform(function () {
            try {
                self._sdk = Java.use('android.os.Build$VERSION').SDK_INT.value;
            } catch (e) { self._sdk = 0; }
            console.log('[*] device SDK = ' + self._sdk +
                        (self._sdk >= 31 ? '  (getSecurityLevel available)'
                                         : '  (falling back to isInsideSecureHardware)'));
        });
    },

    _keystore: function () {
        var KS = Java.use('java.security.KeyStore');
        var k = KS.getInstance('AndroidKeyStore');
        k.load(null);
        return k;
    },

    /* ------------------------------------------------------------ KeyInfo -- */

    /*
     * Resolving a KeyInfo differs for symmetric and asymmetric keys, and the
     * caller does not always know which they have. Try both.
     */
    _keyInfo: function (keystore, alias) {
        var KeyInfo = Java.use('android.security.keystore.KeyInfo');

        // Symmetric first — SecretKeyFactory.
        try {
            var key = keystore.getKey(alias, null);
            if (key !== null) {
                var SecretKey = Java.use('javax.crypto.SecretKey');
                var sk = Java.cast(key, SecretKey);
                var skf = Java.use('javax.crypto.SecretKeyFactory')
                              .getInstance(sk.getAlgorithm(), 'AndroidKeyStore');
                return { info: Java.cast(skf.getKeySpec(sk, KeyInfo.class), KeyInfo),
                         kind: 'secret', key: sk };
            }
        } catch (e) { /* not symmetric, or not this factory */ }

        // Asymmetric — KeyFactory over the private key.
        try {
            var pk = keystore.getKey(alias, null);
            if (pk !== null) {
                var PrivateKey = Java.use('java.security.PrivateKey');
                var priv = Java.cast(pk, PrivateKey);
                var kf = Java.use('java.security.KeyFactory')
                             .getInstance(priv.getAlgorithm(), 'AndroidKeyStore');
                return { info: Java.cast(kf.getKeySpec(priv, KeyInfo.class), KeyInfo),
                         kind: 'private', key: priv };
            }
        } catch (e) { /* fall through */ }

        return null;
    },

    /* ------------------------------------------------------------- one key -- */

    one: function (alias) {
        var self = this;
        Java.perform(function () {
            var keystore;
            try { keystore = self._keystore(); }
            catch (e) { console.log('[-] Could not load AndroidKeyStore: ' + e); return; }

            console.log('');
            console.log('=== alias: ' + alias + ' ===');

            // Entry type first — it tells you what kind of key this is even if
            // KeyInfo resolution fails.
            self.line('isKeyEntry', self.safe(function () { return keystore.isKeyEntry(alias); }));
            self.line('isCertificateEntry',
                self.safe(function () { return keystore.isCertificateEntry(alias); }));
            self.line('creationDate', self.safe(function () {
                var d = keystore.getCreationDate(alias);
                return d === null ? '(null)' : d.toString();
            }));

            var res = self._keyInfo(keystore, alias);
            if (res === null) {
                console.log('    (no KeyInfo — this may be a certificate-only entry, or a');
                console.log('     key type this device does not expose through a factory)');
                self._certChain(keystore, alias);
                return;
            }

            var i = res.info;
            self.line('kind', res.kind);
            self.line('keystoreAlias', self.safe(function () { return i.getKeystoreAlias(); }));
            self.line('algorithm', self.safe(function () { return res.key.getAlgorithm(); }));
            self.line('keySize', self.safe(function () { return i.getKeySize(); }));

            // --- purposes -----------------------------------------------------
            var purposes = null;
            try { purposes = i.getPurposes(); } catch (e) { /* ignore */ }
            self.line('purposes', purposes === null ? '(unavailable)'
                                                    : self.decodeMask(purposes, self.PURPOSES)
                                                      + '  (0x' + purposes.toString(16) + ')');

            self.line('blockModes', self.safe(function () { return self.joinArray(i.getBlockModes()); }));
            self.line('encryptionPaddings',
                self.safe(function () { return self.joinArray(i.getEncryptionPaddings()); }));
            self.line('signaturePaddings',
                self.safe(function () { return self.joinArray(i.getSignaturePaddings()); }));
            self.line('digests', self.safe(function () { return self.joinArray(i.getDigests()); }));

            // --- where the key lives -----------------------------------------
            var level = null;
            if (self._sdk >= 31) {
                try { level = i.getSecurityLevel(); } catch (e) { level = null; }
            }
            if (level !== null) {
                self.line('securityLevel',
                    (self.SEC_LEVELS[String(level)] || String(level)) + '  (' + level + ')');
                if (level === 0 || level === -1) {
                    self.flag(alias, 'security level is SOFTWARE/UNKNOWN — any ' +
                        '"hardware-backed" claim about this key is false on this device');
                }
            } else {
                var hw = self.safe(function () { return i.isInsideSecureHardware(); });
                self.line('isInsideSecureHardware', hw + '   (a floor, not a grade)');
                if (hw === false) {
                    self.flag(alias, 'key is NOT inside secure hardware');
                }
            }

            var origin = self.safe(function () { return i.getOrigin(); }, null);
            if (typeof origin === 'number') {
                self.line('origin', (self.ORIGINS[String(origin)] || String(origin)) +
                                    '  (' + origin + ')');
                if (self.ORIGINS[String(origin)] === 'IMPORTED') {
                    self.flag(alias, 'origin is IMPORTED — the plaintext key material ' +
                        'existed in the app heap at some point. Find where it came from; ' +
                        'that source is now the weakest link.');
                }
            } else {
                self.line('origin', origin);
            }

            // --- authentication binding --------------------------------------
            var authReq = null;
            try { authReq = i.isUserAuthenticationRequired(); } catch (e) { /* ignore */ }
            self.line('isUserAuthenticationRequired',
                authReq === null ? '(unavailable)' : String(authReq));

            var dur = self.safe(function () {
                return i.getUserAuthenticationValidityDurationSeconds();
            }, null);
            self.line('authValidityDurationSeconds', dur);

            if (authReq === true) {
                if (dur === -1 || dur === 0) {
                    self.line('  -> binding', 'PER-USE (CryptoObject required). The strong form.');
                } else if (typeof dur === 'number' && dur > 0) {
                    self.line('  -> binding', 'TIME WINDOW of ' + dur + 's');
                    self.flag(alias, 'auth binding is a ' + dur + '-second WINDOW, not per-use. ' +
                        'Any authentication in that window — including an unrelated device ' +
                        'unlock — authorises any use of this key by any code in the process.');
                }
            } else if (authReq === false) {
                self.line('  -> binding', 'NONE — usable by any code in the process at any time');
            }

            var atype = self.safe(function () { return i.getUserAuthenticationType(); }, null);
            if (typeof atype === 'number') {
                self.line('userAuthenticationType', self.decodeMask(atype, self.AUTH_TYPES));
                if ((atype & 2) !== 0 && (atype & 1) === 0) {
                    self.flag(alias, 'AUTH_DEVICE_CREDENTIAL only — a shoulder-surfed PIN ' +
                        'satisfies this key. Check whether the threat model allows that.');
                }
            }

            var inval = self.safe(function () {
                return i.isInvalidatedByBiometricEnrollment();
            }, null);
            self.line('invalidatedByBiometricEnrollment', inval);
            if (inval === false && authReq === true) {
                self.flag(alias, 'setInvalidatedByBiometricEnrollment(false) — an attacker ' +
                    'who reaches the settings screen enrols their own biometric and ' +
                    'inherits this key.');
            }

            self.line('userAuthValidWhileOnBody',
                self.safe(function () { return i.isUserAuthenticationValidWhileOnBody(); }));
            self.line('unlockedDeviceRequired',
                self.safe(function () { return i.isUserAuthenticationRequired() &&
                                                i.isUnlockedDeviceRequired ?
                                                i.isUnlockedDeviceRequired() : '(n/a)'; }));
            self.line('trustedUserPresenceRequired',
                self.safe(function () { return i.isTrustedUserPresenceRequired(); }));
            self.line('userConfirmationRequired',
                self.safe(function () { return i.isUserConfirmationRequired(); }));

            // --- validity -----------------------------------------------------
            self.line('keyValidityStart',
                self.safe(function () { var d = i.getKeyValidityStart(); return d ? d.toString() : '(none)'; }));
            self.line('keyValidityForOriginationEnd',
                self.safe(function () { var d = i.getKeyValidityForOriginationEnd(); return d ? d.toString() : '(none)'; }));
            self.line('keyValidityForConsumptionEnd',
                self.safe(function () { var d = i.getKeyValidityForConsumptionEnd(); return d ? d.toString() : '(none)'; }));
            self.line('remainingUsageCount',
                self.safe(function () { return i.getRemainingUsageCount(); }));

            // --- the diagnostic everyone should know ---------------------------
            self.line('getEncoded()', self.safe(function () {
                var e = res.key.getEncoded();
                return e === null ? 'null  <- CORRECT: a genuine Keystore handle'
                                  : 'NON-NULL, ' + e.length + ' bytes  <<< NOT a Keystore key';
            }));

            self._certChain(keystore, alias);
        });
    },

    _certChain: function (keystore, alias) {
        var self = this;
        try {
            var chain = keystore.getCertificateChain(alias);
            if (chain === null || chain.length === 0) return;
            console.log('    certificate chain              : ' + chain.length + ' certificate(s)');
            var X509 = Java.use('java.security.cert.X509Certificate');
            for (var n = 0; n < chain.length; n++) {
                var c = Java.cast(chain[n], X509);
                console.log('      [' + n + '] subject=' + c.getSubjectDN().toString());
                console.log('          issuer =' + c.getIssuerDN().toString());
                if (n === 0) {
                    var ext = c.getExtensionValue(self.ATTESTATION_OID);
                    if (ext !== null) {
                        console.log('          *** ATTESTATION EXTENSION PRESENT (' +
                                    self.ATTESTATION_OID + '), ' + ext.length + ' bytes');
                        console.log('          Export the chain and verify it SERVER-SIDE:');
                        console.log('            ../examples/04-verify-attestation.py');
                        console.log('            ../labs/lab-03-attestation-analysis.md');
                    } else {
                        console.log('          no attestation extension on the leaf');
                    }
                }
            }
        } catch (e) { /* no chain — normal for symmetric keys */ }
    },

    /* ----------------------------------------------------------------- list */

    list: function () {
        var self = this;
        Java.perform(function () {
            var keystore;
            try { keystore = self._keystore(); }
            catch (e) {
                console.log('[-] Could not load AndroidKeyStore: ' + e);
                console.log('    If you spawned with -f, wait for the app to finish starting');
                console.log('    and then call ks.list() from the REPL.');
                return;
            }

            var aliases = [];
            try {
                var e = keystore.aliases();
                while (e.hasMoreElements()) aliases.push(e.nextElement().toString());
            } catch (err) {
                console.log('[-] aliases() failed: ' + err);
                return;
            }

            console.log('');
            console.log('=========================================================');
            console.log('  ANDROIDKEYSTORE INVENTORY — ' + aliases.length + ' alias(es)');
            console.log('=========================================================');

            if (aliases.length === 0) {
                console.log('  (none)');
                console.log('');
                console.log('  An EMPTY keystore in an app that claims to use it is itself a');
                console.log('  result. Two explanations, and you must distinguish them:');
                console.log('    1. Keys are created lazily, later in the session. Exercise the');
                console.log('       app (log in, open the protected screen) and re-run ks.list().');
                console.log('       Run hook-keygenparameterspec.js to catch creation live.');
                console.log('    2. The app does not actually use the Keystore. Run');
                console.log('       hook-secretkeyspec.js — the key is probably a hardcoded');
                console.log('       byte array that never goes near it. That is Finding 1, and');
                console.log('       it is the most common real mistake in this chapter.');
                return;
            }

            self._findings = [];
            aliases.forEach(function (a) { self.one(a); });

            console.log('');
            console.log('=== SUMMARY ===');
            if (self._findings.length === 0) {
                console.log('  No automatic flags raised. That is a POSITIVE result and should');
                console.log('  be reported as one — a report that only lists breakage gives the');
                console.log('  client no way to know which controls worked.');
            } else {
                self._findings.forEach(function (f) { console.log('  ! ' + f); });
            }
            console.log('');
            console.log('  Now do the part this script cannot: for EACH alias, work out WHAT IT');
            console.log('  PROTECTS — which file, which preference, which network field. An');
            console.log('  alias with no answer is an orphan, and orphans are usually the weak');
            console.log('  ones. See ../labs/lab-01-keystore-inventory.md.');
            console.log('');
        });
    },

    /* ---------------------------------------------------------------- table */

    table: function () {
        var self = this;
        Java.perform(function () {
            var keystore = self._keystore();
            var e = keystore.aliases();
            console.log('');
            console.log('| Alias | Alg | Size | Purposes | Auth | Timeout | Sec level | Origin | Protects |');
            console.log('|---|---|---|---|---|---|---|---|---|');
            while (e.hasMoreElements()) {
                var a = e.nextElement().toString();
                var r = self._keyInfo(keystore, a);
                if (r === null) { console.log('| `' + a + '` | ? | | | | | | | |'); continue; }
                var i = r.info;
                var lvl = self._sdk >= 31
                    ? self.safe(function () { return self.SEC_LEVELS[String(i.getSecurityLevel())]; })
                    : self.safe(function () { return i.isInsideSecureHardware() ? 'HW' : 'SOFTWARE'; });
                console.log('| `' + a + '` | ' +
                    self.safe(function () { return r.key.getAlgorithm(); }) + ' | ' +
                    self.safe(function () { return i.getKeySize(); }) + ' | ' +
                    self.safe(function () { return self.decodeMask(i.getPurposes(), self.PURPOSES); }) + ' | ' +
                    self.safe(function () { return i.isUserAuthenticationRequired(); }) + ' | ' +
                    self.safe(function () { return i.getUserAuthenticationValidityDurationSeconds(); }) + ' | ' +
                    lvl + ' | ' +
                    self.safe(function () { return self.ORIGINS[String(i.getOrigin())]; }) + ' | ' +
                    ' *fill this in* |');
            }
            console.log('');
        });
    },

    /* ---------------------------------------------------------- proveHandle */

    proveHandle: function (alias) {
        var self = this;
        Java.perform(function () {
            var keystore = self._keystore();
            var k = keystore.getKey(alias, null);
            if (k === null) { console.log('[-] no such alias: ' + alias); return; }
            console.log('');
            console.log('=== NON-EXTRACTABILITY, DEMONSTRATED ===');
            console.log('  class        = ' + k.$className);
            var enc = k.getEncoded();
            console.log('  getEncoded() = ' + enc);
            if (enc === null) {
                console.log('');
                console.log('  null. There is no key material in this process to steal, and no');
                console.log('  amount of hooking changes that — the bytes are on the other side');
                console.log('  of the Binder boundary, inside keystore2 and then inside the');
                console.log('  secure hardware.');
                console.log('');
                console.log('  Now prove the OTHER half of the story: that you can still USE it.');
                console.log('  See ../labs/lab-02-extraction-vs-use.md — that lab is the point');
                console.log('  of this entire chapter.');
            } else {
                console.log('');
                console.log('  *** NON-NULL. This key is NOT protected by the Keystore. The');
                console.log('  *** material is in the app heap right now. Find where it came');
                console.log('  *** from — hook-secretkeyspec.js will tell you.');
            }
            console.log('');
        });
    },

    /* ---------------------------------------------------------------- watch */

    watch: function () {
        var self = this;
        Java.perform(function () {
            var KS = Java.use('java.security.KeyStore');

            try {
                KS.getKey.implementation = function (alias, pw) {
                    console.log('[watch] KeyStore.getKey("' + alias + '")');
                    console.log(self._stack());
                    return this.getKey(alias, pw);
                };
            } catch (e) { console.log('[!] could not hook getKey: ' + e); }

            try {
                KS.deleteEntry.implementation = function (alias) {
                    console.log('[watch] KeyStore.deleteEntry("' + alias + '")  <- rotation or cleanup');
                    return this.deleteEntry(alias);
                };
            } catch (e) { /* ignore */ }

            try {
                KS.containsAlias.implementation = function (alias) {
                    var r = this.containsAlias(alias);
                    console.log('[watch] KeyStore.containsAlias("' + alias + '") = ' + r);
                    return r;
                };
            } catch (e) { /* ignore */ }

            console.log('[+] Watching KeyStore access. Exercise the app.');
            console.log('    Which aliases are touched, and WHEN, tells you what each one');
            console.log('    protects — which is the column ks.table() cannot fill in.');
        });
    },

    _stack: function () {
        try {
            return Java.use('android.util.Log')
                .getStackTraceString(Java.use('java.lang.Exception').$new())
                .split('\n').slice(1, 9).join('\n');
        } catch (e) { return '  (no stack)'; }
    },

    help: function () {
        console.log([
            '',
            'ks.list()                enumerate every alias with full KeyInfo',
            'ks.one("alias")          full detail for one alias',
            'ks.table()               markdown table for the report',
            'ks.proveHandle("alias")  show getEncoded() == null',
            'ks.watch()               log getKey/deleteEntry/containsAlias live',
            ''
        ].join('\n'));
    }
};

/* --------------------------------------------------------------- bootstrap */

setTimeout(function () {
    Java.perform(function () {
        console.log('');
        console.log('=== enumerate-keystore — Chapter 49 section 7.3 ===');
        ks.init();
        ks.list();
        console.log('[+] Ready. ks.help() for commands.');
        console.log('');
    });
}, 500);   // let Application.onCreate finish when spawned with -f
