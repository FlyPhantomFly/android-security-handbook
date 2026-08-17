/*
 * hook-cipher-keystore.js — capture plaintext flowing through Keystore keys.
 *
 * WHAT IT DOES
 *   Hooks javax.crypto.Cipher (init / update / doFinal), javax.crypto.Mac and
 *   java.security.Signature, and for each operation records:
 *
 *     - the transformation ("AES/GCM/NoPadding", "AES/CBC/PKCS7Padding", …)
 *     - the opmode (ENCRYPT / DECRYPT / WRAP / UNWRAP)
 *     - the key's class, and whether it is a genuine AndroidKeyStore handle
 *       (getEncoded() == null) or a SecretKeySpec holding raw material
 *     - the IV / GCM parameters, flagging a repeated or all-zero IV
 *     - the input and the output, as UTF-8 when printable and hex otherwise
 *     - a Java stack trace, so you know which code path did it
 *
 *   It can also actively DRIVE a key: ks.decrypt(alias, ivHex, ctHex) uses the
 *   app's own Keystore key with no user interaction at all.
 *
 * WHY IT MATTERS — THIS IS THE CHAPTER'S CENTRAL POINT
 *   The Android Keystore prevents key EXTRACTION. It does not prevent key USE.
 *
 *   Key material never enters the app's process, so it cannot be dumped out of
 *   it — no hook, no heap scan, no memory dump will produce those bytes. That
 *   is a real guarantee and it holds even against root.
 *
 *   But the plaintext is a different matter entirely. It exists in the app's
 *   process before encryption and after decryption, by necessity, and it
 *   travels over Binder to keystore2 in between. Any code executing inside the
 *   process can therefore:
 *
 *       - read every plaintext the app encrypts,
 *       - read every plaintext the app decrypts, and
 *       - command the key itself, at any time, for any operation the key
 *         permits.
 *
 *   An attacker does not need to steal the key. The key will do whatever they
 *   ask. That is why "we store it in the hardware Keystore" is not, on its own,
 *   an answer to "can an attacker with code execution recover the token".
 *
 *   THE QUESTION YOU MUST ANSWER BEFORE WRITING THIS UP
 *     "What did I learn that I did not already have?"
 *
 *   If you hooked a Cipher in the process, you already had code execution in
 *   the process — and an attacker with code execution could equally have read
 *   the token before it was ever encrypted, or after it was decrypted, or out
 *   of a network buffer. The Keystore was not the weak link, and reporting it
 *   as one misattributes the problem and will be corrected by the developer.
 *
 *   This script produces a finding when it shows something stronger:
 *     - the key is a SecretKeySpec, so it is hardcoded and works on EVERY
 *       installation with no device access at all (Finding 1);
 *     - the key has NO auth binding, so the "biometric protection" the app
 *       advertises is not enforced by the key (Findings 4 and 6);
 *     - the IV is fixed, so GCM's security collapses without any hooking
 *       (Finding 7);
 *     - the same plaintext is ALSO stored unencrypted elsewhere, so the crypto
 *       is decorative (Finding 3).
 *
 *   See ../README.md sections 1.3, 5.2, 7.5 and 7.6, and — above all —
 *   ../labs/lab-02-extraction-vs-use.md, which is built entirely around this
 *   distinction.
 *
 * HOW TO RUN
 *   # host
 *   frida -U -f com.target.app -l hook-cipher-keystore.js
 *   frida -U -n com.target.app -l hook-cipher-keystore.js
 *
 *   Then exercise the app and watch. From the REPL:
 *     cy.summary()                     what has been seen so far
 *     cy.verbose(true)                 include stack traces on every operation
 *     cy.maxBytes(4096)                raise the print limit
 *     cy.aliases()                     Keystore aliases in this app
 *     cy.decrypt(alias, ivHex, ctHex)  DRIVE the key with no user interaction
 *     cy.encrypt(alias, "plaintext")   the same, in the other direction
 *     cy.heapKeys()                    live SecretKeySpec instances on the heap
 *
 * REQUIREMENTS
 *   frida-server on the device matching your host frida version. Android 6+.
 *   Every hook is individually guarded; a missing overload is skipped rather
 *   than aborting the script.
 *
 * SAFETY
 *   The hooks are read-only and call through unmodified. cy.decrypt() and
 *   cy.encrypt() ACTIVELY USE the app's keys — they perform a real cryptographic
 *   operation. On a key with setMaxUsageCount that consumes a use. Know what you
 *   are doing before you run them against a production account.
 *
 * AUTHORISED TESTING ONLY.
 */

'use strict';

var cy = {

    _verbose: false,
    _max: 512,
    _ivSeen: {},
    _stats: { ops: 0, keystoreKeys: 0, rawKeys: 0, aliases: {}, transforms: {} },

    OPMODE: { 1: 'ENCRYPT', 2: 'DECRYPT', 3: 'WRAP', 4: 'UNWRAP' },

    /* ---------------------------------------------------------------- utils */

    verbose: function (b) { this._verbose = !!b; console.log('[*] verbose = ' + this._verbose); },
    maxBytes: function (n) { this._max = n; console.log('[*] print limit = ' + n); },

    hex: function (b) {
        if (b === null || b === undefined) return '(null)';
        try {
            var s = '', n = Math.min(b.length, this._max);
            for (var i = 0; i < n; i++) {
                var v = b[i] & 0xff;
                s += (v < 16 ? '0' : '') + v.toString(16);
            }
            return s + (b.length > n ? '… (' + b.length + ' bytes total)' : '');
        } catch (e) { return '(unreadable)'; }
    },

    /* Print as text when it looks like text; otherwise hex. */
    show: function (b) {
        if (b === null || b === undefined) return '(null)';
        try {
            if (b.length === 0) return '(empty)';
            var printable = 0, n = Math.min(b.length, 256);
            for (var i = 0; i < n; i++) {
                var v = b[i] & 0xff;
                if ((v >= 0x20 && v < 0x7f) || v === 0x0a || v === 0x09) printable++;
            }
            if (printable / n > 0.85) {
                var s = Java.use('java.lang.String').$new(b);
                s = s.toString();
                return '"' + (s.length > this._max ? s.substring(0, this._max) + '…' : s) + '"';
            }
        } catch (e) { /* fall through to hex */ }
        return this.hex(b);
    },

    stack: function () {
        try {
            return Java.use('android.util.Log')
                .getStackTraceString(Java.use('java.lang.Exception').$new())
                .split('\n').slice(2, 12).join('\n');
        } catch (e) { return '  (no stack)'; }
    },

    /*
     * The one-line diagnostic that decides how much a captured plaintext is
     * worth. A genuine AndroidKeyStore key returns null from getEncoded().
     * Anything else is holding material in this process right now.
     */
    describeKey: function (key) {
        if (key === null || key === undefined) return { text: '(null key)', keystore: false };
        var cls = '(unknown)';
        try { cls = key.$className; } catch (e) { /* ignore */ }

        var enc = null, isKs = false;
        try { enc = key.getEncoded(); } catch (e) { /* some keys throw */ }

        if (enc === null) {
            isKs = true;
            this._stats.keystoreKeys++;
            return {
                text: cls + '  getEncoded()=null  -> GENUINE KEYSTORE HANDLE ' +
                      '(material is NOT in this process)',
                keystore: true
            };
        }

        this._stats.rawKeys++;
        return {
            text: cls + '  getEncoded()=' + enc.length + ' bytes: ' + this.hex(enc) +
                  '\n        *** NOT A KEYSTORE KEY. The material is in this process right ' +
                  'now.\n        *** If it is a constant, it is in the APK, which is ' +
                  'world-readable —\n        *** so it works on EVERY installation with no ' +
                  'device access. Finding 1.\n        *** Run hook-secretkeyspec.js to see ' +
                  'where it was built.',
            keystore: false
        };
    },

    noteIv: function (ivBytes, transform) {
        if (ivBytes === null) return '';
        var h = this.hex(ivBytes);
        var zero = true;
        try {
            for (var i = 0; i < ivBytes.length; i++) if ((ivBytes[i] & 0xff) !== 0) { zero = false; break; }
        } catch (e) { zero = false; }

        var msg = '';
        if (zero) {
            msg = '\n        *** ALL-ZERO IV. With GCM this is catastrophic, not merely weak: ' +
                  'two\n        *** messages under the same key and nonce leak the XOR of the ' +
                  'plaintexts\n        *** AND allow forgery of further messages. Finding 7.';
        } else if (this._ivSeen[h] !== undefined) {
            this._ivSeen[h]++;
            msg = '\n        *** IV REPEATED (' + this._ivSeen[h] + ' times). ' +
                  (/GCM/i.test(transform)
                      ? 'GCM nonce reuse destroys both confidentiality and integrity. Finding 7.'
                      : 'Deterministic IV. Confirm whether it is derived or constant.');
        } else {
            this._ivSeen[h] = 1;
        }
        return msg;
    },

    /* ---------------------------------------------------------------- hooks */

    install: function () {
        var self = this;

        /* ------------------------------------------------------- Cipher --- */

        var Cipher;
        try { Cipher = Java.use('javax.crypto.Cipher'); }
        catch (e) { console.log('[-] javax.crypto.Cipher not found: ' + e); return; }

        try {
            Cipher.getInstance.overload('java.lang.String').implementation = function (t) {
                var c = this.getInstance(t);
                self._stats.transforms[t] = (self._stats.transforms[t] || 0) + 1;
                if (/ECB/i.test(t)) {
                    console.log('[cipher] getInstance("' + t + '")  *** ECB — leaks plaintext ' +
                                'structure. Immediate finding.');
                }
                return c;
            };
        } catch (e) { /* ignore */ }

        try {
            Cipher.getInstance.overload('java.lang.String', 'java.lang.String')
            .implementation = function (t, p) {
                self._stats.transforms[t] = (self._stats.transforms[t] || 0) + 1;
                return this.getInstance(t, p);
            };
        } catch (e) { /* ignore */ }

        // init overloads. Each is guarded separately.
        var initOverloads = [
            ['int', 'java.security.Key'],
            ['int', 'java.security.Key', 'java.security.spec.AlgorithmParameterSpec'],
            ['int', 'java.security.Key', 'java.security.AlgorithmParameters'],
            ['int', 'java.security.Key', 'java.security.SecureRandom'],
            ['int', 'java.security.Key', 'java.security.spec.AlgorithmParameterSpec',
                    'java.security.SecureRandom'],
            ['int', 'java.security.cert.Certificate']
        ];

        initOverloads.forEach(function (sig) {
            try {
                Cipher.init.overload.apply(Cipher.init, sig).implementation = function () {
                    var args = Array.prototype.slice.call(arguments);
                    var mode = args[0];
                    var key  = args[1];
                    var transform = '(unknown)';
                    try { transform = this.getAlgorithm(); } catch (e) { /* ignore */ }

                    console.log('');
                    console.log('=== Cipher.init  ' + (self.OPMODE[mode] || mode) +
                                '  ' + transform + ' ===');

                    var d = self.describeKey(key);
                    console.log('    key   : ' + d.text);
                    this.__ksKey = d.keystore;
                    this.__transform = transform;
                    this.__mode = mode;

                    // Parameters — the IV lives here.
                    if (args.length > 2 && args[2] !== null) {
                        var p = args[2];
                        var pcls = '(unknown)';
                        try { pcls = p.$className; } catch (e) { /* ignore */ }
                        console.log('    params: ' + pcls);
                        try {
                            if (/GCMParameterSpec/.test(pcls)) {
                                var giv = Java.cast(p,
                                    Java.use('javax.crypto.spec.GCMParameterSpec')).getIV();
                                console.log('    iv    : ' + self.hex(giv) +
                                            '  (tag ' + Java.cast(p,
                                            Java.use('javax.crypto.spec.GCMParameterSpec'))
                                            .getTLen() + ' bits)' +
                                            self.noteIv(giv, transform));
                                console.log('    NOTE: a caller-supplied IV means the key was');
                                console.log('          created with setRandomizedEncryptionRequired');
                                console.log('          (false) for ENCRYPT. For DECRYPT this is');
                                console.log('          normal and expected.');
                            } else if (/IvParameterSpec/.test(pcls)) {
                                var iiv = Java.cast(p,
                                    Java.use('javax.crypto.spec.IvParameterSpec')).getIV();
                                console.log('    iv    : ' + self.hex(iiv) +
                                            self.noteIv(iiv, transform));
                            }
                        } catch (e) { /* ignore */ }
                    }

                    var ret = this.init.apply(this, args);

                    // For ENCRYPT with a KeyMint-generated IV, the IV appears
                    // only AFTER init.
                    try {
                        var iv = this.getIV();
                        if (iv !== null) {
                            console.log('    iv (post-init): ' + self.hex(iv) +
                                        self.noteIv(iv, transform));
                        }
                    } catch (e) { /* ignore */ }

                    if (self._verbose) console.log(self.stack());
                    return ret;
                };
            } catch (e) { /* overload absent — fine */ }
        });

        // doFinal / update — where the data is.
        [['doFinal', '[B'], ['update', '[B']].forEach(function (pair) {
            try {
                Cipher[pair[0]].overload(pair[1]).implementation = function (input) {
                    var out = this[pair[0]](input);
                    self._stats.ops++;
                    var dir = self.OPMODE[this.__mode] || '?';
                    console.log('');
                    console.log('--- Cipher.' + pair[0] + '  ' + dir + '  ' +
                                (this.__transform || '') + ' ---');
                    if (dir === 'ENCRYPT') {
                        console.log('    PLAINTEXT  in : ' + self.show(input));
                        console.log('    ciphertext out: ' + self.hex(out));
                    } else {
                        console.log('    ciphertext in : ' + self.hex(input));
                        console.log('    PLAINTEXT out : ' + self.show(out));
                    }
                    if (this.__ksKey === false) {
                        console.log('    (key is NOT in the Keystore — see the init line above)');
                    }
                    if (self._verbose) console.log(self.stack());
                    return out;
                };
            } catch (e) { /* ignore */ }
        });

        try {
            Cipher.doFinal.overload('[B', 'int', 'int').implementation =
            function (input, off, len) {
                var out = this.doFinal(input, off, len);
                self._stats.ops++;
                var dir = self.OPMODE[this.__mode] || '?';
                console.log('');
                console.log('--- Cipher.doFinal(buf,off,len)  ' + dir + ' ---');
                console.log('    in (' + off + '..' + (off + len) + ') : ' + self.show(input));
                console.log('    out: ' + (dir === 'DECRYPT' ? self.show(out) : self.hex(out)));
                return out;
            };
        } catch (e) { /* ignore */ }

        /* ---------------------------------------------------------- Mac --- */

        try {
            var Mac = Java.use('javax.crypto.Mac');
            Mac.init.overload('java.security.Key').implementation = function (key) {
                console.log('');
                console.log('=== Mac.init  ' + this.getAlgorithm() + ' ===');
                console.log('    key: ' + self.describeKey(key).text);
                if (self._verbose) console.log(self.stack());
                return this.init(key);
            };
            Mac.doFinal.overload('[B').implementation = function (input) {
                var out = this.doFinal(input);
                console.log('--- Mac.doFinal ---');
                console.log('    message: ' + self.show(input));
                console.log('    mac    : ' + self.hex(out));
                return out;
            };
        } catch (e) { /* ignore */ }

        /* ---------------------------------------------------- Signature --- */

        try {
            var Sig = Java.use('java.security.Signature');
            Sig.initSign.overload('java.security.PrivateKey').implementation = function (k) {
                console.log('');
                console.log('=== Signature.initSign  ' + this.getAlgorithm() + ' ===');
                console.log('    key: ' + self.describeKey(k).text);
                if (self._verbose) console.log(self.stack());
                return this.initSign(k);
            };
            Sig.sign.overload().implementation = function () {
                var s = this.sign();
                console.log('--- Signature.sign -> ' + self.hex(s));
                return s;
            };
        } catch (e) { /* ignore */ }

        /* ----------------------------------------- the auth-binding tell --- */

        try {
            var UNA = Java.use('android.security.keystore.UserNotAuthenticatedException');
            UNA.$init.overload().implementation = function () {
                console.log('');
                console.log('*** UserNotAuthenticatedException ***');
                console.log('    The key IS auth-bound and there is no valid authentication.');
                console.log('    THIS IS A POSITIVE RESULT FOR THE APPLICATION and you should');
                console.log('    report it as one — a report that only lists breakage gives the');
                console.log('    client no way to know which controls worked.');
                console.log('');
                console.log('    The attack is no longer on the key. It is on the PROMPT:');
                console.log('    if BiometricPrompt.authenticate() was called WITHOUT a');
                console.log('    CryptoObject, the result is a boolean in this process and you');
                console.log('    can set it yourself. See ../../48-Biometrics/.');
                return this.$init();
            };
        } catch (e) { /* ignore */ }

        try {
            var KPI = Java.use('android.security.keystore.KeyPermanentlyInvalidatedException');
            KPI.$init.overload().implementation = function () {
                console.log('*** KeyPermanentlyInvalidatedException — biometric enrolled, lock');
                console.log('    screen removed, or factory reset. The key is gone for good.');
                return this.$init();
            };
        } catch (e) { /* ignore */ }

        console.log('[+] Hooks installed.');
    },

    /* ------------------------------------------------- actively drive a key */

    aliases: function () {
        Java.perform(function () {
            var ksj = Java.use('java.security.KeyStore').getInstance('AndroidKeyStore');
            ksj.load(null);
            var e = ksj.aliases();
            console.log('');
            console.log('AndroidKeyStore aliases:');
            var n = 0;
            while (e.hasMoreElements()) { console.log('  ' + e.nextElement()); n++; }
            if (n === 0) console.log('  (none — run hook-secretkeyspec.js instead)');
            console.log('');
        });
    },

    _bytes: function (hexStr) {
        var clean = hexStr.replace(/[^0-9a-fA-F]/g, '');
        var out = [];
        for (var i = 0; i + 1 < clean.length; i += 2) {
            var v = parseInt(clean.substr(i, 2), 16);
            out.push(v > 127 ? v - 256 : v);      // Java bytes are signed
        }
        return Java.array('byte', out);
    },

    /*
     * THE DEMONSTRATION. Use the app's own Keystore key, with no user
     * interaction whatsoever, from code that is not the app's.
     */
    decrypt: function (alias, ivHex, ctHex, tagBits) {
        var self = this;
        tagBits = tagBits || 128;
        Java.perform(function () {
            try {
                var ksj = Java.use('java.security.KeyStore').getInstance('AndroidKeyStore');
                ksj.load(null);
                var key = Java.cast(ksj.getKey(alias, null),
                                    Java.use('javax.crypto.SecretKey'));
                if (key === null) { console.log('[-] no such alias: ' + alias); return; }

                console.log('');
                console.log('=== DRIVING KEY "' + alias + '" WITH NO USER INTERACTION ===');
                console.log('    getEncoded() = ' + key.getEncoded() +
                            '   (null = we cannot EXTRACT it)');

                var c = Java.use('javax.crypto.Cipher').getInstance('AES/GCM/NoPadding');
                var spec = Java.use('javax.crypto.spec.GCMParameterSpec')
                               .$new(tagBits, self._bytes(ivHex));
                c.init(2 /* DECRYPT_MODE */, key, spec);
                var pt = c.doFinal(self._bytes(ctHex));

                console.log('');
                console.log('    RECOVERED: ' + self.show(pt));
                console.log('');
                console.log('    That is the whole chapter in one output. The key could not be');
                console.log('    extracted and did not need to be. Screenshot it, and put it in');
                console.log('    the report next to the developer\'s claim.');
                console.log('');
                console.log('    NOW ANSWER THE QUESTION: what did you learn that you did not');
                console.log('    already have? You had code execution in the process. If the');
                console.log('    app would have decrypted this itself two seconds later, the');
                console.log('    Keystore was not the weak link. The finding is elsewhere —');
                console.log('    in the auth binding, the hardcoded key, or the plaintext copy.');
            } catch (e) {
                console.log('[-] ' + e);
                if (/UserNotAuthenticated/.test(e.toString())) {
                    console.log('');
                    console.log('    THE KEY IS PROPERLY BOUND. That is a positive result for');
                    console.log('    the app and belongs in the report as one.');
                    console.log('    Attack the PROMPT instead — see ../../48-Biometrics/.');
                }
            }
        });
    },

    encrypt: function (alias, text) {
        var self = this;
        Java.perform(function () {
            try {
                var ksj = Java.use('java.security.KeyStore').getInstance('AndroidKeyStore');
                ksj.load(null);
                var key = Java.cast(ksj.getKey(alias, null),
                                    Java.use('javax.crypto.SecretKey'));
                var c = Java.use('javax.crypto.Cipher').getInstance('AES/GCM/NoPadding');
                c.init(1 /* ENCRYPT_MODE */, key);
                var ct = c.doFinal(Java.use('java.lang.String').$new(text).getBytes());
                console.log('    iv         = ' + self.hex(c.getIV()));
                console.log('    ciphertext = ' + self.hex(ct));
                console.log('    (the IV was generated inside KeyMint — that is what');
                console.log('     setRandomizedEncryptionRequired(true) enforces)');
            } catch (e) { console.log('[-] ' + e); }
        });
    },

    /*
     * AndroidKeyStoreSecretKey holds no material, so a heap scan for
     * SecretKeySpec finds EXACTLY the keys that are not hardware-protected.
     * That is precisely the set worth caring about.
     */
    heapKeys: function () {
        var self = this;
        Java.perform(function () {
            console.log('');
            console.log('=== LIVE SecretKeySpec INSTANCES ON THE HEAP ===');
            var n = 0;
            Java.choose('javax.crypto.spec.SecretKeySpec', {
                onMatch: function (inst) {
                    try {
                        var enc = inst.getEncoded();
                        console.log('  [' + (++n) + '] ' + inst.getAlgorithm() + '  ' +
                                    enc.length + ' bytes: ' + self.hex(enc));
                    } catch (e) { /* ignore */ }
                },
                onComplete: function () {
                    console.log('  ' + n + ' instance(s).');
                    if (n > 0) {
                        console.log('');
                        console.log('  Every one of these is a key that is NOT protected by the');
                        console.log('  Keystore. Trace where each came from — hook-secretkeyspec.js');
                        console.log('  gives you the stack at construction time.');
                    }
                    console.log('');
                }
            });
        });
    },

    summary: function () {
        console.log('');
        console.log('=== SESSION SUMMARY ===');
        console.log('  crypto operations observed : ' + this._stats.ops);
        console.log('  genuine Keystore keys used : ' + this._stats.keystoreKeys);
        console.log('  RAW keys used (in-heap)    : ' + this._stats.rawKeys +
                    (this._stats.rawKeys > 0 ? '   <<< investigate every one' : ''));
        console.log('  transformations seen:');
        Object.keys(this._stats.transforms).forEach(function (t) {
            console.log('    ' + t);
        });
        console.log('  distinct IVs seen: ' + Object.keys(this._ivSeen).length);
        var reused = Object.keys(this._ivSeen).filter(function (k) {
            return cy._ivSeen[k] > 1;
        });
        if (reused.length) {
            console.log('  *** REUSED IVs: ' + reused.length + ' — Finding 7');
        }
        console.log('');
    },

    help: function () {
        console.log([
            '',
            'cy.summary()                       what has been seen so far',
            'cy.verbose(true)                   stack trace on every operation',
            'cy.maxBytes(4096)                  raise the print limit',
            'cy.aliases()                       list AndroidKeyStore aliases',
            'cy.decrypt(alias, ivHex, ctHex)    DRIVE the key, no user interaction',
            'cy.encrypt(alias, "text")          the same, encrypting',
            'cy.heapKeys()                      live SecretKeySpec instances',
            ''
        ].join('\n'));
    }
};

/* --------------------------------------------------------------- bootstrap */

Java.perform(function () {
    console.log('');
    console.log('=== hook-cipher-keystore — Chapter 49 sections 7.5 and 7.6 ===');
    console.log('[*] The Keystore prevents key EXTRACTION, not key USE.');
    console.log('[*] This script demonstrates the second half of that sentence.');
    cy.install();
    console.log('[+] Ready. cy.help() for commands. Now exercise the app.');
    console.log('');
});
