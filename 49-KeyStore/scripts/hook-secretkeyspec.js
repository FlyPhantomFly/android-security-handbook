/*
 * hook-secretkeyspec.js — catch keys that never reach the Keystore at all.
 *
 * WHAT IT DOES
 *   Hooks javax.crypto.spec.SecretKeySpec's constructors and prints the raw key
 *   material of every one the process builds, with the algorithm, the length, an
 *   entropy estimate, and a Java stack trace showing exactly which code path
 *   produced it.
 *
 *   It also hooks the neighbouring paths a key can arrive by:
 *     - PBEKeySpec / SecretKeyFactory     (password-derived keys, and the
 *                                          iteration count, which is the finding)
 *     - IvParameterSpec / GCMParameterSpec (a constant IV alongside a constant key)
 *     - KeyStore.setEntry                  (the import path — §3.6)
 *     - Base64.decode and Cipher key paths (how a "hidden" constant becomes bytes)
 *
 * WHY IT MATTERS — THIS IS THE HIGHEST-VALUE HOOK IN THE CHAPTER
 *   The single most common real-world Keystore finding is not a Keystore
 *   finding at all. It is a key that never went near the Keystore:
 *
 *       byte[] k = { 0x2f, (byte)0x91, ... };
 *       SecretKey key = new SecretKeySpec(k, "AES");
 *
 *   `SecretKeySpec` wraps raw bytes that exist in the application's heap. Those
 *   bytes came from somewhere, and on an Android device there are only a few
 *   somewheres: a compiled-in constant, a string resource, an asset, a value
 *   assembled at runtime from obfuscated fragments, or a native library. All of
 *   them ship inside the APK — and the APK is world-readable on every device.
 *
 *   So the consequence is categorically worse than anything in the rest of this
 *   chapter. A key recovered from a Keystore-using app requires code execution
 *   on THAT device, and yields THAT device's data. A hardcoded key requires no
 *   device access at all, works against EVERY installation simultaneously, and
 *   cannot be rotated without shipping a new build.
 *
 *   Why this hook rather than grep? Because everything eventually has to become
 *   a byte[] at this constructor. It does not matter whether the key was:
 *       - XOR'd together from three arrays at runtime,
 *       - decrypted from assets/config.dat with a second hardcoded key,
 *       - assembled character by character to defeat `strings`,
 *       - built in C and passed up through JNI, or
 *       - derived from a device identifier the attacker can also read.
 *   All of those paths converge here, and the stack trace tells you which one
 *   you are looking at.
 *
 *   Run it for the whole session on every engagement. It costs nothing and it
 *   finds the most serious thing in the category.
 *
 *   See ../README.md sections 5.2 (Finding 1), 6.3 and 7.4.
 *
 * HOW TO RUN
 *   # host — spawn, so keys built during startup are caught
 *   frida -U -f com.target.app -l hook-secretkeyspec.js
 *
 *   # host — or attach
 *   frida -U -n com.target.app -l hook-secretkeyspec.js
 *
 *   Then exercise the app fully: first launch, log in, open every screen that
 *   handles data. From the REPL:
 *     sks.summary()      every distinct key seen, with entropy
 *     sks.heap()         live SecretKeySpec instances (Java.choose)
 *     sks.verbose(false) suppress stack traces
 *
 * REQUIREMENTS
 *   frida-server on the device matching your host frida version. Any Android
 *   version. Every hook is individually guarded.
 *
 * SAFETY
 *   Read-only. Every hook logs and calls through unmodified.
 *
 * REPORTING NOTE
 *   Before writing this up, confirm the key is genuinely CONSTANT rather than
 *   per-install or per-device. Uninstall, reinstall, and run again on a second
 *   device. A key derived from ANDROID_ID is a different (and much weaker)
 *   finding from a key compiled into the APK — but note that ANDROID_ID is
 *   readable by the attacker too, so "derived" is not the same as "secret".
 *
 * AUTHORISED TESTING ONLY.
 */

'use strict';

var sks = {

    _verbose: true,
    _seen: {},

    verbose: function (b) { this._verbose = !!b; console.log('[*] verbose = ' + this._verbose); },

    hex: function (b) {
        if (b === null || b === undefined) return '(null)';
        try {
            var s = '';
            for (var i = 0; i < b.length; i++) {
                var v = b[i] & 0xff;
                s += (v < 16 ? '0' : '') + v.toString(16);
            }
            return s;
        } catch (e) { return '(unreadable)'; }
    },

    ascii: function (b) {
        try {
            var s = '', printable = 0;
            for (var i = 0; i < b.length; i++) {
                var v = b[i] & 0xff;
                if (v >= 0x20 && v < 0x7f) { s += String.fromCharCode(v); printable++; }
                else s += '.';
            }
            return printable / b.length > 0.7 ? '  ascii="' + s + '"' : '';
        } catch (e) { return ''; }
    },

    /*
     * A crude Shannon entropy estimate, in bits per byte. Genuinely random key
     * material approaches 8.0 (though a 16-byte sample is small, so treat the
     * number as a hint, not a verdict). A low value means the "key" is text, a
     * repeated pattern, or padding — all of which are strong indicators of a
     * constant rather than a generated key.
     */
    entropy: function (b) {
        try {
            var counts = {}, n = b.length;
            if (n === 0) return 0;
            for (var i = 0; i < n; i++) {
                var v = b[i] & 0xff;
                counts[v] = (counts[v] || 0) + 1;
            }
            var h = 0;
            Object.keys(counts).forEach(function (k) {
                var p = counts[k] / n;
                h -= p * (Math.log(p) / Math.log(2));
            });
            return Math.round(h * 100) / 100;
        } catch (e) { return -1; }
    },

    stack: function () {
        try {
            return Java.use('android.util.Log')
                .getStackTraceString(Java.use('java.lang.Exception').$new())
                .split('\n').slice(2, 14).join('\n');
        } catch (e) { return '  (no stack)'; }
    },

    record: function (algo, bytes, source) {
        var h = this.hex(bytes);
        var first = this._seen[h] === undefined;
        if (first) {
            this._seen[h] = { algo: algo, len: bytes.length, count: 0,
                              entropy: this.entropy(bytes), source: source };
        }
        this._seen[h].count++;
        return first;
    },

    /* ---------------------------------------------------------------- hooks */

    install: function () {
        var self = this;

        /* ----------------------------------------------- SecretKeySpec --- */

        var SKS;
        try { SKS = Java.use('javax.crypto.spec.SecretKeySpec'); }
        catch (e) { console.log('[-] SecretKeySpec not found: ' + e); return; }

        try {
            SKS.$init.overload('[B', 'java.lang.String').implementation =
            function (bytes, alg) {
                self.report(bytes, alg, 'SecretKeySpec(byte[], String)');
                return this.$init(bytes, alg);
            };
        } catch (e) { console.log('[!] SecretKeySpec(byte[],String) hook failed: ' + e); }

        try {
            SKS.$init.overload('[B', 'int', 'int', 'java.lang.String').implementation =
            function (bytes, off, len, alg) {
                // Report only the slice that becomes the key.
                var slice = [];
                try {
                    for (var i = off; i < off + len; i++) slice.push(bytes[i]);
                } catch (e) { slice = bytes; }
                self.report(Java.array('byte', slice), alg,
                            'SecretKeySpec(byte[], ' + off + ', ' + len + ', String)');
                return this.$init(bytes, off, len, alg);
            };
        } catch (e) { /* ignore */ }

        /* -------------------------------------------- password derivation --- */

        try {
            var PBE = Java.use('javax.crypto.spec.PBEKeySpec');
            PBE.$init.overload('[C', '[B', 'int', 'int').implementation =
            function (pw, salt, iter, len) {
                console.log('');
                console.log('=== PBEKeySpec — a PASSWORD-DERIVED key ===');
                try {
                    console.log('    password    : "' +
                        Java.use('java.lang.String').$new(pw).toString() + '"');
                } catch (e) { console.log('    password    : (unreadable)'); }
                console.log('    salt        : ' + self.hex(salt) +
                            (salt !== null && salt.length < 8
                                ? '   *** SHORT SALT' : ''));
                console.log('    iterations  : ' + iter +
                            (iter < 10000 ? '   *** LOW — trivially brute-forced offline' : ''));
                console.log('    key length  : ' + len + ' bits');
                console.log('    If the password is a CONSTANT, this derivation is theatre: the');
                console.log('    attacker has the password, the salt and the iteration count.');
                if (self._verbose) console.log(self.stack());
                return this.$init(pw, salt, iter, len);
            };
        } catch (e) { /* ignore */ }

        /* ------------------------------------------------- the IV, too --- */

        ['javax.crypto.spec.IvParameterSpec'].forEach(function (cls) {
            try {
                var C = Java.use(cls);
                C.$init.overload('[B').implementation = function (iv) {
                    console.log('[iv] IvParameterSpec(' + self.hex(iv) + ')');
                    var zero = true;
                    try {
                        for (var i = 0; i < iv.length; i++)
                            if ((iv[i] & 0xff) !== 0) { zero = false; break; }
                    } catch (e) { zero = false; }
                    if (zero) {
                        console.log('     *** ALL-ZERO IV. A constant IV alongside a constant key');
                        console.log('     *** means identical plaintexts produce identical');
                        console.log('     *** ciphertexts. Finding 7.');
                    }
                    return this.$init(iv);
                };
            } catch (e) { /* ignore */ }
        });

        try {
            var GCM = Java.use('javax.crypto.spec.GCMParameterSpec');
            GCM.$init.overload('int', '[B').implementation = function (tlen, iv) {
                console.log('[iv] GCMParameterSpec(tag=' + tlen + ' bits, iv=' + self.hex(iv) + ')');
                return this.$init(tlen, iv);
            };
        } catch (e) { /* ignore */ }

        /* ------------------------------------------------- the import path --- */

        try {
            var KS = Java.use('java.security.KeyStore');
            KS.setEntry.implementation = function (alias, entry, prot) {
                console.log('');
                console.log('=== KeyStore.setEntry("' + alias + '") — AN IMPORT ===');
                console.log('    The plaintext key material existed in this process before this');
                console.log('    call. KeyInfo.getOrigin() will report IMPORTED, and so will the');
                console.log('    attestation. Follow the material back to its source — that');
                console.log('    source is now the weakest link and it is where you attack.');
                console.log('    The SecretKeySpec line above this one is the material itself.');
                if (self._verbose) console.log(self.stack());
                return this.setEntry(alias, entry, prot);
            };
        } catch (e) { /* ignore */ }

        /* --------------------------- how a "hidden" constant becomes bytes --- */

        try {
            var B64 = Java.use('android.util.Base64');
            B64.decode.overload('java.lang.String', 'int').implementation = function (s, f) {
                var out = this.decode(s, f);
                if (out !== null && (out.length === 16 || out.length === 24 || out.length === 32)) {
                    console.log('[b64] Base64.decode("' + s + '") -> ' + out.length +
                                ' bytes  <-- KEY-SIZED. Watch what it is used for.');
                }
                return out;
            };
        } catch (e) { /* ignore */ }

        try {
            var HexOrString = Java.use('java.lang.String');
            HexOrString.getBytes.overload().implementation = function () {
                var out = this.getBytes();
                // Only comment on key-sized results, and only for short strings,
                // to keep the noise down.
                try {
                    var s = this.toString();
                    if ((out.length === 16 || out.length === 32) && s.length <= 64 &&
                        /^[\x20-\x7e]+$/.test(s)) {
                        console.log('[str] "' + s + '".getBytes() -> ' + out.length +
                                    ' bytes  <-- key-sized string');
                    }
                } catch (e) { /* ignore */ }
                return out;
            };
        } catch (e) { /* ignore — this one is noisy on some apps */ }

        console.log('[+] Hooks installed.');
    },

    /* --------------------------------------------------------------- report */

    report: function (bytes, alg, source) {
        var first = this.record(alg, bytes, source);
        var h = this.hex(bytes);
        var ent = this._seen[h].entropy;

        console.log('');
        console.log('==========================================================');
        console.log('  SecretKeySpec  —  A KEY THAT IS NOT IN THE KEYSTORE');
        console.log('==========================================================');
        console.log('  algorithm : ' + alg);
        console.log('  length    : ' + bytes.length + ' bytes (' + (bytes.length * 8) + ' bits)');
        console.log('  hex       : ' + h);
        console.log('  entropy   : ' + ent + ' bits/byte' +
                    (ent < 4.0 ? '   *** LOW — this looks like text or a pattern, not a ' +
                                 'generated key' : ''));
        console.log('  ' + this.ascii(bytes));
        console.log('  source    : ' + source);
        console.log('  seen      : ' + this._seen[h].count + ' time(s) this session');

        if (first) {
            console.log('');
            console.log('  WHAT TO DO NEXT — in this order:');
            console.log('   1. Read the stack below and identify WHERE these bytes came from.');
            console.log('   2. Decide whether the key is CONSTANT or per-install:');
            console.log('        adb uninstall <pkg> && adb install <pkg>   then re-run.');
            console.log('        Same bytes  -> hardcoded. Works on EVERY installation, needs');
            console.log('                       no device access, cannot be rotated without a');
            console.log('                       new build. That is the High-severity case.');
            console.log('        Different   -> per-install. Now find out what it is derived');
            console.log('                       from. If it is ANDROID_ID or an IMEI, the');
            console.log('                       attacker can read that too.');
            console.log('   3. Find it statically so the finding does not depend on Frida:');
            console.log('        grep -rn "' + h.substring(0, 16) + '" out/sources/');
            console.log('        strings work/assets/* work/res/raw/* | grep -i key');
            console.log('   4. Determine WHAT THIS KEY PROTECTS. The severity is the value of');
            console.log('      that, not the fact that a key was hardcoded.');
            console.log('   5. Write the fix as code: generate in AndroidKeyStore, keep only');
            console.log('      the alias, and if the key must come from a server use secure key');
            console.log('      import (WrappedKeyEntry) so the material never enters the heap.');
            console.log('      See ../examples/01-basic-aes-key.java.');
        }

        if (this._verbose) {
            console.log('');
            console.log(this.stack());
        }
        console.log('');
    },

    /* ---------------------------------------------------------------- heap */

    heap: function () {
        var self = this;
        Java.perform(function () {
            console.log('');
            console.log('=== LIVE SecretKeySpec INSTANCES ON THE HEAP ===');
            console.log('  AndroidKeyStoreSecretKey holds NO material, so this scan finds');
            console.log('  exactly the keys that are not hardware-protected — which is');
            console.log('  precisely the set you care about.');
            console.log('');
            var n = 0;
            Java.choose('javax.crypto.spec.SecretKeySpec', {
                onMatch: function (inst) {
                    try {
                        var enc = inst.getEncoded();
                        console.log('  [' + (++n) + '] ' + inst.getAlgorithm() + '  ' +
                                    enc.length + ' bytes  entropy=' + self.entropy(enc));
                        console.log('       ' + self.hex(enc));
                    } catch (e) { /* ignore */ }
                },
                onComplete: function () {
                    console.log('');
                    console.log('  ' + n + ' instance(s) live right now.');
                    if (n === 0) {
                        console.log('  None. Either the app really does use the Keystore for');
                        console.log('  everything, or the keys are created and released outside');
                        console.log('  this moment. Keep the constructor hook running instead.');
                    }
                    console.log('');
                }
            });
        });
    },

    /* -------------------------------------------------------------- summary */

    summary: function () {
        var keys = Object.keys(this._seen);
        console.log('');
        console.log('=== SESSION SUMMARY — keys that never reached the Keystore ===');
        if (keys.length === 0) {
            console.log('  None seen.');
            console.log('');
            console.log('  That is a genuinely GOOD sign and worth reporting as one: it means');
            console.log('  every key this app used during the session was a Keystore handle.');
            console.log('  Two caveats before you write that down:');
            console.log('    - Did you exercise every flow? Keys are often built lazily.');
            console.log('    - A key built in NATIVE code and used through a native crypto');
            console.log('      library never touches javax.crypto at all. Check for bundled');
            console.log('      libcrypto/libssl and see ../../15-Native-Code/.');
            console.log('');
            return;
        }
        console.log('  ' + keys.length + ' distinct key(s):');
        console.log('');
        var self = this;
        keys.forEach(function (h) {
            var r = self._seen[h];
            console.log('  ' + r.algo.padEnd(8) + ' ' + String(r.len).padEnd(4) + 'B  ' +
                        'entropy=' + String(r.entropy).padEnd(5) + '  used ' +
                        r.count + 'x');
            console.log('    ' + h);
            console.log('    via ' + r.source);
        });
        console.log('');
        console.log('  For EACH of these, answer: constant or per-install? what does it');
        console.log('  protect? and where is it in the APK? Only then is it a finding.');
        console.log('');
    },

    help: function () {
        console.log([
            '',
            'sks.summary()       every distinct key seen this session',
            'sks.heap()          live SecretKeySpec instances right now',
            'sks.verbose(false)  suppress stack traces',
            ''
        ].join('\n'));
    }
};

/* --------------------------------------------------------------- bootstrap */

Java.perform(function () {
    console.log('');
    console.log('=== hook-secretkeyspec — Chapter 49 section 7.4 ===');
    console.log('[*] The most common Keystore finding is not IN the Keystore.');
    console.log('[*] Every key, however it was obfuscated, becomes a byte[] here.');
    sks.install();
    console.log('[+] Ready. sks.help() for commands. Now exercise the app fully.');
    console.log('');
});
