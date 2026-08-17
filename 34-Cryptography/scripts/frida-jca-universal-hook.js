/*
 * frida-jca-universal-hook.js — instrument the entire Java Cryptography Architecture.
 *
 * WHAT IT DOES
 *   Installs hooks across every entry point an Android app can use to perform
 *   cryptography through the JCA, and prints, for each operation:
 *
 *     - the transformation string ("AES/GCM/NoPadding") and the resolved provider
 *     - the raw key bytes, in hex and in ASCII, whenever the key is a software key
 *     - the IV / nonce / salt, in hex
 *     - the plaintext going in and the ciphertext coming out (both directions)
 *     - the associated data passed to updateAAD
 *     - an optional Java stack trace showing which app class asked for it
 *
 *   On top of the raw trace it applies a set of judgements, because a wall of hex
 *   is not a finding. It flags:
 *
 *     - ECB mode, including the silent form Cipher.getInstance("AES")     (F-02)
 *     - all-zero, all-constant and repeated IVs                            (F-03)
 *     - (key, nonce) pair reuse under GCM/CTR — the catastrophic case      (F-04)
 *     - SecretKeySpec built from what looks like a hardcoded constant      (F-01)
 *     - java.util.Random anywhere near key or IV material                  (F-06)
 *     - MD5 / SHA-1 / DES / 3DES / RC4 / RC2 / Blowfish                    (F-07)
 *     - PBKDF2 iteration counts below the current recommendation
 *     - GCM tags shorter than 128 bits, and RSA without OAEP               (F-14)
 *     - Arrays.equals / String.equals used to compare MACs                 (F-15)
 *
 *   The finding identifiers (F-01 … F-16) match the catalogue in ../README.md §5.2,
 *   so anything this script prints can be pasted straight into a report row.
 *
 * WHY IT MATTERS
 *   Almost no Android application is broken because AES is broken. They are broken
 *   because of *how* AES was used, and every one of those mistakes is visible at the
 *   JCA boundary — the layer between the app's own code and the provider that does
 *   the maths. One hook point, every symmetric key the app holds in software.
 *
 *   This is also the fastest route into a packed or obfuscated app. Obfuscation
 *   renames the app's classes; it cannot rename javax.crypto.Cipher, because the
 *   platform owns that name. A malware dropper that decrypts a DEX payload before
 *   loading it hands you the plaintext DEX here, whatever its own code looks like.
 *
 * HOW TO RUN
 *   # host — spawn (preferred: catches crypto performed during app initialisation)
 *   frida -U -f com.example.target -l frida-jca-universal-hook.js
 *
 *   # host — attach to an already running app
 *   frida -U -n com.example.target -l frida-jca-universal-hook.js
 *
 *   # host — with options
 *   frida -U -f com.example.target -l frida-jca-universal-hook.js \
 *         -P '{"filterPackage":"com.example","maxDump":512,"showStacks":true}'
 *
 *   From the Frida REPL, at any time:
 *     jca.report()        summary: algorithms seen, keys recovered, findings raised
 *     jca.keys()          every distinct key observed, with its call site
 *     jca.reset()         clear the accumulated state
 *     jca.config()        show the active configuration
 *     jca.help()
 *
 *   Options (all optional; pass as JSON to -P, or edit CONFIG below):
 *     filterPackage  string  only print operations whose stack mentions this prefix
 *     maxDump        int     max bytes of any single buffer to hex-dump (default 256)
 *     showStacks     bool    print a Java stack trace for every operation
 *     stackDepth     int     frames of stack to print (default 8)
 *     quiet          bool    suppress the per-operation trace; findings only
 *     dumpDir        string  if set, write every plaintext/ciphertext buffer here
 *
 * REQUIREMENTS
 *   - frida-server running on the device, version-matched to the host frida
 *   - Frida 14 or newer (the script uses only long-stable Java bridge APIs)
 *   - No root strictly required if you can repackage the app with a gadget, but
 *     root plus frida-server is the normal setup
 *
 *   If a hook installs but never fires, the method was probably inlined by the
 *   optimizing compiler. Force interpretation first — see ../../13-ART/README.md:
 *     # host
 *     adb shell cmd package compile -m verify -f com.example.target
 *     adb shell am force-stop com.example.target
 *
 * AUTHORISED TESTING ONLY. This script recovers secret key material.
 */

'use strict';

/* ============================================================== configuration */

var CONFIG = {
    filterPackage: null,   // e.g. "com.example" — null means print everything
    maxDump: 256,
    showStacks: false,
    stackDepth: 8,
    quiet: false,
    dumpDir: null,         // e.g. "/data/local/tmp/jca" — must already exist
    warnOnly: false        // true = print only lines that carry a finding
};

// frida-tools exposes the -P JSON as a global named `parameters`. Older versions
// do not define it at all, hence the guard: never assume a global exists.
try {
    if (typeof parameters !== 'undefined' && parameters !== null) {
        Object.keys(parameters).forEach(function (k) {
            CONFIG[k] = parameters[k];
        });
    }
} catch (e) { /* no parameters supplied */ }

/* ==================================================================== helpers */

var HEX = '0123456789abcdef';

function b2h(bytes, limit) {
    if (bytes === null || bytes === undefined) return '<null>';
    var n = bytes.length;
    var cap = (limit === undefined) ? CONFIG.maxDump : limit;
    var shown = Math.min(n, cap);
    var out = [];
    for (var i = 0; i < shown; i++) {
        var v = bytes[i] & 0xff;
        out.push(HEX[v >> 4] + HEX[v & 0x0f]);
    }
    var s = out.join(' ');
    if (n > shown) s += ' … (' + n + ' bytes total)';
    return s;
}

function b2hCompact(bytes) {
    if (bytes === null || bytes === undefined) return '';
    var out = '';
    for (var i = 0; i < bytes.length; i++) {
        var v = bytes[i] & 0xff;
        out += HEX[v >> 4] + HEX[v & 0x0f];
    }
    return out;
}

function b2a(bytes, limit) {
    if (bytes === null || bytes === undefined) return '<null>';
    var cap = (limit === undefined) ? CONFIG.maxDump : limit;
    var shown = Math.min(bytes.length, cap);
    var s = '';
    for (var i = 0; i < shown; i++) {
        var v = bytes[i] & 0xff;
        s += (v >= 0x20 && v < 0x7f) ? String.fromCharCode(v) : '.';
    }
    if (bytes.length > shown) s += '…';
    return s;
}

function isAllZero(bytes) {
    if (bytes === null || bytes.length === 0) return false;
    for (var i = 0; i < bytes.length; i++) if ((bytes[i] & 0xff) !== 0) return false;
    return true;
}

function isPrintable(bytes) {
    if (bytes === null || bytes.length === 0) return false;
    for (var i = 0; i < bytes.length; i++) {
        var v = bytes[i] & 0xff;
        if (v < 0x20 || v >= 0x7f) return false;
    }
    return true;
}

/*
 * Shannon entropy in bits per byte. Real key material sits very close to 8.0
 * for 16+ bytes; an ASCII passphrase typically lands between 2.5 and 4.5.
 * This is a heuristic, not proof — it is here to sort the output, not to decide.
 */
function entropy(bytes) {
    if (bytes === null || bytes.length === 0) return 0;
    var freq = new Array(256);
    for (var i = 0; i < 256; i++) freq[i] = 0;
    for (var j = 0; j < bytes.length; j++) freq[bytes[j] & 0xff]++;
    var h = 0;
    for (var k = 0; k < 256; k++) {
        if (freq[k] === 0) continue;
        var p = freq[k] / bytes.length;
        h -= p * (Math.log(p) / Math.log(2));
    }
    return h;
}

function toJsBytes(javaByteArray) {
    // Frida hands a Java byte[] to JS as an array-like of signed numbers.
    if (javaByteArray === null || javaByteArray === undefined) return null;
    try {
        var out = [];
        for (var i = 0; i < javaByteArray.length; i++) out.push(javaByteArray[i]);
        return out;
    } catch (e) {
        return null;
    }
}

/* ---------------------------------------------------------------- output ---- */

var COUNTS = { ops: 0, findings: 0, suppressed: 0 };

function log(line) {
    if (CONFIG.quiet) return;
    console.log(line);
}

function warn(id, line) {
    COUNTS.findings++;
    console.warn('[!] ' + (id ? id + ' ' : '') + line);
}

function crit(id, line) {
    COUNTS.findings++;
    console.error('[!!!] ' + (id ? id + ' ' : '') + line);
}

/* ------------------------------------------------------------- stack traces - */

var _Exception = null;
var _Log = null;

function stackTrace() {
    try {
        if (_Exception === null) _Exception = Java.use('java.lang.Exception');
        if (_Log === null) _Log = Java.use('android.util.Log');
        var raw = _Log.getStackTraceString(_Exception.$new());
        var lines = raw.split('\n');
        // Drop the synthetic "java.lang.Exception" header and Frida's own frames.
        var kept = [];
        for (var i = 1; i < lines.length && kept.length < CONFIG.stackDepth; i++) {
            var l = lines[i].trim();
            if (l.length === 0) continue;
            if (l.indexOf('re.frida') !== -1) continue;
            kept.push(l);
        }
        return kept;
    } catch (e) {
        return [];
    }
}

function callerFrame() {
    var st = stackTrace();
    for (var i = 0; i < st.length; i++) {
        var l = st[i];
        if (l.indexOf('javax.crypto') !== -1) continue;
        if (l.indexOf('java.security') !== -1) continue;
        if (l.indexOf('com.android.org.conscrypt') !== -1) continue;
        if (l.indexOf('org.conscrypt') !== -1) continue;
        return l.replace(/^at /, '');
    }
    return st.length > 0 ? st[0].replace(/^at /, '') : '<unknown>';
}

function stackMentionsFilter() {
    if (!CONFIG.filterPackage) return true;
    var st = stackTrace();
    for (var i = 0; i < st.length; i++) {
        if (st[i].indexOf(CONFIG.filterPackage) !== -1) return true;
    }
    COUNTS.suppressed++;
    return false;
}

function printStack(prefix) {
    if (!CONFIG.showStacks) return;
    var st = stackTrace();
    for (var i = 0; i < st.length; i++) console.log(prefix + st[i]);
}

/* ------------------------------------------------------------ file dumping - */

function dumpToFile(tag, bytes) {
    if (!CONFIG.dumpDir || bytes === null) return;
    try {
        var name = CONFIG.dumpDir + '/' + tag + '_' + Date.now() + '_' +
                   Math.floor(Math.random() * 100000) + '.bin';
        var f = new File(name, 'wb');
        var buf = [];
        for (var i = 0; i < bytes.length; i++) buf.push(bytes[i] & 0xff);
        f.write(buf);
        f.close();
        log('    saved  ' + name);
    } catch (e) {
        log('    [-] could not write dump: ' + e);
    }
}

/* =============================================================== judgements */

var WEAK_CIPHERS = ['DES', 'DESEDE', 'TRIPLEDES', 'RC2', 'RC4', 'ARCFOUR', 'BLOWFISH'];
var WEAK_DIGESTS = ['MD2', 'MD4', 'MD5', 'SHA1', 'SHA-1'];

/*
 * Algorithms whose default mode is ECB when the caller omits mode and padding.
 * This is the single highest-yield check in the whole script. In the JCA, a
 * one-token transformation is legal and resolves to <alg>/ECB/PKCS5Padding for a
 * block cipher — the developer did not choose ECB, they simply chose nothing.
 * See ../README.md section 3.5.1.
 */
var BLOCK_CIPHERS_DEFAULTING_TO_ECB =
    ['AES', 'AES_128', 'AES_192', 'AES_256', 'DES', 'DESEDE', 'BLOWFISH', 'RC2'];

function judgeTransformation(t) {
    var findings = [];
    if (!t) return findings;
    var up = t.toUpperCase();
    var parts = up.split('/');
    var alg = parts[0];

    if (parts.length === 1 && BLOCK_CIPHERS_DEFAULTING_TO_ECB.indexOf(alg) !== -1) {
        findings.push({
            id: 'F-02', sev: 'HIGH',
            msg: 'getInstance("' + t + '") has no mode — silently resolves to ' +
                 alg + '/ECB/PKCS5Padding. ECB leaks plaintext structure and permits ' +
                 'block splicing.'
        });
    } else if (up.indexOf('/ECB/') !== -1 || up.indexOf('ECB') === parts[1]) {
        if (parts.length > 1 && parts[1] === 'ECB' && alg !== 'RSA') {
            findings.push({
                id: 'F-02', sev: 'HIGH',
                msg: 'explicit ECB mode in "' + t + '".'
            });
        }
    }

    for (var i = 0; i < WEAK_CIPHERS.length; i++) {
        if (alg.replace(/[-_]/g, '') === WEAK_CIPHERS[i]) {
            findings.push({
                id: 'F-07', sev: 'HIGH',
                msg: 'obsolete cipher "' + alg + '". 64-bit block ciphers are ' +
                     'birthday-bound (Sweet32); RC4 has practical biases.'
            });
        }
    }

    // RSA/ECB/* is a JCA naming quirk — RSA has no mode — but the padding matters.
    if (alg === 'RSA') {
        if (up.indexOf('OAEP') === -1) {
            if (up.indexOf('NOPADDING') !== -1) {
                findings.push({
                    id: 'F-14', sev: 'HIGH',
                    msg: 'textbook RSA (NoPadding): deterministic, malleable, ' +
                         'and trivially attacked for small plaintexts.'
                });
            } else if (up.indexOf('PKCS1') !== -1) {
                findings.push({
                    id: 'F-14', sev: 'MEDIUM',
                    msg: 'RSA PKCS#1 v1.5 encryption padding — Bleichenbacher/ROBOT ' +
                         'oracle class. Use OAEPWithSHA-256AndMGF1Padding.'
                });
            }
        }
    }

    if (up.indexOf('CBC') !== -1 || up.indexOf('CTR') !== -1) {
        findings.push({
            id: 'F-12', sev: 'INFO',
            msg: 'unauthenticated mode "' + t + '" — verify an HMAC is applied ' +
                 'encrypt-then-MAC, otherwise the ciphertext is malleable.'
        });
    }
    return findings;
}

function judgeDigest(alg) {
    if (!alg) return null;
    var up = alg.toUpperCase().replace(/-/g, '');
    for (var i = 0; i < WEAK_DIGESTS.length; i++) {
        if (up === WEAK_DIGESTS[i].replace(/-/g, '')) {
            return {
                id: 'F-07', sev: 'CONTEXT',
                msg: alg + ' is collision-broken. A finding when used for integrity, ' +
                     'signatures, password hashing or key derivation; not a finding ' +
                     'when used as a cache key or ETag. Determine which before reporting.'
            };
        }
    }
    return null;
}

/* ================================================================== state ==== */

var STATE = {
    ciphers: {},        // identityHashCode -> { transformation, keyHex, ivHex, opmode }
    keys: {},           // keyHex -> { alg, len, sites: [], count }
    ivs: {},            // ivHex  -> count
    keyIvPairs: {},     // keyHex|ivHex -> count   (nonce reuse detector)
    transformations: {},
    digests: {},
    macs: {},
    findings: []
};

function recordFinding(id, sev, msg, site) {
    STATE.findings.push({ id: id, sev: sev, msg: msg, site: site || callerFrame() });
}

var _System = null;
function idOf(obj) {
    try {
        if (_System === null) _System = Java.use('java.lang.System');
        return '' + _System.identityHashCode(obj);
    } catch (e) {
        return 'unknown';
    }
}

/* ================================================= key material bookkeeping = */

function noteKey(bytes, alg, origin) {
    if (bytes === null || bytes.length === 0) return;
    var hex = b2hCompact(bytes);
    var site = callerFrame();

    if (STATE.keys[hex] === undefined) {
        STATE.keys[hex] = { alg: alg, len: bytes.length, sites: [], count: 0,
                            entropy: entropy(bytes), printable: isPrintable(bytes),
                            origin: origin };
    }
    var rec = STATE.keys[hex];
    rec.count++;
    if (rec.sites.indexOf(site) === -1) rec.sites.push(site);

    log('[+] KEY  alg=' + alg + '  len=' + bytes.length + 'B (' + (bytes.length * 8) + ' bits)' +
        '  via ' + origin);
    log('    hex    ' + b2h(bytes));
    log('    ascii  ' + b2a(bytes));
    log('    entropy ' + rec.entropy.toFixed(2) + ' bits/byte    site ' + site);

    /*
     * A key that is printable ASCII almost always came from a String literal in
     * the source ("MySuperSecretKey".getBytes()). A key with low entropy came
     * from something structured. Neither is proof on its own, but together with
     * the same value reappearing on every run they are decisive — a key derived
     * from SecureRandom would differ between installs.
     */
    if (rec.printable) {
        recordFinding('F-01', 'HIGH',
            'key material is entirely printable ASCII ("' + b2a(bytes) + '") — ' +
            'consistent with a hardcoded String literal', site);
        warn('F-01', 'key is printable ASCII — almost certainly a hardcoded constant. ' +
             'Confirm by grepping the DEX string pool for: ' + b2a(bytes));
    } else if (rec.entropy < 3.5 && bytes.length >= 16) {
        warn('F-01', 'key entropy is only ' + rec.entropy.toFixed(2) +
             ' bits/byte — not the output of SecureRandom. Trace its construction.');
    }

    if (isAllZero(bytes)) {
        crit('F-01', 'key is ALL ZERO BYTES. Everything encrypted under it is public.');
    }

    if (bytes.length < 16 && alg && alg.toUpperCase().indexOf('AES') !== -1) {
        warn('F-01', 'AES key is only ' + (bytes.length * 8) + ' bits — the JCA will ' +
             'reject anything that is not 16/24/32 bytes, so check what is really happening.');
    }
}

function noteIv(bytes, context) {
    if (bytes === null || bytes.length === 0) return null;
    var hex = b2hCompact(bytes);
    STATE.ivs[hex] = (STATE.ivs[hex] || 0) + 1;

    log('    iv/nonce (' + bytes.length + 'B) ' + b2h(bytes) + '   [' + context + ']');

    if (isAllZero(bytes)) {
        warn('F-03', 'IV/nonce is ALL ZERO. Encryption is deterministic: identical ' +
             'plaintexts produce identical ciphertexts.');
        recordFinding('F-03', 'MEDIUM', 'all-zero IV in ' + context);
    } else if (isPrintable(bytes)) {
        warn('F-03', 'IV/nonce is printable ASCII ("' + b2a(bytes) + '") — a constant, ' +
             'not a random value.');
        recordFinding('F-03', 'MEDIUM', 'ASCII-constant IV in ' + context);
    } else if (STATE.ivs[hex] === 2) {
        warn('F-03', 'IV/nonce repeated (seen ' + STATE.ivs[hex] + ' times): ' + hex);
        recordFinding('F-03', 'MEDIUM', 'repeated IV ' + hex + ' in ' + context);
    }
    return hex;
}

/*
 * The nonce-reuse detector. For GCM and CTR, repeating a (key, nonce) pair is not
 * a weakness — it is a break. For GCM it additionally leaks the authentication
 * subkey H, which lets an attacker forge tags for *arbitrary* messages under that
 * key, forever. See ../README.md section 3.3.5.
 */
function checkNonceReuse(keyHex, ivHex, transformation) {
    if (!keyHex || !ivHex) return;
    var up = (transformation || '').toUpperCase();
    var streamish = up.indexOf('GCM') !== -1 || up.indexOf('CTR') !== -1 ||
                    up.indexOf('CHACHA') !== -1 || up.indexOf('CCM') !== -1;
    var pair = keyHex + '|' + ivHex;
    STATE.keyIvPairs[pair] = (STATE.keyIvPairs[pair] || 0) + 1;

    if (STATE.keyIvPairs[pair] > 1 && streamish) {
        crit('F-04', 'NONCE REUSE under ' + transformation + '. Same (key, nonce) used ' +
             STATE.keyIvPairs[pair] + ' times. nonce=' + ivHex.substring(0, 24) +
             '  key=…' + keyHex.substring(keyHex.length - 8));
        console.error('      Consequence: XOR of the two plaintexts is recoverable, and for ' +
                      'GCM the authentication subkey H is recoverable, enabling universal forgery.');
        recordFinding('F-04', 'CRITICAL',
            'GCM/CTR nonce reuse: nonce ' + ivHex + ' used ' + STATE.keyIvPairs[pair] +
            ' times under the same key');
    }
}

/* ============================================================ hook installers */

var INSTALLED = 0;
var FAILED = [];

function group(name, fn) {
    try {
        fn();
        INSTALLED++;
    } catch (e) {
        FAILED.push(name + ': ' + e);
    }
}

/*
 * safeUse — resolve a class without throwing. Classes come and go across API
 * levels (GCMParameterSpec is API 19+, ChaCha20ParameterSpec is API 28+), and an
 * app may not have loaded the class that declares a hook target yet. Returning
 * null and skipping is always better than aborting the whole script.
 */
function safeUse(name) {
    try {
        return Java.use(name);
    } catch (e) {
        return null;
    }
}

/* Replace every overload of a method, with per-overload isolation. */
function hookAll(clazz, methodName, before, after) {
    if (clazz === null) return 0;
    var member;
    try {
        member = clazz[methodName];
    } catch (e) { return 0; }
    if (member === undefined || member === null) return 0;

    var overloads;
    try {
        overloads = member.overloads || [member];
    } catch (e) { return 0; }

    var n = 0;
    overloads.forEach(function (ov) {
        try {
            ov.implementation = function () {
                var args = arguments;
                var ctx = {};
                if (before) {
                    try { before.call(this, args, ctx); } catch (e) {
                        console.log('[-] hook(before) ' + methodName + ': ' + e);
                    }
                }
                var ret = ov.apply(this, args);
                if (after) {
                    try { after.call(this, args, ret, ctx); } catch (e) {
                        console.log('[-] hook(after) ' + methodName + ': ' + e);
                    }
                }
                return ret;
            };
            n++;
        } catch (e) { /* this overload cannot be replaced; keep the others */ }
    });
    return n;
}

/* ================================================================== the hooks */

function installAll() {

    /* ---------------------------------------------------- 1. Cipher.getInstance */
    group('Cipher.getInstance', function () {
        var Cipher = Java.use('javax.crypto.Cipher');
        hookAll(Cipher, 'getInstance', null, function (args, ret) {
            if (!stackMentionsFilter()) return;
            var t = args[0] ? args[0].toString() : '<null>';
            STATE.transformations[t] = (STATE.transformations[t] || 0) + 1;

            var provider = '';
            try { provider = ' provider=' + ret.getProvider().getName(); } catch (e) {}

            var judgements = judgeTransformation(t);
            var flag = '';
            for (var i = 0; i < judgements.length; i++) {
                if (judgements[i].sev === 'HIGH' || judgements[i].sev === 'CRITICAL') {
                    flag = '   <-- ' + judgements[i].id + '!';
                    break;
                }
            }
            if (!CONFIG.warnOnly || flag) {
                log('\n[+] Cipher.getInstance("' + t + '")' + provider + flag);
            }
            judgements.forEach(function (j) {
                if (j.sev === 'INFO') { log('    note ' + j.id + ': ' + j.msg); return; }
                warn(j.id, j.msg);
                recordFinding(j.id, j.sev, j.msg);
            });
            printStack('      ');
        });
    });

    /* ------------------------------------------------------------ 2. Cipher.init */
    group('Cipher.init', function () {
        var Cipher = Java.use('javax.crypto.Cipher');
        var OPMODE = { 1: 'ENCRYPT_MODE', 2: 'DECRYPT_MODE', 3: 'WRAP_MODE', 4: 'UNWRAP_MODE' };

        hookAll(Cipher, 'init', function (args) {
            if (!stackMentionsFilter()) return;

            var opmode = args.length > 0 ? args[0] : -1;
            var transformation = '<unknown>';
            try { transformation = this.getAlgorithm(); } catch (e) {}

            var keyHex = null, ivHex = null, keyBytes = null;

            // args[1] is normally the Key. Read its encoded form if the provider
            // allows it — AndroidKeyStore keys deliberately return null here, and
            // that null is itself the most useful single fact in the output.
            var keyDesc = '<none>';
            if (args.length > 1 && args[1] !== null && args[1] !== undefined) {
                var key = args[1];
                try {
                    var cls = key.$className || '?';
                    var enc = null;
                    try { enc = key.getEncoded(); } catch (e) { enc = null; }
                    if (enc === null) {
                        keyDesc = '<' + cls + '  getEncoded()=null — NON-EXPORTABLE, ' +
                                  'almost certainly AndroidKeyStore/TEE>';
                    } else {
                        keyBytes = toJsBytes(enc);
                        keyHex = b2hCompact(keyBytes);
                        var kalg = '?';
                        try { kalg = key.getAlgorithm(); } catch (e) {}
                        keyDesc = '<' + cls + ' ' + kalg + ' ' + keyBytes.length + 'B>';
                    }
                } catch (e) {
                    keyDesc = '<unreadable key: ' + e + '>';
                }
            }

            // args[2] may be an AlgorithmParameterSpec (IvParameterSpec,
            // GCMParameterSpec, …) or an AlgorithmParameters, or a SecureRandom.
            var paramDesc = 'null';
            if (args.length > 2 && args[2] !== null && args[2] !== undefined) {
                paramDesc = describeParams(args[2]);
            }

            log('\n[+] Cipher.init(' + (OPMODE[opmode] || opmode) + ')  transformation=' +
                transformation + '  key=' + keyDesc + '  params=' + paramDesc.summary);

            if (keyBytes !== null) {
                log('    key hex   ' + b2h(keyBytes));
                log('    key ascii ' + b2a(keyBytes));
                noteKey(keyBytes, transformation, 'Cipher.init');
            }
            if (paramDesc.ivBytes !== null) {
                ivHex = noteIv(paramDesc.ivBytes, 'Cipher.init/' + transformation);
            }

            // The provider generates the IV when the caller passes none on encrypt.
            // That is the *correct* pattern, so say so — a tester who cannot tell
            // good code from bad code is not useful to a client.
            if (paramDesc.ivBytes === null && opmode === 1) {
                try {
                    var gen = this.getIV();
                    if (gen !== null) {
                        var g = toJsBytes(gen);
                        log('    provider-generated IV (' + g.length + 'B) ' + b2h(g) +
                            '   [good: fresh per call]');
                        ivHex = b2hCompact(g);
                        STATE.ivs[ivHex] = (STATE.ivs[ivHex] || 0) + 1;
                    }
                } catch (e) { /* not available before doFinal on some providers */ }
            }

            if (keyHex && ivHex) checkNonceReuse(keyHex, ivHex, transformation);

            STATE.ciphers[idOf(this)] = {
                transformation: transformation,
                opmode: opmode,
                keyHex: keyHex,
                ivHex: ivHex
            };

            printStack('      ');
        });
    });

    /* --------------------------------------------------------- 3. Cipher.doFinal */
    group('Cipher.doFinal', function () {
        var Cipher = Java.use('javax.crypto.Cipher');

        hookAll(Cipher, 'doFinal', function (args, ctx) {
            ctx.show = stackMentionsFilter();
            ctx.st = STATE.ciphers[idOf(this)] || {};
            ctx.input = (args.length > 0 && args[0] !== null &&
                         typeof args[0] === 'object' && args[0].length !== undefined)
                        ? toJsBytes(args[0]) : null;
        }, function (args, ret, ctx) {
            if (!ctx.show) return;
            COUNTS.ops++;

            var st = ctx.st;
            var enc = (st.opmode === 1 || st.opmode === 3);
            var dir = enc ? 'ENCRYPT' : (st.opmode === 2 ? 'DECRYPT' : 'op=' + st.opmode);
            var out = null;
            try {
                if (ret !== null && typeof ret === 'object' && ret.length !== undefined) {
                    out = toJsBytes(ret);
                }
            } catch (e) {}

            log('[+] Cipher.doFinal  ' + dir + '  ' + (st.transformation || '?') +
                '  in=' + (ctx.input ? ctx.input.length : 0) + 'B' +
                '  out=' + (out ? out.length : 0) + 'B');

            if (ctx.input !== null) {
                log('    in  hex   ' + b2h(ctx.input));
                log('    in  ascii ' + b2a(ctx.input));
            }
            if (out !== null) {
                log('    out hex   ' + b2h(out));
                log('    out ascii ' + b2a(out));
            }

            // The plaintext is whichever side is not the ciphertext.
            var plaintext = enc ? ctx.input : out;
            if (plaintext !== null && plaintext.length > 0) {
                dumpToFile('plaintext', plaintext);
                sniffPayload(plaintext);
            }
            var ciphertext = enc ? out : ctx.input;
            if (ciphertext !== null) {
                dumpToFile('ciphertext', ciphertext);
                checkEcbInCiphertext(ciphertext, st.transformation);
            }
            printStack('      ');
        });
    });

    /* ------------------------------------------------------ 4. Cipher.update(AAD) */
    group('Cipher.updateAAD', function () {
        var Cipher = Java.use('javax.crypto.Cipher');
        hookAll(Cipher, 'updateAAD', function (args) {
            if (!stackMentionsFilter()) return;
            if (args.length > 0 && args[0] !== null && args[0].length !== undefined) {
                var aad = toJsBytes(args[0]);
                log('    AAD (' + aad.length + 'B) ' + b2a(aad));
                log('        hex ' + b2h(aad));
            }
        });
    });

    group('Cipher.update', function () {
        var Cipher = Java.use('javax.crypto.Cipher');
        hookAll(Cipher, 'update', function (args, ctx) {
            ctx.show = stackMentionsFilter();
        }, function (args, ret, ctx) {
            if (!ctx.show) return;
            if (args.length > 0 && args[0] !== null && args[0].length !== undefined) {
                var inp = toJsBytes(args[0]);
                log('[.] Cipher.update  in=' + inp.length + 'B  ' + b2a(inp, 64));
            }
        });
    });

    /* ------------------------------------------------------- 5. Cipher.wrap/unwrap */
    group('Cipher.wrap/unwrap', function () {
        var Cipher = Java.use('javax.crypto.Cipher');
        hookAll(Cipher, 'wrap', function (args) {
            if (!stackMentionsFilter()) return;
            log('[+] Cipher.wrap — a key is being wrapped (envelope encryption). ' +
                'Find out where the wrapped blob is stored: F-13 lives here.');
            try {
                var k = args[0];
                var enc = k.getEncoded();
                if (enc !== null) noteKey(toJsBytes(enc), k.getAlgorithm(), 'Cipher.wrap');
            } catch (e) {}
        });
        hookAll(Cipher, 'unwrap', null, function (args, ret) {
            if (!stackMentionsFilter()) return;
            try {
                var enc = ret.getEncoded();
                if (enc !== null) noteKey(toJsBytes(enc), ret.getAlgorithm(), 'Cipher.unwrap');
                else log('[+] Cipher.unwrap -> non-exportable key (good)');
            } catch (e) {}
        });
    });

    /* ------------------------------------------------------- 6. SecretKeySpec ctor */
    /*
     * The single highest-value hook in the file. Every software symmetric key an
     * app uses passes through this constructor, whatever the app calls its own
     * classes, and whatever obfuscator was applied.
     */
    group('SecretKeySpec.<init>', function () {
        var SKS = Java.use('javax.crypto.spec.SecretKeySpec');
        hookAll(SKS, '$init', function (args) {
            if (!stackMentionsFilter()) return;
            var bytes = null, alg = '?';
            try {
                if (args.length >= 2 && args[0] !== null && args[0].length !== undefined) {
                    if (args.length === 2) {              // (byte[], String)
                        bytes = toJsBytes(args[0]);
                        alg = args[1].toString();
                    } else if (args.length === 4) {       // (byte[], int off, int len, String)
                        var whole = toJsBytes(args[0]);
                        var off = args[1], len = args[2];
                        bytes = whole.slice(off, off + len);
                        alg = args[3].toString();
                    }
                }
            } catch (e) { /* unexpected overload shape */ }

            if (bytes !== null) {
                log('\n[+] new SecretKeySpec(alg=' + alg + ', len=' + bytes.length + ')');
                noteKey(bytes, alg, 'SecretKeySpec.<init>');
                printStack('      ');
            }
        });
    });

    /* ---------------------------------------------------- 7. IvParameterSpec ctor */
    group('IvParameterSpec.<init>', function () {
        var IPS = Java.use('javax.crypto.spec.IvParameterSpec');
        hookAll(IPS, '$init', function (args) {
            if (!stackMentionsFilter()) return;
            var bytes = null;
            try {
                if (args.length >= 1 && args[0] !== null && args[0].length !== undefined) {
                    if (args.length === 1) bytes = toJsBytes(args[0]);
                    else if (args.length === 3) {
                        bytes = toJsBytes(args[0]).slice(args[1], args[1] + args[2]);
                    }
                }
            } catch (e) {}
            if (bytes !== null) {
                log('\n[+] new IvParameterSpec(' + bytes.length + ' bytes)');
                noteIv(bytes, 'IvParameterSpec.<init>');
                printStack('      ');
            }
        });
    });

    /* --------------------------------------------------- 8. GCMParameterSpec ctor */
    group('GCMParameterSpec.<init>', function () {
        var GCM = safeUse('javax.crypto.spec.GCMParameterSpec');
        if (GCM === null) return;                       // API < 19
        hookAll(GCM, '$init', function (args) {
            if (!stackMentionsFilter()) return;
            var tLen = args.length > 0 ? args[0] : -1;
            var iv = null;
            try {
                if (args.length >= 2 && args[1] !== null && args[1].length !== undefined) {
                    iv = (args.length === 2) ? toJsBytes(args[1])
                                             : toJsBytes(args[1]).slice(args[2], args[2] + args[3]);
                }
            } catch (e) {}

            log('\n[+] new GCMParameterSpec(tagBits=' + tLen + ', ivLen=' +
                (iv ? iv.length : '?') + ')');

            /*
             * The API takes the tag length in BITS. Passing 16 (meaning "16 bytes")
             * is a real and recurring bug: it asks for a 16-bit tag, so an attacker
             * forges a valid message in about 2^15 attempts.
             */
            if (tLen < 96) {
                crit('F-12', 'GCM tag length is ' + tLen + ' BITS. Below 96 bits this is ' +
                     'forgeable; a value like 16 usually means the developer confused ' +
                     'bits with bytes. Use 128.');
                recordFinding('F-12', 'HIGH', 'GCM tag length ' + tLen + ' bits');
            } else if (tLen < 128) {
                warn('F-12', 'GCM tag length ' + tLen + ' bits — 128 is the standard choice.');
            }

            if (iv !== null) {
                if (iv.length !== 12) {
                    log('    note: nonce is ' + iv.length + ' bytes. GCM is specified for ' +
                        '12; other lengths are hashed through GHASH first, which is legal ' +
                        'but slower and more error-prone (NIST SP 800-38D §8.2).');
                }
                noteIv(iv, 'GCMParameterSpec');
            }
            printStack('      ');
        });
    });

    /* ----------------------------------------------------- 9. PBEKeySpec ctor ---- */
    group('PBEKeySpec.<init>', function () {
        var PBE = Java.use('javax.crypto.spec.PBEKeySpec');
        hookAll(PBE, '$init', function (args) {
            if (!stackMentionsFilter()) return;
            try {
                if (args.length < 3) {
                    log('\n[+] new PBEKeySpec(password only) — no salt, no iteration count. ' +
                        'The defaults come from the SecretKeyFactory and are usually weak.');
                    return;
                }
                var pw = '';
                if (args[0] !== null && args[0].length !== undefined) {
                    for (var i = 0; i < args[0].length; i++) pw += String.fromCharCode(args[0][i]);
                }
                var salt = toJsBytes(args[1]);
                var iter = args[2];
                var bits = args.length > 3 ? args[3] : '?';

                log('\n[+] new PBEKeySpec  password="' + pw + '"  saltLen=' +
                    (salt ? salt.length : 0) + '  iterations=' + iter + '  keyBits=' + bits);
                if (salt) log('    salt hex ' + b2h(salt));

                if (iter < 100000) {
                    warn('', 'PBKDF2 iteration count ' + iter + ' is far below the ' +
                         'current recommendation (600,000 for PBKDF2-HMAC-SHA256, ' +
                         'OWASP Password Storage Cheat Sheet).');
                    recordFinding('F-05', 'MEDIUM', 'PBKDF2 iterations = ' + iter);
                }
                if (iter <= 1000) {
                    crit('F-05', 'PBKDF2 iteration count ' + iter + ' provides essentially ' +
                         'no protection: a GPU tries billions of candidates per second.');
                }
                if (salt === null || salt.length === 0) {
                    crit('F-05', 'PBKDF2 with an EMPTY SALT — rainbow tables apply and the ' +
                         'same password yields the same key on every device.');
                } else if (salt.length < 8) {
                    warn('F-05', 'PBKDF2 salt is only ' + salt.length + ' bytes; RFC 8018 ' +
                         'specifies at least 8, and 16 is the practical minimum.');
                } else if (isPrintable(salt)) {
                    warn('F-05', 'PBKDF2 salt is printable ASCII ("' + b2a(salt) +
                         '") — a constant salt is equivalent to no salt across devices.');
                }
                printStack('      ');
            } catch (e) { /* unusual overload */ }
        });
    });

    /* ----------------------------------------------------- 10. SecretKeyFactory --- */
    group('SecretKeyFactory', function () {
        var SKF = Java.use('javax.crypto.SecretKeyFactory');
        hookAll(SKF, 'getInstance', null, function (args, ret) {
            if (!stackMentionsFilter()) return;
            var alg = args[0] ? args[0].toString() : '?';
            log('[+] SecretKeyFactory.getInstance("' + alg + '")');
            var up = alg.toUpperCase();
            if (up.indexOf('PBKDF2') !== -1 && up.indexOf('SHA1') !== -1) {
                warn('', 'PBKDF2WithHmacSHA1 is still acceptable but SHA-256 is the ' +
                     'current choice; note it and move on. Not a finding by itself.');
            }
            if (up.indexOf('PBEWITHMD5') !== -1 || up.indexOf('PBEWITHSHA1AND') !== -1) {
                warn('F-07', 'legacy PKCS#12 PBE algorithm "' + alg + '" — low iteration ' +
                     'defaults and obsolete primitives.');
            }
        });
        hookAll(SKF, 'generateSecret', null, function (args, ret) {
            if (!stackMentionsFilter()) return;
            try {
                var enc = ret.getEncoded();
                if (enc !== null) {
                    var b = toJsBytes(enc);
                    log('[+] SecretKeyFactory.generateSecret -> ' + b.length + ' bytes');
                    noteKey(b, ret.getAlgorithm(), 'SecretKeyFactory.generateSecret');
                }
            } catch (e) {}
        });
    });

    /* ------------------------------------------------------- 11. KeyGenerator ---- */
    group('KeyGenerator', function () {
        var KG = Java.use('javax.crypto.KeyGenerator');
        hookAll(KG, 'getInstance', null, function (args, ret) {
            if (!stackMentionsFilter()) return;
            var alg = args[0] ? args[0].toString() : '?';
            var prov = (args.length > 1 && args[1]) ? ' provider=' + args[1].toString() : '';
            log('[+] KeyGenerator.getInstance("' + alg + '")' + prov);
            if (prov.indexOf('AndroidKeyStore') !== -1) {
                log('    -> AndroidKeyStore: the key will be generated inside the ' +
                    'keystore daemon / TEE and will never enter this process. Good sign.');
            }
        });
        hookAll(KG, 'init', function (args) {
            if (!stackMentionsFilter()) return;
            var desc = [];
            for (var i = 0; i < args.length; i++) {
                try {
                    if (args[i] === null) { desc.push('null'); continue; }
                    if (typeof args[i] === 'number') { desc.push(args[i]); continue; }
                    desc.push(args[i].$className || ('' + args[i]));
                } catch (e) { desc.push('?'); }
            }
            log('[+] KeyGenerator.init(' + desc.join(', ') + ')');
            if (typeof args[0] === 'number' && args[0] < 128) {
                warn('', 'key size ' + args[0] + ' bits requested.');
            }
            // A SecureRandom passed with an explicit seed is the classic F-05 route.
            for (var j = 0; j < args.length; j++) {
                try {
                    var cn = args[j] && args[j].$className;
                    if (cn === 'java.security.SecureRandom') {
                        log('    a SecureRandom instance was supplied explicitly — check ' +
                            'whether setSeed() was called on it (see the Random hooks).');
                    }
                } catch (e) {}
            }
        });
        hookAll(KG, 'generateKey', null, function (args, ret) {
            if (!stackMentionsFilter()) return;
            try {
                var enc = ret.getEncoded();
                if (enc === null) {
                    log('[+] KeyGenerator.generateKey -> non-exportable key ' +
                        '(getEncoded()==null). Hardware- or keystore-backed.');
                } else {
                    var b = toJsBytes(enc);
                    log('[+] KeyGenerator.generateKey -> ' + b.length + ' bytes (software key)');
                    noteKey(b, ret.getAlgorithm(), 'KeyGenerator.generateKey');
                }
            } catch (e) {}
        });
    });

    /* ------------------------------------------------------ 12. KeyPairGenerator - */
    group('KeyPairGenerator', function () {
        var KPG = Java.use('java.security.KeyPairGenerator');
        hookAll(KPG, 'getInstance', null, function (args) {
            if (!stackMentionsFilter()) return;
            log('[+] KeyPairGenerator.getInstance("' + args[0] + '")');
        });
        hookAll(KPG, 'initialize', function (args) {
            if (!stackMentionsFilter()) return;
            if (typeof args[0] === 'number') {
                log('[+] KeyPairGenerator.initialize(' + args[0] + ')');
                if (args[0] < 2048) {
                    warn('F-14', 'asymmetric key size ' + args[0] + ' bits is below the ' +
                         '2048-bit RSA minimum (NIST SP 800-131A).');
                }
            } else {
                var cn = '?';
                try { cn = args[0].$className; } catch (e) {}
                log('[+] KeyPairGenerator.initialize(' + cn + ')');
            }
        });
    });

    /* ------------------------------------------------------- 13. MessageDigest --- */
    group('MessageDigest', function () {
        var MD = Java.use('java.security.MessageDigest');
        hookAll(MD, 'getInstance', null, function (args) {
            if (!stackMentionsFilter()) return;
            var alg = args[0] ? args[0].toString() : '?';
            STATE.digests[alg] = (STATE.digests[alg] || 0) + 1;
            var j = judgeDigest(alg);
            log('[+] MessageDigest.getInstance("' + alg + '")' + (j ? '   <-- weak' : ''));
            if (j) {
                warn(j.id, j.msg);
                recordFinding(j.id, j.sev, alg + ' in use');
                printStack('      ');
            }
        });
        hookAll(MD, 'digest', function (args, ctx) {
            ctx.show = stackMentionsFilter();
            ctx.alg = '?';
            try { ctx.alg = this.getAlgorithm(); } catch (e) {}
            ctx.input = (args.length > 0 && args[0] !== null && args[0].length !== undefined)
                        ? toJsBytes(args[0]) : null;
        }, function (args, ret, ctx) {
            if (!ctx.show) return;
            var out = null;
            try {
                if (ret !== null && ret.length !== undefined) out = toJsBytes(ret);
            } catch (e) {}
            log('[+] MessageDigest(' + ctx.alg + ').digest' +
                (ctx.input ? ' in=' + ctx.input.length + 'B' : ''));
            if (ctx.input) {
                log('    in  ascii ' + b2a(ctx.input));
                log('    in  hex   ' + b2h(ctx.input));
            }
            if (out) log('    out hex   ' + b2h(out));

            /*
             * A digest whose output is 16 or 32 bytes and is fed straight into a
             * SecretKeySpec is the "hash as a KDF" pattern (F-05). We cannot see
             * the consumer from here, so record the digest and let jca.report()
             * correlate it against the keys we captured.
             */
            if (out && (out.length === 16 || out.length === 32)) {
                var hex = b2hCompact(out);
                if (STATE.keys[hex] !== undefined) {
                    crit('F-05', 'the output of ' + ctx.alg + '() is being used directly ' +
                         'as an encryption key. A hash is not a KDF: it is fast, unsalted ' +
                         'and offers no work factor, so the input is brute-forceable.');
                }
            }
        });
        hookAll(MD, 'isEqual', null, function (args, ret) {
            if (!stackMentionsFilter()) return;
            log('[.] MessageDigest.isEqual -> ' + ret + '   [good: constant-time comparison]');
        });
    });

    /* ------------------------------------------------------------------ 14. Mac -- */
    group('Mac', function () {
        var Mac = Java.use('javax.crypto.Mac');
        hookAll(Mac, 'getInstance', null, function (args) {
            if (!stackMentionsFilter()) return;
            var alg = args[0] ? args[0].toString() : '?';
            STATE.macs[alg] = (STATE.macs[alg] || 0) + 1;
            log('[+] Mac.getInstance("' + alg + '")');
            var up = alg.toUpperCase();
            if (up.indexOf('MD5') !== -1) {
                warn('F-07', 'HmacMD5 — HMAC is still secure with MD5 in theory, but its ' +
                     'presence signals a codebase that has not been reviewed. Report as ' +
                     'Low/Informational unless something else depends on it.');
            }
        });
        hookAll(Mac, 'init', function (args) {
            if (!stackMentionsFilter()) return;
            try {
                var enc = args[0].getEncoded();
                if (enc !== null) {
                    var b = toJsBytes(enc);
                    log('[+] Mac.init  key=' + b.length + 'B');
                    noteKey(b, 'HMAC', 'Mac.init');
                } else {
                    log('[+] Mac.init  key=<non-exportable>');
                }
            } catch (e) {}
        });
        hookAll(Mac, 'doFinal', function (args, ctx) {
            ctx.show = stackMentionsFilter();
            ctx.input = (args.length > 0 && args[0] !== null && args[0].length !== undefined)
                        ? toJsBytes(args[0]) : null;
            ctx.alg = '?';
            try { ctx.alg = this.getAlgorithm(); } catch (e) {}
        }, function (args, ret, ctx) {
            if (!ctx.show) return;
            log('[+] Mac(' + ctx.alg + ').doFinal');
            if (ctx.input) log('    msg   ' + b2a(ctx.input));
            try {
                if (ret !== null && ret.length !== undefined) {
                    log('    tag   ' + b2h(toJsBytes(ret)));
                }
            } catch (e) {}
        });
    });

    /* ------------------------------------------------------------ 15. Signature -- */
    group('Signature', function () {
        var Sig = Java.use('java.security.Signature');
        hookAll(Sig, 'getInstance', null, function (args) {
            if (!stackMentionsFilter()) return;
            var alg = args[0] ? args[0].toString() : '?';
            log('[+] Signature.getInstance("' + alg + '")');
            var up = alg.toUpperCase();
            if (up.indexOf('MD5') !== -1 || up.indexOf('SHA1WITH') !== -1) {
                warn('F-07', 'signature algorithm "' + alg + '" uses a collision-broken ' +
                     'hash. Collisions break signatures directly (SHAttered, 2017).');
                recordFinding('F-07', 'HIGH', 'weak signature algorithm ' + alg);
            }
        });
        hookAll(Sig, 'verify', null, function (args, ret) {
            if (!stackMentionsFilter()) return;
            log('[+] Signature.verify -> ' + ret + '    site ' + callerFrame());
            if (ret === false) {
                log('    a failed verification here is the interesting one: check whether ' +
                    'the app actually acts on the result.');
            }
        });
    });

    /* ------------------------------------------------- 16. java.util.Random (F-06) */
    /*
     * java.util.Random is a 48-bit linear congruential generator. Observing two
     * consecutive outputs is enough to recover its internal state and predict
     * every subsequent value. Any use of it for a key, IV, nonce, token, session
     * identifier, OTP or password-reset code is a finding.
     */
    group('java.util.Random (F-06)', function () {
        var R = Java.use('java.util.Random');
        hookAll(R, '$init', function (args) {
            if (!stackMentionsFilter()) return;
            var seeded = args.length > 0 ? ' seed=' + args[0] : ' (time-seeded)';
            warn('F-06', 'new java.util.Random(' + (args.length ? args[0] : '') + ')' +
                 seeded + ' at ' + callerFrame());
            recordFinding('F-06', 'HIGH', 'java.util.Random instantiated' + seeded);
            printStack('      ');
        });
        hookAll(R, 'nextBytes', function (args, ctx) {
            ctx.show = stackMentionsFilter();
        }, function (args, ret, ctx) {
            if (!ctx.show) return;
            try {
                if (args[0] !== null && args[0].length !== undefined) {
                    var b = toJsBytes(args[0]);
                    crit('F-06', 'java.util.Random.nextBytes() filled ' + b.length +
                         ' bytes: ' + b2h(b, 32));
                    console.error('      java.util.Random is a 48-bit LCG. Two outputs ' +
                                  'reveal the state; all future output is predictable.');
                    console.error('      site: ' + callerFrame());
                }
            } catch (e) {}
        });
    });

    /* ------------------------------------------- 17. SecureRandom.setSeed (F-05) - */
    group('SecureRandom', function () {
        var SR = Java.use('java.security.SecureRandom');
        hookAll(SR, 'getInstance', null, function (args) {
            if (!stackMentionsFilter()) return;
            var alg = args[0] ? args[0].toString() : '?';
            log('[+] SecureRandom.getInstance("' + alg + '")');
            if (alg.toUpperCase() === 'SHA1PRNG') {
                warn('F-05', 'SecureRandom.getInstance("SHA1PRNG") is the signature of the ' +
                     'deterministic-key anti-pattern: setSeed(secret) then nextBytes() to ' +
                     '"derive" a key. On Android 7+ setSeed no longer replaces the seed, so ' +
                     'this code silently produces DIFFERENT keys across versions.');
                recordFinding('F-05', 'HIGH', 'SHA1PRNG used');
                printStack('      ');
            }
        });
        hookAll(SR, 'setSeed', function (args) {
            if (!stackMentionsFilter()) return;
            var d = '?';
            try {
                if (typeof args[0] === 'number') d = 'long ' + args[0];
                else if (args[0] !== null && args[0].length !== undefined) {
                    d = b2h(toJsBytes(args[0]), 32);
                }
            } catch (e) {}
            crit('F-05', 'SecureRandom.setSeed(' + d + ') — supplying a seed to derive ' +
                 'deterministic "keys". The output is only as unpredictable as the seed.');
            printStack('      ');
        });
    });

    /* ------------------------------------------------------------ 18. KeyStore --- */
    group('KeyStore', function () {
        var KS = Java.use('java.security.KeyStore');
        hookAll(KS, 'getInstance', null, function (args) {
            if (!stackMentionsFilter()) return;
            var type = args[0] ? args[0].toString() : '?';
            log('[+] KeyStore.getInstance("' + type + '")');
            if (type === 'AndroidKeyStore') {
                log('    the app uses the platform keystore. Shift your attention from ' +
                    '"can I extract the key" to "can I make the app use the key for me" ' +
                    '— see ../../49-KeyStore/README.md.');
            }
        });
        hookAll(KS, 'getKey', null, function (args, ret) {
            if (!stackMentionsFilter()) return;
            var alias = args.length > 0 && args[0] ? args[0].toString() : '?';
            var exportable = 'unknown';
            try { exportable = (ret.getEncoded() === null) ? 'NO (hardware/keystore)' : 'YES'; }
            catch (e) {}
            log('[+] KeyStore.getKey(alias="' + alias + '")  exportable=' + exportable);
            try {
                var enc = ret.getEncoded();
                if (enc !== null) noteKey(toJsBytes(enc), ret.getAlgorithm(), 'KeyStore.getKey');
            } catch (e) {}
        });
    });

    /* --------------------------------- 19. non-constant-time comparison (F-15) --- */
    /*
     * Arrays.equals returns as soon as it finds a differing byte, so the time it
     * takes leaks how many leading bytes of a MAC the attacker got right. On a
     * local Android app the timing signal is usually too noisy to exploit, which
     * is why this is reported as Low unless the comparison happens server-side or
     * over a channel the attacker can time precisely. Report it honestly.
     */
    group('Arrays.equals (F-15)', function () {
        var A = Java.use('java.util.Arrays');
        var member = A.equals;
        if (member === undefined) return;
        member.overloads.forEach(function (ov) {
            var sig;
            try {
                sig = ov.argumentTypes.map(function (t) { return t.className; }).join(',');
            } catch (e) { return; }
            if (sig !== '[B,[B') return;                     // byte[] only
            ov.implementation = function (a, b) {
                var ret = ov.call(this, a, b);
                if (stackMentionsFilter()) {
                    var site = callerFrame();
                    try {
                        if (a !== null && (a.length === 16 || a.length === 20 ||
                                           a.length === 32 || a.length === 64)) {
                            log('[.] Arrays.equals(byte[' + a.length + ']) -> ' + ret +
                                '   at ' + site);
                            log('    if these are MAC/digest/tag bytes, this comparison is ' +
                                'not constant-time. Use MessageDigest.isEqual. (F-15)');
                        }
                    } catch (e) {}
                }
                return ret;
            };
        });
    });

    /* -------------------------------------------- 20. Base64 as "encryption" ----- */
    group('android.util.Base64', function () {
        var B64 = safeUse('android.util.Base64');
        if (B64 === null) return;
        hookAll(B64, 'encodeToString', function (args, ctx) {
            ctx.show = stackMentionsFilter() && CONFIG.showStacks;
        }, function (args, ret, ctx) {
            if (!ctx.show) return;
            try {
                var b = toJsBytes(args[0]);
                if (b && isPrintable(b) && b.length > 4) {
                    log('[.] Base64.encodeToString("' + b2a(b, 64) + '") — encoding, not ' +
                        'encryption. If this value is stored as a "protected" field, F-10.');
                }
            } catch (e) {}
        });
    });

    /* ---------------------------------- 21. dynamic code loading after decryption  */
    /*
     * The malware case. A dropper decrypts a DEX with Cipher.doFinal and hands it
     * straight to a ClassLoader. Catching the handover proves the two halves belong
     * together and gives you the payload on disk.
     */
    group('DexClassLoader / InMemoryDexClassLoader', function () {
        var installed = 0;
        ['dalvik.system.DexClassLoader',
         'dalvik.system.PathClassLoader',
         'dalvik.system.InMemoryDexClassLoader'].forEach(function (name) {
            var C = safeUse(name);
            if (C === null) return;
            hookAll(C, '$init', function (args) {
                crit('F-16', 'dynamic code loading via ' + name + ' at ' + callerFrame());
                console.error('      If a Cipher.doFinal produced this payload, the app is ' +
                              'decrypting and executing code. Correlate with the last ' +
                              'doFinal output above, and dump it with dumpDir.');
            });
            installed++;
        });
        if (installed === 0) throw new Error('no class loaders resolvable');
    });
}

/* --------------------------------------------- ciphertext-side ECB detection - */

/*
 * ECB is provable from the ciphertext alone, with no access to the code: identical
 * 16-byte plaintext blocks encrypt to identical 16-byte ciphertext blocks. If the
 * app encrypts anything with repetition — a JSON document, a bitmap, padding — the
 * repeats survive. This is the evidence you put in the report, because it does not
 * depend on the reader trusting your reading of obfuscated code.
 */
function checkEcbInCiphertext(bytes, transformation) {
    if (bytes === null || bytes.length < 32) return;
    var seen = {}, repeats = 0;
    var blocks = Math.floor(bytes.length / 16);
    for (var i = 0; i < blocks; i++) {
        var h = b2hCompact(bytes.slice(i * 16, i * 16 + 16));
        if (seen[h]) repeats++;
        seen[h] = true;
    }
    if (repeats > 0) {
        crit('F-02', 'ciphertext contains ' + repeats + ' repeated 16-byte block(s) out of ' +
             blocks + '. That is only possible in ECB (or with a reused keystream). ' +
             'transformation=' + (transformation || 'unknown'));
        recordFinding('F-02', 'HIGH', repeats + ' repeated ciphertext blocks observed');
    }
}

/* ------------------------------------------------- recognise decrypted payloads */

function sniffPayload(bytes) {
    if (bytes === null || bytes.length < 8) return;
    var b = bytes;
    function is(off, arr) {
        for (var i = 0; i < arr.length; i++) {
            if (((b[off + i]) & 0xff) !== arr[i]) return false;
        }
        return true;
    }
    if (is(0, [0x64, 0x65, 0x78, 0x0a])) {
        crit('F-16', 'the decrypted plaintext is a DEX file ("dex\\n" magic, ' +
             bytes.length + ' bytes). This app decrypts and loads code at runtime.');
    } else if (is(0, [0x7f, 0x45, 0x4c, 0x46])) {
        crit('F-16', 'the decrypted plaintext is an ELF binary (' + bytes.length + ' bytes).');
    } else if (is(0, [0x50, 0x4b, 0x03, 0x04])) {
        warn('F-16', 'the decrypted plaintext is a ZIP/APK/JAR (' + bytes.length + ' bytes).');
    } else if (b[0] === 0x7b || b[0] === 0x5b) {
        log('    payload looks like JSON.');
    } else if (isPrintable(bytes.slice(0, Math.min(32, bytes.length)))) {
        log('    payload is printable text.');
    }
}

/* ================================================================== reporting */

var jca = {
    report: function () {
        console.log('\n================= JCA universal hook — summary =================');
        console.log('operations traced : ' + COUNTS.ops);
        console.log('findings raised   : ' + COUNTS.findings);
        if (CONFIG.filterPackage) {
            console.log('suppressed (filter): ' + COUNTS.suppressed);
        }

        console.log('\n-- transformations seen --');
        var t = Object.keys(STATE.transformations);
        if (t.length === 0) console.log('  (none)');
        t.forEach(function (k) {
            var j = judgeTransformation(k);
            var mark = '';
            for (var i = 0; i < j.length; i++) {
                if (j[i].sev === 'HIGH' || j[i].sev === 'CRITICAL') { mark = '  <-- ' + j[i].id; break; }
            }
            console.log('  ' + STATE.transformations[k] + '×  ' + k + mark);
        });

        console.log('\n-- digests seen --');
        var d = Object.keys(STATE.digests);
        if (d.length === 0) console.log('  (none)');
        d.forEach(function (k) {
            console.log('  ' + STATE.digests[k] + '×  ' + k + (judgeDigest(k) ? '  <-- weak' : ''));
        });

        console.log('\n-- MACs seen --');
        var m = Object.keys(STATE.macs);
        if (m.length === 0) console.log('  (none)');
        m.forEach(function (k) { console.log('  ' + STATE.macs[k] + '×  ' + k); });

        jca.keys();

        console.log('\n-- nonce reuse --');
        var reuse = 0;
        Object.keys(STATE.keyIvPairs).forEach(function (p) {
            if (STATE.keyIvPairs[p] > 1) {
                reuse++;
                var parts = p.split('|');
                console.log('  ' + STATE.keyIvPairs[p] + '×  nonce=' + parts[1] +
                            '  key=…' + parts[0].substring(parts[0].length - 8));
            }
        });
        if (reuse === 0) console.log('  (none observed)');

        console.log('\n-- findings --');
        if (STATE.findings.length === 0) console.log('  (none)');
        var byId = {};
        STATE.findings.forEach(function (f) {
            var k = f.id + '|' + f.msg;
            if (byId[k] === undefined) byId[k] = { f: f, n: 0 };
            byId[k].n++;
        });
        Object.keys(byId).forEach(function (k) {
            var e = byId[k];
            console.log('  [' + e.f.id + '] ' + e.f.sev + ' ×' + e.n + '  ' + e.f.msg);
            console.log('        site: ' + e.f.site);
        });
        console.log('================================================================\n');
    },

    keys: function () {
        console.log('\n-- distinct key material recovered --');
        var ks = Object.keys(STATE.keys);
        if (ks.length === 0) { console.log('  (none — the app may use AndroidKeyStore only)'); return; }
        ks.forEach(function (hex) {
            var r = STATE.keys[hex];
            console.log('  ' + r.alg + '  ' + r.len + 'B  used ' + r.count + '×  ' +
                        'entropy=' + r.entropy.toFixed(2) +
                        (r.printable ? '  [PRINTABLE — hardcoded]' : ''));
            console.log('    hex   ' + hex);
            console.log('    ascii ' + b2a(hex.match(/../g).map(function (x) {
                return parseInt(x, 16);
            })));
            r.sites.forEach(function (s) { console.log('    site  ' + s); });
        });
    },

    reset: function () {
        STATE.ciphers = {}; STATE.keys = {}; STATE.ivs = {};
        STATE.keyIvPairs = {}; STATE.transformations = {};
        STATE.digests = {}; STATE.macs = {}; STATE.findings = [];
        COUNTS.ops = 0; COUNTS.findings = 0; COUNTS.suppressed = 0;
        console.log('[*] state cleared');
    },

    config: function () {
        console.log(JSON.stringify(CONFIG, null, 2));
        return CONFIG;
    },

    filter: function (pkg) {
        CONFIG.filterPackage = pkg || null;
        console.log('[*] filterPackage = ' + CONFIG.filterPackage);
    },

    quiet: function (on) {
        CONFIG.quiet = (on === undefined) ? true : !!on;
        console.log('[*] quiet = ' + CONFIG.quiet);
    },

    help: function () {
        console.log([
            '',
            'jca.report()          full summary: algorithms, keys, nonce reuse, findings',
            'jca.keys()            every distinct key recovered, with call sites',
            'jca.reset()           clear accumulated state',
            'jca.config()          show active configuration',
            'jca.filter("com.x")   only trace operations whose stack mentions com.x',
            'jca.quiet(true)       suppress the per-operation trace; keep findings',
            ''
        ].join('\n'));
    }
};

/* ================================================================= bootstrap */

if (!Java.available) {
    console.error('[-] No Java VM in this process. This script targets ART/Dalvik apps.');
} else {
    Java.perform(function () {
        console.log('');
        console.log('=== frida-jca-universal-hook ===');
        try {
            var vm = Java.use('android.os.Build$VERSION');
            console.log('[*] API level ' + vm.SDK_INT.value +
                        '  release ' + vm.RELEASE.value);
        } catch (e) { /* not fatal */ }

        installAll();

        console.log('[*] JCA universal hook loaded. ' + INSTALLED + ' hook groups installed.');
        if (FAILED.length > 0) {
            console.log('[!] ' + FAILED.length + ' group(s) unavailable on this device/API:');
            FAILED.forEach(function (f) { console.log('      ' + f); });
            console.log('    This is normal. Each group is independent; the rest still work.');
        }
        if (CONFIG.filterPackage) {
            console.log('[*] filtering to stacks mentioning "' + CONFIG.filterPackage + '"');
        }
        if (CONFIG.dumpDir) {
            console.log('[*] buffers will be written to ' + CONFIG.dumpDir +
                        ' (create it first: adb shell mkdir -p ' + CONFIG.dumpDir + ')');
        }
        console.log('[*] Type jca.help() for commands. jca.report() when you are done.');
        console.log('');
    });
}

/* Expose for the REPL and for programmatic use from a Python driver. */
rpc.exports = {
    report: function () { jca.report(); },
    keys: function () {
        var out = {};
        Object.keys(STATE.keys).forEach(function (h) {
            out[h] = { alg: STATE.keys[h].alg, len: STATE.keys[h].len,
                       count: STATE.keys[h].count, sites: STATE.keys[h].sites,
                       entropy: STATE.keys[h].entropy };
        });
        return out;
    },
    findings: function () { return STATE.findings; },
    reset: function () { jca.reset(); },
    configure: function (cfg) {
        Object.keys(cfg).forEach(function (k) { CONFIG[k] = cfg[k]; });
        return CONFIG;
    }
};
