/*
 * memory-secret-scanner.js — find keys, tokens and other secrets in process memory.
 *
 * WHAT IT DOES
 *   Scans the target process's address space for material that looks like a
 *   secret, using three complementary strategies:
 *
 *     1. FORMAT DETECTORS.  Byte patterns with unambiguous structure: PEM
 *        headers, PKCS#8/ASN.1 prefixes, JWT prefixes, AWS/Google/Stripe/GitHub
 *        key prefixes, PKCS#12 magic, and common credential substrings.
 *
 *     2. ENTROPY SCAN.  Sliding-window Shannon entropy over anonymous rw- pages,
 *        reporting runs of a chosen length whose entropy exceeds a threshold.
 *        This finds raw AES/HMAC key material that has no recognisable format.
 *
 *     3. JAVA HEAP SCAN.  Java.choose over String, char[], byte[] and the
 *        crypto key classes, which finds secrets that live as managed objects
 *        and therefore never appear as a distinctive byte pattern.
 *
 *   Plus a DIFF mode: snapshot the hits, trigger the operation, snapshot again,
 *   and report what appeared. That is how you attribute a key to an action.
 *
 * WHY IT WORKS
 *   A key that is derived in native code, used, and zeroed may never cross a
 *   hookable API boundary — but between derivation and zeroing it exists as
 *   bytes in a readable page. See ../README.md section 7.6, and
 *   ../../19-Memory/README.md for what the page protections mean.
 *
 * HOW TO RUN
 *   frida -U -f com.example.app -l memory-secret-scanner.js --no-pause
 *
 *   Then from the REPL:
 *     mem.help()
 *     mem.survey()                     // orient: what memory exists?
 *     mem.formats()                    // fast: known key/token formats
 *     mem.entropy(32, 7.0)             // 32-byte runs with entropy > 7.0 bits/byte
 *     mem.java()                       // the managed heap
 *     mem.find("Bearer ")              // a literal string
 *     mem.hex("30 82 ?? ?? 02 01 00")  // a byte pattern with wildcards
 *     mem.snapshot()   ... tap the button in the app ...   mem.diff()
 *     mem.dump("0x7b2c0a1000", 256)    // hexdump around a hit
 *
 * PERFORMANCE
 *   A modern app maps hundreds of megabytes. Scanning all of it synchronously
 *   on the JavaScript thread WILL cause an ANR. Every scan here filters to
 *   anonymous rw- ranges by default and skips ranges above MAX_RANGE_MB.
 *   Widen deliberately, not by accident.
 *
 * AUTHORISED TESTING ONLY.
 */

'use strict';

var mem = {

    /* ------------------------------------------------------------ config */

    MAX_RANGE_MB: 64,          // skip ranges larger than this
    CONTEXT_BYTES: 64,         // bytes shown around a hit
    _lastHits: null,

    /* ------------------------------------------------------- range picking */

    /*
     * The default target set: anonymous, readable-writable, not executable,
     * not too large. That is the native heap, thread stacks, BSS and JNI
     * buffers — where a live secret actually is. File-backed ranges are
     * excluded because their contents came from disk and you can read the file
     * directly instead.
     */
    ranges: function (opts) {
        opts = opts || {};
        var prot = opts.protection || 'rw-';
        var includeFileBacked = opts.fileBacked === true;
        var maxBytes = (opts.maxMB || this.MAX_RANGE_MB) * 1024 * 1024;

        var all;
        try {
            all = Process.enumerateRanges(prot);
        } catch (e) {
            console.log('[-] enumerateRanges failed: ' + e.message);
            return [];
        }

        return all.filter(function (r) {
            if (!includeFileBacked && r.file !== null && r.file !== undefined) return false;
            if (r.size > maxBytes) return false;
            if (r.size === 0) return false;
            return true;
        });
    },

    survey: function () {
        var all = Process.enumerateRanges('r--');
        var byKind = {};
        var totalAll = 0;

        all.forEach(function (r) {
            totalAll += r.size;
            var kind;
            if (r.file) {
                kind = r.file.path;
                // Collapse the long /data/app/~~rand paths.
                var parts = kind.split('/');
                kind = parts[parts.length - 1];
            } else {
                kind = '<anonymous ' + r.protection + '>';
            }
            byKind[kind] = (byKind[kind] || 0) + r.size;
        });

        var rows = Object.keys(byKind).map(function (k) { return [k, byKind[k]]; });
        rows.sort(function (a, b) { return b[1] - a[1]; });

        console.log('\n[*] Address-space survey — ' + all.length + ' readable ranges, ' +
                    (totalAll / 1048576 | 0) + ' MiB total');
        console.log('    (top 25 by size)');
        rows.slice(0, 25).forEach(function (r) {
            console.log(('          ' + (r[1] / 1024 | 0)).slice(-12) + ' KiB  ' + r[0]);
        });

        var targets = this.ranges();
        var tBytes = targets.reduce(function (s, r) { return s + r.size; }, 0);
        console.log('\n[*] Default scan target: ' + targets.length +
                    ' anonymous rw- ranges, ' + (tBytes / 1048576 | 0) + ' MiB');
        console.log('    A scan of this set takes roughly ' +
                    Math.max(1, (tBytes / 1048576 / 20) | 0) + '-' +
                    Math.max(2, (tBytes / 1048576 / 5) | 0) + ' seconds.\n');

        // rwx ranges deserve a callout: they are the JIT code cache, some
        // packers, and injected shellcode.
        var rwx = Process.enumerateRanges('rwx');
        if (rwx.length > 0) {
            console.log('[!] ' + rwx.length + ' rwx range(s) present:');
            rwx.slice(0, 10).forEach(function (r) {
                console.log('      ' + r.base + ' 0x' + r.size.toString(16) +
                            (r.file ? ' ' + r.file.path : ' <anon>'));
            });
            console.log('    Some of these are ART\'s JIT code cache and are entirely');
            console.log('    normal. Others are a packer. See ../../40-Obfuscation/.\n');
        }

        return { ranges: all.length, targetRanges: targets.length, targetMiB: tBytes / 1048576 };
    },

    /* ------------------------------------------------------------ helpers */

    _toPattern: function (str) {
        var out = [];
        for (var i = 0; i < str.length; i++) {
            var c = str.charCodeAt(i) & 0xff;
            out.push((c < 16 ? '0' : '') + c.toString(16));
        }
        return out.join(' ');
    },

    _preview: function (address, len) {
        try {
            var bytes = address.readByteArray(len);
            if (bytes === null) return '<unreadable>';
            var view = new Uint8Array(bytes);
            var ascii = '';
            for (var i = 0; i < view.length; i++) {
                ascii += (view[i] >= 0x20 && view[i] < 0x7f)
                    ? String.fromCharCode(view[i]) : '.';
            }
            return ascii;
        } catch (e) {
            return '<unreadable>';
        }
    },

    _record: function (hits, address, label, preview) {
        hits.push({
            address: address.toString(),
            label: label,
            preview: preview
        });
    },

    /* ==================================================================
     * 1. FORMAT DETECTORS
     * ================================================================== */

    FORMATS: [
        // [human label, pattern, bytes of context to show]
        ['PEM PRIVATE KEY',   '2d 2d 2d 2d 2d 42 45 47 49 4e', 128],  // "-----BEGIN"
        ['PKCS#8 ASN.1',      '30 82 ?? ?? 02 01 00 30',       64],
        ['RSA PRIVATE ASN.1', '30 82 ?? ?? 02 01 00 02 82',    64],
        ['PKCS#12 / JKS',     '30 82 ?? ?? 02 01 03',          48],
        ['X.509 cert',        '30 82 ?? ?? 30 82',             48],
        ['JWT (compact)',     '65 79 4a',                      160], // "eyJ"
        ['Bearer token',      '42 65 61 72 65 72 20',          160], // "Bearer "
        ['Basic auth',        '42 61 73 69 63 20',             96],  // "Basic "
        ['AWS access key',    '41 4b 49 41',                   32],  // "AKIA"
        ['Google API key',    '41 49 7a 61 53 79',             48],  // "AIzaSy"
        ['GitHub token',      '67 68 70 5f',                   48],  // "ghp_"
        ['Stripe live key',   '73 6b 5f 6c 69 76 65 5f',       48],  // "sk_live_"
        ['Slack token',       '78 6f 78 62 2d',                48],  // "xoxb-"
        ['Private key hdr',   '50 52 49 56 41 54 45 20 4b 45 59', 64],
        ['password= ',        '70 61 73 73 77 6f 72 64 3d',    64],
        ['api_key=',          '61 70 69 5f 6b 65 79 3d',       64],
        ['secret=',           '73 65 63 72 65 74 3d',          64],
        ['Authorization:',    '41 75 74 68 6f 72 69 7a 61 74 69 6f 6e 3a', 160],
        ['SQLite header',     '53 51 4c 69 74 65 20 66 6f 72 6d 61 74 20 33', 32],
        ['ZIP/APK header',    '50 4b 03 04',                   32]
    ],

    formats: function (opts) {
        var self = this;
        var targets = this.ranges(opts);
        var hits = [];
        var scanned = 0;

        console.log('[*] format scan over ' + targets.length + ' range(s)…');

        targets.forEach(function (range) {
            scanned += range.size;
            self.FORMATS.forEach(function (fmt) {
                var label = fmt[0], pattern = fmt[1], ctx = fmt[2];
                var matches;
                try {
                    matches = Memory.scanSync(range.base, range.size, pattern);
                } catch (e) {
                    return;                       // range unmapped mid-scan: normal
                }
                matches.forEach(function (m) {
                    var preview = self._preview(m.address, ctx);
                    // Suppress obvious noise: a preview that is nearly all dots
                    // is a false positive on a binary blob.
                    var printable = (preview.match(/[^.]/g) || []).length;
                    if (label.indexOf('ASN.1') === -1 &&
                        label.indexOf('PKCS') === -1 &&
                        label.indexOf('X.509') === -1 &&
                        printable < preview.length * 0.5) {
                        return;
                    }
                    self._record(hits, m.address, label, preview);
                    console.log('[hit] ' + label + '  @ ' + m.address);
                    console.log('      ' + preview.replace(/\s+/g, ' ').substring(0, 140));
                });
            });
        });

        console.log('[*] format scan complete: ' + hits.length + ' hit(s) over ' +
                    (scanned / 1048576 | 0) + ' MiB');
        this._lastHits = hits;
        return hits;
    },

    /* ==================================================================
     * 2. ENTROPY SCAN
     *
     * Raw key material has no format. What it does have is high entropy: a
     * 32-byte AES key is close to 8 bits of entropy per byte, whereas English
     * text is around 4 and structured binary is lower still.
     *
     * The catch is that compressed data and already-encrypted data are ALSO
     * high entropy, so this produces false positives by design. Use it with
     * diff mode: run it, trigger the operation, run it again, and look at what
     * is new.
     * ================================================================== */

    _entropy: function (bytes, offset, length) {
        var counts = new Uint32Array(256);
        for (var i = 0; i < length; i++) {
            counts[bytes[offset + i]]++;
        }
        var h = 0;
        for (var v = 0; v < 256; v++) {
            if (counts[v] === 0) continue;
            var p = counts[v] / length;
            h -= p * (Math.log(p) / Math.LN2);
        }
        return h;
    },

    entropy: function (windowSize, threshold, opts) {
        var self = this;
        windowSize = windowSize || 32;
        threshold = threshold || 7.0;

        // Below 16 bytes the entropy estimate is meaningless: a 16-byte window
        // cannot exceed log2(16) = 4 bits of measured entropy per byte even if
        // every byte is distinct. Use >= 32 for a real signal.
        if (windowSize < 16) {
            console.log('[!] windowSize < 16 gives meaningless entropy. Using 32.');
            windowSize = 32;
        }
        var maxPossible = Math.log(windowSize) / Math.LN2;
        if (threshold > maxPossible) {
            console.log('[!] threshold ' + threshold + ' exceeds the maximum measurable ' +
                        'entropy for a ' + windowSize + '-byte window (' +
                        maxPossible.toFixed(2) + '). Lowering.');
            threshold = maxPossible - 0.2;
        }

        var targets = this.ranges(opts);
        var hits = [];
        var step = windowSize;                    // non-overlapping: fast enough
        var totalBytes = 0;

        console.log('[*] entropy scan: window=' + windowSize + ' threshold=' +
                    threshold.toFixed(2) + ' over ' + targets.length + ' range(s)');

        targets.forEach(function (range) {
            var chunkSize = 1024 * 1024;
            for (var off = 0; off < range.size; off += chunkSize) {
                var len = Math.min(chunkSize, range.size - off);
                var buf;
                try {
                    buf = range.base.add(off).readByteArray(len);
                } catch (e) { continue; }         // unmapped: normal
                if (buf === null) continue;

                var view = new Uint8Array(buf);
                totalBytes += len;

                for (var w = 0; w + windowSize <= view.length; w += step) {
                    // Cheap pre-filter: skip windows that are mostly zeros or
                    // mostly one repeated byte. This removes 90% of the work.
                    var b0 = view[w], same = 0, zeros = 0;
                    for (var q = 0; q < windowSize; q += 4) {
                        if (view[w + q] === b0) same++;
                        if (view[w + q] === 0) zeros++;
                    }
                    if (same > windowSize / 8 || zeros > windowSize / 8) continue;

                    var h = self._entropy(view, w, windowSize);
                    if (h >= threshold) {
                        var addr = range.base.add(off + w);
                        var hex = '';
                        for (var z = 0; z < Math.min(windowSize, 32); z++) {
                            var bb = view[w + z];
                            hex += (bb < 16 ? '0' : '') + bb.toString(16);
                        }
                        self._record(hits, addr,
                                     'entropy ' + h.toFixed(2), hex);
                    }
                }
            }
        });

        console.log('[*] entropy scan complete: ' + hits.length +
                    ' candidate(s) over ' + (totalBytes / 1048576 | 0) + ' MiB');

        hits.slice(0, 40).forEach(function (h) {
            console.log('      ' + h.address + '  ' + h.label + '  ' + h.preview);
        });
        if (hits.length > 40) {
            console.log('      … ' + (hits.length - 40) + ' more');
            console.log('    That is too many to read. Use diff mode:');
            console.log('      mem.snapshot(); <trigger the operation>; mem.diff()');
        }

        this._lastHits = hits;
        return hits;
    },

    /* ==================================================================
     * 3. JAVA HEAP SCAN
     *
     * Secrets that live as managed objects — a String password, a
     * SecretKeySpec, a char[] PIN — are found far more reliably by walking the
     * managed heap than by pattern-matching raw memory, because Java.choose
     * knows the object layout.
     * ================================================================== */

    java: function (filterRegex) {
        var self = this;
        var re = filterRegex ? new RegExp(filterRegex, 'i')
                             : /pass|pwd|secret|token|key|auth|pin|session|jwt|bearer|credential/i;
        var found = [];

        Java.perform(function () {
            /* --- 3a. Strings -------------------------------------------- */
            console.log('[*] scanning java.lang.String instances…');
            var stringCount = 0;
            Java.choose('java.lang.String', {
                onMatch: function (s) {
                    stringCount++;
                    var v;
                    try { v = s.toString(); } catch (e) { return; }
                    if (v.length < 6 || v.length > 4096) return;
                    if (re.test(v)) {
                        found.push({ type: 'String', value: v });
                        console.log('  [String] ' + v.substring(0, 160));
                    } else if (/^ey[A-Za-z0-9_-]{10,}\./.test(v)) {
                        found.push({ type: 'JWT', value: v });
                        console.log('  [JWT] ' + v.substring(0, 160));
                    } else if (/^[A-Fa-f0-9]{32,}$/.test(v)) {
                        found.push({ type: 'hex-blob', value: v });
                        console.log('  [hex] ' + v.substring(0, 96));
                    }
                },
                onComplete: function () {
                    console.log('  scanned ' + stringCount + ' String instance(s)');
                }
            });

            /* --- 3b. Key material objects -------------------------------- */
            var keyClasses = [
                'javax.crypto.spec.SecretKeySpec',
                'javax.crypto.spec.IvParameterSpec',
                'java.security.KeyPair',
                'javax.crypto.spec.PBEKeySpec'
            ];

            keyClasses.forEach(function (cls) {
                try { Java.use(cls); } catch (e) { return; }   // not loaded
                console.log('[*] scanning ' + cls + ' instances…');
                Java.choose(cls, {
                    onMatch: function (o) {
                        try {
                            var algo = (typeof o.getAlgorithm === 'function')
                                     ? o.getAlgorithm() : '?';
                            var enc = (typeof o.getEncoded === 'function')
                                    ? o.getEncoded() : null;
                            if (enc !== null) {
                                var hex = '';
                                for (var i = 0; i < Math.min(enc.length, 64); i++) {
                                    var b = enc[i] & 0xff;
                                    hex += (b < 16 ? '0' : '') + b.toString(16);
                                }
                                found.push({ type: cls, algorithm: algo, hex: hex,
                                             length: enc.length });
                                console.log('  [' + cls.split('.').pop() + '] algo=' + algo +
                                            ' len=' + enc.length + ' ' + hex);
                            }
                        } catch (e) { /* not readable */ }
                    },
                    onComplete: function () {}
                });
            });

            /* --- 3c. char[] — the "correct" way to hold a password ------- */
            // Apps that follow the advice to use char[] instead of String are
            // still visible here if they have not zeroed it.
            console.log('[*] scanning SharedPreferences-backed maps…');
            try {
                Java.choose('java.util.HashMap', {
                    onMatch: function (map) {
                        try {
                            var keys = map.keySet().toArray();
                            for (var i = 0; i < keys.length; i++) {
                                var k = String(keys[i]);
                                if (!re.test(k)) continue;
                                var v = map.get(keys[i]);
                                if (v === null) continue;
                                found.push({ type: 'map-entry', key: k, value: String(v) });
                                console.log('  [map] ' + k + ' = ' +
                                            String(v).substring(0, 120));
                            }
                        } catch (e) { /* not a string map */ }
                    },
                    onComplete: function () {}
                });
            } catch (e) { /* skip */ }

            console.log('[*] java heap scan complete: ' + found.length + ' item(s)');
        });

        return found;
    },

    /* ==================================================================
     * TARGETED SEARCHES
     * ================================================================== */

    find: function (literal, opts) {
        var self = this;
        var pattern = this._toPattern(literal);
        var targets = this.ranges(opts);
        var hits = [];

        console.log('[*] searching for "' + literal + '" (' + pattern + ') in ' +
                    targets.length + ' range(s)');

        targets.forEach(function (range) {
            var matches;
            try { matches = Memory.scanSync(range.base, range.size, pattern); }
            catch (e) { return; }
            matches.forEach(function (m) {
                var preview = self._preview(m.address, self.CONTEXT_BYTES);
                self._record(hits, m.address, literal, preview);
                console.log('[hit] ' + m.address + '  ' + preview);
            });
        });

        console.log('[*] ' + hits.length + ' hit(s)');
        this._lastHits = hits;
        return hits;
    },

    hex: function (pattern, opts) {
        var self = this;
        var targets = this.ranges(opts);
        var hits = [];

        targets.forEach(function (range) {
            var matches;
            try { matches = Memory.scanSync(range.base, range.size, pattern); }
            catch (e) { return; }
            matches.forEach(function (m) {
                self._record(hits, m.address, pattern, self._preview(m.address, 48));
                console.log('[hit] ' + m.address);
                console.log(hexdump(m.address, { length: 64, ansi: false }));
            });
        });

        console.log('[*] ' + hits.length + ' hit(s) for pattern ' + pattern);
        this._lastHits = hits;
        return hits;
    },

    dump: function (address, length) {
        length = length || 256;
        try {
            var p = (typeof address === 'string') ? ptr(address) : address;
            console.log(hexdump(p, { length: length, ansi: false }));
            var mod = Process.findModuleByAddress(p);
            if (mod !== null) {
                console.log('[*] inside ' + mod.name + '+0x' +
                            p.sub(mod.base).toString(16));
            } else {
                var r = Process.findRangeByAddress(p);
                if (r !== null) {
                    console.log('[*] anonymous ' + r.protection + ' range, base=' + r.base +
                                ' size=0x' + r.size.toString(16));
                }
            }
        } catch (e) {
            console.log('[-] cannot read ' + address + ': ' + e.message);
        }
    },

    /* ==================================================================
     * DIFF MODE — attribute a secret to an action
     * ================================================================== */

    _snapshot: null,

    snapshot: function (kind) {
        kind = kind || 'formats';
        var hits = (kind === 'entropy') ? this.entropy(32, 7.0) : this.formats();
        var set = {};
        hits.forEach(function (h) { set[h.preview] = h; });
        this._snapshot = { kind: kind, set: set, count: hits.length };
        console.log('[*] snapshot taken: ' + hits.length + ' item(s), kind=' + kind);
        console.log('    Now trigger the operation, then run mem.diff()');
        return hits.length;
    },

    diff: function () {
        if (this._snapshot === null) {
            console.log('[-] no snapshot. Run mem.snapshot() first.');
            return [];
        }
        var kind = this._snapshot.kind;
        var hits = (kind === 'entropy') ? this.entropy(32, 7.0) : this.formats();
        var before = this._snapshot.set;
        var novel = hits.filter(function (h) { return before[h.preview] === undefined; });

        console.log('\n[*] DIFF: ' + novel.length + ' NEW item(s) since the snapshot');
        console.log('    (these appeared as a result of what you just did)');
        novel.slice(0, 60).forEach(function (h) {
            console.log('  ' + h.address + '  ' + h.label);
            console.log('      ' + String(h.preview).substring(0, 140));
        });
        if (novel.length === 0) {
            console.log('    Nothing new. Either the secret was already resident,');
            console.log('    or it lives in a range excluded by the default filter.');
            console.log('    Try:  mem.formats({fileBacked:true, maxMB:256})');
        }
        return novel;
    },

    /* ------------------------------------------------------------- output */

    save: function (tag) {
        if (this._lastHits === null) { console.log('[-] nothing to save'); return 0; }
        // Structured send(): the host driver writes this to disk. Far better
        // than console.log for anything you want to keep.
        send({ kind: 'secret-scan', tag: tag || 'scan', hits: this._lastHits });
        console.log('[*] sent ' + this._lastHits.length + ' hit(s) to the host');
        return this._lastHits.length;
    },

    help: function () {
        console.log([
            '',
            'ORIENTATION',
            '  mem.survey()                       what memory exists, and how much',
            '',
            'SCANS',
            '  mem.formats()                      known key/token/cert formats (fast)',
            '  mem.entropy(32, 7.0)               high-entropy runs (raw key material)',
            '  mem.java([regex])                  the managed heap (Strings, keys, maps)',
            '  mem.find("Bearer ")                a literal string',
            '  mem.hex("30 82 ?? ?? 02 01 00")    a byte pattern with wildcards',
            '',
            'ATTRIBUTION',
            '  mem.snapshot()                     record the current state',
            '  <trigger the operation in the app>',
            '  mem.diff()                         what appeared as a result',
            '',
            'INSPECTION',
            '  mem.dump("0x7b2c0a1000", 256)      hexdump around an address',
            '  mem.save("login")                  send() the last hits to the host',
            '',
            'OPTIONS (second argument to formats/entropy/find/hex)',
            '  {protection:"rw-", fileBacked:false, maxMB:64}',
            '',
            'WARNING: widening these scans across the whole address space on the',
            'JS thread will ANR the app. See ../README.md section 7.6.',
            ''
        ].join('\n'));
    }
};

/* ---------------------------------------------------------- RPC surface */

rpc.exports = {
    init: function (stage) {
        console.log('[*] memory-secret-scanner loaded (stage=' + stage + ')');
    },
    survey: function () { return mem.survey(); },
    formats: function () { return mem.formats(); },
    entropy: function (w, t) { return mem.entropy(w, t); },
    javaHeap: function (re) { return mem.java(re); },
    find: function (s) { return mem.find(s); },
    snapshot: function (k) { return mem.snapshot(k); },
    diff: function () { return mem.diff(); },
    read: function (address, length) {
        // ArrayBuffer return values are transferred as raw binary, not JSON.
        return ptr(address).readByteArray(length);
    }
};

/* --------------------------------------------------------------- bootstrap */

console.log('');
console.log('=== memory-secret-scanner ===');
console.log('[*] pid=' + Process.id + ' arch=' + Process.arch +
            ' pageSize=' + Process.pageSize);
console.log('[+] ready — type mem.help(), and start with mem.survey()');
console.log('');
