/*
 * frida-dexdump-lite.js
 * ---------------------------------------------------------------------------
 * WHAT IT DOES
 *   Scans the target process's readable memory for the DEX magic, VALIDATES
 *   each candidate against the DEX header's structural invariants, and carves
 *   every genuine DEX out to disk.
 *
 *   The validation is the point of the script. A bare search for the four
 *   bytes `64 65 78 0a` ("dex\n") in a live Android process returns dozens to
 *   hundreds of hits, almost all of them false positives: the literal string
 *   "dex\n" inside libart's own data, log format strings, fragments of a
 *   string pool, JIT-generated code that happens to contain those bytes.
 *   Writing all of them to disk gives you a directory of garbage and no way to
 *   tell which file matters.
 *
 *   Four cheap header checks eliminate essentially all of them:
 *
 *     offset 0x24  header_size  MUST be 0x70          <- the decisive one
 *     offset 0x28  endian_tag   MUST be 0x12345678
 *     offset 0x20  file_size    must be sane and must fit in the mapping
 *     offset 0x04  version      must be three ASCII digits then NUL
 *
 *   `header_size == 0x70` is fixed by the DEX specification and has never
 *   changed across any DEX version. Random data matches it with probability
 *   about 2^-32 once combined with the endian tag, so the two together are a
 *   near-perfect filter. See ../../12-DEX-Internals/README.md for the full
 *   header layout, and its lab 04, which uses exactly this validation to
 *   distinguish a hidden payload from noise.
 *
 * WHY IT MATTERS
 *   This is the UNIVERSAL FALLBACK for unpacking. Chapter 40 section 3.7.3
 *   lists three implementations of the unpacking idea, in order of preference:
 *
 *     1. Hook the ClassLoader constructors    (frida-classloader-dump.js)
 *     2. Hook ART's internal DEX entry points (fragile — symbols are not ABI)
 *     3. SCAN MEMORY FOR THE DEX MAGIC        (this script)
 *
 *   The first two can be defeated. A packer can build the DEX entirely in
 *   native code and register it through a route no Java constructor observes;
 *   ART's C++ symbols are not a stable ABI and are frequently not exported on
 *   release builds, so a hook written against one device fails on the next.
 *
 *   Memory scanning cannot be defeated by any of that, because it does not
 *   depend on any symbol, any API, or any name. It depends only on the fact
 *   that ART requires a valid, plaintext DEX image in the process's address
 *   space in order to execute the app's code at all. The bytes must be there.
 *   This script finds them.
 *
 *   What it cannot do is choose the moment for you — see TIMING below.
 *
 * HOW TO RUN
 *   Timing matters more than the scan itself.
 *
 *   # host — ATTACH, deliberately, AFTER the first Activity is visible.
 *   # This is the one script in the chapter where attaching is correct: you
 *   # want the app to have finished unpacking before you look.
 *   frida -U -n com.target.app -l frida-dexdump-lite.js
 *
 *   # in the REPL:
 *   dd.sweep()              scan and carve
 *   dd.sweep({rw: true})    also scan rw- ranges (slower, occasionally needed)
 *   dd.probe()              count candidates without writing anything
 *   dd.stats()              what was carved
 *   dd.repair()             print the checksum/signature repair recipe
 *
 *   # retrieve:
 *   adb pull /data/local/tmp/dexdump
 *   jadx -d out /path/to/dexdump/*.dex
 *
 * TIMING
 *   Too early  : the DEX is not loaded and you get the stub, or nothing.
 *   Too late   : some packers wipe or re-protect the region after use.
 *   Reliable   : after the first Activity is on screen. By then the real code
 *                has certainly been loaded AND executed.
 *   If you get a DEX whose method bodies are empty, the packer is decrypting
 *   lazily, per class or per method. Exercise more of the app and sweep again;
 *   each sweep is deduplicated so repeated sweeps are cheap and additive.
 *
 * REQUIREMENTS
 *   frida-server on the device matching your client. Root is required for the
 *   process to be able to write to /data/local/tmp; otherwise the script falls
 *   back to the app's own cache directory, which always works.
 *
 * AUTHORISED TESTING ONLY.
 * ---------------------------------------------------------------------------
 */

'use strict';

var dd = {

    cfg: {
        // Output directory. Falls back to the app's cache dir if unwritable.
        outDir: '/data/local/tmp/dexdump',

        // A DEX smaller than this is a stub fragment or a false positive that
        // passed the header checks by chance. 0x70 is the header itself.
        minSize: 0x200,

        // 512 MB. Anything larger is not a DEX; the format's practical ceiling
        // is far below this.
        maxSize: 512 * 1024 * 1024,

        // Skip ranges backed by a file whose path matches this. The base APK
        // is already on disk and its DEX is already yours; mapping it again
        // wastes time and fills the output directory.
        skipFileBacked: /\.apk$|\.jar$|\.oat$|\.odex$|\.vdex$|\.art$|\/system\/|\/apex\//,

        // Very large ranges are almost always the heap or a file mapping;
        // scanning them is slow. Raise if a big DEX is being missed.
        maxRangeSize: 512 * 1024 * 1024,

        // Print every rejected candidate and why. Useful once, educational,
        // then noisy.
        explainRejects: false
    },

    counter: 0,
    carved: [],
    seen: {},
    stats_: { ranges: 0, hits: 0, rejected: {}, written: 0 },

    // ------------------------------------------------------------- internals

    _reject: function (reason, addr) {
        this.stats_.rejected[reason] = (this.stats_.rejected[reason] || 0) + 1;
        if (this.cfg.explainRejects) {
            console.log('    [x] ' + addr + '  ' + reason);
        }
    },

    _ensureOutDir: function () {
        // Try the configured directory; if we cannot create a file there, fall
        // back to the app's cache, which the app UID can always write.
        try {
            var probe = new File(this.cfg.outDir + '/.probe', 'wb');
            probe.write([0]);
            probe.close();
            return this.cfg.outDir;
        } catch (e) { }

        try {
            var dir = null;
            Java.perform(function () {
                var ctx = Java.use('android.app.ActivityThread')
                              .currentApplication().getApplicationContext();
                dir = ctx.getCacheDir().getAbsolutePath() + '/dexdump';
                var F = Java.use('java.io.File');
                var f = F.$new(dir);
                if (!f.exists()) f.mkdirs();
            });
            if (dir !== null) {
                console.log('[!] ' + this.cfg.outDir + ' not writable; using ' + dir);
                this.cfg.outDir = dir;
            }
        } catch (e) {
            console.log('[-] no writable output directory found: ' + e);
        }
        return this.cfg.outDir;
    },

    /*
     * Validate a candidate DEX header.
     *
     * Returns { ok: true, size, version } or { ok: false, reason }.
     *
     * Every one of these checks is cheap, and together they are what separates
     * this script from `grep -abo 'dex\n'`.
     */
    _validate: function (addr, rangeBase, rangeSize) {
        // --- version: magic[4..6] must be three ASCII digits, magic[7] NUL --
        var v0, v1, v2, v3;
        try {
            v0 = addr.add(4).readU8();
            v1 = addr.add(5).readU8();
            v2 = addr.add(6).readU8();
            v3 = addr.add(7).readU8();
        } catch (e) {
            return { ok: false, reason: 'header unreadable' };
        }
        var isDigit = function (c) { return c >= 0x30 && c <= 0x39; };
        if (!isDigit(v0) || !isDigit(v1) || !isDigit(v2) || v3 !== 0x00) {
            return { ok: false, reason: 'bad version bytes (not "dex\\nNNN\\0")' };
        }
        var version = String.fromCharCode(v0, v1, v2);

        // --- header_size at 0x24 MUST be 0x70 -------------------------------
        // Fixed by the specification for every DEX version ever published.
        // This single check removes the overwhelming majority of false hits.
        var headerSize;
        try { headerSize = addr.add(0x24).readU32(); }
        catch (e) { return { ok: false, reason: 'header_size unreadable' }; }
        if (headerSize !== 0x70) {
            return { ok: false, reason: 'header_size != 0x70 (got 0x' +
                                        headerSize.toString(16) + ')' };
        }

        // --- endian_tag at 0x28 must be ENDIAN_CONSTANT ---------------------
        var endian;
        try { endian = addr.add(0x28).readU32(); }
        catch (e) { return { ok: false, reason: 'endian_tag unreadable' }; }
        if (endian !== 0x12345678) {
            // 0x78563412 would be the (never used in practice) reverse-endian
            // form. Worth naming so you recognise it if you ever meet it.
            if (endian === 0x78563412) {
                return { ok: false, reason: 'reverse-endian DEX (unsupported)' };
            }
            return { ok: false, reason: 'endian_tag != 0x12345678' };
        }

        // --- file_size at 0x20 must be sane --------------------------------
        var fileSize;
        try { fileSize = addr.add(0x20).readU32(); }
        catch (e) { return { ok: false, reason: 'file_size unreadable' }; }
        if (fileSize < this.cfg.minSize) {
            return { ok: false, reason: 'file_size too small (' + fileSize + ')' };
        }
        if (fileSize > this.cfg.maxSize) {
            return { ok: false, reason: 'file_size implausible (' + fileSize + ')' };
        }

        // --- the whole file must fit inside this mapping --------------------
        // If it does not, either this is a false positive or the DEX spans a
        // range boundary. We report it rather than reading off the end and
        // crashing the process we are inspecting.
        var offsetInRange = addr.sub(rangeBase).toUInt32();
        if (offsetInRange + fileSize > rangeSize) {
            return { ok: false,
                     reason: 'file_size exceeds mapping (' + fileSize +
                             ' from +0x' + offsetInRange.toString(16) +
                             ' in a 0x' + rangeSize.toString(16) + ' range)' };
        }

        // --- cross-check a couple of table offsets --------------------------
        // map_off (0x34) and string_ids_off (0x3C) must point inside the file.
        // Cheap, and it catches the rare false positive that survives the
        // first four checks.
        try {
            var mapOff = addr.add(0x34).readU32();
            var strIdsSize = addr.add(0x38).readU32();
            var strIdsOff = addr.add(0x3C).readU32();
            if (mapOff !== 0 && (mapOff < 0x70 || mapOff >= fileSize)) {
                return { ok: false, reason: 'map_off outside file' };
            }
            if (strIdsSize !== 0 &&
                (strIdsOff < 0x70 || strIdsOff >= fileSize)) {
                return { ok: false, reason: 'string_ids_off outside file' };
            }
            return { ok: true, size: fileSize, version: version,
                     strings: strIdsSize, mapOff: mapOff };
        } catch (e) {
            return { ok: false, reason: 'table offsets unreadable' };
        }
    },

    _fingerprint: function (addr, size) {
        // Sample the file rather than hashing all of it: a 20 MB DEX hashed on
        // a phone is slow, and we only need to know whether we have already
        // written this exact image.
        var acc = size | 0;
        try {
            var step = Math.max(64, Math.floor(size / 32));
            for (var off = 0; off < size - 4; off += step) {
                acc = ((acc * 31) ^ addr.add(off).readU32()) | 0;
            }
        } catch (e) { }
        return size + ':' + (acc >>> 0).toString(16);
    },

    _carve: function (addr, info) {
        var fp = this._fingerprint(addr, info.size);
        if (this.seen[fp] !== undefined) {
            return { written: false, reason: 'duplicate of ' + this.seen[fp] };
        }

        var dir = this._ensureOutDir();
        var name = dir + '/mem_' + (this.counter++) + '_' + addr + '_v' +
                   info.version + '.dex';

        var bytes;
        try {
            bytes = addr.readByteArray(info.size);
        } catch (e) {
            return { written: false, reason: 'read failed: ' + e };
        }
        if (bytes === null) {
            return { written: false, reason: 'read returned null' };
        }

        try {
            var f = new File(name, 'wb');
            f.write(bytes);
            f.close();
        } catch (e) {
            return { written: false, reason: 'write failed: ' + e };
        }

        this.seen[fp] = name;
        this.carved.push({
            path: name, size: info.size, version: info.version,
            address: String(addr), strings: info.strings
        });
        this.stats_.written++;
        return { written: true, path: name };
    },

    // ==================================================================== API

    /*
     * Count candidates and show why each was rejected, without writing
     * anything. Run this first: it tells you whether the DEX is even present
     * yet, which is a question about TIMING, not about the scan.
     */
    probe: function (opts) {
        opts = opts || {};
        var self = this;
        this.stats_.rejected = {};
        var hits = 0, valid = 0;

        var protections = ['r--'];
        if (opts.rw !== false) protections.push('rw-');

        protections.forEach(function (prot) {
            Process.enumerateRanges(prot).forEach(function (range) {
                if (range.size > self.cfg.maxRangeSize) return;
                if (range.file && self.cfg.skipFileBacked.test(range.file.path)) return;

                try {
                    Memory.scanSync(range.base, range.size, '64 65 78 0a')
                        .forEach(function (m) {
                            hits++;
                            var r = self._validate(m.address, range.base, range.size);
                            if (r.ok) {
                                valid++;
                                console.log('  [ok] ' + m.address + '  ' + r.size +
                                            ' bytes  v' + r.version +
                                            '  ' + r.strings + ' strings' +
                                            (range.file ? '  <- ' + range.file.path : ''));
                            } else {
                                self._reject(r.reason, m.address);
                            }
                        });
                } catch (e) { /* range vanished mid-scan; normal */ }
            });
        });

        console.log('');
        console.log('=== probe: ' + hits + ' magic hit(s), ' + valid + ' valid DEX ===');
        console.log('rejected:');
        Object.keys(this.stats_.rejected).sort(function (a, b) {
            return self.stats_.rejected[b] - self.stats_.rejected[a];
        }).forEach(function (r) {
            console.log('  ' + self.stats_.rejected[r] + '\t' + r);
        });
        console.log('');
        console.log('That rejection list is why the header checks exist. A bare');
        console.log('magic search would have written all ' + hits + ' of these to disk.');
        console.log('');
        if (valid === 0) {
            console.log('No valid DEX found. This is almost always TIMING:');
            console.log('  - sweep AFTER the first Activity is on screen');
            console.log('  - for a packed app, make sure it actually unpacked');
            console.log('    (frida-classloader-dump.js narrates the sequence)');
            console.log('  - try dd.sweep({rw: true}) if you excluded rw- ranges');
        }
        return valid;
    },

    /*
     * Scan and carve.
     *
     *   dd.sweep()                    r-- and rw- ranges
     *   dd.sweep({rw: false})         r-- only (faster)
     *   dd.sweep({includeApk: true})  also scan file-backed APK/OAT mappings
     */
    sweep: function (opts) {
        opts = opts || {};
        var self = this;
        this.stats_ = { ranges: 0, hits: 0, rejected: {}, written: 0 };

        var protections = ['r--'];
        if (opts.rw !== false) protections.push('rw-');

        console.log('[*] sweeping ' + protections.join(', ') + ' ranges for DEX magic...');
        var t0 = Date.now();

        protections.forEach(function (prot) {
            Process.enumerateRanges(prot).forEach(function (range) {
                if (range.size > self.cfg.maxRangeSize) return;
                if (!opts.includeApk && range.file &&
                    self.cfg.skipFileBacked.test(range.file.path)) return;

                self.stats_.ranges++;

                try {
                    Memory.scanSync(range.base, range.size, '64 65 78 0a')
                        .forEach(function (m) {
                            self.stats_.hits++;
                            var info = self._validate(m.address, range.base, range.size);
                            if (!info.ok) {
                                self._reject(info.reason, m.address);
                                return;
                            }
                            var res = self._carve(m.address, info);
                            if (res.written) {
                                console.log('[+] ' + info.size + ' bytes  v' +
                                            info.version + '  @ ' + m.address +
                                            '  -> ' + res.path);
                            } else {
                                console.log('[=] ' + m.address + '  ' + res.reason);
                            }
                        });
                } catch (e) { /* range vanished; normal in a live process */ }
            });
        });

        var ms = Date.now() - t0;
        console.log('');
        console.log('[*] swept ' + this.stats_.ranges + ' range(s) in ' + ms + 'ms: ' +
                    this.stats_.hits + ' magic hit(s), ' +
                    this.stats_.written + ' DEX written');

        var rejCount = 0;
        Object.keys(this.stats_.rejected).forEach(function (k) {
            rejCount += self.stats_.rejected[k];
        });
        if (rejCount > 0) {
            console.log('[*] ' + rejCount + ' candidate(s) rejected by header validation ' +
                        '(set dd.cfg.explainRejects = true to see why)');
        }
        if (this.stats_.written === 0) {
            console.log('');
            console.log('Nothing written. Run dd.probe() for the rejection breakdown,');
            console.log('and re-read the TIMING section at the top of this script.');
        }
        console.log('');
    },

    stats: function () {
        console.log('');
        console.log('=== carved ' + this.carved.length + ' DEX file(s) ===');
        this.carved.forEach(function (c) {
            console.log('  ' + c.size + ' bytes  v' + c.version + '  ' +
                        c.strings + ' strings  @ ' + c.address);
            console.log('      ' + c.path);
        });
        if (this.carved.length > 0) {
            console.log('');
            console.log('Retrieve and decompile:');
            console.log('  adb pull ' + this.cfg.outDir);
            console.log('  jadx -d out ' + this.cfg.outDir + '/*.dex');
            console.log('');
            console.log('The one with the most strings is usually the real app.');
            console.log('A small one with few strings is the packer stub.');
            console.log('');
            console.log('If jadx complains about the checksum, run dd.repair().');
        }
        console.log('');
    },

    /*
     * A carved DEX frequently fails a checksum or signature verification,
     * because the in-memory image is not byte-identical to the file ART
     * originally read: fields get patched, and some regions are rewritten.
     *
     * The fields are unkeyed integrity values, not security controls, so
     * recomputing them is legitimate and safe.
     */
    repair: function () {
        console.log([
            '',
            '=== repairing a carved DEX ===',
            '',
            'The Adler-32 checksum (offset 0x08) and SHA-1 signature (0x0C..0x1F)',
            'are computed over the rest of the file. An in-memory image usually',
            'no longer matches, because ART patches fields in place.',
            '',
            'They are UNKEYED integrity fields, not signatures in the security',
            'sense, so recomputing them is always valid:',
            '',
            '  # host — repair.py',
            '  import hashlib, struct, zlib, sys',
            '  d = bytearray(open(sys.argv[1], "rb").read())',
            '  # file_size sanity: truncate or report',
            '  size = struct.unpack_from("<I", d, 0x20)[0]',
            '  if size != len(d):',
            '      print(f"file_size={size} actual={len(d)}")',
            '  d[0x0C:0x20] = hashlib.sha1(bytes(d[0x20:])).digest()',
            '  struct.pack_into("<I", d, 0x08, zlib.adler32(bytes(d[0x0C:])) & 0xFFFFFFFF)',
            '  open(sys.argv[1] + ".fixed", "wb").write(bytes(d))',
            '',
            'If it still will not decompile, in order:',
            '  1. baksmali is far more tolerant than jadx — go to Smali.',
            '  2. Check the map_list against file_size; a truncated carve is',
            '     the usual cause (see ../../12-DEX-Internals/).',
            '  3. Empty method bodies mean METHOD-LEVEL protection: bodies are',
            '     decrypted on first invocation and re-encrypted afterwards.',
            '     Exercise more of the app and sweep again — sweeps are',
            '     deduplicated, so repeated sweeps accumulate coverage.',
            ''
        ].join('\n'));
    },

    setOutDir: function (p) {
        this.cfg.outDir = p;
        console.log('[*] output directory: ' + p);
    },

    help: function () {
        console.log([
            '',
            'dd.probe()              count candidates, show rejection reasons',
            'dd.sweep()              scan and carve (r-- and rw-)',
            'dd.sweep({rw:false})    r-- only, faster',
            'dd.sweep({includeApk:true})  also scan file-backed APK/OAT mappings',
            'dd.stats()              list what was carved',
            'dd.repair()             checksum/signature repair recipe',
            'dd.setOutDir(path)      change output directory',
            '',
            'dd.cfg.explainRejects = true   print every rejected candidate',
            '',
            'TIMING: sweep AFTER the first Activity is visible.',
            ''
        ].join('\n'));
    }
};

// --------------------------------------------------------------- bootstrap

console.log('');
console.log('=====================================================================');
console.log(' frida-dexdump-lite.js — memory scan with header validation');
console.log('');
console.log(' A bare search for "dex\\n" returns mostly false positives.');
console.log(' header_size == 0x70 and endian_tag == 0x12345678 remove them.');
console.log('=====================================================================');
console.log('');
console.log(' dd.probe()   see what is there and why candidates are rejected');
console.log(' dd.sweep()   carve every valid DEX to ' + dd.cfg.outDir);
console.log(' dd.help()    everything else');
console.log('');
console.log(' Sweep AFTER the first Activity appears. Timing is the whole skill.');
console.log('');
