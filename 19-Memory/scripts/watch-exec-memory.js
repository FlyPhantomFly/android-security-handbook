// watch-exec-memory.js -- who is creating executable memory in this process,
//                         and where did the request come from?
//
// WHY THIS SCRIPT EXISTS
//     Reading /proc/<pid>/maps tells you that an RWX region exists. It cannot
//     tell you who made it, and that is the only question that matters, because
//     every Android app has an RWX region: ART's JIT code cache. A triage rule
//     of the form "RWX means compromise" fires on every device ever shipped.
//
//     This script answers the follow-up. It hooks mmap and mprotect, reports
//     every request that includes PROT_EXEC, and prints a backtrace for each.
//     ART will be the loudest caller by a wide margin and that is correct.
//     What you are looking for is a caller that is NOT libart.so and NOT the
//     linker.
//
//     mprotect is the more interesting of the two hooks. Making memory
//     executable AFTER it has been written is what a runtime unpacker does once
//     it has finished decrypting. Mapping it executable up front is what a JIT
//     does. The distinction is visible in the output.
//
// HOW TO RUN
//     # host -- attach to a running app
//     frida -U -n com.example.target -l watch-exec-memory.js
//
//     # host -- spawn, if the early allocations matter (they usually do)
//     frida -U -f com.example.target -l watch-exec-memory.js --no-pause
//
//     Then drive the app. Every PROT_EXEC request prints as it happens.
//
//     From the REPL:
//         rpc.exports.summary()          // counts per caller module
//         rpc.exports.quiet(true)        // stop the live stream, keep counting
//         rpc.exports.look('0x73...')    // hexdump the first bytes of a region
//
// REQUIREMENTS
//     Frida 12+ with a matching frida-server, and attach permission on the
//     target -- root, an emulator, or a debuggable build. See 53-Frida.
//
// WHAT THIS SCRIPT WILL *NOT* TELL YOU
//     - Whether anything it reports is malicious. ART's JIT, every other JIT,
//       some packers and some legitimate plugin systems all map executable
//       memory. The script prints WHO and WHERE; the judgement is yours, and
//       README section 6.4 is the checklist for making it.
//     - Anything about memory mapped BEFORE you attached. Spawn rather than
//       attach if the early regions matter. Anything the Zygote mapped before
//       the fork is invisible to this script no matter what you do.
//     - What was written into the memory. Use look() afterwards.
//     - Anything about regions created by a syscall the app made directly
//       rather than through libc's wrapper. Rare, but a deliberately evasive
//       payload can issue `svc #0` itself and this hook will never see it.
//       An unexplained executable region with no corresponding hook output is
//       therefore MORE interesting, not less.
//
// A NOTE ON HONESTY
//     Frida's own agent maps executable memory. Those requests are labelled
//     rather than filtered, because a tool that silently removes the observer's
//     footprint teaches its user that the footprint is not there -- and an
//     anti-tamper check inside the app will count it regardless. See
//     37-RootDetection.

'use strict';

var PROT_READ = 1, PROT_WRITE = 2, PROT_EXEC = 4;

var quiet = false;
var counts = {};        // caller module name -> { mmap, mprotect, bytes }
var seen = [];          // recent events, for summary()
var MAX_SEEN = 256;

function describe(prot) {
    return ((prot & PROT_READ) ? 'r' : '-') +
           ((prot & PROT_WRITE) ? 'w' : '-') +
           ((prot & PROT_EXEC) ? 'x' : '-');
}

function human(n) {
    var u = ['B', 'KiB', 'MiB', 'GiB'];
    var i = 0;
    while (n >= 1024 && i < u.length - 1) {
        n /= 1024;
        i++;
    }
    return (i === 0 ? n + ' B' : n.toFixed(1) + ' ' + u[i]);
}

/*
 * Which module made this request?
 *
 * Walk the backtrace and take the first frame that is inside a named module and
 * is not libc itself -- libc is where mmap lives, so it is always frame 0 and
 * always uninformative.
 */
function blameModule(bt) {
    for (var i = 0; i < bt.length; i++) {
        var m = Process.findModuleByAddress(bt[i]);
        if (m === null) {
            continue;
        }
        if (/^libc\.so$/.test(m.name)) {
            continue;
        }
        return m.name;
    }
    return '(no named module -- itself worth explaining)';
}

function isOurs(bt) {
    return bt.some(function (a) {
        var m = Process.findModuleByAddress(a);
        return m !== null && /frida|gum/i.test(m.name);
    });
}

function record(what, addr, len, prot, ctx) {
    if ((prot & PROT_EXEC) === 0) {
        return;                    // only executable requests are interesting
    }

    var bt;
    try {
        bt = Thread.backtrace(ctx, Backtracer.ACCURATE);
    } catch (e) {
        bt = [];
    }
    var blame = blameModule(bt);
    var ours = isOurs(bt);

    if (!(blame in counts)) {
        counts[blame] = { mmap: 0, mprotect: 0, bytes: 0, frida: ours };
    }
    counts[blame][what] += 1;
    counts[blame].bytes += len;

    seen.push({ what: what, addr: addr.toString(), len: len,
                prot: describe(prot), blame: blame, frida: ours });
    if (seen.length > MAX_SEEN) {
        seen.shift();
    }

    if (quiet) {
        return;
    }

    var wx = ((prot & PROT_WRITE) !== 0) ? '   <-- WRITABLE **AND** EXECUTABLE' : '';
    var tag = ours ? '   [Frida itself -- not the app]' : '';

    console.log('');
    console.log('=== ' + what + ' ' + describe(prot) + '  ' +
                human(len) + ' @ ' + addr + wx + tag);
    console.log('    blamed on: ' + blame);
    if (bt.length > 0) {
        console.log('    ' + bt.slice(0, 8)
                              .map(DebugSymbol.fromAddress)
                              .join('\n    '));
    } else {
        console.log('    (no backtrace -- frame pointers may be omitted)');
    }
}

// ---------------------------------------------------------------------------
// Hooks
// ---------------------------------------------------------------------------

var pMmap = Module.findExportByName('libc.so', 'mmap');
var pMprotect = Module.findExportByName('libc.so', 'mprotect');

if (pMmap === null || pMprotect === null) {
    throw new Error('cannot resolve mmap/mprotect in libc.so');
}

Interceptor.attach(pMmap, {
    onEnter: function (args) {
        this.len = args[1].toInt32();
        this.prot = args[2].toInt32();
        this.savedCtx = this.context;
    },
    onLeave: function (retval) {
        // mmap returns MAP_FAILED, which is (void *)-1, on failure.
        if (retval.equals(ptr(-1))) {
            return;
        }
        record('mmap', retval, this.len, this.prot, this.savedCtx);
    }
});

Interceptor.attach(pMprotect, {
    onEnter: function (args) {
        record('mprotect', args[0], args[1].toInt32(), args[2].toInt32(),
               this.context);
    }
});

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------

function pad(s, n) {
    s = String(s);
    while (s.length < n) {
        s = s + ' ';
    }
    return s;
}

rpc.exports = {
    quiet: function (on) {
        quiet = (on !== false);
        return quiet ? 'live stream off; still counting' : 'live stream on';
    },

    summary: function () {
        var out = [];
        out.push('=== PROT_EXEC requests, by blamed module ===');
        out.push('  ' + pad('MODULE', 40) + pad('mmap', 8) + pad('mprot', 8) +
                 'TOTAL BYTES');
        Object.keys(counts).sort(function (a, b) {
            return counts[b].bytes - counts[a].bytes;
        }).forEach(function (k) {
            var c = counts[k];
            out.push('  ' + pad(k, 40) + pad(c.mmap, 8) + pad(c.mprotect, 8) +
                     human(c.bytes) + (c.frida ? '   [Frida]' : ''));
        });
        out.push('');
        out.push('  libart.so dominating this list is CORRECT -- the JIT maps');
        out.push('  and reprotects executable memory constantly. What deserves');
        out.push('  a look is any row that is not libart.so, not the linker,');
        out.push('  and not Frida. A row reading "(no named module)" is the');
        out.push('  most interesting of all: something with no module identity');
        out.push('  asked for executable memory.');
        out.push('');
        out.push('  Then: rpc.exports.look(<address>) on one of its regions.');
        return out.join('\n');
    },

    /**
     * Hexdump the start of a region, and guess what is in it.
     *
     * Two signatures are worth recognising immediately:
     *   \x7fELF                       a shared object loaded from memory. No
     *                                 file on disk explains it, and static
     *                                 analysis of the APK never will.
     *   stp x29, x30, [sp, #-N]!      an AArch64 function prologue -- raw code.
     */
    look: function (addrStr, len) {
        var a = ptr(addrStr);
        var n = len || 128;
        var out = [];
        var bytes;

        try {
            bytes = Memory.readByteArray(a, 16);
        } catch (e) {
            return 'cannot read ' + a + ': ' + e.message +
                   '\nAn execute-only (--xp) region reads as EFAULT by design.';
        }

        var b = new Uint8Array(bytes);
        if (b[0] === 0x7f && b[1] === 0x45 && b[2] === 0x4c && b[3] === 0x46) {
            out.push('ELF MAGIC at the start of this region.');
            out.push('A shared object was loaded from memory rather than from a');
            out.push('file. Dump it and treat it as a library:');
            out.push('    var r = Process.findRangeByAddress(' + addrStr + ');');
            out.push('    var f = new File("/data/local/tmp/carved.so", "wb");');
            out.push('    f.write(Memory.readByteArray(r.base, r.size)); f.close();');
            out.push('Then: adb pull, and run 15-Native-Code/scripts/elf-harden-check.py');
            out.push('');
        }

        var m = Process.findModuleByAddress(a);
        out.push('module: ' + (m === null ? '(none -- anonymous)' : m.name));
        var r = Process.findRangeByAddress(a);
        if (r !== null) {
            out.push('range : ' + r.base + ' + ' + human(r.size) +
                     '  (' + r.protection + ')');
        }
        out.push('');
        out.push(hexdump(a, { length: n, header: true, ansi: false }));
        return out.join('\n');
    },

    reset: function () {
        counts = {};
        seen = [];
        return 'cleared';
    }
};

console.log('watch-exec-memory.js loaded.');
console.log('');
console.log('Watching mmap and mprotect for PROT_EXEC. Drive the app now.');
console.log('');
console.log('  rpc.exports.summary()        counts per calling module');
console.log('  rpc.exports.quiet(true)      stop the live stream, keep counting');
console.log('  rpc.exports.look(addr)       hexdump a region and identify it');
console.log('');
console.log('Expect libart.so to dominate. That is the JIT and it is correct.');
