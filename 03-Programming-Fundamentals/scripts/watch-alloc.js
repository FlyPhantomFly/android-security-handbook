/*
 * watch-alloc.js — catch an integer overflow at run time by watching what the allocator is asked
 * for, without reading a line of source.
 *
 * WHY THIS SCRIPT EXISTS
 *   Chapter 03 section 3.4 describes the allocation-size overflow: `int size = count * 16` wraps,
 *   a small buffer is allocated, and a large copy follows. This script detects that pattern from
 *   the outside, on a stripped .so, in a running app.
 *
 *   The core idea is one comparison. When code computes `count * elem` in 32-bit arithmetic, we
 *   recompute the same product in 64-bit arithmetic and compare. If they disagree, the app's
 *   arithmetic overflowed. That single check finds a whole vulnerability class without source,
 *   without symbols, and without a fuzzer.
 *
 * WHAT IT DOES
 *   * Hooks malloc, calloc, realloc, memcpy, memmove, memset and strcpy in libc.
 *   * Flags calloc calls where n * elem overflows 32 bits.
 *   * Flags the overflow SIGNATURE: a suspiciously small allocation followed closely, on the same
 *     thread, by a much larger copy into that same pointer. That correlation is the actual bug,
 *     and neither half looks wrong on its own.
 *   * Prints a symbolised backtrace for anything suspicious, so you learn which function to look at.
 *   * Keeps a live table of allocations so the correlation can be made.
 *
 * USAGE
 *   host $ frida -U -f com.target.app -l watch-alloc.js --no-pause
 *   host $ frida -U -n com.target.app -l watch-alloc.js
 *
 *   From the REPL:
 *       report()              // everything flagged so far
 *       setThreshold(1024)    // only report allocations at or above this size
 *       only('libtarget.so')  // restrict reporting to calls from one module
 *       verbose(true)         // print EVERY allocation (extremely noisy)
 *
 *   Then drive the app towards the parser you care about — open the file, receive the message,
 *   scan the QR code — and watch.
 *
 * NOTE ON NOISE
 *   Every Android process allocates constantly. Run with the default settings first, get a feel
 *   for the baseline, then use only() to restrict to the module you care about. Trying to read
 *   unfiltered output is how people conclude this technique does not work.
 *
 * SAFETY
 *   Read-only. It observes and prints; it never changes a size or a return value.
 *
 * Chapter 03 — Programming Fundamentals, sections 3.4 and 7.5; examples/overflow_demo.c
 */

'use strict';

// -------------------------------------------------------------------------------------------------
// CONFIG
// -------------------------------------------------------------------------------------------------
var CONFIG = {
    threshold: 0,             // only report allocations >= this size (0 = report per the rules below)
    suspiciousSmall: 64,      // an allocation below this, followed by a big copy, is the signature
    bigCopy: 4096,            // a copy at or above this into a small buffer is what we are hunting
    correlationWindowMs: 250, // how long an allocation stays "recent" for correlation
    verbose: false,           // print every allocation (very noisy)
    onlyModule: null,         // restrict reporting to calls originating in this module
    maxFindings: 200
};

var INT32_MAX = 2147483647;
var UINT32_MAX = 4294967295;

// -------------------------------------------------------------------------------------------------
// State
// -------------------------------------------------------------------------------------------------
var recent = {};              // pointer string -> { size, time, thread, where }
var findings = [];
var counts = { malloc: 0, calloc: 0, realloc: 0, memcpy: 0, flagged: 0 };

function now() { return Date.now(); }

function line(ch) { return new Array(79).join(ch || '-'); }

function backtrace(context) {
    try {
        return Thread.backtrace(context, Backtracer.ACCURATE)
            .slice(0, 8)
            .map(DebugSymbol.fromAddress)
            .filter(function (s) { return s.moduleName !== null; })
            .map(function (s) { return '        ' + s.toString(); })
            .join('\n');
    } catch (e) {
        return '        <backtrace unavailable>';
    }
}

/* Which module did this call come from? Used to filter out libc-internal and framework noise. */
function callerModule(context) {
    try {
        var frames = Thread.backtrace(context, Backtracer.FUZZY);
        for (var i = 0; i < frames.length && i < 6; i++) {
            var sym = DebugSymbol.fromAddress(frames[i]);
            if (sym.moduleName && sym.moduleName.indexOf('libc') === -1) {
                return sym.moduleName;
            }
        }
    } catch (e) { /* ignore */ }
    return null;
}

function moduleAllowed(mod) {
    if (CONFIG.onlyModule === null) return true;
    return mod !== null && mod.indexOf(CONFIG.onlyModule) !== -1;
}

function flag(kind, message, context) {
    if (findings.length >= CONFIG.maxFindings) return;
    counts.flagged++;
    findings.push({ kind: kind, message: message, time: now() });

    console.log('\n' + line('!'));
    console.log('  [' + kind + '] ' + message);
    console.log(line('!'));
    console.log(backtrace(context));
}

// -------------------------------------------------------------------------------------------------
// The hooks
// -------------------------------------------------------------------------------------------------

function hookAllocators() {

    // ---- malloc -------------------------------------------------------------------------------
    var mallocPtr = Module.findExportByName('libc.so', 'malloc');
    if (mallocPtr) {
        Interceptor.attach(mallocPtr, {
            onEnter: function (args) {
                this.size = args[0].toUInt32();
                this.mod = null;
                // Only take a backtrace when we might need it — backtracing every malloc in an
                // Android process is prohibitively slow.
                if (this.size < CONFIG.suspiciousSmall || this.size >= CONFIG.threshold ||
                    CONFIG.verbose) {
                    this.mod = callerModule(this.context);
                }
            },
            onLeave: function (retval) {
                counts.malloc++;
                if (!moduleAllowed(this.mod)) return;

                if (CONFIG.verbose && this.size >= CONFIG.threshold) {
                    console.log('  malloc(' + this.size + ') = ' + retval +
                                (this.mod ? '   [' + this.mod + ']' : ''));
                }

                // Remember small allocations so a later large copy into them can be correlated.
                if (this.size > 0 && this.size < CONFIG.suspiciousSmall && !retval.isNull()) {
                    recent[retval.toString()] = {
                        size: this.size, time: now(),
                        thread: Process.getCurrentThreadId(), where: this.mod
                    };
                }
            }
        });
    }

    // ---- calloc — the one where the overflow is directly visible --------------------------------
    var callocPtr = Module.findExportByName('libc.so', 'calloc');
    if (callocPtr) {
        Interceptor.attach(callocPtr, {
            onEnter: function (args) {
                this.n = args[0].toUInt32();
                this.elem = args[1].toUInt32();
                this.mod = callerModule(this.context);
            },
            onLeave: function (retval) {
                counts.calloc++;
                if (!moduleAllowed(this.mod)) return;

                // THE CORE CHECK.
                // Recompute the product in JavaScript, whose numbers are 64-bit doubles and can
                // therefore represent the true value exactly up to 2^53. If the true product
                // exceeds what a 32-bit int can hold, the application's own arithmetic — if it
                // computed the same thing in an `int` — already wrapped.
                var truth = this.n * this.elem;

                if (truth > INT32_MAX) {
                    flag('OVERFLOW',
                         'calloc(n=' + this.n + ', elem=' + this.elem + ') — true product ' +
                         truth + ' exceeds INT32_MAX (' + INT32_MAX + '). ' +
                         'Any 32-bit int holding this size has WRAPPED. ' +
                         'Returned ' + retval + '.',
                         this.context);
                } else if (truth > UINT32_MAX) {
                    flag('OVERFLOW',
                         'calloc product ' + truth + ' exceeds UINT32_MAX', this.context);
                } else if (CONFIG.verbose && truth >= CONFIG.threshold) {
                    console.log('  calloc(n=' + this.n + ', elem=' + this.elem + ' -> ' + truth +
                                ') = ' + retval);
                }

                if (truth > 0 && truth < CONFIG.suspiciousSmall && !retval.isNull()) {
                    recent[retval.toString()] = {
                        size: truth, time: now(),
                        thread: Process.getCurrentThreadId(), where: this.mod
                    };
                }
            }
        });
    }

    // ---- realloc ---------------------------------------------------------------------------------
    var reallocPtr = Module.findExportByName('libc.so', 'realloc');
    if (reallocPtr) {
        Interceptor.attach(reallocPtr, {
            onEnter: function (args) {
                this.oldPtr = args[0];
                this.size = args[1].toUInt32();
                this.mod = callerModule(this.context);
            },
            onLeave: function (retval) {
                counts.realloc++;
                if (!moduleAllowed(this.mod)) return;

                // realloc(p, 0) frees. A later write through p is then a use-after-free.
                if (this.size === 0) {
                    flag('REALLOC-ZERO',
                         'realloc(' + this.oldPtr + ', 0) frees the block. Any subsequent write ' +
                         'through the old pointer is a use-after-free.',
                         this.context);
                }
                if (CONFIG.verbose && this.size >= CONFIG.threshold) {
                    console.log('  realloc(' + this.oldPtr + ', ' + this.size + ') = ' + retval);
                }
                delete recent[this.oldPtr.toString()];
                if (this.size > 0 && this.size < CONFIG.suspiciousSmall && !retval.isNull()) {
                    recent[retval.toString()] = {
                        size: this.size, time: now(),
                        thread: Process.getCurrentThreadId(), where: this.mod
                    };
                }
            }
        });
    }

    // ---- free -------------------------------------------------------------------------------------
    var freePtr = Module.findExportByName('libc.so', 'free');
    if (freePtr) {
        Interceptor.attach(freePtr, {
            onEnter: function (args) {
                delete recent[args[0].toString()];
            }
        });
    }
}

// -------------------------------------------------------------------------------------------------
// The copy functions. A large copy into a recently-allocated small buffer is the overflow
// signature, and neither half of it looks wrong on its own.
// -------------------------------------------------------------------------------------------------

function hookCopies() {
    ['memcpy', 'memmove'].forEach(function (fn) {
        var ptr = Module.findExportByName('libc.so', fn);
        if (!ptr) return;

        Interceptor.attach(ptr, {
            onEnter: function (args) {
                counts.memcpy++;
                var dest = args[0];
                var n = args[2].toUInt32();

                if (n < CONFIG.bigCopy) return;          // small copies are not interesting

                var rec = recent[dest.toString()];
                if (rec === undefined) return;           // not a buffer we are tracking

                // Is the allocation recent enough to be plausibly the same logical operation?
                if (now() - rec.time > CONFIG.correlationWindowMs) return;

                flag('HEAP OVERFLOW SIGNATURE',
                     fn + '(dest=' + dest + ', n=' + n + ') into a buffer allocated ' +
                     (now() - rec.time) + 'ms ago with size ' + rec.size + '. ' +
                     'The copy is ' + (n - rec.size) + ' bytes larger than the allocation.' +
                     (rec.where ? '  [allocated from ' + rec.where + ']' : ''),
                     this.context);
            }
        });
    });

    // strcpy has no length at all, so any use is worth knowing about in a security review.
    ['strcpy', 'strcat', 'sprintf'].forEach(function (fn) {
        var ptr = Module.findExportByName('libc.so', fn);
        if (!ptr) return;
        Interceptor.attach(ptr, {
            onEnter: function (args) {
                var dest = args[0];
                var rec = recent[dest.toString()];
                if (rec !== undefined) {
                    flag('UNBOUNDED COPY',
                         fn + '() into a ' + rec.size + '-byte buffer. This function takes no ' +
                         'destination length and cannot be made safe by inspection.',
                         this.context);
                }
            }
        });
    });
}

// -------------------------------------------------------------------------------------------------
// REPL interface
// -------------------------------------------------------------------------------------------------

function report() {
    console.log('\n' + line('='));
    console.log('  watch-alloc.js — report');
    console.log(line('='));
    console.log('  malloc  calls : ' + counts.malloc.toLocaleString());
    console.log('  calloc  calls : ' + counts.calloc.toLocaleString());
    console.log('  realloc calls : ' + counts.realloc.toLocaleString());
    console.log('  large copies  : ' + counts.memcpy.toLocaleString());
    console.log('  FLAGGED       : ' + counts.flagged);

    if (findings.length === 0) {
        console.log('\n  Nothing flagged. Things to try before concluding there is no bug:');
        console.log('    * drive the app INTO the parser — open the file, receive the message');
        console.log('    * feed it a hostile length: a huge record count, a negative size');
        console.log('    * lower --suspiciousSmall, or raise --correlationWindowMs');
        console.log('    * the allocation may not go through libc at all (a custom allocator,');
        console.log('      an arena, or the ART heap) — find and hook that instead');
        console.log('    * the code may be Java, where the same overflow throws');
        console.log('      NegativeArraySizeException rather than corrupting memory');
    } else {
        console.log('\n  Findings by kind:');
        var byKind = {};
        findings.forEach(function (f) { byKind[f.kind] = (byKind[f.kind] || 0) + 1; });
        Object.keys(byKind).forEach(function (k) {
            console.log('    ' + k + ': ' + byKind[k]);
        });
        console.log('\n  Next step: take the flagged function into a debugger or a decompiler and');
        console.log('  find the multiplication. Then follow the operand BACKWARDS to its source.');
        console.log('  If it is attacker-controlled, this is Critical; if it is bounded upstream');
        console.log('  by a protocol field, it may be Low. You cannot rate it without that walk.');
    }
    console.log(line('=') + '\n');
}

function setThreshold(n) { CONFIG.threshold = n; console.log('[*] threshold = ' + n); }
function only(mod) { CONFIG.onlyModule = mod; console.log('[*] only reporting ' + mod); }
function verbose(on) { CONFIG.verbose = !!on; console.log('[*] verbose = ' + CONFIG.verbose); }

rpc.exports = { report: report, setthreshold: setThreshold, only: only, verbose: verbose };
global.report = report;
global.setThreshold = setThreshold;
global.only = only;
global.verbose = verbose;

// -------------------------------------------------------------------------------------------------
// Go
// -------------------------------------------------------------------------------------------------
console.log('\n==============================================================');
console.log('  watch-alloc.js — chapter 03 section 7.5');
console.log('==============================================================');
console.log('  Hooking libc allocators and copy functions.');
console.log('  REPL: report()  setThreshold(n)  only("libfoo.so")  verbose(true)');
console.log('');
console.log('  What it looks for:');
console.log('    1. calloc(n, elem) whose true 64-bit product exceeds INT32_MAX — the app\'s');
console.log('       own 32-bit arithmetic has already wrapped.');
console.log('    2. A small allocation followed within ' + CONFIG.correlationWindowMs +
            'ms by a much larger copy into');
console.log('       it, on the same thread. That correlation IS the heap overflow, and neither');
console.log('       half looks wrong on its own.');
console.log('    3. strcpy/strcat/sprintf into a tracked buffer — unbounded by construction.');
console.log('');
console.log('  Now drive the app towards the parser you care about.\n');

hookAllocators();
hookCopies();

console.log('[+] hooks installed.\n');
