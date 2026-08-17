/*
 * scripts/dataflow-watch.js
 *
 * PURPOSE
 *   Follow a value from where it is PRODUCED to where it is CONSUMED, when no
 *   call edge connects the two.
 *
 *   This is the technique 37-RootDetection's lab 04 defers to chapter 68:
 *
 *       "when detection is decoupled from consequence, the general tool is
 *        data-flow tracking, not control-flow tracking. Your instinct to look
 *        for branches is what the pattern defeats."
 *
 *   The shape of the problem: some function computes a byte, an int or a
 *   pointer and stores it. Hundreds of instructions later, in another function,
 *   something reads it and decides. Reading the code does not connect them,
 *   because the connection is a memory address rather than a call. Hooking
 *   every plausible consumer is guesswork.
 *
 *   So: hook the producer, learn the ADDRESS it writes to, then watch that
 *   address and take a backtrace on the first read. The backtrace is the
 *   consumer you could not find.
 *
 * USAGE
 *   All configuration is in the CONFIG block below -- edit it, then:
 *
 *     # host -- ALWAYS -D <serial>; -U picks a device for you (section 7.5)
 *     frida -D <serial> -f com.example.target -l dataflow-watch.js
 *
 *     # host -- against a plain native process rather than an app
 *     frida -D <serial> -n investigate -l dataflow-watch.js
 *
 *   Three modes, chosen with CONFIG.mode:
 *
 *     'poll'    Read the address on a timer. Cheapest, always works, gives you
 *               NO backtrace -- only proof that the value changes and when.
 *     'monitor' MemoryAccessMonitor: mark the page inaccessible and trap the
 *               fault. Gives a backtrace. Page-granular, so noisy, and slow.
 *     'both'    Poll for the value, monitor for the consumer. The default.
 *
 * WORKED EXAMPLE -- the chapter's fixture
 *   iv_derive_seed() writes one byte into a global; iv_open_vault() reads it
 *   and compares against 0xbd. Nothing calls between them. With:
 *
 *     producerModule: 'libinvestigate.so', producerSymbol: 'iv_derive_seed',
 *     watchModule:    'libinvestigate.so', watchOffset: null   // auto-discover
 *
 *   the first read traps inside iv_open_vault at the `ldrb`, which is exactly
 *   the edge the disassembly does not draw. See chapter 68 section 9.3.
 *
 * WHAT THIS DOES NOT ESTABLISH -- put this in your residue
 *   * MemoryAccessMonitor is PAGE granular. Any access to any byte on the same
 *     page traps, so unrelated hits are expected. Filter by offset.
 *   * A consumer that reads the value BEFORE the watch is armed is missed
 *     entirely. Arm early, and say when you armed it.
 *   * Marking a hot page inaccessible changes timing enough that the app is,
 *     briefly, a different program. If a result appears ONLY under the monitor,
 *     treat it as inconclusive until you reproduce it another way.
 *   * Frida re-arms after each fault in this script; between the fault and the
 *     re-arm, reads are not observed.
 *
 * ETHICS
 *   Apps you own, are authorised to test, or purpose-built targets only.
 */

'use strict';

/* ----------------------------- CONFIG ----------------------------------- */
var CONFIG = {
    mode: 'both',                       // 'poll' | 'monitor' | 'both'

    // The producer: a native export whose call we hook.
    producerModule: 'libinvestigate.so',
    producerSymbol: 'iv_derive_seed',

    // The address to watch. Either give an explicit module+offset, or leave
    // watchOffset null and let discoverWrites() find what the producer touched.
    watchModule: 'libinvestigate.so',
    watchOffset: null,                  // e.g. 0x4011, or null to auto-discover

    // Size of the value in bytes (1, 2, 4 or 8).
    valueSize: 1,

    // Where auto-discovery looks: the module's writable data sections are
    // snapshotted before and after the producer runs, and the diff is the
    // candidate set. Keep this modest -- it is a byte-for-byte compare.
    discoverMaxBytes: 64 * 1024,

    pollIntervalMs: 250,
    reportAfterMs: 30000,
    maxBacktraces: 8
};
/* ------------------------------------------------------------------------ */

var state = {
    watchPtr: null,
    lastValue: null,
    changes: 0,
    reads: 0,
    backtraces: 0,
    armed: false,
    producerCalls: 0,
    warnedNoWrite: false
};

function log(s) { console.log('[dfw] ' + s); }

function readValue(p) {
    try {
        switch (CONFIG.valueSize) {
            case 1: return p.readU8();
            case 2: return p.readU16();
            case 4: return p.readU32();
            case 8: return p.readU64().toString();
            default: return p.readU8();
        }
    } catch (e) {
        return null;
    }
}

/* ---------------------- writable-region snapshotting -------------------- */
function writableRegionsOf(moduleName) {
    var mod = Process.findModuleByName(moduleName);
    if (!mod) return [];
    var out = [];
    Process.enumerateRanges('rw-').forEach(function (r) {
        if (r.base.compare(mod.base) >= 0 &&
            r.base.compare(mod.base.add(mod.size)) < 0) {
            out.push({ base: r.base,
                       size: Math.min(r.size, CONFIG.discoverMaxBytes) });
        }
    });
    return out;
}

function snapshot(regions) {
    return regions.map(function (r) {
        try { return r.base.readByteArray(r.size); }
        catch (e) { return null; }
    });
}

function diffSnapshots(regions, before, after) {
    var changed = [];
    for (var i = 0; i < regions.length; i++) {
        if (!before[i] || !after[i]) continue;
        var b = new Uint8Array(before[i]);
        var a = new Uint8Array(after[i]);
        for (var j = 0; j < b.length && j < a.length; j++) {
            if (b[j] !== a[j]) {
                changed.push({ ptr: regions[i].base.add(j),
                               from: b[j], to: a[j] });
                if (changed.length > 64) return changed;   // enough
            }
        }
    }
    return changed;
}

/* ------------------------------ the watch ------------------------------- */
function arm() {
    if (CONFIG.mode === 'poll') { state.armed = true; return; }
    if (typeof MemoryAccessMonitor === 'undefined') {
        log('MemoryAccessMonitor unavailable on this platform -- poll only');
        return;
    }
    try {
        MemoryAccessMonitor.enable(
            { base: state.watchPtr, size: CONFIG.valueSize },
            {
                onAccess: function (details) {
                    state.reads++;
                    if (state.backtraces < CONFIG.maxBacktraces) {
                        state.backtraces++;
                        log('ACCESS #' + state.reads + ' ' + details.operation +
                            ' at ' + details.address + ' from ' + details.from);
                        log('  backtrace -- THIS is the consumer:');
                        Thread.backtrace(details.context, Backtracer.ACCURATE)
                            .map(DebugSymbol.fromAddress)
                            .forEach(function (sym) { log('    ' + sym); });
                    }
                    // Re-arm; reads between the fault and here are not seen.
                    setTimeout(arm, 0);
                }
            });
        state.armed = true;
        log('watch armed at ' + state.watchPtr + ' (' + CONFIG.valueSize + ' B)');
    } catch (e) {
        log('could not arm MemoryAccessMonitor: ' + e.message);
    }
}

function startPolling() {
    setInterval(function () {
        if (!state.watchPtr) return;
        var v = readValue(state.watchPtr);
        if (v === null) return;
        if (state.lastValue === null) {
            state.lastValue = v;
            log('initial value = ' + v);
        } else if (v !== state.lastValue) {
            state.changes++;
            log('VALUE CHANGED ' + state.lastValue + ' -> ' + v);
            state.lastValue = v;
        }
    }, CONFIG.pollIntervalMs);
}

/* ------------------------------- producer ------------------------------- */
function hookProducer() {
    var addr;
    try {
        addr = Module.getExportByName(CONFIG.producerModule, CONFIG.producerSymbol);
    } catch (e) {
        log('producer export ' + CONFIG.producerSymbol + ' not found in ' +
            CONFIG.producerModule + '.');
        log('  If the symbol is absent the function may be static or stripped;');
        log('  set watchOffset explicitly and skip auto-discovery.');
        return false;
    }
    log('producer ' + CONFIG.producerSymbol + ' @ ' + addr);

    var regions = writableRegionsOf(CONFIG.watchModule);
    var before = null;

    Interceptor.attach(addr, {
        onEnter: function () {
            state.producerCalls++;
            if (!state.watchPtr && CONFIG.watchOffset === null) {
                before = snapshot(regions);
            }
        },
        onLeave: function () {
            if (state.watchPtr || CONFIG.watchOffset !== null || !before) return;

            var after = snapshot(regions);
            var changed = diffSnapshots(regions, before, after);
            before = null;

            if (!changed.length) {
                // Say this ONCE. A hot producer would otherwise bury the run in
                // identical lines -- which is what happened the first time this
                // script was tested against a libc export called on every frame.
                if (!state.warnedNoWrite) {
                    state.warnedNoWrite = true;
                    log('producer returned but wrote nothing in ' +
                        CONFIG.watchModule + "'s writable ranges.");
                    log('  It may write to the heap, to another module, or the');
                    log('  value may be unchanged. Not a failure -- but if this');
                    log('  persists, set watchOffset explicitly instead of');
                    log('  relying on auto-discovery. (Reported once per run.)');
                }
                return;
            }
            log('producer wrote to ' + changed.length + ' byte(s):');
            changed.slice(0, 8).forEach(function (c) {
                log('   ' + c.ptr + '  0x' + c.from.toString(16) +
                    ' -> 0x' + c.to.toString(16));
            });
            state.watchPtr = changed[0].ptr;
            log('watching ' + state.watchPtr +
                ' (first changed byte -- override with watchOffset if wrong)');
            arm();
        }
    });
    return true;
}

/* --------------------------------- main --------------------------------- */
function main() {
    if (CONFIG.watchOffset !== null) {
        var mod = Process.findModuleByName(CONFIG.watchModule);
        if (!mod) {
            log('module ' + CONFIG.watchModule + ' not loaded yet.');
            log('  Spawn with -f and let it load, or hook dlopen first.');
            return;
        }
        state.watchPtr = mod.base.add(CONFIG.watchOffset);
        log('watching explicit address ' + state.watchPtr);
        arm();
    }

    hookProducer();

    if (CONFIG.mode === 'poll' || CONFIG.mode === 'both') startPolling();

    setTimeout(function () {
        log('--- report ---');
        log('producer calls observed : ' + state.producerCalls);
        log('watch armed             : ' + state.armed);
        log('value changes seen      : ' + state.changes);
        log('accesses trapped        : ' + state.reads);
        if (!state.producerCalls) {
            log('');
            log('ZERO producer calls. That is not yet a result -- a silent run');
            log('and a broken hook look identical. Confirm the hook fires at');
            log('all before recording this. Chapter 68 section 7.2.');
        }
        if (state.armed && !state.reads) {
            log('');
            log('Armed but never trapped. Either nothing read the value in the');
            log('window, or the consumer read it before the watch was armed.');
            log('Both belong in the residue; neither is proof of absence.');
        }
    }, CONFIG.reportAfterMs);
}

setTimeout(function () { main(); }, 0);

rpc.exports = {
    snapshot: function () { return state; },
    setWatch: function (addrString) {
        state.watchPtr = ptr(addrString);
        arm();
        return state.watchPtr.toString();
    }
};
