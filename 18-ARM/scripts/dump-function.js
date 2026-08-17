// dump-function.js -- disassemble a native function AS IT EXISTS IN MEMORY,
//                     print its AAPCS64 argument registers on entry and its
//                     return value on exit, and dump the bytes to a file.
//
// HOW TO RUN
//     # host -- by exported symbol name
//     frida -U -f com.example.target -l dump-function.js --no-pause \
//           -P '{"module":"libnative.so","symbol":"lc_verify_signature"}'
//
//     # host -- by module offset, for a function with no symbol
//     frida -U -f com.example.target -l dump-function.js --no-pause \
//           -P '{"module":"libnative.so","offset":"0x48d0","count":40}'
//
//     # host -- attach to something already running
//     frida -U -n com.example.target -l dump-function.js \
//           -P '{"module":"libnative.so","symbol":"lc_is_licensed"}'
//
//     # Frida REPL, after loading -- re-dump without restarting
//     rpc.exports.dump("libnative.so", "0x48d0", 30)
//     rpc.exports.save("libnative.so", "0x48d0", 512)      // -> /data/local/tmp
//     rpc.exports.trace("libnative.so", "lc_verify_signature")
//
// WHY THIS EXISTS, AND WHY A STATIC DISASSEMBLY IS NOT ENOUGH
//     The bytes on disk and the bytes in memory are not always the same. A
//     packed library decrypts itself in a constructor; a self-modifying check
//     rewrites its own comparison; another hooking framework may already have
//     overwritten the first instructions with a trampoline. Disassembling the
//     live process is the only way to know what the CPU will actually execute.
//     It also gives you the LOAD BASE, which is the number every Ghidra
//     address has to be corrected by.
//
// WHAT IT PRINTS
//     - the module base and the file-relative offset, both directions
//     - Instruction.parse output for `count` instructions, which is Capstone,
//       the same engine radare2 and many others use
//     - on --trace: x0..x7 on entry, decoded as AAPCS64 says to, and x0 on
//       exit. It cannot know the real prototype, so it prints each register
//       three ways -- as an integer, as a pointer, and as a C string if the
//       memory reads as one -- and lets you decide.
//
// REQUIREMENTS
//     Frida 14 or newer on the host, frida-server of the matching version
//     running on the device. Root is needed for frida-server in the usual
//     way; see 53-Frida. AArch64 device. Nothing else.
//
// WHAT THIS WILL *NOT* TELL YOU
//     - What the function means. It gives you instructions and register
//       values. Turning those into a decompiled function is 57-Ghidra.
//     - The correct prototype. It guesses nothing. `x1` holding 17 might be a
//       length, an enum or a pointer that happens to be tiny. AAPCS64 tells
//       you WHERE arguments are, never WHAT they are.
//     - Whether the function is the interesting one. Finding that out is
//       what `trace` and a lot of patience are for.
//     - Anything on ARM32. Instruction.parse handles Thumb, but the argument
//       register set is r0..r3 and this script prints x0..x7. Read section
//       3.13 before you trust the entry dump on a 32-bit target.
//     - Whether your hook is stable. Attaching to the FIRST instruction of a
//       function that another tool has already trampolined gives you nonsense.
//       The disassembly will show it -- an unexpected `ldr x16` / `br x16` at
//       the entry point is somebody else's hook, not the app's code.

'use strict';

var PARAMS = (typeof parameters !== 'undefined' && parameters) ? parameters : {};

// ---------------------------------------------------------------------------
// Address plumbing. Everything else depends on getting this right.
// ---------------------------------------------------------------------------

function moduleOf(name) {
    var m = Process.findModuleByName(name);
    if (m === null) {
        throw new Error('module not loaded: ' + name +
                        '. Loaded modules matching: ' +
                        Process.enumerateModules()
                            .map(function (x) { return x.name; })
                            .filter(function (x) {
                                return x.indexOf(name.replace('.so', '')) >= 0;
                            }).join(', ') || '(none)');
    }
    return m;
}

function resolve(moduleName, symbol, offset) {
    var m = moduleOf(moduleName);
    var addr;
    if (symbol) {
        addr = Module.findExportByName(moduleName, symbol);
        if (addr === null) {
            // Not exported. It may still be in .symtab on an unstripped build,
            // which enumerateSymbols reads and findExportByName does not.
            var hit = m.enumerateSymbols().filter(function (s) {
                return s.name === symbol;
            });
            if (hit.length === 0) {
                throw new Error('symbol not found in ' + moduleName + ': ' +
                                symbol + '. It may be hidden (see ' +
                                '15-Native-Code section 3.6) -- use offset.');
            }
            addr = hit[0].address;
        }
    } else if (offset !== undefined && offset !== null) {
        addr = m.base.add(ptr(offset));
    } else {
        throw new Error('give either symbol or offset');
    }
    return { module: m, address: addr, offset: addr.sub(m.base) };
}

// ---------------------------------------------------------------------------
// Disassembly
// ---------------------------------------------------------------------------

function dump(moduleName, symbolOrOffset, count) {
    count = count || 24;
    var isOffset = typeof symbolOrOffset === 'string' &&
                   symbolOrOffset.indexOf('0x') === 0;
    var r = isOffset
        ? resolve(moduleName, null, symbolOrOffset)
        : resolve(moduleName, symbolOrOffset, null);

    console.log('');
    console.log('module      : ' + r.module.name + '  ' + r.module.path);
    console.log('base        : ' + r.module.base +
                '   size 0x' + r.module.size.toString(16));
    console.log('address     : ' + r.address);
    console.log('offset      : 0x' + r.offset.toString(16) +
                '   <- type this into Ghidra (plus its image base)');
    console.log('');

    // Are the pages even readable? A packed library may not be decrypted yet.
    var prot = Process.findRangeByAddress(r.address);
    console.log('protection  : ' + (prot ? prot.protection : '(unmapped!)'));
    console.log('');

    var p = r.address;
    for (var i = 0; i < count; i++) {
        var insn;
        try {
            insn = Instruction.parse(p);
        } catch (e) {
            console.log('  ' + p + '  <undecodable: ' + e.message + '>');
            break;
        }
        var raw = Array.prototype.slice
            .call(new Uint8Array(p.readByteArray(insn.size)))
            .map(function (b) {
                return ('0' + b.toString(16)).slice(-2);
            }).join(' ');
        var rel = p.sub(r.module.base);
        console.log('  +0x' + pad(rel.toString(16), 6) + '  ' + p + '  ' +
                    pad(raw, 12) + '  ' + insn.mnemonic + '\t' + insn.opStr);
        // `ret` almost always ends the function; stop there unless the caller
        // asked for more. It is a heuristic, not a rule -- a function with
        // several returns keeps going.
        p = insn.next;
    }
    console.log('');
    return r.offset.toString();
}

function pad(s, n) {
    while (s.length < n) { s += ' '; }
    return s;
}

// ---------------------------------------------------------------------------
// Save the live bytes, for loading into Ghidra as a raw binary.
// ---------------------------------------------------------------------------

function save(moduleName, symbolOrOffset, length) {
    length = length || 1024;
    var isOffset = typeof symbolOrOffset === 'string' &&
                   symbolOrOffset.indexOf('0x') === 0;
    var r = isOffset
        ? resolve(moduleName, null, symbolOrOffset)
        : resolve(moduleName, symbolOrOffset, null);

    var out = '/data/local/tmp/' + moduleName + '_0x' +
              r.offset.toString(16) + '.bin';
    var f = new File(out, 'wb');
    f.write(r.address.readByteArray(length));
    f.flush();
    f.close();
    console.log('wrote ' + length + ' bytes from ' + r.address + ' to ' + out);
    console.log('pull it with:  adb pull ' + out);
    console.log('then in Ghidra: File > Import, format "Raw Binary", ' +
                'language AARCH64:LE:64:v8A, base address 0x' +
                r.offset.toString(16));
    return out;
}

// ---------------------------------------------------------------------------
// Entry/exit register trace, decoded the way AAPCS64 says to read it.
// ---------------------------------------------------------------------------

function describe(v) {
    if (v.isNull()) { return 'NULL'; }
    var parts = [v.toString(), 'dec=' + v.toInt32()];
    try {
        var s = v.readUtf8String(64);
        if (s !== null && s.length > 0 && /^[\x20-\x7e]*$/.test(s)) {
            parts.push('str=' + JSON.stringify(s));
        }
    } catch (e) { /* not a readable string; entirely normal */ }
    return parts.join('  ');
}

function trace(moduleName, symbolOrOffset, nargs) {
    nargs = (nargs === undefined) ? 4 : nargs;
    var isOffset = typeof symbolOrOffset === 'string' &&
                   symbolOrOffset.indexOf('0x') === 0;
    var r = isOffset
        ? resolve(moduleName, null, symbolOrOffset)
        : resolve(moduleName, symbolOrOffset, null);

    Interceptor.attach(r.address, {
        onEnter: function (args) {
            console.log('');
            console.log('>>> ' + moduleName + '+0x' + r.offset.toString(16) +
                        '  thread ' + this.threadId);
            console.log('    lr (x30, caller) : ' + this.returnAddress +
                        '   ' + DebugSymbol.fromAddress(this.returnAddress));
            for (var i = 0; i < nargs && i < 8; i++) {
                console.log('    x' + i + ' : ' + describe(this.context['x' + i]));
            }
        },
        onLeave: function (retval) {
            console.log('<<< returned x0 = ' + describe(ptr(retval.toString())));
        }
    });
    console.log('tracing ' + moduleName + '+0x' + r.offset.toString(16));
}

// ---------------------------------------------------------------------------

rpc.exports = {
    dump: dump,
    save: save,
    trace: trace
};

if (Process.arch !== 'arm64') {
    console.log('[!] Process.arch is "' + Process.arch +
                '", not arm64. The register names below are AArch64 and this ' +
                'script will be misleading. See README section 3.13.');
}

if (PARAMS.module) {
    var target = PARAMS.symbol || PARAMS.offset;
    var go = function () {
        try {
            dump(PARAMS.module, target, PARAMS.count);
            if (PARAMS.trace) { trace(PARAMS.module, target, PARAMS.nargs); }
        } catch (e) {
            console.log('[!] ' + e.message);
        }
    };
    // If the library is not loaded yet -- the usual case with -f -- wait for
    // the linker to finish with it rather than failing immediately.
    if (Process.findModuleByName(PARAMS.module) !== null) {
        go();
    } else {
        console.log('[.] waiting for ' + PARAMS.module + ' to be loaded...');
        var dlopen = Module.findExportByName(null, 'android_dlopen_ext') ||
                     Module.findExportByName(null, 'dlopen');
        Interceptor.attach(dlopen, {
            onEnter: function (a) { this.path = a[0].readCString(); },
            onLeave: function () {
                if (this.path && this.path.indexOf(PARAMS.module) >= 0) {
                    go();
                }
            }
        });
    }
} else {
    console.log('[.] loaded. Call rpc.exports.dump("libfoo.so", "0x1234", 30)');
}
