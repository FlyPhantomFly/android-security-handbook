// native-map.js -- connect the ELF file on your disk to the mapping in a live
//                  process, and show what Module.findExportByName is searching.
//
// PURPOSE
//     Chapter 15 is about a file. This script is about the same bytes after the
//     dynamic linker has finished with them. It prints, for every native
//     library in a running app:
//
//       - the load base, so you can convert a link-time address you noted in
//         Ghidra into a runtime address and back:
//             runtime = base + file_virtual_address
//             file    = runtime - base
//       - the mapped ranges and their permissions, which is the PT_LOAD table
//         from the file as the kernel actually realised it
//       - the export table Frida searches by name -- this IS .dynsym, nothing
//         more and nothing less, which is why a stripped library still
//         resolves and why a hidden-visibility function never does
//       - the imports, and the GOT slot each one currently points at, so you
//         can watch full RELRO and lazy binding behave differently
//       - which pages are writable and executable at the same time, which no
//         library should have and packers routinely create
//
// USAGE
//     # host -- spawn and hold at the first instruction
//     frida -U -f com.example.app -l native-map.js --no-pause
//
//     # host -- attach to something already running
//     frida -U -n com.example.app -l native-map.js
//
//     # then, in the Frida REPL:
//     rpc.exports.modules()                       // every module, base and size
//     rpc.exports.detail('libnative.so')          // ranges, exports, imports
//     rpc.exports.got('libnative.so')             // GOT slots and their targets
//     rpc.exports.find('libnative.so', 'strcpy')  // what findExportByName does
//     rpc.exports.wx()                            // writable+executable pages
//     rpc.exports.watchload()                     // report every future dlopen
//
// REQUIREMENTS
//     frida-tools on the host, a matching frida-server on the device, and root
//     or a debuggable app. Chapter 53 covers getting there. Nothing in this
//     script is Android-specific except the paths it recognises.
//
// WHAT THIS WILL *NOT* TELL YOU
//     - Whether a function is ever CALLED. An export is an offer. Use an
//         Interceptor to find out, or Stalker for coverage (53-Frida).
//     - The name of a function that is not exported. Internal functions in a
//         stripped library have no name at run time, in any tool. You find them
//         by offset from a known export, and the offset comes from static
//         analysis (57-Ghidra).
//     - Anything about Java. The Java side of the boundary is 16-JNI's subject.
//     - The truth, if the process is defending itself. A library can hide
//         itself from the linker's module list by unlinking its link_map entry,
//         and this script reads that same list. If a module you know is loaded
//         does not appear here, that absence is itself the finding -- fall back
//         to reading /proc/self/maps, which the loader does not control.
//     - Whether a mitigation applies. RELRO state is inferred from current page
//         permissions, which is an observation about now, not a guarantee.

'use strict';

var ANDROID_SYSTEM_PREFIXES = ['/system/', '/apex/', '/vendor/', '/product/'];

function isAppLibrary(mod) {
    for (var i = 0; i < ANDROID_SYSTEM_PREFIXES.length; i++) {
        if (mod.path.indexOf(ANDROID_SYSTEM_PREFIXES[i]) === 0) return false;
    }
    return true;
}

function hex(x) {
    return '0x' + x.toString(16);
}

function protOf(addr) {
    try {
        var r = Process.findRangeByAddress(addr);
        return r ? r.protection : '???';
    } catch (e) {
        return '???';
    }
}

// ---------------------------------------------------------------------------
// modules
// ---------------------------------------------------------------------------

function listModules(appOnly) {
    var out = [];
    Process.enumerateModules().forEach(function (m) {
        if (appOnly && !isAppLibrary(m)) return;
        out.push({
            name: m.name,
            base: m.base.toString(),
            size: m.size,
            end: m.base.add(m.size).toString(),
            path: m.path
        });
    });
    return out;
}

function printModules(appOnly) {
    var mods = listModules(appOnly);
    console.log('\n=== modules (' + mods.length + ') ===');
    console.log('base'.padEnd(20) + 'size'.padEnd(12) + 'name');
    mods.forEach(function (m) {
        console.log(m.base.padEnd(20) + String(m.size).padEnd(12) + m.name);
    });
    console.log('\nTo convert an address you noted in a decompiler:');
    console.log('  runtime = base + file_virtual_address');
    console.log('The decompiler shows file virtual addresses because the file');
    console.log('is ET_DYN and has no fixed load address. See README 3.4.\n');
    return mods;
}

// ---------------------------------------------------------------------------
// one module in detail
// ---------------------------------------------------------------------------

function detail(name) {
    var m = Process.findModuleByName(name);
    if (m === null) {
        console.log('no module named ' + name + '. Try rpc.exports.modules().');
        return null;
    }
    console.log('\n=== ' + m.name + ' ===');
    console.log('path      ' + m.path);
    console.log('base      ' + m.base);
    console.log('size      ' + m.size + ' (' + hex(m.size) + ')');

    console.log('\n-- mapped ranges (the PT_LOAD table, as realised) --');
    Process.enumerateRanges('---').forEach(function (r) {
        if (r.base < m.base || r.base >= m.base.add(m.size)) return;
        var off = r.base.sub(m.base);
        console.log('  ' + r.base + '  +' + hex(off.toInt32()).padEnd(10) +
                    r.protection + '  ' + r.size + ' bytes' +
                    (r.file ? '  ' + r.file.path : ''));
    });

    var exps = m.enumerateExports();
    var funcs = exps.filter(function (e) { return e.type === 'function'; });
    var vars_ = exps.filter(function (e) { return e.type !== 'function'; });
    console.log('\n-- exports: ' + exps.length + ' (' + funcs.length +
                ' functions, ' + vars_.length + ' variables) --');
    console.log('This list is .dynsym. It is what findExportByName searches.');
    var jni = funcs.filter(function (e) { return e.name.indexOf('Java_') === 0; });
    if (jni.length) {
        console.log('\n  ' + jni.length + ' statically registered JNI entry points:');
        jni.slice(0, 25).forEach(function (e) {
            console.log('    ' + e.address + '  +' +
                        hex(e.address.sub(m.base).toInt32()).padEnd(10) + e.name);
        });
        if (jni.length > 25) console.log('    ... ' + (jni.length - 25) + ' more');
    } else {
        console.log('\n  no Java_* exports. If this library serves native');
        console.log('  methods, registration is dynamic (RegisterNatives) and');
        console.log('  the mapping exists only at run time -- see 16-JNI.');
    }
    var onload = funcs.filter(function (e) { return e.name === 'JNI_OnLoad'; });
    if (onload.length) {
        console.log('\n  JNI_OnLoad at ' + onload[0].address + '  (+' +
                    hex(onload[0].address.sub(m.base).toInt32()) + ')');
    }

    var imports = m.enumerateImports();
    console.log('\n-- imports: ' + imports.length + ' --');
    var watch = ['strcpy', 'strcat', 'sprintf', 'system', 'popen', 'ptrace',
                 'dlopen', 'dlsym', 'mprotect', 'fork', 'execve', 'syscall',
                 'prctl', '__system_property_get', 'inotify_add_watch'];
    var interesting = imports.filter(function (i) {
        return watch.indexOf(i.name) >= 0;
    });
    if (interesting.length) {
        console.log('  worth reading the call sites of:');
        interesting.forEach(function (i) {
            console.log('    ' + i.name + '  from ' + (i.module || '?') +
                        '  resolved to ' + i.address);
        });
    } else {
        console.log('  none of the usual suspects');
    }
    return {
        name: m.name, base: m.base.toString(), size: m.size,
        exports: exps.length, imports: imports.length, jni: jni.length
    };
}

// ---------------------------------------------------------------------------
// the GOT, live
// ---------------------------------------------------------------------------

function got(name) {
    var m = Process.findModuleByName(name);
    if (m === null) { console.log('no module named ' + name); return null; }
    console.log('\n=== ' + m.name + ' GOT, as it stands right now ===');
    console.log('Each import below is currently pointing somewhere. Where it');
    console.log('points is the question that separates lazy binding, full');
    console.log('RELRO, and a library someone has already hooked.\n');
    var rows = [];
    m.enumerateImports().forEach(function (imp) {
        if (imp.slot === undefined || imp.slot === null) return;
        var slot = imp.slot;
        var current;
        try {
            current = Memory.readPointer(slot);
        } catch (e) {
            current = null;
        }
        var target = null;
        if (current !== null) {
            var owner = Process.findModuleByAddress(current);
            target = owner ? (owner.name + '!+' +
                     hex(current.sub(owner.base).toInt32())) : 'unmapped/unknown';
        }
        rows.push({
            name: imp.name,
            slot: slot.toString(),
            slotProt: protOf(slot),
            value: current ? current.toString() : '(unreadable)',
            resolvesTo: target
        });
    });
    rows.slice(0, 60).forEach(function (r) {
        console.log('  ' + r.name.padEnd(28) + ' slot ' + r.slot +
                    ' [' + r.slotProt + '] -> ' + r.resolvesTo);
    });
    var writable = rows.filter(function (r) {
        return r.slotProt.indexOf('w') >= 0;
    });
    console.log('\n  ' + rows.length + ' import slots, ' + writable.length +
                ' currently writable.');
    if (writable.length === 0) {
        console.log('  Every slot is read-only: full RELRO is in effect and');
        console.log('  binding already happened. Overwriting one now needs an');
        console.log('  mprotect first -- which is exactly what Frida does for you.');
    } else {
        console.log('  Writable slots mean partial RELRO or lazy binding. A');
        console.log('  single write redirects every future call through that');
        console.log('  slot, from anywhere in this module. See README 3.8.');
    }
    var foreign = rows.filter(function (r) {
        return r.resolvesTo === 'unmapped/unknown';
    });
    if (foreign.length) {
        console.log('\n  ' + foreign.length + ' slot(s) point outside every known');
        console.log('  module. That is either an anonymous JIT/trampoline page');
        console.log('  or someone got here before you. Investigate each one.');
    }
    return rows;
}

// ---------------------------------------------------------------------------
// findExportByName, explained
// ---------------------------------------------------------------------------

function find(modname, symbol) {
    console.log('\n=== resolving "' + symbol + '" ===');
    var scoped = Module.findExportByName(modname, symbol);
    console.log('Module.findExportByName(' + JSON.stringify(modname) + ', ' +
                JSON.stringify(symbol) + ') = ' + scoped);
    var global_ = Module.findExportByName(null, symbol);
    console.log('Module.findExportByName(null, ' + JSON.stringify(symbol) +
                ') = ' + global_ + '   <- searches EVERY loaded module in order');
    if (scoped !== null && global_ !== null && !scoped.equals(global_)) {
        console.log('\n  THE TWO DISAGREE. More than one loaded library exports');
        console.log('  this name. Passing null gives you whichever the linker');
        console.log('  found first, which is not necessarily the one being');
        console.log('  called by the code you are studying. Always name the');
        console.log('  module when it matters.');
    }
    if (scoped === null) {
        console.log('\n  Not found in ' + modname + '. That means one of:');
        console.log('    - the symbol is not in .dynsym at all (a static or');
        console.log('      hidden-visibility function -- most functions in a');
        console.log('      release library are exactly this)');
        console.log('    - the name is mangled: a C++ symbol is not "decrypt",');
        console.log('      it is something like _ZN6Crypto7decryptEPKc');
        console.log('    - the module name is wrong or not loaded yet');
        console.log('  A stripped library still exports; stripping removes');
        console.log('  .symtab, never .dynsym. See README 3.6.');
        var m = Process.findModuleByName(modname);
        if (m) {
            var near = m.enumerateExports().filter(function (e) {
                return e.name.toLowerCase().indexOf(symbol.toLowerCase()) >= 0;
            });
            if (near.length) {
                console.log('\n  Exports containing that substring:');
                near.slice(0, 15).forEach(function (e) {
                    console.log('    ' + e.address + '  ' + e.name);
                });
            }
        }
        return null;
    }
    var owner = Process.findModuleByAddress(scoped);
    if (owner) {
        console.log('\n  It lives in ' + owner.name + ' at file offset +' +
                    hex(scoped.sub(owner.base).toInt32()) + '.');
        console.log('  Open that library in a decompiler and go to that');
        console.log('  address -- it is the same byte.');
    }
    return scoped.toString();
}

// ---------------------------------------------------------------------------
// writable AND executable pages
// ---------------------------------------------------------------------------

function wx() {
    var hits = Process.enumerateRanges('rwx');
    console.log('\n=== pages that are writable and executable: ' + hits.length +
                ' ===');
    if (hits.length === 0) {
        console.log('None. Expected for an app that is not unpacking or JITing');
        console.log('native code. Note that ART\'s own JIT regions are handled');
        console.log('separately and are not usually rwx simultaneously.');
        return [];
    }
    hits.forEach(function (r) {
        var owner = Process.findModuleByAddress(r.base);
        console.log('  ' + r.base + '  ' + r.size + ' bytes  ' + r.protection +
                    '  ' + (r.file ? r.file.path : (owner ? owner.name :
                            'ANONYMOUS -- allocated at run time')));
    });
    console.log('\nAn anonymous rwx region in an app process is where unpacked');
    console.log('code lives. Dump it and take it to a decompiler:');
    console.log('  var b = Memory.readByteArray(ptr("0x..."), size);');
    console.log('See 57-Ghidra section 7.4 for loading a dump.');
    return hits.map(function (r) {
        return { base: r.base.toString(), size: r.size, file: r.file ? r.file.path : null };
    });
}

// ---------------------------------------------------------------------------
// libraries loaded later
// ---------------------------------------------------------------------------

function watchload() {
    var candidates = ['android_dlopen_ext', 'dlopen', '__loader_dlopen'];
    var hooked = 0;
    candidates.forEach(function (fn) {
        var addr = Module.findExportByName(null, fn);
        if (addr === null) return;
        Interceptor.attach(addr, {
            onEnter: function (args) {
                this.path = args[0].isNull() ? '(null)' : args[0].readCString();
            },
            onLeave: function (retval) {
                console.log('[dlopen] ' + fn + '("' + this.path + '") -> ' +
                            retval);
                if (!retval.isNull() && this.path) {
                    var base = this.path.split('/').pop();
                    var m = Process.findModuleByName(base);
                    if (m) {
                        console.log('         mapped at ' + m.base + ', ' +
                                    m.size + ' bytes, ' +
                                    m.enumerateExports().length + ' exports');
                    }
                }
            }
        });
        hooked++;
    });
    console.log('watching ' + hooked + ' loader entry point(s). Anything the');
    console.log('app loads from now on is reported. A library that appears');
    console.log('here but not in the module list afterwards has unlinked');
    console.log('itself -- see 40-Obfuscation.');
    return hooked;
}

// ---------------------------------------------------------------------------

rpc.exports = {
    modules: function (appOnly) { return printModules(appOnly !== false); },
    all: function () { return printModules(false); },
    detail: detail,
    got: got,
    find: find,
    wx: wx,
    watchload: watchload
};

console.log('[native-map] loaded. Process: ' + Process.id + ', arch ' +
            Process.arch + ', pointer size ' + Process.pointerSize);
console.log('[native-map] try: rpc.exports.modules()');
printModules(true);
