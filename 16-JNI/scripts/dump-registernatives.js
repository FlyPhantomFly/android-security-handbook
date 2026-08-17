/*
 * dump-registernatives.js -- recover dynamically registered JNI methods at runtime.
 *
 * WHAT IT DOES
 *     Hooks ART's RegisterNatives and prints, for every registration the
 *     process performs:
 *
 *         the Java class it is registering against
 *         each method's name
 *         each method's JNI signature
 *         the implementation address, resolved to  module + 0xoffset
 *         the exported symbol name, when the address happens to have one
 *
 *     That mapping is the thing static analysis cannot produce. A library
 *     that registers dynamically exports no Java_* symbol at all, so
 *     `nm -D` shows nothing and the Java class is free to be renamed to
 *     a.b.c by R8. The mapping exists only in memory, and only after
 *     JNI_OnLoad has run.
 *
 * WHY IT ALWAYS WORKS
 *     The name, the signature and the address must be handed to ART in
 *     plaintext, because ART has to look the method up on the class by exact
 *     string comparison. No amount of string encryption, table construction
 *     at runtime, or symbol stripping changes that. The registration call is
 *     a mandatory chokepoint. See ../README.md section 3.8.
 *
 * HOW TO RUN
 *     # SPAWN, do not attach. Registration normally happens during
 *     # System.loadLibrary in a static initialiser, long before you could
 *     # attach to a running process.
 *     frida -U -f com.example.app -l dump-registernatives.js --no-pause
 *
 *     # If the library is loaded later (a button press, a download), attach:
 *     frida -U -n com.example.app -l dump-registernatives.js
 *
 *     # Machine-readable output for diffing against the DEX inventory:
 *     frida -U -f com.example.app -l dump-registernatives.js --no-pause \
 *           -o registrations.txt
 *
 * REQUIREMENTS
 *     frida-server running on the device, matching your frida-tools version.
 *     A rooted device or emulator, or a repackaged debuggable build with
 *     frida-gadget. Tested shape: Android 8 through 16, arm64 and arm32.
 *     No root is needed if you are using the gadget.
 *
 * WHAT THIS WILL NOT TELL YOU
 *     - Statically registered methods. Those never call RegisterNatives.
 *       Enumerate them with `nm -D --defined-only lib.so | grep ' T Java_'`
 *       or with the exports pass this script prints at the end.
 *     - Methods registered before your hook was installed. If you attached
 *       instead of spawning, you have already missed JNI_OnLoad. An empty
 *       result does NOT mean there is no dynamic registration.
 *     - Whether the registered function is the real implementation. A
 *       protector can register a stub that resolves the real target later,
 *       or re-register the same method again afterwards. This script prints
 *       every call, including later ones, so watch for duplicates.
 *     - The return type semantics beyond what the signature string says.
 *     - Anything about @CriticalNative methods' argument layout; those
 *       receive no JNIEnv* and no jclass. Check the DEX annotation.
 *     - What the function does. Take the module+offset to Ghidra
 *       (see ../../57-Ghidra/README.md) and rebase.
 */

'use strict';

var VERBOSE = false;          // set true to print addresses that resolve to no module
var MAX_ENTRIES = 4096;       // sanity bound on the count argument

/* ------------------------------------------------------------------ */
/* Utilities                                                           */
/* ------------------------------------------------------------------ */

function resolveExport(mod, name) {
  // Frida 16 renamed some of these; try the modern API first, then the old.
  try {
    if (mod === null && typeof Module.getGlobalExportByName === 'function') {
      return Module.getGlobalExportByName(name);
    }
  } catch (e) { /* fall through */ }
  try {
    return Module.findExportByName(mod, name);
  } catch (e) {
    return null;
  }
}

function describeAddress(addr) {
  if (addr === null || addr.isNull()) return '<null>';
  var m = null;
  try { m = Process.findModuleByAddress(addr); } catch (e) { m = null; }
  if (m === null) {
    // Anonymous executable memory: a packer that decrypted code into a fresh
    // mapping, or a JIT page. Worth reporting loudly.
    var range = null;
    try { range = Process.findRangeByAddress(addr); } catch (e) { }
    var prot = range ? range.protection : '???';
    return String(addr) + '  <NO MODULE -- anonymous mapping, prot=' + prot + '>';
  }
  var off = addr.sub(m.base);
  var text = m.name + '+0x' + off.toString(16);
  // If the address happens to be an exported symbol, say so.
  try {
    var sym = DebugSymbol.fromAddress(addr);
    if (sym && sym.name && sym.name !== '' && sym.name.indexOf('0x') !== 0) {
      text += '  (' + sym.name + ')';
    }
  } catch (e) { /* symbols unavailable; the offset is enough */ }
  return text;
}

function readCStringSafe(ptrVal) {
  if (ptrVal === null || ptrVal.isNull()) return null;
  try { return ptrVal.readCString(); } catch (e) { return null; }
}

/* Read the jclass name by calling back through JNIEnv. Best effort: if the
 * runtime is in a state where this is unsafe we simply omit the name rather
 * than risk destabilising the target. */
function classNameOf(clazz) {
  if (clazz === null || clazz.isNull()) return '<null class>';
  try {
    var env = Java.vm.getEnv();
    var cls = env.getObjectClass(clazz);                 // java.lang.Class
    var mid = env.getMethodID(cls, 'getName', '()Ljava/lang/String;');
    var jname = env.callObjectMethod(clazz, mid);
    var p = env.getStringUtfChars(jname, null);
    var s = p.readCString();
    env.releaseStringUtfChars(jname, p);                  // pair the get
    env.deleteLocalRef(jname);
    env.deleteLocalRef(cls);
    return s;
  } catch (e) {
    return '<unknown class>';
  }
}

/* ------------------------------------------------------------------ */
/* The table walker                                                    */
/* ------------------------------------------------------------------ */

var registrations = [];   // every entry we have seen, for the summary

function dumpTable(clazz, methodsPtr, count) {
  if (methodsPtr === null || methodsPtr.isNull()) {
    console.log('[jni] RegisterNatives with a NULL table -- ignoring');
    return;
  }
  if (count <= 0 || count > MAX_ENTRIES) {
    console.log('[jni] RegisterNatives with an implausible count (' + count +
                ') -- ignoring. Check the hooked symbol matches the ABI.');
    return;
  }

  var ps = Process.pointerSize;                 // 8 on arm64, 4 on arm32
  var name = classNameOf(clazz);

  console.log('');
  console.log('[jni] class=' + name + '  count=' + count +
              '  table=' + describeAddress(methodsPtr));

  for (var i = 0; i < count; i++) {
    /* struct JNINativeMethod {
     *     const char* name;        offset 0
     *     const char* signature;   offset 1*ps
     *     void*       fnPtr;       offset 2*ps
     * };   sizeof == 3*ps  (24 bytes on 64-bit)
     */
    var entry = methodsPtr.add(i * ps * 3);
    var mName, mSig, mFn;
    try {
      mName = readCStringSafe(entry.readPointer());
      mSig = readCStringSafe(entry.add(ps).readPointer());
      mFn = entry.add(ps * 2).readPointer();
    } catch (e) {
      console.log('      [' + i + '] unreadable entry at ' + entry + ': ' + e);
      continue;
    }

    var where = describeAddress(mFn);
    console.log('      ' + pad(mName || '<null>', 24) + ' ' +
                pad(mSig || '<null>', 44) + ' -> ' + where);

    registrations.push({
      klass: name,
      name: mName,
      sig: mSig,
      addr: mFn,
      where: where
    });
  }
}

function pad(s, n) {
  s = String(s);
  while (s.length < n) s += ' ';
  return s;
}

/* ------------------------------------------------------------------ */
/* Hook point 1 -- the C++ symbol inside libart.so                     */
/* ------------------------------------------------------------------ */

/* art::JNI<kEnableIndexIds>::RegisterNatives is the function behind the
 * JNIEnv->RegisterNatives slot. The mangled name differs across Android
 * versions and build configurations, so try every form and report which one
 * matched -- do not silently pick one. */
var ART_CANDIDATES = [
  '_ZN3art3JNIILb0EE15RegisterNativesEP7_JNIEnvP7_jclassPK15JNINativeMethodi',
  '_ZN3art3JNIILb1EE15RegisterNativesEP7_JNIEnvP7_jclassPK15JNINativeMethodi',
  '_ZN3art8JNIEnvExt15RegisterNativesEP7_jclassPK15JNINativeMethodi',
  '_ZN3art3JNI15RegisterNativesEP7_JNIEnvP7_jclassPK15JNINativeMethodi'
];

function hookBySymbol() {
  for (var i = 0; i < ART_CANDIDATES.length; i++) {
    var addr = resolveExport('libart.so', ART_CANDIDATES[i]);
    if (addr === null) continue;

    var isEnvExt = ART_CANDIDATES[i].indexOf('JNIEnvExt') >= 0;
    Interceptor.attach(addr, {
      onEnter: function (args) {
        /* JNI<b>::RegisterNatives(JNIEnv*, jclass, const JNINativeMethod*, jint)
         * JNIEnvExt::RegisterNatives(jclass, const JNINativeMethod*, jint)
         *   -- the latter is a C++ member function, so args[0] is `this`. */
        if (isEnvExt) {
          dumpTable(args[1], args[2], args[3].toInt32());
        } else {
          dumpTable(args[1], args[2], args[3].toInt32());
        }
      }
    });
    console.log('[+] RegisterNatives hooked via ' + ART_CANDIDATES[i]);
    return true;
  }
  return false;
}

/* ------------------------------------------------------------------ */
/* Hook point 2 -- the function-table slot, version independent        */
/* ------------------------------------------------------------------ */

/* JNINativeInterface begins with four reserved pointers, so index 4 is the
 * first real function. RegisterNatives is index 215:
 *     64-bit: 215 * 8 = 0x6b8
 *     32-bit: 215 * 4 = 0x35c
 * See ../README.md section 3.11. We read the slot to get the SAME function
 * the symbol route would have found, and hook that -- we never write to the
 * table, because a protector may checksum it. */
function hookByTable() {
  var env;
  try { env = Java.vm.getEnv(); }
  catch (e) { console.log('[-] no JNIEnv available for the table route: ' + e); return false; }

  var ps = Process.pointerSize;
  var handle = env.handle;                       // JNIEnv*
  var table = handle.readPointer();              // JNINativeInterface*
  var slot = table.add(215 * ps);
  var fn = slot.readPointer();

  if (fn.isNull()) { console.log('[-] RegisterNatives slot is null'); return false; }

  Interceptor.attach(fn, {
    onEnter: function (args) {
      // (JNIEnv*, jclass, const JNINativeMethod*, jint)
      dumpTable(args[1], args[2], args[3].toInt32());
    }
  });
  console.log('[+] RegisterNatives hooked via the JNIEnv table slot at ' +
              describeAddress(fn) + '  (index 215, offset 0x' +
              (215 * ps).toString(16) + ')');
  return true;
}

/* ------------------------------------------------------------------ */
/* Bonus -- the static-registration inventory, for the diff             */
/* ------------------------------------------------------------------ */

function dumpStaticExports() {
  console.log('');
  console.log('[=] Statically registered natives currently visible in loaded modules');
  var found = 0;
  Process.enumerateModules().forEach(function (m) {
    var hits = [];
    try {
      m.enumerateExports().forEach(function (e) {
        if (e.type === 'function' && e.name.indexOf('Java_') === 0) {
          hits.push('      ' + e.name + '  @ ' + m.name + '+0x' +
                    e.address.sub(m.base).toString(16));
        }
      });
    } catch (err) { return; }
    if (hits.length) {
      found += hits.length;
      console.log('  [' + m.name + ']');
      console.log(hits.join('\n'));
    }
  });
  if (found === 0) {
    console.log('  (none -- everything this process binds is registered dynamically,');
    console.log('   or the interesting library is not loaded yet)');
  }
}

/* ------------------------------------------------------------------ */
/* Also watch library loads, so you can see WHEN registration happens  */
/* ------------------------------------------------------------------ */

function traceLoads() {
  ['android_dlopen_ext', 'dlopen'].forEach(function (name) {
    var a = resolveExport(null, name);
    if (a === null) return;
    Interceptor.attach(a, {
      onEnter: function (args) {
        this.path = args[0].isNull() ? '<null>' : (readCStringSafe(args[0]) || '<unreadable>');
      },
      onLeave: function (retval) {
        if (!retval.isNull()) console.log('[dlopen] ' + this.path);
      }
    });
  });
}

/* ------------------------------------------------------------------ */
/* Entry point                                                         */
/* ------------------------------------------------------------------ */

console.log('[*] dump-registernatives.js  pointerSize=' + Process.pointerSize +
            '  arch=' + Process.arch);

traceLoads();

if (!hookBySymbol()) {
  console.log('[!] No known art::JNI RegisterNatives symbol on this build.');
  console.log('    Falling back to the JNIEnv function-table slot.');
  if (!hookByTable()) {
    console.log('[-] Both routes failed. Nothing will be recovered.');
    console.log('    Next step: hook JNI_OnLoad in the target library and read');
    console.log('    the third argument of its RegisterNatives call by hand.');
  }
}

/* Print the static inventory a little after start-up, once the app has had a
 * chance to load its libraries. rpc.exports lets you ask again at any time. */
setTimeout(dumpStaticExports, 3000);

rpc.exports = {
  // frida -U -n app -l dump-registernatives.js  then:  %resume ; rpc.exports.summary()
  summary: function () {
    return registrations.map(function (r) {
      return r.klass + '.' + r.name + r.sig + ' -> ' + r.where;
    });
  },
  exportsNow: function () { dumpStaticExports(); return true; },
  count: function () { return registrations.length; }
};
