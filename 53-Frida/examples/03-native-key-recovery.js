/*
 * 03-native-key-recovery.js — recover a signing key from stripped native code.
 *
 * THE SITUATION
 *   The app signs requests in a native library. There is no Java_* symbol
 *   (RegisterNatives was used), the library is stripped, and the key is derived
 *   at runtime rather than stored. Static analysis gives you almost nothing.
 *
 * THE STRATEGY, in increasing order of cost
 *   1. Recover the dynamic JNI registration table. Cheap, and it converts an
 *      opaque binary into a list of (Java method -> module+offset) pairs you
 *      can hand to Ghidra.
 *   2. Hook the recovered function and read its JNI arguments.
 *   3. Hook the CRYPTO PRIMITIVES the library must call. This is the key move:
 *      libcrypto.so exports HMAC_Init_ex and EVP_* even when the app's own
 *      symbols are stripped, and the key is an argument. It is the
 *      framework-boundary technique (../README.md section 6.4) applied at the
 *      native level.
 *
 * HOW TO RUN
 *   # MUST spawn: RegisterNatives fires inside System.loadLibrary.
 *   frida -U -f com.example.app -l 03-native-key-recovery.js --no-pause
 *
 * SEE ALSO
 *   ../scripts/native-tracer.js — the hardened, reusable version of part 1.
 *   ../labs/lab-03-native-instrumentation.md — the guided version.
 *
 * AUTHORISED TESTING ONLY.
 */

'use strict';

/* ------------------------------------------------------------------ config */

// Java method names whose native implementations we want to hook automatically
// once recovered. Add whatever the app declares as `native`.
var INTERESTING = ['sign', 'nativeSign', 'hmac', 'encrypt', 'sealRequest'];

var MAX_KEY_DUMP = 512;      // do not hexdump a megabyte by accident

/* ------------------------------------------------- version-safe resolution */

/*
 * Frida 17 reorganised the Module API. Any script that must run on a machine
 * you do not control needs this shim. A null return is a NORMAL outcome.
 */
function globalExport(name) {
    try {
        if (typeof Module.getGlobalExportByName === 'function') {
            return Module.getGlobalExportByName(name);
        }
    } catch (e) { /* not found */ }
    try { return Module.findExportByName(null, name); }
    catch (e) { return null; }
}

function moduleExport(mod, name) {
    try {
        if (typeof Process.findModuleByName === 'function') {
            var m = Process.findModuleByName(mod);
            if (m !== null && typeof m.findExportByName === 'function') {
                var a = m.findExportByName(name);
                if (a !== null) return a;
            }
        }
    } catch (e) { /* fall through */ }
    try { return Module.findExportByName(mod, name); }
    catch (e) { return null; }
}

function firstOf(mod, names) {
    for (var i = 0; i < names.length; i++) {
        var a = (mod === null) ? globalExport(names[i]) : moduleExport(mod, names[i]);
        if (a !== null && !a.isNull()) return { name: names[i], addr: a };
    }
    return null;
}

function where(addr) {
    var m = Process.findModuleByAddress(addr);
    if (m === null) return String(addr);
    return m.name + '+0x' + addr.sub(m.base).toString(16);
}

/* =========================================================================
 * PART 1 — recover the RegisterNatives table
 * ========================================================================= */

var RECOVERED = [];

function recoverJni() {
    // The mangled name of art::JNI<...>::RegisterNatives differs across Android
    // releases AND across ART Mainline module versions. Try each; report which
    // one matched so the operator knows what happened.
    var CANDIDATES = [
        '_ZN3art3JNIILb0EE15RegisterNativesEP7_JNIEnvP7_jclassPK15JNINativeMethodi',
        '_ZN3art3JNIILb1EE15RegisterNativesEP7_JNIEnvP7_jclassPK15JNINativeMethodi',
        '_ZN3art3JNI15RegisterNativesEP7_JNIEnvP7_jclassPK15JNINativeMethodi',
        '_ZN3art8JNIEnvExt15RegisterNativesEP7_jclassPK15JNINativeMethodi'
    ];

    var found = firstOf('libart.so', CANDIDATES);
    if (found === null) {
        console.log('[-] No RegisterNatives symbol exported by this libart.so.');
        console.log('    Fall back to hooking JNI_OnLoad directly:');
        console.log('      ../scripts/native-tracer.js  ->  nat.onload("libfoo.so")');
        return false;
    }

    console.log('[+] RegisterNatives resolved: ' + found.name);
    console.log('    at ' + found.addr + '  (' + where(found.addr) + ')');

    Interceptor.attach(found.addr, {
        onEnter: function (args) {
            // Both the JNI<...> and JNIEnvExt forms put the method array at
            // args[2] and the count at args[3].
            var methods = args[2];
            var count = args[3].toInt32();

            // Sanity-check before dereferencing. A wrong guess here is a
            // segfault, not an exception.
            if (methods.isNull() || count <= 0 || count > 8192) return;

            var clazzName = '<unknown>';
            try {
                clazzName = Java.cast(ptr(args[1]),
                                      Java.use('java.lang.Class')).getName();
            } catch (e) { /* keep the placeholder */ }

            console.log('');
            console.log('[jni] RegisterNatives  class=' + clazzName +
                        '  count=' + count);

            var ps = Process.pointerSize;
            for (var i = 0; i < count; i++) {
                // struct JNINativeMethod {
                //     const char* name;
                //     const char* signature;
                //     void*       fnPtr;
                // };
                var entry = methods.add(i * ps * 3);
                var name, sig, fn;
                try {
                    name = entry.readPointer().readCString();
                    sig  = entry.add(ps).readPointer().readCString();
                    fn   = entry.add(ps * 2).readPointer();
                } catch (e) { continue; }
                if (name === null || fn === null || fn.isNull()) continue;

                console.log('      ' + name + (sig || '') + '   ->   ' + where(fn));

                RECOVERED.push({ clazz: clazzName, name: name, sig: sig, addr: fn });

                if (INTERESTING.indexOf(name) !== -1) {
                    hookRecovered(fn, clazzName + '.' + name);
                }
            }
            console.log('');
        }
    });

    return true;
}

/* =========================================================================
 * PART 2 — hook a recovered function, reading JNI arguments correctly
 * ========================================================================= */

function hookRecovered(addr, label) {
    try {
        Interceptor.attach(addr, {
            onEnter: function (args) {
                // JNI calling convention (../../16-JNI/README.md):
                //   args[0] = JNIEnv*
                //   args[1] = jobject (instance) or jclass (static)
                //   args[2] = first declared parameter
                this.label = label;
                console.log('[' + label + '] enter');
                console.log('    JNIEnv* = ' + args[0]);
                console.log('    this    = ' + args[1]);
                console.log('    arg0    = ' + args[2]);

                // Casting a jbyteArray through the Java bridge is far safer than
                // decoding ART's array header by hand — the layout differs
                // between ART versions and hard-coding it is exactly the mistake
                // ../README.md section 11 warns about.
                try {
                    var arr = Java.cast(ptr(args[2]), Java.use('[B'));
                    console.log('    arg0 is a byte[' + arr.length + ']');
                } catch (e) { /* not a byte array — fine */ }
            },
            onLeave: function (retval) {
                console.log('[' + this.label + '] leave -> ' + retval);
            }
        });
        console.log('[+] hooked recovered function ' + label +
                    ' at ' + where(addr));
    } catch (e) {
        console.log('[-] could not hook ' + label + ': ' + e.message);
    }
}

/* =========================================================================
 * PART 3 — hook the crypto primitives
 *
 * This is the move that actually recovers the key. The app's own functions are
 * stripped and non-exported; libcrypto's are not. Whatever the app does, if it
 * computes an HMAC it must eventually pass the key to HMAC_Init_ex.
 * ========================================================================= */

function hookCrypto() {
    var hooked = 0;

    // Search EVERY module, not just libcrypto.so: a statically linked BoringSSL
    // puts these symbols in the app's own library.
    Process.enumerateModules().forEach(function (m) {
        if (m.name.indexOf('libart') === 0) return;

        /* ---- HMAC ------------------------------------------------------- */
        var hmacInit = null;
        try {
            hmacInit = m.findExportByName
                     ? m.findExportByName('HMAC_Init_ex')
                     : moduleExport(m.name, 'HMAC_Init_ex');
        } catch (e) { hmacInit = null; }

        if (hmacInit !== null) {
            Interceptor.attach(hmacInit, {
                onEnter: function (args) {
                    // int HMAC_Init_ex(HMAC_CTX* ctx, const void* key,
                    //                  size_t len, const EVP_MD* md, ENGINE* e)
                    var keyPtr = args[1];
                    var keyLen = args[2].toInt32();
                    if (keyPtr.isNull() || keyLen <= 0 || keyLen > MAX_KEY_DUMP) return;

                    console.log('');
                    console.log('[HMAC_Init_ex] in ' + m.name + '  key length=' + keyLen);
                    console.log(hexdump(keyPtr, { length: keyLen, ansi: false }));

                    // Many keys are ASCII. Show that interpretation too.
                    try {
                        var s = keyPtr.readCString(keyLen);
                        if (s !== null && /^[\x20-\x7e]+$/.test(s)) {
                            console.log('    as ASCII: "' + s + '"');
                        }
                    } catch (e) { /* binary key */ }

                    // Send it to the host so a driver can persist it.
                    send({ kind: 'key', source: m.name + '!HMAC_Init_ex',
                           length: keyLen }, keyPtr.readByteArray(keyLen));
                }
            });
            console.log('[+] hooked ' + m.name + '!HMAC_Init_ex');
            hooked++;
        }

        /* ---- EVP symmetric encryption ------------------------------------ */
        ['EVP_EncryptInit_ex', 'EVP_DecryptInit_ex',
         'EVP_CipherInit_ex'].forEach(function (sym) {
            var addr = null;
            try {
                addr = m.findExportByName ? m.findExportByName(sym)
                                          : moduleExport(m.name, sym);
            } catch (e) { return; }
            if (addr === null) return;

            Interceptor.attach(addr, {
                onEnter: function (args) {
                    // int EVP_EncryptInit_ex(EVP_CIPHER_CTX*, const EVP_CIPHER*,
                    //                        ENGINE*, const unsigned char* key,
                    //                        const unsigned char* iv)
                    var key = args[3];
                    var iv = args[4];
                    console.log('');
                    console.log('[' + sym + '] in ' + m.name);
                    if (!key.isNull()) {
                        // Key length depends on the cipher; 32 covers AES-256.
                        console.log('    key:');
                        console.log(hexdump(key, { length: 32, ansi: false }));
                    }
                    if (!iv.isNull()) {
                        console.log('    iv:');
                        console.log(hexdump(iv, { length: 16, ansi: false }));
                    }
                }
            });
            console.log('[+] hooked ' + m.name + '!' + sym);
            hooked++;
        });

        /* ---- digest naming ------------------------------------------------ */
        var digestInit = null;
        try {
            digestInit = m.findExportByName ? m.findExportByName('EVP_DigestInit_ex')
                                            : moduleExport(m.name, 'EVP_DigestInit_ex');
        } catch (e) { digestInit = null; }

        if (digestInit !== null) {
            // Resolving the digest's NAME tells you the algorithm without
            // reading a single instruction of the app's code.
            var nameFn = firstOf(m.name, ['EVP_MD_get0_name', 'EVP_MD_name']);
            Interceptor.attach(digestInit, {
                onEnter: function (args) {
                    if (nameFn === null || args[1].isNull()) return;
                    try {
                        var f = new NativeFunction(nameFn.addr, 'pointer', ['pointer']);
                        var p = f(args[1]);
                        if (!p.isNull()) {
                            console.log('[EVP_DigestInit_ex] algorithm = ' +
                                        p.readCString());
                        }
                    } catch (e) { /* best effort */ }
                }
            });
            hooked++;
        }
    });

    if (hooked === 0) {
        console.log('[-] No crypto primitives found in any loaded module.');
        console.log('    Either the crypto happens in Java (hook javax.crypto.Cipher');
        console.log('    instead), or the library is statically linked AND stripped.');
        console.log('    In the latter case use Stalker coverage to find the routine:');
        console.log('    ../README.md section 7.9.');
    }
    return hooked;
}

/* =========================================================================
 * PART 4 — report what we know
 * ========================================================================= */

rpc.exports = {
    init: function (stage) {
        console.log('[*] 03-native-key-recovery loaded (stage=' + stage + ')');
    },
    table: function () {
        return RECOVERED.map(function (r) {
            return {
                clazz: r.clazz, name: r.name, sig: r.sig,
                where: where(r.addr), address: r.addr.toString()
            };
        });
    }
};

/* ------------------------------------------------------------- bootstrap */

console.log('');
console.log('=== 03-native-key-recovery ===');

// Part 1 must be armed BEFORE System.loadLibrary runs, which is why it happens
// at script-load time rather than inside a Java.perform callback.
recoverJni();

// Log library loads so you know when part 3 becomes worth re-running.
Java.perform(function () {
    try {
        var System = Java.use('java.lang.System');
        System.loadLibrary.overload('java.lang.String').implementation = function (n) {
            console.log('[lib] System.loadLibrary("' + n + '")');
            var r = this.loadLibrary(n);
            hookCrypto();          // new module may export what we want
            return r;
        };
    } catch (e) {
        console.log('[.] could not hook System.loadLibrary: ' + e.message);
    }
});

// First pass over whatever is already loaded.
hookCrypto();

console.log('[+] ready. Exercise the signing feature in the app.');
console.log('');
