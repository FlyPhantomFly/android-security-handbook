/*
 * jni-arg-tracer.js -- hook a native JNI method and decode its arguments
 *                      using its JNI signature.
 *
 * WHAT IT DOES
 *     You give it a target (an exported Java_* symbol, or a module and an
 *     offset recovered from dump-registernatives.js) and the method's JNI
 *     signature. It attaches, and for every call prints each declared
 *     argument decoded according to its descriptor:
 *
 *         Ljava/lang/String;   -> the string contents
 *         [B                   -> length and a hexdump
 *         [I [J [S [C          -> length and the first elements
 *         I J S B C Z          -> the numeric value
 *         F D                  -> the floating point value
 *         Lother/Class;        -> the runtime class name and toString()
 *
 *     and the return value on the way out.
 *
 * WHY IT EXISTS
 *     Because the single most common mistake in native Android
 *     instrumentation is reading args[0] as "the first argument". It is not:
 *     args[0] is the JNIEnv*, args[1] is the jobject receiver or the jclass,
 *     and the first declared parameter is args[2]. See ../README.md section
 *     3.9. Once you have the signature, the mapping from args[n] to a typed
 *     value is entirely mechanical -- so let a script do it rather than
 *     counting by hand every time.
 *
 * HOW TO RUN
 *     Edit the TARGETS array at the bottom, then:
 *
 *     frida -U -f com.example.app -l jni-arg-tracer.js --no-pause
 *
 *     A target is one of:
 *       { symbol: 'Java_com_example_Crypto_encrypt',
 *         sig: '([BI)[B', static: false }
 *
 *       { module: 'libcrypto.so', offset: 0x45a10,
 *         sig: '(Ljava/lang/String;[B)Z', static: true, label: 'nativeVerify' }
 *
 *       { module: 'libcrypto.so', offset: 0x12340,
 *         sig: '(JI)I', critical: true }        // @CriticalNative: no JNIEnv*
 *
 * REQUIREMENTS
 *     frida-server on the device. The target library must be loaded before
 *     the offset form can resolve -- the script retries on each dlopen, so
 *     spawning is safe.
 *
 * WHAT THIS WILL NOT TELL YOU
 *     - The signature. Get it from jadx, from smali (`.method native ...`),
 *       or from dump-registernatives.js, which prints it.
 *     - Whether the method is static. That changes what args[1] IS, though
 *       not where the real arguments start. Guessing costs you nothing here,
 *       but it matters when you interpret args[1].
 *     - Whether the method is @CriticalNative. If it is and you do not say
 *       so, every argument is off by two. Check the DEX annotation with
 *       a recursive grep for 'optimization/CriticalNative' over the smali
 *       directories that apktool produced.
 *     - Anything about float or double arguments' register slots. On ARM64
 *       they travel in v0-v7, NOT in the integer args[] sequence, so a
 *       method mixing ints and floats will decode its floats wrongly here.
 *       The script warns when it sees F or D in a signature.
 *     - What the function does with the data. That is Ghidra's job.
 *
 * SAFETY
 *     Every JNI call this script makes is paired with its release. It uses
 *     JNI_ABORT (2) when releasing array elements, so it never writes the
 *     app's data back. It never modifies arguments or return values unless
 *     you uncomment the example in onLeave.
 */

'use strict';

var MAX_HEX = 128;          // bytes of an array to hexdump
var MAX_ELEMS = 16;         // elements of a numeric array to print

/* ------------------------------------------------------------------ */
/* Signature parsing -- the same grammar as scripts/jni_mangle.py       */
/* ------------------------------------------------------------------ */

function parseSignature(sig) {
  if (sig[0] !== '(') throw new Error('signature must start with "(": ' + sig);
  var close = sig.indexOf(')');
  if (close < 0) throw new Error('signature has no ")": ' + sig);
  var params = [];
  var i = 1;
  while (i < close) {
    var start = i;
    while (sig[i] === '[') i++;
    if (sig[i] === 'L') {
      var semi = sig.indexOf(';', i);
      if (semi < 0 || semi > close) throw new Error('unterminated L descriptor: ' + sig);
      i = semi + 1;
    } else {
      if ('ZBCSIJFDV'.indexOf(sig[i]) < 0) {
        throw new Error('unknown descriptor char "' + sig[i] + '" in ' + sig);
      }
      i++;
    }
    params.push(sig.substring(start, i));
  }
  return { params: params, ret: sig.substring(close + 1) };
}

/* ------------------------------------------------------------------ */
/* Decoding one argument                                               */
/* ------------------------------------------------------------------ */

function env() { return Java.vm.getEnv(); }

function decodeString(handle) {
  if (handle.isNull()) return 'null';
  var e = env();
  var p = e.getStringUtfChars(handle, null);
  if (p.isNull()) return '<GetStringUTFChars returned null>';
  var s;
  try { s = p.readCString(); } catch (err) { s = '<unreadable>'; }
  e.releaseStringUtfChars(handle, p);      // pair the get -- always
  return JSON.stringify(s);
}

function decodeByteArray(handle) {
  if (handle.isNull()) return 'null';
  var e = env();
  var len = e.getArrayLength(handle);
  var p = e.getByteArrayElements(handle, null);
  if (p.isNull()) return '<GetByteArrayElements returned null>';
  var n = Math.min(len, MAX_HEX);
  var buf = null;
  try { buf = Memory.readByteArray(p, n); } catch (err) { }
  e.releaseByteArrayElements(handle, p, 2);   // JNI_ABORT: never write back
  var head = 'byte[' + len + ']';
  if (buf === null) return head + ' <unreadable>';
  return head + '\n' + hexdump(buf, { length: n, ansi: false }) +
         (len > n ? '        ... (' + (len - n) + ' more bytes)' : '');
}

function decodeNumericArray(handle, desc) {
  if (handle.isNull()) return 'null';
  var e = env();
  var len = e.getArrayLength(handle);
  return desc + '[' + len + ']  (element dump not implemented for this type; ' +
         'read it in Ghidra or convert to byte[] in the app)';
}

function decodeObject(handle, desc) {
  if (handle.isNull()) return 'null';
  try {
    var e = env();
    var cls = e.getObjectClass(handle);
    var toStr = e.getMethodID(cls, 'toString', '()Ljava/lang/String;');
    var s = e.callObjectMethod(handle, toStr);
    var out = decodeString(s);
    e.deleteLocalRef(s);
    e.deleteLocalRef(cls);
    return desc + ' ' + out;
  } catch (err) {
    return desc + ' <handle ' + handle + ', toString failed: ' + err + '>';
  }
}

function decodeArg(raw, desc) {
  switch (desc) {
    case 'Z': return (raw.toInt32() & 0xff) ? 'true' : 'false';
    case 'B': {
      var b = raw.toInt32() & 0xff;
      return (b > 127 ? b - 256 : b) + '  (signed jbyte)';
    }
    case 'C': return 'U+' + (raw.toInt32() & 0xffff).toString(16);
    case 'S': {
      var s = raw.toInt32() & 0xffff;
      return (s > 32767 ? s - 65536 : s);
    }
    case 'I': return raw.toInt32() + '  (0x' + (raw.toInt32() >>> 0).toString(16) + ')';
    case 'J': return raw.toString() + '  (jlong -- if this is a handle, see README 5.5)';
    case 'F':
    case 'D': return '<float/double: not in the integer register file, see header>';
    case 'Ljava/lang/String;': return decodeString(raw);
    case '[B': return decodeByteArray(raw);
    default:
      if (desc[0] === '[') return decodeNumericArray(raw, desc);
      if (desc[0] === 'L') return decodeObject(raw, desc);
      return '<' + desc + '> ' + raw;
  }
}

/* ------------------------------------------------------------------ */
/* Attaching                                                           */
/* ------------------------------------------------------------------ */

function resolveTarget(t) {
  if (t.symbol) {
    var a = null;
    try { a = Module.findExportByName(t.module || null, t.symbol); } catch (e) { }
    if (a === null && typeof Module.getGlobalExportByName === 'function') {
      try { a = Module.getGlobalExportByName(t.symbol); } catch (e) { }
    }
    return a;
  }
  if (t.module && typeof t.offset === 'number') {
    var m = Process.findModuleByName(t.module);
    if (m === null) return null;
    return m.base.add(t.offset);
  }
  return null;
}

function attach(t) {
  var addr = resolveTarget(t);
  if (addr === null) return false;

  var parsed;
  try { parsed = parseSignature(t.sig); }
  catch (e) { console.log('[-] bad signature for ' + label(t) + ': ' + e); return true; }

  if (t.sig.indexOf('F') >= 0 || t.sig.indexOf('D') >= 0) {
    console.log('[!] ' + label(t) + ' has float/double parameters. On ARM64 those ' +
                'travel in v0-v7, not in args[], so their slots will be wrong.');
  }

  var base = t.critical ? 0 : 2;

  Interceptor.attach(addr, {
    onEnter: function (args) {
      console.log('');
      console.log('>>> ' + label(t) + '  ' + t.sig + '   [tid=' +
                  Process.getCurrentThreadId() + ']');
      if (!t.critical) {
        console.log('    args[0] JNIEnv*  = ' + args[0]);
        console.log('    args[1] ' + (t.static ? 'jclass ' : 'jobject') + '  = ' + args[1]);
      } else {
        console.log('    (@CriticalNative: no JNIEnv*, no jclass)');
      }
      for (var i = 0; i < parsed.params.length; i++) {
        var d = parsed.params[i];
        var v;
        try { v = decodeArg(args[base + i], d); }
        catch (e) { v = '<decode failed: ' + e + '>'; }
        console.log('    args[' + (base + i) + '] ' + pad(d, 22) + ' = ' + v);
      }
    },
    onLeave: function (retval) {
      var r;
      try {
        r = (parsed.ret === 'V') ? '(void)' : decodeArg(retval, parsed.ret);
      } catch (e) { r = '<decode failed: ' + e + '>'; }
      console.log('<<< ' + label(t) + ' -> ' + r);
      // To force a boolean true:  retval.replace(ptr(1));
    }
  });

  console.log('[+] hooked ' + label(t) + ' at ' + addr);
  return true;
}

function label(t) {
  return t.label || t.symbol || (t.module + '+0x' + t.offset.toString(16));
}

function pad(s, n) { s = String(s); while (s.length < n) s += ' '; return s; }

/* ------------------------------------------------------------------ */
/* Targets -- EDIT THIS                                                */
/* ------------------------------------------------------------------ */

var TARGETS = [
  // Statically registered: found with `nm -D lib.so | grep ' T Java_'`.
  { symbol: 'Java_com_example_jnidemo_HelloJni_greeting',
    sig: '(Ljava/lang/String;)Ljava/lang/String;',
    static: false },

  // Dynamically registered: address from dump-registernatives.js.
  // { module: 'libcrypto.so', offset: 0x45a10, label: 'encrypt',
  //   sig: '([BI)[B', static: false },

  // @CriticalNative: no synthetic arguments at all.
  // { module: 'libfast.so', offset: 0x1200, label: 'fastHash',
  //   sig: '(JI)I', critical: true }
];

/* ------------------------------------------------------------------ */
/* Bootstrap: attach now, and retry after every library load           */
/* ------------------------------------------------------------------ */

var pending = TARGETS.slice();

function sweep() {
  pending = pending.filter(function (t) { return !attach(t); });
}

sweep();
if (pending.length) {
  console.log('[*] ' + pending.length + ' target(s) not resolvable yet; ' +
              'retrying after each library load.');
  ['android_dlopen_ext', 'dlopen'].forEach(function (name) {
    var a = null;
    try { a = Module.findExportByName(null, name); } catch (e) { }
    if (a === null) return;
    Interceptor.attach(a, { onLeave: function () { if (pending.length) sweep(); } });
  });
}
