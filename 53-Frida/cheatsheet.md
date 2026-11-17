# 53 — Frida · Cheat Sheet

Printable. No prose. See [README.md](README.md) for why each of these works.

---

## The four commands that start every session

```bash
frida --version                                          # 1. know your host version
adb shell "su -c '/data/local/tmp/frida-server -D'"      # 2. matching server, running
adb shell cmd package compile -m verify -f <pkg>         # 3. make hooks reliable
frida -U -f <pkg> -l agent.js --no-pause                 # 4. SPAWN, never attach
```

`-f` not `-n`. Always. Everything in `Application.attachBaseContext` depends on it.

---

## Setup

### Version + ABI

```bash
frida --version                                    # host version — the source of truth
adb shell getprop ro.product.cpu.abi               # arm64-v8a | armeabi-v7a | x86_64 | x86
adb shell "cat /proc/$(adb shell pidof -s <pkg>)/maps" | grep -m1 linker
#   /system/bin/linker64 → 64-bit process    /system/bin/linker → 32-bit
```

| ABI reported | frida-server asset |
|---|---|
| `arm64-v8a` | `frida-server-<ver>-android-arm64` |
| `armeabi-v7a` | `frida-server-<ver>-android-arm` |
| `x86_64` | `frida-server-<ver>-android-x86_64` |
| `x86` | `frida-server-<ver>-android-x86` |

### Deploy

```bash
adb push frida-server /data/local/tmp/frida-server
adb shell "su -c 'chmod 755 /data/local/tmp/frida-server'"
adb shell "su -c '/data/local/tmp/frida-server -D'"           # daemonize
adb shell "su -c '/data/local/tmp/frida-server -l 127.0.0.1:1337 -D'"   # random port
```

### Both ABIs simultaneously

```bash
# device (root)
/data/local/tmp/frida-server-arm64 -l 127.0.0.1:27042 -D
/data/local/tmp/frida-server-arm   -l 127.0.0.1:27043 -D
# host
adb forward tcp:27043 tcp:27043 && frida -H 127.0.0.1:27043 -f <pkg>
```

### Smoke test

**Do this one first, and read its output.** `frida-ps -U` is not a proof the server works:

```bash
adb shell "su 0 /data/local/tmp/frida-server --version"   # AVD form; Magisk: su -c '...'
```

`CANNOT LINK EXECUTABLE … empty/missing DT_HASH/DT_GNU_HASH … (new hash type from the future?)`
means the server binary is newer than the image's linker. Measured on `sdk_gphone16k_x86_64`,
Android 15 / API 35, x86_64. **Not a root problem** — `su 0 id` returns 0 — and **`frida-ps -U`
still lists processes** while it is happening. Match the build to the image, or use gadget.
Full disclosure: [README §top](README.md#read-this-before-you-install-anything-frida-server-does-not-run-on-every-image).

```bash
frida -U -f <pkg> -q --no-pause -e \
 'Java.perform(function(){console.log("alive: "+Java.use("android.app.ActivityThread").currentPackageName())})'
```

---

## CLI

| Tool | Use |
|---|---|
| `frida` | REPL / script runner |
| `frida-ps -Uai` | Installed apps (`-a`) including not running (`-i`) |
| `frida-ps -Ua` | Running app processes — **shows `:remote` children** |
| `frida-ls-devices` | Reachable devices |
| `frida-kill -U <pkg>` | Kill on device |
| `frida-trace` | Auto-generate + run handlers |
| `frida-discover -U -n <pkg>` | Find functions worth tracing |
| `frida-apk --debuggable a.apk` | Flip `android:debuggable`, re-sign |
| `frida-create agent` | Scaffold a project |

### `frida` flags

| Flag | Meaning |
|---|---|
| `-U` | USB device |
| `-H host:port` / `-R` | Remote frida-server or gadget |
| `-D <id>` | Specific device |
| `-f <pkg>` | **Spawn** |
| `-n <name>` / `-p <pid>` | Attach |
| `-l <file>` | Load script (repeatable) |
| `--no-pause` | Resume after the script loads |
| `-q` | Quiet — no REPL banner |
| `-o <file>` | Log to file |
| `-e '<code>'` | One-liner |
| `-P '{"k":"v"}'` | Params passed to `rpc.exports.init` |
| `--runtime=qjs\|v8` | JS engine |
| `--debug` | V8 inspector on 9229 |

### REPL meta-commands

| Command | Effect |
|---|---|
| `%resume` | Resume a paused spawn |
| `%reload` | Re-read and reload `-l` scripts |
| `%load <f>` / `%unload <n>` | Add / remove a script |
| `%exec <f>` | Run once |
| `Ctrl-D` | Detach and quit |

### frida-trace

```bash
frida-trace -U -f <pkg> -i "SSL_*"                  # native by name
frida-trace -U -n <pkg> -I "libnative.so"           # whole module
frida-trace -U -f <pkg> -i "*" -x "malloc" -x "free"
frida-trace -U -f <pkg> -a "libnative.so!0x4a1c"    # by offset
frida-trace -U -f <pkg> -j "com.example.crypto.*!*" # JAVA
frida-trace -U -f <pkg> -j "*!*decrypt*"
```

Handlers appear in `__handlers__/` and hot-reload on save.

---

## Java API

### Basics

```javascript
Java.perform(function () { /* everything Java goes in here */ });
Java.performNow(function () { /* when already on a VM thread */ });
Java.available                       // is there a VM?
Java.androidVersion                  // "14"
Java.vm.getEnv()                     // raw JNIEnv
```

### Hooking

```javascript
// single overload
Java.use("com.x.C").m.implementation = function (a) { return this.m(a); };

// specific overload — REQUIRED when more than one exists
Java.use("com.x.C").m.overload("java.lang.String", "int")
  .implementation = function (s, i) { return this.m(s, i); };

// constructor
Java.use("com.x.C").$init.overload("java.lang.String")
  .implementation = function (s) { return this.$init(s); };

// every overload
Java.use("com.x.C").m.overloads.forEach(ov => {
  ov.implementation = function () { return ov.apply(this, arguments); };
});

// static method — same syntax; `this` is the class
// revert
Java.use("com.x.C").m.implementation = null;
```

### Overload type strings

| Java | String |
|---|---|
| `int` `boolean` `long` `char` `byte` `short` `float` `double` | same word |
| `String` | `"java.lang.String"` |
| `byte[]` | `"[B"` |
| `int[]` | `"[I"` |
| `char[]` | `"[C"` |
| `String[]` | `"[Ljava.lang.String;"` |
| `byte[][]` | `"[[B"` |
| `Outer.Inner` | `"com.x.Outer$Inner"` |
| `f(String...)` | `"[Ljava.lang.String;"` |
| `List<String>` | `"java.util.List"` (erased) |
| constructor | member name `$init` |

### Fields

```javascript
const o = Java.use("com.x.C");
o.staticField.value = 42;                    // static
inst.instanceField.value;                    // instance, inside a hook: this.f.value
o.$className;                                // runtime class of an instance
// name collision between a field and a method:
inst._name.value                             // underscore prefix
```

### Objects, casts, arrays

```javascript
const s = Java.use("com.x.C").$new("arg");           // construct
Java.cast(ptr(handle), Java.use("java.lang.Class")); // reinterpret
Java.array("byte", [1,2,3]);                          // build a Java array
Java.retain(obj);                                     // keep past the callback
```

### Finding things

```javascript
Java.enumerateLoadedClasses({ onMatch(n){}, onComplete(){} });
Java.enumerateClassLoaders({ onMatch(l){}, onComplete(){} });
Java.choose("com.x.C", { onMatch(i){ /* return "stop" to end */ }, onComplete(){} });
Java.ClassFactory.get(loader).use("com.x.C");     // per-loader wrapper
Java.classFactory.loader = loader;                // global — SAVE AND RESTORE
```

### Stack trace

```javascript
Java.use("android.util.Log")
    .getStackTraceString(Java.use("java.lang.Exception").$new());
```

### Deoptimisation

```javascript
Java.deoptimizeEverything();          // global — slow, detectable
Java.deoptimizeMethod(m);             // surgical, Frida 16+
```

### Registering a class

```javascript
const T = Java.registerClass({
  name: "com.frida.T",
  implements: [Java.use("javax.net.ssl.X509TrustManager")],
  methods: {
    checkClientTrusted(c, a) {},
    checkServerTrusted(c, a) {},
    getAcceptedIssuers() { return []; }
  }
});
```

---

## Native API

### Interceptor

```javascript
const l = Interceptor.attach(addr, {
  onEnter(args) { this.x = args[0]; },     // `this` persists to onLeave
  onLeave(retval) { retval.replace(ptr(0)); }
});
l.detach();

Interceptor.replace(addr, new NativeCallback(fn, "int", ["pointer"]));
Interceptor.revert(addr);
Interceptor.detachAll();
Interceptor.flush();                       // batch many hooks: one i-cache flush
```

### Module / symbol lookup (version-safe)

```javascript
// Frida 17
Module.getGlobalExportByName("open");
Process.getModuleByName("libc.so").getExportByName("open");
// Frida 16 and earlier
Module.findExportByName("libc.so", "open");
Module.findExportByName(null, "open");
Module.findBaseAddress("libnative.so");
```

```javascript
Process.enumerateModules();
Process.findModuleByName("libssl.so");
Process.findModuleByAddress(ptr);
mod.enumerateExports() / enumerateImports() / enumerateSymbols();
mod.base, mod.size, mod.path
```

### Memory

```javascript
Memory.alloc(64);
Memory.allocUtf8String("x");
Memory.protect(addr, len, "rwx");
Memory.patchCode(addr, 8, code => { /* writer */ });
Memory.scan(base, size, "41 ?? 43", { onMatch(a,s){}, onError(r){}, onComplete(){} });
Memory.scanSync(base, size, "41 ?? 43");     // blocks — filter ranges first
Memory.copy(dst, src, n);
```

| Pattern | Matches |
|---|---|
| `"41 42 43"` | exact bytes `ABC` |
| `"41 ?? 43"` | any byte in the middle |
| `"41 4? 43"` | high nibble 4 |
| `"/Bearer ey[A-Za-z0-9]/"` | regex over raw bytes |

### Pointer reads/writes

```javascript
ptr("0x1234"); NULL;
p.readU8/S8/U16/S16/U32/S32/U64/S64/Float/Double/Pointer();
p.readCString([n]); p.readUtf8String([n]); p.readUtf16String(); p.readByteArray(n);
p.writeU32(v); p.writeUtf8String(s); p.writeByteArray([1,2,3]); p.writePointer(q);
p.add(n) / sub(n) / and(m) / or(m) / xor(m) / shr(n) / shl(n);
p.isNull(); p.compare(q); p.toInt32(); p.toString(16);
hexdump(p, { length: 64, ansi: false });
```

### Ranges

```javascript
Process.enumerateRanges("rw-");             // r-- rw- r-x rwx
Process.enumerateRanges({ protection: "rw-", coalesce: true });
Process.findRangeByAddress(p);
Process.enumerateMallocRanges();
Process.id, Process.arch, Process.pointerSize, Process.pageSize
Process.getCurrentThreadId(), Process.enumerateThreads()
```

### Calling code

```javascript
const f = new NativeFunction(addr, "int", ["pointer","size_t"],
                             { exceptions: "propagate" });
const cb = new NativeCallback(function (a) { return 0; }, "int", ["pointer"]);
const KEEP = []; KEEP.push(cb);            // MANDATORY GC anchor
new NativeFunction(addr, "void", ["pointer","int","pointer"]);
```

| C type | Frida string |
|---|---|
| `void` | `"void"` |
| `int`/`int32_t` | `"int"` |
| `long`/`int64_t` | `"long"` |
| `size_t` | `"size_t"` |
| `bool` | `"bool"` |
| `float` `double` | `"float"` `"double"` |
| any pointer | `"pointer"` |
| struct by value | `["int","pointer"]` |

### Backtrace

```javascript
Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress);
Thread.backtrace(this.context, Backtracer.FUZZY);      // candidates, verify them
DebugSymbol.fromAddress(p);       // .name .moduleName .fileName .lineNumber
DebugSymbol.fromName("open");
```

### Stalker

```javascript
Stalker.exclude(Process.getModuleByName("libc.so"));    // do this FIRST
Stalker.follow(tid, {
  events: { call: true, ret: false, exec: false, block: false, compile: false },
  onReceive(events) { Stalker.parse(events, { annotate: true }); },
  transform(iter) {
    let i = iter.next();
    do {
      if (i.mnemonic === "cmp") iter.putCallout(ctx => console.log(ctx.x0));
      iter.keep();                       // MANDATORY for every kept instruction
      i = iter.next();
    } while (i !== null);
  }
});
Stalker.unfollow(tid);
Stalker.garbageCollect();
Stalker.trustThreshold = -1;             // never re-instrument (fastest)
Stalker.trustThreshold = 0;              // always (self-modifying code)
Stalker.queueCapacity = 16384;
```

---

## Agent structure

```javascript
rpc.exports = {
  init(stage, params) { /* stage: "early" (spawn) | "late" (attach) */ },
  dispose() { Interceptor.detachAll(); },
  myFn(a) { return a * 2; }              // JS myFn → Python my_fn
};

send({ kind: "log", msg: "x" });          // JSON
send({ kind: "blob" }, arrayBuffer);      // binary, out of band
recv("tag", msg => { /* ONE-SHOT — re-arm inside */ }).wait();   // .wait() BLOCKS
```

### frida-compile

```bash
npm i -D frida-compile @types/frida-gum typescript
frida-compile agent/index.ts -o _agent.js -c      # -c minify
frida-compile agent/index.ts -o _agent.js -w      # watch
```

### Python host

```python
import frida
device  = frida.get_usb_device(timeout=10)
device.enable_child_gating()
device.on("child-added", lambda c: ...)
pid     = device.spawn(["com.x"])
session = device.attach(pid)
script  = session.create_script(open("_agent.js").read())
script.on("message", lambda m, d: print(m, d))
script.load()
device.resume(pid)                       # AFTER load()
script.exports_sync.my_fn(1)
script.post({"type": "tag", "value": 1})
script.unload(); session.detach()
```

---

## Failure modes

| Symptom | Cause | Fix |
|---|---|---|
| Hook installs, never fires | **ART inlining** | `cmd package compile -m verify -f <pkg>` |
| Hook installs, never fires, method absent in JADX | **R8 inlining** | Hook the callers |
| Fires at first, then stops | JIT recompiled | `Java.deoptimizeEverything()` |
| `ClassNotFoundException` | **Wrong ClassLoader** | `Java.enumerateClassLoaders` + `Java.ClassFactory.get` |
| `has more than one overload` | **Wrong overload** | `.overload(...)` — list `.overloads` first |
| Startup code never seen | **Attached with `-n`** | Spawn with `-f` |
| Stack overflow in a hook | Called `C.m()` not `this.m()` | Use `this.` or `ov.apply(this, arguments)` |
| Random crash minutes later | `NativeCallback` GC'd | Module-scope `KEEP[]` |
| `Error: expected a pointer` | JS number passed | `ptr(x)` |
| `Module.findExportByName is not a function` | Frida 17 API change | `Process.getModuleByName(m).getExportByName(n)` |
| `major versions match` error | Host/device mismatch | Match exactly |
| `CANNOT LINK EXECUTABLE … DT_HASH/DT_GNU_HASH` | **Server newer than the image's linker** (API 35 x86_64) | Match the build to the image, or gadget. `frida-ps -U` still works — do not trust it |
| SIGSEGV on attach | Anti-debug | Spawn with `-f`, hook `ptrace` first, or gadget |
| Works on emulator, not phone | ABI / emulator detection / compilation state | Test on hardware |
| Java hooks fine, proxy sees nothing | **Native TLS stack** | Hook `SSL_CTX_set_custom_verify` |
| ANR under instrumentation | `scanSync` or Stalker on the UI thread | Filter ranges; `Stalker.exclude` |

### Decision order

```
error thrown?  ── ClassNotFound → loader
               ── overload      → .overload()
no error, never fires?
   respawn with -f  → fires? → you were attaching
   -m verify        → fires? → ART inlining
   in JADX?  no     → R8 inlining
                yes → wrong process / dead code / native
LAST: detection (process DIES, not silent)
```

---

## No-root

| Method | Root | Re-signs | Startup code | Effort |
|---|---|---|---|---|
| `frida-server` + `-f` | **yes** | no | yes | lowest |
| gadget, `on_load: wait` | no | **yes** | yes | highest |
| gadget, `script` mode | no | **yes** | yes | high, unattended |
| `frida-apk --debuggable` | no | **yes** | partial | low |
| Magisk module | Magisk | no | yes | low, persistent |

### Gadget embed

```bash
apktool d -o work base.apk
cp frida-gadget-<ver>-android-arm64.so work/lib/arm64-v8a/libgadget.so
# work/lib/arm64-v8a/libgadget.config.so  (JSON, .so extension)
apktool b work -o patched.apk
zipalign -p -f 4 patched.apk aligned.apk
apksigner sign --ks test.keystore --out signed.apk aligned.apk
adb uninstall <pkg> && adb install signed.apk
adb forward tcp:27042 tcp:27042 && frida -U -n Gadget -l agent.js
```

```json
{ "interaction": { "type": "listen", "address": "127.0.0.1",
                   "port": 27042, "on_load": "wait" } }
```

```smali
.method static constructor <clinit>()V
    .locals 1
    const-string v0, "gadget"
    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V
    return-void
.end method
```

---

## Framework boundary hooks

| Want to know | Hook |
|---|---|
| Crypto keys and algorithms | `javax.crypto.Cipher`, `SecretKeySpec`, `Mac`, `MessageDigest` |
| HTTP requests | `okhttp3.OkHttpClient`, `java.net.URL.openConnection`, `okhttp3.Request$Builder` |
| TLS validation | `X509TrustManager`, `okhttp3.CertificatePinner`, `HostnameVerifier` |
| Storage writes | `FileOutputStream`, `SharedPreferences$Editor`, `SQLiteDatabase` |
| Logging | `android.util.Log` |
| Intents | `Activity.startActivity`, `ContextWrapper.sendBroadcast` |
| KeyStore use | `java.security.KeyStore`, `KeyGenParameterSpec$Builder` |
| WebView config | `WebSettings`, `WebView.addJavascriptInterface` |
| Reflection | `Method.invoke`, `Class.forName` |
| Native loads | `System.loadLibrary`, `System.load` |
| Process exec | `Runtime.exec`, `ProcessBuilder.start` |

---

## Static recon before you start

```bash
apktool d -o work base.apk && unzip -o -d raw base.apk
grep -rn "\.method.*native" work/smali*/ | head
nm -D --defined-only raw/lib/*/*.so | grep " T Java_" | head
grep -oE 'android:name="[^"]*"'  work/AndroidManifest.xml | head -3
grep -oE 'android:process="[^"]*"' work/AndroidManifest.xml | sort -u
grep -oE 'android:extractNativeLibs="[^"]*"' work/AndroidManifest.xml
grep -rnE "TracerPid|27042|frida|gum-js|/proc/self/(maps|status)" work/smali*/ | head
for so in raw/lib/*/*.so; do strings -a "$so" | grep -iE "frida|gum|27042|ptrace"; done
```

---

## Scripts in this chapter

```bash
frida -U -f <pkg> -l scripts/ssl-pinning-bypass.js --no-pause
frida -U -f <pkg> -l scripts/root-detection-bypass.js --no-pause
frida -U -f <pkg> -l scripts/java-method-tracer.js --no-pause     # trace.help()
frida -U -f <pkg> -l scripts/native-tracer.js --no-pause          # nat.help()
frida -U -f <pkg> -l scripts/memory-secret-scanner.js --no-pause  # mem.help()
frida -U -f <pkg> -l scripts/class-enumerator.js --no-pause       # cls.help()
```

`-l` is repeatable; later scripts see earlier globals.

---

## Cleanup

```bash
adb shell settings put global http_proxy :0
adb shell cmd package compile --reset <pkg>      # BEFORE writing the finding up
adb shell am force-stop <pkg>
adb shell "su -c 'pkill frida-server'"
```
