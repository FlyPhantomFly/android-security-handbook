# 11 — Android Runtime · Cheat Sheet

Printable. No prose. See [README.md](README.md) for why each of these works.
Implementation detail (OAT, VDEX, `ArtMethod`, GC) is in [13-ART](../13-ART/cheatsheet.md).

---

## The two commands that unblock you most

```bash
# 1. Class visible in JADX but Java.use() throws? It's a ClassLoader problem.
#    (Frida REPL — see the snippet under "Class loading" below)

# 2. Hook installs but never fires? Force the interpreter.
adb shell cmd package compile -m verify -f <pkg>
adb shell am force-stop <pkg>
```

---

## What the runtime enforces — and what it does NOT

| Property | Enforced by | Security boundary? |
|---|---|---|
| Type safety of managed code | Bytecode verifier | ❌ correctness only |
| Array bounds checks | Runtime | ❌ correctness only |
| `private` / `internal` | Compiler only | ❌ reflection ignores it |
| Hidden API restrictions | ART, in-process | ❌ in-process bypass |
| Class shadowing | ClassLoader delegation | ⚠️ platform classes only |
| Memory isolation | **Kernel** (UID, page tables) | ✅ |
| Syscall restriction | **Kernel** (seccomp-bpf) | ✅ |
| File access between apps | **Kernel** DAC + **SELinux** MAC | ✅ |
| Permission checks | **system_server**, vs calling UID | ✅ |

> The runtime executes the app's intentions; the kernel constrains the app's reach.

---

## Class loading

### Hierarchy

```
BootClassLoader                    framework: java.*, android.*
  └── PathClassLoader              the app's own APK + splits
        └── DexClassLoader         DEX from an arbitrary file path
        └── InMemoryDexClassLoader DEX from a ByteBuffer — no file on disk
        └── DelegateLastClassLoader ⚠️ INVERTS delegation (self before parent)
```

### Parent delegation

```java
loadClass(name):
  1. findLoadedClass(name)      already loaded by me?
  2. parent.loadClass(name)     ask parent FIRST
  3. findClass(name)            only now search my own DexPathList
```

Protects platform classes from shadowing. Protects nothing about the app's own classes.

### Find a class in any loader (Frida)

```javascript
Java.perform(function () {
    Java.enumerateClassLoaders({
        onMatch: function (loader) {
            try {
                loader.loadClass("com.example.hidden.Payload");
                console.log("[+] found in " + loader);
                Java.classFactory.loader = loader;   // switch context
            } catch (e) {}
        },
        onComplete: function () {}
    });
});
```

### List every loader

```javascript
Java.perform(function () {
    Java.enumerateClassLoaders({
        onMatch: function (l) { console.log(l); },
        onComplete: function () {}
    });
});
```

---

## Dynamic code loading

| Class | Source of DEX | Leaves a file? |
|---|---|---|
| `PathClassLoader` | APK on disk | n/a |
| `DexClassLoader` | arbitrary file path | yes |
| `InMemoryDexClassLoader` | `ByteBuffer` | **no** |
| `DexFile` (legacy) | file path | yes |

### Static detection

```bash
grep -rn "DexClassLoader\|InMemoryDexClassLoader\|PathClassLoader\|DexFile" out/sources/
grep -rn "getExternalFilesDir\|getExternalStorageDirectory\|/sdcard" out/sources/
# THE OVERLAP IS THE FINDING
```

### Dynamic capture

```bash
frida -U -f <pkg> -l examples/hook-classloaders.js     # SPAWN, never attach
# hardened version with memory sweep:
frida -U -f <pkg> -l ../13-ART/scripts/dump-loaded-dex.js
```

### Severity

| Situation | Severity |
|---|---|
| DEX on shared storage, or fetched without integrity | **High** — RCE in the app's context |
| DEX app-private but unverified | Medium — needs root or a write primitive |
| DEX app-private **and** signature-verified vs pinned key | Informational — correct design |

⚠️ A stored **hash** is not enough. Whoever can replace the DEX can replace the hash. Verify a
**signature** against a public key pinned in the app.

---

## Reflection

### Trace it (Frida)

```javascript
Java.perform(function () {
    var C = Java.use("java.lang.Class");
    C.forName.overload("java.lang.String").implementation = function (n) {
        console.log("[forName] " + n); return this.forName(n);
    };
    C.getMethod.overload("java.lang.String", "[Ljava.lang.Class;")
     .implementation = function (n, p) {
        console.log("[getMethod] " + this.getName() + "." + n);
        return this.getMethod(n, p);
    };
    var M = Java.use("java.lang.reflect.Method");
    M.invoke.overload("java.lang.Object", "[Ljava.lang.Object;")
     .implementation = function (t, a) {
        console.log("[invoke] " + this.getDeclaringClass().getName() + "." + this.getName());
        return this.invoke(t, a);
    };
});
```

Reflection is a **technique**, not a finding. The finding is what it reaches.

---

## Runtime.exec

```javascript
Java.perform(function () {
    var R = Java.use("java.lang.Runtime");
    R.exec.overload("java.lang.String").implementation = function (c) {
        console.log("[exec] " + c); return this.exec(c);
    };
    R.exec.overload("[Ljava.lang.String;").implementation = function (c) {
        console.log("[exec] " + c.join(" ")); return this.exec(c);
    };
});
```

Most hits = root detection (`which su`, `su -c id`). See [37](../37-RootDetection/README.md).

---

## Hidden API

| List | Behaviour |
|---|---|
| SDK | allowed |
| Blocklist | denied, throws |
| `max-target-*` | allowed only if `targetSdk` ≤ named level |
| Unsupported (greylist) | allowed, logs a warning |

```bash
adb shell settings put global hidden_api_policy 1   # 0=enforce 1=allow all 2=warn
```

Enforcement is in-process, driven by bits in the member's `access_flags_`. In-process = bypassable.

---

## Manifest attributes that change runtime behaviour

| Attribute | Effect |
|---|---|
| `android:name` on `<application>` | **Check this first.** Obscure class = likely packer stub |
| `android:vmSafeMode="true"` | Disables JIT + AOT optimisation; all interpreted |
| `android:debuggable="true"` | JDWP, CheckJNI, forces interpretation |
| `android:largeHeap="true"` | Raises heap cap |
| `android:extractNativeLibs="false"` | `.so` mapped from APK, not extracted |

---

## Packer identification

| Signal | Meaning |
|---|---|
| `classes.dex` < 100 KB in a large APK | Stub loader only |
| Multi-MB high-entropy file in `assets/` | Encrypted payload |
| `<application android:name>` is one obscure class | Packer entry point |
| `.so` loaded in `attachBaseContext` | Native decryption |
| `apktool` fails but the app installs | Anti-decompilation |

```bash
unzip -o app.apk -d /tmp/apk >/dev/null
find /tmp/apk/assets -type f -size +100k -exec sh -c \
  'printf "%-50s " "$1"; ent "$1" 2>/dev/null | head -1' _ {} \;
```

---

## Execution modes (summary — detail in ch 13)

```
interpreted ──hotness──▶ JIT compiled ──┐
     ▲                                   │ deoptimization
     └───────────────────────────────────┘
AOT compiled ──deoptimization──▶ interpreted
```

```bash
adb shell dumpsys package dexopt | grep -A5 "<pkg>"
adb shell cmd package compile -m verify -f <pkg>   # → interpreter (best for hooks)
adb shell cmd package compile -m speed  -f <pkg>   # → full AOT + inlining
adb shell cmd package compile --reset <pkg>
```

---

## Diagnostics

| Need | Command |
|---|---|
| Runtime events, GC, verification | `adb logcat -s art` |
| Managed vs native heap | `adb shell dumpsys meminfo <pkg>` |
| Heap dump | `adb shell am dumpheap <pid> /data/local/tmp/h.hprof` |
| Convert hprof for MAT | `hprof-conv h.hprof h-std.hprof` |
| Watch DEX being mapped | `strace -f -e trace=openat,mmap -p <pid>` |
| Loader chain from inside the app | see `examples/ClassLoaderInspector.java` |

---

## Chapter scripts

| Script | Use |
|---|---|
| `scripts/runtime-recon.js` | Enumerate loaders, classes, runtime state |
| `scripts/find-dynamic-loading.py` | Cross-reference dynamic loading vs external storage |
| `scripts/dexopt-inspect.sh` | Report and change compilation state |
| `examples/hook-classloaders.js` | Capture dynamically loaded DEX |

---

## Rules

1. **Spawn (`-f`), never attach (`-n`)**, against anything that might be packed.
2. Check `<application android:name>` before anything else.
3. `ClassNotFoundException` in Frida = ClassLoader problem, **not** anti-hooking.
4. Reflection is a technique; the finding is what it reaches.
5. A bypassed in-process control is a prerequisite, not the vulnerability.
6. Analysing only the APK's DEX misses dynamically loaded code entirely.
7. The verifier is not a sandbox. `private` is not access control.
8. Real boundaries need a different UID on the other side.
