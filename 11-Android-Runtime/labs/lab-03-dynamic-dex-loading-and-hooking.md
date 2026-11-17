# Lab 03 — Dynamic DEX Loading and Hooking

> **Difficulty:** Advanced · **Time:** 2–4 hours · **Chapter:** [11 — Android Runtime](../README.md)

An app that ships all of its code inside `classes.dex` is an app you decompile in thirty seconds. Real
protection schemes therefore do not do that. They ship an encrypted blob, decrypt it in memory at
runtime, hand the plaintext straight to the runtime without ever touching the filesystem, and call
into it by reflection. On disk there is nothing to decompile. In this lab you build exactly that app,
confirm that static analysis fails, and then defeat it — because the runtime must eventually be given
the plaintext, and whatever the runtime receives, you can receive too.

---

## Objective

**Build** an app that reads `assets/payload.enc`, decrypts it with AES-256-CBC into a `byte[]`,
constructs an `InMemoryDexClassLoader` over that buffer, and reflectively invokes a class that exists
nowhere on disk in plaintext.

**Attack** it with a [Frida](../../53-Frida/README.md) script that hooks
`dalvik.system.InMemoryDexClassLoader.<init>`, copies the `ByteBuffer` argument to a file, and lets
you recover the hidden class with [jadx](../../56-JADX/README.md) — without ever learning the AES key.

> **Definition — InMemoryDexClassLoader.** Added in API 26, this is a `BaseDexClassLoader` that
> takes a `java.nio.ByteBuffer` (or an array of them, from API 29) instead of a filesystem path. ART
> parses the DEX container directly out of that buffer. No file is created, no `oat/` artefact is
> written, and nothing appears in `/data/data` for a forensic tool to find. The container format is
> [12 — DEX Internals](../../12-DEX-Internals/README.md).

---

## Prerequisites

- [Lab 02](lab-02-classloader-archaeology.md) completed; walking `pathList` and `dexElements` must be
  routine.
- `javac`, `d8`, `openssl`, and `jadx` on your host `PATH`.
- `frida-server` on a rooted device or emulator (API 28+), matching your host client.
- Key, IV, block mode, and padding vocabulary from
  [34 — Cryptography](../../34-Cryptography/README.md); this lab uses them without re-teaching them.

---

## Setup

### Step A — Write and compile the payload class

```java
// file: ~/memlab-payload/com/example/hidden/Secret.java — compiled on your host, executed on the device
package com.example.hidden;

public class Secret {

    private static final String LICENCE_PREFIX = "MEMLAB-";

    public static String compute(String seed) {
        StringBuilder sb = new StringBuilder(LICENCE_PREFIX);
        int acc = 0x5A;
        for (int i = 0; i < seed.length(); i++) {
            acc = (acc * 31 + seed.charAt(i)) & 0xFF;
            sb.append(String.format("%02X", acc));
        }
        return sb.toString();
    }

    public static boolean isPremium(String licence) {
        return licence != null && licence.equals(compute("device-bound"));
    }
}
```

```bash
# runs on your host machine
mkdir -p ~/memlab-payload/com/example/hidden ~/memlab-payload/classes ~/memlab-payload/out
javac -d ~/memlab-payload/classes ~/memlab-payload/com/example/hidden/Secret.java
"$ANDROID_HOME/build-tools/34.0.0/d8" --min-api 26 \
    --output ~/memlab-payload/out ~/memlab-payload/classes/com/example/hidden/Secret.class
```

Encrypt with a fixed key and IV so the Java side can hard-code them. The values below are the
published AES-256 test vectors from NIST SP 800-38A, chosen so nobody mistakes this for real key
management.

```bash
# runs on your host machine
KEY=603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4
IV=000102030405060708090a0b0c0d0e0f
openssl enc -aes-256-cbc -nosalt -K "$KEY" -iv "$IV" \
    -in  ~/memlab-payload/out/classes.dex \
    -out ~/memlab-payload/out/payload.enc
xxd ~/memlab-payload/out/payload.enc | head -n 2
mkdir -p ~/AndroidStudioProjects/MemLab/app/src/main/assets
cp ~/memlab-payload/out/payload.enc \
   ~/AndroidStudioProjects/MemLab/app/src/main/assets/payload.enc
```

The first bytes must **not** read `dex\n035`. If they do, encryption did not happen.

### Step B — Write the loader app

```java
// file: app/src/main/java/com/example/memlab/MainActivity.java — runs on the device
package com.example.memlab;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import dalvik.system.InMemoryDexClassLoader;

public class MainActivity extends Activity {

    private static final String TAG = "MemLab";
    private static final String KEY_HEX =
            "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";
    private static final String IV_HEX = "000102030405060708090a0b0c0d0e0f";

    private static byte[] hex(String s) {
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    private byte[] readAsset(String name) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (InputStream in = getAssets().open(name)) {
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) > 0) bos.write(buf, 0, n);
        }
        return bos.toByteArray();
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        TextView tv = new TextView(this);
        setContentView(tv);

        String result;
        try {
            Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
            c.init(Cipher.DECRYPT_MODE,
                   new SecretKeySpec(hex(KEY_HEX), "AES"),
                   new IvParameterSpec(hex(IV_HEX)));
            byte[] dex = c.doFinal(readAsset("payload.enc"));

            Log.i(TAG, "decrypted " + dex.length + " bytes, magic=" + String.format(
                    "%02X%02X%02X%02X", dex[0], dex[1], dex[2], dex[3]));

            InMemoryDexClassLoader loader =
                    new InMemoryDexClassLoader(ByteBuffer.wrap(dex), getClassLoader());

            Class<?> secret = loader.loadClass("com.example.hidden.Secret");
            Method compute = secret.getMethod("compute", String.class);
            String token = (String) compute.invoke(null, "device-bound");
            Method isPremium = secret.getMethod("isPremium", String.class);
            boolean premium = (Boolean) isPremium.invoke(null, token);

            result = "token   = " + token + "\npremium = " + premium;
            java.util.Arrays.fill(dex, (byte) 0);   // best-effort scrub; see warning below
        } catch (Throwable t) {
            Log.e(TAG, "load failed", t);
            result = "error: " + t;
        }
        Log.i(TAG, result);
        tv.setText(result);
    }
}
```

```bash
# runs on your host machine
./gradlew installDebug
adb logcat -c && adb shell am start -n com.example.memlab/.MainActivity && adb logcat -s MemLab
```

> **Warning.** `Arrays.fill(dex, (byte) 0)` is theatre, not security. By the time it runs ART has
> copied the DEX contents into its own native structures, and the garbage collector may have moved or
> duplicated the array. Developers who write this line believe they mitigated memory dumping. They did
> not. Never accept it as a compensating control in a report.

---

## Steps

### Step 1 — Confirm static analysis fails

```bash
# runs on your host machine
./gradlew assembleDebug
jadx -d /tmp/memlab-jadx app/build/outputs/apk/debug/app-debug.apk
grep -r "com.example.hidden" /tmp/memlab-jadx/sources || echo "NOT FOUND in decompiled output"
```

`classes.dex` contains `MainActivity` and nothing else of interest. `assets/payload.enc` is
high-entropy noise. The string `com.example.hidden.Secret` appears exactly once, as a constant passed
to `loadClass`, with no class behind it. This is the analyst's dead end and it is the entire point of
the technique; see [52 — Static Analysis](../../52-StaticAnalysis/README.md) for why entropy alone is
not a finding.

### Step 2 — Confirm nothing hits the filesystem

```bash
# adb shell as root — runs on the device
find /data/data/com.example.memlab -type f 2>/dev/null
grep -E "\.(dex|odex|vdex)" /proc/$(pidof -s com.example.memlab)/maps
```

No `.dex` appears anywhere the app can write, and the only DEX-family mappings belong to `base.apk`
and the boot image. Compare with [Lab 01, Step 7](lab-01-observing-the-runtime.md), where the mappings
told you everything; here they tell you nothing, because the code never became a file.

> **Under the Hood.** Given a `ByteBuffer`, `InMemoryDexClassLoader` reaches
> `DexFile.openInMemoryDexFile` and then native code that constructs an `art::DexFile` over a copy of
> the buffer contents in an anonymous, ART-owned region. Because there is no file, there is no
> `dex2oat` invocation and no `.odex`: in-memory DEX is always interpreted or JIT-compiled, never
> ahead-of-time compiled. That performance cost is one of the few reliable behavioural fingerprints of
> the technique. The framework file is
> `libcore/dalvik/src/main/java/dalvik/system/InMemoryDexClassLoader.java`.

### Step 3 — Hook the constructor and dump the buffer

The plaintext must pass through one specific place: the `ByteBuffer` argument. Hook it there, across
every overload, because the signature set differs by API level.

```javascript
// Frida script — save as dumpdex.js, run: frida -U -f com.example.memlab -l dumpdex.js
Java.perform(function () {
    var IMDCL = Java.use('dalvik.system.InMemoryDexClassLoader');
    var FOS   = Java.use('java.io.FileOutputStream');
    var n     = 0;

    function dump(buf) {
        if (buf === null || buf === undefined) return;
        var dup = buf.duplicate();          // independent position; do not disturb the app
        dup.rewind();
        var len = dup.remaining();
        if (len < 112) { console.log("[-] skipping " + len + "-byte buffer"); return; }

        var arr = Java.array('byte', new Array(len).fill(0));
        dup.get(arr);
        var path = "/data/local/tmp/dumped_" + (n++) + ".dex";
        var f = FOS.$new(path); f.write(arr); f.close();

        var magic = [0, 1, 2, 3].map(function (i) {
            return ("0" + (arr[i] & 0xff).toString(16)).slice(-2); }).join("");
        console.log("[+] " + path + " len=" + len + " magic=" + magic +
                    (magic === "6465780a" ? "  (valid DEX)" : "  (NOT dex!)"));
    }

    IMDCL.$init.overloads.forEach(function (ovl) {
        var sig = ovl.argumentTypes.map(function (t) { return t.className; }).join(", ");
        console.log("[*] hooking InMemoryDexClassLoader(" + sig + ")");
        ovl.implementation = function () {
            var a0 = arguments[0];
            if (a0 !== null && a0 !== undefined) {
                if (typeof a0.length === "number" && !a0.$className) {
                    for (var i = 0; i < a0.length; i++) dump(a0[i]);   // ByteBuffer[] overload
                } else {
                    dump(a0);                                          // single ByteBuffer
                }
            }
            var r = ovl.apply(this, arguments);
            console.log("[*] loader constructed: " + this.$className + "@" + this.hashCode());
            return r;
        };
    });
});
```

The reported magic must be `6465780a`, the ASCII bytes `dex\n`. Anything else means you dumped the
wrong buffer, or dumped it after ART consumed it.

### Step 4 — Recover and decompile

```bash
# runs on your host machine
adb pull /data/local/tmp/dumped_0.dex .
file dumped_0.dex
jadx -d ./secret-src dumped_0.dex
cat ./secret-src/sources/com/example/hidden/Secret.java
```

You now have the source of a class that never existed as a file, and you never learned the AES key.
That asymmetry is the lesson: **the key was never the secret worth protecting, because the runtime is
a mandatory decryption oracle.**

> **Pentester's Note.** In a report, do not write "the app uses a hard-coded AES key". Write "the
> protected code is recoverable without recovering the key, because the runtime requires plaintext DEX
> at a fixed, hookable API boundary". The first finding invites the developer to rotate the key, which
> fixes nothing. The second correctly frames in-memory loading as obfuscation with a cost measured in
> analyst-minutes, not as a security control.

### Step 5 — Generalise: find memory-backed loaders after the fact

Constructor hooking works only if you attach first. A wider net inspects loaders that already exist.

```javascript
// Frida script — save as watchloaders.js, run: frida -U -n com.example.memlab -l watchloaders.js
Java.perform(function () {
    var BDCL = Java.use('dalvik.system.BaseDexClassLoader');
    var DPL  = Java.use('dalvik.system.DexPathList');
    var EL   = Java.use('dalvik.system.DexPathList$Element');

    Java.enumerateClassLoaders({
        onMatch: function (l) {
            try {
                var pl  = Java.cast(Java.cast(l, BDCL).pathList.value, DPL);
                var els = pl.dexElements.value;
                for (var i = 0; i < els.length; i++) {
                    var df = Java.cast(els[i], EL).dexFile.value;
                    if (df === null) continue;
                    var name = df.getName();
                    if (name === null || name.indexOf('/') === -1) {
                        console.log("[mem] " + l.$className + "@" + l.hashCode() +
                                    " dex name = " + name);
                    }
                }
            } catch (e) { }
        },
        onComplete: function () { }
    });
});
```

A `DexFile` whose `getName()` is not an absolute path is memory-backed. That is the tell you met at
the end of [Lab 02](lab-02-classloader-archaeology.md), now used offensively.

---

## Hints

- Attach with `-f` (spawn and hold), not `-n`. `onCreate` runs within milliseconds of launch and a
  plain attach misses the constructor entirely.
- Use `buf.duplicate()` before `get()`. Reading the original advances its position, ART then parses a
  truncated DEX, and the app crashes in a way that looks unrelated to your hook.
- `Java.array('byte', new Array(len).fill(0))` allocates the destination. A type error there means you
  passed a JavaScript array where Frida wanted a Java one.
- If `FileOutputStream.$new` throws, the app cannot write to your chosen directory. Fall back to the
  app's own `files` directory and `adb pull` it as root.
- A jadx checksum error means you dumped fewer bytes than the header claims. Compare `remaining()`
  with the `file_size` field at offset 32 of the DEX header, described in
  [12 — DEX Internals](../../12-DEX-Internals/README.md).
- Nothing printed at all? The app may be loading via `DexClassLoader` from a temporary file instead.
  Hook `dalvik.system.DexClassLoader.$init` too, and read [Lab 04](lab-04-ctf-the-vanishing-class.md).

---

## Success Criteria

1. `jadx` on the original APK produces no `com.example.hidden` package.
2. The app logs a token beginning `MEMLAB-`, proving the hidden class executed.
3. `/proc/<pid>/maps` shows no `.dex` mapping outside `base.apk` and the boot image.
4. Your dump's first four bytes are `64 65 78 0a`.
5. `jadx` on the dump reproduces `Secret.compute` closely enough that you can recompute the token by
   hand and get the same string the app printed.
6. You can state in one sentence why recovering the AES key was unnecessary.

---

## Solution

<details>
<summary>Reveal solution</summary>

### End-to-end transcript

```text
# example output — host terminal, running dumpdex.js
[*] hooking InMemoryDexClassLoader(java.nio.ByteBuffer, java.lang.ClassLoader)
[*] hooking InMemoryDexClassLoader([Ljava.nio.ByteBuffer;, java.lang.ClassLoader)
[+] /data/local/tmp/dumped_0.dex len=1284 magic=6465780a  (valid DEX)
[*] loader constructed: dalvik.system.InMemoryDexClassLoader@231758291
```

```bash
# runs on your host machine
adb pull /data/local/tmp/dumped_0.dex .
jadx -d ./secret-src dumped_0.dex
sed -n '1,40p' ./secret-src/sources/com/example/hidden/Secret.java
```

The decompiled `compute` is a loop over the seed characters accumulating
`acc = (acc * 31 + ch) & 0xFF` and appending two uppercase hex digits, starting at `0x5A` after the
prefix `MEMLAB-`. Reimplement it in any language and confirm it matches the app's logged token for the
seed `device-bound`. Matching output proves the dump is complete and correct, not merely a file with
the right magic bytes.

### Why the attack cannot be prevented at this layer

The runtime is a mandatory participant. To execute a class, ART must be handed a parseable DEX
container in a memory region it controls. Every scheme that hides DEX — asset encryption, native
decryption in a `.so`, downloading from a server, deriving keys from attestation — converges on the
same final instruction: give plaintext bytes to a loader. There are only a handful of such loaders,
they are framework classes the app cannot rename, and their constructors are the choke point.

The useful defensive question is therefore never "how do I stop this" but "how much analyst time does
this buy, and against whom".

| Defence layered on top | Effect on this attack | Real cost to the attacker |
|---|---|---|
| Decrypt in a native library instead of Java | The `ByteBuffer` still reaches the same constructor | None; the hook is unchanged |
| Load via JNI `DefineClass` from native code | A Java-level constructor hook misses it | Moderate; hook the native symbol |
| Root and Frida detection before loading | The script must run first, or defeat the check | Low; see [37 — Root Detection](../../37-RootDetection/README.md) |
| Split the payload across many small buffers | Produces several dumps to reassemble | Low; the loop already handles arrays |
| Execute the sensitive logic server-side | The logic is never on the device to dump | High; this is the only real fix |

The last row is the recommendation that belongs in a report. Everything above it is obfuscation, and
obfuscation is measured in hours, not in "prevented".

### Catching the file-backed cousins too

Adding this block to `dumpdex.js` makes one script cover this lab and the next one, because
`DexClassLoader` and `PathClassLoader` take a path where `InMemoryDexClassLoader` takes a buffer.

```javascript
// Frida script — append to dumpdex.js
['dalvik.system.DexClassLoader', 'dalvik.system.PathClassLoader'].forEach(function (cn) {
    var C = Java.use(cn);
    C.$init.overloads.forEach(function (ovl) {
        ovl.implementation = function () {
            console.log("[*] " + cn + " <- " + arguments[0]);
            return ovl.apply(this, arguments);
        };
    });
});
```

### Detection guidance for the defensive half of a report

```bash
# runs on your host machine
jadx -d /tmp/target --no-res target.apk
grep -rn "InMemoryDexClassLoader\|openInMemoryDexFile\|ByteBuffer.wrap" /tmp/target/sources | head
```

For obfuscated targets where the string is gone, the behavioural signature holds: a process containing
a `BaseDexClassLoader` whose `DexFile.getName()` is not a path, with no corresponding `oat/` artefact,
is loading code from memory. Malware families are profiled this way in
[69 — Malware Analysis](../../69-MalwareAnalysis/README.md).

</details>

---

**Next:** [Lab 04 — CTF: The Vanishing Class](lab-04-ctf-the-vanishing-class.md) — this time the code
does touch the disk, but only for a few milliseconds.
