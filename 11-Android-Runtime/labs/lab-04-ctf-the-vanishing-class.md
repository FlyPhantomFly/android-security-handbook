# Lab 04 — CTF: The Vanishing Class

> **Difficulty:** CTF / Expert · **Time:** 3–6 hours · **Chapter:** [11 — Android Runtime](../README.md)

## Objective

**The challenge.** `com.vanishing.chal` asks for a flag and tells you whether it is right. The class
that performs the check is not in `classes.dex`. It is decrypted at startup, written to the app's
cache directory, loaded by a `DexClassLoader`, and then deleted — all within a few milliseconds of
process start. By the time you can type `ls`, the file is gone. The class is still executing.

Recover the flag. It has the form `FLAG{...}`. You are finished when the app prints **ACCEPTED**, and
when you can explain which of the three independent solution paths you took and why the other two
also work.

> **🧠 Mental Model.** A deleted file on Linux is not erased; its *name* is erased. `unlink()` removes
> a directory entry. The inode, and every byte it points at, survives as long as one reference remains
> — an open file descriptor, or a memory mapping. ART maps the DEX it is executing. The "vanished"
> file is therefore still fully present and still readable, provided you know where the kernel keeps
> the last reference. That single fact is the challenge.

---

## Prerequisites

- [Lab 03](lab-03-dynamic-dex-loading-and-hooking.md) completed; constructor hooking and DEX dumping
  must be routine.
- A rooted device or emulator (API 28+) with `frida-server` and a matching host client.
- `javac`, `d8`, `openssl`, `apksigner`, `jadx`, and Python 3 on your host, plus Gradle or Android
  Studio. You build the challenge yourself; nothing is distributed as a binary.

---

## Setup

### Step A — Generate the payload source

The flag is never written in plaintext, not even in the payload source. It is stored as a byte array
XOR-ed against a repeating key, so recovering the DEX is necessary but not sufficient.

```python
#!/usr/bin/env python3
# runs on your host machine — save as gen_guard.py, run: python3 gen_guard.py > Guard.java
FLAG = b"FLAG{unlink3d_but_still_mapp3d}"
KEY  = b"vanish"
jb = lambda bs: ", ".join("(byte) 0x%02X" % b for b in bs)
CIPH = bytes(FLAG[i] ^ KEY[i % len(KEY)] for i in range(len(FLAG)))

print("""package com.vanishing.payload;

public class Guard {
    private static final byte[] K = { %s };
    private static final byte[] C = { %s };

    public static boolean check(String candidate) {
        if (candidate == null) return false;
        byte[] b = candidate.getBytes();
        if (b.length != C.length) return false;
        int diff = 0;
        for (int i = 0; i < b.length; i++) diff |= (b[i] ^ K[i %% K.length]) ^ C[i];
        return diff == 0;
    }

    public static String banner() { return "guard-v1"; }
}""" % (jb(KEY), jb(CIPH)))
```

```bash
# runs on your host machine
mkdir -p ~/vanish/src/com/vanishing/payload ~/vanish/classes ~/vanish/out
python3 gen_guard.py > ~/vanish/src/com/vanishing/payload/Guard.java
javac -d ~/vanish/classes ~/vanish/src/com/vanishing/payload/Guard.java
"$ANDROID_HOME/build-tools/34.0.0/d8" --min-api 28 \
    --output ~/vanish/out ~/vanish/classes/com/vanishing/payload/Guard.class
```

### Step B — Create the challenge app

New project, package `com.vanishing.chal`, **minSdk 28**, language Java. Create
`app/src/main/assets/` and put a placeholder file `v.bin` in it for the first build.

```java
// file: app/src/main/java/com/vanishing/chal/MainActivity.java — runs on the device
package com.vanishing.chal;

import android.app.Activity;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.Bundle;
import android.os.Debug;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.security.MessageDigest;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import dalvik.system.DexClassLoader;

public class MainActivity extends Activity {

    private static final String TAG = "Vanish";
    private Class<?> guard;

    /** AES key = SHA-256 of this APK's signing certificate. Changes with every signer. */
    private byte[] deriveKey() throws Exception {
        PackageInfo pi = getPackageManager().getPackageInfo(
                getPackageName(), PackageManager.GET_SIGNING_CERTIFICATES);
        Signature sig = pi.signingInfo.getApkContentsSigners()[0];
        return MessageDigest.getInstance("SHA-256").digest(sig.toByteArray());
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

    private static void rmdir(File f) {
        if (f == null || !f.exists()) return;
        File[] kids = f.listFiles();
        if (kids != null) for (File k : kids) rmdir(k);
        f.delete();
    }

    private void loadGuard() throws Exception {
        // Naive tamper checks: part of the challenge, not of the security.
        if (Debug.isDebuggerConnected()) throw new IllegalStateException("no");
        if (new File("/data/local/tmp/frida-server").exists())
            throw new IllegalStateException("no");

        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(deriveKey(), "AES"),
               new IvParameterSpec(new byte[16]));
        byte[] dex = c.doFinal(readAsset("v.bin"));

        File tmp = new File(getCacheDir(), "v.dex");
        try (FileOutputStream fos = new FileOutputStream(tmp)) { fos.write(dex); }

        DexClassLoader dcl = new DexClassLoader(
                tmp.getAbsolutePath(), null, null, getClassLoader());
        guard = dcl.loadClass("com.vanishing.payload.Guard");

        // --- the vanishing act ---
        tmp.delete();
        rmdir(new File(getCacheDir(), "oat"));

        Log.i(TAG, "guard ready: " + guard.getMethod("banner").invoke(null)
                 + " (file exists? " + tmp.exists() + ")");
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        final EditText input = new EditText(this);
        final TextView out = new TextView(this);
        Button go = new Button(this);
        go.setText("Check");
        root.addView(input); root.addView(go); root.addView(out);
        setContentView(root);

        try { loadGuard(); out.setText("guard loaded"); }
        catch (Throwable t) { Log.e(TAG, "guard failed", t); out.setText("guard unavailable"); }

        go.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                try {
                    Method m = guard.getMethod("check", String.class);
                    boolean ok = (Boolean) m.invoke(null, input.getText().toString());
                    out.setText(ok ? "ACCEPTED" : "rejected");
                } catch (Throwable t) { out.setText("error: " + t); }
            }
        });
    }
}
```

### Step C — Two-pass build, because the key is the signing certificate

```bash
# runs on your host machine — pass 1: build so a signature exists
cd ~/AndroidStudioProjects/Vanish
printf 'placeholder' > app/src/main/assets/v.bin
./gradlew assembleDebug
apksigner verify --print-certs app/build/outputs/apk/debug/app-debug.apk | grep -i "SHA-256 digest"
```

Copy the 64-character hex digest; that is the AES-256 key.

```bash
# runs on your host machine — pass 2: encrypt the payload with that key, rebuild
CERT=<paste the 64-hex-char SHA-256 digest here>
openssl enc -aes-256-cbc -nosalt -K "$CERT" \
    -iv 00000000000000000000000000000000 \
    -in  ~/vanish/out/classes.dex \
    -out app/src/main/assets/v.bin
./gradlew installDebug
adb logcat -c && adb shell am start -n com.vanishing.chal/.MainActivity && adb logcat -s Vanish
```

Logcat must print `guard ready: guard-v1 (file exists? false)`. If it prints `guard unavailable`, the
key is wrong, a tamper check tripped, or the asset was not rebuilt.

> **⚠️ Warning.** The all-zero IV is a genuine cryptographic defect, used here only to keep the
> `openssl` invocation on one line. A fixed IV under a fixed key makes CBC deterministic and leaks
> equality of plaintext prefixes. Never accept this pattern in real code; see
> [34 — Cryptography](../../34-Cryptography/README.md).

---

## Steps

1. Install the app and confirm it behaves as described: it loads, it rejects wrong input, and no
   `.dex` survives anywhere under `/data/data/com.vanishing.chal/`.
2. Establish what static analysis alone gives you, and note precisely which facts remain hidden.
3. Get the DEX. There are three independent routes; attempt at least two.
4. Decompile the recovered DEX and read `Guard`.
5. Compute the flag from the constants. Do not brute-force; the arithmetic is trivial once you have
   the arrays.
6. Type the flag into the app and confirm **ACCEPTED**.

```bash
# adb shell as root — runs on the device; confirm the file is really gone
ls -la /data/data/com.vanishing.chal/cache/
find /data/data/com.vanishing.chal -name "*.dex" -o -name "*.odex" -o -name "*.vdex"
```

---

## Hints

<details>
<summary>Hint 1 — where to point the telescope</summary>

The file exists for a moment, which means something **created** it and something **destroyed** it.
Both actions were performed by methods on framework classes the app cannot rename, cannot inline, and
cannot avoid. You do not need to find the app's own code; you need to stand at the framework boundary
the app was forced to cross.

Note the timing problem as well: `onCreate` finishes before you can attach to a running process. Read
the `-f` flag in `frida --help`.

</details>

<details>
<summary>Hint 2 — the two Java-level choke points</summary>

`dalvik.system.DexClassLoader.<init>` receives the absolute path of the file as its first argument.
`java.io.File.delete()` is what makes it vanish. Hooking either one solves the challenge: hook the
constructor and copy the file somewhere the app will not clean up, or hook `delete()` and return
`true` without deleting anything.

The tamper checks are not part of the intended difficulty. One looks for a file by exact name in
`/data/local/tmp`, so rename your `frida-server` binary. The other calls
`Debug.isDebuggerConnected()`, so do not attach a Java debugger.

</details>

<details>
<summary>Hint 3 — the route that needs no hooking at all</summary>

`unlink()` removes a name, not data. ART has the DEX mapped into the app's address space, so the inode
is still referenced and still readable.

```bash
# adb shell as root — runs on the device
grep -i "v.dex" /proc/$(pidof -s com.vanishing.chal)/maps
```

Look for the `(deleted)` suffix. The kernel exposes one link per file-backed mapping under
`/proc/<pid>/map_files/<start>-<end>`, and reading that path reads the original file even though it
has no name left. This requires root.

Separately: the AES key is not hidden. It is the SHA-256 digest of the APK's own signing certificate,
and `apksigner verify --print-certs` prints it for any APK you hold.

</details>

---

## Success Criteria

1. You possess a file whose first four bytes are `64 65 78 0a` and which `jadx` decompiles into
   `com.vanishing.payload.Guard`.
2. You can print both constant arrays, `K` and `C`, from that decompilation.
3. You have a short script that turns those arrays into the flag.
4. Pasting the flag into the app produces **ACCEPTED**.
5. You can explain why the deleted file was still readable, referring to inodes and references rather
   than to "caching".
6. You can name two changes to the app that would defeat your chosen route, and say which route would
   still work afterwards.

---

## Solution

<details>
<summary>Reveal solution</summary>

### What static analysis alone tells you

```bash
# runs on your host machine
jadx -d /tmp/vanish-jadx app/build/outputs/apk/debug/app-debug.apk
grep -rn "com.vanishing.payload" /tmp/vanish-jadx/sources | head
```

You learn the class name, the cipher, the zero IV, and the key derivation. You do not get the flag,
because the `Guard` bytecode is not in this APK. That already narrows the problem to "obtain one DEX".

### Route A — hook the constructor, steal the file before it dies

```bash
# adb shell as root — runs on the device; defeat the naive tamper check
mv /data/local/tmp/frida-server /data/local/tmp/fs
/data/local/tmp/fs &
```

```javascript
// Frida script — save as vanish.js, run: frida -U -f com.vanishing.chal -l vanish.js
Java.perform(function () {
    var DCL  = Java.use('dalvik.system.DexClassLoader');
    var File = Java.use('java.io.File');
    var FIS  = Java.use('java.io.FileInputStream');
    var FOS  = Java.use('java.io.FileOutputStream');

    function copy(src, dst) {
        var i = FIS.$new(src), o = FOS.$new(dst);
        var buf = Java.array('byte', new Array(65536).fill(0)), n;
        while ((n = i.read(buf)) > 0) o.write(buf, 0, n);
        i.close(); o.close();
        console.log("[+] copied " + src + " -> " + dst);
    }

    DCL.$init.overload('java.lang.String', 'java.lang.String',
                       'java.lang.String', 'java.lang.ClassLoader')
       .implementation = function (dexPath, optDir, libPath, parent) {
        console.log("[!] DexClassLoader(" + dexPath + ")");
        try { copy(dexPath, "/data/local/tmp/stolen.dex"); }
        catch (e) { console.log("[-] copy failed: " + e); }
        return this.$init(dexPath, optDir, libPath, parent);
    };

    // Belt and braces: refuse to let the file be deleted at all.
    File.delete.implementation = function () {
        var p = this.getAbsolutePath();
        if (p.indexOf("v.dex") !== -1 || p.indexOf("/oat") !== -1) {
            console.log("[*] blocked delete of " + p);
            return true;                       // lie: the app believes it succeeded
        }
        return this.delete();
    };
});
```

```bash
# runs on your host machine
frida -U -f com.vanishing.chal -l vanish.js
adb pull /data/local/tmp/stolen.dex .
```

Returning `true` from the hooked `delete()` matters: the app logs `file exists? false` because it
never re-checks, and no code path depends on the file actually being gone. Lying to a caller that
ignores the result is the cheapest possible bypass, and the pattern generalises far beyond this lab;
see [65 — Hooking](../../65-Hooking/README.md).

### Route B — recover the unlinked inode from `/proc`

No Frida, no bypass of the tamper checks. Just the kernel.

```bash
# adb shell as root — runs on the device
PID=$(pidof -s com.vanishing.chal)
grep -i "v.dex" /proc/$PID/maps
```

```text
# example output — device shell; addresses differ
71a2c40000-71a2c41000 r--p 00000000 fe:07 262148  /data/user/0/com.vanishing.chal/cache/v.dex (deleted)
```

```bash
# adb shell as root — runs on the device; use the mapping's start-end, no 0x prefix
cat /proc/$PID/map_files/71a2c40000-71a2c41000 > /data/local/tmp/recovered.dex
head -c 4 /data/local/tmp/recovered.dex | xxd
```

`/proc/<pid>/map_files/` contains one link per file-backed mapping, and each resolves to the
underlying inode rather than to a pathname. Opening it reads the whole original file, not merely the
mapped page range, which is why the recovered file has the correct size even though the mapping shown
covers one page. Access requires `CAP_SYS_ADMIN`, which is why this route needs root.

> **🔬 Under the Hood.** ART opens the DEX and `mmap`s it so class data can be read lazily and shared.
> That mapping is a reference on the inode, so `unlink()` drops the link count to zero but the kernel
> defers reclamation until the last reference goes away. The `(deleted)` marker in `/proc/<pid>/maps`
> is the kernel telling you exactly this. The same technique recovers unlinked native libraries,
> databases, and temporary files from any Linux process; it is not Android-specific.

### Route C — decrypt the asset statically

```bash
# runs on your host machine
apksigner verify --print-certs app/build/outputs/apk/debug/app-debug.apk | grep -i "SHA-256 digest"
unzip -p app/build/outputs/apk/debug/app-debug.apk assets/v.bin > v.bin
CERT=<the 64-hex-char digest>
openssl enc -d -aes-256-cbc -nosalt -K "$CERT" \
    -iv 00000000000000000000000000000000 -in v.bin -out static.dex
head -c 4 static.dex | xxd
```

This works because "the key is the signing certificate" is a *tamper*-detection idea, not a *secrecy*
idea: the certificate is public by construction, since every verifier must read it. Developers reach
for this pattern believing it binds the payload to an untampered build. It does bind it — an attacker
who re-signs the APK breaks decryption — but it hides nothing from an analyst holding the original
APK. That distinction belongs in your report; see
[38 — Tamper Detection](../../38-TamperDetection/README.md).

### Extracting the flag

```bash
# runs on your host machine
jadx -d ./guard-src stolen.dex
sed -n '1,30p' ./guard-src/sources/com/vanishing/payload/Guard.java
```

```python
#!/usr/bin/env python3
# runs on your host machine — save as solve.py; paste the arrays jadx printed
K = bytes([0x76, 0x61, 0x6E, 0x69, 0x73, 0x68])   # Guard.K
C = bytes([ ... ])                                 # Guard.C, in order
print("".join(chr(C[i] ^ K[i % len(K)]) for i in range(len(C))))
```

The printed string is the flag. Type it into the app and the label changes to **ACCEPTED**.

If you would rather not transcribe arrays, read them out of the running process instead.

```javascript
// Frida REPL — paste after the app has loaded the guard
Java.perform(function () {
    Java.enumerateClassLoaders({
        onMatch: function (l) {
            try {
                var G = Java.ClassFactory.get(l).use("com.vanishing.payload.Guard");
                var fk = G.class.getDeclaredField("K"); fk.setAccessible(true);
                var fc = G.class.getDeclaredField("C"); fc.setAccessible(true);
                var k = fk.get(null), c = fc.get(null), s = "";
                for (var i = 0; i < c.length; i++)
                    s += String.fromCharCode((c[i] ^ k[i % k.length]) & 0xff);
                console.log("[FLAG] " + s);
            } catch (e) { }
        },
        onComplete: function () { }
    });
});
```

### What would have made this harder

| Change to the challenge | Which route it breaks | Which route still works |
|---|---|---|
| Use `InMemoryDexClassLoader` instead of a temp file | B, and C's usefulness drops | A, retargeted at the buffer — see [Lab 03](lab-03-dynamic-dex-loading-and-hooking.md) |
| Decrypt and load from native code via JNI `DefineClass` | A, if it only hooks Java | B, and native hooking |
| Fetch the payload from a server on every launch | C | A and B |
| Detect Frida properly rather than by one filename | A, until the detection is bypassed | B and C |
| Keep the check on a server | All three | None; this is the only real fix |

The last row is the recommendation. Every other row buys time, and time is the only currency
obfuscation trades in.

</details>

---

**Chapter labs complete.** Return to [11 — Android Runtime](../README.md), or continue into
[12 — DEX Internals](../../12-DEX-Internals/README.md) to learn what the bytes you recovered mean, and
[13 — ART](../../13-ART/README.md) for how the runtime executes them.
