# Lab 04 — CTF: The Lying DEX

**Difficulty:** Advanced
**Time:** 2–4 hours
**Prerequisites:** [Lab 01](lab-01-parse-dex-by-hand.md), [Lab 02](lab-02-decode-instructions.md),
[Chapter 12 §3.22, §5.2](../README.md)

---

## The challenge

You are handed an APK. Your tools tell you it is boring: a handful of classes, no obvious secrets, a
clean manifest, nothing interesting in the string table.

The app, running on a device, disagrees. It prints a flag you cannot find anywhere in your decompiled
output.

**Recover the flag, and explain the mechanism that made your tools lie to you.**

There are at least three independent ways in. Find one, then find a second — the point of this lab is
that the format gives you several angles, and knowing more than one is what makes you fast.

---

## Rules

- No running the app and reading the flag off the screen. That works and teaches nothing.
- No brute force.
- You must be able to explain **why** your first approach failed, in terms of specific DEX structures.

---

## Building the challenge

Build it yourself — implementing the deception is half the education.

### Part 1 — the visible app

A trivial app whose decompiled source contains nothing of interest.

**`MainActivity.java`**

```java
package com.artlab.lyingdex;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;

public class MainActivity extends Activity {
    private static final String TAG = "LYINGDEX";

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        TextView tv = new TextView(this);
        setContentView(tv);

        String result = Helper.compute();
        Log.i(TAG, result);
        tv.setText(result);
    }
}
```

**`Helper.java`**

```java
package com.artlab.lyingdex;

public class Helper {
    // Decompiles to something entirely mundane.
    static String compute() {
        return "nothing to see here";
    }
}
```

### Part 2 — the hidden payload

Build a *second* DEX containing the real code, then append it to the first in a way the map does not
describe.

**`Payload.java`** — compiled into a separate DEX:

```java
package com.artlab.lyingdex;

public class Payload {
    public static String flag() {
        // Assembled at runtime so it is not one contiguous string constant.
        StringBuilder sb = new StringBuilder();
        sb.append("ARTLAB");
        sb.append((char) 0x7B);          // {
        sb.append("map_gaps_hide_things");
        sb.append((char) 0x7D);          // }
        return sb.toString();
    }
}
```

### Part 3 — the deception

Three mechanisms; implement at least one, ideally all three so you can compare.

**Mechanism A — payload in a map gap.** Append the payload DEX to `classes.dex` **without** adding a
`map_list` entry for it, and without updating `header.file_size`. A tool that walks the map sees
nothing. Recompute the Adler-32 and SHA-1 afterwards so the file still passes a naive integrity check.

```python
# build-lying-dex.py
import struct, zlib, hashlib

main    = bytearray(open("classes.dex", "rb").read())
payload = open("payload.dex", "rb").read()

# Append the payload past everything the map describes.
offset = len(main)
main += payload

# DELIBERATELY do not update file_size, and do not add a map entry.
# A parser that trusts the map will never look here.
# (To make the file *look* consistent to a lenient parser, you could update
#  file_size instead and leave the map alone — try both variants.)

# Recompute the unkeyed integrity fields so a naive check still passes.
struct.pack_into("<I", main, 8, 0)                      # zero checksum first
sig = hashlib.sha1(bytes(main[32:])).digest()
main[12:32] = sig
adler = zlib.adler32(bytes(main[12:])) & 0xFFFFFFFF
struct.pack_into("<I", main, 8, adler)

open("classes.dex", "wb").write(bytes(main))
print(f"payload appended at offset 0x{offset:x}, {len(payload)} bytes")
```

**Mechanism B — the app loads it at runtime.** Change `Helper.compute()` to read its own APK, seek to
the appended offset, and hand the bytes to `InMemoryDexClassLoader`:

```java
static String compute() {
    try {
        String apk = MainActivity.class.getProtectionDomain()
                        .getCodeSource().getLocation().getPath();
        // In practice: read from ApplicationInfo.sourceDir; simplified here.
        byte[] all = readAll(apk);
        int off = findAppendedDexOffset(all);      // scan for a second "dex\n"
        ByteBuffer buf = ByteBuffer.wrap(all, off, all.length - off);

        ClassLoader cl = new InMemoryDexClassLoader(buf, Helper.class.getClassLoader());
        Class<?> c = cl.loadClass("com.artlab.lyingdex.Payload");
        return (String) c.getMethod("flag").invoke(null);
    } catch (Throwable t) {
        return "nothing to see here";
    }
}
```

**Mechanism C — header/map disagreement.** Set `header.string_ids_off` to a decoy table while the
`map_list` points at the real one, so a header-trusting parser and a map-trusting parser produce
different string pools. This is the purest form of parser divergence.

Then package and install:

```bash
# host
# rebuild the APK around the modified classes.dex
zip -j app-lying.apk classes.dex        # plus the rest of the APK contents
zipalign -p -f -v 4 app-lying.apk aligned.apk
apksigner sign --ks ~/.android/debug.keystore --ks-pass pass:android \
  --out challenge.apk aligned.apk
adb install -r challenge.apk
```

---

## Your first attempt (which will fail)

```bash
# host
jadx -d out challenge.apk
grep -rn "ARTLAB" out/ || echo "not found"
strings challenge.apk | grep ARTLAB || echo "not found"
apktool d challenge.apk -o work/
grep -rn "ARTLAB" work/ || echo "not found"
```

**Q1.** Did any tool find the flag? Did any tool *warn* you that something was unusual?

**Q2.** `jadx` shows `Helper.compute()` returning a constant. Is that what the app actually does?
How would you tell, without running it?

---

## Investigation

Work through these before reading the solutions.

### Check the file's structural invariants

```bash
# host
unzip -o challenge.apk 'classes*.dex' -d dex/
python3 ../examples/dex_parser.py dex/classes.dex --verify-header
```

**Q3.** Does `header.file_size` match the actual file length? By how much do they differ?

**Q4.** Do the checksum and signature verify? What does that tell you — and what does it *not* tell
you?

### Check map coverage

```bash
python3 ../examples/dex_parser.py dex/classes.dex --map-coverage
```

**Q5.** Are there uncovered regions? Record the offset and size of each.

**Q6.** Dump the first 16 bytes of each uncovered region. What do you see?

```bash
xxd -s <offset> -l 16 dex/classes.dex
```

### Cross-check your parsers

```bash
# host
dexdump -f dex/classes.dex | grep -E 'string_ids|class_defs'
baksmali list classes dex/classes.dex | sort > /tmp/bak.txt
python3 ../examples/dex_parser.py dex/classes.dex --classes | grep '^  L' | sort > /tmp/mine.txt
diff /tmp/bak.txt /tmp/mine.txt
```

**Q7.** Do the tools agree on the class list? On the string count?

**Q8.** If they disagree — which is right? How would you determine that definitively?

---

## Solutions

Do not read until you have made a genuine attempt.

<details>
<summary>Solution A — carve the appended DEX out of the map gap</summary>

The map-coverage check reports an uncovered region whose first four bytes are `64 65 78 0a` —
another DEX file.

```bash
# host — find the second DEX magic
python3 - <<'PY'
d = open("dex/classes.dex","rb").read()
first = d.find(b"dex\n", 0)
second = d.find(b"dex\n", first + 4)
print(f"second DEX at offset 0x{second:x}")
open("payload.dex","wb").write(d[second:])
PY

jadx -d payload_out payload.dex
grep -rn "ARTLAB" payload_out/
```

The flag is assembled from fragments in `Payload.flag()`, so you may need to read the `StringBuilder`
sequence rather than finding one literal — which is itself worth noticing.

**Why the first attempt failed:** every tool you ran enumerates classes via the `map_list` and the
header's `class_defs` table. The appended DEX is described by neither, so as far as those tools are
concerned it does not exist. It is data sitting in a file, not code in a DEX.
</details>

<details>
<summary>Solution B — hook the ClassLoader and catch it in flight</summary>

If the app loads the payload at runtime, intercept the handover:

```bash
frida -U -f com.artlab.lyingdex -l ../../13-ART/scripts/dump-loaded-dex.js
```

That hooks `InMemoryDexClassLoader`, `DexClassLoader` and friends, and writes every payload to disk.
Then decompile what it captured.

**Why this works when static analysis did not:** you are no longer asking the file what it contains.
You are watching what the runtime is actually handed. Obfuscation of the *container* is irrelevant to
a hook on the *consumer*.

This is also the approach that keeps working when the payload is encrypted, because you catch it
after decryption. See [40-Obfuscation](../../40-Obfuscation/README.md).
</details>

<details>
<summary>Solution C — memory sweep</summary>

If the DEX is assembled in native code and never passes through a Java constructor, hooks miss it.
Scan process memory for the magic:

```javascript
// Frida REPL
Process.enumerateRanges('r--').forEach(function (r) {
    try {
        Memory.scanSync(r.base, r.size, '64 65 78 0a').forEach(function (m) {
            var fileSize = m.address.add(0x20).readU32();
            var headerSize = m.address.add(0x24).readU32();
            if (headerSize === 0x70 && fileSize > 0x70 && fileSize < 64*1024*1024) {
                console.log('[+] DEX at ' + m.address + ' size ' + fileSize);
                var f = new File('/data/local/tmp/swept_' + m.address + '.dex', 'wb');
                f.write(m.address.readByteArray(fileSize));
                f.close();
            }
        });
    } catch (e) {}
});
```

Validating `header_size == 0x70` filters out the false positives that a bare magic search produces —
which is exactly why knowing the header layout matters.
</details>

<details>
<summary>Solution D — resolve the header/map disagreement (Mechanism C only)</summary>

If you implemented Mechanism C, `dexdump` and your own parser will report different string counts or
different table offsets.

Determine which the **runtime** believes by asking the device rather than a tool:

```bash
adb shell cmd package dump com.artlab.lyingdex | head -60
```

Or, decisively, dump the DEX the runtime is actually executing:

```bash
# adb shell as root
APK=$(pm path com.artlab.lyingdex | head -1 | sed 's/package://')
oatdump --vdex-file=$(dirname $APK)/oat/arm64/base.vdex \
        --export-dex-to=/data/local/tmp/real
```

Whatever is in the VDEX is what runs. Compare it against both of your parsers' views.
</details>

---

## Debrief questions

Answer these in writing. They are the actual point of the lab.

1. Name the specific DEX structure that each of your tools relied on, and explain precisely why the
   appended payload was invisible to it.
2. The checksum and SHA-1 signature both verified on a file containing a hidden payload. Explain how
   that is possible, and what it says about using those fields as an integrity control.
3. Map coverage found the payload in seconds. Why is that check not built into mainstream tools?
   Should it be?
4. Rank the three solution approaches by (a) speed, (b) reliability against an *encrypted* payload,
   (c) reliability against a payload assembled in native code.
5. You are reviewing an APK for an app store. Write the three automated checks you would add, based
   on this lab, that would have caught this file.
6. A vendor tells you their scanner "fully analyses the DEX". What single question would you ask to
   find out whether it would have caught this?

---

## Success criteria

- [ ] You recovered the flag
- [ ] You solved it a **second** way by a different mechanism
- [ ] You can name the exact structure (`map_list` / `class_defs`) your first tool trusted, and why
      that made the payload invisible
- [ ] You explained how a file with a hidden payload still passes its checksum and signature
- [ ] You performed a map-coverage analysis and read the uncovered region's magic bytes
- [ ] You cross-checked at least two independent parsers and interpreted any disagreement
- [ ] You answered all six debrief questions in writing
- [ ] You can state the three automated checks that would catch this class of file

---

## Note for instructors

The pedagogical goal is **not** the flag. It is that participants experience their tools confidently
reporting something false, and learn that structural invariants — map coverage, `file_size` agreement,
`header_size == 0x70`, sorted map entries — are cheap, fast, and catch a whole class of evasion that
decompilation misses entirely.

If running this as a group exercise, hand out Mechanism A first (it is the most instructive), and
introduce B and C only after everyone has found the appended DEX. Participants who reach for Frida
immediately should be asked to also solve it statically, and vice versa — the comparison is where the
learning is.
