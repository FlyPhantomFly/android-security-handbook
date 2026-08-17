# Lab 06 — CTF: The Lying Manifest

**Difficulty:** Advanced
**Time:** 2–4 hours
**Prerequisites:** Labs [01](lab-01-three-way-read.md)–[05](lab-05-merge-and-inject.md),
[Chapter 32](../README.md), [10-APK-Internals §AXML](../../10-APK-Internals/README.md)

---

## The challenge

You are handed an APK. Your tools tell you it is well-built: `android:debuggable="false"`, no exported
components without permissions, cleartext traffic disabled, nothing alarming.

The device disagrees. `run-as` works. An activity you were told is not exported launches from another
app. Something is wrong with what you were shown.

**Determine what the platform actually parsed, recover the flag, and explain the mechanism that made
your tools lie.**

There are at least three ways in. Find one, then find a second.

---

## Rules

- No decompiling the DEX to find the flag as a string constant. That works and teaches nothing; the
  flag is not a plaintext constant anyway.
- No brute force.
- You must be able to explain, in terms of specific AXML structures, **why** your first reading was
  wrong.

---

## Building the challenge

Build it yourself — implementing the deception is most of the education.

### Part 1 — the app

**`MainActivity.java`**

```java
package com.artlab.lyingmanifest;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;

public class MainActivity extends Activity {
    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        TextView tv = new TextView(this);
        tv.setText("Nothing to see here.");
        setContentView(tv);
        Log.i("LYINGMANIFEST", "main started");
    }
}
```

**`FlagActivity.java`** — the target. It is declared `exported="false"` in the source manifest.

```java
package com.artlab.lyingmanifest;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;

public class FlagActivity extends Activity {

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);

        // Assembled at runtime so it is not one contiguous string constant.
        StringBuilder sb = new StringBuilder();
        sb.append("ARTLAB");
        sb.append((char) 0x7B);
        sb.append("the_platform_is_the_authority");
        sb.append((char) 0x7D);
        String flag = sb.toString();

        TextView tv = new TextView(this);
        tv.setText(flag);
        setContentView(tv);
        Log.i("LYINGMANIFEST", flag);
    }
}
```

### Part 2 — the source manifest

This is what a reviewer sees, and it is honest:

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application
        android:debuggable="false"
        android:allowBackup="false"
        android:label="LyingManifest">

        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>

        <activity android:name=".FlagActivity" android:exported="false" />
    </application>
</manifest>
```

### Part 3 — the deception

Build normally first, then post-process the compiled AXML. Pick at least one mechanism; ideally
implement all three so you can compare.

**Mechanism A — `rawValue` / `typedValue` divergence.** An AXML attribute carries *two*
representations: a `rawValue` string-pool reference and a typed `Res_value`. The platform reads
`typedValue`; several tools display `rawValue`. Set them to disagree for `android:debuggable` and
`android:exported`.

**Mechanism B — oversized `headerSize`.** A chunk's `headerSize` tells a parser where the payload
begins. A lenient parser that trusts an inflated value skips fields; a strict one does not.

**Mechanism C — a decoy element after the root close.** Append a second `START_ELEMENT` chunk after
the document's logical end. Some parsers stop at the root close; others keep walking.

```python
#!/usr/bin/env python3
"""
craft-lying-manifest.py — post-process a compiled AndroidManifest.xml so that
tools and PackageManager disagree.

This edits AXML at the chunk level. See ../../10-APK-Internals/README.md
section 6.3 for the structures involved.

Usage:
    unzip -o app-release.apk AndroidManifest.xml -d extracted/
    python3 craft-lying-manifest.py extracted/AndroidManifest.xml out.xml
    # then repack, zipalign and re-sign

AUTHORISED TESTING AND EDUCATION ONLY.
"""
import struct, sys

RES_XML_START_ELEMENT = 0x0102

def patch_typed_bool(data, attr_name_idx, new_value):
    """
    Walk START_ELEMENT chunks and, for the attribute whose name string index
    matches, set typedValue.data while leaving rawValue untouched.

    Attribute record layout (README 6.3 of chapter 10):
        uint ns, uint name, uint rawValue,
        Res_value{ ushort size, ubyte res0, ubyte dataType, uint data }
    """
    out = bytearray(data)
    off = 8                                  # skip the RES_XML_TYPE header
    while off + 8 <= len(out):
        ctype, hsize, csize = struct.unpack_from('<HHI', out, off)
        if csize == 0 or off + csize > len(out):
            break
        if ctype == RES_XML_START_ELEMENT:
            attr_start, attr_size, attr_count = struct.unpack_from('<HHH', out, off + 0x1C)
            base = off + 0x10 + attr_start
            for i in range(attr_count):
                a = base + i * attr_size
                name_idx = struct.unpack_from('<I', out, a + 4)[0]
                if name_idx == attr_name_idx:
                    # typedValue.data sits at +0x10 within the attribute record
                    struct.pack_into('<I', out, a + 0x10, new_value)
                    print(f"  patched typedValue at chunk 0x{off:x} attr {i}")
        off += csize
    return bytes(out)

if __name__ == '__main__':
    src, dst = sys.argv[1], sys.argv[2]
    blob = open(src, 'rb').read()
    # Resolve the string-pool index of "debuggable" / "exported" first —
    # parse the string pool, or read it from `aapt2 dump chunks`.
    DEBUGGABLE_IDX = int(sys.argv[3]) if len(sys.argv) > 3 else None
    if DEBUGGABLE_IDX is None:
        print("Pass the string-pool index of the attribute to patch.")
        print("Find it with: aapt2 dump chunks app.apk | less")
        sys.exit(1)
    open(dst, 'wb').write(patch_typed_bool(blob, DEBUGGABLE_IDX, 0xFFFFFFFF))
    print(f"wrote {dst}")
```

Then repack. Order matters:

```bash
# host
cd extracted && zip -X ../patched.apk AndroidManifest.xml && cd ..
# (merge into a copy of the original APK, replacing the manifest entry)
zipalign -p -f -v 4 patched.apk aligned.apk
apksigner sign --ks ~/.android/debug.keystore --ks-pass pass:android \
  --out challenge.apk aligned.apk
adb install -r challenge.apk
```

---

## Your first attempt (which will mislead you)

```bash
# host
apktool d -f challenge.apk -o work/
grep -E 'debuggable|exported' work/AndroidManifest.xml
```

**Q1.** What does apktool report for `android:debuggable` and for `FlagActivity`'s `exported`?

**Q2.** Based on that alone, write the one-line manifest finding you would report.

---

## Investigation

### Read it the second way

```bash
# host
aapt2 dump xmltree challenge.apk --file AndroidManifest.xml | grep -A3 -E 'debuggable|exported|FlagActivity'
```

**Q3.** Does `aapt2` agree with apktool? If they agree, does that make them right?

### Read it the third way — the authority

```bash
# host
adb install -r challenge.apk
adb shell dumpsys package com.artlab.lyingmanifest | grep -E 'flags=|privateFlags='
adb shell dumpsys package com.artlab.lyingmanifest | grep -n 'exported=true'
```

**Q4.** What does the platform say about `DEBUGGABLE`? About `FlagActivity`?

**Q5.** You now have a disagreement. Which reading is correct, and how do you *prove* it rather than
assert it?

### Prove it behaviourally

```bash
# host — if the platform really parsed debuggable=true, this works
adb shell run-as com.artlab.lyingmanifest id
```

```bash
# adb shell — if FlagActivity is really exported, this launches
am start -n com.artlab.lyingmanifest/.FlagActivity
```

**Q6.** Which behavioural test succeeded? What does that settle?

**Q7.** Now do it properly — launch `FlagActivity` from an **unprivileged probe app** rather than from
`adb shell`. Does it still work? Why does this step matter even here, where you already know the
answer?

### Find the mechanism

```bash
# host — dump the AXML chunk structure
aapt2 dump chunks challenge.apk | head -80
```

```bash
# host — compare against a clean build of the same app
aapt2 dump chunks clean.apk > clean.chunks
aapt2 dump chunks challenge.apk > lying.chunks
diff clean.chunks lying.chunks | head -40
```

**Q8.** What structural difference do you see? Name the specific field.

**Q9.** Explain, in terms of the AXML attribute record layout, why apktool showed one value and
`PackageManager` used another.

---

## Solutions

<details>
<summary>Solution A — the three-way read</summary>

The method the whole chapter is built around. Read the manifest with apktool, with `aapt2`, and with
`dumpsys package`. When they disagree, the platform wins.

Then confirm behaviourally: `run-as` succeeding proves `debuggable` was parsed as true regardless of
what any tool displayed, and launching `FlagActivity` from a probe app proves it was parsed as
exported.

**Why the first attempt failed:** apktool renders the attribute's `rawValue` — the human-readable
string — while `PackageManager` reads the typed `Res_value`. Crafting them to disagree makes every
tool that prefers `rawValue` display something the platform never used.
</details>

<details>
<summary>Solution B — the runtime read</summary>

Ask the framework directly what it parsed, from inside the process:

```bash
frida -U -f com.artlab.lyingmanifest -l ../scripts/frida-manifest-runtime.js
```

That script calls `getPackageInfo` with the component flags and prints the `ActivityInfo`,
`ServiceInfo` and `ApplicationInfo` the platform holds — including the real `FLAG_DEBUGGABLE` and the
real `exported` value per component.

This is the most direct answer available: not a file being re-parsed, but the platform's own
in-memory representation.
</details>

<details>
<summary>Solution C — behavioural enumeration</summary>

Ignore the manifest entirely and enumerate by behaviour. For every activity class in the DEX, try to
launch it from a probe app and record which succeed:

```java
for (String cls : candidateClasses) {
    try {
        Intent i = new Intent();
        i.setComponent(new ComponentName(TARGET, cls));
        i.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        startActivity(i);
        Log.i(TAG, "REACHABLE: " + cls);
    } catch (SecurityException e) {
        Log.i(TAG, "denied:    " + cls);
    } catch (Exception e) { /* not an activity, or missing */ }
}
```

Slower and noisier, but it cannot be lied to — it measures what the platform permits rather than what
a file claims. Worth knowing as a fallback when you suspect any form of manifest trickery.
</details>

---

## Debrief

Answer in writing.

1. Name the specific AXML structure each of your tools relied on, and explain why it produced the
   wrong answer.
2. `apktool` and `aapt2` agreed with each other and were both wrong. What does that tell you about
   using "two tools agree" as a confidence signal?
3. You had already installed the app when you ran `dumpsys`. What would you do if installing the
   sample were not acceptable — how would you get the platform's reading without running it?
4. Rank the three solutions by speed, by reliability, and by how much they depend on having a device.
5. Write the three automated checks you would add to a store-review pipeline to catch this class of
   APK.
6. A vendor's scanner reports this APK as clean. What single question would you ask to find out
   whether it could ever have caught it?

---

## Success criteria

- [ ] You recovered the flag
- [ ] You solved it a **second** way by a different mechanism
- [ ] You can name the AXML field responsible and explain the divergence precisely
- [ ] You confirmed the platform's reading **behaviourally**, not just by reading another tool's output
- [ ] You launched `FlagActivity` from an unprivileged probe app, not only from `adb shell`
- [ ] You diffed the chunk structure against a clean build and identified the modification
- [ ] You answered all six debrief questions in writing
- [ ] You can state, without hesitating, which of the four manifest views belongs in a report

---

## Note for instructors

The goal is **not** the flag. It is that participants watch two independent tools confidently agree on
something false, and learn that tool consensus is not truth — only the platform's own parse is.

Run Mechanism A first; it is the most instructive and the easiest to build reliably. Introduce B and C
only once everyone has found the divergence.

Participants who reach for Frida immediately should be made to solve it statically as well, and vice
versa. The comparison between the two routes is where the durable lesson lives.
