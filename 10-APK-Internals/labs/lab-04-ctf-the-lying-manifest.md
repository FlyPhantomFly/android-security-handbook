# Lab 04 — CTF: The Lying Manifest

**Difficulty:** Advanced
**Time:** 3–5 hours
**Chapter:** [10-APK-Internals](../README.md) §6.3, §6.5, §18
**Builds on:** [Lab 01](lab-01-dissecting-the-apk-byte-by-byte.md),
[Lab 02](lab-02-unpack-modify-rebuild-resign.md),
[Lab 03](lab-03-write-your-own-axml-parser.md)

---

## Read this first — how this differs from chapter 32's lying manifest

Chapter 32 has a CTF with almost this title:
[32-Manifest lab 06 — CTF: The Lying Manifest](../../32-Manifest/labs/lab-06-ctf-lying-manifest.md).
The two are deliberately different challenges, and you should do both.

| | 32 lab 06 | **this lab** |
|---|---|---|
| The question it asks | *Which components are reachable, and what is the effective security posture?* | *Which bytes did each reader read, and why did they differ?* |
| The mechanism | `rawValue` vs `typedValue`; an inflated `headerSize`; a decoy element after the root close | A field that changes the **addressing** of attribute records, so two readers parse different bytes as the same attribute list |
| The layer | The declaration — what the manifest says | The container and the chunk — what the bytes are |
| The winning move | The three-way read, then behavioural confirmation | A byte-level diff of the chunk structure against a clean build |
| What you leave with | A method for auditing declarations | A parser you trust, and a habit of accounting for every byte |

If you have done 32's version, none of what you learned there will solve this one: the attribute
records here are internally honest. `rawValue` agrees with `typedValue` everywhere. Nothing has an
unusual `headerSize`. Nothing follows the root close. Every check that caught 32's challenge comes up
clean on this one, which is the first thing this lab is here to teach you.

---

## The challenge

You are handed `challenge.apk`.

Your tools say it is unremarkable. `android:debuggable="false"`. One activity, not exported.
Cleartext traffic disabled. `apksigner` verifies it. `unzip -l` looks like every other APK. Nothing in
your usual first-sixty-seconds pass raises an eyebrow.

The device disagrees.

**Answer three questions, and be able to prove each one:**

1. **Is `android:debuggable` true or false, as `PackageManager` parses it?**
2. **How many components are actually exported?**
3. **What specific structural technique makes the analysis tools disagree with the platform?**

**The flag is the name of the AXML field being abused.** It is a single identifier, exactly as it is
spelled in `ResourceTypes.h`.

There is a self-check hidden in the APK so that you can confirm your answer without being told it.
Lab 01 taught you where to look for bytes that no ZIP entry accounts for.

---

## Rules

- **No installing it on a device you care about.** Use an emulator or a test device. It is a
  deliberately malformed package; treat it like one.
- **No decompiling the DEX to look for the answer.** It is not in there.
- **You must be able to name the field.** "The manifest was tampered with" is not a solution. The
  solution is a field name from `ResourceTypes.h` and a sentence explaining what a reader that
  mishandles it does differently.
- **You must produce the platform's reading, not just an alternative one.** Two tools agreeing is not
  evidence, as chapter 32's lab already showed you.
- **Do not distribute the APK you build.** The construction below is a real store-review evasion
  technique. It is documented here so that you can detect it.

---

## Building the challenge

Build it yourself. Constructing the deception is most of the education, and it means you can rebuild
variants to test your detection against.

### Part 1 — the app

Two activities. `MainActivity` is the launcher. `FlagActivity` is the one that should not be
reachable.

**`MainActivity.java`**

```java
package com.artlab.lyingbytes;

import android.app.Activity;
import android.os.Bundle;
import android.widget.TextView;

public class MainActivity extends Activity {
    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        TextView tv = new TextView(this);
        tv.setText("Nothing to see here.");
        setContentView(tv);
    }
}
```

**`FlagActivity.java`**

```java
package com.artlab.lyingbytes;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;

public class FlagActivity extends Activity {
    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        // Assembled at runtime so that it is not one contiguous constant in
        // the string table. Rule 2 says you may not go looking for it here.
        StringBuilder sb = new StringBuilder();
        sb.append("reachable_because_the_platform_strides_by_the_declared_size");
        TextView tv = new TextView(this);
        tv.setText(sb.toString());
        setContentView(tv);
        Log.i("LYINGBYTES", sb.toString());
    }
}
```

### Part 2 — the source manifest

This is what a reviewer reads, and every word of it is true of the *source*.

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.artlab.lyingbytes">

    <application
        android:label="LyingBytes"
        android:allowBackup="false"
        android:debuggable="false">

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

> **Warning** Each element you intend to target must carry **at least two** attributes, and the
> targeted one must not be the only one. The builder below moves the targeted attribute to the end of
> the list and needs a second attribute to hide behind. `android:label` and `android:allowBackup` are
> there for that reason; do not remove them.

Build it normally, then extract the compiled manifest:

```bash
# host
./gradlew assembleRelease
cp app/build/outputs/apk/release/app-release-unsigned.apk clean.apk
unzip -o clean.apk AndroidManifest.xml -d clean/
```

Keep `clean.apk`. The diff against it is one of the three solutions.

### Part 3 — the deception

The whole trick is one field.

Every `START_ELEMENT` chunk declares `attributeSize`: the size, in bytes, of **each** attribute
record. Attribute *i* lives at `nodeStart + headerSize + attributeStart + i * attributeSize`. The
record is 20 bytes and `aapt2` always writes 20 — which is exactly why so much code multiplies by a
hardcoded 20 and never reads the field.

Widen the stride to 40, keep every real record in the first 20 bytes of its slot, and park a **decoy
record in the padding of the first slot**. Now:

| Reader | Reads attributes at | Sees |
|---|---|---|
| Honours `attributeSize` (the platform, `aapt2`, your Lab 03 parser) | +0, +40, +80 | real₀, real₁, real₂ |
| Assumes 20 | +0, +20, +40 | real₀, **decoy**, real₁ |

Put the sensitive attribute last among the real records and its benign twin in the decoy slot, and
the wrong-stride reader renders a complete, well-formed, entirely plausible manifest in which the
sensitive attribute has the value you chose for it — and never sees the real one at all.

Nothing in that construction is malformed. Every chunk size is correct, every offset is in range,
every `Res_value` is eight bytes with `res0` zero, and `rawValue` agrees with `typedValue` wherever
both are present. It is a legal document that two conforming-looking readers read differently.

```python
#!/usr/bin/env python3
# host — save as widen-attributes.py
"""
widen-attributes.py — post-process a compiled AndroidManifest.xml so that a
reader honouring attributeSize and a reader assuming 20 disagree.

Usage:
    unzip -o clean.apk AndroidManifest.xml -d clean/
    python3 widen-attributes.py clean/AndroidManifest.xml challenge-manifest.xml

Structures: see ../README.md section 6.3 and, in AOSP,
frameworks/base/libs/androidfw/include/androidfw/ResourceTypes.h
(ResXMLTree_attrExt and ResXMLTree_attribute).

AUTHORISED TESTING AND EDUCATION ONLY. Do not distribute the output.
"""
import struct
import sys

RES_STRING_POOL = 0x0001
RES_XML_START_ELEMENT = 0x0102
ATTR = 20        # the real record size
WIDE = 40        # the declared stride we are moving to

# name -> (value the PLATFORM will read, value a 20-stride reader will read)
TARGETS = {
    "debuggable": (0xFFFFFFFF, 0x00000000),
    "exported":   (0xFFFFFFFF, 0x00000000),
}


def u16(d, o):
    return struct.unpack_from("<H", d, o)[0]


def u32(d, o):
    return struct.unpack_from("<I", d, o)[0]


def top_chunks(data):
    """Yield (offset, type, headerSize, size) for each top-level chunk."""
    off = u16(data, 2)                       # root headerSize
    limit = min(u32(data, 4), len(data))     # root size
    while off + 8 <= limit:
        t, h, s = struct.unpack_from("<HHI", data, off)
        if s == 0:
            return
        yield off, t, h, s
        off += s


def pool_strings(data):
    for off, t, h, s in top_chunks(data):
        if t != RES_STRING_POOL:
            continue
        count = u32(data, off + 8)
        utf8 = bool(u32(data, off + 16) & 0x100)
        start = u32(data, off + 20)
        out = []
        for i in range(count):
            p = off + start + u32(data, off + h + 4 * i)
            if utf8:
                cn = data[p]; p += 2 if cn & 0x80 else 1
                bn = data[p]; p += 2 if bn & 0x80 else 1
                out.append(data[p:p + (bn & 0x7F)].decode("utf-8", "replace"))
            else:
                n = u16(data, p); p += 2
                if n & 0x8000:
                    n = ((n & 0x7FFF) << 16) | u16(data, p); p += 2
                out.append(data[p:p + n * 2].decode("utf-16-le", "replace"))
        return out
    return []


def build(src):
    data = open(src, "rb").read()
    if u16(data, 0) != 0x0003:
        raise SystemExit("not a binary XML document")

    strings = pool_strings(data)
    index_of = {s: i for i, s in enumerate(strings)}
    out = bytearray()
    prev = 0
    hidden = []

    for off, t, h, s in top_chunks(data):
        out += data[prev:off]
        prev = off + s
        if t != RES_XML_START_ELEMENT:
            out += data[off:off + s]
            continue

        body = bytearray(data[off:off + s])
        a_start, a_size, a_count = struct.unpack_from("<HHH", body, h + 8)
        element = strings[u32(body, h + 4)] if u32(body, h + 4) < len(strings) \
            else "?"

        if a_size != ATTR or a_count == 0:
            out += bytes(body)
            continue

        records = [bytearray(body[h + a_start + i * ATTR:
                                  h + a_start + (i + 1) * ATTR])
                   for i in range(a_count)]

        target = None
        for i, rec in enumerate(records):
            name_index = u32(rec, 4)
            name = strings[name_index] if name_index < len(strings) else None
            if name in TARGETS:
                target = (i, name)
                break

        decoy = bytearray(b"\x00" * ATTR)
        if target is not None:
            i, name = target
            if a_count < 2:
                print(f"  SKIP <{element}>: {name} is the only attribute, so "
                      f"there is no slot to hide it behind. Add another "
                      f"attribute to this element in the source manifest.")
                out += bytes(body)
                continue

            rec = records.pop(i)
            platform_value, decoy_value = TARGETS[name]

            struct.pack_into("<i", rec, 8, -1)                 # rawValue absent
            struct.pack_into("<I", rec, 16, platform_value)    # typedValue
            records.append(rec)                                # move it LAST

            decoy = bytearray(rec)
            struct.pack_into("<I", decoy, 16, decoy_value)
            # Give the decoy a rawValue too, so that a tool preferring
            # rawValue is ALSO satisfied and nothing looks odd.
            if "false" in index_of:
                struct.pack_into("<i", decoy, 8, index_of["false"])

            hidden.append(f"{element}/{name}")

        widened = b""
        for j, rec in enumerate(records):
            widened += bytes(rec)
            widened += bytes(decoy) if j == 0 else b"\x00" * ATTR

        new_body = bytearray(body[:h + a_start]) + widened
        struct.pack_into("<H", new_body, h + 10, WIDE)         # attributeSize
        struct.pack_into("<I", new_body, 4, len(new_body))     # chunk size
        out += bytes(new_body)

    out += data[prev:]
    struct.pack_into("<I", out, 4, len(out))                   # root size
    return bytes(out), hidden


if __name__ == "__main__":
    src = sys.argv[1]
    dst = sys.argv[2] if len(sys.argv) > 2 else "challenge-manifest.xml"
    blob, hidden = build(src)
    open(dst, "wb").write(blob)
    print(f"wrote {dst}")
    print(f"hidden from a 20-stride reader: {hidden or 'nothing'}")
```

```bash
# host
python3 widen-attributes.py clean/AndroidManifest.xml challenge-manifest.xml
```

Expected:

```
wrote challenge-manifest.xml
hidden from a 20-stride reader: ['application/debuggable', 'activity/exported']
```

### Part 4 — prove the divergence before you package it

Do not package anything until you have watched both readings come out of the same bytes.

```python
#!/usr/bin/env python3
# host — save as both-ways.py, run: python3 both-ways.py challenge-manifest.xml
"""Read every element's attributes twice: once at the declared stride, once at
a hardcoded 20. Print both. Any line where they differ is the deception."""
import struct
import sys

sys.path.insert(0, ".")
from widen_attributes import pool_strings, top_chunks, u16, u32   # noqa: E402


def main(path):
    data = open(path, "rb").read()
    strings = pool_strings(data)

    for off, t, h, s in top_chunks(data):
        if t != 0x0102:
            continue
        base = off + h
        a_start, a_size, a_count = struct.unpack_from("<HHH", data, base + 8)
        element = strings[u32(data, base + 4)]

        for stride, label in ((20, "assumes 20"), (a_size, f"honours {a_size}")):
            parts = []
            for i in range(a_count):
                rec = base + a_start + i * stride
                name = strings[u32(data, rec + 4)]
                dtype = data[rec + 15]
                value = u32(data, rec + 16)
                if dtype == 0x12:
                    shown = "true" if value else "false"
                elif dtype == 0x03:
                    shown = strings[value]
                else:
                    shown = hex(value)
                parts.append(f"{name}={shown}")
            print(f"  {label:<12} <{element}> {', '.join(parts)}")
        print()


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "challenge-manifest.xml")
```

> **Note** `from widen_attributes import ...` needs the file named with an underscore for Python
> to import it. Either save the builder as `widen_attributes.py` and adjust the command lines, or
> copy the three helper functions into `both-ways.py` directly.

```bash
# host
python3 both-ways.py challenge-manifest.xml
```

Expected — this is the whole challenge in eight lines:

```
  assumes 20   <manifest> package=com.artlab.lyingbytes
  honours 40   <manifest> package=com.artlab.lyingbytes

  assumes 20   <application> label=LyingBytes, debuggable=false, allowBackup=false
  honours 40   <application> label=LyingBytes, allowBackup=false, debuggable=true

  assumes 20   <activity> name=.FlagActivity, exported=false
  honours 40   <activity> name=.FlagActivity, exported=true
```

Two readings. One file. Both well-formed.

### Part 5 — the container layer

Chapter 10 owns the bytes outside the manifest too. Add a self-check where Lab 01 taught you to look.

```python
#!/usr/bin/env python3
# host — save as add-check.py, run: python3 add-check.py aligned.apk final.apk
"""
Insert an ID-value pair carrying a verification token into the APK Signing
Block, so that a solver can confirm the flag without being told it.

The pair is added AFTER signing, which is exactly the point: the signing block
is not covered by any digest, so this does not invalidate anything. Confirm
that yourself with `apksigner verify -v` before and after.

See ../README.md section 6.5 and section 18.4.
"""
import hashlib
import struct
import sys

MAGIC = b"APK Sig Block 42"
CHECK_ID = 0x41525442          # "ARTB" - not a real, allocated block ID


def main(src, dst):
    data = bytearray(open(src, "rb").read())

    eocd = data.rfind(b"PK\x05\x06")
    cd_off = struct.unpack_from("<I", data, eocd + 16)[0]
    if bytes(data[cd_off - 16:cd_off]) != MAGIC:
        raise SystemExit("no APK Signing Block - sign the APK first")

    size_suffix = struct.unpack_from("<Q", data, cd_off - 24)[0]
    block_start = cd_off - size_suffix - 8

    # The token is the SHA-256 of the answer, so the file never contains it.
    answer = "attributesize"                        # lower-cased field name
    token = (b"ARTLAB-CHECK-v1 sha256(lowercased field name)="
             + hashlib.sha256(answer.encode()).hexdigest().encode())

    pair_body = struct.pack("<I", CHECK_ID) + token
    pair = struct.pack("<Q", len(pair_body)) + pair_body

    # Rebuild the block: prefix | pairs | NEW PAIR | suffix | magic
    pairs = bytes(data[block_start + 8:cd_off - 24])
    new_pairs = pairs + pair
    new_size = len(new_pairs) + 8 + 16
    new_block = (struct.pack("<Q", new_size) + new_pairs
                 + struct.pack("<Q", new_size) + MAGIC)

    grew = len(new_block) - (cd_off - block_start)
    out = bytearray(data[:block_start]) + new_block + data[cd_off:]

    # The central directory moved, so the EOCD's pointer to it must move too.
    new_eocd = out.rfind(b"PK\x05\x06")
    struct.pack_into("<I", out, new_eocd + 16, cd_off + grew)

    open(dst, "wb").write(bytes(out))
    print(f"wrote {dst}: block grew by {grew} bytes, "
          f"central directory now at 0x{cd_off + grew:x}")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else "final.apk")
```

> **Under the Hood** Read that script's EOCD fix-up carefully, because it is the same subtlety
> §5 of the chapter warns about from the other direction. Inserting bytes into the signing block
> shifts the central directory, so the EOCD's central-directory-offset field has to be corrected —
> and the v2 digest is *unaffected*, because the verifier substitutes the signing block's start
> offset for that field before digesting. That substitution is what lets the block grow without
> breaking the signature. It is also what makes the block a hiding place.

### Part 6 — package it

```bash
# host — replace the manifest, align, sign, then add the token
cp clean.apk work.apk
cp challenge-manifest.xml AndroidManifest.xml
zip -X -q work.apk AndroidManifest.xml

zipalign -p -f 4 work.apk aligned.apk
apksigner sign --ks ~/.android/debug.keystore --ks-pass pass:android \
  --key-pass pass:android --out signed.apk aligned.apk

apksigner verify -v signed.apk          # must say Verifies

python3 add-check.py signed.apk challenge.apk
apksigner verify -v challenge.apk       # STILL says Verifies — that is the lesson
```

> **Warning** If `zip` is not installed, replace the manifest with Python:
> `python3 -c "import zipfile,shutil; shutil.copy('clean.apk','work.apk'); zipfile.ZipFile('work.apk','a').write('challenge-manifest.xml','AndroidManifest.xml')"`.
> That leaves **two** entries named `AndroidManifest.xml`, which is a second, unintended puzzle —
> check with `python3 ../examples/parse_apk_zip.py work.apk | grep -i duplicate` and decide whether
> you want it.

Order matters and it is the order from Lab 02: replace, **align, sign**, and only then add the
signing-block pair. Adding it before signing means `apksigner` rewrites the block and your pair
disappears.

---

## Your first attempt — which will mislead you

Do this before reading further, and write the answers down. Being wrong on paper is the point.

```bash
# host
sha256sum challenge.apk
xxd -l 16 challenge.apk
unzip -l challenge.apk
apksigner verify -v --print-certs challenge.apk
```

```bash
# host — the tool reading
apktool d -f challenge.apk -o work/
grep -E 'debuggable|exported' work/AndroidManifest.xml
```

**Q1.** What does your decoder report for `android:debuggable`?

**Q2.** How many components does it report as exported?

**Q3.** Write the one-line manifest finding you would put in a report based on that alone.

**Q4.** Nothing in your Lab 01 container walk fires. Does that increase or decrease your confidence
in Q3? Justify the answer you actually gave, not the one you now think you should have given.

---

## Investigation

### Read it a second way

```bash
# host
aapt2 dump xmltree challenge.apk --file AndroidManifest.xml \
  | grep -iE 'debuggable|exported|allowBackup'
```

**Q5.** Does `aapt2` agree with your first decoder? If it does not, which one do you believe, and on
what basis other than preference?

`aapt2` is a host build of `libandroidfw` — the same code the device runs. That makes it the closest
thing to the platform you can run without a device, and it is a strong hint about which reading is
real. It is not proof: it is still a file being re-parsed on your machine.

### Read it the third way — the authority

```bash
# host
adb install -r challenge.apk
```

```bash
# adb shell
dumpsys package com.artlab.lyingbytes | grep -E 'flags=|privateFlags='
dumpsys package com.artlab.lyingbytes | grep -n 'exported=true'
```

**Q6.** What does `PackageManagerService` say about `DEBUGGABLE`? About `FlagActivity`?

### Confirm behaviourally

A parse is a claim. Behaviour is evidence.

```bash
# host — if debuggable really parsed as true, this returns a uid
adb shell run-as com.artlab.lyingbytes id
```

```bash
# adb shell — if FlagActivity really is exported, this launches it
am start -n com.artlab.lyingbytes/.FlagActivity
```

**Q7.** Which behavioural tests succeeded?

**Q8.** `am start` from `adb shell` runs with the shell UID, which holds privileges an ordinary app
does not. Repeat the launch from an unprivileged probe app. Does it still work? Why must you do this
step even when you already believe you know the answer?

### Find the mechanism

You now know *that* the readings differ. Find *where*.

```bash
# host — your own parser from Lab 03, which reports rather than guesses
python3 ../examples/parse_axml.py --extract challenge.apk --chunks
```

```bash
# host — the chunk-level diff against your clean build
aapt2 dump chunks clean.apk     > clean.chunks
aapt2 dump chunks challenge.apk > challenge.chunks
diff clean.chunks challenge.chunks | head -40
```

**Q9.** Compare the `START_ELEMENT` chunks between the two builds. One header field differs, and
every element's chunk `size` changed as a consequence. Name the field.

**Q10.** Compute, for the `<application>` element, the byte offset of attribute #1 under each
reading. Show the arithmetic. The two numbers you get are the entire vulnerability.

**Q11.** Why does `rawValue` versus `typedValue` — the mechanism from chapter 32's version of this
challenge — not explain anything you have seen here? Check it explicitly rather than assuming.

### Find the self-check

```bash
# host
python3 ../examples/parse_apk_zip.py challenge.apk
python3 ../examples/parse_signing_block.py challenge.apk
```

**Q12.** One ID-value pair has no name. What is in it, and why did adding it not break the signature?

**Q13.** Verify your answer to question 3 against the token, without anyone telling you whether you
are right:

```bash
# host — replace <your answer> with the field name, lower-cased
python3 -c "import hashlib,sys; print(hashlib.sha256(sys.argv[1].lower().encode()).hexdigest())" "<your answer>"
```

---

## Solutions

<details>
<summary>Solution A — the chunk diff against a clean build</summary>

The most direct route, and the one that generalises to constructions you have never seen.

Build the same source manifest cleanly, dump both with `aapt2 dump chunks`, and diff. The
`START_ELEMENT` chunks in the challenge declare `attributeSize` 40 where the clean build declares 20,
and each chunk is correspondingly larger.

`attributeSize` is a field of `ResXMLTree_attrExt` in
`frameworks/base/libs/androidfw/include/androidfw/ResourceTypes.h`. It exists so that the record
layout can grow in a future platform release without breaking old parsers — which is precisely why
the platform reads the declared value instead of assuming one.

Attribute *i* lives at `nodeStart + headerSize + attributeStart + i * attributeSize`. For
`<application>` with `headerSize` 16 and `attributeStart` 20, attribute #1 is at `nodeStart + 76`
under the declared stride and at `nodeStart + 56` under a hardcoded 20. Those are different bytes,
and both of them decode to a syntactically valid attribute record — because the file was built so
that they would.

**The flag is `attributeSize`.**

Why your first reading was wrong: your decoder multiplied the index by a literal 20. In every
manifest `aapt2` has ever emitted that is the right answer, so the bug is invisible until someone
writes a manifest specifically to expose it.
</details>

<details>
<summary>Solution B — write the reading you can defend</summary>

If you did Lab 03, you already have the tool. It strides by the declared value and it reports the
field:

```bash
# host
python3 ../examples/parse_axml.py --extract challenge.apk --anomalies-only
```

```
!! [ALERT] attribute-size
     <application> at 0x2ac declares attributeSize 40, not 20
     next step: Attribute records are addressed as attributeStart +
     index * attributeSize. A parser that honours the declared stride and one
     that assumes 20 read DIFFERENT BYTES as the attribute list from index 1
     onwards.
```

This is why Lab 03 exists. A parser that reports every place the file *could* be read two ways turns
a four-hour CTF into a one-line answer — and, more usefully, catches the next construction of this
class before anyone has given it a name.

The same check is in the triage script, if you would rather run one command over forty APKs:

```bash
# host
python3 ../scripts/apk-container-triage.py challenge.apk
```
</details>

<details>
<summary>Solution C — ignore the file entirely and measure the platform</summary>

Every route above reads the APK. This one refuses to.

Install it and ask the platform what it did, then confirm by behaviour:

```bash
# adb shell
dumpsys package com.artlab.lyingbytes | grep -E 'flags=|privateFlags='
```

```bash
# host
adb shell run-as com.artlab.lyingbytes id
```

`run-as` succeeding proves `FLAG_DEBUGGABLE` was set, no matter what any decoder rendered — `run-as`
is enforced by the platform against `ApplicationInfo`, not against a file on your laptop.

For the component question, enumerate by behaviour from an unprivileged probe app:

```java
// probe app — try to launch every activity class you found in the DEX
for (String cls : candidateClasses) {
    try {
        Intent i = new Intent();
        i.setComponent(new ComponentName(TARGET, cls));
        i.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        startActivity(i);
        Log.i(TAG, "REACHABLE: " + cls);
    } catch (SecurityException e) {
        Log.i(TAG, "denied:    " + cls);
    } catch (Exception e) { /* not an activity, or absent */ }
}
```

Slower, noisier, needs a device — and it cannot be lied to, because it measures what the platform
permits rather than what a file claims. This is the fallback whenever you suspect manifest trickery
of any kind, including kinds nobody has documented yet.

What it will *not* give you is the mechanism. It answers questions 1 and 2 and leaves question 3
untouched, which is why it is a solution and not *the* solution.
</details>

<details>
<summary>Solution D — the container, for completeness</summary>

The unnamed ID-value pair in the signing block holds:

```
ARTLAB-CHECK-v1 sha256(lowercased field name)=ea1780a61f18f07a908ff5cbd0aa58fa24062532ab428903998dcd5d05c9dc0b
```

```bash
# host
python3 -c "import hashlib; print(hashlib.sha256(b'attributesize').hexdigest())"
```

It matches, which confirms the answer without the file ever containing it in plaintext.

Adding that pair did not break the signature because the v2 and v3 digests cover sections 1, 3 and 4
of the file — the entry data, the central directory and the EOCD — and deliberately exclude section
2, the signing block. Unknown IDs are ignored by design so that old verifiers survive new schemes.
The two facts together make an unknown ID-value pair signature-safe storage for arbitrary bytes. See
README §18.4.

Run `apksigner verify -v` on `signed.apk` and on `challenge.apk` and confirm that both say `Verifies`,
even though the second is 122 bytes larger — a 110-byte token, plus four bytes of ID and an eight-byte
length prefix. That is not a bug in `apksigner`; it is the format working as specified.
</details>

---

## Debrief

Answer in writing. These are the questions an interviewer asks.

1. Name the AXML field, the struct it belongs to, and the AOSP header it is declared in. State what
   the field is *for* — the legitimate reason it exists.
2. Your first decoder was wrong. Was it *buggy*? Argue both sides. It produced correct output for
   every manifest ever emitted by `aapt2`.
3. Chapter 32's version of this challenge is defeated by comparing `rawValue` with `typedValue`. That
   check comes up clean here. What does that tell you about check-list-driven analysis?
4. You have now seen four readings: your decoder, `aapt2`, `dumpsys`, and behaviour. Rank them by how
   much they can be lied to, and say why.
5. Write the three automated checks you would add to a store-review pipeline to catch this class. At
   least one must not be specific to `attributeSize`.
6. A vendor's scanner reports this APK as clean. What single question would you ask to find out
   whether it could ever have caught it?
7. The signing-block pair carried a 110-byte token. What is the practical upper bound, and what would
   you do with it if you were the attacker? What does that imply for your triage checklist?
8. You installed a deliberately malformed package on a device to answer question 1. What would you do
   if installing it were not acceptable — a client's production fleet, a sample from an active
   incident? Give a route that does not involve running it.

---

## Success criteria

- [ ] You answered all three challenge questions with evidence, not inference
- [ ] You recovered the flag: the exact field name as spelled in `ResourceTypes.h`
- [ ] You verified it against the token in the signing block
- [ ] You solved it a **second** way, by a different mechanism
- [ ] You showed the offset arithmetic for both readings of one specific attribute
- [ ] You confirmed the platform's reading **behaviourally**, not only from another tool's output
- [ ] You launched the hidden activity from an unprivileged probe app, not only from `adb shell`
- [ ] You explicitly checked, and ruled out, the chapter-32 mechanisms
- [ ] You found the signing-block pair and can explain why it does not break the signature
- [ ] You answered all eight debrief questions in writing

---

## Note for instructors

The flag is not the goal. Two things are.

The first is that participants watch a *correct-looking* parser be confidently wrong, on a file with
nothing malformed in it. Chapter 32's challenge teaches that tool consensus is not truth. This one
teaches something sharper: that a check-list of known tricks is a lower bound, not a method. Every
check that catches 32's challenge passes this one.

The second is `attributeSize` as a specimen of a general shape — a field whose *purpose* is
forward-compatibility, whose value is constant in practice, and which therefore gets hardcoded. That
shape recurs across every binary format in this repository: `headerSize` in AXML, `header_size` in
DEX, `attributeSize` here. Participants who leave able to name that pattern will find the next one
themselves.

Run it after chapter 32's lab 06, not before. The contrast is the lesson, and it only lands in that
order.

Participants who reach for a device immediately should be made to solve it statically as well, and
vice versa. Two participants who solved it by different routes should present to each other.

---

## Where to go next

You can now read a container, read a manifest, and tell the difference between what a tool says and
what a platform does. That is the whole of chapter 10.

For the contents of the container: [12-DEX-Internals](../../12-DEX-Internals/README.md) for
`classes*.dex`, and [32-Manifest](../../32-Manifest/README.md) for what the attributes you have been
decoding actually mean once the platform acts on them.
