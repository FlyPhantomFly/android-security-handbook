# Lab 03 — Write Your Own AXML Parser

**Difficulty:** Advanced
**Time:** 3–5 hours
**Chapter:** [10-APK-Internals](../README.md) §6.3
**Builds on:** [Lab 01 — Dissecting the APK, Byte by Byte](lab-01-dissecting-the-apk-byte-by-byte.md),
[Lab 02 — Unpack, modify, rebuild, re-sign](lab-02-unpack-modify-rebuild-resign.md)

---

## Objective

Implement a parser for Android binary XML from the specification, in a language you control, and
then use it to read a manifest that at least one of your normal tools cannot.

You are going to write roughly two hundred lines of Python. That is not the point. The point is the
thing you will own at the end of it: a reading of `AndroidManifest.xml` that you can defend byte by
byte, so that when `apktool`, `jadx`, `aapt2` and the device disagree about an app, you are not
choosing between other people's opinions.

**You will finish able to answer:**

1. What is a chunk, and why does every AXML structure begin with the same six bytes?
2. Why must you navigate with `headerSize` and `size` rather than with the offsets in a table?
3. How are strings stored, and why does the UTF-8 encoding have *two* length fields?
4. What is the difference between an attribute's `rawValue` and its `typedValue`, and which one does
   the platform read?
5. What does `attributeSize` do, and what happens to a parser that assumes it is always 20?
6. When your parser and a mainstream tool disagree, how do you find out which is right?

---

## Prerequisites

| Requirement | Why | Check |
|---|---|---|
| Python 3.8 or later | The parser you are about to write | `python3 --version` |
| Labs 01 and 02 completed | You need the container before the contents | — |
| `xxd` or `hexdump` | Reading the bytes when your code is wrong | `xxd --version` |
| `aapt2` (Android SDK build-tools) | The comparison reading | `aapt2 version` |
| `apktool` (optional but wanted) | A second, independent comparison | `apktool --version` |
| An APK to read | Any one; your own build is ideal | — |

> **📖 Definition — binary XML (AXML).** The build tool `aapt2` compiles every XML file in an
> Android project into a compact binary form. Text XML is parsed by scanning for `<`, `>` and `"`;
> AXML is parsed by arithmetic on length fields. The device does this on every app launch and every
> `PackageManager` query, which is why it is worth the format's complexity.

> **📖 Definition — chunk.** A length-prefixed block of bytes that knows its own type, the size of
> its own header, and its total size. Chunks nest. A parser walks the tree by adding sizes, never by
> searching for a delimiter — there are no delimiters.

> **📖 Definition — string pool.** A single table holding every distinct string in the document
> exactly once. Element names, attribute names, namespace URIs and string values are all stored as
> 32-bit *indices* into this table. Nothing in an AXML document is text where you would expect text.

### The specification

The specification for everything in this lab is a single AOSP header:

```
frameworks/base/libs/androidfw/include/androidfw/ResourceTypes.h
```

Read it on [cs.android.com](https://cs.android.com/). Every constant used below is declared there as
a C++ `struct` or `enum` — `ResChunk_header`, `ResStringPool_header`, `ResXMLTree_node`,
`ResXMLTree_attrExt`, `ResXMLTree_attribute`, `Res_value`. The implementation that consumes those
structures is in `frameworks/base/libs/androidfw/ResourceTypes.cpp`, and the Java wrapper the
framework calls is `frameworks/base/core/java/android/content/res/XmlBlock.java`.

Keep the header open in a second window for the whole lab. When your parser produces nonsense, the
answer is in it.

> **⚠️ Warning** Do not cite line numbers from that header, in your notes or in a report. The paths
> are stable across releases; the line numbers are not, and a stale line number in a report is worse
> than no reference at all.

---

## Why write your own

Chapter 20's first lab establishes the repository's habit here: **write yours first, then compare.**
A tool you have only used is a tool you cannot argue with.

There is a reference implementation in this chapter at
[`../examples/parse_axml.py`](../examples/parse_axml.py). **Do not read it yet.** It is the
comparison at the end of Part 8, and reading it now converts a lab into a transcription exercise.

The practical payoff is specific. Four independent implementations read the manifest of an app you
assess:

| Reader | Implementation |
|---|---|
| `apktool` | Its own AXML decoder, written in Java |
| `aapt2 dump xmltree` | AOSP's `ResXMLTree`, compiled for your host |
| `jadx` | Its own decoder again, written in Java |
| The device | `ResXMLParser` in `libandroidfw`, driven by the package parsing code |

When they disagree, the disagreement is the finding — but you can only *see* a disagreement if you
have a reading you understand well enough to trust. That is what you are building.

---

## Setup

### Step 0.1 — Working directory

```bash
# host
mkdir -p ~/apk-lab-03 && cd ~/apk-lab-03
```

### Step 0.2 — Get a manifest to practise on

Any APK will do. Pull one as in Lab 01, or use one you have built.

```bash
# host
cp /path/to/your/app.apk target.apk
unzip -o target.apk AndroidManifest.xml
ls -l AndroidManifest.xml
```

```bash
# host — confirm it really is AXML and not text
xxd -l 16 AndroidManifest.xml
```

Expected:

```
00000000: 0300 0800 f47b 0000 0100 1c00 3427 0000  .....{......4'..
```

Decode those first eight bytes now, by hand, before writing any code:

| Offset | Bytes | Value | Field |
|---|---|---|---|
| `0x00` | `03 00` | `0x0003` | `type` — `RES_XML_TYPE`, the root chunk |
| `0x02` | `08 00` | 8 | `headerSize` — this chunk's header is 8 bytes |
| `0x04` | `f4 7b 00 00` | 31732 | `size` — the whole document, which should equal the file size |

```bash
# host — the size field must equal the file size
stat -c%s AndroidManifest.xml     # Linux
stat -f%z AndroidManifest.xml     # macOS
```

If those two numbers differ, stop and write down by how much. You have found something before
writing a line of code, and Part 6 will tell you what it means.

### Step 0.3 — Record the answer you are about to reproduce

```bash
# host
aapt2 dump xmltree target.apk --file AndroidManifest.xml > aapt2-reading.txt
head -20 aapt2-reading.txt
```

Keep that file. Your parser's output must agree with it, and when it does not, one of you is wrong
and you will have to work out which.

---

## Part 1 — The chunk walk

Everything in AXML is a chunk, and every chunk starts with the same six bytes.

```
struct ResChunk_header {
    uint16_t type;         // which chunk this is
    uint16_t headerSize;   // bytes of header before the payload
    uint32_t size;         // total bytes of this chunk, INCLUDING the header
};
```

Three rules follow, and every one of them is a security property:

1. **The payload begins at `chunkStart + headerSize`.** Not at `chunkStart + 8`. A chunk may declare
   a larger header than you expect, and the correct behaviour is to skip it.
2. **The next chunk begins at `chunkStart + size`.** Not after the payload you understood.
3. **A chunk you do not recognise is skipped by `size`.** That is what makes the format extensible —
   and what makes an unknown chunk a place to hide bytes.

### Step 1.1 — The skeleton

```python
#!/usr/bin/env python3
# host — save as myaxml.py
"""My AXML parser. Chapter 10, lab 03."""
import struct
import sys

RES_STRING_POOL_TYPE          = 0x0001
RES_XML_TYPE                  = 0x0003
RES_XML_START_NAMESPACE_TYPE  = 0x0100
RES_XML_END_NAMESPACE_TYPE    = 0x0101
RES_XML_START_ELEMENT_TYPE    = 0x0102
RES_XML_END_ELEMENT_TYPE      = 0x0103
RES_XML_CDATA_TYPE            = 0x0104
RES_XML_RESOURCE_MAP_TYPE     = 0x0180

NAMES = {
    RES_STRING_POOL_TYPE:         "RES_STRING_POOL_TYPE",
    RES_XML_TYPE:                 "RES_XML_TYPE",
    RES_XML_START_NAMESPACE_TYPE: "RES_XML_START_NAMESPACE_TYPE",
    RES_XML_END_NAMESPACE_TYPE:   "RES_XML_END_NAMESPACE_TYPE",
    RES_XML_START_ELEMENT_TYPE:   "RES_XML_START_ELEMENT_TYPE",
    RES_XML_END_ELEMENT_TYPE:     "RES_XML_END_ELEMENT_TYPE",
    RES_XML_CDATA_TYPE:           "RES_XML_CDATA_TYPE",
    RES_XML_RESOURCE_MAP_TYPE:    "RES_XML_RESOURCE_MAP_TYPE",
}


def u16(d, o):
    return struct.unpack_from("<H", d, o)[0]


def u32(d, o):
    return struct.unpack_from("<I", d, o)[0]


def i32(d, o):
    return struct.unpack_from("<i", d, o)[0]      # -1 means "absent"


def main(path):
    data = open(path, "rb").read()

    ctype, header_size, size = struct.unpack_from("<HHI", data, 0)
    print(f"root: type=0x{ctype:04x} headerSize={header_size} size={size} "
          f"file={len(data)}")
    if ctype != RES_XML_TYPE:
        raise SystemExit(f"not binary XML: root type is 0x{ctype:04x}")

    # RULE 1: children begin at chunkStart + headerSize, not + 8.
    off = header_size
    # RULE: bound the walk by the ROOT CHUNK'S declared size, not by the file.
    limit = min(size, len(data))

    while off + 8 <= limit:
        ctype, header_size, csize = struct.unpack_from("<HHI", data, off)
        name = NAMES.get(ctype, f"UNKNOWN_0x{ctype:04x}")
        print(f"  0x{off:08x}  {name:<32} headerSize={header_size:<4} "
              f"size={csize}")

        if csize == 0:
            raise SystemExit(f"chunk at 0x{off:x} declares size 0 — a parser "
                             f"that does not check this loops forever")
        if off + csize > limit:
            raise SystemExit(f"chunk at 0x{off:x} runs past its parent")

        # RULE 2: the next chunk starts at chunkStart + size.
        off += csize

    if off != limit:
        print(f"!! {limit - off} bytes left over after the walk")
    if limit < len(data):
        print(f"!! {len(data) - limit} bytes follow the root chunk")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "AndroidManifest.xml")
```

```bash
# host
python3 myaxml.py AndroidManifest.xml
```

Expected output shape:

```
root: type=0x0003 headerSize=8 size=31732 file=31732
  0x00000008  RES_STRING_POOL_TYPE             headerSize=28   size=12924
  0x0000329c  RES_XML_RESOURCE_MAP_TYPE        headerSize=8    size=456
  0x00003464  RES_XML_START_NAMESPACE_TYPE     headerSize=16   size=24
  0x0000347c  RES_XML_START_ELEMENT_TYPE       headerSize=16   size=96
  ...
  0x00007bd4  RES_XML_END_NAMESPACE_TYPE       headerSize=16   size=24
```

> **🧠 Mental Model** The chunk walk is a linked list where the link is arithmetic rather than a
> pointer. Every `size` field is a jump instruction. Forge one and you decide where the reader lands
> next — and if two readers compute the jump differently, they are reading different documents from
> the same bytes.

### Step 1.2 — Checkpoint

Before continuing, confirm three things:

- The root `size` equals the file size. Note the difference if it does not.
- You see exactly one `RES_STRING_POOL_TYPE`.
- The number of `START_ELEMENT` chunks equals the number of `END_ELEMENT` chunks.

```bash
# host — count them from your own output
python3 myaxml.py AndroidManifest.xml | grep -c START_ELEMENT
python3 myaxml.py AndroidManifest.xml | grep -c END_ELEMENT
```

---

## Part 2 — The string pool

This is the hard part, it is where implementations diverge most, and it is worth doing slowly.

```
struct ResStringPool_header {
    ResChunk_header header;      // 8 bytes
    uint32_t stringCount;
    uint32_t styleCount;
    uint32_t flags;              // SORTED_FLAG = 0x1, UTF8_FLAG = 0x100
    uint32_t stringsStart;       // offset from the CHUNK start to the string data
    uint32_t stylesStart;
};                               // 28 bytes total
```

Immediately after the header come `stringCount` 32-bit offsets, then `styleCount` more, then the
string data itself at `chunkStart + stringsStart`.

> **⚠️ Warning** The offset array starts at `chunkStart + headerSize`. Almost every tutorial
> hardcodes 28. Hardcode it and you have written a parser that reads the wrong bytes the moment
> someone declares 32 — which is the first thing an author of a hostile manifest tries.

### Step 2.1 — UTF-16 strings

With `UTF8_FLAG` clear, each string is:

| Part | Encoding |
|---|---|
| Length | A 16-bit count of UTF-16 *code units*. If the high bit is set, the real length is 31 bits spread across **two** 16-bit values: `((first & 0x7FFF) << 16) \| second` |
| Data | That many UTF-16 little-endian code units |
| Terminator | `0x0000` |

```python
# host — add to myaxml.py
def read_utf16(data, pos):
    n = u16(data, pos)
    pos += 2
    if n & 0x8000:                      # the two-value long form
        n = ((n & 0x7FFF) << 16) | u16(data, pos)
        pos += 2
    raw = data[pos:pos + n * 2]
    return raw.decode("utf-16-le", "replace"), n
```

### Step 2.2 — UTF-8 strings

With `UTF8_FLAG` set, each string carries **two** lengths:

| Part | Encoding |
|---|---|
| Character count | One byte, or two when the high bit of the first is set |
| **Byte count** | One byte, or two when the high bit of the first is set |
| Data | That many bytes of UTF-8 |
| Terminator | `0x00` |

```python
# host — add to myaxml.py
def read_u8len(data, pos):
    n = data[pos]
    pos += 1
    if n & 0x80:
        n = ((n & 0x7F) << 8) | data[pos]
        pos += 1
    return n, pos


def read_utf8(data, pos):
    char_len, pos = read_u8len(data, pos)
    byte_len, pos = read_u8len(data, pos)
    raw = data[pos:pos + byte_len]
    text = raw.decode("utf-8", "replace")
    # THE CHECK. Nothing in the format forces these two to agree.
    if len(text) != char_len:
        print(f"!! string declares {char_len} chars and {byte_len} bytes, "
              f"but those bytes decode to {len(text)} chars: {text!r}")
    return text, char_len
```

> **🔬 Under the Hood** Why two lengths? Because a reader that only wants to *skip* a string needs
> the byte count, and a reader that wants to allocate a UTF-16 buffer needs the character count.
> Storing both saves a decode pass. The consequence is that the two fields are independent, nothing
> validates them against each other, and a parser that trusts one while another parser trusts the
> other will read different strings from the same bytes. Chapter 10 §6.3 calls this "one of the most
> reliable ways to build an APK that analysis tools misreport", and this is the check that catches
> it.

### Step 2.3 — Assemble the pool

```python
# host — add to myaxml.py
UTF8_FLAG = 0x100


def read_string_pool(data, start, header_size, chunk_size):
    count         = u32(data, start + 8)
    style_count   = u32(data, start + 12)
    flags         = u32(data, start + 16)
    strings_start = u32(data, start + 20)
    utf8 = bool(flags & UTF8_FLAG)

    print(f"string pool: {count} strings, {'UTF-8' if utf8 else 'UTF-16'}, "
          f"flags=0x{flags:x}, stringsStart={strings_start}")

    offsets_at = start + header_size          # NOT start + 28
    strings = []
    for i in range(count):
        if offsets_at + 4 * i + 4 > start + chunk_size:
            print(f"!! offset #{i} is outside the pool chunk")
            break
        pos = start + strings_start + u32(data, offsets_at + 4 * i)
        if pos >= start + chunk_size:
            print(f"!! string #{i} points to 0x{pos:x}, outside the chunk")
            strings.append(None)
            continue
        text, _ = read_utf8(data, pos) if utf8 else read_utf16(data, pos)
        strings.append(text)
    return strings
```

Wire it into the walk, then:

```bash
# host
python3 myaxml.py AndroidManifest.xml | head -40
```

You should now be able to print every string in the document. Sanity check: the package name, the
namespace URI `http://schemas.android.com/apk/res/android`, `manifest`, `application`, `activity`
and every permission name must all be in there.

```bash
# host — compare your string list against the tool's
grep -o 'android\.permission\.[A-Z_]*' aapt2-reading.txt | sort -u
```

---

## Part 3 — The resource map

`RES_XML_RESOURCE_MAP_TYPE` (`0x0180`) is an array of 32-bit resource IDs, one per string-pool entry,
in the same order. It says: "string #7 is the framework attribute `0x0101000f`."

```python
# host — add to myaxml.py
def read_resource_map(data, start, header_size, chunk_size):
    count = (chunk_size - header_size) // 4
    return [u32(data, start + header_size + 4 * i) for i in range(count)]
```

You do not need it to read a manifest, because attribute *names* are also in the string pool. You do
need it to understand two things:

- An obfuscated or hand-built manifest can leave the name string **empty** and rely on the resource
  ID alone. The platform matches attributes by ID, not by name. A parser that only reads names sees
  an attribute with no name; the platform sees `android:exported`.
- A resource ID in the map that does not match the framework's real ID for that name is a mismatch
  worth reporting.

> **🔍 Pentester's Note** If your parser prints an attribute whose name is the empty string, do not
> shrug. Look up its resource ID against the framework's `public.xml` — `aapt2 dump resources` on
> `android.jar`'s resources, or simply search for the constant. That construction exists precisely so
> that name-matching tools see nothing.

---

## Part 4 — Elements and attributes

```
struct ResXMLTree_node {          // the common header for every XML chunk
    ResChunk_header header;       // 8 bytes
    uint32_t lineNumber;
    uint32_t comment;             // string index, or -1
};                                // 16 bytes

struct ResXMLTree_attrExt {       // follows the node header in START_ELEMENT
    uint32_t ns;                  // string index, or -1
    uint32_t name;                // string index
    uint16_t attributeStart;      // from the END of the node header
    uint16_t attributeSize;       // the size of EACH attribute record
    uint16_t attributeCount;
    uint16_t idIndex;             // 1-based, or 0
    uint16_t classIndex;
    uint16_t styleIndex;
};

struct ResXMLTree_attribute {
    uint32_t ns;                  // string index, or -1
    uint32_t name;                // string index
    uint32_t rawValue;            // string index of the ORIGINAL TEXT, or -1
    Res_value typedValue;         // 8 bytes
};

struct Res_value {
    uint16_t size;                // 8
    uint8_t  res0;                // 0
    uint8_t  dataType;
    uint32_t data;
};
```

### Step 4.1 — The two fields that decide everything

Two fields in that listing are the whole reason this lab exists.

**`attributeSize`.** Attribute record *i* lives at
`nodeStart + headerSize + attributeStart + i * attributeSize`. The record is defined as 20 bytes, and
in every file `aapt2` produces `attributeSize` *is* 20 — so it is enormously tempting to write
`i * 20` and move on. Honour the field. A document that declares a larger stride is still legal, and
the platform strides by the declared value.

**`rawValue` and `typedValue`.** Every attribute carries two representations: the original text as a
string-pool index, and the parsed value as a `Res_value`. **The platform reads `typedValue`.**
`rawValue` exists so that tools can show a human the text the developer typed. Nothing forces them to
agree.

> **⚠️ Warning** Write `typedValue` into your output and `rawValue` into a side note, never the other
> way around. If you render `rawValue` because it is prettier, you have written a tool that displays
> a value the platform never consults — which is exactly the tool the next lab is designed to defeat.

### Step 4.2 — Implement it

```python
# host — add to myaxml.py
def read_start_element(data, start, header_size, chunk_size, strings):
    base = start + header_size
    ns_idx  = i32(data, base)
    name_idx = i32(data, base + 4)
    attr_start = u16(data, base + 8)
    attr_size  = u16(data, base + 10)
    attr_count = u16(data, base + 12)

    name = strings[name_idx] if 0 <= name_idx < len(strings) else "?"

    if attr_size != 20:
        print(f"!! <{name}> declares attributeSize={attr_size}, not 20 — "
              f"a parser that assumes 20 reads different bytes from here on")

    attrs = []
    for i in range(attr_count):
        rec = base + attr_start + i * attr_size      # HONOUR the field
        if rec + 20 > start + chunk_size:
            print(f"!! <{name}> attribute {i} runs past the end of its chunk")
            break
        a_ns   = i32(data, rec)
        a_name = i32(data, rec + 4)
        a_raw  = i32(data, rec + 8)
        v_size = u16(data, rec + 12)
        v_res0 = data[rec + 14]
        v_type = data[rec + 15]
        v_data = u32(data, rec + 16)
        attrs.append((a_ns, a_name, a_raw, v_size, v_res0, v_type, v_data))
    return name, attrs
```

### Step 4.3 — Render `Res_value`

| `dataType` | Meaning | How to render `data` |
|---|---|---|
| `0x00` | `TYPE_NULL` | `@null` when 0, `@empty` otherwise |
| `0x01` | `TYPE_REFERENCE` | `@0x7f0a0013` — a resource ID |
| `0x02` | `TYPE_ATTRIBUTE` | `?0x0101000f` |
| `0x03` | `TYPE_STRING` | `data` is a string-pool index |
| `0x04` | `TYPE_FLOAT` | reinterpret the 32 bits as IEEE-754 |
| `0x05` | `TYPE_DIMENSION` | mantissa and radix, unit in the low nibble |
| `0x06` | `TYPE_FRACTION` | as dimension, unit `%` or `%p` |
| `0x10` | `TYPE_INT_DEC` | signed decimal |
| `0x11` | `TYPE_INT_HEX` | hexadecimal |
| `0x12` | `TYPE_INT_BOOLEAN` | **zero is false; any non-zero value is true** |
| `0x1c`–`0x1f` | colours | `#aarrggbb` |

```python
# host — add to myaxml.py
def render(dtype, data, strings):
    if dtype == 0x03:
        return repr(strings[data]) if data < len(strings) else f"<#{data}>"
    if dtype == 0x12:
        return "true" if data != 0 else "false"      # NON-ZERO is true
    if dtype == 0x01:
        return f"@0x{data:08x}"
    if dtype == 0x10:
        return str(data if data < 0x80000000 else data - (1 << 32))
    if dtype == 0x11:
        return f"0x{data:x}"
    if dtype == 0x04:
        return repr(struct.unpack("<f", struct.pack("<I", data))[0])
    return f"0x{data:08x}"
```

> **🔬 Under the Hood** `TYPE_INT_BOOLEAN` treats *any* non-zero value as true, and `aapt2` writes
> `0xffffffff` for true. Both `0x00000001` and `0xffffffff` are true to the platform. A parser that
> compares against 1 reads `0xffffffff` as… something else, depending on how carelessly it was
> written. Test yours: build a manifest with `debuggable` set to `0x00000002` and see what you print.

### Step 4.4 — The divergence check

This is the single most valuable ten lines in your parser.

```python
# host — add to myaxml.py, inside your attribute loop
typed = render(v_type, v_data, strings)
raw = strings[a_raw] if 0 <= a_raw < len(strings) else None

if raw is not None and v_type != 0x03:
    if str(raw).strip().lower() != str(typed).strip().lower():
        print(f"!! <{name}> {attr_name}: rawValue={raw!r} but "
              f"typedValue={typed} (type=0x{v_type:02x}, "
              f"data=0x{v_data:08x}) — THE PLATFORM READS typedValue")
```

Run it against a normal APK. It should print nothing: in an `aapt2`-produced manifest the two always
agree, because `aapt2` wrote both from the same source text. Any output at all is either a bug in
your parser or a manifest that was post-processed after the build.

---

## Part 5 — Print the tree

Maintain a depth counter: `+1` on `START_ELEMENT`, `-1` on `END_ELEMENT`. Resolve namespace prefixes
by recording each `START_NAMESPACE` chunk's `uri -> prefix` mapping.

```
<manifest
    package='com.example.app'                        (TYPE_STRING)
    android:versionCode=12                           (TYPE_INT_DEC)
>
  <application
      android:label=@0x7f120000                      (TYPE_REFERENCE)
      android:debuggable=false                       (TYPE_INT_BOOLEAN)
      android:allowBackup=false                      (TYPE_INT_BOOLEAN)
  >
    <activity
        android:name='.MainActivity'                 (TYPE_STRING)
        android:exported=true                        (TYPE_INT_BOOLEAN)
    >
```

### Step 5.1 — Compare with `aapt2`

```bash
# host
python3 myaxml.py AndroidManifest.xml > mine.txt
diff <(grep -oE 'android:[a-zA-Z]+' mine.txt | sort -u) \
     <(grep -oE 'android:[a-zA-Z]+' aapt2-reading.txt | sort -u)
```

Empty output means you agree on which attributes exist. Now compare the *values* of the ones that
matter:

```bash
# host
grep -iE 'debuggable|allowBackup|exported|usesCleartextTraffic|testOnly' mine.txt
grep -iE 'debuggable|allowBackup|exported|usesCleartextTraffic|testOnly' aapt2-reading.txt
```

If those disagree on a normal APK, your parser is wrong. Fix it before continuing. This is the
calibration step: you must know your tool is correct on an honest file before you can use it on a
dishonest one.

---

## Part 6 — Refuse to continue silently

The README's brief for this lab has four requirements. Three are done. The fourth is the one that
turns a decoder into an analysis tool: **report any structural inconsistency rather than silently
continuing.**

Add each of these. Every one corresponds to a real construction.

| Check | Why it matters |
|---|---|
| Root `size` != file size | Bytes exist that a size-bounded parser never sees |
| A chunk's `size` is 0 | Infinite loop in a naive parser; stop condition in a careful one |
| A chunk's `size` runs past its parent | Forged length or truncation |
| `headerSize` < 8, or > `size` | Impossible; a lenient parser skips fields it should read |
| `headerSize` != the expected value for the type | The classic AXML confusion primitive |
| `attributeSize` != 20 | Stride divergence — see the next lab |
| `Res_value.size` != 8 | Not 8 by definition; strides go wrong from here |
| `Res_value.res0` != 0 | A reserved field with something in it |
| A string index out of range | Crash primitive in a naive parser |
| UTF-8 char count != decoded length | Two readers now hold different strings |
| Missing string terminator | A terminator-driven reader runs into the next string |
| Two attributes with the same ns+name | Which one wins is an implementation detail |
| An `END_ELEMENT` with no matching start | The event stream is not a tree |
| Chunks after the root chunk's end | Seen by a file-bounded parser, not by a size-bounded one |
| An unknown chunk type | Skipped by size — so it can hold anything |

> **🧠 Mental Model** A decoder answers "what does this say?". An analysis tool answers "is there any
> way to read this other than the way I just did?". The list above is that second question, written
> out. Every entry is a place where two reasonable implementations part company.

### Step 6.1 — Test that your checks fire

Break a copy deliberately and confirm each check catches it.

```bash
# host — inflate the root chunk's headerSize from 8 to 12
cp AndroidManifest.xml broken1.xml
printf '\x0c' | dd of=broken1.xml bs=1 seek=2 conv=notrunc 2>/dev/null
python3 myaxml.py broken1.xml
```

```bash
# host — append a stray chunk after the document ends
cp AndroidManifest.xml broken2.xml
printf '\x03\x01\x10\x00\x18\x00\x00\x00' >> broken2.xml
printf '\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff' >> broken2.xml
python3 myaxml.py broken2.xml
```

The second one is instructive: the root chunk's `size` still says the old length, so a parser bounded
by `size` never sees the appended bytes and a parser bounded by the file does. **Both behaviours are
defensible.** That is exactly the problem.

---

## Part 7 — The manifest your tools cannot read

Now build a manifest that is legal, that the platform accepts, and that breaks at least one
mainstream decoder.

> **⚠️ Warning** Build this yourself, in your own directory, and do not distribute it. The
> construction below is the mechanism behind real store-review evasion. It is here so that you can
> *detect* it. See the rules at the top of
> [lab 04](lab-04-ctf-the-lying-manifest.md).

### Step 7.1 — Build the awkward manifests

```python
#!/usr/bin/env python3
# host — save as bend.py, run: python3 bend.py AndroidManifest.xml
"""Produce four legal-but-awkward variants of a compiled manifest.

Each one bends a different field. None of them is malformed in a way that
ResourceTypes.cpp rejects; all of them are things a decoder can get wrong.
"""
import struct
import sys

src = sys.argv[1] if len(sys.argv) > 1 else "AndroidManifest.xml"
base = open(src, "rb").read()


def chunks(data):
    """Yield (offset, type, headerSize, size) for every top-level chunk."""
    root_size = struct.unpack_from("<I", data, 4)[0]
    off = struct.unpack_from("<H", data, 2)[0]
    while off + 8 <= min(root_size, len(data)):
        t, h, s = struct.unpack_from("<HHI", data, off)
        if s == 0:
            return
        yield off, t, h, s
        off += s


# --- A. a trailing chunk the root chunk's size does not cover --------------
extra = struct.pack("<HHI", 0x0103, 16, 24) + b"\xff" * 16
open("bent-trailing.xml", "wb").write(base + extra)

# --- B. an unknown chunk type, skipped by size -----------------------------
payload = b"HIDDEN-IN-AN-UNKNOWN-CHUNK" + b"\x00" * 38
blob = struct.pack("<HHI", 0x4242, 8, 8 + len(payload)) + payload
out = bytearray(base)
insert_at = next(o for o, t, h, s in chunks(base)
                 if t == 0x0100)                  # before the first namespace
out[insert_at:insert_at] = blob
struct.pack_into("<I", out, 4, len(out))          # fix the root size
open("bent-unknown.xml", "wb").write(bytes(out))

# --- C. a non-standard attributeSize ---------------------------------------
# Widen every attribute record to 40 bytes, re-laying out the records so the
# document still says exactly what it said before.
out = bytearray()
prev_end = 0
for off, t, h, s in chunks(base):
    out += base[prev_end:off]
    if t != 0x0102:                               # START_ELEMENT only
        out += base[off:off + s]
        prev_end = off + s
        continue
    body = bytearray(base[off:off + s])
    a_start, a_size, a_count = struct.unpack_from("<HHH", body, h + 8)
    if a_size != 20:
        out += bytes(body)
        prev_end = off + s
        continue
    records = [bytes(body[h + a_start + i * 20: h + a_start + (i + 1) * 20])
               for i in range(a_count)]
    widened = b"".join(r + b"\x00" * 20 for r in records)
    new_body = bytearray(body[:h + a_start]) + widened
    struct.pack_into("<H", new_body, h + 10, 40)          # attributeSize = 40
    struct.pack_into("<I", new_body, 4, len(new_body))    # fix chunk size
    out += bytes(new_body)
    prev_end = off + s
out += base[prev_end:]
struct.pack_into("<I", out, 4, len(out))
open("bent-attrsize.xml", "wb").write(bytes(out))

# --- D. an inflated headerSize on the root chunk ---------------------------
out = bytearray(base)
struct.pack_into("<H", out, 2, 12)                # headerSize 8 -> 12
open("bent-headersize.xml", "wb").write(bytes(out))

print("wrote bent-trailing.xml bent-unknown.xml bent-attrsize.xml "
      "bent-headersize.xml")
```

```bash
# host
python3 bend.py AndroidManifest.xml
ls -l bent-*.xml
```

### Step 7.2 — Package each one and measure

An AXML file on its own is not much use to `apktool`, which wants an APK. Put each variant back into
a copy of the original.

```bash
# host — one APK per variant
for v in trailing unknown attrsize headersize; do
  cp target.apk "bent-$v.apk"
  cp "bent-$v.xml" AndroidManifest.xml
  zip -X -q "bent-$v.apk" AndroidManifest.xml
done
ls -l bent-*.apk
```

If `zip` is not installed — it often is not on Windows — do the same with Python:

```python
#!/usr/bin/env python3
# host — save as repack.py, run: python3 repack.py
"""Replace AndroidManifest.xml inside a copy of the APK, four times."""
import shutil
import zipfile

for v in ("trailing", "unknown", "attrsize", "headersize"):
    out = f"bent-{v}.apk"
    shutil.copy("target.apk", out)
    with zipfile.ZipFile(out, "a") as zf:
        zf.write(f"bent-{v}.xml", "AndroidManifest.xml")
    print(f"wrote {out}")
```

That leaves *two* entries named `AndroidManifest.xml` in each output, which is itself the Master Key
shape from Lab 01 — and readers resolve it differently, which is a second experiment for free. Check
what you have produced before drawing conclusions:

```bash
# host
python3 ../examples/parse_apk_zip.py bent-attrsize.apk | grep -i duplicate
```

> **⚠️ Warning** These APKs are now unsigned garbage as far as any device is concerned, because
> replacing an entry invalidates every signature. That is fine — this part of the lab is about
> *decoders*, not installation. Lab 04 does the whole pipeline properly.

Now run every reader you have against every variant, and fill in this table **from what you actually
observe**, not from what you expect:

| Variant | your parser | `aapt2 dump xmltree` | `apktool d` | `jadx` |
|---|---|---|---|---|
| `bent-trailing` | | | | |
| `bent-unknown` | | | | |
| `bent-attrsize` | | | | |
| `bent-headersize` | | | | |

```bash
# host — one cell at a time
python3 myaxml.py bent-attrsize.xml
aapt2 dump xmltree bent-attrsize.apk --file AndroidManifest.xml
apktool d -f -o /tmp/bent bent-attrsize.apk && cat /tmp/bent/AndroidManifest.xml
jadx -d /tmp/bentjx --no-src bent-attrsize.apk && cat /tmp/bentjx/resources/AndroidManifest.xml
```

Record for each cell: **decoded correctly**, **decoded but wrong**, **refused**, or **crashed**.

> **⚠️ Warning** Your results will not match anyone else's exactly, because they depend on the
> versions of `apktool`, `jadx` and `aapt2` you have installed. That is not a flaw in the lab — it is
> the finding. **Write your versions down next to your table.** A statement like "apktool cannot read
> this" is worthless without them; "apktool 2.9.3 renders `debuggable=false` where aapt2 2.19 renders
> `debuggable=true`" is a report line.

One column is worth predicting so that you can check your own work. `aapt2` is a host build of the
same `libandroidfw` code the device runs, so it is the closest thing to the platform you can run
without a device.

For calibration, here is that column measured on `aapt2` 2.19. **Treat it as a worked example, not
as ground truth — run your own and record your own version.**

| Variant | `aapt2` 2.19 result |
|---|---|
| `bent-trailing` | Decodes the document unchanged. It is bounded by the root chunk's `size`, so it never sees the appended chunk. |
| `bent-unknown` | Decodes the document unchanged. The unknown chunk is skipped by its `size`, exactly as the format intends — and its 72 bytes of payload are never mentioned. |
| `bent-attrsize` | Decodes the document unchanged. It strides by the declared 40, which confirms `attributeSize` is honoured rather than assumed. |
| `bent-headersize` | **Refuses**: `XML header size 0x0000 is too small.` followed by `error: could not identify format of APK`. |

Two lessons are in that table.

The `bent-unknown` row is the more alarming one. Nothing is wrong, nothing is reported, and 72 bytes
of attacker-chosen data went past a tool built by the platform vendor without a word. "The tool did
not complain" and "there is nothing there" are different statements.

The `bent-headersize` row is the honest counterweight. A well-written parser — including, if you did
Part 6 properly, yours — *also* refuses that file, and refusing is the correct behaviour. The goal of
this lab is not a parser that reads everything. It is a parser that never reads something one way
while telling you it read it another.

### Step 7.3 — Explain why yours succeeded

For every cell where your parser did better than a mainstream tool, write one sentence naming the
field. Not "my parser is more robust" — "my parser strides attribute records by the declared
`attributeSize` rather than a hardcoded 20, so it read the second attribute at offset +40 where the
other tool read it at +20."

If a mainstream tool did better than yours, that sentence is even more valuable. Write it and fix
your parser.

---

## Part 8 — Compare with the reference implementation

Now, and only now, read [`../examples/parse_axml.py`](../examples/parse_axml.py).

```bash
# host — the reference, on the same files
python3 ../examples/parse_axml.py AndroidManifest.xml
python3 ../examples/parse_axml.py bent-attrsize.xml --anomalies-only
python3 ../examples/parse_axml.py --extract target.apk --chunks
```

Diff its behaviour against yours, on all four bent variants:

```bash
# host
for v in trailing unknown attrsize headersize; do
  echo "=== $v ==="
  python3 myaxml.py "bent-$v.xml"                       > /tmp/mine.txt  2>&1
  python3 ../examples/parse_axml.py "bent-$v.xml"       > /tmp/ref.txt   2>&1
  diff /tmp/mine.txt /tmp/ref.txt | head -20
done
```

Three questions to answer in writing:

1. Which checks does the reference make that yours does not? Add the ones you agree with.
2. Which checks does *yours* make that the reference does not? If you are right, that is a genuine
   improvement — say why.
3. The reference calls itself "a FOURTH reading, not the authority". What is the authority, and how
   would you consult it for a specific APK?

---

## Hints

<details>
<summary>Hint 1 — every string I print is garbage</summary>

Two usual causes.

You are reading the offset array from `chunkStart + 28` instead of `chunkStart + headerSize`. They
are the same number in an honest file, so this bug hides until you meet a dishonest one.

Or you are adding the per-string offset to the wrong base. The offsets are relative to
`chunkStart + stringsStart`, **not** to the start of the file and not to the end of the offset array.

```bash
xxd -s <poolChunkOffset> -l 32 AndroidManifest.xml
```

The first 8 bytes are the chunk header; `stringCount` is the four bytes at +8.
</details>

<details>
<summary>Hint 2 — my UTF-16 strings have a NUL between every character</summary>

You decoded them as ASCII or Latin-1. UTF-16LE stores `A` as `41 00`. Use
`raw.decode("utf-16-le")`, and take exactly `n * 2` bytes where `n` is the declared count of *code
units* — not `n` bytes, and not "up to the next NUL".
</details>

<details>
<summary>Hint 3 — my chunk walk stops after the string pool</summary>

You advanced by `headerSize` instead of by `size`. `headerSize` tells you where the payload begins
*inside* this chunk; `size` tells you where the *next* chunk begins. Print both for every chunk and
the mistake becomes obvious immediately.
</details>

<details>
<summary>Hint 4 — attribute values are all zero or nonsense</summary>

The attribute array starts at `nodeStart + headerSize + attributeStart`, and `attributeStart` is
measured **from the end of the node header**, not from the start of the chunk. So it is
`start + 16 + attributeStart` for a standard 16-byte node header — which is why you must use
`headerSize` rather than the literal 16.

Also check you are reading `Res_value` as `<HBBI` (size, res0, dataType, data) and not `<HHI`. The
type is a single byte.
</details>

<details>
<summary>Hint 5 — aapt2 shows an attribute my parser does not</summary>

Count the attributes it shows against the `attributeCount` you read. If the counts match but one
value differs, you have a stride or a rendering bug. If `aapt2` shows *more* attributes than your
`attributeCount`, you are reading `attributeCount` from the wrong offset — it is at
`base + 12`, after `ns`(4), `name`(4), `attributeStart`(2), `attributeSize`(2).
</details>

<details>
<summary>Hint 6 — how do I know which reading is RIGHT?</summary>

You do not, from the file alone, and that is the honest answer. The platform is the authority. Sign
the APK, install it, and ask:

```bash
adb install -r bent-attrsize.apk
adb shell dumpsys package com.example.app | grep -E 'flags=|privateFlags='
```

`dumpsys` reports what `PackageManagerService` parsed and stored. Whatever it says is what the
device will enforce, no matter what any decoder rendered. Lab 04 turns this into the method.
</details>

---

## Success criteria

| # | Criterion | How you prove it |
|---|---|---|
| 1 | Your parser walks the chunk tree by `headerSize` and `size` | `grep -n 'headerSize\|+ 28\|+ 16' myaxml.py` shows no hardcoded structural offsets |
| 2 | It reads both string-pool encodings | It decodes a UTF-16 manifest and a UTF-8 one; if you have no UTF-8 sample, build one and say so |
| 3 | It renders `typedValue`, with `rawValue` only as a note | Your output for `android:debuggable` shows the `Res_value`, and the raw text is labelled as such |
| 4 | It honours `attributeSize` | `bent-attrsize.xml` decodes to the same document as the original |
| 5 | It reports rather than continues | All fifteen checks in the Part 6 table are implemented, and you have demonstrated at least four firing |
| 6 | It agrees with `aapt2` on an honest APK | The Part 5 diff is empty for attribute names, and the security-relevant values match |
| 7 | You measured the tool matrix | The Part 7.2 table is filled in from observation, with tool versions recorded |
| 8 | You can name the field for every divergence | One sentence per cell where the tools disagreed, naming the specific AXML field |
| 9 | You compared with the reference | You listed checks to add, checks you have that it does not, and named the real authority |

---

## What to take into the next lab

You now have a reading of any manifest that you can defend, and a list of the fields that make two
readers disagree. [Lab 04 — CTF: The Lying Manifest](lab-04-ctf-the-lying-manifest.md) hands you an
APK built to exploit exactly one of them, plus a container hiding something where lab 01 taught you
to look, and asks you to work out what the platform really does with it.

For what the attributes you have been decoding actually *mean* — which components are reachable, what
`exported` implies for each, how `permission` interacts with it — go to
[32-Manifest](../../32-Manifest/README.md). This chapter owns the bytes; that chapter owns the
semantics.
