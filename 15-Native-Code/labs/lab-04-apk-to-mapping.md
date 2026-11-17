# Lab 04 — From APK entry to mapped page

> **Objective:** follow one native library the whole way: from a ZIP entry inside an APK, through
> the install-time decision that decides whether it is extracted or mapped in place, to the four
> lines it occupies in `/proc/<pid>/maps` — and reconcile every number in the file with every number
> in the live process.

**Prerequisites:** [Lab 01](lab-01-elf-by-hand.md), [Lab 03](lab-03-symbols-and-linking.md),
[15-Native-Code §3.3](../README.md#33-program-headers-what-the-loader-reads),
[§3.10](../README.md#310-the-bionic-linker-how-the-file-becomes-a-mapping),
[§3.11](../README.md#311-how-the-library-gets-out-of-the-apk),
[10-APK-Internals](../../10-APK-Internals/README.md)
**Difficulty:** Intermediate
**Time:** 75 minutes
**You will need:** the fixtures, Python 3. Parts 4 and 5 need a device or emulator; Parts 1–3 do
not.

---

## Why this lab exists

Three questions get asked constantly and are almost always answered from memory rather than from
evidence:

- *Where is the `.so` on the device?* — which is where you `adb pull` from, and where a
  root-level attacker would tamper.
- *Which ABI directory actually runs?* — analysing the wrong one wastes a day.
- *Why does `/proc/<pid>/maps` show four lines for one library, and which one is the base?* —
  getting this wrong makes every subsequent address wrong by a constant.

This lab answers all three by measurement.

---

## Setup

```bash
# host
export ANDROID_HOME="$HOME/Android/Sdk"
cd 15-Native-Code/examples && ./build-fixtures.sh /tmp/ch15-fixtures
cd /tmp/ch15-fixtures
S=~/…/15-Native-Code/scripts
```

`build-fixtures.sh` produces `fixture.apk`, deliberately containing one **stored** library and one
**deflated** one, so the two paths can be compared in the same file.

---

## Part 1 — The APK is a ZIP, and the storage method matters

### Task 1.1 — look at the entries

```bash
# host — with Python, so this works everywhere
python3 - <<'PY'
import zipfile
z = zipfile.ZipFile('fixture.apk')
print('%-40s %-10s %10s %10s' % ('name', 'method', 'compressed', 'original'))
for i in z.infolist():
    method = 'STORED' if i.compress_type == 0 else 'DEFLATED'
    print('%-40s %-10s %10d %10d' % (i.filename, method, i.compress_size, i.file_size))
PY
```

```bash
# host — the same with unzip, if you have it
unzip -v fixture.apk | awk 'NR>3 {print $2, $3, $8}'
```

### Task 1.2 — find the data offset and check the alignment

A ZIP entry's *data* does not start at its local-header offset. It starts 30 bytes later, plus the
file name length, plus the **local** extra-field length — which is not necessarily the same as the
central directory's extra-field length, and is exactly where `zipalign` inserts its padding.

```bash
# host
python3 $S/elf-harden-check.py --apk fixture.apk | grep 'in APK'
```

<details>
<summary>Expected</summary>

```text
fixture.apk!lib/arm64-v8a/libdemo-hard.so
  in APK: STORED (uncompressed), data at offset 16384, 16384-byte aligned

fixture.apk!lib/arm64-v8a/libjnisurface.so
  in APK: STORED (uncompressed), data at offset 137, 1-byte aligned
           -> stored uncompressed BUT NOT page-aligned, so it still cannot be mapped
              in place: mmap needs a page-multiple file offset. Both conditions
              are required. Run zipalign. See README section 3.11.

fixture.apk!lib/armeabi-v7a/libdemo-arm32.so
  in APK: DEFLATED (compressed), data at offset 4863, 1-byte aligned
           -> compressed, so the library must be extracted to /data/app/.../lib/
              at install time rather than mapped straight out of the APK.
```

**Three entries, three outcomes, and only the first one can be mapped in place.** The fixture is
built that way on purpose:

| Entry | Method | Aligned? | Result |
|---|---|---|---|
| `libdemo-hard.so` | `STORED` | 16 KiB | mapped straight out of the APK |
| `libjnisurface.so` | `STORED` | no | **still extracted at install** |
| `libdemo-arm32.so` | `DEFLATED` | no | extracted at install |

The middle row is the one that catches real apps out. The manifest says
`extractNativeLibs="false"`, the entry is uncompressed, the build looks correct — and because
nobody ran `zipalign`, the library is extracted anyway and the app gets neither the disk saving nor
the in-place mapping. `build-fixtures.sh` produces the aligned entry the same way `zipalign` does:
by padding the entry's **local extra field** with Android's `0xD935` alignment record until the data
lands on a page boundary.

</details>

### Task 1.3 — why both conditions are needed

Answer in your own words: why is "uncompressed" not enough on its own, and why is "page-aligned" not
enough on its own?

<details>
<summary>Answer</summary>

`mmap` maps a **file** at a **file offset**, and the kernel requires that offset to be a multiple of
the page size. So:

- **Compressed but aligned** — the bytes in the file are not the bytes of the library. Mapping them
  would map compressed data. Useless.
- **Uncompressed but unaligned** — the bytes are right, but the offset cannot be passed to `mmap`.
  You could map from the previous page boundary and add a delta, but the linker does not, because
  the segment alignment inside the ELF then no longer lines up with page boundaries.

Both together mean the kernel can map the library's `PT_LOAD` segments straight out of the APK file,
with no copy, no extraction, and no second copy on disk. That is what `extractNativeLibs="false"`
buys.

</details>

---

## Part 2 — Reconcile the file with what will be mapped

### Task 2.1 — the segment table

```bash
# host
python3 $S/elf-inspect.py libjnisurface.so --segments
```

Write out, for each `PT_LOAD`, the memory-map instruction:

| # | file offset | maps at base + | file bytes | memory bytes | perms | align |
|---|---|---|---|---|---|---|
| | | | | | | |

### Task 2.2 — predict the maps output

Before touching a device, predict what `/proc/<pid>/maps` will look like. For a library loaded at a
hypothetical base of `0x7b2c146000`, and assuming 4 KiB pages, write the four lines you expect:

```text
<start>-<end> <perms>p <file offset> ... libjnisurface.so
```

<details>
<summary>Method</summary>

For each `PT_LOAD`:

- start = `base + (p_vaddr rounded DOWN to a page boundary)`
- end = `base + ((p_vaddr + p_memsz) rounded UP to a page boundary)`
- the file offset column = `p_offset rounded DOWN to a page boundary`
- perms = `p_flags`, plus `p` for `MAP_PRIVATE`

The rounding is why the numbers in `maps` are never exactly the numbers in the program headers, and
why `p_memsz > p_filesz` produces an extra anonymous mapping for `.bss` on some layouts.

</details>

### Task 2.3 — the RELRO prediction

Which of your four predicted lines will have **different** permissions in the live process from what
the file's program headers say, and why?

<details>
<summary>Answer</summary>

The one covering the `PT_GNU_RELRO` region. The file says it is part of a `RW` `PT_LOAD`; after the
linker finishes relocating, it calls `mprotect` on that range and it becomes `r--p`.

So the file describes the *initial* permissions and the live process shows the *final* ones. If you
see it as `rw-p` in a live process, RELRO did not happen — which for an Android library would be
notable, since the NDK links `-z relro -z now` by default.

</details>

---

## Part 3 — Which ABI wins

### Task 3.1 — the mismatch check

`build-fixtures.sh` puts a 32-bit library in `lib/armeabi-v7a/`, which is correct. Now make a
deliberately broken APK:

```bash
# host
python3 - <<'PY'
import zipfile, shutil
shutil.copy('fixture.apk', 'broken.apk')
with zipfile.ZipFile('broken.apk', 'a') as z:
    # a 64-bit library, stored under the 32-bit ABI directory
    z.write('libdemo-hard.so', 'lib/armeabi-v7a/libdemo-hard.so', zipfile.ZIP_STORED)
print('made broken.apk')
PY

python3 $S/elf-harden-check.py --apk broken.apk | grep -A2 MISMATCH
```

<details>
<summary>Expected</summary>

```text
  ! ABI MISMATCH: stored under lib/armeabi-v7a/ but e_machine says arm64-v8a.
    The device picks the directory by ABI, so this library is either never
    loaded or loaded by a device it was not built for.
```

</details>

### Task 3.2 — what a mismatch means in the field

List three plausible explanations for a real APK containing this. Rank them by likelihood.

<details>
<summary>Answers</summary>

1. **A build script bug.** By far the most likely. Someone copied files with a hard-coded path.
   Consequence: on a 32-bit device the app crashes on `loadLibrary`; on a 64-bit device the
   `armeabi-v7a` directory is never consulted at all, so nobody notices.
2. **A deliberate stash.** The "library" is a payload the app never loads via `System.loadLibrary`,
   but `dlopen`s or reads by absolute path later, or writes elsewhere and executes. Worth checking:
   does anything in the DEX reference the file by path rather than by library name?
3. **A repackaging artefact.** Someone added a library to a signed APK and did not think about ABI
   directories.

The point is that the checker's job is to state the observation, and yours is to decide which
explanation fits. All three are worth a line in notes; only the second is a finding.

</details>

### Task 3.3 — which directory would the device pick?

```bash
# adb shell — on any device or emulator
getprop ro.product.cpu.abilist
getprop ro.product.cpu.abi
```

Given `arm64-v8a,armeabi-v7a,armeabi` and an APK containing `lib/arm64-v8a/`,
`lib/armeabi-v7a/` and `lib/x86_64/`, which one is used, and what happens to the other two?

<details>
<summary>Answer</summary>

`arm64-v8a` — the first entry in the device's list for which the APK has a directory. The other two
are downloaded, stored on disk inside the APK, and never read. They are pure size, which is what App
Bundles and split APKs exist to remove.

Consequence for you: **analyse `arm64-v8a`**. The 32-bit build is not necessarily identical — it can
have different inlining, different code paths, occasionally different features.

</details>

---

## Part 4 — On a device *(optional but recommended)*

Any device or emulator you own, with any app that has native libraries.

### Task 4.1 — find where the library actually is

```bash
# adb shell
pm path com.example.app
# package:/data/app/~~AbC.../com.example.app-XyZ.../base.apk

# is it extracted?
adb shell 'ls -la /data/app/~~AbC*/com.example.app-*/lib/arm64/' 2>/dev/null \
  || echo "no extracted lib directory -- mapped from the APK"
```

<details>
<summary>Interpreting the result</summary>

- **A `lib/arm64/` directory exists with `.so` files in it** → the libraries were extracted at
  install. `extractNativeLibs` was `true`, or the entries were compressed.
- **No such directory** → the libraries are mapped straight out of `base.apk`.

Note the directory is `lib/arm64`, not `lib/arm64-v8a`. The install-time name uses the *instruction
set* name, not the ABI name. This trips people up when scripting.

</details>

### Task 4.2 — read the live mapping

```bash
# adb shell — as the app itself, if it is debuggable
run-as com.example.app cat /proc/self/maps | grep '\.so' | head -20

# adb shell (root) — for any app
adb shell 'su -c "grep libnative /proc/$(pidof com.example.app)/maps"'
```

> **The quoting trap.** `adb shell` does not preserve quoting from the host shell. Writing
> `adb shell su -c "grep x y"` reaches the device as `su -c grep x y`, and `su -c` runs only `grep`. <!-- lint:allow SU-DASH-C SU-DASH-C-BARE -- the broken form, quoted as the counter-example this warning teaches -->
> Wrap the whole device-side command in single quotes as above.

### Task 4.3 — reconcile, line by line

Take the maps output for one library and check every one of these:

- [ ] The **first** line has file offset `00000000`. Its start address is the load base.
- [ ] The number of lines equals the number of `PT_LOAD` segments (plus possibly one anonymous
      `.bss` line).
- [ ] Each line's permissions match the corresponding `p_flags`, **except** the RELRO region.
- [ ] `end - start` for each line equals `p_memsz` rounded up to a page.
- [ ] The line covering `PT_GNU_RELRO` is `r--p`, not `rw-p`.

### Task 4.4 — verify the address arithmetic

```javascript
// Frida REPL -- frida -U -n com.example.app
var m = Process.findModuleByName('libnative.so');
console.log('Frida base       ', m.base);
// compare with the first maps line's start address -- they must be identical

var e = Module.findExportByName('libnative.so', 'JNI_OnLoad');
console.log('JNI_OnLoad live  ', e);
console.log('file vaddr       ', e.sub(m.base));
// compare with elf-inspect.py --dynsyms on the pulled file
```

Pull the file and check:

```bash
# host
adb pull /data/app/.../lib/arm64/libnative.so /tmp/
python3 $S/elf-inspect.py /tmp/libnative.so --dynsyms --grep JNI_OnLoad
```

The `value` column must equal `e.sub(m.base)` exactly. If it does not, you almost certainly took the
base from the `r-xp` line rather than the first line.

---

## Part 5 — The full loading sequence, observed *(optional)*

### Task 5.1 — watch the syscalls

```bash
# adb shell (root)
strace -f -e trace=openat,mmap,mprotect -p $(pidof com.example.app) 2>&1 | grep -i '\.so' | head -40
```

Then trigger something in the app that loads a library. You are looking for this sequence, per
library:

| Syscall | What it is |
|---|---|
| `openat(... "libnative.so" ...)` | Step 3 of §3.10 |
| `mmap(NULL, <total>, PROT_NONE, ...)` | Step 4 — the whole-image reservation |
| `mmap(<addr>, <filesz>, PROT_READ, ...)` | Step 5 — one per `PT_LOAD` |
| `mmap(<addr>, <filesz>, PROT_READ|PROT_EXEC, ...)` | |
| `mmap(<addr>, <filesz>, PROT_READ|PROT_WRITE, ...)` | |
| `mprotect(<addr>, <size>, PROT_READ)` | Step 8 — RELRO |

### Task 5.2 — watch the loader from inside

```bash
# host
frida -U -f com.example.app -l ~/…/15-Native-Code/scripts/native-map.js --no-pause
```

```javascript
// Frida REPL
rpc.exports.watchload();
// then drive the app so it loads something
// [dlopen] android_dlopen_ext("/data/app/.../libextra.so") -> 0xb4000...
//          mapped at 0x7b2c146000, 20480 bytes, 17 exports
```

### Task 5.3 — the question this answers

If a library appears in `watchload()` output but **not** in `rpc.exports.modules()` a moment later,
what has happened, and what should you do?

<details>
<summary>Answer</summary>

The library unlinked itself from the linker's `link_map` list — the same list `dl_iterate_phdr`
walks, and therefore the same list Frida's `Process.enumerateModules()` reads. This is a deliberate
anti-analysis technique.

What to do: fall back to `/proc/self/maps`, which is the kernel's bookkeeping and is not under the
process's control. The library's mappings are still there, still named after the file.

```javascript
// Frida REPL
var maps = new File('/proc/self/maps', 'r');  // or use Memory ranges
Process.enumerateRanges('r--').forEach(function (r) {
    if (r.file && r.file.path.indexOf('.so') > 0) console.log(r.base, r.file.path);
});
```

**The discrepancy is itself the finding.** A library that hides from the loader's own list is not
doing so for performance.

</details>

---

## Success criteria

- [ ] You identified which entries in an APK are `STORED` and which are `DEFLATED`, and found the
      data offset of each
- [ ] You can explain why both "uncompressed" and "page-aligned" are required, not either alone
- [ ] You predicted the `/proc/<pid>/maps` lines from the program header table before looking
- [ ] You correctly predicted which line's permissions would differ from the file, and why
- [ ] You produced an ABI mismatch and can give three explanations ranked by likelihood
- [ ] *(device)* You located the library on disk and determined whether it was extracted
- [ ] *(device)* You confirmed `findExportByName(...) - base` equals the `.dynsym` value exactly
- [ ] *(device)* You observed the `openat` → reservation `mmap` → per-segment `mmap` → `mprotect`
      sequence

---

## Going further

1. **Build the same APK twice**, once with each entry `STORED` and once `DEFLATED`, install both on
   a device, and compare the on-disk footprint and the contents of
   `/data/app/.../lib/`. The difference is the cost of `extractNativeLibs="true"` in bytes.
2. **Check a real app's manifest** for `extractNativeLibs` using `apktool` and see whether the
   attribute matches what the ZIP entries actually are. They can disagree, and the ZIP wins.
3. **Compute 16 KiB compatibility across an APK's whole library set** and count how many would fail
   on a 16 KiB-page device. Present it as a compatibility item, not a security one.
4. **Read `DexPathList.java`** in AOSP and work out exactly how the `!/lib/<abi>` path syntax reaches
   `android_dlopen_ext`. It is short and it explains how a library can be loaded from inside a ZIP.

---

## Next

[Lab 05 — CTF: the honest header](lab-05-ctf-the-honest-header.md). Everything so far has been
against files that told the truth.
