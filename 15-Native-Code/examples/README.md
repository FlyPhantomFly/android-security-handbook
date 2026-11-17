# 15 — Native Code · Examples

Four files. Two are C sources you compile yourself, one builds every fixture the
labs need, and one is the parser you should write before you trust anyone
else's.

**No compiled binary ships with this chapter.** A `.so` is a build artefact,
this repository commits none, and you should not run a binary you did not build.
Every fixture is three commands away.

---

## The files

| File | What it is | Why it exists |
|---|---|---|
| [`hardening-demo.c`](hardening-demo.c) | ~120 lines of deliberately flawed C | One source, six ELF files. Compile it several ways and watch the hardening checklist change while the source does not |
| [`jni-surface.c`](jni-surface.c) | A library whose export table is the point | Shows the three shapes a native method takes in `.dynsym`: statically registered and visible, dynamically registered and invisible, and not exported at all |
| [`build-fixtures.sh`](build-fixtures.sh) | The build script | Produces all eight fixtures, including a stripped copy, a 32-bit copy, a copy with its section headers removed, and an APK-shaped ZIP |
| [`elf_header_by_hand.py`](elf_header_by_hand.py) | ~200 lines, `struct.unpack` only | The parser [lab 01](../labs/lab-01-elf-by-hand.md) asks you to write. Use it to check your answer, not to skip the exercise |

---

## Build everything

```bash
# host — the NDK is the only toolchain that can produce an Android ELF
export ANDROID_HOME="$HOME/Android/Sdk"
cd examples
./build-fixtures.sh /tmp/ch15-fixtures
```

Put the output **outside the repository**. Compiled libraries are build
artefacts; nothing under `Android-Security-Handbook/` should ever be one.

If the script cannot find your NDK, set one of `ANDROID_HOME`, `NDK_HOME` or
`NDK_BIN` and try again. There is no substitute: a host `gcc` produces a glibc
binary that no Android device will load.

---

## What each fixture is for

| Fixture | Demonstrates | Used by |
|---|---|---|
| `libdemo-default.so` | What the compiler driver gives you unasked: RELRO and NX yes, canaries and FORTIFY no | [Lab 02](../labs/lab-02-hardening-audit.md), README §5.2 |
| `libdemo-hard.so` | Every mitigation on | Lab 02 |
| `libdemo-weak.so` | Every mitigation off, including an executable stack | Lab 02 |
| `libdemo-hard-stripped.so` | `.symtab` gone, `.dynsym` intact | [Lab 03](../labs/lab-03-symbols-and-linking.md) |
| `libdemo-arm32.so` | ELF32, `REL` rather than `RELA` relocations | Lab 01, Lab 03 |
| `libjnisurface.so` | Two visible JNI exports, four hidden behind dynamic registration | Lab 03, [Lab 04](../labs/lab-04-apk-to-mapping.md) |
| `libnoshdr.so` | No section header table at all — what a packer leaves you | Lab 03, [Lab 05](../labs/lab-05-ctf-the-honest-header.md) |
| `fixture.apk` | All three ZIP storage outcomes: `STORED` and 16 KiB-aligned (mappable in place), `STORED` but unaligned (**still extracted** — the case that catches real apps out), and `DEFLATED` | [Lab 04](../labs/lab-04-apk-to-mapping.md) |

---

## The three comparisons worth making first

```bash
# host — the whole point of the chapter, in one screen
python3 ../scripts/elf-harden-check.py /tmp/ch15-fixtures/libdemo-default.so \
                                       /tmp/ch15-fixtures/libdemo-hard.so \
                                       /tmp/ch15-fixtures/libdemo-weak.so | grep '^\['
```

1. **`default` versus `hard`** — `__stack_chk_fail` and the `__*_chk` family
   appear, and the *imports list shrinks*, because `strcpy` became
   `__strcpy_chk`. Same source, different symbols.
2. **`hard` versus `hard-stripped`** — `.symtab` disappears and `.dynsym` does
   not. `internal_checksum` vanishes; `public_checksum` does not. This is what
   "stripped" actually means.
3. **`arm64` versus `arm32`, `--init`** — on AArch64 the `.init_array` slot in
   the file is zero and the constructor's address lives in the
   `R_AARCH64_RELATIVE` relocation's *addend*. On ARM32, which uses `REL` and
   has no addend, the address really is in the slot. Read `.init_array` by hand
   on arm64 without knowing this and you will conclude there are no
   constructors.

---

## Honest note on how these were verified

Both `.c` files were compiled with NDK r25c's `aarch64-linux-android21-clang`
and `armv7a-linux-androideabi21-clang` while the chapter was written, and every
piece of tool output quoted in [README §9](../README.md#9-examples) is that
build's real output rather than an illustration. Addresses will differ with your
NDK version; the checklist **states** will not.

`jni-surface.c` compiles with no `jni.h` on purpose — its few JNI types are
declared locally, which is honest about the fact that from the ELF's point of
view `JNIEnv` is one pointer-sized argument like any other. Do not learn JNI
from it; that is [16-JNI](../../16-JNI/README.md)'s subject. It is a fixture.

---

## Related

| Where | Why |
|---|---|
| [`../scripts/`](../scripts/) | The four tools that read these fixtures |
| [`../labs/`](../labs/) | Five labs, all built on this output |
| [17-Libraries `lib-fingerprint.py`](../../17-Libraries/scripts/lib-fingerprint.py) | Run it next: which third-party libraries are statically linked in, and which versions |
| [57-Ghidra](../../57-Ghidra/README.md) | What to do once you know which address to open |
