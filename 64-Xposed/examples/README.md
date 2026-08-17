# 64-Xposed — examples

Four files, flat. This directory is **not** an Android project, and the mapping below is how these
files sit in a real one. That distinction has caused false "promised but absent" reports elsewhere in
this repository, so it is stated explicitly rather than assumed.

---

## What is here

| File | What it is | Lines |
|---|---|---|
| [`ClassicXposedModule.java`](ClassicXposedModule.java) | A module written entirely against the API rovo89 froze at version 82. Nothing in it is LSPosed-aware; it would have compiled in 2015 and it dexes cleanly today | ~215 |
| [`XposedDetector.java`](XposedDetector.java) | The eight-check specimen detector — the code still shipping in real applications. Every check carries its **measured** or **structural** verdict in a comment above it | ~330 |
| [`xposed_init`](xposed_init) | One line: the fully-qualified entry class name. **The file an obfuscated module can never rename** | 1 |
| [`AndroidManifest.xml`](AndroidManifest.xml) | The four `<meta-data>` declarations that make an APK a module, annotated — including which one changed meaning between frameworks | ~110 |

---

## Where these files live in a real project

```
my-module/
├── build.gradle.kts
│       dependencies {
│           compileOnly("de.robv.android.xposed:api:82")   // NEVER implementation
│       }
└── src/main/
    ├── AndroidManifest.xml                      <- AndroidManifest.xml
    ├── assets/
    │   └── xposed_init                          <- xposed_init
    └── java/com/pentest/ch64/
        ├── module/ClassicXposedModule.java      <- ClassicXposedModule.java
        └── detector/XposedDetector.java         <- XposedDetector.java
```

Two of those four rows are load-bearing in a way that is easy to get wrong:

- **`assets/xposed_init`** must be under `assets/`, not `res/raw/` and not the project root. The
  framework opens it by that exact path.
- **`compileOnly`, never `implementation`.** The framework supplies `de.robv.android.xposed.*` at
  runtime. A module that packages its own copy ends up with its code calling *its own*
  `XposedBridge` — a different class from the one the framework loaded — so every hook installs into
  nothing. The module loads cleanly, logs nothing, hooks nothing, and **no stage of the build or the
  load reports a problem.** See the chapter README §3.7.

> **Note — the detector does not belong in a module.** `XposedDetector.java` is placed here because it
> is *this chapter's subject*, not because a module would ship it. In a real project that class lives
> in the **application being defended**, not in the module doing the hooking. They are put in one
> directory so that a single build produces both, and so §6.2's point — that a `de.robv` string can
> mean "this is a module" **or** "this is looking for modules" — can be demonstrated in one DEX.

---

## Building, without Gradle or a network

```bash
# from 64-Xposed/
./scripts/build-classic-module.sh --with-detector --disassemble --keep \
    --ground-truth /tmp/ch64-ground-truth.txt
```

The script builds **out of tree** — `.class`, `.jar` and `.dex` are on this repository's artefact
blocklist, and it refuses to build inside the repo even if you ask it to. If you do not have the real
`de.robv.android.xposed:api:82` jar it synthesises a **source-compatible stub**, compiles against
that, and then **excludes the stub from the DEX** — which is mechanically exactly what `compileOnly`
does.

Measured on the host described in the chapter README §7.1 (JDK 24, build-tools 35.0.1, `--min-api 21`):

```
[*] compiling 12 source files
[+] compiled: 21 class files
[*] dexing 4 class files (17 API classes excluded, as compileOnly would)
[+] classes.dex: 10940 bytes
    (10 distinct types)
```

**21 classes compiled, 4 dexed.** The shipped DEX **references** ten `de.robv.android.xposed` types
and **defines** none of them. On an ordinary Android app that is a broken build; on a module it is
the defining structural property of the format.

---

## What the built DEX proves

Three things, each of which is an argument in the chapter made checkable:

**1. The API is alive.** Source written for a framework that stopped being supported at API 27
compiles and dexes with a 2026 toolchain, unchanged. That is chapter §1.6's second reason, measured.

**2. A module cannot hide what it hooks.** From the same DEX:

```
com.pentest.ch64.vault
com.pentest.ch64.vault.RootCheck
com.pentest.ch64.vault.VaultGate
```

Class and method names are string constants because reflection is string-based. Obfuscating the
module does not touch them — they name somebody else's classes.

**3. A detector cannot hide what it looks for.** Also from the same DEX:

```
/proc/self/maps
/system/bin/app_process
/system/framework/XposedBridge.jar
/system/lib/libxposed_art.so
/system/lib/libxposed_dalvik.so
/system/lib64/libxposed_art.so
/system/xposed.prop
```

That is the classic-Xposed artefact set reproduced verbatim in an application's constant pool, and it
is the pattern [`../scripts/xposed-detection-scan.py`](../scripts/xposed-detection-scan.py) keys on
when sweeping real APKs. Every one of those paths was measured `ENOENT` **to root** on a current
device — chapter README §7.2.

---

## Using these as a positive control

A detector validated only against clean samples has not been validated. The chapter's corpus sweep
found **zero** genuine Xposed-detection code across 237 real APKs, which is a fine negative result and
proves nothing about whether the scanner *can* find anything. These files are the positive control:

```bash
# host — wrap the built DEX in a minimal zip and scan it
./scripts/build-classic-module.sh --with-detector --keep --out /tmp/ch64-build
python3 -B - <<'PY'
import zipfile
z = zipfile.ZipFile('/tmp/ch64-fixture.apk', 'w')
z.write('/tmp/ch64-build/dex/classes.dex', 'classes.dex', zipfile.ZIP_STORED)
z.close()
PY
python3 -B scripts/xposed-detection-scan.py /tmp/ch64-fixture.apk --verbose
```

Expected: **STRONG**, with twelve or more distinct signatures firing, including `api.bridge.desc`,
`path.bridge.jar`, `path.libxposed`, `path.xposedprop`, `pkg.installer`, `pkg.lsposed`,
`pkg.edxposed` and `pkg.taichi`. If it reports anything less, the scanner has regressed.

[Lab 01](../labs/lab-01-the-detection-surface.md) walks this end to end and asks you to break the
scanner deliberately, so that you have seen both of its failure modes rather than only its successes.

---

## Ethics

Both `.java` files target `com.pentest.ch64.vault`, a lab application you build yourself in
[Lab 02](../labs/lab-02-read-a-classic-module.md). Nothing here targets software you do not own.
Where an example needs a network endpoint it uses the `.invalid` top-level domain, reserved by
RFC 2606, which can never resolve.

**Do not install classic Xposed to run any of this.** It cannot be installed on a modern device
without disabling Verified Boot, which is not reversible in practice. Chapter README §7.5 maps every
classic behaviour onto a modern reproduction using [63-LSPosed](../../63-LSPosed/README.md).
