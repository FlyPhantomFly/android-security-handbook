# 63-LSPosed — `examples/`

Runnable module sources for [chapter 63](../README.md). Everything here targets
`com.pentest.ch63.vault`, the deliberately vulnerable lab application you build in
[Lab 02](../labs/lab-02-your-first-module.md), and nothing else.

> **⚠️ Ethics.** A module runs inside somebody's application, with that application's identity.
> Point these files, or anything derived from them, only at software you own or are explicitly
> authorised to test. Nothing in this repository defeats licensing, payment or anti-cheat controls in
> shipped third-party software.

---

## What is here

| File | What it is |
|---|---|
| [`VaultUnlockModule.java`](VaultUnlockModule.java) | **The flagship.** Both entry points, `findAndHookMethod`, `hookAllMethods`, before/after, `setResult`, `getObjectField`, and the observe-versus-modify discipline, in one heavily commented file |
| [`LateClassHookModule.java`](LateClassHookModule.java) | The class-loader problem solved: hooking a class that is defined later, by a loader the app builds itself |
| [`AndroidManifest.xml`](AndroidManifest.xml) | The four `<meta-data>` elements that make an APK a module, each annotated with what it does and how it is commonly got wrong |
| [`xposed_init`](xposed_init) | The entry-class list. One fully-qualified class name per line |

---

## How these flat files map onto a real Android project

This repository stores one directory of examples per chapter, flat. A real Android module project
puts the same content in a tree. **The paths in the left column are what an Android Gradle project
expects**; the right column is where the file lives here.

| In an Android project | Here |
|---|---|
| `app/src/main/java/com/pentest/ch63/module/VaultUnlockModule.java` | `VaultUnlockModule.java` |
| `app/src/main/java/com/pentest/ch63/module/LateClassHookModule.java` | `LateClassHookModule.java` |
| `app/src/main/AndroidManifest.xml` | `AndroidManifest.xml` |
| `app/src/main/assets/xposed_init` | `xposed_init` |

Nothing else is needed. A module has no Activity, no Service, no resources beyond an icon, and no
permissions — see the comments in `AndroidManifest.xml` for why the empty permission list is correct
rather than an omission.

---

## Building

### Offline, with no Gradle and no network

```bash
# from the chapter root
./scripts/build-xposed-module.sh --decompile --keep
```

That script generates a **source-compatible stub** of the `de.robv.android.xposed` API, compiles
these files against it, converts the result to DEX with `d8`, excludes the stub from the DEX exactly
as `compileOnly` would, and disassembles the result with `baksmali`. It proves the sources compile
and produces the listings chapter §6 quotes. It does **not** produce a runnable module — the stub's
methods have empty bodies.

Measured on the machine that wrote this chapter:

```
[*] compiling 13 source files
[+] compiled: 27 class files
[*] dexing 9 module class files (API classes excluded, as compileOnly would)
[+] classes.dex: 11272 bytes
```

### For real, with Gradle

```gradle
// app/build.gradle
android {
    namespace 'com.pentest.ch63.module'
    compileSdk 35
    defaultConfig {
        applicationId 'com.pentest.ch63.module'
        minSdk 27              // LSPosed's floor
        targetSdk 35
        versionCode 1
        versionName '1.0'
    }
}

dependencies {
    compileOnly 'de.robv.android.xposed:api:82'
}
```

> **⚠️ `compileOnly`, never `implementation`.** The framework supplies `de.robv.android.xposed.*` at
> runtime. A module that packages its own copy ends up with the module's code calling the *module's*
> `XposedBridge`, which is a different class from the one the framework loaded, and every hook is
> installed into nothing. The symptom is a module that loads cleanly, logs nothing and hooks nothing.
> Verify with `unzip -l module.apk | grep de/robv` — it must be **empty**.

And, if you minify:

```proguard
# The framework reads assets/xposed_init and resolves the class BY NAME, with no
# knowledge of any mapping file. Renaming the entry class breaks the module.
-keep class com.pentest.ch63.module.VaultUnlockModule { *; }
-keep class com.pentest.ch63.module.LateClassHookModule { *; }
-keep class * implements de.robv.android.xposed.IXposedMod { *; }
```

This is the structural leak chapter §6.4 names: **an obfuscated module must still publish its entry
class name in plaintext.** There is no configuration in which that stops being true.

---

## Running

1. Install the APK: `adb install -r module.apk`
2. Enable it in LSPosed's manager, and set its **scope to `com.pentest.ch63.vault` only**. Never
   `android` — see chapter §5.4 for why that entry is categorically different from the others.
3. `adb shell am force-stop com.pentest.ch63.vault`, then launch the app.
4. Read the output: LSPosed's own log for `XposedBridge.log` lines, and `adb logcat | grep CH63` for
   anything the module additionally sent to `android.util.Log`.

Step 3 is the one that is forgotten. **A module is loaded at process start.** Installing it,
enabling it, or changing its scope does nothing to a process that is already running, and Android
keeps app processes alive long after the user leaves the app.

---

## Reading these files in the order they were meant to be read

1. `AndroidManifest.xml` and `xposed_init` first — five minutes, and they explain what a module *is*.
2. `VaultUnlockModule.java` — read `initZygote` and `handleLoadPackage` for the timing difference
   (chapter §3.13), then the three `hook*` methods for the API surface.
3. `LateClassHookModule.java` — read it only after you have had a `ClassNotFoundError` on a class you
   could see in jadx. It will make much more sense with that experience behind you.

---

## Related

| | |
|---|---|
| [Chapter README](../README.md) | §3.6 for the API surface, §3.12 for packaging, §6 for what these compile to |
| [`../scripts/build-xposed-module.sh`](../scripts/build-xposed-module.sh) | Builds everything here, offline |
| [`../scripts/detect-xposed-module.py`](../scripts/detect-xposed-module.py) | Run it against your own build; it should report exactly what you declared |
| [Lab 02](../labs/lab-02-your-first-module.md) | Builds the target app these modules hook |
| [65-Hooking](../../65-Hooking/README.md) | What a hook physically is. These files are its hook type 1 |
| [13-ART](../../13-ART/README.md) | The `ArtMethod` field every one of these hooks ends up rewriting |
