# 57 — Ghidra · Cheat Sheet

Printable. No prose. See [README.md](README.md) for why each of these works.

> **Provenance.** Ghidra **is** installed on the machine this chapter was written on (12.1.2 PUBLIC,
> Java 24.0.2) and was run headless against the chapter's own target — so the commands, menu paths
> and JNI offsets here are **✅ Measured** unless noted. What is **📘 Illustrative** is the *sample
> data* in the README's section 9: `libcrypto_helper.so`, `libsecure.so` and `libapi.so` do not
> exist, and **the 32-byte "AES key" in README §9.1 is invented, not recovered from any app.** Never
> quote it as a finding. Full statement: [README.md](README.md#-read-this-before-you-read-anything-else-what-is-measured-here-and-what-is-not).

---

## The first five minutes

```bash
# host — triage BEFORE opening any GUI
unzip -o -d raw app.apk 'lib/*'
file raw/lib/arm64-v8a/libnative.so
readelf -h raw/lib/arm64-v8a/libnative.so           # class, machine, type
readelf -d raw/lib/arm64-v8a/libnative.so | grep NEEDED
readelf --dyn-syms raw/lib/arm64-v8a/libnative.so | grep ' Java_'
readelf --dyn-syms raw/lib/arm64-v8a/libnative.so | grep 'JNI_OnLoad'
readelf --dyn-syms raw/lib/arm64-v8a/libnative.so | grep ' UND ' | awk '{print $8}'
strings -a -n 6 raw/lib/arm64-v8a/libnative.so | head -60
readelf -S raw/lib/arm64-v8a/libnative.so | grep -q '\.symtab' && echo "NOT stripped"
```

Or: `./scripts/so-triage.sh app.apk`

### The decision it makes for you

| `Java_*` exports | `JNI_OnLoad` | Means |
|---|---|---|
| > 0 | either | Static registration — read the exports |
| 0 | present | **Dynamic registration** — recover the table |
| 0 | absent | No Java surface; confirm the library is even loaded |

---

## Setup

```bash
# host — Ghidra needs a JDK matching the release's requirement
java -version
unzip ghidra_11.x_PUBLIC_*.zip -d /opt
/opt/ghidra_11.x_PUBLIC/ghidraRun
```

```properties
# ghidra/support/launch.properties — give the JVM room for large libraries
VMARGS=-Xmx8G
```

### Import options that matter

| Option | Set it to |
|---|---|
| Format | `Executable and Linking Format (ELF)` |
| Language | `AARCH64:LE:64:v8A` (arm64-v8a) · `ARM:LE:32:v8` (armeabi-v7a) · `x86:LE:64:default` |
| Image base | Leave at Ghidra's default (`0x100000` for a `.so`) |

### Auto-analysis options that matter

| Analyser | Why |
|---|---|
| **Decompiler Parameter ID** | Recovers parameter counts and types — leave ON, it is the biggest quality win |
| **Demangler GNU** | Turns `_ZN3foo3barEv` into `foo::bar()` — essential for C++ |
| **Aggressive Instruction Finder** | Finds code auto-analysis missed; also creates false functions. ON for stripped/packed, OFF otherwise |
| **Non-Returning Functions** | Stops control flow after `abort`/`exit` — improves graph accuracy |
| **Shared Return Calls** | Fixes tail-call misattribution |

---

## Keyboard

| Key | Action |
|---|---|
| `G` | Go to address or symbol |
| `L` | Rename label / function / variable |
| `F` | Edit function signature |
| `Ctrl+L` | Retype variable (Decompiler pane) |
| `;` | Set EOL comment |
| `Ctrl+;` | Set pre-comment |
| `Ctrl+Shift+F` | Find references TO here |
| `Ctrl+Shift+E` | Find references FROM here |
| `Ctrl+E` | Show Decompiler pane |
| `D` | Disassemble at cursor |
| `C` | Clear code/data |
| `T` | Set data type |
| `[` | Create array |
| `Ctrl+Alt+T` | Create structure from selection |
| `Alt+←` / `Alt+→` | Navigate back / forward |
| `Ctrl+Shift+G` | Graph function |
| `Space` | Toggle graph/listing |
| `Ctrl+Shift+D` | Diff view |
| `Ctrl+Shift+M` | Memory map |

---

## The JNIEnv problem — fix this FIRST

### Untyped

```c
(**(code **)(*(long *)param_1 + 0x548))(param_1,param_3,0);
```

### Typed

```c
(*env)->GetStringUTFChars(env,input,(jboolean *)0x0);
```

### Three routes

| Route | How | When |
|---|---|---|
| 1. Import `.gdt` | Data Type Manager → down-arrow → *Open File Archive…* → `jni_all.gdt` | Always, if you have it |
| 2. Parse `jni.h` | *File → Parse C Source…*, add NDK `jni.h`, save as `.gdt` | Version-exact types |
| 3. Declare by hand | Build `JNINativeInterface` with pointer fields | Once, to learn the layout |

### Apply it

```c
/* Right-click the function name in the Decompiler → Edit Function Signature (F) */
jstring Java_com_example_Crypto_decrypt(JNIEnv *env, jobject thiz, jstring input)
```

Or click `param_1` → `Ctrl+L` → `JNIEnv *`.

### Function table offsets (64-bit; index × 8) — ✅ Measured

> **✅ Measured** — `0x30` `FindClass`, `0xa8` `NewGlobalRef`, `0x108` `GetMethodID`, `0x538`
> `NewStringUTF`, `0x558` `GetArrayLength`, `0x5c0` `GetByteArrayElements` and `0x6b8`
> `RegisterNatives` were all read off real Ghidra 12.1.2 decompiler output for this chapter's own
> `libreference.so` (README §9.0). The rest follow from the same fixed JNI index × 8 rule.
> Watch `0x538` vs `0x548`: one slot apart, opposite directions of data flow.

| Function | Index | Offset | Why |
|---|---|---|---|
| `FindClass` | 6 | `0x30` | Which Java classes native code reaches |
| `GetMethodID` | 33 | `0x108` | Which Java method is about to be called |
| `GetStaticMethodID` | 113 | `0x388` | Same, static |
| `NewStringUTF` | 167 | `0x538` | Native producing a Java string |
| `GetStringUTFChars` | 169 | `0x548` | Native consuming a Java string |
| `ReleaseStringUTFChars` | 170 | `0x550` | Pairs with the above |
| `GetByteArrayElements` | 184 | `0x5c0` | Crypto input |
| `ReleaseByteArrayElements` | 192 | `0x600` | |
| `RegisterNatives` | 215 | **`0x6b8`** | **The dynamic table** |
| `UnregisterNatives` | 216 | `0x6c0` | |
| `GetJavaVM` | 219 | `0x6d8` | Library caching the VM for thread attach |

32-bit: index × 4. `RegisterNatives` = `0x35c`.

---

## JNI symbol mangling

```
Java_<package with . -> _>_<Class>_<method>[__<encoded arg signature>]
```

| Java character | Encoded |
|---|---|
| `.` | `_` |
| `_` | `_1` |
| `;` | `_2` |
| `[` | `_3` |
| `U+XXXX` | `_0XXXX` |

`com.example.Crypto.decrypt` → `Java_com_example_Crypto_decrypt`
`com.my_app.C.m` → `Java_com_my_1app_C_m`

---

## Type signatures

| Descriptor | Java type |
|---|---|
| `B` `C` `D` `F` `I` `J` `S` `Z` `V` | byte char double float int long short boolean void |
| `[B` | `byte[]` |
| `Ljava/lang/String;` | `String` |
| `[Ljava/lang/String;` | `String[]` |
| `(Ljava/lang/String;I)Z` | `boolean f(String, int)` |
| `([B)[B` | `byte[] f(byte[])` |

```c
/* JNINativeMethod — three pointers per entry */
typedef struct {
    const char *name;        /* "decrypt"                      */
    const char *signature;   /* "(Ljava/lang/String;)Ljava/..." */
    void       *fnPtr;       /* -> .text                        */
} JNINativeMethod;
```

### Recovering a dynamic table in the GUI

1. Find `JNI_OnLoad`, define `JNIEnv`.
2. Locate the call through `+0x6b8`; follow its **third** argument.
3. At the table address: define `JNINativeMethod`, then select `count × 24` bytes → `[` → array.
4. Rename each `fnPtr` target to its Java name.

Or run `scripts/RecoverRegisterNatives.py`. Or recover it at runtime with
[`../53-Frida/scripts/native-tracer.js`](../53-Frida/scripts/native-tracer.js) → `nat.table()`.

---

## Static ↔ dynamic address arithmetic

```
runtime_addr = module_base + (ghidra_addr - image_base)
ghidra_addr  = image_base  + (runtime_addr - module_base)
```

```bash
# adb shell — the runtime base
cat /proc/$(pidof com.example.app)/maps | grep libnative.so | head -1
```

```javascript
// Frida — the runtime base, plus a hook by Ghidra offset
const m = Process.findModuleByName("libnative.so");
console.log(m.base);
Interceptor.attach(m.base.add(0x3e40), {
  onEnter(args) { console.log("hit", args[0], args[1], args[2]); }
});
```

```javascript
// Frida — is this library even loaded?
Process.enumerateModules().forEach(m => console.log(m.base + "  " + m.name));
```

---

## Headless

```bash
# host — general form
$GHIDRA_HOME/support/analyzeHeadless <project-dir> <project-name> \
    -import lib/arm64-v8a/libnative.so \
    -processor AARCH64:LE:64:v8A \
    -scriptPath ./scripts \
    -postScript FindJNI.py \
    -analysisTimeoutPerFile 900 \
    -max-cpu 4 \
    -deleteProject
```

| Flag | Meaning |
|---|---|
| `-import <path>` | Add a binary (repeatable; accepts directories) |
| `-process '<glob>'` | Operate on already-imported programs |
| `-preScript` / `-postScript` | Run before / after auto-analysis |
| `-scriptPath` | Where your scripts live |
| `-noanalysis` | Import only |
| `-processor` | Force the language |
| `-loader ElfLoader` | Force the loader |
| `-analysisTimeoutPerFile <s>` | Cap per binary |
| `-max-cpu <n>` | Analyser threads |
| `-deleteProject` | Throw the project away afterwards |
| `-overwrite` | Replace an existing program |
| `-recursive` | Recurse into `-import` directories |
| `-readOnly` | Do not save changes |

### Scripts in this chapter

```bash
./scripts/so-triage.sh app.apk                      # CSV inventory, no Ghidra
GHIDRA_HOME=/opt/ghidra DEEP=1 ./scripts/so-triage.sh corpus/ out/

analyzeHeadless /tmp/p P -import lib.so -scriptPath ./scripts \
  -postScript FindJNI.py -deleteProject                 # JNI + risk inventory

analyzeHeadless /tmp/p P -import lib.so -scriptPath ./scripts \
  -postScript RecoverRegisterNatives.py -deleteProject  # dynamic table, renames

analyzeHeadless /tmp/p P -import lib.so -scriptPath ./scripts \
  -postScript DecompileMatching.py Java_ /tmp/out.c -deleteProject
```

---

## Scripting API (Jython)

```python
prog     = currentProgram
fm       = prog.getFunctionManager()
st       = prog.getSymbolTable()
listing  = prog.getListing()
mem      = prog.getMemory()

f = getFirstFunction()
while f is not None:
    print(f.getName(), f.getEntryPoint())
    f = getFunctionAfter(f)

getFunctionAt(addr) / getFunctionContaining(addr) / getFunctionBefore(f)
getSymbols("JNI_OnLoad", None)
getReferencesTo(addr) / getReferencesFrom(addr)
getDataAt(addr) / getBytes(addr, n) / getInt(addr)
toAddr(0x103a10)
createFunction(addr, name)
f.setName("jni_decrypt", SourceType.USER_DEFINED)
f.setComment("...")
getScriptArgs()
```

```python
# decompile one function
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
iface = DecompInterface(); iface.openProgram(currentProgram)
res = iface.decompileFunction(f, 120, ConsoleTaskMonitor())
if res.decompileCompleted():
    print(res.getDecompiledFunction().getC())
iface.dispose()
```

---

## Recognisable ARM64 patterns

| Decompiled shape | Usually is |
|---|---|
| `(**(code **)(*(long *)param_1 + 0x…))(...)` | A JNI call — define `JNIEnv` |
| `__stack_chk_fail` at the end | Stack protector; ignore it |
| `*(long *)(in_x28 + 0x28)` near entry and exit | Stack canary load/check |
| `if (iVar1 != 0) { ... }` after a `strcmp` | A string comparison; `0` means equal |
| `uVar1 = uVar1 * 0x1f + …` in a loop | A hash, often Java's `String.hashCode` idiom |
| `for (i…) buf[i] = buf[i] ^ k` | XOR "encryption" |
| `__android_log_print(4,"TAG","fmt",…)` | A narrated walkthrough of the algorithm |
| A `switch` on a variable reassigned each iteration | Control-flow flattening |
| Huge functions, no loops, endless `goto` | Obfuscator output |

---

## Common problems

| Symptom | Cause | Fix |
|---|---|---|
| Everything is `FUN_00…` | Stripped binary | Normal. Recover names from exports, strings, runtime |
| `undefined8` everywhere | No type info | Set the function signature; define `JNIEnv` |
| Decompilation is nonsense | Wrong types, wrong convention, or data-as-code | Read the disassembly first; fix the signature |
| Instructions look random | Wrong processor / ARM-vs-Thumb / wrong base | Re-import with the right language |
| No `Java_*` symbols | Dynamic registration | `RecoverRegisterNatives.py`, or hook `RegisterNatives` |
| Function not created at an address | Auto-analysis declined | `D` to disassemble, then *Create Function* |
| Decompiler times out | Enormous obfuscated function | Raise the timeout; read the graph instead |
| Analysis takes forever | Large library, small heap | `-Xmx8G` in `launch.properties` |
| Address does not match runtime | Ignored the base | `base + (ghidra - image_base)` |
| The `.so` behaves unlike the file | Packer decrypts at load | Dump from memory, load at the runtime base |

---

## When not to use Ghidra

| Question | Better tool |
|---|---|
| "What value does this produce for input X?" | [Frida](../53-Frida/README.md) — `NativeFunction` |
| "Which functions actually run when I press this?" | Frida `Stalker` coverage |
| "What syscalls does it make?" | `strace` |
| "What is in the Java layer?" | [JADX](../56-JADX/README.md) |
| "Quick look, over SSH, no JVM" | [radare2](../59-radare2/README.md) |
| "This function's decompilation is hopeless" | [IDA Pro](../58-IDA/README.md) — sometimes simply better |
| "Is this library even loaded?" | `adb shell cat /proc/<pid>/maps` |

---

## The static/dynamic loop

```
readelf/strings  ->  which library, which functions
     |
Ghidra           ->  hypothesis: "this computes an HMAC over the URL"
     |
Frida            ->  hook module+offset, print the arguments
     |
confirmed?  no ->  back to Ghidra with real values as ground truth
            yes -> write the finding, with BOTH kinds of evidence
```
