# 56 — JADX · Cheat Sheet

Dense. Printable. Measured against **jadx 1.5.3**. Chapter: [README.md](README.md).

---

## Invocation

| Situation | Command |
|---|---|
| Normal install | `jadx -d out app.apk` |
| **Windows `jadx-gui`-only install** (the exe opens the GUI and blocks) | `java -cp "C:\Program Files\jadx\lib\jadx-gui-1.5.3-all.jar" jadx.cli.JadxCLI -d out app.apk` |
| Large app | `java -Xmx8g -cp jadx.jar jadx.cli.JadxCLI -j 4 --no-res --log-level error -d out app.apk` |
| GUI | `jadx-gui app.apk` |
| Version | `jadx --version` |
| Plugin list | `jadx plugins --help` |

## The ten-command first pass

```bash
file app.apk; unzip -l app.apk | head -30
sha256sum app.apk | tee provenance.txt
jadx -s -d out-res app.apk                                   # manifest + resources, seconds
unzip -l app.apk | grep -E "classes.*\.dex|\.so$"
jadx --no-res -j 4 --log-level error -d out app.apk          # the long one
find out/sources -name '*.java' | wc -l
grep -rho "Method not decompiled" out/sources | wc -l        # <-- BEFORE reading anything
grep -rho "JADX WARN: [A-Za-z' -]*" out/sources | sed 's/ *$//' | sort | uniq -c | sort -rn
find out/sources -name '*.java' | sed 's|out/sources/||; s|/[^/]*$||' | cut -d/ -f1-3 | sort | uniq -c | sort -rn | head
grep -rn "System.loadLibrary\|native " out/sources --include=*.java | head
```

---

## Flags

### Output

| Flag | Effect |
|---|---|
| `-d DIR` | Output directory |
| `-ds DIR` / `-dr DIR` | Sources / resources to separate dirs |
| `-r`, `--no-res` | Skip resource decoding (faster) |
| `-s`, `--no-src` | Skip code — manifest and resources only |
| `--single-class NAME` | Decompile exactly one class |
| `--single-class-output PATH` | Where that class goes |
| `--output-format java\|json` | JSON for machine consumption |
| `-e`, `--export-gradle` | Emit a Gradle project skeleton |
| `--export-gradle-type auto\|android-app\|android-library\|simple-java` | Template for `-e` |

### Decompilation behaviour

| Flag | Effect |
|---|---|
| `-m auto` | Default: restructure, fall back per method |
| `-m restructure` | Full region reconstruction, no per-method fallback |
| `-m simple` | **Never refuses.** Linear statements, labels, explicit `goto` |
| `-m fallback` | Near-disassembly. Registers, labels, catch ranges. Asserts almost nothing |
| `--show-bad-code` | Print known-incorrect reconstructions **instead of** the instruction dump |
| `--no-debug-info` | Ignore debug info even when present |
| `--add-debug-lines` | Emit `// line N` comments |
| `--no-inline-anonymous` | Keep anonymous classes as declarations |
| `--no-inline-methods` | Do not inline small methods into callers |
| `--no-move-inner-classes` | Inner classes as separate files |
| `--no-inline-kotlin-lambda` | Keep Kotlin lambdas as classes |
| `--no-finally` | Do not reconstruct `finally` |
| `--no-restore-switch-over-string` | Leave the two-stage string switch as compiled |
| `--no-replace-consts` | **Do not substitute constant field names for literals** |
| `--respect-bytecode-access-modifiers` | Do not widen modifiers |
| `--integer-format auto\|decimal\|hexadecimal` | Literal formatting |
| `--escape-unicode` | Non-Latin string chars as `\uXXXX` |

**Maximally literal rendering** (differences from the default are jadx's editorialising):

```bash
jadx --no-inline-methods --no-inline-anonymous --no-replace-consts \
     --no-restore-switch-over-string --no-finally -d out app.apk
```

### Naming

| Flag | Effect |
|---|---|
| `--deobf` | Unique, valid, greppable names. **Recovers nothing** |
| `--deobf-min N` | Rename identifiers shorter than N (default 3) |
| `--deobf-max N` | Rename identifiers longer than N (default 64) |
| `--deobf-whitelist "a.* b.*"` | Leave these alone |
| `--deobf-cfg-file FILE` | Persist aliases (`.jobf`) — **required for cross-version diffs** |
| `--deobf-cfg-file-mode read\|read-or-save\|overwrite\|ignore` | How to treat it |
| `--use-source-name-as-class-name-alias always\|if-better\|never` | **Recovers class names from `SourceFile`.** Always try |
| `--source-name-repeat-limit N` | Ignore a `SourceFile` name used more than N times (default 10) |
| `--rename-flags case,valid,printable\|all\|none` | Identifier legalisation (on by default) |
| `--mappings-path FILE` | Load Tiny / Tiny v2 / Enigma mappings |
| `--mappings-mode read\|read-and-autosave-every-change\|read-and-autosave-before-closing\|ignore` | |
| `--use-kotlin-methods-for-var-names disable\|apply\|apply-and-hide` | Name params from `Intrinsics` strings |
| `--fs-case-sensitive` | **Set on Linux; leave off on Windows/macOS** |

### Diagnostics

| Flag | Effect |
|---|---|
| `--comments-level error\|warn\|info\|debug\|user-only\|none` | Default `info` |
| `--log-level quiet\|progress\|error\|warn\|info\|debug` | Console verbosity |
| `-v` / `-q` | debug / quiet |
| `--cfg` / `--raw-cfg` | Per-method control-flow graphs as Graphviz `.dot` |
| `-j N`, `--threads-count N` | Threads. **Lower it** to cut peak memory |

### Plugin options (`-P`)

| Option | Use |
|---|---|
| `-Pdex-input.verify-checksum=no` | **Load a DEX whose header checksum is wrong** |
| `-Pjava-convert.mode=dx\|d8\|both` | How `.class`/`.jar` become DEX |
| `-Pjava-convert.d8-desugar=yes` | Desugar during conversion |
| `-Psmali-input.api-level=27` | API level for `.smali` assembly |
| `-Prename-mappings.format=PROGUARD_FILE` | **Read an R8/ProGuard `mapping.txt`** |
| `-Prename-mappings.invert=yes` | Invert mapping direction |
| `-Pkotlin-metadata.method-args=no` | Stop recovering Kotlin parameter names |
| `-Pkotlin-smap.class-alias-source-dbg=yes` | Class names from `SourceDebugExtension` |

### Environment

| Variable | Meaning |
|---|---|
| `JADX_DISABLE_ZIP_SECURITY=true` | Disable zip traversal / bomb / entry-count checks. **Disposable VM only** |
| `JADX_ZIP_MAX_ENTRIES_COUNT` | Entry cap (default 100000) |
| `JADX_DISABLE_XML_SECURITY=true` | Disable XXE protection. **Disposable VM only** |
| `JADX_CONFIG_DIR`, `JADX_CACHE_DIR`, `JADX_TMP_DIR` | Relocate jadx's state |

---

## Input formats

`.apk` `.dex` `.jar` `.class` `.smali` `.zip` `.aar` `.arsc` `.aab` `.xapk` `.apkm` `.jadx.kts`

**`.smali` input assembles Smali into DEX and decompiles it** — the fastest way to test what jadx
does with a specific instruction shape, with no other tooling.

---

## Search

### jadx-gui

| Key | Action |
|---|---|
| Ctrl+Shift+F | Global search (Class / Method / Field / Code) |
| Ctrl+N | Search classes by name |
| Ctrl+Shift+N | Search by resource / file name |
| Ctrl+F | Search inside the open class |
| Ctrl+Click, F4 | Jump to declaration |
| Alt+Left / Alt+Right | Back / forward |
| **Right-click → Find Usage** | **Cross-references — the thing `grep` cannot do** |
| F2 | Rename (persist with `--mappings-mode`) |
| Ctrl+Shift+E | Show the class's bytecode |

### Command line

```bash
APP=out/sources/com/example/app          # ALWAYS scope first: the app is ~10% of the tree

# secrets
grep -rnE "(?i)(api[_-]?key|secret|password|token|bearer)\s*=\s*\"" "$APP" --include=*.java
grep -rnE "AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|sk_(live|test)_[0-9a-zA-Z]{24,}|gh[pousr]_[0-9A-Za-z]{36}" out/sources
grep -rn -- "-----BEGIN" out/sources

# network
grep -rnE "https?://[^\"'<> ]+" "$APP" --include=*.java | sort -u
grep -rn "setHostnameVerifier\|checkServerTrusted\|CertificatePinner\|sslSocketFactory" out/sources
grep -rn "onReceivedSslError" out/sources          # + handler.proceed() = full TLS bypass

# crypto
grep -rn "Cipher.getInstance\|MessageDigest.getInstance\|SecretKeySpec\|IvParameterSpec" out/sources
grep -rnE "\"(AES|DES|DESede|RSA|Blowfish)(/[A-Za-z0-9]+){0,2}\"" out/sources
grep -rn "AndroidKeyStore\|KeyGenParameterSpec" out/sources

# storage and logging
grep -rn "getSharedPreferences\|getExternalFilesDir\|MODE_WORLD_" out/sources
grep -rnE "Log\.[vdiwe]\(.*(token|password|key|secret|pin)" out/sources

# webview
grep -rn "setJavaScriptEnabled(true)\|addJavascriptInterface\|setAllowUniversalAccessFromFileURLs" out/sources

# ipc
grep -rn "extends ContentProvider\|public Cursor query\|onReceive(\|getStringExtra\|FLAG_MUTABLE" out/sources

# anti-analysis
grep -rn "/system/xbin/su\|Superuser.apk\|magisk\|test-keys\|isDebuggerConnected\|GET_SIGNING_CERTIFICATES" out/sources

# native + dynamic
grep -rn "native \|System.loadLibrary\|System.load(" out/sources --include=*.java
grep -rn "DexClassLoader\|InMemoryDexClassLoader\|Class.forName\|getDeclaredMethod" out/sources
```

**Framework contracts cannot be obfuscated** — the runtime resolves them by name. Best foothold in an
obfuscated app:

```bash
grep -rn "onCreate(Bundle\|public Cursor query\|onReceive(\|shouldOverrideUrlLoading\|checkServerTrusted\|doInBackground" "$APP"
```

---

## Failure census

```bash
grep -rho "Method not decompiled" out/sources | wc -l                    # refused methods
grep -rl  "Method not decompiled" out/sources | wc -l                    # files affected
grep -rl  "Method not decompiled" out/sources | sed 's|out/sources/||; s|/[^/]*$||' \
  | cut -d/ -f1-3 | sort | uniq -c | sort -rn                            # WHERE (the diagnosis)
grep -rho "JADX WARN: [A-Za-z' -]*" out/sources | sed 's/ *$//' | sort | uniq -c | sort -rn
grep -rl  "Removed duplicated region" out/sources | wc -l                # missing control flow
```

> **jadx's console error count is NOT its failure count.** Measured on a 17.5 MB app: console said
> `finished with errors, count: 61`; the tree contained **2,104** refused methods in **1,424** files.

### Reference numbers — `com.vendor.hrapp`, 17.5 MB, jadx 1.5.3, `--no-res`, 8 threads

| | |
|---|---|
| Wall time | 148 s |
| Java files | 20,091 |
| Lines | 1,829,607 |
| Refused methods | 2,104 |
| Files with a refusal | 1,424 (7.1%) |
| App's own package | 2,211 files (**11%** of the tree) |
| `Removed duplicated region for block` | 9,102 |
| `Intrinsics.checkNotNullParameter` | **3** (R8 strips them in release builds) |

---

## Comment reference

| Comment | Meaning |
|---|---|
| `/* loaded from: classes3.dex */` | Which DEX; late DEX often means dynamic loading |
| `/* renamed from: a.b.c */` | `--deobf` or a mapping renamed it |
| `/* synthetic */` | Compiler-generated member |
| `/* bridge */` | Generics erasure or covariant return |
| `// from class: Foo.1` | Anonymous class inlined at its use site |
| `JADX INFO: Access modifiers changed from: private` | jadx widened a modifier |
| `JADX INFO: Thrown type has an unknown type hierarchy` | Exception class not in the input |
| `JADX WARN: Type inference failed for: rNvM` | The declared type is a **guess** |
| `JADX WARN: Removed duplicated region for block` | **A control-flow path is MISSING from the Java** |
| `JADX WARN: Code restructure failed ... code lost:` | Named code is absent; the comment prints it |
| `JADX WARN: 'super' call moved to the top of the method` | **Code was REORDERED** |
| `JADX WARN: Unsupported multi-entry loop pattern` | Irreducible control flow |
| `JADX WARN: Can't fix incorrect switch cases order` | Switch reconstruction gave up |
| `Code decompiled incorrectly, refer to instructions dump` | The body below is **known wrong** |
| `throw new UnsupportedOperationException("Method not decompiled")` | Total refusal |

---

## Decompiler artefact → what it really was

| You see | It really was | Author |
|---|---|---|
| `str`, `str2`, `i2`, `z`, `cArr`, `bArr`, `iArr` | Names that were never in the file | jadx `NameGen` |
| `iMin`, `iMax`, `string`, `substring` | A value named after the method that produced it | jadx `NameGen` |
| `unused` as a catch parameter | An exception the code never references | jadx |
| `a`, `b`, `c`, `p001a.b.c` | R8's renaming | R8 |
| `C0000a`, `f0a`, `m0a` | R8's names made unique by jadx | jadx `--deobf` |
| `f0a` with `reason: collision with root package name` | jadx legalising an identifier **without any flag** | jadx `--rename-flags` |
| `this$0` | Synthetic outer-instance field | `javac` |
| `val$tags` | Synthetic capture field of an anonymous class | `javac` |
| `access$000` | Synthetic accessor for a private outer member | `javac` |
| `$$ExternalSyntheticLambda0`, `$r8$lambda$` | A lambda desugared into a class | `d8`/R8 |
| `lambda$onCreate$0` | A lambda body lifted into a synthetic method | `javac` |
| name ending `$app_release` | A Kotlin `internal` declaration, mangled | `kotlinc` |
| `new HashMap()` raw, but `Map<String,List<String>>` on the field | Erasure: `new` never carried a signature; the declaration did | `javac` |
| `i != 10` where the source said `!= '\n'` | A `char` literal resolved to `int` | jadx `TypeInferenceVisitor` |
| `char c = 65535;` | A synthesised `-1` index typed as `char` | jadx inference |
| `(char) i` casts from nowhere | The bytecode's `int-to-char` | `javac` |
| `MAX_ATTEMPTS` where the bytecode has `3` | jadx matched a literal to a constant field — **a guess** | jadx `ConstInlineVisitor` |
| `Intent.FLAG_ACTIVITY_NEW_TASK` for `268435456` | Framework constant recognised | jadx `AddAndroidConstants` |
| An inlined URL where the source used a named constant | `javac` inlined a compile-time constant | `javac` |
| `str.hashCode();` orphan before `switch (str)` | **Really in the bytecode** — `javac`'s implicit null check | `javac` |
| `switch (str)` with cases in odd order | Two-stage hash switch, folded; order is **hash order** | `javac` + jadx |
| `try`/`catch (Throwable th)` + `addSuppressed` | `try`-with-resources, desugared | `javac` |
| `while (true) { ... break; }` where the source had `for` | Loop kind is not recoverable from jumps | `javac` + jadx |
| `while (true) { switch (i) }` with a state variable | **Control-flow flattening** — [40](../40-Obfuscation/README.md) | an obfuscator |
| A `finally` body duplicated or absent | `javac` duplicates it; jadx tries to re-merge | `javac` + jadx |
| `new Runnable(this) { final synthetic Outer this$0; ... }` | Reality of the generated class. **Does not compile** | `javac` + jadx |
| `1.$SwitchMap$Foo` (starts with a digit) | The synthetic `Outer$1` enum-switch-map class | `javac` + jadx |
| Members in alphabetical order | No debug info → DEX order | `d8` + jadx |
| `values()`/`valueOf()` + `$VALUES` | An `enum` | `javac` |
| `public native int b();` | A `native` method → [16-JNI](../16-JNI/README.md), [57](../57-Ghidra/README.md) | source |

Kotlin artefacts: [05-Kotlin §6.1](../05-Kotlin/README.md#61-the-master-fingerprint-table).

---

## Drop to Smali when…

| Symptom | Why |
|---|---|
| `Method not decompiled` | There is no Java |
| `Code decompiled incorrectly` | jadx says the body is wrong |
| `Code restructure failed` / `code lost` | Named code is missing |
| `Removed duplicated region for block` | A control-flow path is missing |
| `Unsupported multi-entry loop pattern` | Irreducible control flow |
| `'super' call moved to the top` | Code was reordered |
| `Type inference failed` | A declared type is a guess |
| `while(true) switch(i)` | Correct but useless — read the graph, not the text |
| A folded expression inside a `try` starting with a constant | Possible lost partial state |
| Exception ordering matters to your claim | Folding erases intermediate states |
| You need an exact descriptor | Overload resolution |
| **You are about to patch anything** | jadx output does not recompile |
| **The claim will be disputed** | Indicative evidence is not proof |

Destination: [14 — Dalvik](../14-Dalvik/README.md). Arrive with one of these questions:
1. Which registers hold what, here?
2. Where do the `try` ranges start and end, and what is live at the handler?
3. What is the exact order of the `invoke` instructions?
4. What is the true method descriptor?

---

## Escalation ladder

| Step | Command | Trust |
|---|---|---|
| 1 | `jadx -d out app.apk` | Readable, sometimes wrong |
| 2 | `jadx -m simple` | Always produces output; no structure asserted |
| 3 | `jadx -m fallback` | Near-disassembly; control flow faithful |
| 4 | `apktool d` / `baksmali d` | Real Smali. Required for patching |
| 5 | `dexdump -d` | Offsets and encodings. Arguments end here |

One command for all five: [`scripts/jadx-vs-smali.sh`](scripts/jadx-vs-smali.sh).

---

## jadx → Frida

| jadx shows | Frida overload string |
|---|---|
| `String` | `'java.lang.String'` (fully qualified) |
| `byte[]` | `'[B'` |
| `String[]` | `'[Ljava.lang.String;'` |
| `int` `boolean` `long` `char` | `'int'` `'boolean'` `'long'` `'char'` |
| `Map<String,String>` | `'java.util.Map'` (**never include generics**) |
| `Outer.Inner` | `'com.example.Outer$Inner'` |
| a `private` method | Hookable identically |

```javascript
Java.use('com.example.Crypto').encrypt.overloads.forEach(function (o) {
    console.log(o.argumentTypes.map(function (t) { return t.className; }).join(', '));
});
```

**A `--deobf` alias (`C0000a`) is not a real class name.** The real one is in the
`/* renamed from: */` comment.

---

## Version and reproducibility

- Record the **jadx version** with every extract you quote. Output changes between versions.
- Diffing two app versions: same jadx version, same flags, **shared `--deobf-cfg-file`**, or the
  diff is pure noise.
- Provenance for any artefact you will be asked about: APK SHA-256, jadx version, exact command,
  timestamp.

## Chapter scripts

| Script | Does |
|---|---|
| [`scripts/jadx-triage.py`](scripts/jadx-triage.py) | Decompile, census failures, rank classes, grep catalogue, JSON out |
| [`scripts/jadx-vs-smali.sh`](scripts/jadx-vs-smali.sh) | One method through all five renderings |
| [`scripts/jadx-blindspot.js`](scripts/jadx-blindspot.js) | Frida: observe a class jadx could not decompile |
