# 04 — Java: References

Grouped, annotated sources for [04 — Java](../README.md). Every entry has one line stating what it is
and why you would open it. Where a resource is well known but the canonical URL is version-dependent
or unstable, the resource is named rather than linked, so that nothing here is invented.

---

## 1. Language and virtual machine specifications

These are the primary sources. When a tutorial and a specification disagree, the specification wins.

| Resource | Link | Why you open it |
|---|---|---|
| Java Language Specification, Java SE 21 | https://docs.oracle.com/javase/specs/jls/se21/html/index.html | The definitive answer on what a construct means, including the exact autoboxing and string-pool rules |
| Java Virtual Machine Specification, Java SE 21 | https://docs.oracle.com/javase/specs/jvms/se21/html/index.html | Class file format, constant pool, descriptors, verification, and the full stack-based opcode list |
| JVMS Chapter 4, The class file format | https://docs.oracle.com/javase/specs/jvms/se21/html/jvms-4.html | The table that defines `I`, `J`, `Z`, `[I`, `Ljava/lang/String;` and every other descriptor |
| JVMS Chapter 6, The instruction set | https://docs.oracle.com/javase/specs/jvms/se21/html/jvms-6.html | What `javap -c` output actually means, opcode by opcode |
| Java SE 21 API documentation | https://docs.oracle.com/en/java/javase/21/docs/api/index.html | Authoritative behaviour of `String`, `HashMap`, `Integer.valueOf`, and the reflection classes |
| Java Object Serialization Specification | https://docs.oracle.com/en/java/javase/21/docs/specs/serialization/index.html | The stream format, `serialVersionUID` computation, and exactly when `readObject` is called |
| Serialization filtering guide | https://docs.oracle.com/en/java/javase/21/core/serialization-filtering1.html | How to build the `ObjectInputFilter` allow-list that mitigates gadget chains |
| JEP 290, Filter Incoming Serialization Data | https://openjdk.org/jeps/290 | The design rationale for serialization filters, and the threat model in the JDK's own words |
| Secure Coding Guidelines for Java SE | https://www.oracle.com/java/technologies/javase/seccodeguide.html | Oracle's own list of Java-specific security anti-patterns, including mutable-state and serialization advice |
| OpenJDK project | https://openjdk.org/ | Source of the reference implementation, JEP index, and mailing-list archaeology |

---

## 2. Android runtime, DEX, and bytecode

| Resource | Link | Why you open it |
|---|---|---|
| Dalvik Executable format | https://source.android.com/docs/core/runtime/dex-format | The authoritative DEX layout, including the header offsets that `dump-strings.py` parses |
| Dalvik bytecode | https://source.android.com/docs/core/runtime/dalvik-bytecode | Every DEX opcode, which is the reference for reading Smali |
| Dalvik instruction formats | https://source.android.com/docs/core/runtime/instruction-formats | Why the same logical operation has `const/4`, `const/16`, `const`, and `const/high16` variants |
| Android Runtime overview | https://source.android.com/docs/core/runtime | How ART compiles, when AOT runs, and what a profile is |
| Configuring ART | https://source.android.com/docs/core/runtime/configure | `dex2oat`, compiler filters, and where the `.oat` and `.vdex` artefacts live |
| D8 documentation | https://developer.android.com/tools/d8 | The tool that turns `.class` into `.dex`, with its flags |
| R8 documentation | https://developer.android.com/tools/r8 | Shrinking, optimisation, and renaming — the source of `$$ExternalSyntheticLambda` names |
| Java 8+ API desugaring support | https://developer.android.com/studio/write/java8-support | Which modern Java features work on which `minSdk`, and how lambdas are desugared |
| Android developer reference | https://developer.android.com/reference/packages | The `android.*` API surface that does not exist on the desktop JVM |
| `android.os.Parcelable` reference | https://developer.android.com/reference/android/os/Parcelable | The `CREATOR` contract and the ordering requirement that makes `Parcelable` fragile |
| `java.io.Serializable` on Android | https://developer.android.com/reference/java/io/Serializable | Android's own documentation of the interface, and its recommendation to prefer explicit formats |
| Restrictions on non-SDK interfaces | https://developer.android.com/guide/app-compat/restrictions-non-sdk-interfaces | Why reflection into hidden APIs is blocklisted, and how apps try to get around it |
| Android API level reference | https://developer.android.com/guide/topics/manifest/uses-sdk-element | Mapping between API levels, versions, and the desugaring behaviour that follows |

---

## 3. AOSP source paths

Browse these at https://cs.android.com/ (fast search, cross-references) or clone from
https://android.googlesource.com/. The paths below are stable directory locations rather than line
numbers, because line numbers move between releases.

| Path | What lives there |
|---|---|
| `libcore/ojluni/src/main/java/java/lang/String.java` | Android's `String`, including `hashCode` caching and the `equals` implementation you should read before arguing about comparison |
| `libcore/ojluni/src/main/java/java/lang/Integer.java` | `IntegerCache`, the reason `Integer` identity comparison behaves differently above 127 |
| `libcore/ojluni/src/main/java/java/lang/Class.java` | `forName`, `getDeclaredMethod`, and `getDeclaredField` as Android implements them |
| `libcore/ojluni/src/main/java/java/lang/reflect/` | `Method`, `Field`, `Constructor`, and `AccessibleObject.setAccessible` |
| `libcore/ojluni/src/main/java/java/util/HashMap.java` | Bucket array, hash spreading, treeify thresholds, and resize logic |
| `libcore/ojluni/src/main/java/java/util/concurrent/ConcurrentHashMap.java` | The CAS and per-bin locking strategy |
| `libcore/ojluni/src/main/java/java/io/ObjectInputStream.java` | The deserialization entry point, including where `readObject` is invoked reflectively |
| `libcore/dalvik/src/main/java/dalvik/system/` | `DexClassLoader`, `PathClassLoader`, `InMemoryDexClassLoader`, `BaseDexClassLoader` |
| `art/runtime/` | The ART runtime core: class linker, interpreter, JNI bridge, and reflection support |
| `art/runtime/class_linker.cc` | How a class is loaded, verified, and initialised, which is where `<clinit>` is actually triggered |
| `art/runtime/native/java_lang_Class.cc` | The native implementation behind `Class.forName` and the reflection lookups |
| `art/dexdump/` | The `dexdump` tool source, useful as a second opinion on DEX parsing |
| `art/dex2oat/` | Ahead-of-time compilation from DEX to native code |
| `art/libdexfile/dex/dex_file.h` | The canonical C++ struct definitions for the DEX header and the `string_id_item` table |
| `dalvik/dx/` | The legacy `dx` converter, historically interesting and still the clearest small reference implementation of class-to-DEX translation |
| `frameworks/base/core/java/android/os/Parcel.java` | How `Parcelable` marshalling really works, including the type tags used by `Bundle` |
| `frameworks/base/core/java/android/os/BaseBundle.java` | Lazy unparcelling, which is the mechanism behind the historical `Bundle` mismatch bug class |
| `external/r8/` | The R8 and D8 source, if you want to know exactly why a synthetic class got the name it did |

---

## 4. OWASP MASVS and MASTG

The OWASP Mobile Application Security project is the reference framework this repository maps
findings to. MASVS states the requirement; MASTG states how to test it.

| Resource | Link | Note |
|---|---|---|
| OWASP MAS project home | https://mas.owasp.org/ | Entry point for MASVS, MASTG, MASWE, and the checklist |
| MASVS, the verification standard | https://mas.owasp.org/MASVS/ | The control list, grouped by category |
| MASTG, the testing guide | https://mas.owasp.org/MASTG/ | Test procedures, techniques, and tooling per control |
| MASTG test index | https://mas.owasp.org/MASTG/tests/ | Browse the current test IDs — they are versioned, so read them from here rather than from memory |
| MASWE, the weakness catalogue | https://mas.owasp.org/MASWE/ | Weakness-level identifiers that sit between a MASVS control and a MASTG test |
| MAS checklist | https://mas.owasp.org/checklists/ | The spreadsheet form used in real engagements |

### MASVS controls this chapter feeds

| Control | Statement (paraphrased) | Chapter 4 connection |
|---|---|---|
| `MASVS-STORAGE-1` | Sensitive data is stored securely | Hardcoded secrets in the DEX string table, secrets held in immutable `String` objects |
| `MASVS-STORAGE-2` | Sensitive data leakage is prevented | Passwords in logs, credentials surviving in the heap, serialized blobs written to disk |
| `MASVS-CRYPTO-1` | Current, strong cryptography is used correctly | Comparing password hashes with `equals` rather than a constant-time comparison |
| `MASVS-CODE-3` | Only components without known vulnerabilities are used | Deserialization gadget chains live in dependencies, not in your code |
| `MASVS-CODE-4` | All untrusted inputs are validated and sanitised | `ObjectInputStream` on attacker-influenced bytes, `Intent` extras, `Parcel` reads |
| `MASVS-PLATFORM-1` | IPC mechanisms are used securely | `Serializable` and `Parcelable` payloads crossing process boundaries |
| `MASVS-RESILIENCE-3` | The app implements anti-tampering and obfuscation appropriately | Why `private` and identifier renaming are cost, not control |

### Related MASTG topics to search for by name

Test identifiers change between MASTG releases, so search the test index above for these topic names
rather than quoting an ID from memory: testing for hardcoded and insecurely stored secrets; testing
for sensitive data in logs; testing object persistence and serialization; testing for insecure use of
reflection and dynamic code loading; testing whether debugging symbols and metadata are stripped;
testing obfuscation effectiveness.

### Related general OWASP material

| Resource | Link | Note |
|---|---|---|
| OWASP Deserialization Cheat Sheet | https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html | The concise version of the gadget-chain threat model and the allow-list mitigation |
| OWASP Cheat Sheet Series index | https://cheatsheetseries.owasp.org/ | Password storage, cryptographic storage, and logging cheat sheets all apply here |
| OWASP Mobile Top 10 | https://owasp.org/www-project-mobile-top-10/ | The older, coarser list still cited in many reports |

---

## 5. Tools

### Decompilers and disassemblers

| Tool | Link | One-line note |
|---|---|---|
| JADX | https://github.com/skylot/jadx | DEX and APK straight to readable Java, with a GUI, cross-references, and a deobfuscation mode |
| Apktool | https://apktool.org/ | Unpacks resources and produces Smali, and rebuilds a modified APK |
| Apktool source | https://github.com/iBotPeaches/Apktool | Issue tracker worth reading when a rebuild fails |
| smali and baksmali (Google fork) | https://github.com/google/smali | The maintained assembler and disassembler for DEX |
| smali and baksmali (original) | https://github.com/JesusFreke/smali | The original project, archived but the source of most documentation you will find |
| CFR | https://www.benf.org/other/cfr/ | JVM class decompiler that handles modern language features unusually well |
| Procyon | https://github.com/mstrobel/procyon | JVM class decompiler with strong generics and control-flow reconstruction |
| Fernflower | https://github.com/JetBrains/intellij-community | The analytical decompiler used inside IntelliJ IDEA, in `plugins/java-decompiler` |
| dex2jar | https://github.com/pxb1988/dex2jar | Converts DEX to a JAR so JVM-only decompilers can be used on Android code |
| Bytecode Viewer | https://github.com/Konloch/bytecode-viewer | Runs several decompilers side by side, which is the fastest way to spot a bad reconstruction |
| Recaf | https://github.com/Col-E/Recaf | Bytecode editor with a decompiler, useful for JVM-side experiments |
| ASM | https://asm.ow2.io/ | The bytecode manipulation library most instrumentation and obfuscation tooling is built on |

### Analysis and instrumentation

| Tool | Link | One-line note |
|---|---|---|
| Frida | https://frida.re/ | Dynamic instrumentation, the fastest way to confirm a reflective call statically inferred from Smali |
| Frida JavaScript API | https://frida.re/docs/javascript-api/ | The `Java.use`, `Java.perform`, and `Java.choose` calls used throughout this repository |
| Objection | https://github.com/sensepost/objection | Frida wrapper with ready-made Android commands |
| MobSF | https://github.com/MobSF/Mobile-Security-Framework-MobSF | Automated first pass that will find the obvious hardcoded strings for you |
| Ghidra | https://ghidra-sre.org/ | For the moment a Java app pushes logic into a native library |
| Android SDK command-line tools | https://developer.android.com/tools | Where `d8`, `apksigner`, `zipalign`, `aapt2`, and `adb` come from |

### Serialization-specific research tooling

| Tool | Link | One-line note |
|---|---|---|
| ysoserial | https://github.com/frohoff/ysoserial | The reference collection of Java deserialization gadget chains, for understanding the class rather than for use on targets you do not own |
| Marshalling Pickles (Frohoff and Lawrence) | Named resource — search for the AppSecCali 2015 talk title | The talk that made Java deserialization a mainstream finding |
| Java Deserialization Cheat Sheet (GrrrDog) | https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet | Community-maintained index of affected libraries and detection strings |

---

## 6. Books

| Title | Author | Why it is on this list |
|---|---|---|
| Effective Java, 3rd edition | Joshua Bloch | The `equals`/`hashCode` contract, `serialVersionUID`, and why serialization is a liability, from the person who wrote the collections framework |
| Java Concurrency in Practice | Brian Goetz and others | The `volatile` versus atomicity distinction, safe publication, and the memory model, explained correctly |
| Java Puzzlers | Joshua Bloch and Neal Gafter | A whole book of the `Integer` caching class of surprise, which is excellent training for reading hostile code |
| Android Security Internals | Nikolay Elenkov | Platform-level context for everything the Java layer sits on top of |
| The Android Hacker's Handbook | Drake, Lanier, Mulliner, Fora, Ridley, Wicherski | Older, but the DEX and runtime chapters remain a solid grounding |
| The Mobile Application Hacker's Handbook | Chell, Erasmus, Colley, Whitehouse | Methodology-oriented companion to MASTG |
| Practical Malware Analysis | Sikorski and Honig | Not Android-specific, but the static-then-dynamic workflow used in lab 3 comes from here |

---

## 7. Talks and long-form articles

Conference talk URLs rot quickly, so these are listed by title and speaker. Search the conference's
own archive or its YouTube channel.

| Talk | Venue | Topic |
|---|---|---|
| Marshalling Pickles, by Chris Frohoff and Gabriel Lawrence | AppSecCali 2015 | The origin of the modern Java deserialization gadget-chain understanding |
| The Anatomy of a DEX file, various speakers | Multiple Android security conferences | Walkthroughs of the same header fields `dump-strings.py` parses |
| Android obfuscation and deobfuscation sessions | Black Hat and DEF CON archives | What R8, commercial packers, and string encryption do to the artefacts described in this chapter |
| Google I/O sessions on R8 and D8 | Google I/O archive | First-party explanation of desugaring and synthetic class naming |

---

## 8. Cross-references inside this repository

| Chapter | Why it follows from here |
|---|---|
| [03 — Programming Fundamentals](../../03-Programming-Fundamentals/README.md) | The prerequisite: variables, control flow, functions, and what a compiler is |
| [05 — Kotlin](../../05-Kotlin/README.md) | The same bytecode from a different source language, with its own artefacts |
| [10 — APK Internals](../../10-APK-Internals/README.md) | What the container around `classes.dex` contains |
| [12 — DEX Internals](../../12-DEX-Internals/README.md) | The full DEX format, of which this chapter's string table is one table |
| [13 — ART](../../13-ART/README.md) | How the DEX you just read is actually executed |
| [40 — Obfuscation](../../40-Obfuscation/README.md) | What happens to every fingerprint in this chapter when someone tries to hide it |
| [41 — ProGuard](../../41-ProGuard/README.md) and [42 — R8](../../42-R8/README.md) | The specific tools that produce the renamed and synthetic identifiers |
| [53 — Frida](../../53-Frida/README.md) | Dynamic confirmation of anything you inferred statically here |
| [56 — JADX](../../56-JADX/README.md) | Getting the most out of the decompiler whose output this chapter teaches you to read |
| [71 — OWASP Mobile](../../71-OWASP-Mobile/README.md) | The full MASVS and MASTG mapping methodology |
