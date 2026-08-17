# 17 — Libraries · FAQ

Real questions, answered directly. Including the ones people are embarrassed to ask.

---

**1. How do I even tell what libraries are in an APK? I open it and I see a zip.**

You look in six places, and most people look in two. In rough order of effort:

| Where | What is there | One command |
|---|---|---|
| `lib/<abi>/*.so` | Native libraries the app shipped | `unzip -l app.apk \| grep '\.so$'` |
| `META-INF/*.version` | Literal version numbers, written by the build | `unzip -l app.apk \| grep '\.version$'` |
| `classes*.dex` | Every Java/Kotlin library, merged into the app's own code | `python3 scripts/lib-fingerprint.py app.apk --list-prefixes 3` |
| `AndroidManifest.xml` | Providers, permissions and `meta-data` each SDK contributed | `apktool d app.apk -o work && grep -oE '<provider[^>]*>' work/AndroidManifest.xml` |
| `assets/`, `res/raw/` | More code: extra DEX, JS bundles, `.so` files, Lua, models | `unzip -l app.apk \| grep -E 'assets/.*\.(dex\|so\|jar\|bundle)$'` |
| `/proc/<pid>/maps` at runtime | What is *actually* loaded, including things not in the APK at all | `adb shell grep '\.so' /proc/$(adb shell pidof -s pkg)/maps` |

Or run [`scripts/lib-inventory.sh`](scripts/lib-inventory.sh), which does all six and tells you which
tool produced each answer. Do it by hand once first — [lab 01](labs/lab-01-library-inventory.md)
walks it — because the script cannot teach you which of the six you are in the habit of skipping.

The Java/Kotlin one is the surprise for most people. There is no `lib/` folder for them. Every
dependency is compiled into the same `classes.dex` as the app's own code, with no boundary of any
kind. That is why "package prefix" is the unit of analysis on the managed side.

---

**2. Why can't I just read `build.gradle`?**

If you have it, read it — [chapter §8.3](README.md#8-static-analysis) shows what to run, and
`./gradlew :app:dependencies` will produce a transitive tree that surprises the team that wrote the
app.

But you often will not have it, and even when you do it does not answer the question you actually
have. The build file says what the developer *asked for*. It does not say:

- what R8 kept (a declared dependency may be almost entirely absent from the shipped APK);
- what a native `.so` statically linked into itself (OpenSSL, zlib, SQLite, curl — none of it appears
  in any Gradle file, ever);
- what an SDK shaded and rebadged inside itself;
- what the app downloads and loads after installation.

[Chapter §3.6](README.md#3-deep-internal-working) puts it as: mobile needs **two** inventories, one
of what the build intended and one of what the artifact contains, and the interesting findings live
in the gap.

---

**3. Why does the same library appear under three different names?**

Because four different things can happen to a name, and they are not the same thing:

| Situation | What you see | Is it the same library? |
|---|---|---|
| **Major-version rename** | `com.squareup.okhttp` and `okhttp3`; `com.appboy` and `com.braze`; `coil` and `coil3` | Same project, different major. The rename exists so both can be in one app |
| **Shading / relocation** | `com.vendor.internal.okhttp3.OkHttpClient` | Yes — byte-identical code, moved to a different package by the vendor that embedded it |
| **A fork** | `org.spongycastle` versus `org.bouncycastle` | Same codebase, repackaged to avoid clashing with the platform's copy |
| **Two genuinely separate copies** | `okhttp3` *and* `com.vendor.internal.okhttp3` in the same APK | No — two copies, possibly at two different versions, both shipping |

That last row is common and worth reporting on its own. An app can carry three protobuf runtimes at
three versions because three SDKs each shaded their own. Patching one does nothing to the others.

`lib-fingerprint.py` reports relocated copies specifically, because a prefix search for the original
package will never find them.

---

**4. Is a shaded library still that library?**

**Yes, for every purpose that matters to you.**

Shading (Gradle's `shadow` plugin, Maven Shade, R8's repackaging) rewrites the package names of a
dependency and its references so it can be embedded without clashing. The bytecode is otherwise the
same bytecode. If the original version had a parsing bug, the shaded copy has the same parsing bug.

Three practical consequences:

1. **Your scanner will not find it.** Every dependency scanner keys on coordinates or package names.
   A relocated copy matches nothing.
2. **Patching the original does not patch it.** The shaded copy is updated only when the vendor that
   shaded it ships a new build. You are now depending on a third party's release cadence for a fix in
   a library they did not write.
3. **You must report it by structure, not by name.** "A relocated copy of library X, at approximately
   version Y, is embedded in SDK Z under package P" — with the class-set comparison as the evidence.

One caveat to be honest about: shading is sometimes accompanied by *modification* — a backported fix,
a removed feature, a patched behaviour. So "the same library" is a strong prior, not a certainty. If
severity hinges on it, diff the shaded class set against the real release rather than assuming.

---

**5. The `META-INF` version says one thing and the code says another. Which is right?**

Neither, automatically. You have two claims and no adjudicator, so get a third observation.

The stamp is a **plain text file inside a zip**. It is written by the build, it can be stale, it can
be copied forward, it can come from an AAR that was built against a different version, and anyone who
can repackage the APK can edit it in ten seconds.

The code is harder to forge but harder to read. A version string in the DEX is also just a string; a
*class set* is hundreds of files that would all have to be edited consistently.

So: rank the signals by **how expensive they would be to fake**, not by how much you like them.

```text
cheap to fake  ->  a version string, a META-INF stamp, a .so filename, a package name
                   a JNI symbol name, a log tag
expensive      ->  a class set matching a published release
                   an ELF build ID matching the vendor's published artifact
                   a symbol set consistent with a specific upstream era
```

And when they disagree, **the disagreement is the finding**. Two conflicting versions usually means
two bundled copies, a stale artefact, or a deliberate lie, and every one of those is worth more in a
report than the number you were originally after.
[Lab 02](labs/lab-02-version-fingerprint.md) plants a conflicting stamp for exactly this reason.

---

**6. Is an outdated library automatically a finding?**

**No.** This is the most important answer on this page, and the one most often got wrong in both
directions.

A version number tells you a component *might* contain a known defect. It does not tell you:

- whether the vulnerable code is even in the APK — R8 removes classes the app never calls, and the
  vulnerable method is frequently among them;
- whether anything can reach it — a vulnerable image decoder in a library the app only uses to parse
  its own bundled assets is not exposed to attacker-chosen input;
- whether the vulnerable feature is compiled in at all — an FFmpeg build with the affected demuxer
  disabled is not affected, and the configure line is right there in `.rodata`;
- whether the platform, not the library, handles the dangerous input;
- whether the specific CVE was ever applicable to Android — many are Windows-only, server-only, or
  depend on a configuration Android does not have.

**What makes it a finding is reachability plus consequence.** The chapter's rubric
([§8.1 Phase 4](README.md#8-static-analysis)) scores exactly that, and
[§7.4](README.md#7-dynamic-analysis) shows the method: hook the vulnerable function, drive the app,
and see whether it ever fires.

Three ways to write it, in ascending order of professional value:

> *Wrong:* "The app uses library X 1.2.3, which is affected by CVE-XXXX-YYYY. Critical."

> *Honest:* "The app bundles library X 1.2.3, which is affected by CVE-XXXX-YYYY. **Reachability was
> not confirmed.** Medium."

> *Best:* "The app bundles library X 1.2.3. The affected function is present, and it is reached when
> the app parses a server-supplied response on the profile screen — hooked and confirmed at 14:02,
> backtrace in appendix B. High."

The honest version is completely acceptable and takes zero extra work. The wrong version costs you
credibility on every *other* finding in the report.

And the opposite error is real too: never write off an outdated library merely because you did not
find the path. "I could not reach it in the time available" is a different sentence from "it is not
reachable", and only one of them is true.

---

**7. My dependency scanner reported 200 issues. How many are real?**

On Android, fewer than you would like — and the reasons are structural rather than the tools being
bad:

| Cause of false positives | Why it happens on Android specifically |
|---|---|
| Reachability is ignored | The scanner matches a coordinate, not a call graph. R8 has already removed a lot of what it matched |
| Server-side CVEs | A huge share of advisories for libraries like Jackson, Netty and Log4j-family projects describe conditions (JNDI, deserialisation gadgets, servlet containers) that have no analogue in an app |
| Platform substitution | Advisories against a bundled component when Android supplies its own, patched version |
| Version-matching failures | Android artifacts have coordinates and qualifiers that confuse matchers; AAR versus JAR; `-android` variants |
| Nothing sees native static linking | The opposite error: a whole class of real issues that scanners **miss entirely**, because `libcore.so` statically links OpenSSL and no Gradle file mentions it |

OSV and the NVD are good databases and you should use them — [`references/README.md`](references/README.md)
says when to reach for each. Use them to *generate leads*. Then confirm each lead by hand: is the
class present, is the function present, is it reachable, does the affected feature exist in this
build?

The last row of that table is the one to remember. Scanner noise is annoying; scanner *silence* is
dangerous, and on mobile the silence is about native code.

---

**8. What is the difference between a `.so`, a `.jar`, an `.aar` and a `.dex`?**

| Thing | What it is | Where it ends up in an APK |
|---|---|---|
| `.so` | A compiled native shared library (ELF), machine code for one ABI | `lib/<abi>/name.so` |
| `.jar` | A zip of `.class` files: JVM bytecode, plus resources | Nowhere. It is an *input*; its classes are compiled into DEX |
| `.aar` | A zip containing a `classes.jar` **plus** Android resources, a manifest fragment, ProGuard rules, and optionally `.so` files | Nowhere directly. Its parts are merged into the app's DEX, resources, and manifest |
| `.dex` | Dalvik Executable: the bytecode format ART runs | `classes.dex`, `classes2.dex`, … at the archive root |

The consequence people miss: **the AAR's manifest fragment is merged into the app's manifest.** That
is how an SDK adds permissions and components the developer never wrote, and it is why
[chapter §8.1 Phase 3](README.md#8-static-analysis) makes you diff the manifest.

The format details are [12-DEX-Internals](../12-DEX-Internals/README.md) for DEX and
[10-APK-Internals](../10-APK-Internals/README.md) for the container.

---

**9. There is no `lib/` folder. Does that mean no native code?**

No, and this is a genuinely common way to produce a wrong report. Four other possibilities:

1. **You have `base.apk` from a bundle build.** The native libraries are in
   `split_config.arm64_v8a.apk`. Pull every path `adb shell pm path <pkg>` returns.
2. **The code is in `assets/`** and extracted or `System.load()`ed at runtime.
3. **A dynamic feature module** is downloaded after install.
4. **The app is a cross-platform framework app** and its native runtime is in a split.

Confirm at runtime rather than arguing about it: `grep '\.so' /proc/<pid>/maps` shows you the truth
in one command.

---

**10. Is a `.so` in `lib/` always loaded?**

No. Apps ship libraries for code paths that never run, for ABIs the device does not use, and for
features that were removed but whose dependency was not.

[Chapter §11](README.md#11-common-mistakes) lists "assuming a `.so` present in `lib/` is loaded" as a
reverse engineer mistake. The correct move is the maps sweep, and the correct thing to write when a
library never loads is that it is inventory rather than a finding.

Same rule on the managed side: a class in the DEX is not a class that runs. `android hooking list
classes` in Objection shows what is actually loaded, which excludes dead code kept alive by an
over-broad `-keep` rule.

---

**11. Do I have to care about the platform libraries too, or only the app's?**

Sort everything into three rings ([chapter §2](README.md#2-high-level-architecture)) and report each
differently:

- **Platform** (`/system`, `/apex`, Bionic, Skia, Conscrypt, the media stack). Not the developer's
  problem and not fixable by them. Report it as a **patch-level** observation: what security patch
  level is the device on, which Mainline module versions are installed. One paragraph.
- **Bundled** (the APK's own `lib/` and its DEX). Entirely the developer's problem. This is where
  your findings live. Fingerprint and rate every one.
- **Dynamically loaded** (anything obtained after install). Rare, and usually the most severe row in
  the table.

The mistake to avoid is spending a day on a platform CVE the client cannot do anything about, while
the bundled OpenSSL from four years ago sits unexamined.

---

**12. The app has 40,000 classes. Do I really inventory all of them?**

No. You inventory **package prefixes**, not classes. Forty thousand classes collapse to fifty or so
prefixes, of which perhaps thirty are recognisable from the table in
[chapter §8.1 Phase 2](README.md#8-static-analysis), fifteen are the app's own, and five are the ones
worth your time.

```bash
# host
python3 scripts/lib-fingerprint.py app.apk --list-prefixes 3 | head -50
```

Then spend your effort on the prefixes nobody recognises. An SDK nobody has heard of is an SDK nobody
has audited, and that is where the interesting findings are.

---

**13. Everything is obfuscated. Now what?**

Note first what obfuscation does *not* touch, because it is more than people expect:

- **Native libraries.** R8 obfuscates DEX. It does nothing to your `.so` files — symbols, strings,
  `NEEDED` list and build ID are all still there.
- **Library packages.** SDKs ship `consumer-rules.pro` files that keep their own public API, so
  `okhttp3.OkHttpClient` is usually still called that even when the app's code is `a.b.c`.
- **Manifest components and provider authorities.** Resolved by the system as strings.
- **JNI entry point names.** JNI binds by name, so the original Java package is embedded in the `.so`.
- **`SharedPreferences` keys, endpoints, log tags, thread names.** String constants used as
  persistent or external identifiers.

So an obfuscated app is still very inventoriable. What you lose is the *app's own* class names, which
is not what this chapter is about.

When the library packages themselves have been renamed, fall back to structure: class-set comparison,
string constants, and behaviour. What obfuscation is and how to attack it directly is
[40-Obfuscation](../40-Obfuscation/README.md)'s subject — here it is only an obstacle.

---

**14. Everyone keeps saying `.init_array`. What is it and why does it matter so much?**

It is a section in an ELF file holding a list of function pointers. The dynamic linker calls every
one of them as the **last step of `dlopen()`, before `dlopen()` returns**. In C you create one with
`__attribute__((constructor))`.

Why it matters: that is *before* `JNI_OnLoad`, *before* any Java code in the process, and inside a
call that has not returned. So:

- code there never appears in a call graph rooted at `JNI_OnLoad`;
- a `Java.perform` hook cannot observe it;
- a Frida script that installs hooks in the `onLeave` of `dlopen` installs them **after** it ran.

Anti-analysis lives there for exactly those reasons. The general defeat is not to fight for the
window but to hook the layer below — libc is already mapped when your process starts, so hooks placed
there at spawn are in position before the target library exists.
[Lab 04](labs/lab-04-constructor-hook.md) is that lesson end to end.

You can see the count in any `.so` in one command:

```bash
# host
readelf -S lib/arm64-v8a/libfoo.so | grep -A1 init_array
```

---

**15. The client says "that's just a transitive dependency, we don't use it". Is that a defence?**

It is a *hypothesis*, and a testable one. Do not accept it and do not dismiss it.

"We don't use it" can mean four things:

1. **R8 removed it.** Check: is the class actually in the DEX? If not, the client is right and the
   scanner matched a build file rather than an artifact.
2. **It is present but we never call it.** Check by hooking the entry points and driving the app.
   Often true, and it downgrades severity honestly.
3. **We don't call it, but the SDK that pulled it in does.** Very common, and the client has no
   visibility into it. Their belief is sincere and wrong.
4. **We don't call it directly.** True and irrelevant, if attacker-controlled data reaches it through
   two hops.

`./gradlew :app:dependencyInsight --dependency <name>` tells you who pulled it in, which usually
settles which of the four you are in within a minute.

---

**16. An SDK is abandoned — last release four years ago. Is that a finding?**

Yes, but be precise about what the finding *is*. It is not "there is a vulnerability". It is:

- **No fix is available** if one is ever needed. That changes the client's options from "update" to
  "replace", which is a quarter of engineering work rather than a line in a build file.
- **It is a takeover target.** An abandoned package can change hands.
   [Chapter §3.6](README.md#3-deep-internal-working) lists abandoned-package takeover as a distinct
   supply chain class.
- **It ages against the platform.** Android changes; unmaintained code eventually breaks or starts
  using restricted APIs.

The rubric scores maintenance as its own factor precisely so you can report this without having to
invent a vulnerability to justify it.

---

**17. Is bundling OpenSSL (or zlib, or SQLite) inside a `.so` bad?**

It is not *automatically* bad — cross-platform cores in fintech, VPN, media and game apps do it for
real reasons, and sometimes a specific version is required. But it has three consequences you must
report:

1. **It is outside every update mechanism.** The platform's TLS stack is a Mainline module and
   receives fixes through Play. A statically linked copy is fixed when the app developer rebuilds.
2. **No build-time SBOM knows about it.** It appears in no Gradle file. Symbol enumeration is the
   only way to find it, and most assessments never do it.
3. **It multiplies parsers.** A statically linked libpng means the app has its own PNG parser, taking
   adversary-chosen bytes, outside the platform's process isolation, seccomp filters and SELinux
   domains.

The finding to write is usually about (1) and (3) rather than a CVE: "this application carries its
own TLS/compression/database stack, which is not covered by platform updates, and no process exists
to track its patch level."

---

**18. Do I need root? Can I do this without a device at all?**

Most of the inventory is static and needs nothing but the APK and `python3`.
[Lab 01](labs/lab-01-library-inventory.md) is written so that every step has a pure-Python route.

You need a device for three things, and they are the three that turn inventory into findings:

- **What is actually loaded** (`/proc/<pid>/maps`). Root, or a debuggable app plus `run-as`.
- **What is actually sent** (the SDK audit). A device and a proxy; root or a debug build for the CA.
- **Whether the vulnerable path is reached.** Frida, so a device you can instrument.

You can write a professional inventory with no device. You cannot write a professional *risk rating*
with no device, because reachability is a runtime property. Say which you produced.

---

**19. Can I just run MobSF, or a scanner, and be done?**

Run it — it is a fine first pass and it will find things quickly. Then check everything it says and
everything it does not say.

[Chapter §8.4](README.md#8-static-analysis) has the honest table of what each tool does and where it
fails on Android. The short version: automated library detection is prefix-based and shallow, it does
not see native static linking, it does not see shading, it does not see runtime loading, and it does
not know about reachability.

The professional skill the tools cannot give you is the fourth item in
[the style guide's definition of senior](../STYLE-GUIDE.md): being able to explain **why an automated
tool's finding is a false positive**. That requires having done the manual process often enough to
know what the tool was looking at.

---

**20. Where does this chapter stop and another one start?**

| Question | Chapter |
|---|---|
| What libraries are in here, what version, and how bad is each? | **17, this one** |
| How is the APK laid out, and how do I unpack, modify and re-sign it? | [10-APK-Internals](../10-APK-Internals/README.md) |
| How is DEX structured, byte by byte? | [12-DEX-Internals](../12-DEX-Internals/README.md) |
| How do I defeat obfuscation, string encryption or a packer? | [40-Obfuscation](../40-Obfuscation/README.md) |
| How does Frida work, and how do I write hooks? | [53-Frida](../53-Frida/README.md) |
| How do I read the disassembly of a `.so` I found here? | [57-Ghidra](../57-Ghidra/README.md) |
| How does ART load and execute the code? | [13-ART](../13-ART/README.md), [11-Android-Runtime](../11-Android-Runtime/README.md) |
| Where do third-party findings map in a standard? | [71-OWASP-Mobile](../71-OWASP-Mobile/README.md) |

Obfuscation is the case that confuses people most. In chapter 40 obfuscation is the *subject*. Here
it is an *obstacle* — something in the way of an inventory, worked around rather than studied.

---

## Still stuck?

| Symptom | Read |
|---|---|
| "I don't know where to start on this APK" | [Lab 01](labs/lab-01-library-inventory.md) |
| "I have a library but no version" | [Lab 02](labs/lab-02-version-fingerprint.md), [chapter §3.7](README.md#3-deep-internal-working) |
| "I can see traffic but not who sent it" | [Lab 03](labs/lab-03-sdk-audit.md), [chapter §7.3](README.md#7-dynamic-analysis) |
| "My hooks are installed but nothing fires" | [Lab 04](labs/lab-04-constructor-hook.md) |
| "The evidence agrees but something feels wrong" | [Lab 05](labs/lab-05-ctf-library-that-lied.md) |
| "I need a command and I need it now" | [`cheatsheet.md`](cheatsheet.md) |
| "I need the shape of the whole chapter" | [`mindmap.md`](mindmap.md) |
