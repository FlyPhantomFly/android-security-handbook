# Lab 03 — Mapping the blind spots

> **Objective.** Measure, for one real application, how much of its actual behaviour your static pass
> could not see — and write the **limits section** of a report from numbers you obtained yourself
> rather than from boilerplate.

**Difficulty:** intermediate. Part A needs no device; Part B needs a rooted device with
`frida-server`; Part C needs neither.
**Time:** 45 minutes for Part A, another hour for Part B.
**Prerequisites:** [Lab 01](lab-01-first-static-pass.md). For Part B,
[53-Frida](../../53-Frida/README.md) §2 and a working `frida -U -f <pkg>`.

---

## 0. Why this lab exists

The most dangerous sentence in mobile security is **"the static analysis came back clean"**, because
the listener hears "the app is clean" and the speaker rarely corrects them.

Five things static analysis structurally cannot observe:

| Blind spot | Measured scale | Where the number comes from |
|---|---|---|
| Broadcast receivers registered at runtime | **299 of 431 distinct actions (69%)** used by third-party processes on a live device had no manifest-declared receiver anywhere | [29-BroadcastReceivers](../../29-BroadcastReceivers/README.md) |
| Native methods bound with `RegisterNatives` | No symbol exists in the `.so` at all | [16-JNI](../../16-JNI/README.md), [README §4.4](../README.md#44-registernatives-the-blind-spot-in-source) |
| Reflective dispatch targets | Chosen by string at runtime | [README §3.9](../README.md#39-stage-0--the-blind-spots-stated-plainly) |
| DEX loaded after installation | The code is not in the artefact you swept | [40-Obfuscation](../../40-Obfuscation/README.md) §3.7.3 |
| Server-side behaviour and remote config | Not on the device at all | — |

You are going to turn those from a list into a paragraph about *one specific app*, with counts.

> **Warning — device etiquette**
> Part B spawns an application under an instrumentation tool. Do this on a device you own, with an
> app you are permitted to test. On a shared or daily-driver phone, prefer a training app you
> installed yourself. Nothing in this lab installs, broadcasts or modifies state; if your variation
> would, stop and reconsider.

---

## Part A — What the artefact says (no device needed)

### A.1 Pick a target and get a tree

Use the tree from [Lab 01](lab-01-first-static-pass.md) if you still have it, or build the Lab 02
practice tree, which was constructed to have blind spots in the app's own code:

```bash
# host
bash build-gauntlet.sh                     # from Lab 02
python3 -B ../scripts/static-sweep.py ./out | sed -n '/BLIND SPOTS/,$p'
```

### A.2 Read the blind-spot section properly

On the Lab 02 tree the tool reports:

```
  BLIND-01  receiver registered at runtime
    1 occurrence(s) across 1 file(s); 1 in app code
      sources/com/gauntlet/app/sync/SyncService.java

  BLIND-02  reflective dispatch
    3 occurrence(s) across 1 file(s); 1 in app code
      sources/com/gauntlet/app/sync/SyncService.java
```

**The phrase "in app code" is the whole point.** On the Lab 01 reference target the same two markers
fire, but with `none in app code` — the application itself neither registers receivers nor reflects,
and only its bundled libraries do. Those two situations require completely different sentences in a
report, and a tool that only counted occurrences could not tell them apart.

### A.3 Enumerate the receiver gap, statically

```bash
# host — receivers the manifest declares
awk '/<(intent-filter|meta-data|action|category)[ \t>\/]/{t=0}
     /<receiver([ \t>\/]|$)/{t=1}
     t && match($0,/android:name="[^"]+"/){print substr($0,RSTART+14,RLENGTH-15);t=0}' \
    out/resources/AndroidManifest.xml | sort -u > declared-receivers.txt

# host — actions the manifest declares for them
grep -oE '<action android:name="[^"]+"' out/resources/AndroidManifest.xml \
    | sed 's/.*name="//; s/"//' | sort -u > declared-actions.txt

# host — actions the CODE adds to IntentFilters at runtime
grep -rhoE 'addAction\("[^"]+"\)|addAction\([A-Za-z_.]+\)' out/sources/ \
    | sed 's/addAction(//; s/)//; s/"//g' | sort -u > runtime-actions.txt

comm -13 declared-actions.txt runtime-actions.txt
```

On the Lab 02 tree, that last command prints:

```
Intent.ACTION_POWER_CONNECTED
com.gauntlet.app.SYNC_NOW
```

**Two actions the application listens for that appear nowhere in its manifest.** A reviewer who
enumerated the broadcast surface from the manifest alone would have reported zero receivers, and
would have been wrong by two.

> **Hint.** `addAction(Intent.ACTION_POWER_CONNECTED)` passes a *constant*, not a literal, so a
> naive grep for `addAction("` misses it entirely. The command above handles both forms. On real
> code you will also meet actions built by string concatenation, and those you cannot recover
> statically at all — which is Part B.

### A.4 Follow the reflection

```bash
# host
grep -rn -A3 'Class.forName' out/sources/ | head -20
```

On the Lab 02 tree:

```java
Class.forName("com.gauntlet.app.sync.OptionalUploader")
     .getDeclaredMethod("start")
     .invoke(null);
```

Now check whether that class exists in the tree:

```bash
# host
find out/sources -path '*sync/OptionalUploader*'
grep -rl 'OptionalUploader' out/sources/
```

**It does not exist.** That is one of the highest-value observations available from a static pass,
and it has exactly three explanations:

1. The class was stripped by R8 as unused, and the reflective call always fails and is caught. Benign.
2. The class ships in a **split** you did not decompile.
3. The class is **loaded at runtime** from somewhere else.

You cannot distinguish those three from the artefact. Write down all three, in the report, and say
which one you would test first and how.

### A.5 Native and code-loading markers

```bash
# host
grep -rn 'System.loadLibrary\|System.load(' out/sources/ | head
grep -rn 'DexClassLoader\|InMemoryDexClassLoader' out/sources/ | head
```

If either fires, add the corresponding paragraph to the limits section. If native code is present,
also check what the symbol table says:

```bash
# host — with a real APK
mkdir -p x && cd x && unzip -o -q ../base.apk 'lib/*'
for so in $(find lib -name '*.so'); do
    echo "=== $so"
    echo -n "  Java_ exports: "; readelf --dyn-syms --wide "$so" | grep -c ' Java_'
    echo -n "  JNI_OnLoad:    "; readelf --dyn-syms --wide "$so" | grep -c 'JNI_OnLoad'
done
cd ..
```

**`JNI_OnLoad` present with zero `Java_` exports means the native surface is registered at runtime**
and is not enumerable from the file. That is a blind-spot entry, not an absence of JNI.

### A.6 Write the static half of the limits section

Before moving to Part B, write this paragraph for your app, with your numbers:

> Static analysis of this artefact cannot observe: broadcast receivers registered at runtime, native
> methods bound with `RegisterNatives`, reflective dispatch targets, code loaded after installation,
> or server-side behaviour. For this application we identified **N** runtime receiver registration
> sites in the application's own code, covering **M** actions that do not appear in the manifest;
> **P** reflective dispatch sites, one of which names a class that is not present in the artefact;
> and **Q** native libraries, of which **R** export `JNI_OnLoad` with no `Java_`-prefixed symbols.
> Each of these is resolved in section <x> by runtime observation, or recorded as untested.

---

## Part B — What actually happens (device required)

### B.1 Arm the recorder

```bash
# host — spawn, do not attach. Attaching misses Application.onCreate and every
# ContentProvider that runs before it, which is where most registrations happen.
frida -U -f com.example.target -l ../scripts/blindspot-recorder.js --no-pause
```

You should see:

```
[*] blindspot-recorder armed (java hooks)
[*] blindspot-recorder armed (native hooks)
[*] drive the app, then call: rpc.exports.report()
```

> **Hint — `libart.so not found` or `no RegisterNatives symbol`?** Some builds strip the symbol. The
> script says so and continues; record that section as **untested** rather than as **empty**. The
> difference matters: "we did not measure it" and "there was nothing to measure" are different
> sentences and only one of them is honest.

> **Hint — more than one device attached?** `frida -U` picks the USB device and will complain if
> there are several. `frida-ls-devices` then `frida -D <id>`.

### B.2 Drive the app deliberately

Not randomly. Cover, and **write down** what you covered:

- cold start, then background, then resume
- log in, if you can
- the main navigation, one level deep
- a settings screen
- rotate the device once
- leave it idle for two minutes

**Record the wall-clock duration.** The report needs it, because every negative statement you make is
bounded by it.

### B.3 Take the delta report

In the Frida REPL:

```javascript
rpc.exports.report()
```

The output has five sections. The shape (this is the format, not a measurement of your app):

```
==============================================================
 DELTA: what static analysis could not have told you
 observation window: 8.4 minutes
==============================================================

  runtime-registered receivers   14 distinct action(s) across 6 registration(s)
      android.intent.action.SCREEN_ON   x2
      ...
  reflective invocations         37 distinct target(s)
      ...
  runtime DEX loading            0 event(s)
  native libraries loaded        3
  RegisterNatives bindings       41 method(s)
      seal(...)  ->  libcore.so+0x3f180
```

### B.4 Compute the gap

This is the number that goes in the report:

```bash
# host — actions your STATIC pass knew about
cat declared-actions.txt runtime-actions.txt | sort -u > static-known-actions.txt
wc -l < static-known-actions.txt

# host — actions the RECORDER observed (paste them into observed-actions.txt)
sort -u observed-actions.txt | wc -l

comm -13 static-known-actions.txt observed-actions.txt | tee gap.txt
wc -l < gap.txt
```

`gap.txt` is the set of broadcast actions this application listens for that **no amount of reading
the artefact would have revealed**. Chapter 29's device-wide measurement puts the general figure at
69%; yours will differ, and yours is the one that belongs in your report.

### B.5 Cross-check against the platform

The recorder sees registrations made by the process it is in. The platform sees all of them:

```bash
# adb shell — the live registration table
dumpsys activity broadcasts | grep -A3 'Receiver Resolver Table' | head -40
dumpsys package com.example.target | sed -n '/Receiver Resolver Table/,/Provider/p'
```

Compare the two. If the platform shows a registration your recorder missed, your hooks went in too
late — which is itself a finding about your method, and worth knowing before you rely on it in an
engagement.

---

## Part B-bis — What each hook costs you if it is missing

Before writing anything, know what an empty section in the recorder's output actually means. The
four states are not interchangeable and conflating them is how a limits section becomes fiction.

| Recorder says | Means | Correct sentence in the report |
|---|---|---|
| `runtime DEX loading  0 event(s)` | The hook was installed and nothing fired | "No runtime DEX loading observed during \<T\> minutes of use covering \<flows\>" |
| `[!] no RegisterNatives symbol in libart.so` | The hook could **not** be installed | "Native method registration was **not measured**; the symbol is stripped on this build" |
| Section absent entirely | You attached after the event | "Not measured; instrumentation attached after process start" |
| Section present, non-zero | A measurement | Quote the number and the window |

Two of those four are "we did not look". Only one is "we looked and there was nothing". A report that
writes the same sentence for all four is not describing the application, it is describing the
author's hope.

---

## Part B-ter — A worked example, with real numbers

For calibration, here is what Part A produced on the Lab 01 reference target
(`com.mobilehackinglab.FridaThree`, 3,655 files, 2,783 classes), so you know what a *good* result
looks like:

```
BLIND-01  receiver registered at runtime
    12 occurrence(s) across 3 file(s); none in app code

BLIND-02  reflective dispatch
    across 313 file(s); none in app code
```

Verified independently rather than trusted:

```bash
# host
grep -rl 'registerReceiver' out/sources/ | wc -l                          # 3
grep -rl 'registerReceiver' out/sources/com/mobilehackinglab/ | wc -l     # 0
grep -rl 'DexClassLoader'   out/sources/ | wc -l                          # 0
grep -rl 'loadLibrary'      out/sources/ | wc -l                          # 0
unzip -l base.apk | grep -c 'lib/'                                        # 0
```

Which supports exactly this paragraph, and no stronger one:

> The application's own code does not register broadcast receivers at runtime, does not use
> reflection, contains no native libraries, and shows no evidence of runtime DEX loading. Runtime
> registration and reflection occur only within bundled framework libraries (AndroidX and the Kotlin
> runtime). For this application the usual static-analysis blind spot around runtime broadcast
> registration — measured at 69% of the broadcast surface on a comparable device — therefore applies
> to its dependencies rather than to its own logic.

**Notice what that paragraph does not say.** It does not say the app is safe, it does not say the
blind spots do not apply, and it does not extend to the server. It says precisely what was measured,
about precisely which code, and names the residual.

Now compare with the Lab 02 practice tree, where the same two markers fire **in the app's own code**:

```
BLIND-01  1 occurrence, 1 in app code   (SyncService.onCreate)
BLIND-02  3 occurrences, 1 in app code  (SyncService.onCreate)
```

Same tool, same rules, opposite conclusion — and the difference is one column in the output.

---

## Part C — Write the limits section

Take everything above and produce one section of report prose. This is the deliverable.

```markdown
## Limits of this assessment

This assessment examined base.apk (SHA-256 <hash>) plus <n> split APKs, pulled from
<device, OS version> on <date>.

**Not observable from the artefact.** Static analysis of an Android application cannot
observe broadcast receivers registered at runtime, native methods bound with
RegisterNatives, reflective dispatch targets, code loaded after installation, or
server-side behaviour including remote configuration.

**What that meant for this application.**
- Runtime receivers: the application registers <N> receivers covering <M> broadcast
  actions. <K> of those actions appear nowhere in the manifest. We enumerated them
  by instrumenting the running process for <T> minutes covering <list of flows>.
- Reflection: <P> reflective dispatch sites in the application's own code. One names
  com.example.OptionalUploader, a class not present in any artefact we were given.
  We were unable to determine whether it is stripped, split, or loaded at runtime.
- Native code: <Q> libraries. <R> export JNI_OnLoad with no Java_-prefixed symbols,
  so their JNI surface is registered at runtime; we enumerated <S> such bindings.
- Runtime DEX loading: no events observed in <T> minutes of use. This is not
  evidence of absence.
- Server-side behaviour: <U> remote-config flags identified. We tested <V> of them
  in both states; the remainder were not testable within the engagement.

**Coverage.** <T> minutes of instrumented use covering <flows>. Negative statements
above are bounded by that window and should not be read as proofs of absence.
```

**Every angle-bracket placeholder must be a number you obtained.** If one of them cannot be, write
"not measured" and say why — that sentence is worth more than a plausible guess.

---

## 4. Success criteria

- [ ] You can name all five structural blind spots without looking.
- [ ] For your target, you know whether each blind-spot mechanism occurs in **the app's own code** or
      only in bundled libraries, and you can point at the file.
- [ ] You produced a list of broadcast actions the app listens for that are not in its manifest.
- [ ] You followed at least one reflective call to its target and stated whether the target exists in
      the artefact.
- [ ] If native code is present, you know whether its JNI surface is symbol-visible or registered.
- [ ] Your limits section contains **numbers you measured** and no boilerplate.
- [ ] Every negative statement in it carries its observation window.
- [ ] You wrote "not measured" at least once, honestly.

---

## 5. Common ways this lab goes wrong

| Symptom | Cause | Fix |
|---|---|---|
| The recorder reports zero receivers on an app that visibly has them | You attached instead of spawning | `frida -U -f <pkg> … --no-pause` |
| `addAction` grep finds nothing but the app still listens | Actions passed as constants or built by concatenation | Use the both-forms grep in A.3; concatenated actions are only recoverable at runtime |
| RegisterNatives section is empty | Symbol stripped, or the app has no native code | Distinguish the two. Empty because absent ≠ empty because unmeasured |
| Your gap set is empty | The app is simple, or your window was too short | Report the window length; a two-minute window proves very little |
| The limits section reads like a template | You wrote it before collecting the numbers | Write it last, from the numbers |

---

## 6. What to take away

1. **"Clean sweep" and "clean app" are different claims**, and the gap between them is measurable.
2. **The gap is app-specific.** The 69% figure is the general shape, not your app's number.
3. **A reflective call naming a class that is not in the tree** is one of the most informative things
   a static pass can produce, and no tool will flag it for you — you have to look.
4. **Negative statements need windows.** "No runtime DEX loading observed in 8.4 minutes covering
   login, browse and settings" is a professional sentence. "No runtime DEX loading" is not.
5. **Absence of a symbol is not absence of a mechanism.** `JNI_OnLoad` with no `Java_` exports is the
   normal shape of a hidden native surface.

Then do [Lab 04](lab-04-ctf-honest-report.md), where over-claiming costs you points.
