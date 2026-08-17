# Lab 02 — The loop, run explicitly

> **Objective.** Take a lead from a **static** pass, answer it at **runtime**, feed the runtime answer
> back into a **second static** pass, and close it. In one sitting, with the artefacts to show each
> hand-off. Because "static and dynamic complement each other" is a slogan until you have done it.

**Difficulty:** intermediate.
**Time:** three to four hours.
**Prerequisites:** [Lab 01](lab-01-first-runtime-pass.md) completed.
[52-StaticAnalysis §3](../../52-StaticAnalysis/README.md#3-deep-internal-working) read once. An APK
you may decompile — see §1. `jadx` or `apktool`, `python3`.

---

## 0. Why this lab exists

Seven chapters in this repository describe 51 and 52 as *"the other half of the loop"*. Nobody has
ever been asked to actually run it, and there is a reason: it is uncomfortable. Each half keeps
producing questions the other half owns, and the natural instinct is to answer them badly inside the
half you are currently in.

This lab forces four crossings, in order, with a written artefact at each:

```
52 -> 51   the lead queue becomes an exercise plan and a coverage denominator
51 -> 52   the runtime answer becomes a vocabulary: names, offsets, values
52 -> 51   completeness turns "I saw one" into "there are eleven, and here are the other ten"
51 -> done the one remaining question that only execution can answer
```

**The rule for the whole lab: you may not answer a question in the wrong half.** When you are in the
dynamic half and you catch yourself wondering *"how many other places does this happen?"*, you stop,
write the question on the crossing sheet, and cross.

---

## 1. Choose a target you may decompile

This lab needs an APK on disk and a running app, so the target must be one you are permitted to pull
apart. In order of preference:

1. **An app you wrote**, with at least three or four Activities and something it persists.
2. **A public, deliberately vulnerable training app.** Several exist and are made for this.
3. **A third-party app on your own device**, for **static analysis and observation only** — you may
   decompile and observe, but you may not repackage or instrument it.

```bash
# host
export PKG=com.example.target
mkdir -p loop/{artefact,static,dynamic,crossings}
adb shell "pm path $PKG"
adb pull <each path printed> loop/artefact/
sha256sum loop/artefact/*.apk | tee loop/artefact/hashes.txt
```

**Note every split.** An entry-point list built from `base.apk` alone will be short, and §6 measures
exactly that error.

---

## 2. Crossing 1 — the static pass produces a plan

### 2.1 Decompile and sweep

```bash
# host
jadx -d loop/static/out loop/artefact/base.apk
python3 -B ../../52-StaticAnalysis/scripts/static-sweep.py loop/static/out \
        --app-package "$PKG" --csv loop/static/leads.csv | tee loop/static/sweep.txt
```

Read the queue. You are not looking for findings; you are looking for **next steps that are runtime
steps**.

### 2.2 Build the exercise plan from the queue

Open `loop/static/leads.csv` and, for every lead, write one line into
`loop/crossings/01-static-to-dynamic.md` in this form:

```markdown
| Lead | Static says | The runtime question | The exercise step that answers it |
|---|---|---|---|
| L004 | `putString("auth_token", …)` in `SessionStore` | Does a token reach disk, and where? | Log in, then read channel 04 |
| L009 | `setJavaScriptEnabled(true)` in `HelpWebView` | What URL does it load? | Reach the Help screen; capture the URL |
| L012 | `registerReceiver` in 3 files | With which actions? | Any exercise at all; read channel 06 |
| L015 | A `TrustManager` subclass | Does it accept my CA? | Proxy and drive one request |
```

**Checkpoint 1.** Your table has at least four rows and every "exercise step" is something you could
hand to a colleague to perform without further explanation.

> **Hint.** If a lead has no runtime question, that is a legitimate answer — write `— static only` in
> the third column. 52's 13-environment `Domain` enum is the canonical example: twelve of those hosts
> will never appear in a proxy log, and no amount of driving will produce them.

### 2.3 And the denominator

```bash
# host — the second thing static hands over, and the one people forget
aapt2 dump xmltree --file AndroidManifest.xml loop/artefact/base.apk > loop/static/manifest.txt
awk '/E: (activity|activity-alias|service|receiver|provider) /{k=$2; next}
     /E: /{ if ($2 !~ /^(intent-filter|meta-data|action|category|data)$/) k=""; next }
     k != "" && /android:name\(0x01010003\)=/ {
        match($0,/="[^"]+"/); print substr($0,RSTART+2,RLENGTH-3)" kind="k; k="" }' \
    loop/static/manifest.txt | sort -u > loop/static/entrypoints.txt
wc -l < loop/static/entrypoints.txt
```

**If you have splits, repeat for each and concatenate.** §6 asks you what difference it made.

---

## 3. The dynamic half — answer the plan

### 3.1 Baseline

```bash
# host
bash ../scripts/session-recorder.sh -p "$PKG" -o loop/dynamic/control --wait 45
```

### 3.2 Exercise, driven by the plan

Write the script from column four of your crossing table, then run it:

```bash
# host — [MUTATES] force-stop; the app restarts
bash ../scripts/session-recorder.sh -p "$PKG" -o loop/dynamic/s01 \
  --exec "adb shell am force-stop $PKG; sleep 3;
          adb shell am start -W -n $PKG/<LAUNCH>; sleep 25;
          <the taps and inputs your plan calls for>
          sleep 15"
```

**Verify the exercise happened** before you read anything: the `Activity:` line in
`loop/dynamic/s01/exercise.log`, then `mCurrentFocus`, then `pidof`. Lab 01 §6.3.

### 3.3 Answer each row

Go back to `loop/crossings/01-static-to-dynamic.md` and add a fifth column: **the runtime answer**.

Some will be easy:

```bash
# L012 -- with which actions?
adb shell "dumpsys activity broadcasts" | awk -v p="$PKG" \
  '/ReceiverList\{/{b=index($0,p)>0} /^ +app=/{if(index($0,p)>0)b=1} b&&/Action: /{print}' | sort -u
```

Some will need channel 04:

```bash
# L004 -- did a token reach disk?
adb shell "run-as $PKG find /data/data/$PKG -type f -exec stat -c%s,%Y,%n {} +"
adb shell "run-as $PKG cat /data/data/$PKG/shared_prefs/session.xml"
```

And some will not be answerable at your altitude, which is a real answer:

```markdown
| L015 | A `TrustManager` subclass | Does it accept my CA? | Proxy one request | **Unanswered.** The device's system CA store is modified (`mount \| grep cacerts` returns an APatch tmpfs), so an intercept here proves nothing about user-CA trust. Recorded as a limitation |
```

**Checkpoint 2.** Every row has a fifth column, and at least one of them says something other than a
clean yes or no.

---

## 4. Crossing 2 — the runtime answer becomes a vocabulary

This is the crossing people never make, and it is the one that pays.

Open `loop/crossings/02-dynamic-to-static.md` and record everything the runtime pass produced that is
**a search term you did not previously have**:

| Category | What runtime gave you | What to do with it in static |
|---|---|---|
| Action strings | The 14 actions channel 06 listed | `grep -rn '<action>' loop/static/out` — they are string literals and survive R8 |
| Class names | The classes that actually ran, including obfuscated ones | Open them. You now know which of four thousand matter |
| File names | `session.xml`, `cache/blob.dat` | `grep -rn 'session' loop/static/out` — find every writer, not just the one you saw |
| Values | A token, a device id, a URL | `grep -rn '<value>' loop/static/out` and 52's sweep with `--app-package` |
| Native offsets | `libfoo.so+0x3f180` from a `RegisterNatives` hook | Open that address in [57-Ghidra](../../57-Ghidra/README.md) |
| Hosts | Whatever the proxy saw | Compare against every host in the artefact — §5 is about the gap |

```bash
# host — the crossing, mechanised. One example for each category you have.
grep -rn 'com.vendor.internal.SYNC_DONE' loop/static/out | head
grep -rn 'session.xml'                   loop/static/out | head
grep -rln 'SessionStore'                 loop/static/out | head
```

**Checkpoint 3.** Pick the single most interesting runtime observation and find its *source* in the
decompiled tree. Write the file and line into the crossing sheet.

> **Hint — this is the deobfuscation trick.** If the app is obfuscated, the class name your runtime
> observation produced (`com.vendor.a.b`) is a name you can now grep for and open, and its *string
> literals* tell you what it does. [40-Obfuscation](../../40-Obfuscation/README.md) §6.1 automates the
> substitution; the point here is only that **runtime gave you the entry point that made static
> tractable.**

---

## 5. Crossing 3 — completeness

Now ask the question you were forbidden from answering in the dynamic half.

For your chosen observation — say, *"a session token was written to `shared_prefs/session.xml`"* —
static answers:

```bash
# host — how many OTHER places write to preferences?
grep -rn 'getSharedPreferences\|edit()\.put' loop/static/out --include='*.java' | wc -l
grep -rn 'getSharedPreferences' loop/static/out --include='*.java' | grep -v '/androidx/\|/kotlin/' | head -20

# host — how many OTHER hosts are configured, versus the ones the proxy saw?
grep -rhoE 'https?://[a-z0-9.-]+' loop/static/out --include='*.java' | sort -u | head -40
```

Write the arithmetic into `loop/crossings/03-completeness.md`:

```markdown
Runtime observed:  1 preference file written, on the login path
Static enumerates: 7 distinct getSharedPreferences call sites in app code, in 5 classes
Not exercised:     6 of the 7. Named below, with the component that reaches each.

Runtime observed:  2 hosts contacted (api.example.com, cdn.example.com)
Static enumerates: 9 hosts in app code, including 3 matching a non-production pattern
Not exercised:     7 of 9. The production build points at production.
```

**Checkpoint 4.** You now have a sentence you could not have written from either half alone:

> *"The application writes session material to `shared_prefs/session.xml` on the login path
> (observed). Static analysis identifies six further preference write sites in application code that
> were not exercised, listed in Appendix B with the component that reaches each."*

That sentence is the whole point of the lab. **Neither half can produce it.**

---

## 6. Crossing 4 — close it at runtime

Take **one** of the un-exercised sites static just handed you and go back to the dynamic half to
settle it. Choose one that matters — a write site on a path you can reach.

```bash
# host — a narrow, targeted second session
bash ../scripts/session-recorder.sh -p "$PKG" -o loop/dynamic/s02 \
  --exec "<drive ONLY the path that reaches the site you chose>; sleep 20"
```

Then the fourth correlation question, which is the strongest and which this lab exists to make you
run:

```bash
# host — the control: the same session with that one step removed
bash ../scripts/session-recorder.sh -p "$PKG" -o loop/dynamic/s03 \
  --exec "<the identical script, minus the one step>; sleep 20"
```

If the file appears in `s02` and not in `s03`, **the attribution is beyond argument**. That is a
controlled experiment and it costs one extra run.

### And re-measure coverage with the corrected denominator

```bash
# host
python3 -B ../scripts/coverage-reporter.py -p "$PKG" \
        --components loop/static/entrypoints.txt \
        --logcat loop/dynamic/s01/09-logcat.txt \
        --logcat loop/dynamic/s02/09-logcat.txt \
        --markdown loop/COVERAGE.md
```

**Checkpoint 5.** Did adding the second session move the number? By how much? And how much of the
remaining gap is components you now know how to reach?

---

## 7. The deliverable

`loop/REPORT.md`, containing:

1. **The artefact.** Package, version, every split, SHA-256 of each.
2. **The device.** Model, API, patch level, posture — including the `cacerts` check.
3. **The crossing log.** All four crossing sheets, in order. This *is* the methodology section.
4. **One finding**, validated, with evidence from **both** halves — a file:line and a moment in a
   session.
5. **The completeness paragraph** from §5.
6. **The coverage statement**, with the denominator's source named.
7. **The limits**: what static could not see, what dynamic did not reach, and what your device could
   not answer.

---

## 8. Success criteria

- [ ] Four crossing sheets exist, in `loop/crossings/`, and each has content produced by the *other*
      half.
- [ ] Your exercise script is traceable to specific rows of the static lead queue — not improvised.
- [ ] At least one static lead is recorded as `— static only`, with the reason.
- [ ] At least one runtime observation is recorded as unanswerable at your altitude, with the reason.
- [ ] You located the source of a runtime observation in the decompiled tree: file and line.
- [ ] You wrote a completeness sentence of the form "observed N, static enumerates M, N−M not
      exercised", with the un-exercised sites named.
- [ ] You ran the make-it-*not*-happen control and it behaved as predicted — or it did not, and you
      recorded that your attribution was wrong.
- [ ] Coverage is computed against the **static** denominator and you know how it differs from the
      device's.
- [ ] The device is as you found it.

---

## 9. Common ways this lab goes wrong

| Symptom | Cause | Fix |
|---|---|---|
| The crossing sheets are empty in one direction | You did the two halves side by side rather than in sequence | Redo crossing 2. It is the one that pays and the one people skip |
| Every static lead has a runtime question | You are treating static leads as a to-do list | Some questions are completeness questions. Mark them `— static only` |
| The runtime pass found nothing to hand back | Your exercise was too shallow, or void | Check the `Activity:` line first; then drive more of the plan |
| Static grep for a runtime action string finds nothing | The action is built at runtime by concatenation, or it is in a split you did not decompile | Both are findings about your *method* — record them |
| Coverage did not change after the second session | The second session drove a path inside an already-reached component | Correct, and worth noting: component coverage is a floor |
| You cannot find the class the runtime named | It is in a split, or it is generated | `unzip -l` every split; check `$$ExternalSyntheticLambda` |

---

## 10. What to take away

1. **Static hands over a plan; dynamic hands back a vocabulary.** The second direction is the one
   nobody runs, and it is what makes an obfuscated target tractable.
2. **The coverage denominator is a static artefact.** You cannot compute an honest dynamic coverage
   figure without a static pass — which means the two chapters are not merely complementary, they are
   mutually dependent for one specific number.
3. **"Observed N; static enumerates M"** is the strongest sentence in mobile reporting and it requires
   both halves in one sitting.
4. **Some questions belong to neither half.** Anything the server decides is not on the device. Write
   it down and test the API directly.
5. **The make-it-not-happen control is cheap and almost nobody runs it.** One extra session converts
   a correlation into a controlled experiment.

---

## 11. A worked crossing, with real numbers

So that §2–§6 are not abstract, here is one lead followed all the way round the loop. The numbers are
from the chapter's own measurements; the lead is constructed from them.

### The lead, as static produced it

```
L004  [MEDIUM 0.50]  BLIND-01  (blind spot)
  what      receiver registered at runtime
  sites     12 occurrence(s) in 3 file(s); 3 in app code
  NEXT STEP Static analysis cannot tell you which actions these register.
            Enumerate them on a live device.
```

52's sweeper is explicit that this is **not a lead at all** in the ordinary sense — it is a *limit on
your report*. It goes in the blind-spot section, and it is a question for the other half.

### Crossing 1 — the question becomes an exercise step

| Lead | Static says | Runtime question | Exercise step |
|---|---|---|---|
| L004 | `registerReceiver` in 3 app files, 12 sites | **With which actions?** | Any exercise; then read channel 06 |

Note how cheap the exercise is. This lead needs no login, no state and no instrumentation — the
information is in AMS's table the moment the process is alive.

### The runtime answer

```bash
# adb shell
dumpsys activity broadcasts | awk -v p="$PKG" \
  '/ReceiverList\{/{b=index($0,p)>0} /^ +app=/{if(index($0,p)>0)b=1} b&&/Action: /{print}' | sort -u
```

Twelve call sites, and the live table names the actions. Suppose it returns four, two of which are
custom:

```
Action: "android.intent.action.SCREEN_ON"
Action: "android.net.conn.CONNECTIVITY_CHANGE"
Action: "com.vendor.internal.SYNC_DONE"
Action: "com.vendor.internal.APPLY_CONFIG"
```

**Static knew there were twelve calls and could name zero actions. Runtime named four and knows
nothing about the other eight call sites.** Neither half is close to complete alone, and that is the
whole shape of the lab.

### Crossing 2 — the answer becomes a vocabulary

```bash
# host — action strings are string literals and survive R8 renaming completely
grep -rn 'com.vendor.internal.APPLY_CONFIG' loop/static/out | head
```

That grep lands you in the exact class and method that registers it — including if the class is named
`a.b.c`. **You now have a name you had no reason to open five minutes ago**, and its string literals
tell you what it does. This is the deobfuscation trick, and it cost one command.

### Crossing 3 — completeness

```bash
# host
grep -rn 'registerReceiver' loop/static/out --include='*.java' | grep -v '/androidx/\|/kotlin/' | wc -l
```

Twelve. Runtime named the actions for however many were registered *on the path you drove* — likely
two or three of the twelve. Write the arithmetic:

```
Runtime observed:  4 actions live, from an unknown subset of the call sites
Static enumerates: 12 registerReceiver call sites in application code, in 3 classes
Not exercised:     the sites in <ClassB> and <ClassC>, which run on paths not driven
```

### Crossing 4 — close one at runtime

Pick the un-exercised class, find what reaches it, drive only that, and re-read channel 06. Then run
the make-it-*not*-happen control: the identical session with that step removed. If the actions appear
in one and not the other, the attribution is beyond argument.

### And the device-wide context, if you want it

```bash
# host — how unusual is any of this?
python3 -B ../../29-BroadcastReceivers/scripts/receiver-surface.py --runtime-only --third-party | tail -8
```

Measured on the chapter's API 33 device: **214 of 321 distinct actions had live runtime registrations
and no manifest-declared receiver anywhere.** Chapter 29 measured **299 of 431 (69%)** on an API 30
device. Your app is one slice of a device-wide phenomenon, and knowing the base rate is what stops you
reporting "this app registers receivers at runtime" as though it were remarkable.

---

## 12. The report this lab produces, in outline

A page you could hand to a client, assembled entirely from the crossing sheets:

```markdown
### F-0N — <title> (<severity>)

**Runtime evidence.** <what was observed, on which channel, in which session, at what offset
from which exercise step, and reproduced N times>

**Static evidence.** <file:line in the decompiled tree, plus the artefact SHA-256>

**Completeness.** Runtime observed <N>. Static analysis enumerates <M> equivalent sites
(Appendix B). The remaining <M-N> were not exercised; the components that reach them are
named in the coverage statement.

**Reachability.** <observed during ordinary use / started from adb shell (uid 2000) and
therefore NOT established for an unprivileged app / demonstrated from an attacker app>

**Impact.** <the asset>

**Fix.** <as code>
```

The two lines that no single-half assessment can produce are **Static evidence** on a finding that
runtime discovered, and **Completeness** on a finding that runtime observed. If your report has both,
you ran the loop.

---

## 13. Going further

- Run the loop a second time on the same target with the roles reversed: start dynamic (drive the app
  blind), then use what you saw to target the static pass. Which order was more efficient, and why?
- If your target loads code at runtime, hook the loader, dump the DEX, hash it, and **restart 52's
  pipeline at stage 3 on the dump**. That is the loop at its most literal — a new artefact produced by
  the dynamic half.
- Then go to [Lab 03](lab-03-coverage-and-blind-spots.md), which measures how little of an app a
  plausible-looking session actually reaches.
