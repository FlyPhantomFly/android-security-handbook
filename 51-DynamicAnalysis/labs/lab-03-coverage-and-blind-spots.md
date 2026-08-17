# Lab 03 — Coverage, and the lie of a clean pass

> **Objective.** Measure how little of an application a plausible, professional-looking dynamic
> session actually reaches. Then write the limits section that measurement forces you to write — the
> one that turns "we tested the app" into a sentence a reviewer can act on.

**Difficulty:** intermediate. The commands are easy; the honesty is the work.
**Time:** two to three hours.
**Prerequisites:** [Lab 01](lab-01-first-runtime-pass.md) completed against a target you still have.
[README §3.9](../README.md#39-stage-0--coverage-recorded-throughout) read once.

---

## 0. Why this lab exists

Every dynamic report ever written contains an implicit claim it did not earn: *the parts I did not
mention are fine*. Nobody writes that sentence, and every reader infers it.

This lab makes the size of that claim visible. You will drive an app the way a competent tester drives
an app — deliberately, for a reasonable length of time, hitting the obvious screens — and then measure
what fraction of it you actually touched. The number is always lower than it feels, and the gap
between the two is the exact size of the lie.

The lab has three parts, and they are deliberately in this order:

- **Part A** — measure coverage of a session you *believe* was thorough.
- **Part B** — measure the things that are invisible to *any* number of sessions.
- **Part C** — write the limits section, which is the deliverable.

---

## Part A — What you actually reached

### A.1 Build the honest denominator

You did this in Lab 01. Do it again, and this time check it against the device's version, because the
difference is the lab's first lesson.

```bash
# host
export PKG=com.example.target
mkdir -p cov/{artefact,evidence}
adb shell "pm path $PKG"
adb pull <every path printed> cov/artefact/

aapt2 dump xmltree --file AndroidManifest.xml cov/artefact/base.apk > cov/manifest.txt
awk '/E: (activity|activity-alias|service|receiver|provider) /{k=$2; next}
     /E: /{ if ($2 !~ /^(intent-filter|meta-data|action|category|data)$/) k=""; next }
     k != "" && /android:name\(0x01010003\)=/ {
        match($0,/="[^"]+"/); print substr($0,RSTART+2,RLENGTH-3)" kind="k; k="" }' \
    cov/manifest.txt | sort -u > cov/entrypoints.txt

echo "static  : $(wc -l < cov/entrypoints.txt)"
echo "device  : $(adb shell "dumpsys package $PKG" | grep -oE "$PKG/[A-Za-z0-9_.\$]+" | sort -u | wc -l)"
```

**Checkpoint A.1.** Two numbers. Which is larger, and why?

> **Hint.** The static one, always. `dumpsys package`'s resolver tables index only components carrying
> an `<intent-filter>`, because they exist to answer "which component would win this Intent". A
> settings screen started by explicit Intent from inside the app is real and is not in them. On the
> chapter's measured app: **4 static, 3 device** — a 25% error on a tiny app, and always in the
> flattering direction.

**If you have splits, decompile each and concatenate.** A denominator built from `base.apk` alone is a
second, independent way to flatter yourself, and it is invisible.

### A.2 Drive the app like a professional

Not randomly. Write a script first, and make it the session you would defend in a status meeting:

```
T+00:00  cold start
T+00:20  the main screen, fully
T+00:50  every item in the primary navigation
T+02:00  the settings screen
T+02:30  background and foreground
T+03:00  log out, if there is a log out
```

```bash
# host — [MUTATES] force-stop; the app restarts
bash ../scripts/session-recorder.sh -p "$PKG" -o cov/evidence/s01 \
  --exec "adb shell am force-stop $PKG; sleep 3;
          adb shell am start -W -n $PKG/<LAUNCH>; sleep 200"
```

Drive it by hand during those 200 seconds, following your script. **Verify it ran**: the `Activity:`
line, `mCurrentFocus`, `pidof`.

### A.3 The number

```bash
# host
python3 -B ../scripts/coverage-reporter.py -p "$PKG" \
        --components cov/entrypoints.txt \
        --logcat cov/evidence/s01/09-logcat.txt \
        --markdown cov/COVERAGE-A.md
cat cov/COVERAGE-A.md
```

**Checkpoint A.2.** Before you look: **write down what you expect the percentage to be.** Then look.

Almost everyone over-estimates, and the gap between your guess and the number is the most useful
output of this lab. Record both in `cov/NOTES.md`.

### A.4 Read the "not reached" list out loud

The percentage is not the deliverable. **The named list is.**

Go through every component the report marks `**no**` and put it in one of four buckets:

| Bucket | Meaning | What to do |
|---|---|---|
| **Reachable, I just did not** | A screen behind a menu I did not open | Drive it. This is free coverage |
| **Reachable, but needs state** | Requires a logged-in account, a paid tier, a device state | Get the state, or record why you could not |
| **Not reachable by a user** | A boot receiver, a job service, a sync adapter | Trigger it deliberately — §A.5 |
| **Genuinely unreachable in this build** | Dead code, a flavour-gated screen | Static's question. Record it and cross to 52 |

**Checkpoint A.3.** Every unreached component is in exactly one bucket, in writing.

### A.5 Reach the components a user cannot

Receivers and services are where coverage quietly dies, because no amount of tapping reaches them.

```bash
# host — what would a BOOT_COMPLETED receiver do? [MUTATES: sends a broadcast]
#   Only against an app you own. Note that `am broadcast` sends ordered=true,
#   which is NOT how the platform sends most broadcasts -- chapter 29 measured this.
adb shell "am broadcast -a android.intent.action.BOOT_COMPLETED -p $PKG"

# host — start a service explicitly
adb shell "am start-service -n $PKG/<SERVICE>"

# host — probe a provider read-only
adb shell "content query --uri content://<authority>/<path>"
```

> **⚠️ Warning**
> These are mutations and two of them can change application state. **Only against an app you own or
> have written permission to test.** And remember that reaching a component from `adb shell` (uid
> 2000) is not the same as an app reaching it — that is a separate demonstration, and
> [60-ADB](../../60-ADB/README.md) measured why: `com.android.shell` requests 200 permissions with 16
> pre-granted `SYSTEM_FIXED`.

Re-run the coverage report with the second session's log added:

```bash
# host
python3 -B ../scripts/coverage-reporter.py -p "$PKG" \
        --components cov/entrypoints.txt \
        --logcat cov/evidence/s01/09-logcat.txt \
        --logcat cov/evidence/s02/09-logcat.txt \
        --markdown cov/COVERAGE-B.md
```

**Checkpoint A.4.** How much did deliberate component-triggering add, compared with an extra ten
minutes of tapping?

### A.6 The orphan list

Read the section the tool prints titled **"Reached, but not in the inventory"**.

Every name there means your **denominator is wrong**. The usual causes:

| Orphan looks like | Cause |
|---|---|
| A class in a package you do not recognise | A library contributed it at manifest-merge time |
| `Foo$Bar` or `$$ExternalSyntheticLambda0` | An inner or compiler-generated class |
| A component of a different package entirely | Your regex matched too widely — or the app really does start another app's component |
| A component you *know* is in the app | **You decompiled the wrong artefact, or missed a split** |

The last row is the one to care about. Ten minutes here is worth an hour of extra clicking.

---

## Part B — What no number of sessions will reach

Coverage measures what you drove. This part is about the things that are invisible **however long you
drive**, and it is why a report needs a limits section and not just a percentage.

### B.1 Completeness — the question dynamic cannot ask

Pick something you observed. A file written, a host contacted, a preference key set. Now ask *how many
other places do that*, and notice that no session can tell you.

```bash
# host — static answers it in one command
jadx -d cov/out cov/artefact/base.apk 2>/dev/null
grep -rn 'getSharedPreferences' cov/out --include='*.java' | grep -v '/androidx/\|/kotlin/' | wc -l
grep -rhoE 'https?://[a-z0-9.-]+'  cov/out --include='*.java' | sort -u | wc -l
```

**Checkpoint B.1.** Write the arithmetic:

```
observed at runtime : 1 preference file, 2 hosts
enumerated statically: 7 preference call sites, 9 hosts
therefore not exercised: 6 sites, 7 hosts
```

That third line is a sentence only the two halves together can produce, and it belongs in the report.

### B.2 Configuration that is never exercised

52 swept a real 17 MB commercial application and found a `Domain` enum shipping **thirteen
environments** — production, pre-production, eight QA hosts and three staging hosts.

**Twelve of those thirteen will never appear in any proxy log**, because the production build points
at production. No session reaches them. No amount of driving reaches them.

```bash
# host — look for the same shape in your target
grep -rniE '(staging|preprod|uat|sandbox|qa)[0-9]*\.[a-z0-9-]+\.[a-z]{2,}' cov/out --include='*.java' | head
```

**Checkpoint B.2.** If you find any, note that this is a finding **dynamic analysis structurally
cannot produce** — and that fact is worth a line in your limits section.

### B.3 Branches inside components you did reach

Component coverage is a floor. Prove it to yourself.

```bash
# host — pick ONE Activity you definitely reached, and count its branches
grep -c 'if (' cov/out/sources/$(echo "$PKG" | tr '.' '/')/MainActivity.java
```

You reached the component. You executed some unknown fraction of those branches. **Nothing you have
measured tells you which fraction**, and if you need to know, the answer is `Stalker`
([53-Frida](../../53-Frida/README.md) §7.9) at 100–1000× slowdown, or a coverage-instrumented build.

**Checkpoint B.3.** Write the sentence: *"Component coverage was N%. Branch coverage within reached
components was not measured."*

### B.4 The runtime surface no file records — and no static tool sees

The mirror of B.1: things dynamic sees that static cannot, so that your limits section is honest in
both directions.

```bash
# host — the app's live runtime receiver surface
adb shell "dumpsys activity broadcasts" | awk -v p="$PKG" \
  '/ReceiverList\{/{b=index($0,p)>0} /^ +app=/{if(index($0,p)>0)b=1} b&&/Action: /{print}' | sort -u

# host — and the device-wide measurement, for context
python3 -B ../../29-BroadcastReceivers/scripts/receiver-surface.py --runtime-only --third-party | tail -20
```

**Checkpoint B.4.** Compare the actions your app registered at runtime against any receiver declared
in `cov/manifest.txt`. How many of the runtime actions appear in the manifest?

> **Hint.** Probably none. Chapter 29 measured **299 of 431 distinct actions (69%)** device-wide on an
> API 30 device with no manifest-declared receiver anywhere; this chapter re-measured **214 of 321
> (67%)** on an API 33 device. Two devices, two API levels, both about two thirds. Your app is a
> single-app slice of the same phenomenon.

### B.5 Snapshot blindness

The recorder takes two snapshots. Anything that returns to its starting state is in **neither**.

Demonstrate it:

```bash
# host — snapshot the receiver set while the app is FOREGROUND
adb shell "am start -n $PKG/<LAUNCH>"; sleep 5
adb shell "dumpsys activity broadcasts" | grep -c "$PKG"

# host — and again after backgrounding it
adb shell "input keyevent KEYCODE_HOME"; sleep 5
adb shell "dumpsys activity broadcasts" | grep -c "$PKG"
```

**Checkpoint B.5.** Did the count change? If it did, you have just proved that a receiver registered
in `onResume` and unregistered in `onPause` is invisible to a before/after method — and that the only
way to catch it is a hook on `registerReceiver`
([52's `blindspot-recorder.js`](../../52-StaticAnalysis/scripts/blindspot-recorder.js)) or a much
higher snapshot frequency.

### B.6 What each missing channel costs you

Fill this in for **your** session. The point is that a closed channel is a *gap*, not a *negative*.

| Channel | Captured? | If not, what you cannot say |
|---|---|---|
| 04 private FS | | Nothing at all about what the app persists |
| 08 network content | | Nothing about what was sent, only that bytes moved |
| Heap | | Nothing about what survives in memory after logout |
| Method-level coverage | | Which branches ran inside the components you reached |
| Another app's data | | Whether this app can read it |

---

## Part C — Write the limits section

This is the deliverable. Everything above exists to make it truthful.

```markdown
## Scope and limits of the dynamic assessment

This assessment exercised `<package>` version `<v>` on a `<model>`, Android `<rel>` / API `<sdk>`,
security patch `<patch>`, SELinux `<mode>`, `<rooted|not rooted>`, over `<N>` sessions totalling
`<M>` minutes on `<date>`. The system CA store was verified `<unmodified|MODIFIED — see below>`.
Instrumentation was at altitude `<0-3>`: `<what was armed>`.

### Coverage

Of `<T>` components enumerated from the shipped artefact (`base.apk`, SHA-256 `<hash>`, plus
`<n>` splits), `<R>` (`<P>`%) were reached. The following were **not** exercised, and no statement
in this report — positive or negative — applies to them:

  - `<component>` (`<kind>`) — `<which bucket from A.4, and why>`
  - ...

Component coverage is not code coverage. Branch coverage within reached components was not
measured.

### Channels not captured

  - `<channel>` — `<why>`. No statement in this report addresses `<what that channel would have
    covered>`.

### What runtime observation structurally cannot establish

  - **Completeness.** `<N>` occurrences were observed at runtime; static analysis enumerates `<M>`
    (section `<x>`). The remaining `<M-N>` were not exercised.
  - **Configuration that is never exercised.** `<e.g. 13 environments are enumerated in the
    artefact; the production build contacts 1>`.
  - **Dependency versions**, which are a property of the artefact — section `<y>`.
  - **Server-side behaviour**, including remote configuration. `<K>` feature flags were identified;
    `<L>` were tested in both states.

### What static analysis could not have established

  - `<N>` broadcast actions were registered at runtime by this application; `<M>` of them appear in
    no manifest. Comparable device-wide measurements put the runtime-only share of the broadcast
    surface at approximately two thirds.
  - `<any RegisterNatives bindings, reflection targets or loaded DEX>`.

### Observations

`<K>` observations were recorded. `<A>` were attributed to a specific exercise step, `<B>` were
discarded as background after comparison with a control run of equal length, and `<C>` could not be
attributed and were re-tested with a narrower window.
```

**Checkpoint C.** Every angle-bracket is replaced with a number or a name you can point at in your
evidence directory. If any of them is a guess, go back and measure it.

---

## Success criteria

- [ ] You wrote down your expected coverage figure **before** computing it, and both numbers are in
      `cov/NOTES.md`.
- [ ] You have two denominators, static and device, and you know which to quote and why.
- [ ] Every unreached component is in one of the four buckets, in writing.
- [ ] You deliberately triggered at least one component a user cannot reach, and measured what it
      added.
- [ ] You read the orphan list and either fixed the denominator or recorded why you could not.
- [ ] You wrote the "observed N, static enumerates M" arithmetic for at least one behaviour.
- [ ] You demonstrated snapshot blindness with the foreground/background receiver count.
- [ ] Part C's limits section is complete with real numbers and no placeholders.
- [ ] Nowhere in your output does the phrase "no issues found" appear.
- [ ] The device is as you found it.

---

## Common ways this lab goes wrong

| Symptom | Cause | Fix |
|---|---|---|
| Coverage is 100% | A tiny app, or the device denominator | Check A.1's two numbers. And say the grain: it means you drove every front door |
| Coverage is 8% and you feel defeated | Normal for a large app in one session | The number is not a grade. The **named list** is the deliverable |
| The orphan list is enormous | Your regex is matching uids (`u0a150`) or non-components | The reporter filters those; if you rolled your own, anchor it |
| Part C reads like boilerplate | You filled it in without measuring | Every bracket must be traceable to a file in `cov/` |
| You cannot find the unreached components in the UI | Many are not in the UI at all | That is bucket three. Trigger them explicitly — A.5 |
| The receiver count did not change between foreground and background | The app registers everything in `onCreate` | A valid result. Note it: this app's surface *is* snapshot-visible |

---

## What to take away

1. **The number is not the deliverable; the named list is.** A percentage tells a client nothing they
   can act on. "These six screens were not tested" tells them exactly what to ask for next.
2. **The denominator is where the dishonesty enters**, and it enters silently. The device will hand
   you a flattering one every single time.
3. **Component coverage is a floor.** 100% of it is compatible with a small fraction of the code.
   Say the grain.
4. **A closed channel is a gap, not a negative.** "Private storage was not captured" and "no sensitive
   data was found in private storage" are different sentences and only one of them is true.
5. **A two-snapshot method is blind to anything that returns to its starting state** — which you
   proved yourself in B.5.
6. **The strongest sentence in mobile reporting needs both halves:** "observed N; static enumerates M;
   the remaining M−N were not exercised".

---

## Going further

- Run the whole of Part A again a week later on a new build. Did coverage hold? A dynamic pipeline
  whose exercise script is not maintained silently loses coverage as the app grows, and that decay is
  the metric worth tracking.
- If you have root or a rebuildable app, run
  [52's `blindspot-recorder.js`](../../52-StaticAnalysis/scripts/blindspot-recorder.js) over the same
  session and compare its delta report against your snapshot-based channel 06. The gap is exactly
  B.5's lesson, quantified.
- Then go to [Lab 04](lab-04-ctf-the-session-that-lied.md), where the obvious reading of a complete,
  professional-looking evidence set is wrong.
