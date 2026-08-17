# Lab 03 — Build a sheet you would trust a year from now

> **Difficulty:** Intermediate → Advanced
> **Time:** 3 hours, best split across two sittings with a night in between. The gap is part of the
> method: you are building for a reader who has forgotten, and after a night's sleep you *are* that
> reader.
> **Prerequisites:** [Lab 01](lab-01-sixty-minute-triage.md) and [Lab 02](lab-02-the-sheet-lies.md).
> A real target you are authorised to analyse, and a device or emulator.
> **Deliverable:** one `cheatsheet.md`, every row executed or labelled `unrun`, passing the linter.

---

## 1. Why build your own

Because the sheets in this repository are written for a generic Android target, and yours is not.
Every real engagement accumulates a private vocabulary within the first day: the two `adb` incantations
that reach *this* app's data, the one hostname that matters, the flag combination that makes *this*
build install, the check that keeps firing.

That vocabulary lives in your terminal history for a week and then evaporates. Six months later the
same client sends the next version and you re-derive all of it.

> **🧠 Mental Model**
> A general cheat sheet is a **reminder of what is common**. A personal one is a **record of what is
> specific**. They fail differently: the general one omits your target, the personal one silently
> assumes it. Both need the same discipline — say what each row assumes.

The second reason is harder to admit. **Writing a row forces you to find out whether you actually
understand the command.** A row needs its vantage, its device class, and its failure shape, and you
cannot supply those from a half-understanding. Most of the learning in this lab happens at the
moment you try to write column four and discover you do not know what failure looks like.

---

## 2. Authorisation

Same rule as Lab 01. Your own app, a licensed training target, or something with written
authorisation. Do not point this at a third-party production app you have no scope document for.

If you are using a training app, prefer one you have **not** worked before. Rediscovering is not the
exercise; discovering is.

---

## 3. Sitting one — accumulate (90 minutes)

### 3.1 Set up the capture

The most important thing about this sitting is that you write **nothing** in cheat-sheet form. You
are collecting raw material. Editing while collecting produces a sheet of the things that were easy
to write, which is not the same as the things that were useful.

```bash
# host — from 76-CheatSheets/
bash examples/03-session-preflight.sh --pkg <target> | tee notes/00-preflight.txt
```

Then work. Anything: the Lab 01 triage, a specific feature, a protection you want to defeat. The task
does not matter; the accumulation does.

### 3.2 The capture rule

Every time you do any of these four things, paste the command into `notes/raw.txt` with a one-line
note:

| Trigger | Why it matters |
|---|---|
| You **retype** a command you have typed before | Repetition is the definition of a sheet row |
| You **look something up** | The lookup is the row. Write it down while you still remember what you searched for |
| Something **fails in a confusing way** | The failure shape is column four, and you will not remember it |
| You **guess right** | A guess that worked is a fact you did not know you had |

Do not filter. A raw file with sixty entries and forty duplicates is a better input than a tidy file
with twelve.

### 3.3 Capture the failures verbatim

This is the part everyone skips and it is the part that makes the sheet worth keeping.

When something fails, paste the **exact output**, not your summary of it:

```
$ adb shell "run-as com.example.target ls"
run-as: package not debuggable

# NOT: "run-as didn't work"
```

Six months from now, `run-as: package not debuggable` and `run-as: package not an application` will
mean completely different things to you, and your summary will have lost the difference. (They *do*
mean different things: the second is a debuggable **system** app, and reading it as the first loses a
genuine finding.)

### 3.4 End the sitting

Stop after 90 minutes even if you are mid-task. Do not tidy `raw.txt`. Sleep on it.

---

## 4. Sitting two — build (90 minutes)

### 4.1 Cluster, do not sort

Read `raw.txt` end to end and group the entries by **what you were trying to do**, not by tool.

The temptation is to make sections called "adb", "frida", "jadx". Resist it. That is a tool index and
you already have one — [`../references/cheatsheet-index-by-tool.md`](../references/cheatsheet-index-by-tool.md)
is generated for the whole repository. What no generator can produce is the task grouping, because
"what am I doing" is a judgement.

Aim for four to seven clusters. Real ones from real sheets:

| Cluster | Contents |
|---|---|
| "Get to a fresh state" | Uninstall, reinstall, clear data, re-grant permissions, re-login |
| "Reach the data" | The exact `run-as`/root path to this app's storage, its database, its WAL |
| "Make the traffic visible" | The specific CA + config + proxy dance that works for *this* app |
| "Get past the check" | The protection that fires, where it fires, and what actually moves it |
| "Prove it" | The reproduction steps for the two findings you already have |

### 4.2 Write each row to the four-property standard

From [`../examples/01-anatomy-of-a-sheet-row.md`](../examples/01-anatomy-of-a-sheet-row.md):

```
| <command> | <Needs> | <Device> | <what it does — and what failure looks like> |
```

- **`Needs`** — `any`, `dbg`, `root`, `sig`, `host`. The lowest privilege it actually works from.
- **`Device`** — `all`, `avd`, `avd≠`, `phys`, `unrun`.
- **Column four** — what it does, and **what it prints when it does not work**.

> **⚠️ Warning**
> If you cannot fill in the failure shape, you have not seen the command fail. Make it fail. Point it
> at a package that does not exist, unplug the device, run it against a release build. Sixty seconds
> now saves an hour later, because the failure you have never seen is the one you will misread as a
> result.

### 4.3 Run every row again, in the form you wrote it

Not the form you remember. The form on the page.

This is where most of the defects appear, and they are not subtle once you look:

- A row that works in your history because of a shell variable you set earlier.
- A row that worked because you were `root` at the time and the `Needs` column says `any`.
- A row with your quoting silently mangled — `adb shell sh -c '…'` <!-- lint:allow --> instead of
  `adb shell "sh -c '…'"`, which drops its first command and exits 0.
- A row you copied from a web page and never actually ran.

Anything you do not re-run gets `unrun` in the Device column. **That label is not a failure; the
failure is a row that was never run and does not say so.**

### 4.4 Add the negative rows

For each protection or check you met, add a row for the thing that **did not** work, and why. These
are worth more than the working rows, because the working row you will rediscover in ten minutes and
the dead end you will re-walk in full.

```
| `objection --gadget <pkg> explore` then `android root disable` | `any` | `all` | **Did not defeat this target.** It is three hooks and thirteen hard-coded paths; two of this app's five checks are outside its envelope and one was inlined by ART. Hook the specific check instead. |
```

### 4.5 Add the target-identity header

A personal sheet with no header is a trap for future you, because you will not remember which build
it was written against.

```markdown
# <Target> · working sheet

**App:** com.example.target 4.2.1 (versionCode 4021)
**APK SHA-256:** <hash>
**minSdk / targetSdk:** 24 / 33
**Device rows were measured on:** <model>, Android <rel> / API <sdk>, <build type>, root: <yes/no + how>
**SELinux:** Enforcing
**Written:** <date>

> Rows tagged `unrun` were not executed against this build.
```

Everything below that header is scoped by it. Without it the sheet is a set of claims with no subject.

---

## 5. Verify (30 minutes)

### 5.1 Lint it

```bash
# host — from 76-CheatSheets/
python3 -B scripts/lint-commands.py --path /path/to/your-sheet.md --no-fail
```

Eight rules, each a form this repository has measured to be broken on a real device. Expect hits the
first time; almost everybody writes at least one.

Deliberate counter-examples get a marker:

```
adb shell su -c 'id'        # lint:allow SU-DASH-C SU-DASH-C-BARE
```

Rule ids match exactly, so name each rule you mean, or use a bare `lint:allow` for the whole line. A
marker on the line above a fence covers the whole block.

### 5.2 Check the vantage of every row that makes a claim

```bash
# host — from 76-CheatSheets/
bash scripts/vantage.sh --file <path> --pkg <target>
bash scripts/vantage.sh --cmd '<probe>' --pkg <target>
```

Any row whose column four says "the file is there" or "the check does not fire" needs this. Three
different answers from three vantages is the normal case, not an anomaly, and a row that does not say
which vantage it means is a row that will be read as whichever one the reader happens to have.

### 5.3 The one-year test

Read your sheet as if you had never seen the target. For each row, ask:

- [ ] Do I know **which device** this was measured on?
- [ ] Do I know **what privilege** it needs?
- [ ] Do I know what it prints **when it fails**?
- [ ] Do I know **why** it works, or only that it does?
- [ ] If this row were wrong, **would I notice**, or would I just get an answer?

The last one is the Lab 02 skill applied to your own writing. A row that fails the last test needs
either a cross-check next to it or a warning that it can lie.

### 5.4 Delete ruthlessly

A row you will look up anyway is a row that costs you attention every time you scan the sheet and
gives nothing back. Cut:

- Anything already in a per-chapter sheet, unless your target changes what it does.
- Anything you understood so well you never had to look it up.
- Anything you cannot state a `Needs` and `Device` for — that is not a row yet, it is a note.

A twenty-row sheet you trust beats an eighty-row sheet you scan past.

---

## 6. Success criteria

- [ ] `raw.txt` from sitting one exists and was **not** edited during collection.
- [ ] Four to seven clusters, named by **task**, not by tool.
- [ ] Every row has `Needs` and `Device` filled in.
- [ ] Every row has a failure shape in column four.
- [ ] Every row was re-run in the exact form written, or is tagged `unrun`.
- [ ] At least two **negative** rows — things that did not work, and why.
- [ ] A target-identity header naming the build and the device.
- [ ] `lint-commands.py` reports zero live findings, or every finding is a marked counter-example.
- [ ] At least one row carries a cross-check because it could plausibly lie.

---

## 7. Hints

<details>
<summary>My raw.txt is 90% duplicates.</summary>

Good. Duplicates are the signal — a command you typed five times is exactly the row you need, and it
is the one you would never have thought to write down deliberately.

Count occurrences, sort descending, and take the top fifteen. That list is most of your sheet.
</details>

<details>
<summary>I cannot decide between clusters for a command.</summary>

Put it in both. A cheat sheet is not a taxonomy; it is a lookup table, and the cost of a duplicated
row is far lower than the cost of a row filed where you will not look for it.

The generated router does the same thing on purpose: `53-Frida` appears under both "the app detects
my hook" and "nothing works", because those are different questions arriving at the same sheet.
</details>

<details>
<summary>Every row I write is just the general sheet again.</summary>

Then you are writing the wrong rows. Ask a sharper question: what did you have to **discover** about
this target that a generic sheet could not have told you?

The package name and its exact `pm path`. The one activity that takes the URL extra. The preference
file the token lands in. The build flag combination that lets your patched APK install. The name of
the check that fires. None of that is in any general sheet, and all of it will be gone in a month.
</details>

<details>
<summary>I do not know what "failure shape" means for a command that has never failed.</summary>

Make it fail. Four cheap ways:

```bash
# host — each of these should produce a different, informative failure
adb shell "run-as com.does.not.exist id"
adb shell "dumpsys package com.does.not.exist"
adb shell "su 0 cat /data/data/com.does.not.exist/x"
adb -s no-such-device shell id
```

Notice which of them produce an **error** and which produce **empty output and exit 0**. The second
category is the one that needs a warning in column four, because silence reads as a negative result.
</details>

<details>
<summary>The linter flags a row I am sure is fine.</summary>

Adjudicate it — do not suppress it reflexively. Two of this linter's own rules were withdrawn or
downgraded after exactly that exercise: one flagged 130 lines of `adb shell am start … && adb logcat`
as errors when that is correct, intentional host-side chaining.

If your row is genuinely fine, the linter has a false positive and you have found a real defect in
it. If you are not sure, run the command and read the output — that settles it either way, and
settles it better than an argument.
</details>

<details>
<summary>How long should the sheet be?</summary>

The per-chapter sheets in this repository run 155 to 877 lines, with a median around 330 — and those
cover a whole subject. A personal sheet for one target is usually 40 to 120 lines.

Length is not the metric. **The metric is whether every row earns its place**, and a row earns its
place by being one you would otherwise have to re-derive.
</details>

---

## 8. Extension — contribute a row upstream

If a row you wrote is not target-specific — it applies to any Android app — it belongs in a chapter
sheet, not in your private one.

Before proposing it:

1. Run it on a second device if you have one, and record both.
2. Check it is not already there:
   `python3 -B scripts/build-cheatsheet-index.py --by tool` and search the sheet you would add to.
3. State the vantage, the device class, and the failure shape.
4. Run `lint-commands.py` over it.
5. If it contradicts something already written, **say so explicitly and give your method** — the
   convention in this repository is that the chapter's owner adjudicates their own numbers, and a
   divergence reported with its measurement is worth more than a silent edit.

That fifth point is not politeness. One chapter here failed to reproduce another's published figure,
filed the divergence with its own three-run measurement and changed nothing — and that was the right
call. The original number turned out to be root's, mislabelled as the shell's.

---

## 9. A worked example — the sheet this chapter's own session produced

Not invented. This is the material that accumulated while measuring the AVD for this chapter,
clustered and written to the standard, so you can see the shape before you produce your own. It is
short on purpose: eighteen rows from four hours of work is a normal yield.

```markdown
# sdk_gphone16k_x86_64 · working sheet

**Device:** AVD `sdk_gphone16k_x86_64` (`emu64xa16k`), `emulator-5554`
**Android:** 15 / API 35, `userdebug`, `ro.debuggable=1`
**Fingerprint:** google/sdk_gphone16k_x86_64/emu64xa16k:15/AE3A.240806.043/12960925:userdebug/dev-keys
**SELinux:** Enforcing · **Root:** Magisk 30.7 at /debug_ramdisk/magisk · **Page size:** 16384
**App vantage used:** a DEBUGGABLE package at uid 10207
**Written:** 2026-08-16 — all rows executed unless tagged `unrun`
```

### Cluster 1 — Establish which device I am on

| Command | Needs | Device | Does / fails as |
|---|---|---|---|
| `adb devices -l` | `host` | `all` | Exits **0 with nothing attached** and still prints a header. Count data rows, never the status |
| `adb shell getprop ro.build.fingerprint` | `any` | `all` | Does **not** start with `generic` here, so the most-copied `isEmulator()` returns `false` |
| `adb shell getconf PAGE_SIZE` | `any` | `avd≠` | `16384`. Naively-linked NDK binaries exit **139** with no message naming the cause |
| `adb shell getprop ro.build.type` | `any` | `all` | `userdebug`. Refusals measured here are solid; permissive successes are upper bounds |

### Cluster 2 — Get root, and prove it

| Command | Needs | Device | Does / fails as |
|---|---|---|---|
| `adb shell "su 0 id"` | `root` | `all` | `uid=0(root) … context=u:r:su:s0` |
| `adb shell "su -c id"` <!-- lint:allow --> | — | — | **Broken here.** `su: invalid uid/gid '-c'`, exit 1 — reads as *not rooted* |
| `adb shell "su 0 /debug_ramdisk/magisk -v"` | `root` | `avd` | `30.7:MAGISK:R`. Absolute path required — `magisk` is not on root's `PATH` |
| `adb shell "grep -c magisk /proc/self/mountinfo"` | `any` | `all` | `3`, from shell, root **and** an app uid. The root signal that needs no privilege |

### Cluster 3 — Reach a real app vantage

| Command | Needs | Device | Does / fails as |
|---|---|---|---|
| `adb shell "run-as <pkg> id"` | `dbg` | `all` | `uid=10207 … context=u:r:runas_app:s0:c207,c256,c512,c768` |
| `adb shell "dumpsys package <pkg>" \| grep 'pkgFlags=\['` | `any` | `all` | `[ DEBUGGABLE HAS_CODE … TEST_ONLY ALLOW_BACKUP ]` — the fastest read in the toolkit |
| `adb shell "run-as <pkg> ls -laR ."` | `dbg` | `all` | Full private tree. Refuses two ways: `not debuggable` vs `not an application` — different conditions |
| `bash scripts/vantage.sh --file <p> --pkg <pkg>` | `dbg` | `all` | Three columns. Without `--pkg` the app column says `no --pkg` rather than silently reporting the shell |

### Cluster 4 — Things that lied to me, and what I use instead

| Command | Needs | Device | Does / fails as |
|---|---|---|---|
| `frida-ps -U` | `host` | `all` | **Succeeds with no `frida-server` running** — it enumerates over adb. Proves ADB, not instrumentation |
| `frida -U -n <proc> -e 'console.log(1)'` | `host` | `all` | The real test. Here: `unable to connect to remote frida-server: closed`, exit 1 |
| `adb shell "su 0 /data/local/tmp/frida-server --version"` | `root` | `avd` | `CANNOT LINK EXECUTABLE … empty/missing DT_HASH/DT_GNU_HASH`. Device exit 1 |
| `adb shell "run-as <pkg> sh -c 'test -e /system/xbin/su && echo Y \|\| echo N'"` | `dbg` | `all` | **`N` on a rooted device.** `/system/xbin` is `0750 root:shell` |
| `adb shell getprop ro.boot.verifiedbootstate` | `any` | `avd≠` | **Empty string**, not `orange`. `!"orange".equals(s)` therefore returns `true` |
| `adb shell "su 0 ls -di /data/data /data/user/0"` | `root` | `all` | Same inode (`344065`). Bind mount, not a symlink — `readlink` returns nothing, exit 1 |

### What this example demonstrates

Three things worth copying into your own sheet:

- **Cluster 4 exists.** Four of the eighteen rows are commands that lie, kept because the lie is the
  expensive part. A sheet with no such cluster has quietly decided that everything it lists is
  trustworthy.
- **The `—` rows.** Two rows have no `Needs` and no `Device`, because they do not work here. Listing
  a broken form and marking it broken is what stops the next person re-deriving it in an hour.
- **The header carries the scope.** Every row above is a claim about *that* AVD on *that* date. Move
  the sheet to a phone and half of Cluster 1 and all of Cluster 2 need re-measuring — which is exactly
  what the `Device` column tells you before you find out the hard way.

---

## See also

- [`lab-01-sixty-minute-triage.md`](lab-01-sixty-minute-triage.md) — where the raw material comes from
- [`lab-02-the-sheet-lies.md`](lab-02-the-sheet-lies.md) — the rows you must never write
- [`lab-04-ctf-the-stale-sheet.md`](lab-04-ctf-the-stale-sheet.md) — what happens to a sheet nobody
  maintains
- [`../examples/01-anatomy-of-a-sheet-row.md`](../examples/01-anatomy-of-a-sheet-row.md) — the row standard
- [`../scripts/lint-commands.py`](../scripts/lint-commands.py) — the checker
- [`../../80-Appendix/README.md`](../../80-Appendix/README.md) §6 — the test-environment record your
  header is a compressed form of
