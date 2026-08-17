# Lab 04 — CTF: Before Application

> **Objective.** Recover a three-fragment flag from `com.pentest.ch66.ctf`. Each fragment is
> reachable only if you understand one specific thing about instrumentation, and the three things are
> different. There is no memory corruption, no cryptography worth the name, and no vulnerability in
> the app. There is only *where you are* and *when you are there*.
>
> **Flag format:** `CTF{fragment1_fragment2_fragment3}` — three lowercase words, underscore-joined.
>
> **Difficulty.** Advanced. Solvable in twenty minutes if labs 01–03 landed; otherwise it will resist
> you for an evening, and the way it resists is itself the lesson.
>
> **Time.** 60–120 minutes.

**Prerequisites:** [Lab 01](lab-01-first-instrumentation.md), [Lab 02](lab-02-the-gate-matrix.md) and
[Lab 03](lab-03-ordering-and-vantage.md), all three actually done rather than read ·
[../README.md §3.6–§3.9](../README.md)

> **⚠️ Warning — deliberately vulnerable application**
> `labs/ctf-vault/` builds an application that is **designed to give up its secrets**. It is a lab
> fixture and nothing else. Install it only on a device you own, and uninstall it the moment you are
> finished:
>
> ```bash
> # host
> cd 66-Instrumentation/labs && ./build-ctf.sh --uninstall
> ```
>
> It requests no permissions, exports nothing except its launcher activity, and reaches no network.
> Any network reference anywhere in this chapter's code uses the `.invalid` TLD, which by RFC 2606 can
> never resolve.

---

## 1. Brief

You have been given a signed application and permission to assess it. It keeps a flag in three
pieces. You have the sources — they ship in `labs/ctf-vault/` — because this is not a
guess-what-it-does challenge. It is a **be-in-the-right-place-at-the-right-time** challenge, and
knowing the code makes that harder to fudge, not easier.

What you must produce: the assembled flag, plus, for each fragment, a one-sentence statement of *why*
your approach was necessary. A flag without those three sentences is not a solve.

### 1.1 Rules

| Allowed | Not allowed |
|---|---|
| Everything in the platform SDK | Adding `com.pentest.ch66.ctf` classes to your test APK |
| Reflection, in any quantity | Editing `labs/ctf-vault/` and rebuilding the target |
| Reading `labs/ctf-vault/` sources | `su`, `root`, or anything that needs it |
| Static analysis of the built APK | Frida, LSPosed, or any external hooking framework |
| `logcat`, `dumpsys`, `pm`, `am` | |

The "not allowed" column is not arbitrary. Each entry removes a shortcut that would let you avoid the
thing the fragment teaches.

> **Why shadowing is banned, specifically.** Your test APK's DEX is **first** on the shared class
> path (chapter §3.7). Ship a class named `com.pentest.ch66.ctf.Secrets` and the target's code will
> load *yours*, with all its fields at their defaults. Everything will appear to work, and every
> value you report will be wrong. Chapter §11.2 lists this as the second most common pentester error
> in the subject.

---

## 2. Set up

```bash
# host
cd 66-Instrumentation/labs
OUTDIR=/tmp/ch66ctf ./build-ctf.sh --install
```

Expected tail:

```
=== self-check ===
ctf-vault debuggable attrs : 0
(0 is correct -- the CTF target is deliberately NOT debuggable)
both APKs must share this digest:
  ctf-vault  Signer #1 certificate SHA-256 digest: b0468bf7...
  ctf-probe  Signer #1 certificate SHA-256 digest: b0468bf7...

=== installing ===
Success
Success

instrumentation:com.pentest.ch66.ctf.test/com.pentest.ch66.ctf.probe.CtfProbe (target=com.pentest.ch66.ctf)
```

Two lines in that block are the challenge design, stated openly:

- **`debuggable attrs : 0`.** The target is not debuggable, so `run-as` is closed to you and every
  "just use run-as" answer is off the table. Lab 02 showed why that does not stop instrumentation.
- **The two digests match.** One key signs both. That is the *only* thing
  `ActivityManagerService.startInstrumentation()` cares about.

**Keep using the same `OUTDIR` for every rebuild.** The signing key is generated there once and
reused; a fresh directory makes a fresh key and the two APKs stop matching, which will present as
`Permission Denial: ... does not have a signature matching the target` and waste twenty minutes.

### 2.1 Confirm the skeleton runs

```bash
# host
adb shell am instrument -w -r \
    com.pentest.ch66.ctf.test/com.pentest.ch66.ctf.probe.CtfProbe
```

```
INSTRUMENTATION_RESULT: flag=CTF{not-recovered_not-captured_denied}
INSTRUMENTATION_RESULT: fragment1=not-recovered
INSTRUMENTATION_RESULT: fragment2=not-captured
INSTRUMENTATION_RESULT: fragment3=denied
INSTRUMENTATION_CODE: -1
```

The skeleton compiles, installs, instruments and solves nothing. Those three placeholder values are
your scoreboard.

### 2.2 Look at the app by hand first

```bash
# host
adb shell am start -n com.pentest.ch66.ctf/.CtfActivity
```

The screen reports the *state* of each fragment without revealing any of them:

```
fragment1 : on disk, 6 encoded bytes
fragment2 : gone
fragment3 : denied -- the gate was closed
```

Read those three lines as three different problems. One is a file you cannot reach from where you are
standing. One is *gone by the time anybody looks*. One was refused by a decision that has already
been taken.

And try the obvious thing, so you have felt the refusal yourself:

```bash
# host
adb shell "ls -l /data/data/com.pentest.ch66.ctf/files/"
adb shell "cat /data/data/com.pentest.ch66.ctf/files/fragment1.bin"
adb shell "cat /data/data/com.pentest.ch66.ctf/shared_prefs/ctf.xml"
```

All refused. `adb shell` is uid 2000.

---

## 3. The three fragments

### Fragment 1 — vantage

Written to a private file by `EarlyProvider.onCreate()`, **encoded**. Two things stand between you
and it: reaching the bytes, and reversing the encoding. They are separate problems and you should
solve them separately.

The bytes are in `getFilesDir()` of a package that is not yours. You have just watched `adb shell`
be refused. Chapter §3.8 is the whole hint.

The encoding is a single-byte XOR and the key is a constant in the DEX. You may recover it by reading
`labs/ctf-vault/Secrets.java`, or — more satisfyingly, and better practice — by pulling the built APK
and reading the constant out of the Smali. Both routes are intended:

```bash
# host -- the static route
adb shell pm path com.pentest.ch66.ctf
adb pull <that path> /tmp/ctf.apk
cd /tmp && unzip -o -q ctf.apk 'classes*.dex'
baksmali d classes.dex -o smali
grep -n -A20 'BLOB_1\|KEY_1' smali/com/pentest/ch66/ctf/Secrets.smali
```

> `jadx 1.5.3` on some installations produces no output for a bare `classes.dex` and exits 0. If that
> happens, use `baksmali`, which ships inside apktool's `Resources/` directory. This is recorded in
> this repository as a standing tooling fact rather than a surprise.

**One sentence you must be able to write:** why could the shell not read the file, and what changed?

### Fragment 2 — ordering

`CtfApp.attachBaseContext()` decodes it into a `static volatile String`. The **first line** of
`CtfApp.onCreate()` sets that field to `null`.

Lab 03 measured where `Instrumentation.onCreate()` falls between those two events. The window is
about three milliseconds wide and it is entirely deterministic — you are not racing, you are simply
either inside the window or outside it.

**The failure mode is the thing to notice.** Put your read in `onStart()` and you get:

```
INSTRUMENTATION_RESULT: fragment2=null
```

Not an error. Not a refusal. `null`, from a read that succeeded, of a field that really was set a
moment ago. A probe that reports this without understanding it will conclude the field is never
populated.

**One sentence you must be able to write:** which method must the read live in, and what runs
between that method and the wipe?

### Fragment 3 — you can write, not only read

`CtfApp.onCreate()` reads `Gate.sUnlocked` **exactly once** and decodes fragment 3 only if it is
`true`. Nothing in the application ever sets it.

Setting a private static boolean by reflection is three lines and you already have the helper. The
challenge is not the write; it is *when*.

Here is the measured trap, from a deliberately-wrong solution run against this exact fixture:

```
I ch66solve: late gate write = ok
I ch66solve: late gate reads back = true
INSTRUMENTATION_RESULT: fragment3=denied
```

The write succeeded. The field reads back `true`. Fragment 3 is still `denied`. **A value you change
after it has been consumed has changed nothing**, and the process will cheerfully tell you the field
holds your value, forever, while every consequence of the old value stands.

This is the distinction chapter §3.8 draws between changing what a process *contains* and changing
what a method *does*. If the app recomputed the gate on every access, a late write would work; it
does not, so it does not.

**One sentence you must be able to write:** why did a successful write that reads back correctly
produce no effect?

---

## 4. Working method

1. **Do not start editing.** Read `labs/ctf-vault/CtfApp.java` top to bottom and write down the
   order of events on paper. Five lines.
2. Run the app once and watch `adb logcat -s ch66ctf:I`. The fixture logs `stage 1` through
   `stage 4`. Add your own tag and see exactly where you land between them.
3. Solve fragment 1 first. It is the only one where timing does not matter, so it validates your
   build-install-run loop without a second variable.
4. Solve fragment 3 next. It is one line in the right place, and getting it wrong produces the
   instructive `denied`.
5. Solve fragment 2 last. By then you will know precisely where the window is.
6. Assemble and check the shape: three lowercase words, underscores, wrapped in `CTF{}`.

### 4.1 The one command you will run fifty times

```bash
# host
cd 66-Instrumentation/labs && OUTDIR=/tmp/ch66ctf ./build-ctf.sh >/dev/null 2>&1 \
  && adb install -r /tmp/ch66ctf/ctf-probe.apk >/dev/null \
  && adb shell am instrument -w -r \
       com.pentest.ch66.ctf.test/com.pentest.ch66.ctf.probe.CtfProbe 2>&1 \
  | grep -E 'fragment|flag|Denial'
```

If `adb install -r` starts failing with `INSTALL_FAILED_UPDATE_INCOMPATIBLE`, uninstall the test
package once — you have probably rebuilt into a different `OUTDIR` at some point.

---

## 5. Success criteria

- [ ] You have the flag, and it is three lowercase words joined by underscores inside `CTF{}`.
- [ ] `fragment1`, `fragment2` and `fragment3` are each non-placeholder in your run's output.
- [ ] You can write the one sentence demanded for each fragment, without looking at §3.
- [ ] You solved it with **no** classes of the target package inside your test APK.
- [ ] You solved it with **no** root and with a target that carries no `DEBUGGABLE` flag.
- [ ] You can explain why the value in `SharedPreferences` under `"flag"` is worthless, and what a
      storage-only assessment would have concluded from it.
- [ ] You reproduced the "late gate write" failure at least once, on purpose, and saw the field read
      back `true` while the fragment stayed `denied`.

### 5.1 Extension challenges

- **Do it without touching `onCreate()`.** Is fragment 2 reachable at all from `onStart()`? Argue
  from the measured ordering rather than by trying.
- **Recover the keys entirely statically.** Pull the APK, disassemble, read all four blobs and all
  four keys, and produce the flag without instrumenting anything — then explain exactly which part of
  the challenge that route does *not* prove you understood.
- **Detect yourself.** Add `PackageManager.queryInstrumentation("com.pentest.ch66.ctf", 0)` to a
  scratch app and confirm it sees your test APK. That is the one-line defence the CTF target
  deliberately does not have.
- **Break it as the author.** What single line in `CtfApp` would make fragment 3 unreachable by this
  technique? (Hint: it is not a stronger check. It is a different *shape* of check.)

---

## 6. Hints

<details>
<summary>Hint 1 — I am refused before anything runs</summary>

`Permission Denial: ... does not have a signature matching the target` means your two APKs were
signed with different keys. That happens when you build into a new `OUTDIR`, because `build-ctf.sh`
only generates `ctf.ks` if it is absent. Delete the whole output directory, rebuild both APKs
together, uninstall both packages, and reinstall.
</details>

<details>
<summary>Hint 2 — fragment 1: where am I allowed to read?</summary>

Print `android.os.Process.myUid()` and `getTargetContext().getApplicationInfo().dataDir` from inside
your probe, then compare with what `adb shell id` says. The whole of fragment 1 is that comparison.
`getTargetContext().getFilesDir()` gives you the directory directly.
</details>

<details>
<summary>Hint 3 — fragment 1: the encoding</summary>

Six bytes, one key, XOR. `xorDecode(byte[], int)` is already in your skeleton. The key is a
`static final int` next to the blob in `Secrets`. If you want to do it the honest way, disassemble
the APK and read the constant out of `<clinit>` — it will be a `const/16` or `const/4` immediately
before the array fill.
</details>

<details>
<summary>Hint 4 — fragment 2: what does "gone" mean on the app's own screen?</summary>

`CtfActivity` reports `fragment2 : gone` because by the time an `Activity` exists,
`Application.onCreate()` has long since run and set the field to `null`. That is not a hint about the
Activity; it is a hint about *every* observation made after `Application.onCreate()`. Your `onStart()`
is one of those.
</details>

<details>
<summary>Hint 5 — fragment 2: the window</summary>

Lab 03 measured it: `attachBaseContext` at +1.57 ms, `ContentProvider.onCreate` at +2.75 ms,
`Instrumentation.onCreate` at +6.57 ms, `Application.onCreate` at +9.50 ms. You have roughly three
milliseconds, and you are handed them by the framework — you do not have to win a race, you have to
be in the right *method*.
</details>

<details>
<summary>Hint 6 — fragment 3: my write works and nothing happens</summary>

Log the value immediately after writing it. It will read back `true`. Now log the *time* of your
write and compare it with `stage 3: gate was CLOSED` in the fixture's own logcat output. The gate was
read before you wrote. Move the write.
</details>

<details>
<summary>Hint 7 — a complete plan, no code</summary>

In `onCreate(Bundle)`, before calling `start()`:
  (a) read the volatile field and stash it in an instance field of your probe;
  (b) write the gate boolean to `true`.
In `onStart()`, after waiting for the app's completion marker:
  (c) read the fragment-1 file from the target's `getFilesDir()` and XOR-decode it;
  (d) read the fragment-3 field;
  (e) assemble and `finish()`.

Note that (a) and (b) must both be in `onCreate`, and (c) and (d) must both be after the wait, and
the wait must be on the marker set when startup *completes*.
</details>

<details>
<summary>Hint 8 — the wait keeps timing out or the reads are empty</summary>

`CtfApp` sets `sStartupCompleteAtNs` on **exit** from `onCreate()`, which is the marker the skeleton
already waits on. If you replaced it with something set on entry, you have recreated lab 03 §4's trap:
the wait succeeds and the reads come back empty.
</details>

---

## 7. Instructor notes and the reference solution

<details>
<summary>SPOILER — the flag and the reference solution, verified on a device</summary>

### The flag

```
CTF{before_application_oncreate}
```

Chosen so that the flag states the lesson: your code runs **before** the target's
**`Application.onCreate`**.

### The reference solution

Three edits to the skeleton. In `onCreate(Bundle)`, before `start()`:

```java
mFragment2 = readStatic(cl, PKG + ".Secrets", "sVolatile");
Log.i(TAG, "captured fragment2 = " + mFragment2);

Log.i(TAG, "gate write = " + writeStatic(cl, PKG + ".Gate", "sUnlocked", Boolean.TRUE));
```

and in `onStart()`, replacing the `fragment1` placeholder:

```java
String fragment1 = xorDecode(
        readBytes(new File(getTargetContext().getFilesDir(), "fragment1.bin")), 0x5A);
```

Nothing else changes. `fragment3` is already read from `Secrets.sPart3` after the wait.

### Verified output

Built with `build-ctf.sh`, run on `sdk_gphone16k_x86_64` (Android 15 / API 35, `userdebug`),
target carrying no `DEBUGGABLE` flag, no root used:

```
INSTRUMENTATION_RESULT: flag=CTF{before_application_oncreate}
INSTRUMENTATION_RESULT: fragment1=before
INSTRUMENTATION_RESULT: fragment2=application
INSTRUMENTATION_RESULT: fragment3=oncreate
INSTRUMENTATION_CODE: -1
```

with the interleaved logcat showing the whole mechanism in eight lines:

```
I ch66ctf  : stage 1: attachBaseContext
I ch66ctf  : stage 2: ContentProvider.onCreate, fragment written
I ch66solve: onCreate entered at t=25955313148100
I ch66solve: captured fragment2 = application
I ch66solve: gate write = ok
I ch66ctf  : stage 3: onCreate, volatile wiped
I ch66ctf  : stage 3: gate was OPEN
I ch66ctf  : stage 4: startup complete t=25955317612700
```

Read lines 3 to 7 in order. The probe arrives after the provider, captures the volatile value, opens
the gate, and only then does the application wipe the value and consult the gate. That is the entire
challenge on four lines of log.

### The instructive wrong answer, also verified

Moving both actions into `onStart()` produces:

```
I ch66solve: late gate write = ok
I ch66solve: late gate reads back = true
INSTRUMENTATION_RESULT: flag=CTF{before_null_denied}
INSTRUMENTATION_CODE: -1
```

Fragment 1 still works — vantage does not depend on timing. Fragment 2 is `null` and fragment 3 is
`denied`, **while the gate field reads back `true`**. Show entrants this transcript if they are stuck;
it is worth more than any hint above.

### Grading

| Points | For |
|---|---|
| 1 | fragment 1 recovered, by either route |
| 1 | fragment 2 recovered |
| 1 | fragment 3 recovered |
| 1 | can explain why a late gate write reads back correctly and changes nothing |
| 1 | can explain why the shell could not read `fragment1.bin` and the instrumentation could |
| 1 | did not shadow any target class, and can say what would have happened if they had |
| −2 | modified `ctf-vault` sources, or used root |

### If an entrant asks "what single line would defend fragment 3"

The intended answer is not "check harder". It is to change the **shape** of the decision: make the
gate a method that recomputes from something outside the process — a server response, a signed
token — rather than a value read once from a static field. A static field is a value, and this
chapter changes values. A recomputed decision is a behaviour, and changing behaviours is
[65 — Hooking](../../65-Hooking/README.md)'s subject, which costs the attacker a great deal more.
</details>

---

## 8. Clean up

```bash
# host
cd 66-Instrumentation/labs
./build-ctf.sh --uninstall

# host -- confirm
adb shell pm list instrumentation
adb shell pm list packages | grep ch66
rm -rf /tmp/ch66ctf
```

Nothing was written to `/data/local/tmp` and no device state outside the two packages was touched.

---

## 9. What to read next

- **Chapter [§5](../README.md)** — how to write up what you just did without overstating it. The
  finding is never "the app can be instrumented".
- **[65 — Hooking](../../65-Hooking/README.md)** — everything the extension challenge's final answer
  implies.
- **[67 — Bypassing Protections](../../67-BypassingProtections/README.md)** — the arms race that
  starts the moment the CTF target adds `queryInstrumentation`.
- **[../examples/enterprise-ci-review.md](../examples/enterprise-ci-review.md)** — the same
  capability, viewed as a supply-chain problem rather than a device one.
