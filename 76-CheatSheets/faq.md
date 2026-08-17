# 76 — Cheat Sheets · FAQ

Real questions, including the ones people feel stupid asking. Answered directly.

---

### 1. Why isn't this chapter just all 76 cheat sheets stuck together?

Because that file would be 29,189 lines, and — more importantly — it would be a **copy**. A copy has
no relationship to its source. The moment `33-Storage/cheatsheet.md` is edited, the copy is wrong,
and nothing in the copy says so. A reader who finds a stale command in it has no way to know which
of the two versions is current.

The one part of aggregation that is genuinely useful is **navigation**, and navigation can be
generated. So this chapter ships a router that holds pointers, plus the material no single chapter
can hold.

### 2. So what is actually *in* this chapter that is not in a chapter somewhere?

Three things.

- **The router** (§3) — generated, so it cannot drift.
- **The task sheets** (§4) — "I have an APK and one hour" crosses eleven chapters and belongs to
  none of them. No chapter-shaped sheet can be organised by what you are *doing*.
- **The corrections** (§6) — thirty-three commands where the obvious answer has been measured wrong.

### 3. Why is a wrong command worse in a cheat sheet than in prose?

Because prose is *read* and a cheat sheet is *copied*. When you read a paragraph, its hedges are on
the page in front of you. When you paste a fenced command into a terminal, they are not.

Two real examples from this repository, both in sheets: a "Magisk version" row that actually printed
`su`'s version, and a triage script whose `set -o pipefail` made it print **"not a JNI library"
directly below a list of that library's JNI exports**. Neither produced an error. Both produced a
confident wrong answer.

### 4. What does the `Needs` column mean, and can I ignore it?

`Needs` is the lowest privilege the command actually works from: `any` (uid 2000), `dbg` (the target
must be `android:debuggable`), `root`, `sig` (your test APK signed with the target's key), `host`.

You can ignore it exactly once, and then you will spend an hour on a command that returns something
that looks like an answer. The classic: a root check that reads a path works from `adb shell` and
returns `Permission denied` from an app — which `File.exists()` reports as `false`. Same device, same
instant, opposite conclusions.

### 5. What does `unrun` mean? Is the command wrong?

No. It means **it was not executed in the session that wrote this chapter**, usually because the
hardware was not attached — a locked bootloader, a StrongBox element, a production `user` build.

The label exists so you can calibrate. Everything not marked `unrun` was run in exactly the form
printed, on the AVD recorded in §2 of the README. A sheet that does not distinguish "I ran this" from
"this is what the documentation says" cannot be trusted differently in the two cases, so it ends up
trusted equally — which means trusted too much in half of them.

### 6. `su -c` has always worked for me. Why does this chapter say it is broken?

Because you have been using a Magisk-rooted phone. AOSP's `su` — which ships on every `userdebug`
build and every Android emulator — takes `su <uid> <cmd>`, not `su -c <cmd>`. Measured:

<!-- lint:allow -- transcript of the failing form, quoted on purpose -->
```
$ adb shell "su -c id"
su: invalid uid/gid '-c'
$ adb shell "su 0 id"
uid=0(root) gid=0(root) ... context=u:r:su:s0
```

There is a second, nastier failure that hits even where `su -c` is accepted. `adb shell` does not
preserve your quoting: the whole line arrives as separate argv words. So
`adb shell "su -c 'magisk -v'"` <!-- lint:allow --> becomes `su -c magisk -v`, **`-v` is consumed
by `su`**, and you get `su`'s version number in a row labelled "Magisk version".

Run both forms once, at the start of a session, and record which worked.

### 7. `frida-ps -U` lists processes, so Frida is working, right?

No, and this one is genuinely surprising. Measured on the AVD in this session:

```
$ adb shell 'ps -A' | grep -i frida       # nothing -- no frida-server running
$ frida-ps -U                             # full, correct process list
$ frida -U -n zygote64 -e 'console.log(1)'
Failed to attach: unable to connect to remote frida-server: closed
```

`frida-ps -U` enumerates processes **over adb**, through Frida's Android backend. It needs no
`frida-server` at all. A successful `frida-ps` proves your adb connection works. The test for
instrumentation is an **attach**.

(The `frida-server` binary was sitting right there on the device and does not link on this image:
`CANNOT LINK EXECUTABLE … empty/missing DT_HASH/DT_GNU_HASH (new hash type from the future?)`.)

### 8. Why does my root check say the device isn't rooted when I know it is?

Almost certainly because you ran the check from `adb shell` and the app runs at an app uid, or the
reverse. Measured here on a device rooted with Magisk 30.7:

| | `adb shell` | root | app uid |
|---|---|---|---|
| `ls -l /system/xbin/su` | readable | readable | **Permission denied** |
| `test -e /system/xbin/su` | EXISTS | EXISTS | **NOT-VISIBLE** |

`/system/xbin` is `0750 root:shell`. The shell is in the `shell` group; an app is not. And
`File.exists()` maps `ENOENT` (absent), `EACCES` (present but forbidden) and invisible all to
`false`, so `new File("/system/xbin/su").exists()` has **zero discriminating power on a rooted
device** — the only kind of device where it could ever matter.

The signal that does work needs no privilege at all: `/proc/self/mountinfo` carried three lines whose
mount source is literally `magisk`, readable from all three vantages.

### 9. Three different answers from three vantages — which one do I put in the report?

The app one, unless the finding is specifically about shell or root capability. Say which vantage
produced it either way.

The general rule this repository arrived at after hitting the problem four times independently:
**name the uid and the SELinux domain that actually performed the read**, not the process you issued
it from. That last part matters — there is a way to be running inside the app and still measure the
shell, by routing a probe through `UiAutomation.executeShellCommand`, which runs as uid 2000 and says
nothing about it in its output.

### 10. Why does `adb shell sh -c 'echo A; echo B'` <!-- lint:allow --> only print `B`?

Your host shell strips the single quotes before `adb` ever sees them. `adb` then joins the remaining
argv words with spaces and hands them to the device's shell, which re-splits on the `;`. The result
is that `sh -c echo` runs with `A` as an argument to `-c` (printing an empty line), and `echo B` runs
separately.

Wrap the whole thing in double quotes:

```bash
adb shell "sh -c 'echo A; echo B'"        # prints A, then B
```

This is the single most common source of "half my script works" on Android.

### 11. My script prints an error under `set -o pipefail` but the data is obviously fine. What?

`head` and `grep -q` exit the instant they have what they need. That closes the pipe, the writer
upstream dies of `SIGPIPE`, and `pipefail` promotes the writer's status to the pipeline's — so you
get **141 on success**. Measured:

<!-- lint:allow -- the failing pipelines are the point -->
```
$ bash -c 'set -o pipefail; yes | head -3 >/dev/null; echo $?'
141
$ bash -c 'set -o pipefail; seq 1 100000 | grep -q 5; echo $?'
141
$ bash -c 'set -o pipefail; seq 1 100000 | grep -c 5 >/dev/null; echo $?'
0
```

The maddening part is that it is intermittent: with a small producer the writer finishes first and
you get 0. The same script passes on Monday and fails on Tuesday, and the message always blames the
data. Use `grep -c` (it reads all input), or a shell `case` glob, or drop `pipefail`.

### 12. My loop over a package list only processes the first item. Why?

`adb shell` inherits stdin, so inside a `while read` loop fed by a pipe it drinks the loop's input.
Measured:

```
$ printf 'a\nb\nc\n' | while read -r x; do echo "row=$x"; adb shell true; done
row=a
$ printf 'a\nb\nc\n' | while read -r x; do echo "row=$x"; adb shell true < /dev/null; done
row=a
row=b
row=c
```

Exit status is 0 in both cases and there is no error. The first version looks exactly like a device
with one package on it. Put `< /dev/null` on every `adb` call inside a pipeline-fed loop.

### 13. Half my `adb shell` commands fail with a path under `C:/Program Files/Git/`. What?

You are on Git Bash, and MSYS2's path-conversion layer is rewriting your **device** paths into
**host** paths before `adb` ever sees them. Measured in this session:

<!-- lint:allow -- the mangled form is the point -->
```
$ adb shell ls -la /sdcard/
ls: C:/Program: No such file or directory
ls: Files/Git/sdcard/: No such file or directory

$ adb shell 'ls -la /sdcard/'
total 108
drwxrwx--- ...
```

The error names a Windows directory, so it reads as an adb problem or a broken installation.

The confusing part is that it is *selective*. Every Android top-level path tested was rewritten —
`/system`, `/data`, `/dev`, `/sdcard`, `/apex`, `/storage`, `/vendor`, `/product`, `/odm`, `/oem`,
`/mnt`, `/cache` — **except `/proc`**, which MSYS treats as a virtual mount with no Windows
equivalent and passes through untouched. So `adb shell cat /proc/net/tcp` works unquoted and
`adb shell ls /sdcard/` <!-- lint:allow --> does not, on the same line of the same sheet.

Quote the device-side command and it goes away. `MSYS_NO_PATHCONV=1` also works. Harmless on Linux
and macOS — but this repository is written on Git Bash, and the linter counts **121 unquoted device
paths across 81 markdown files** right now.

### 14. Is the router safe to edit if I spot a mistake in it?

No — edit the generator. Anything in `references/` beginning `cheatsheet-index` carries a
`GENERATED FILE` header and will be overwritten on the next run.

This is not pedantry. A sibling chapter's generated index once carried 1,495 broken links, and the
right fix was four lines in the generator, not 1,495 lines in the output. Patching output leaves the
next run to recreate the defect.

### 15. What is `--verify-links` for? Doesn't the repo already have a link checker?

It does, and it hid the problem for months. The repo checker had a category that excused links
pointing into chapters that did not exist yet, and it never re-asked whether the chapter was *still*
unwritten. As chapters landed, wrong paths pointing at them kept falling into the excused bucket.

`--verify-links` resolves every link the generator emits against the filesystem, from the directory
the file is actually written into. On its first run it found **58 broken of 1,595** — three because
this chapter's README did not exist yet, and 55 from a defect nobody predicted: the generator quotes
each sheet's own subtitle line, and those subtitles contain links written relative to the *chapter*
directory. Copying text across a depth boundary is a link operation.

You would never have caught those by eye. That is the point.

### 16. Why is a file in `references/` two levels down and not one?

Because the repository root contains `76-CheatSheets/`, and `76-CheatSheets/` contains
`references/`. So from `76-CheatSheets/references/cheatsheet-index.md`:

```
../          -> 76-CheatSheets/
../../       -> repository root
../../33-Storage/cheatsheet.md      correct
../33-Storage/cheatsheet.md         resolves to 76-CheatSheets/33-Storage/... which does not exist
```

The same applies inside `labs/` and `examples/`. This produced 1,495 broken links in this repository
once already.

### 17. Why does the linter report and never fix?

Because another worker is repairing those exact lines right now, and two agents writing to one file
is how a repository loses content. A linter with a `--fix` mode would have rewritten prose someone
else was mid-way through editing.

It is also the honest division of labour: the detector is the part that did not exist, and it is the
part that keeps working after the repairs land.

### 18. Some broken commands in this chapter are deliberate. Won't the linter flag those?

They are marked. A `lint:allow` marker on the line, on the line above, or on the line above the
fenced block suppresses the rule there — and `--show-suppressed` lists them anyway, so a marker
cannot hide a real defect from an audit. This chapter carries 17 suppressed counter-examples and 0
live findings against itself.

Rule ids are matched **exactly**: `lint:allow SU-DASH-C` does not also silence `SU-DASH-C-BARE`. Use
a bare `lint:allow` when you really mean the whole line. An exemption that quietly widens is how an
exemption category becomes a place defects accumulate.

### 19. Two sweeps for the same defect returned 376 and about 110. Who is right?

Both counted honestly; one detector was narrower than it looked. The earlier sweep was a hand-written
one-liner:

```
Select-String -Pattern "adb\s+(-[des]\s+\S+\s+)?shell\s+su\s+-c\s+'"
```

That pattern requires `su` to follow `shell` with nothing between them, so it only sees the
**unquoted** form, and it reported "~105–118 broken command lines across ~37–50 markdown files".
[`scripts/lint-commands.py`](scripts/lint-commands.py) matches the quoted forms too. Decomposition,
with the arithmetic closed:

| Form | Count |
|---|---:|
| `adb … shell "su -c …` | 283 |
| `adb … shell su -c …` | 79 |
| `adb … shell 'su -c …` | 13 |
| `adb … shell \"su -c …` | 1 |
| **Total** | **376** across 146 files |
| Unexplained | **0** |

The double-quoted form is the more common one and is invisible to the earlier detector — 283 of the
376, about 75% of the defect, so the true scale is roughly three times the first estimate. This is
the same shape as the link-checker defect this repository records against itself, where an unaudited
`forward` exemption hid 1,512 broken links: **a detector's blind spot is invisible in its output.**
Neither count was dishonest, and comparing them is how the blind spot was found — which is the
argument for running two detectors with different regexes over the same corpus and explaining the
difference, rather than trusting the one that has always been there.

### 20. Why do I need to check `mount | grep cacerts` before a TLS test?

Because a rooting stack can replace the system CA store with a tmpfs and bind-mount an interception
CA into it. On one device this repository used, `/system/etc/security/cacerts` was an APatch tmpfs
containing 139 certificates including the proxy's.

The consequence is severe and easy to miss: **a successful intercept on that device does not prove
the app trusts user-installed CAs**, because the proxy CA is in the *system* store. That is exactly
the distinction two chapters here are about, and it cannot be measured on such a device without first
undoing the modification.

### 21. Why does grepping decompiled code for `FLAG_SECURE` find nothing?

Because it is `public static final int FLAG_SECURE = 8192` — verified with `javap -constants` against
`android-35`'s `android.jar`. `javac` folds compile-time constants at the call site, so the *name*
never reaches the DEX; only the literal `0x2000` does.

Search for the constant, or hook `Window.setFlags` at runtime and watch what is actually passed. The
general lesson generalises well past this one flag: **a `static final` primitive has no identity in
compiled output.**

### 22. A grep found 132 matches. Is that 132 findings?

It was 132 false positives, measured. Three independent sweeps in this repository:

| Corpus | Raw hits | Leads | Survived validation |
|---|---:|---:|---:|
| A 17 MB commercial app | 16,836 | 168 | 2 of 17 in the HIGH band |
| A public training APK | 7,346 | 9 | 2 |
| Real Chrome data | 132 | 132 | **0** |

A sweep produces leads, not findings, and confidence ranking is not severity ranking — in the first
sweep the genuinely interesting finding sat at MEDIUM while 15 of 17 HIGH-band leads were rejected by
hand.

### 23. I only have an emulator. Is my testing worthless?

No — but three questions it answers *wrongly* rather than not at all, which is the dangerous category:

- **Verified boot.** `ro.boot.verifiedbootstate` is the **empty string**, not `orange`, so the
  widely-written `!"orange".equals(state)` returns `true` — the check passes on the least trustworthy
  platform it can meet.
- **Hardware-backed keys.** Every key is `SOFTWARE` and `hardwareEnforced` is empty, **and the
  attestation chain still verifies perfectly**. A valid chain proves the chain, not the hardware.
- **Anything fastboot.** There is no bootloader. `adb reboot bootloader` returns 0, reboots, and
  comes back as Android in about 40 seconds while `fastboot devices` never sees it.

Everything else — IPC, storage, manifest, TLS, hooking, instrumentation, the whole app-layer surface
— is perfectly measurable. Just record which device produced each claim.

### 24. Should I print this chapter?

`cheatsheet.md` is designed for it: dense, table-first, no prose. The README is not — it explains
*why*, and a printed explanation is a chapter with the links removed. Print the sheet, keep the
README open.

### 25. What is the single most useful habit from this chapter?

Run the four session-start commands before you trust anything:

```bash
adb devices -l
adb shell getprop ro.build.version.sdk
adb shell "su 0 id"
adb shell "sh -c 'echo A; echo B'"
```

Which device, which API level, which `su` form, and whether your quoting survives. Thirty seconds,
and it removes four whole categories of wrong answer for the rest of the day.
