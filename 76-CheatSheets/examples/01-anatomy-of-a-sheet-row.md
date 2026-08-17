# Example 01 — The anatomy of a cheat-sheet row

Four rows, each shown as it is usually written and as it should be written, with the exact
measurement that separates them. All four "bad" versions are real shapes that appear in published
Android security cheat sheets, including some in this repository.

Read this before writing a row of your own. It is the difference between a sheet that saves an hour
and one that costs an hour.

---

## The four properties every row needs

| Property | The question it answers | What goes wrong without it |
|---|---|---|
| **Vantage** | Which uid and SELinux domain performs the operation? | The reader runs it from `adb shell` and reports a result an app cannot reproduce |
| **Device class** | Phone, emulator, `userdebug`, production? | The reader runs it on the wrong device and gets an answer, not an error |
| **Provenance** | Was this executed, and against what? | The reader cannot tell measurement from folklore |
| **Failure shape** | What does it look like when it does *not* work? | The reader mistakes a silent failure for a negative result |

The fourth is the one almost nobody writes and the one that costs the most, because a command that
fails *loudly* is a five-second problem.

---

## Row 1 — the root check

### As usually written

<!-- lint:allow -- the bad row is the subject of Row 1 -->
```
| `adb shell ls /system/xbin/su` | Check for the su binary |
```

Everything about that row is true and it will still mislead you.

### What was measured

On `sdk_gphone16k_x86_64` (Android 15 / API 35, `userdebug`, **rooted with Magisk 30.7**), with
`scripts/vantage.sh`:

```
probe                      ls -l /system/xbin/su
  shell    -rwsr-x--- 1 root shell 51224 2025-01-23 23:03 /system/xbin/su
  root     -rwsr-x--- 1 root shell 51224 2025-01-23 23:03 /system/xbin/su
  app      ls: /system/xbin/su: Permission denied

probe                      test -e /system/xbin/su
  shell    EXISTS
  root     EXISTS
  app      NOT-VISIBLE
```

`/system/xbin` is mode `0750 root:shell`. `adb shell` is in the `shell` group; an application uid is
not. So the same question, asked from the two places that matter, gives opposite answers on a device
that is unambiguously rooted.

And in Java it is worse than "opposite", because `File.exists()` collapses three distinct conditions
into one boolean:

| Real condition | `errno` | `File.exists()` |
|---|---|---|
| The file is absent | `ENOENT` | `false` |
| The file is present and forbidden | `EACCES` | `false` |
| An ancestor directory is unlistable | `EACCES` | `false` |

`new File("/system/xbin/su").exists()` therefore has **zero discriminating power on a rooted
device** — the only kind of device where it could ever matter.

### As it should be written

```
| `adb shell "ls -l /system/xbin/su"` | `any` | `all` | Present and setuid on AOSP builds. **`shell` sees it, an app gets `EACCES`** (`/system/xbin` is `0750 root:shell`), so `File.exists()` returns `false` from an app on a rooted device. Not a usable root check. |
| `adb shell "grep -c magisk /proc/self/mountinfo"` | `any` | `all` | Returned **3** from `shell`, root and an app uid. Needs no privilege — which is what makes it usable. |
```

Note what the good row does that the bad one does not: it says which vantage sees what, it names the
mode bits that cause it, it states the consequence for the API a developer would actually use, and
it offers the replacement.

---

## Row 2 — the Magisk version

### As usually written

<!-- lint:allow -- this IS the broken row under discussion -->
```
| `adb shell su -c 'magisk -v'` | Magisk version |
```

This row exists, in this shape, in several published sheets. It is wrong in two independent ways and
neither produces an error message that names the cause.

### What was measured

<!-- lint:allow -- transcript of the failing forms, quoted on purpose -->
```
$ adb shell "su -c 'magisk -v'"
su: invalid uid/gid '-c'

$ adb shell "su 0 magisk -v"
su: failed to exec magisk: No such file or directory

$ adb shell "su 0 /debug_ramdisk/magisk -v"
30.7:MAGISK:R
```

**Failure one — the `su` form.** AOSP's `su` takes `su <uid> <cmd>`. It ships on every `userdebug`
build and every emulator, and it rejects `-c` outright. The message reads as *"this device is not
rooted"*, and at least one chapter of this repository nearly recorded exactly that.

**Failure two — the quoting.** `adb shell` does not preserve quoting; the whole line arrives at the
device as separate argv words. So even on a phone whose Magisk `su` *does* accept `-c`, the command
arrives as `su -c magisk -v` and **`-v` is consumed by `su`, not by `magisk`**. The row prints `su`'s
version under a heading that says "Magisk version", and the reader has no way to tell.

**Failure three, found while writing this chapter.** The correct `su 0` form *still* fails, because
`magisk` is not on root's `PATH` on this image:

```
$ adb shell "su 0 sh -c 'echo $PATH'"
/product/bin:/apex/com.android.runtime/bin:/apex/com.android.art/bin:/system_ext/bin:/system/bin:/system/xbin:/odm/bin:/vendor/bin:/vendor/xbin
```

`/debug_ramdisk` is not in it. The absolute path is required.

### As it should be written

```
| `adb shell "su 0 /debug_ramdisk/magisk -v"` | `root` | `avd` | `30.7:MAGISK:R`. The absolute path is required — `magisk` is not on root's `PATH`. On a Magisk phone the binary is usually at `/data/adb/magisk/magisk`; check `mount \| grep magisk` first. |
| `adb shell "su -c 'magisk -v'"` <!-- lint:allow --> | — | — | **Does not work.** `-c` is rejected by AOSP `su`; where it is accepted, `-v` is eaten by `su` and you get *su's* version. |
```

The second row is the important one. **A sheet that lists only the working form leaves the reader to
discover the broken one on their own time**, and it is a form they will meet, because it is
everywhere.

---

## Row 3 — the traffic check

### As usually written

```
| Install the CA and proxy the device | See TLS traffic |
```

### What is missing

Nothing about this is false. What is missing is the failure shape and one precondition, and the
precondition has already cost this repository a whole chapter's worth of conclusions.

A rooting stack can **replace the system CA store with a tmpfs and bind-mount an interception CA
into it**. On one device this repository used, `/system/etc/security/cacerts` was an APatch tmpfs
carrying 139 certificates, including the proxy's.

The consequence is severe and quiet: **a successful intercept on that device does not prove the app
trusts user-installed CAs**, because the proxy CA is in the *system* store. That is precisely the
distinction two chapters here exist to teach, and it cannot be measured on such a device at all
without undoing the modification first.

### As it should be written

```
| `adb shell "mount \| grep cacerts"` | `any` | `all` | **Run before any trust-store claim.** A tmpfs mounted here means the rooting stack has replaced the system store; a successful intercept then proves nothing about user-CA trust. |
| Install CA + proxy | `any` | `all` | Works if the app trusts user CAs. Silent failure looks like *no traffic at all* — check the proxy log for a TLS handshake before concluding the app pins. |
```

---

## Row 4 — the pipeline

### As usually written

<!-- lint:allow -- the buggy pipeline is the subject of this row -->
```bash
set -euo pipefail
readelf --dyn-syms lib.so | grep '^Java_' | head -5 || echo "not a JNI library"
```

This is careful, idiomatic shell. It is also a bug, and it is intermittent, which is worse.

### What was measured

<!-- lint:allow -- measured transcript of the failure -->
```
$ bash -c 'set -o pipefail; yes | head -3 >/dev/null; echo $?'
141
$ bash -c 'set -o pipefail; seq 1 100000 | grep -q 5; echo $?'
141
$ bash -c 'set -o pipefail; seq 1 100000 | grep -c 5 >/dev/null; echo $?'
0
$ bash -c 'set -o pipefail; seq 1 10000 | head -3 >/dev/null; echo $?'
0
```

`head` and `grep -q` exit the instant they have what they need. That closes the pipe; the writer
upstream dies of `SIGPIPE`; `pipefail` promotes 141 to the pipeline's status. So the `||` fallback
fires **because the pattern matched**.

In one real script in this repository this printed **"not a JNI library" directly below a list of
that library's JNI exports.**

The last line above is the reason it is so hard to diagnose: with a *small* producer, the writer
finishes before the consumer closes the pipe, and the status is 0. The same script passes on Monday
against a small library and fails on Tuesday against a large one, and the error blames the data every
time.

### As it should be written

```bash
# Test the CONTENT, not the exit status. `grep -c` reads all of its input, so it
# never provokes SIGPIPE upstream.
n=$(readelf --dyn-syms lib.so | grep -c '^Java_')
if [ "$n" -eq 0 ]; then
    echo "no statically-registered JNI symbols (may still use RegisterNatives)"
else
    readelf --dyn-syms lib.so | grep '^Java_' | head -5
fi
```

Two things changed. The status test became a content test, and the negative branch stopped
overclaiming — "no `Java_` symbols" and "not a JNI library" are different statements, because dynamic
registration through `RegisterNatives` in `JNI_OnLoad` leaves no mangled symbols at all.

---

## The checklist for a row you are about to write

- [ ] Did I **run it**, in exactly this form? If not, is it labelled `unrun`?
- [ ] Which **uid** performed the operation? Is that the uid the reader will have?
- [ ] Which **device** was it measured on? Does an emulator differ? Does an OEM build?
- [ ] What does **failure** look like — an error, or a plausible wrong answer?
- [ ] If a well-known **broken form** exists, is it listed and marked broken?
- [ ] Does the row **overclaim**? "No symbols found" is not "not a JNI library".

A row that passes all six is longer than a row that does not. That is the correct trade: the reader
pays a few extra seconds reading and saves an hour not being misled.

---

## See also

- [`../README.md`](../README.md) §2 — the `Needs` and `Device` tag vocabulary
- [`../README.md`](../README.md) §6 — thirty-three more rows where the obvious command lies
- [`02-vantage-transcript.md`](02-vantage-transcript.md) — the raw session behind Row 1
- [`../scripts/vantage.sh`](../scripts/vantage.sh) — produce Row 1's table for any path
- [`../scripts/lint-commands.py`](../scripts/lint-commands.py) — catch Rows 2 and 4 mechanically
