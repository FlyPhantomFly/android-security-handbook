# Lab 02 — The gate matrix: what actually decides

> **Objective.** Determine, by experiment rather than by reading, which of three variables decides
> whether `am instrument` is permitted: the target's `android:debuggable` flag, the signing
> relationship between the test APK and the target, or the identity of the caller. Read the refusal
> messages, which name each check by name. Then explain why two widely repeated claims about this are
> both wrong.
>
> **Difficulty.** Intermediate. The commands are easy; the discipline is not. This lab is really
> about experimental design.
>
> **Time.** 60–90 minutes.

**Prerequisites:** [Lab 01](lab-01-first-instrumentation.md) completed ·
[../README.md §3.9–§3.10](../README.md) — **but try to resist reading §3.9 until step 6** ·
[10 — APK Internals](../../10-APK-Internals/README.md) for signing blocks ·
[21 — App Sandbox](../../21-App-Sandbox/README.md)

All five artefacts are chapter fixtures. See [SECURITY.md](../../SECURITY.md) for
authorised-testing scope.

---

## 0. The claims under test

Two statements you will find repeated confidently, in blog posts, in StackOverflow answers, and in
at least one commercial mobile security course:

> **Claim A.** *"You can only instrument an app that is `android:debuggable="true"`."*
>
> **Claim B.** *"The test APK must be signed with the same key as the app — unless the app is
> debuggable, in which case any test APK works."*

They cannot both be right, and it turns out neither is. Your job is to establish that with evidence
rather than take this lab's word for it.

Write down, before you run anything, what you expect each of these to do:

| # | Target | Test APK key | Caller | Your prediction |
|---|---|---|---|---|
| 1 | debuggable | same | shell | |
| 2 | release | same | shell | |
| 3 | release | different | shell | |
| 4 | debuggable | different | shell | |
| 5 | debuggable | different | root | |
| 6 | release | different | root | |

Predictions written down before the experiment are the difference between a measurement and a
rationalisation. This chapter's own author got row 5 wrong.

---

## 1. Understand the apparatus before you use it

The five artefacts from lab 01 exist precisely so that each pair differs in **one bit**:

| Artefact | Sources | `debuggable` | Key | `testOnly` |
|---|---|---|---|---|
| `vault-release.apk` | `examples/vault-target/` | absent | A | — |
| `vault-debuggable.apk` | **the same sources** | true | A | — |
| `probe-sigA.apk` | `examples/vault-probe/` | — | A | false |
| `probe-sigB.apk` | **the same sources** | — | B | false |
| `probe-testonly.apk` | the same sources, manifest patched | — | A | true |

The two target builds are the *same Java, the same manifest file, the same everything* — the only
difference is that one build passed `aapt2 link`'s debug-mode flag, which injects
`android:debuggable="true"` into the application node. Confirm it rather than believe it:

```bash
# host
cd 66-Instrumentation/examples
OUTDIR=/tmp/ch66 ./build-instrumentation-fixtures.sh 2>&1 | tail -14
```

```
=== fixture self-check ===
vault-release      debuggable=0
vault-debuggable   debuggable=1
probe-testonly     testOnly=1
probe-sigA         testOnly=0

signer digests (these must differ between sigA and sigB):
  vault-release    Signer #1 certificate SHA-256 digest: 4b7cce36...
  probe-sigA       Signer #1 certificate SHA-256 digest: 4b7cce36...
  probe-sigB       Signer #1 certificate SHA-256 digest: 7800573a...
```

Check it independently as well, because a fixture you have not verified will teach you the wrong
thing quietly:

```bash
# host
for a in vault-release vault-debuggable; do
    printf '%-18s ' "$a"
    aapt2 dump xmltree --file AndroidManifest.xml /tmp/ch66/$a.apk | grep -c debuggable
done
for a in vault-release probe-sigA probe-sigB; do
    printf '%-14s ' "$a"
    apksigner verify --print-certs /tmp/ch66/$a.apk | grep -i 'SHA-256 digest' | head -1
done
```

`vault-release` and `probe-sigA` must share a digest. `probe-sigB` must not.

### 1.1 Record the device, and record `ro.debuggable`

```bash
# host
adb devices -l
adb shell getprop ro.product.model
adb shell getprop ro.build.version.sdk
adb shell getprop ro.build.type
adb shell getprop ro.debuggable
```

**This matters more in this lab than anywhere else in the chapter.** A `userdebug` build reports
`ro.debuggable=1` and takes a more permissive branch in several platform checks. The device this lab
was authored on is `userdebug`, and step 7 says exactly which of your rows that qualifies.

---

## 2. Run the matrix by hand, once

Do this manually before you use the script. You want to see the transcript.

```bash
# host -- ROW 1: debuggable target, matching key, shell
adb uninstall com.pentest.ch66.vault.test 2>/dev/null
adb install -r /tmp/ch66/vault-debuggable.apk
adb install -r /tmp/ch66/probe-sigA.apk
adb shell dumpsys package com.pentest.ch66.vault | grep -m1 'flags='
adb shell am instrument -w -r \
    com.pentest.ch66.vault.test/com.pentest.ch66.probe.VaultProbe 2>&1 | tail -4
```

```
    flags=[ DEBUGGABLE HAS_CODE ALLOW_CLEAR_USER_DATA ]
INSTRUMENTATION_RESULT: write.setPremium=ok
INSTRUMENTATION_CODE: -1
```

```bash
# host -- ROW 2: same, but the target is the RELEASE build
adb install -r /tmp/ch66/vault-release.apk
adb shell dumpsys package com.pentest.ch66.vault | grep -m1 'flags='
adb shell am instrument -w -r \
    com.pentest.ch66.vault.test/com.pentest.ch66.probe.VaultProbe 2>&1 \
  | grep -E 'read.prefs.api_key|INSTRUMENTATION_CODE'
```

```
    flags=[ HAS_CODE ALLOW_CLEAR_USER_DATA ]
INSTRUMENTATION_RESULT: read.prefs.api_key=ch66-APIKEY-3f9a1c
INSTRUMENTATION_CODE: -1
```

**Row 2 is the end of Claim A.** No `DEBUGGABLE` in the flags, and the instrumentation ran, read the
app's `SharedPreferences`, and returned `RESULT_OK`.

`adb install -r` of `vault-release` over `vault-debuggable` succeeded because both are
signed with key A. Turning `debuggable` off is not a downgrade as far as the package manager is
concerned.

```bash
# host -- ROW 3: release target, DIFFERENT key
adb uninstall com.pentest.ch66.vault.test
adb install -r /tmp/ch66/probe-sigB.apk
adb shell am instrument -w -r \
    com.pentest.ch66.vault.test/com.pentest.ch66.probe.VaultProbe 2>&1 | head -3
```

```
INSTRUMENTATION_STATUS: Error=Permission Denial: starting instrumentation
  ComponentInfo{com.pentest.ch66.vault.test/com.pentest.ch66.probe.VaultProbe}
  from pid=14292, uid=2000 not allowed because package com.pentest.ch66.vault.test
  does not have a signature matching the target com.pentest.ch66.vault
INSTRUMENTATION_STATUS: id=ActivityManagerService
INSTRUMENTATION_STATUS_CODE: -1
```

Read that message carefully. It names the caller (`uid=2000`), the check (**signature matching**) and
both packages. That is a well-written error and you should be pleased to see it.

```bash
# host -- ROW 4: the decisive cell. DEBUGGABLE target, different key.
adb install -r /tmp/ch66/vault-debuggable.apk
adb shell dumpsys package com.pentest.ch66.vault | grep -m1 'flags='
adb shell am instrument -w -r \
    com.pentest.ch66.vault.test/com.pentest.ch66.probe.VaultProbe 2>&1 | head -2
```

```
    flags=[ DEBUGGABLE HAS_CODE ALLOW_CLEAR_USER_DATA ]
INSTRUMENTATION_STATUS: Error=Permission Denial: starting instrumentation ... does not have a
  signature matching the target com.pentest.ch66.vault
```

**Row 4 is the end of Claim B.** The target is debuggable and the refusal is identical. `debuggable`
does not waive the signature check.

```bash
# host -- ROWS 5 and 6: same mismatched probe, but call it as root.
# NOTE the argument form: this AVD's su takes `su 0 <cmd>`, NOT `su -c <cmd>`.
adb shell "su 0 am instrument -w -r \
    com.pentest.ch66.vault.test/com.pentest.ch66.probe.VaultProbe" 2>&1 \
  | grep -E 'read.prefs.api_key|Permission Denial|INSTRUMENTATION_CODE'

adb install -r /tmp/ch66/vault-release.apk
adb shell "su 0 am instrument -w -r \
    com.pentest.ch66.vault.test/com.pentest.ch66.probe.VaultProbe" 2>&1 \
  | grep -E 'read.prefs.api_key|Permission Denial|INSTRUMENTATION_CODE'
```

```
INSTRUMENTATION_RESULT: read.prefs.api_key=ch66-APIKEY-3f9a1c
INSTRUMENTATION_CODE: -1
INSTRUMENTATION_RESULT: read.prefs.api_key=ch66-APIKEY-3f9a1c
INSTRUMENTATION_CODE: -1
```

> **The `su` argument form is a standing trap on this emulator.** `adb shell su -c 'cmd'` fails <!-- lint:allow SU-DASH-C SU-DASH-C-BARE -- the broken form, quoted as the counter-example this warning teaches -->
> twice over: the outer shell strips the quotes, and this AVD's AOSP `su` rejects `-c` with
> `su: invalid uid/gid '-c'`, which reads exactly like "not rooted". Three chapters in this
> repository hit it independently. Use `su 0 <cmd>` inside outer double quotes, as above. If your
> device runs Magisk's `su`, `su -c` does work — check with `adb shell "su 0 id"` first and use
> whichever form returns uid 0.

If your device is not rooted, rows 5 and 6 are unavailable. Record that as "not measured on
this device" rather than assuming the answer; a missing measurement honestly labelled is worth more
than a guess.

---

## 3. Now use the script

```bash
# host
cd 66-Instrumentation/scripts
OUTDIR=/tmp/ch66 ./am-instrument-matrix.sh
```

It runs all eight rows and cleans up after itself. Compare its output line by line against what you
got by hand. If any row differs, the difference is your finding — investigate it rather than assuming
the script is right.

```
ROW 1  target=debuggable  probe=sigA(match)   caller=shell
   target flags=[ DEBUGGABLE HAS_CODE ALLOW_CLEAR_USER_DATA ]
   RESULT   OK   INSTRUMENTATION_RESULT: read.prefs.api_key=ch66-APIKEY-3f9a1c
            INSTRUMENTATION_CODE: -1

ROW 2  target=release     probe=sigA(match)   caller=shell
   target flags=[ HAS_CODE ALLOW_CLEAR_USER_DATA ]
   RESULT   OK   ...

ROW 3  target=release     probe=sigB(differ)  caller=shell
   RESULT   REFUSED
            ... not allowed because package com.pentest...

ROW 4  target=debuggable  probe=sigB(differ)  caller=shell
   RESULT   REFUSED
            ... not allowed because package com.pentest...

ROW 5  target=debuggable  probe=sigB(differ)  caller=root
   RESULT   OK   ...

ROW 6  target=release     probe=sigB(differ)  caller=root
   RESULT   OK   ...
```

---

## 4. Row 7 — is `am instrument` a shell privilege?

Rows 1 to 6 varied the target and the key. Row 7 varies the **caller**, downward instead of upward.
`run-as` drops you to the target package's UID, which needs the target to be debuggable — so this row
uses `vault-debuggable` and the *matching* probe, isolating caller identity as the only variable.

```bash
# host
adb install -r /tmp/ch66/vault-debuggable.apk
adb uninstall com.pentest.ch66.vault.test 2>/dev/null
adb install -r /tmp/ch66/probe-sigA.apk

adb shell "run-as com.pentest.ch66.vault am instrument -w -r \
    com.pentest.ch66.vault.test/com.pentest.ch66.probe.VaultProbe" 2>&1 | head -2
```

```
Permission Denial: startInstrumentation asks to run as user -2 but is calling from uid u0a210;
  this requires android.permission.INTERACT_ACROSS_USERS_FULL
```

Do not stop here. **That is not the instrumentation gate.** `am` defaults `--user` to `current`,
which is the constant `-2`, and resolving it needs a permission no app holds. Pin the user:

```bash
# host
adb shell "run-as com.pentest.ch66.vault am instrument -w -r --user 0 \
    com.pentest.ch66.vault.test/com.pentest.ch66.probe.VaultProbe" 2>&1 | head -2
```

```
Permission Denial: disable hidden API checks from pid=14505, uid=10210
  requires android.permission.DISABLE_HIDDEN_API_CHECKS
```

A **different** denial. Still not the gate: `am` also sets a test-API access flag by default, because
tests are expected to use `@TestApi` members, and the service enforces a permission for it. Turn it
off — and confirm that the flag reads backwards, because the default is the permissive one:

```bash
# host
adb shell "run-as com.pentest.ch66.vault am instrument -w -r --user 0 --no-test-api-access \
    com.pentest.ch66.vault.test/com.pentest.ch66.probe.VaultProbe" 2>&1 \
  | grep -E 'read.prefs.api_key|INSTRUMENTATION_CODE'
```

```
INSTRUMENTATION_RESULT: read.prefs.api_key=ch66-APIKEY-3f9a1c
INSTRUMENTATION_CODE: -1
```

**An ordinary application UID started an instrumentation.** `am instrument` is not a shell privilege.

> **State the bound of what you just measured.** The caller here was the *target package's own* UID,
> so this is self-instrumentation from an app UID. Whether an app UID can instrument a **different**
> co-signed package needs a third fixture and was not measured. Report the weaker claim.
>
> The realistic consequence is still substantial: a vendor shipping several co-signed packages has
> built a path for one of them to run code inside another's process, at that other's UID, on an
> unrooted retail device.

---

## 5. Row 8 — `android:testOnly`, which is a different kind of gate entirely

```bash
# host
adb uninstall com.pentest.ch66.vault.test 2>/dev/null
adb install -r /tmp/ch66/probe-testonly.apk
```

```
Failure [INSTALL_FAILED_TEST_ONLY: Failed to install test-only apk. Did you forget to add -t?]
```

```bash
# host
adb install -r -t /tmp/ch66/probe-testonly.apk
adb shell pm list instrumentation
adb shell am instrument -w -r \
    com.pentest.ch66.vault.test/com.pentest.ch66.probe.VaultProbe 2>&1 | tail -2
```

```
Success
instrumentation:com.pentest.ch66.vault.test/com.pentest.ch66.probe.VaultProbe (target=com.pentest.ch66.vault)
INSTRUMENTATION_RESULT: write.setPremium=ok
INSTRUMENTATION_CODE: -1
```

Two conclusions:

1. `testOnly` is an **install-time** gate and it costs one character to defeat.
2. Once installed, a `testOnly` package is an ordinary package. It appears in
   `pm list instrumentation`, and it instruments normally.

So `testOnly` protects a **distribution channel**, not a device. Its value to a reviewer is what it
implies about the pipeline that produced the artefact — see
[../examples/enterprise-ci-review.md](../examples/enterprise-ci-review.md) §4.

---

## 6. Write the rule yourself

Before reading §3.9 of the chapter, fill this in from your own transcripts:

> `ActivityManagerService.startInstrumentation()` refuses unless ______________________,
> or the caller is ______________________. The attribute `android:debuggable` plays
> ______________________ part in this decision.

Then compare against the chapter. If your rule and the chapter's differ, one of you is wrong and the
transcripts decide.

### 6.1 What `debuggable` *does* gate

You have just shown it does not gate instrumentation. It does gate a set of things that are easy to
confuse with it, and it is worth being able to list them:

| Capability | Requires `debuggable`? |
|---|---|
| `run-as <pkg>` from the shell | **Yes** |
| JDWP debugger attach | **Yes** |
| `adb backup` of the app's data | **Yes** on modern versions |
| Frida attaching to a **non**-debuggable app with a root-privileged server | No |
| `am instrument` with a matching signature | **No** — measured |

That table is why Claim A is so persistent: `debuggable` genuinely is the gate for three of the five
rows, and people generalise.

---

## 7. The honest caveat — read this before you cite your own results

Your device almost certainly reports `ro.debuggable=1` if it is an emulator or a `userdebug` build.
Several platform checks take a more permissive branch on such a build, and
`ActivityManagerService.startInstrumentation()` contains at least one `Build.IS_DEBUGGABLE`-gated
branch in the AOSP tree.

Grade your own rows accordingly:

| Rows | Status on a `userdebug` build | Why |
|---|---|---|
| 3 and 4 (**refusals**) | **Solid** | A permissive build cannot manufacture a refusal. These are the rows that carry the argument against both claims |
| 1 and 2 (matching signature) | **Solid** | This is the documented, supported path. Nothing about it is `userdebug`-specific |
| 5 and 6 (root bypass) | **Upper bound** | Re-run on a `user` build before relying on them |
| 7 (app UID) | **Upper bound** for the same reason | |

Writing "measured on a `userdebug` build, rows 5 and 6 not confirmed on a `user` build" costs one
sentence and is the difference between a result and an assertion. This chapter had no second device
available and says so in §3.9; do the same.

---

## 8. Success criteria

- [ ] You wrote predictions for all six rows **before** running anything.
- [ ] You verified the fixtures independently: two `debuggable` counts, three signer digests.
- [ ] Row 2 succeeded against a target with no `DEBUGGABLE` flag, and you can quote the flags line.
- [ ] Rows 3 and 4 both refused, with a message that names the signature check and the caller UID.
- [ ] You can state why row 4 in particular disproves Claim B.
- [ ] Rows 5 and 6 succeeded as root, or you recorded that the device is not rooted.
- [ ] Row 7 needed `--user 0 --no-test-api-access`, and you can explain why **neither** of those two
      denials was the instrumentation gate.
- [ ] Row 8: you saw `INSTALL_FAILED_TEST_ONLY` and then defeated it with `-t`.
- [ ] You wrote the rule in §6 in your own words before reading the chapter's version.
- [ ] You labelled which of your rows are upper bounds because of `ro.debuggable`.

---

## 9. Clean up

```bash
# host
cd 66-Instrumentation/examples
./build-instrumentation-fixtures.sh --uninstall
adb shell pm list instrumentation     # expect nothing
```

The matrix script cleans up after itself unless you pass `--keep`.

---

## 10. Hints

<details>
<summary>Every row refuses, including row 1</summary>

Your two keystores are probably not the ones the APKs were signed with. `OUTDIR` holds `keyA.ks` and
`keyB.ks`, and the script only generates them if they are absent — so building into a *new* `OUTDIR`
produces new keys and everything stops matching. Use one `OUTDIR` throughout, or delete the whole
directory and rebuild all five artefacts together.
</details>

<details>
<summary>Row 5 says "invalid uid/gid '-c'"</summary>

You used `su -c`. This AVD ships AOSP's `su`, which takes `su <uid> <command>`. Use
`adb shell "su 0 am instrument ..."`. The failure mode is nasty because it reads as "not rooted".
</details>

<details>
<summary>run-as says "unknown package" or "not debuggable"</summary>

`run-as` needs the target to carry `android:debuggable="true"`, so row 7 must use
`vault-debuggable.apk`. If you have `vault-release.apk` installed from row 6, reinstall the
debuggable build first.
</details>

<details>
<summary>Row 2 fails to install with INSTALL_FAILED_UPDATE_INCOMPATIBLE</summary>

Something signed with a different key is installed under that package name. Uninstall it first.
the package manager will happily replace a debuggable build with a release build and vice
versa, as long as the key matches — the flag is not part of the upgrade check.
</details>

<details>
<summary>You want to see the server-side stack trace, not just the message</summary>

Do not filter the output. The full `SecurityException` includes a `Caused by: android.os.RemoteException:
Remote stack trace:` block naming `com.android.server.am.ActivityManagerService.startInstrumentation`
and the frames beneath it. That block is how this chapter confirmed which AOSP file makes the
decision, without guessing. The line number in it belongs to your device's build and should not be
carried anywhere else.
</details>

<details>
<summary>You want to test a fourth variable: what if the two packages share a sharedUserId?</summary>

Good instinct, and it is a genuine extension. `android:sharedUserId` requires both packages to be
signed identically anyway, so it cannot separate the variables — but it changes the *data directory*
relationship, which is a different and interesting result. Build it and record what you find; the
chapter does not measure it.
</details>

---

## 11. What to read next

- **[Lab 03 — ordering and vantage](lab-03-ordering-and-vantage.md)**: now that you can get in,
  measure exactly how early you arrive and what that lets you pre-empt — plus the trap that silently
  turns an app-vantage measurement into a shell one.
- **Chapter [§5.1 and §5.9](../README.md)** for how to write up what you just measured without
  overstating it.
- **[38 — Tamper Detection](../../38-TamperDetection/README.md)** for the other half of the
  re-signing path.
