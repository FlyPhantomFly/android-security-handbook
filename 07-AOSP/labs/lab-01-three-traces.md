# Lab 01 — Three traces, unaided

**Difficulty:** Beginner
**Time:** 3–4 hours
**Chapter:** [07 — AOSP](../README.md) §3.4, §4
**Setup required:** a web browser. Nothing else.

---

## Objective

Reproduce Traces A, B and C from [§4](../README.md#4-source-code-walkthrough-aosp) **without looking at
the chapter**, then run a fourth trace of your own choosing from a cold start.

This is the single most transferable skill in the chapter. Everything else — patching the platform,
auditing a vendor framework, explaining why a hook did not work — is an application of it.

---

## Why this lab has no setup

Because you do not need a checkout to read AOSP, and starting with a day-long `repo sync` teaches people
that reading AOSP is expensive. It is not. Open <https://cs.android.com/> and you are ready.

The only preparation is the one step people skip:

> **Set the branch selector (top right) to a release branch, not `main`.**
> Pick `android15-release` or the release matching a device you have. Reading `main` while reasoning
> about a shipped device is the single most common source of "the source says X but the device does Y".

---

## Part A — `Context.startActivity()`

Use [`../examples/01-trace-worksheet.md`](../examples/01-trace-worksheet.md). Print or copy it and fill
it in as you go.

### A1. Start

Search for `class:Context path:frameworks/base/core/java/android/content`.

**Record:** is `startActivity` abstract? What does that tell you about where the work happens?

### A2. Find the implementations

There are two that matter, and the difference between them is observable in real apps.

**Hint:** search `function:startActivity path:frameworks/base/core/java/android/app`.

**Record:** the two classes, and one behavioural difference between calling `startActivity` from an
`Activity` versus from an `Application` context.

### A3. Leave the process

Find the method in `Instrumentation` that both implementations converge on.

**Record:**
- The method name.
- What it does to the `Intent` immediately before sending it, and which exception that can throw.
  (This is a *sender-side* check. Note in your worksheet why a sender-side check is not a security
  boundary.)
- The method it calls on the way back that converts a numeric result into an exception.

### A4. Find the service

**Hint:** the call is `ActivityTaskManager.getService().startActivity(...)`. Read `getService()`.

**Record:**
- The name passed to `ServiceManager.getService(...)`.
- The AIDL file that defines the interface.
- The class that `extends IActivityTaskManager.Stub`, and which package it is in.

**Verify on a device**, if you have one:

```bash
adb shell service list | grep -i activity_task
adb shell service list -l | grep -A1 -i activity_task
```

### A5. Find the check

**Hint:** `ActivityTaskManagerService.startActivity` does very little itself. Follow it until you reach
`ActivityStarter`.

**Record:** at least five distinct things `ActivityStarter.executeRequest` checks or can abort on. For
each, write one sentence saying what it protects.

### A6. Cross the kernel

**Record:**
- The file and function in `frameworks/native/libs/binder/` where user space issues the `ioctl`.
- The `ioctl` command constant.
- The function in `drivers/android/binder.c` that handles a transaction.
- **The specific field the kernel sets from the sender's credentials, and one sentence on why the
  caller cannot forge it.**

Use the kernel project in Code Search's project selector, or
<https://android.googlesource.com/kernel/common/>.

### A7. Write the answer

In your worksheet, write one paragraph in complete sentences describing what happens when an app calls
`startActivity`. **If you cannot write it without the words "somehow" or "under the hood", the trace is
not finished.**

---

## Part B — `SharedPreferences.edit().putString().apply()`

Entirely in-process. Shorter, and it explains several behaviours that confuse people permanently.

### B1. Find the file path

Start at `Context.getSharedPreferences`. Follow it to the implementation and find the method that
computes the file's location.

**Record:** the exact on-disk path template, and which of the file's protections are cryptographic
(answer: none — say why the file is nonetheless not readable by other apps).

### B2. Find the mode restriction

Find where `MODE_WORLD_READABLE` and `MODE_WORLD_WRITEABLE` are rejected.

**Record:** which `targetSdk` triggers the rejection, and what happens on an app below it. Why is a low
`targetSdk` on a real app a finding in its own right?

### B3. `apply()` versus `commit()`

Read `SharedPreferencesImpl`. Find `commitToMemory`, `apply`, `commit` and `enqueueDiskWrite`.

**Record**, as a table:

| | `commit()` | `apply()` |
|---|---|---|
| Return type | | |
| Disk write synchronous? | | |
| In-memory update synchronous? | | |
| Failure visible to the caller? | | |
| Safe on the main thread? | | |

**Then answer:** if `apply()` is asynchronous, why are your preferences not lost when the process is
killed a moment later?

**Hint:** find `QueuedWork`, and find who calls `QueuedWork.waitToFinish()`.

**Record:** the class and the two lifecycle methods that call it, and one consequence for a *tester*
(when is the data guaranteed to be on disk?) and one for a *developer* (why is this a common source of
ANRs?).

### B4. The crash-safe write

Read `writeToFile`.

**Record:** the seven steps in order, including what happens to the existing file, when `fsync` is
called, and when the backup is deleted. Then answer: **if you find a `.xml.bak` file on a device, what
does it tell you, and why should you always list the `shared_prefs/` directory rather than reading one
file?**

### B5. Into the kernel

Follow `FileOutputStream.write` down through `libcore` to the syscall.

**Record:** the `libcore` class, the JNI file, and the syscall.

---

## Part C — `checkSelfPermission` to enforcement

The most important trace, and the one that resolves the most common beginner misconception in Android
security.

### C1. Start

`Context.checkSelfPermission`. Read it. It is two lines.

**Record:** what it passes as `pid` and `uid`, and — in one sentence — why that makes it a *query*
rather than an authorisation.

### C2. Follow it as far as you can

Follow `ContextImpl.checkPermission`.

> **This hop has moved between Android releases.** That is deliberate on the chapter's part. Do **not**
> look up the answer. Practise the procedure: read the method, follow whatever it calls, and keep going
> until you reach something that `extends` a `Stub`.

**Record:** every class you passed through, and the branch you were reading. Then switch the branch
selector to a different release and do it again.

**Record:** did the path change? This is the lesson — memorise the procedure, not the call graph.

### C3. Find the permission state

**Record:** the directory in `frameworks/base/services/core/java/com/android/server/pm/` that owns
permission state, and the file in AOSP that defines every platform permission with its protection level.

**Verify on a device:**

```bash
adb shell pm list permissions -f | grep -A4 CAMERA
adb shell dumpsys package com.android.settings | sed -n '/requested permissions/,/User 0/p'
```

### C4. Find the second gate

There is a permission layer *beside* the permission system that most people have never heard of.

**Hint:** `frameworks/base/services/core/java/com/android/server/appop/`.

**Record:** the four modes an operation can be in, and — the important part — **what the caller observes
when an operation is in the "ignore" mode.** Then answer: why does this make "the permission is granted"
insufficient to conclude anything?

**Verify on a device:**

```bash
adb shell appops get com.android.settings
adb shell appops set <some-app> COARSE_LOCATION ignore
# exercise the app's location feature and observe: empty result, no exception
adb shell appops set <some-app> COARSE_LOCATION allow
```

### C5. Find the *real* enforcement point

`checkSelfPermission` is a query. Find where the camera is actually gated.

**Hint:** `frameworks/av/services/camera/libcameraservice/`.

**Record:** the class, and the three independent layers below the permission model that also have to
permit the operation.

### C6. Answer the question

Write, in complete sentences: *"I hooked `checkSelfPermission` in the app process to return
`PERMISSION_GRANTED`. Why can I still not open the camera?"*

A complete answer names where the check actually happens, whose identity it uses, and where that
identity came from.

---

## Part D — A trace of your own

Pick one you have not seen. Suggestions, in rough order of difficulty:

| Question | Ends at |
|---|---|
| What does `getSystemService(CLIPBOARD_SERVICE)` then `getPrimaryClip()` enforce? | `ClipboardService`, plus app-ops and window focus |
| Why can an app not read another app's files? | Unix ownership set at install, plus SELinux |
| What does `startForegroundService` require? | `ActivityManagerService`, plus the notification requirement |
| How does `PendingIntent` mutability work? | `PendingIntentRecord` in `system_server` |
| What verifies an APK's signature at install? | `PackageManagerService` install path and `apksig` |
| How does `KeyStore` keep a key out of my process? | `system/security/keystore2/`, then the KeyMint HAL |

Fill in a fresh worksheet from scratch, with no hints. Time yourself.

**Target:** under 45 minutes for the whole trace, including writing the paragraph.

---

## Success criteria

- [ ] Three completed worksheets for Traces A, B and C, plus one of your own.
- [ ] For Trace A, you can name the kernel function and the field where caller identity is established,
      and explain in one sentence why the caller cannot forge it.
- [ ] For Trace B, you can state the `apply()`/`commit()` difference precisely, explain the `QueuedWork`
      flush, and say what a `.xml.bak` file tells a forensic examiner.
- [ ] For Trace C, you can explain to a colleague — without notes — why hooking `checkSelfPermission`
      grants nothing.
- [ ] You noticed that Trace C's middle hop differs between releases, and can articulate why that makes
      the *procedure* more valuable than any particular call graph.
- [ ] Your fourth trace was completed in under 45 minutes.
- [ ] Every worksheet records the AOSP branch you read.

---

## Common mistakes in this lab

| Mistake | Why it costs you |
|---|---|
| Leaving the branch selector on `main` | Everything you record may not match any shipped device |
| Stopping at the SDK class | It is abstract. You have found the contract, not the behaviour. |
| Skipping the `.aidl` | The interface name is what lets you find the server, and it is what you will search for later on a device |
| Not searching for `extends I*.Stub` | This is the step that collapses most investigations from an hour to five minutes |
| Reading `checkPermission` and stopping | It is a query. The enforcement is somewhere else entirely, and missing that is the misconception this whole lab exists to correct. |
| Writing arrow chains instead of prose | If you cannot write the paragraph, you have collected file names rather than understanding |

---

## Extension

Take Trace A and repeat it on **two different AOSP release branches** — say `android12-release` and
`android15-release`. Diff your two worksheets.

What changed, and why? Then find the commit that made the change:

```bash
# with a local checkout
git -C frameworks/base log --oneline -S "<a distinctive string from the changed code>"
```

Read the commit message. Understanding *why* a check was added is frequently the fastest route to
understanding what the previous behaviour allowed — which is to say, what the vulnerability was.
