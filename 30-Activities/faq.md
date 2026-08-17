# 30 — Activities: FAQ

Real questions, including the ones people are embarrassed to ask. Answers are direct; the long
version of each is linked.

---

### 1. What *is* a task, in one sentence?

A stack of screens the user thinks of as one piece of work. Your phone has several; it shows one at a
time; the Recents screen is a picture of them.

The sentence that matters more is the second one: **a task is not an app.** Screens from two
different apps can sit in the same task, and pressing Back will walk you from one app's screen to the
other's with no visual seam. That is not a bug — it is what makes a share sheet feel seamless — and it
is the root of half of this chapter. See [README §2.1](README.md).

---

### 2. What is the difference between a task, the back stack, and an Activity?

- An **Activity** is one screen.
- A **task** is a stack of them.
- The **back stack** *is* that stack — "the back stack" and "the task's list of Activities" are the
  same thing, described from the point of view of the Back button.

The confusion comes from people saying "the back stack" as though there were one per device. There is
one **per task**, and a device has many tasks.

---

### 3. Why did my Activity open inside another app's task?

Because whoever started it did not set `FLAG_ACTIVITY_NEW_TASK`, and your Activity's launch mode is
`standard` or `singleTop`.

The rule people expect is "an Activity goes to the task matching its `taskAffinity`". That is only
true when a task is being **chosen or created**. On an ordinary start from another Activity, the
system does not choose a task at all — it uses the caller's — and your affinity is never consulted.

Measured, on API 30: an attacker's Activity called `startActivity()` on a victim's exported Activity
with no flags, and both ended up in task 294, whose affinity belonged to the attacker. The victim
Activity's own affinity said `10311:com.pentest.ch30.victim` and it made no difference at all. See
[README §3.8](README.md).

Fix, if it is your Activity and you do not want this: `android:launchMode="singleTask"`, or do not
export it.

---

### 4. What does `singleTop` *actually* do? I set it and I still got two copies.

`singleTop` means: **do not stack a second copy directly on top of the first.** It says nothing about
the rest of the stack.

If an instance is at the very top of the target task, the system reuses it and calls `onNewIntent`.
If an instance is anywhere else — even one position down — a new one is built. So two instances can
absolutely coexist.

Measured sequence: `Main → Beta → Beta → Beta → Alpha → Beta` produced **one** Beta instance for the
first three starts (two of them `onNewIntent`), then a **second** Beta instance after Alpha was
pushed on top. Final stack: `Main, Beta, Alpha, Beta`. See [README §3.4](README.md).

If you meant "only one of these ever exists", you want `singleTask` — and you need to understand that
it also destroys everything stacked above it.

---

### 5. Does `singleTask` create a new task? Everyone says it does.

**No, not necessarily**, and this is the most widely repeated wrong answer in the whole topic.

`singleTask` means "at most one instance, in the task matching my affinity". If a task with that
affinity already exists — and for your own app's screens it always does, because they share the
default affinity — the Activity goes **into that task**. It creates a new task only when no matching
one exists.

Measured: `Main → Alpha → Gamma → Alpha → Gamma` where Gamma is `singleTask`. Gamma landed in
task 272 alongside Main and Alpha, never in a task of its own. The second Gamma start reused the
instance via `onNewIntent` **and destroyed the Alpha above it** — the stack went from four entries to
three. See [README §3.4](README.md).

---

### 6. Can another app see my Activity? Can it start it?

**See it:** any app can enumerate your exported components, subject to package visibility rules from
`targetSdk` 30. `adb shell` can see everything regardless.

**Start it:** only if `android:exported="true"` and the caller holds any `android:permission` you
declared. Otherwise the system refuses, and it really does refuse — measured, against `adb shell`
which runs as the *privileged* uid 2000:

```text
java.lang.SecurityException: Permission Denial: starting Intent { ... }
    from null (pid=22016, uid=2000) not exported from uid 10311
```

The catch is that a **confused deputy** inside your own app can start it for someone else. See
question 12.

---

### 7. Why is my Back button behaving oddly?

Five common causes, in the order worth checking:

1. **Two tasks where you expected one.** Something set `FLAG_ACTIVITY_NEW_TASK`, or an Activity has a
   non-default `taskAffinity`, or an Activity is `singleTask`/`singleInstance`. Back within a task
   never leaves that task.
2. **`singleTask` cleared the stack.** Re-entering a `singleTask` Activity destroys everything above
   it, so screens the user expected to go back to are gone.
3. **`singleInstance`.** Its task holds nothing else, so Back from it goes to a completely different
   task.
4. **`android:noHistory="true"`** on an intermediate screen — it is finished as soon as you leave it,
   so Back skips it.
5. **You are in someone else's task** (question 3), so Back reveals their screen.

Diagnose it in one command:

```bash
adb shell "dumpsys activity activities" | grep -E "^\s+\* Task\{|Hist #"
```

---

### 8. What is task hijacking, and does it still work?

An attacker declares `android:taskAffinity` equal to your package name and
`android:launchMode="singleTask"`. Launching the attacker once creates a task carrying *your* task's
name. Later, when the user taps *your* icon, the system finds that existing task and brings it
forward — so the user sees the attacker's screen believing it is yours.

**Does it still work: measure it, do not guess.** On the device this chapter was written against
(Redmi M2101K6P, Android 11 / API 30) it **failed**, because the platform prefixes every effective
affinity with the declaring app's uid. The attacker got `10312:com.victim`; the victim got
`10311:com.victim`; the strings never match.

```bash
# the one-line empirical test, on any device
python3 -B scripts/task-affinity-map.py --check
```

Do not repeat "it was fixed in Android X" — including from this file. Run the check on the device in
front of you and report that. See [README §5.2](README.md).

---

### 9. If task hijacking is blocked, why does this chapter still recommend `taskAffinity=""`?

Three reasons.

1. **You do not control the fleet.** One device measured is not every device an app runs on.
2. It costs one attribute and breaks nothing — with no affinity, your own screens still share a task,
   because ordinary starts do not consult affinity anyway.
3. The mitigation you are relying on is invisible in your manifest. A control you can see beats a
   platform behaviour you have to remember to re-verify.

It is a Low/Informational finding on a namespacing device, not a non-finding.

---

### 10. What is a "confused deputy"?

A component with privileges that performs an action on behalf of someone who lacks them, because it
was asked nicely and did not check.

For Activities the shape is: an exported Activity reads an `Intent` out of an extra and starts it.
`startActivity()` then runs with **your** app's identity, so the attacker's Intent reaches components
they could never have reached — including your `exported="false"` screens — and any URI grant flags
on it are honoured *on your behalf*, to a target *they* chose.

Measured, end to end: an Activity marked `exported="false"` was refused to `adb shell`, then reached
through the deputy; and a provider marked `exported="false"` was refused to the attacker's uid by
name, then read by that same uid after the deputy forwarded a grant. See [README §5.3](README.md).

---

### 11. How do I fix a deputy? I already check the package name.

Checking `getPackage()` does not work, for a specific reason: `setPackage()` restricts *resolution*,
not the component, and `getPackage()` returns **`null`** on an Intent that only sets a
`ComponentName` — which is exactly the input an attacker sends. Your check is skipped on the only
input that matters.

The fix is to stop accepting an `Intent` at all:

```java
String dest = getIntent().getStringExtra("dest");     // a SELECTOR
Class<?> target = DESTINATIONS.get(dest);             // closed allow-list
if (target == null) { setResult(RESULT_CANCELED); finish(); return; }   // fail CLOSED
startActivity(new Intent(this, target));              // built HERE, nothing carried across
```

You cannot sanitise an Intent — it is a dozen independently attacker-controlled fields plus an
arbitrary `Bundle`, and a filter has to be right about all of them forever. An allow-list has to be
right about one thing, once.

And one honest caveat: allow-listing a non-exported screen makes **that screen** reachable by anyone
who can reach the deputy. Two allow-list entries deserve two arguments.

---

### 12. Can my Activity find out which app started it?

Usually **no**, and the near-misses are the dangerous part.

- `getCallingActivity()` / `getCallingPackage()` — system-set and trustworthy, but **only** if the
  caller used `startActivityForResult`. `null` otherwise, which includes every plain `startActivity`.
- `getReferrer()` — falls back to an ordinary extra the caller wrote. Worthless.
- `Binder.getCallingUid()` in `onCreate` — **returns your own uid.** Measured: 10311 and 10311. It
  works in a Service because that is a live Binder transaction; an Activity start is performed *by
  `system_server`*, on a different transaction, so the original caller's stamp is long gone.
- `getLaunchedFromPackage()` — genuine, system-set, **API 34+**.

Even when you get a package name, a name is not an identity. Resolve it to a signing certificate, or
better, put a `signature`-level permission on the Activity and let the system enforce it before you
are started. See [README §3.6](README.md).

---

### 13. What is tapjacking and why doesn't the system just block it?

Another app draws a window on top of yours and marks it `FLAG_NOT_TOUCHABLE`, so touches pass
straight through. The user reads the attacker's text and taps your button.

The system *does* tell you: every `MotionEvent` carries `FLAG_WINDOW_IS_OBSCURED` when another
application's window was covering yours at that moment. It then delivers the event anyway, because
blocking all obscured touches globally would break every legitimate overlay — volume panels, gesture
bars, screen dimmers, accessibility tools.

Acting on the flag is your job:

```java
view.setFilterTouchesWhenObscured(true);
```

That makes the view **discard** obscured events. Discarding rather than warning is the only workable
policy: a warning is a UI element, and the attacker already controls the pixels on top of your UI.

---

### 14. Is `FLAG_SECURE` the same thing?

No — they solve **opposite** problems and neither substitutes for the other.

| | Stops | Use on |
|---|---|---|
| `filterTouchesWhenObscured` | input **arriving at** your window | consent, confirm, approve, pay |
| `FLAG_SECURE` | information **leaving** your window (screenshots, recordings, Recents snapshots) | anything showing a secret |

A screen that shows a one-time code *and* asks you to confirm needs both.
`android:excludeFromRecents` is a third, weaker thing: it hides the task from Recents but does not
stop the system snapshot being written. `FLAG_SECURE` is the control for that. Set `FLAG_SECURE`
**before** `setContentView`.

---

### 15. Do I need root to test any of this?

For the analysis, no: `dumpsys activity activities`, `dumpsys window windows`, `am start` and
`cmd appops query-op` all work from ordinary `adb shell`.

For the labs, you need to **install two apps**, and that is where devices vary. The device used for
this chapter refuses `adb install` with `INSTALL_FAILED_USER_RESTRICTED` — an OEM "Install via USB"
gate, not a fault in the APK, and the message ("Install canceled by user") is simply untrue. On that
device the labs were run by installing through root:

```bash
adb push app.apk /data/local/tmp/app.apk
adb shell "su -c 'pm install -r /data/local/tmp/app.apk'"
```

`examples/build.sh --install` detects the failure and tries this automatically. If you cannot root
the device and cannot enable the vendor toggle, use a different device — and if this is an engagement,
write down which test you could not run rather than reporting "not applicable".

For Frida, yes, you need root (or a patched app) — see [53-Frida](../53-Frida/README.md).

---

### 16. Why can't I just use `adb shell am start` for everything?

Three reasons, all measured:

1. **`am` always implies `FLAG_ACTIVITY_NEW_TASK`,** because the shell process is not an Activity and
   has no task to join. So the one case you most want to observe — an Activity starting another app's
   Activity *without* that flag, which is the task attack that still works — is unreachable from the
   shell.
2. **`am` has no `--eparcelable`.** The nested-Intent flavour of the deputy bug cannot be expressed.
   "I couldn't trigger it with `am`" is not evidence a deputy is safe.
3. **`am` runs as uid 2000**, which holds permissions no third-party app holds. Reaching something
   from `am` is not the same as an app reaching it.

The escape for all three is a twelve-line app. `examples/hijacker-app/` has two of them.

---

### 17. My exploit returns a null cursor instead of a SecurityException. Is the provider gone?

Almost certainly not. On API 30+ your **attacker app** cannot see other packages unless it declares
`<queries>`, and an unresolvable authority makes `ContentResolver.query()` return `null` rather than
throw.

This cost real time while writing this chapter. Three outcomes, three meanings:

| Outcome | Meaning |
|---|---|
| `SecurityException` | the provider exists and refused you — **this is the control you want** |
| **null cursor** | the authority did not resolve — usually package visibility |
| a row | it was reachable all along, and your experiment proves nothing |

Add this to the attacker's manifest and re-run:

```xml
<queries>
    <package android:name="com.victim.package"/>
</queries>
```

---

### 18. `dumpsys activity activities` prints everything twice. Am I reading it wrong?

No — it really does. The dump lists tasks once per display and then again in a summary block at the
end. Any naive `grep | wc -l` over it double-counts, and any naive parser produces duplicate tasks.

Key by task id. `scripts/task-affinity-map.py` does exactly that, and it has to.

---

### 19. What is the single highest-value command in this chapter?

```bash
adb shell "dumpsys activity activities" | grep -E "taskAffinity=|affinity=" | sort -u
```

If the strings look like `10196:com.android.chrome`, affinities are uid-namespaced on this device and
the classic task hijack cannot work. If they look like `com.android.chrome`, it can.

That one line replaces an entire argument about Android versions with a fact about the device you are
holding.

---

### 20. Where does this chapter stop and another begin?

| You want to know | Go to |
|---|---|
| How an Intent resolves; the twelve fields; `PendingIntent`; deep-link verification | [26-Intent](../26-Intent/README.md) |
| What a stolen URI grant is worth; provider exploitation | [27-ContentProviders](../27-ContentProviders/README.md) |
| Every `<activity>` attribute and the export matrix, audited from an APK | [32-Manifest](../32-Manifest/README.md) |
| Why `Binder.getCallingUid()` cannot be forged | [25-Binder](../25-Binder/README.md) |
| uid isolation and what "another app's data" means | [21-App-Sandbox](../21-App-Sandbox/README.md) |
| `protectionLevel`, and why `android:permission` can be worthless | [23-Permissions](../23-Permissions/README.md) |
| The Activity, the task model, hijacking, the deputy, tapjacking | **you are here** |
