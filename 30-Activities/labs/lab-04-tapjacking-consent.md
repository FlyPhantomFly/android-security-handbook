# Lab 04 — Tapjacking a consent screen

> **Difficulty:** Advanced
> **Time:** 60–90 minutes
> **You will need:** an Android device or emulator you own **and can unlock**, `adb`, and the two apps
> from [`../examples/`](../examples/build.sh).
> **Prerequisite:** [Lab 01](lab-01-read-the-task-graph.md).

---

## Read this before anything else: the device must be UNLOCKED

**This is the only lab in the chapter that cannot be run on a locked device**, and the failure mode
is confusing enough that it is worth stating up front rather than letting you diagnose it.

On a locked device, no application reaches a foreground process state. The overlay lives in a
Service, and from API 26 a background app may not start a Service, so every attempt fails with:

```text
IllegalStateException: Not allowed to start service Intent { ... }:
    app is in background uid UidRecord{... u0a312 TPSL idle procs:1 ...}
```

`TPSL` is `PROCESS_STATE_TOP_SLEEPING`. The Activity really is top; the platform still counts it as
background because the display is not interactive. **Driving it through root does not help**, because
the check is made against the *target app's* uid state, not the caller's — measured while writing
this chapter.

Check before you start:

```bash
# host
adb shell "dumpsys trust" | grep -o "deviceLocked=[01]"
adb shell "dumpsys window | grep mCurrentFocus"
```

`deviceLocked=0` and a focus that is not `NotificationShade` or a keyguard window mean you are good.
Unlock the device by hand — do not disable the lock screen, and do not attempt to bypass it.

> **Honest note.** The end-to-end tap-through in this lab was **not** executed on the reference
> device for exactly this reason; it stayed locked for the whole session and unlocking it required a
> credential this work did not have. [README §5.5](../README.md) and [§7.9](../README.md) record that
> gap explicitly. Everything about the overlay's construction, the flags, the defence and the
> detection is documented; the "the victim accepted the obscured tap" measurement is yours to take.
> If you take it, you have produced something this chapter does not contain — record your device.

---

## Why this lab exists

Tapjacking is the one attack in this chapter that does not go through
`ActivityTaskManagerService` at all. It goes through `WindowManagerService` and the input pipeline,
and treating it as "another task attack" leads people to apply the wrong mitigations —
`taskAffinity=""` does nothing here, and neither does `FLAG_SECURE`.

It is also the attack with the cleanest defence in the whole chapter: **one line**, whose absence is
invisible in code review because there is no wrong line to spot, only a missing one.

> The attacker app draws an overlay over other applications. Install it on a device you own, remove
> the overlay when you are finished, and uninstall both apps at the end. A `FLAG_NOT_TOUCHABLE`
> window you forget about is invisible to the task switcher. See
> [SECURITY.md](../../SECURITY.md) for the handling rules.

---

## Objectives

1. Understand why the overlay must live in a **Service** and not an Activity.
2. Grant `SYSTEM_ALERT_WINDOW` and understand what kind of permission it is.
3. Raise a `FLAG_NOT_TOUCHABLE` overlay over a victim consent screen.
4. Land a tap and show that the victim **accepted an obscured event** — and that the platform had
   flagged it.
5. Repeat against the hardened screen and show the event being **discarded**.
6. Distinguish `filterTouchesWhenObscured` from `FLAG_SECURE` with evidence, not assertion.

---

## Setup

```bash
# host
cd 30-Activities/examples
./build.sh --install
```

Grant the overlay permission. Two routes:

```bash
# host — ROUTE A: the user-facing route, which is what a real victim would experience
adb shell "am start -a android.settings.action.MANAGE_OVERLAY_PERMISSION \
    -d package:com.pentest.ch30.attacker"
# ...then toggle it on the device by hand.

# host — ROUTE B: directly, on a device you own and have rooted
adb shell "su -c 'appops set com.pentest.ch30.attacker SYSTEM_ALERT_WINDOW allow'"
```

Verify:

```bash
# host
adb shell "appops get com.pentest.ch30.attacker SYSTEM_ALERT_WINDOW"
# -> SYSTEM_ALERT_WINDOW: allow
```

> **Measured trap.** The appop is **reset to `ignore` by every reinstall**. If you rebuild the
> attacker app mid-lab, re-grant it or you will spend twenty minutes debugging a permission you
> already granted.

> **Question 1.** Route A shows a Settings screen. Route B does not. What kind of permission is
> `SYSTEM_ALERT_WINDOW` — normal, dangerous, signature, or something else? Why can it not be
> requested with `requestPermissions()`?
>
> **Question 2.** How many packages on your device already hold it?
>
> ```bash
> adb shell "cmd appops query-op SYSTEM_ALERT_WINDOW allow"
> ```
>
> Look at the list. Would you report "an app holds `SYSTEM_ALERT_WINDOW`" as a finding on this device?

---

## Part 1 — Read the attacker before you run it

```bash
# host
cat ../examples/hijacker-app/OverlayService.java
cat ../examples/hijacker-app/TapjackActivity.java
```

> **Question 3.** The overlay is added by a **Service**. What would go wrong if an Activity of the
> attacker's added it instead? Be specific about the lifecycle callback involved.
>
> **Question 4.** `TapjackActivity` does almost nothing and immediately calls `finish()`. What is it
> for? Why does the overlay survive it?
>
> **Question 5.** Two `WindowManager.LayoutParams` flags are set. Name them and say what each one
> buys the attacker. Which one turns "a window in the way" into "tapjacking"?
>
> **Question 6.** The window type is chosen by API level. What is used on API 26+, what was used
> before, and why did the older options go away?
>
> **Question 7.** When you audit a real APK for overlay behaviour, which component type do you look at
> first, and what call do you grep for?

---

## Part 2 — The victim, and its hardened twin

```bash
# host
cat ../examples/victim-app/ConsentActivity.java
cat ../examples/victim-app/ConsentSafeActivity.java
diff <(grep -n "filterObscuredTouches" -A2 ../examples/victim-app/ConsentActivity.java) \
     <(grep -n "filterObscuredTouches" -A2 ../examples/victim-app/ConsentSafeActivity.java)
```

> **Question 8.** State the difference between the two classes in one sentence.
>
> **Question 9.** `ConsentActivity` installs an `OnTouchListener` that logs the event flags. Is that
> listener part of the vulnerability, part of the fix, or neither?
>
> **Question 10.** `ConsentSafeActivity` also has an `OnTouchListener`. With filtering enabled, will
> it ever fire for an obscured event? What does that mean for how you will read the evidence in
> Part 4 — what does *absence* of a log line prove?

---

## Part 3 — Land the attack

Unlock the device. Keep it unlocked and awake for this whole part.

```bash
# host
adb shell "am force-stop com.pentest.ch30.victim; am force-stop com.pentest.ch30.attacker"
adb shell logcat -c

# 1. raise the overlay
adb shell "am start -n com.pentest.ch30.attacker/.TapjackActivity --es op show"
sleep 2
adb shell "logcat -d -s CH30:I" | grep -i overlay
```

> **Question 11.** Did the overlay report success? If you got the `TPSL`/background error, re-read
> the box at the top of this file.

Confirm the window exists, and confirm that this is the command you would use on a real target:

```bash
# host
adb shell "dumpsys window windows" | grep -B2 -A6 "ch30.attacker"
```

> **Question 12.** What is the window's type value? What is its `mOwnerUid`? Where does it sit in the
> z-order relative to the victim's window?

Now bring the victim's undefended consent screen forward:

```bash
# host
adb shell "am start -n com.pentest.ch30.victim/.ConsentActivity"
sleep 2
adb shell screencap -p /sdcard/ch30-tapjack.png && adb pull /sdcard/ch30-tapjack.png . \
  && adb shell rm /sdcard/ch30-tapjack.png
```

> **Question 13.** Look at the screenshot. What does the user see? What is underneath it?

Find where to tap, then tap:

```bash
# host — locate the button
adb shell "uiautomator dump /sdcard/ui.xml" && adb pull /sdcard/ui.xml . && adb shell rm /sdcard/ui.xml
grep -o 'text="GRANT[^"]*"[^>]*bounds="[^"]*"' ui.xml

# host — tap the centre of those bounds
adb shell "input tap <X> <Y>"
sleep 1
adb shell "logcat -d -s CH30:I" | grep -iE "ConsentActivity|CONSENT GRANTED"
```

> **Question 14.** Quote the touch log line. Is `OBSCURED=true`?
>
> **Question 15.** Did `CONSENT GRANTED -- the sensitive action ran` appear?
>
> **Question 16.** The platform **knew** the window was obscured — it set the flag. It delivered the
> event anyway. Why does the platform not block obscured touches globally? Give a concrete
> example of what that would break.

---

## Part 4 — The defence

```bash
# host — the overlay is still up; do not drop it
adb shell logcat -c
adb shell "am start -n com.pentest.ch30.victim/.ConsentSafeActivity"
sleep 2
adb shell "uiautomator dump /sdcard/ui.xml" && adb pull /sdcard/ui.xml . && adb shell rm /sdcard/ui.xml
grep -o 'text="GRANT[^"]*"[^>]*bounds="[^"]*"' ui.xml
adb shell "input tap <X> <Y>"
sleep 1
adb shell "logcat -d -s CH30:I"
```

> **Question 17.** What appeared in the log? What did **not** appear?
>
> **Question 18.** In Part 3 the evidence was a log line. Here the evidence is the *absence* of one.
> Explain why, referring to `View.onFilterTouchEventForSecurity` — at what point is the event dropped
> relative to the `OnTouchListener`?
>
> **Question 19.** Drop the overlay and tap the same button again:
>
> ```bash
> adb shell "am start -n com.pentest.ch30.attacker/.TapjackActivity --es op hide"
> sleep 1
> adb shell "input tap <X> <Y>"
> adb shell "logcat -d -s CH30:I" | grep -i consent
> ```
>
> Does the safe screen work normally when nothing is covering it? Why is this control necessary —
> what would you have failed to distinguish without it?

---

## Part 5 — Frida, and the runtime detector

```bash
# host — terminal 1
cd 30-Activities
frida -U -f com.pentest.ch30.victim -l scripts/activity-trace.js
```

```bash
# host — terminal 2: raise the overlay, open the UNSAFE screen, tap
adb shell "am start -n com.pentest.ch30.attacker/.TapjackActivity --es op show"
adb shell "am start -n com.pentest.ch30.victim/.ConsentActivity"
adb shell "input tap <X> <Y>"
```

> **Question 20.** The script prints a `TAPJACK` block. Quote it. What does it report about
> `getFilterTouchesWhenObscured()`?
>
> **Question 21.** Repeat against `ConsentSafeActivity`. What does the script report now, and why is
> that still a `TAPJACK` block rather than silence?
>
> **Question 22.** Why is a Frida hook on `dispatchTouchEvent` a better detector than grepping the
> source for `setFilterTouchesWhenObscured`? Name two cases the grep gets wrong.

---

## Part 6 — `FLAG_SECURE` is a different control

```bash
# host — with nothing obscuring anything, on the plain consent screen
adb shell "am start -n com.pentest.ch30.victim/.ConsentActivity"
adb shell screencap -p /sdcard/a.png && adb pull /sdcard/a.png . && adb shell rm /sdcard/a.png
```

The screenshot works, because neither consent Activity sets `FLAG_SECURE`.

> **Question 23.** Add `FLAG_SECURE` to `ConsentActivity`:
>
> ```java
> // in onCreate, BEFORE setContentView
> getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE,
>                      WindowManager.LayoutParams.FLAG_SECURE);
> ```
>
> Rebuild, reinstall, **re-grant the appop**, and try `screencap` again. What happens?
>
> **Question 24.** Now repeat Part 3's tap with `FLAG_SECURE` set and
> `filterTouchesWhenObscured` still false. Is the tapjacking attack stopped?
>
> **Question 25.** Fill in this table from your own measurements, not from memory:
>
> | Control | Stops screenshots? | Stops obscured touches? | Stops the Recents snapshot? |
> |---|---|---|---|
> | `FLAG_SECURE` | | | |
> | `filterTouchesWhenObscured` | | | |
> | `android:excludeFromRecents` | | | |
>
> **Question 26.** A screen shows a one-time code **and** has a "Confirm" button. Which controls does
> it need, and why is choosing only one a mistake?

---

## Part 7 — The limits, honestly

> **Question 27.** `filterTouchesWhenObscured` is set on a **View**. The consent screen shows a
> confirmation `Dialog` before acting. Is the dialog protected? Test it if you can; reason about it if
> you cannot.
>
> **Question 28.** An attacker uses an **accessibility service** instead of an overlay, and drives the
> button directly. Does `filterTouchesWhenObscured` help? What threat model does that belong to?
>
> **Question 29.** During your testing, did any *legitimate* window ever set
> `FLAG_WINDOW_IS_OBSCURED` — a volume panel, a gesture bar, a notification shade? What does that
> mean for a detector that reports every obscured touch as an attack?
>
> **Question 30.** Write the finding for the undefended consent screen. State the precondition in the
> title. What severity, and what would raise or lower it?

---

## Hints

<details>
<summary>Hint for Question 3</summary>

An Activity's window is tied to the Activity's lifecycle. The instant the victim's Activity comes to
the foreground, yours is paused and then stopped, and its window is removed — so the overlay
disappears exactly when it would be useful. A Service holds no window of its own but may add one
directly to `WindowManager`, and that window is not tied to any Activity.
</details>

<details>
<summary>Hint for Question 10</summary>

With filtering enabled, `onFilterTouchEventForSecurity` returns `false` **before** the view dispatches
the event to listeners. So the listener never runs. Absence of a log line is the successful result —
which means you must run the Question 19 control to distinguish "filtered" from "my tap missed".
</details>

<details>
<summary>Hint for Question 22</summary>

The grep is wrong when (a) the call exists but is made on a *different* view from the consequential
control, or on a view that is later replaced; and (b) the call is absent from the source you have but
the app is not the one you think — a library, a dynamically loaded module, or an obfuscated build
where you are reading the wrong sources. The runtime hook observes the actual view that actually
received the actual event.
</details>

<details>
<summary>Hint for Question 24</summary>

`FLAG_SECURE` controls **capture** of the window's contents. It has nothing to say about input
arriving at the window. The two flags sit on opposite sides of the same window.
</details>

---

## Success criteria

You have completed this lab when you can produce, as evidence:

- [ ] `deviceLocked=0` from `dumpsys trust`, recorded before you started.
- [ ] The appop reading `SYSTEM_ALERT_WINDOW: allow`, and a note that reinstalling resets it.
- [ ] A `dumpsys window windows` capture showing the attacker's overlay window with its type and
      `mOwnerUid`.
- [ ] A **screenshot** of the overlay sitting on top of the victim's consent screen.
- [ ] A log capture from `ConsentActivity` showing `OBSCURED=true` **and** the consequential action
      running.
- [ ] A log capture from `ConsentSafeActivity` showing the touch **not** delivered while the overlay
      was up.
- [ ] The control from Question 19 showing the safe screen working normally with no overlay.
- [ ] A `TAPJACK` block from `activity-trace.js` for each of the two screens.
- [ ] The completed table from Question 25, filled in from measurement.
- [ ] A written answer to Question 29 naming at least one legitimate obscuring window on your device.
- [ ] A finding write-up with the precondition in the title and remediation as code.

---

## Clean up

```bash
# host — DROP THE OVERLAY FIRST
adb shell "am start -n com.pentest.ch30.attacker/.TapjackActivity --es op hide"
adb shell "dumpsys window windows" | grep -c "ch30.attacker"    # should be 0

adb shell "su -c 'appops set com.pentest.ch30.attacker SYSTEM_ALERT_WINDOW ignore'" 2>/dev/null
cd 30-Activities/examples && ./build.sh --uninstall
git checkout victim-app/ConsentActivity.java 2>/dev/null || true   # if you added FLAG_SECURE
```

---

## Where to go next

- [Lab 05 — CTF: The Understudy](lab-05-ctf-the-understudy.md) chains this with the deputy.
- [README §3.9](../README.md) has the full mechanism and the three limits of the defence.
- [23-Permissions](../../23-Permissions/README.md) covers `SYSTEM_ALERT_WINDOW` as a special
  permission and the appops system behind it.
- [71-OWASP-Mobile](../../71-OWASP-Mobile/README.md) maps this to MASVS-PLATFORM-3.
