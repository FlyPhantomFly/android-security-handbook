# Lab 05 — CTF: The Understudy

> **Difficulty:** CTF
> **Time:** 90 minutes to several hours, depending on how much you refuse to read the hints
> **You will need:** an Android device or emulator you own **and can unlock**, `adb`, and the two apps
> from [`../examples/`](../examples/build.sh).
> **Prerequisites:** Labs [01](lab-01-read-the-task-graph.md) and
> [03](lab-03-deputy-grant-laundering.md). Lab 02 is useful but not required.

---

## The brief

An understudy learns the part, waits in the wings, and goes on when the lead cannot. Nobody in the
audience is told.

`com.pentest.ch30.victim` ships a screen called `VaultActivity`. It is **exported**, so anybody may
start it — and it knows that, so it refuses to do anything useful unless *its own application* opened
it. The developer picked the one identity mechanism an Activity actually has that cannot be forged,
and used it correctly.

Your job is to make the application open its own vault, and then walk in behind it.

There are **two flags**. The first is a warm-up you have already earned if you did Lab 03; the second
is the challenge.

```text
Flag format: CH30{...}
```

---

## Rules

1. **No decompiling the victim's DEX, and no reading `VaultActivity.java`** until you have either
   captured flag 2 or exhausted every hint. Everything you need is discoverable from the device with
   `adb`, plus the *manifest*, which a real attacker always has.
2. No root for the attack itself. Root is permitted only to install the apps if your device refuses
   `adb install` (see [README §7.8](../README.md)) and to run `frida-server` if you use it.
3. No modifying the victim app. You may write as much attacker code as you like.
4. The victim app is not to be attacked through any bug that is not in this chapter — no memory
   corruption, no `run-as`, no pulling `/data`.

> Device you own. Uninstall both apps afterwards. See [SECURITY.md](../../SECURITY.md) for the
> handling rules.

---

## Precondition: the device must be UNLOCKED

Unlock the device by hand and keep it unlocked. Do not disable the lock screen.

This is not a formality. On the MIUI device used to write this chapter, **every** activity start is
refused while the keyguard is up — including an app starting its own Activity — with:

```text
MIUILOG- Permission Denied Activity KeyguardLocked: Intent { cmp=com.pentest.ch30.victim/.VaultActivity }
    pkg : com.pentest.ch30.victim uid : 10311
```

Note the `MIUILOG-` prefix: this is an **OEM** policy, not AOSP behaviour, and it silently breaks the
middle of the chain while leaving `adb shell am start` working, which is a maddening combination to
debug. Check first:

```bash
# host
adb shell "dumpsys trust" | grep -o "deviceLocked=[01]"     # you want 0
```

---

## Setup

```bash
# host
cd 30-Activities/examples
./build.sh --install
adb shell logcat -c
```

Everything the apps log goes to the `CH30` tag:

```bash
# host
adb shell "logcat -d -s CH30:I"
```

---

## Stage 0 — Reconnaissance

Start where you would start on a real target: with what the platform will tell you.

```bash
# host
adb shell "dumpsys package com.pentest.ch30.victim" | sed -n '/Activity Resolver Table/,/Receiver/p'
adb shell "cmd package query-activities --brief -a android.intent.action.MAIN com.pentest.ch30.victim"
cd .. && python3 -B scripts/task-affinity-map.py -p com.pentest.ch30.victim --recents
```

And the manifest, which you are allowed to read:

```bash
# host
cat examples/victim-app/AndroidManifest.xml
```

**Questions to answer before you touch anything:**

- Which Activities are exported and which are not?
- Which one is the target, and which one is the way in?
- One Activity has a `launchMode` that is not `standard`. Which, and what does that buy an attacker?
- One provider exists. Is it exported? Does it grant URI permissions?

---

## Stage 1 — Flag 1 (warm-up)

The provider holds a flag. It is `exported="false"`, so you cannot read it.

Read it.

If you did [Lab 03](lab-03-deputy-grant-laundering.md), this is fifteen minutes. If you did not, the
three ingredients are: a component that forwards an `Intent` you supply, a `content://` URI belonging
to the victim, and a flag on the Intent that makes the system issue a grant.

**Success:** `CH30{...}` appears in your logcat, and you can point at a log line proving the
**provider itself** saw the *attacker's* uid.

---

## Stage 2 — Flag 2 (the challenge)

`VaultActivity` is exported. Start it and ask for the flag:

```bash
# host
adb shell "am start -n com.pentest.ch30.victim/.VaultActivity --es cmd reveal"
adb shell "logcat -d -s CH30:I" | grep -i vault
```

You will get:

```text
I CH30 : VaultActivity onCreate callingActivity=null unlocked=false ...
I CH30 : VaultActivity REFUSED: not unlocked by this app
```

That refusal is **correct**, and no amount of extra-guessing will get past it. The check the vault
performs cannot be satisfied by anything you put in an Intent.

### What you are being asked to work out

Three questions, in order. Each one has an answer you can reach from the device.

1. **What is `unlocked` actually testing?** The log line tells you which value it looked at. Consult
   the identity table in [README §3.6](../README.md) and work out which mechanism produces that value,
   who sets it, and what the caller would have to do for it to be non-null. Then work out why *you*
   cannot do that.
2. **Who *can* satisfy it?** Something inside the victim app must be able to, or the vault would be
   permanently dead code. Look at the manifest for an Activity that is not exported and ask what it
   would be for. You already know, from Stage 1, how to reach a non-exported Activity.
3. **How do you get in behind it?** Once the app has opened its own vault, the vault instance is
   alive and authorised. What does its `launchMode` let you do to a *live instance* — and what does
   [README §3.1](../README.md) say about the relationship between the Intent an Activity was
   validated with and the Intent it later acts on?

### The shape of the answer

Three primitives, chained:

```text
[ the deputy ]  ->  [ the app's own internal screen ]  ->  [ the live vault instance ]
      Lab 03                 Lab 03 prize 1                    Lab 01 launch modes
```

**Success:** the second `CH30{...}` in your logcat, plus a written explanation of why the vault's
authorisation check was correct and still insufficient.

---

## Stage 3 — Be the defender

Capturing the flag is half the exercise.

1. Write the **two-line** fix for `VaultActivity`. It is two lines. Say what each one does.
2. Explain why moving the authorisation check into `handle()` is the *general* form of the fix, and
   why it would also have prevented a bug you have not seen.
3. The vault's `launchMode="singleTop"` made your attack convenient. Would removing it stop the
   attack? Test your answer. (Hint: `am start --activity-single-top`.)
4. The chain has three links. Which single link, if broken, kills the whole thing at least cost to
   the developer? Justify it in terms of what each fix costs the product.
5. Write the finding as you would submit it: title with the precondition, severity with reasoning,
   evidence, remediation as code.

---

## Stage 4 — Extensions

Only attempt these once you have flag 2. Each is a real variation you will meet in the field, and
each has an answer you can establish on the device rather than argue about.

**4.1 — Break the chain from the middle.** Point the deputy at `DeputyActivityFixed` instead
(`--es mode fixed`). The fixed deputy allow-lists `internal`, so `InternalActivity` still runs and the
vault is still unlocked. Does flag 2 still fall? What does that tell you about a fix that removes
*arbitrary* redirection while leaving a sensitive destination on the allow-list?

**4.2 — Race the top of the stack.** After unlocking the vault, start something else — anything —
before your `--activity-single-top` command:

```bash
# host
adb shell "am start -n com.pentest.ch30.victim/.AlphaActivity"
adb shell "am start --activity-single-top -n com.pentest.ch30.victim/.VaultActivity --es cmd reveal"
```

Does it still work? Explain the result in terms of what `singleTop` requires, and then find a flag
that would make it work anyway. (There is one. [README §3.5](../README.md).)

**4.3 — Do it without `singleTop`.** Suppose the developer removes `android:launchMode="singleTop"`
from the vault. Reason about whether the attack dies, then test it. Which side of the interaction
actually decides that `onNewIntent` is used — the target's manifest, or the caller's flags?

**4.4 — Do it from a real app.** Everything above was driven from `adb shell`, which runs as the
privileged uid 2000. Re-run the whole chain from an unprivileged app — add the two starts to
`DeputyExploitActivity` — and confirm that nothing about the result depended on shell's privileges.
This is the step that converts your write-up from "reachable in a lab" to "reachable by any installed
app", and it is the step triagers ask for.

**4.5 — Detect it, don't exploit it.** Put `scripts/activity-trace.js` on the victim and run the chain
again. Which single line of its output would have told a defender that something was wrong? Would a
log-based detection be reliable, or is the only real fix the two-line one from Stage 3?

**4.6 — Find the third flag that is not there.** The provider serves a string. Suppose it served a
session token that the attacker could replay. Re-read your Stage 1 finding and re-rate it. Then
consider: the grant expired when the sink finished ([Lab 03](lab-03-deputy-grant-laundering.md)
Part 5). Which flag and which API call would an attacker add to keep it, and would that change your
severity? Name them; do not re-derive them —
[27-ContentProviders](../../27-ContentProviders/README.md) owns that ground.

---

## Post-mortem: what the developer did right

It is worth being explicit about this, because a CTF write-up that reads "the app was insecure" has
taught nobody anything.

| Decision | Verdict |
|---|---|
| Refusing to act on an unauthenticated caller | **Right.** Most exported Activities do not even try. |
| Choosing `getCallingActivity()` rather than an extra, a `getReferrer()`, or `Binder.getCallingUid()` | **Right, and unusually well-informed.** It is the only tier-2 mechanism available to an Activity before API 34, and the two obvious alternatives are both tier 3 or broken. |
| Requiring the caller's package to be its own | **Right.** An external app cannot make the system write the victim's package into that field. |
| Caching the answer in a field | **The bug.** Not the check — the *cache*. |
| Using `singleTop` | Neutral. It made the attack convenient; it did not make it possible (see 4.3). |

The lesson generalises past this lab: **an authorisation decision is a property of a message, not of
an object.** The moment you store one on the instance, you have created a window in which a second
message inherits the first one's privileges. Every instance-reusing launch mode, every
`FLAG_ACTIVITY_SINGLE_TOP` from a caller you do not control, and every
`onActivityResult` widens that window.

---

## Hints

Open in order. Each costs you nothing but pride.

<details>
<summary>Hint 1 — I cannot even find the entry point</summary>

`dumpsys package <pkg>` prints an "Activity Resolver Table" containing only components with
`<intent-filter>`s. Components without filters can still be exported. Read
`examples/victim-app/AndroidManifest.xml` — you are allowed to, and a real attacker unpacks the APK
in ten seconds.

The Activity you want in Stage 1 has an `<intent-filter>` with a custom action.
</details>

<details>
<summary>Hint 2 — Stage 1: what does "forward an Intent" mean in practice?</summary>

You need to send an Intent that *contains another Intent as an extra*. `adb shell am start` cannot do
that — there is no `--eparcelable`. You need a real app. One already exists:

```bash
adb shell "am start -n com.pentest.ch30.attacker/.DeputyExploitActivity --es mode grant"
```

Read its source afterwards, not before.
</details>

<details>
<summary>Hint 3 — Stage 2, question 1: what is `unlocked` testing?</summary>

The log prints `callingActivity=` right next to `unlocked=`. That is `getCallingActivity()`.

From [README §3.6](../README.md): it is **system-stamped**, it cannot be set by the caller, and it is
non-null **only when the caller used `startActivityForResult`**. So the vault is asking "did somebody
open me with a result channel, and was that somebody in my own package?"

You can create a result channel — `startActivityForResult` is available to your attacker app. What
you cannot do is make the resulting `ComponentName` name the *victim's* package, because the system
fills it in from the real caller.
</details>

<details>
<summary>Hint 4 — Stage 2, question 2: who can satisfy it?</summary>

Look at the manifest for an Activity that is `exported="false"` and ask what it exists for. Then start
it — through the deputy, exactly as in Lab 03's `--es mode reach` — and watch the log carefully.

It does something on the way past. Read every `CH30` line, not just the ones with your flag format in
them.
</details>

<details>
<summary>Hint 5 — Stage 2, question 3: I unlocked it, but my next command builds a NEW instance</summary>

A new instance re-runs `onCreate`, which re-computes `unlocked` from *your* Intent, which is `false`.
You do not want a new instance. You want the **existing** one.

Which means you need `onNewIntent`, which means the system must decide to reuse the instance. Two ways
to make that happen — one is a property of the target, one is a flag you set:

```bash
adb shell "am start --activity-single-top -n ..."
```

And the instance must still be at the **top of its task** when you do it. If something else was
started in between, it is not.
</details>

<details>
<summary>Hint 6 — the full chain, spelled out</summary>

```bash
# host — 0. clean slate, device UNLOCKED
adb shell "am force-stop com.pentest.ch30.victim; am force-stop com.pentest.ch30.attacker"
adb shell logcat -c

# host — 1. use the deputy to reach the non-exported internal screen.
#           That screen opens the vault with startActivityForResult, so the
#           vault's getCallingActivity() names the VICTIM's own package and
#           `unlocked` is computed as true. The vault is now live and authorised.
adb shell "am start -n com.pentest.ch30.attacker/.DeputyExploitActivity --es mode reach"
sleep 2
adb shell "logcat -d -s CH30:I" | grep -i vault      # confirm unlocked=true

# host — 2. do NOT let anything else start. Re-enter the LIVE instance.
adb shell "am start --activity-single-top -n com.pentest.ch30.victim/.VaultActivity --es cmd reveal"
sleep 1
adb shell "logcat -d -s CH30:I" | grep -i vault
```

If step 2 logs `onCreate` rather than `onNewIntent`, the instance was not on top. Redo step 1 and try
again without anything in between.
</details>

<details>
<summary>Hint 7 — the fix, for Stage 3</summary>

```java
@Override protected void onNewIntent(Intent intent) {
    super.onNewIntent(intent);
    setIntent(intent);                       // (1) getIntent() no longer lies
    mUnlockedByOwnApp = recheck();           // (2) authorise THIS message
    handle(intent);
}
```

The general form is stronger: do not cache an authorisation derived from one message and apply it to
another. Compute it inside `handle()`, from the message being handled.
</details>

---

## Verifying your solution

You have solved it when you can produce:

- [ ] **Flag 1**, plus the `SecretProvider.query ... callingUid=<attacker uid>` line that proves the
      provider itself served the attacker.
- [ ] The refusal from a naive direct attempt on the vault (`unlocked=false`, `REFUSED`).
- [ ] A log capture showing the vault reaching `unlocked=true`, together with the `callingActivity=`
      value that made it true.
- [ ] A log capture showing **`onNewIntent`** on the vault with the **same `instance=`** as the
      earlier `onCreate` — this is the proof that you re-entered rather than recreated.
- [ ] **Flag 2**.
- [ ] A written explanation, in your own words, of why `getCallingActivity()` was the *right* choice
      of identity mechanism and still did not save the vault.
- [ ] The two-line fix, and a test showing it holds.
- [ ] An answer to Stage 3 question 3, with the experiment that decided it.

---

## What was verified on the reference device, and what was not

This repository states what it measured. For this lab, on the Redmi M2101K6P
(Android 11 / API 30, MIUI 12.5):

| Link in the chain | Status |
|---|---|
| Deputy forwards an attacker's nested Intent | **measured** — [README §5.3](../README.md) |
| Deputy reaches `InternalActivity` (`exported="false"`) | **measured** — [README §5.3](../README.md) |
| A direct start of the vault is refused (`unlocked=false`) | **measured** |
| `VaultActivity` (`singleTop`) reuses its instance via `onNewIntent`, with the cached field intact across the reuse | **measured** — same `instance=` across `onCreate` and two `onNewIntent` calls |
| `InternalActivity`'s `startActivityForResult` makes the vault's `getCallingActivity()` name the victim's own package | **not measured on this device.** The device locked itself mid-session and MIUI's `KeyguardLocked` policy refused every subsequent activity start, including the app's start of its own Activity. This link is documented framework behaviour (`getCallingActivity()` is set by the system when, and only when, `startActivityForResult` was used) rather than a measurement taken here. |

If you complete the chain on an unlocked device, you have produced a measurement this chapter does
not contain. Record your device model, release and API level with it.

---

## Clean up

```bash
# host
cd 30-Activities/examples
./build.sh --uninstall
adb shell "pm list packages | grep ch30"    # should print nothing
```

---

## Where to go next

- [README §5.3](../README.md) for the deputy, [§3.1](../README.md) for the `getIntent()` staleness
  rule, and [§3.6](../README.md) for the identity tiers.
- [26-Intent §5.2](../../26-Intent/README.md) for the other flavours of the redirection primitive —
  including the one reachable from a **web page**.
- [27-ContentProviders §5.4](../../27-ContentProviders/README.md) for what flag 1's grant would have
  been worth if it had been a session token instead of a string.
