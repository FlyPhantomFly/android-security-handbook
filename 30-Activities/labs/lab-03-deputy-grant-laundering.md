# Lab 03 — The deputy that launders a grant

> **Difficulty:** Intermediate–Advanced
> **Time:** 75–110 minutes
> **You will need:** an Android device or emulator you own, `adb`, and the two apps from
> [`../examples/`](../examples/build.sh).
> **Prerequisite:** [Lab 01](lab-01-read-the-task-graph.md). Helpful:
> [26-Intent](../../26-Intent/README.md) §5.2 and
> [27-ContentProviders](../../27-ContentProviders/README.md) §5.4.

---

## Why this lab exists

Lab 02 has an outcome that depends on your device, and on modern hardware the answer is usually
"blocked". **This lab's outcome does not depend on your device.** The confused deputy works on every
Android version, needs no special permission, needs no manifest trick, and is limited only by the
attacker having *any* app on the device — or, if the deputy is reachable from a deep link, by nothing
at all.

It is also the family where the difference between a good report and a bad one is starkest, because
the whole thing turns on **controls**. "I read the provider through the deputy" proves nothing unless
you first showed that you could not read it directly.

---

## Objectives

1. Establish two controls: a non-exported Activity and a non-exported provider, both refused to you.
2. Reach the non-exported Activity through the deputy — **confused-deputy reachability**.
3. Read the non-exported provider through the deputy — **grant laundering** — and prove it with the
   provider's own `Binder.getCallingUid()`.
4. Measure the grant's **lifetime**.
5. Defeat the identical payload with the fixed deputy, and find the residual issue the fix does *not*
   solve.
6. Learn the package-visibility trap that turns a `SecurityException` into a silent `null`.

---

## Background in ninety seconds

An exported Activity does this:

```java
Intent next = getIntent().getParcelableExtra("next");
if (next != null) startActivity(next);
```

`startActivity()` runs with **the victim's** uid. So the forwarded Intent gets the victim's
privileges, and two things follow:

- **Reachability.** The forwarded Intent can name a component that is `exported="false"`. The
  attacker reaches screens the platform would have refused to start for them.
- **Grant laundering.** If the forwarded Intent carries `FLAG_GRANT_READ_URI_PERMISSION` and a
  `content://` URI belonging to the victim, the system issues a URI grant *on the victim's behalf*, to
  a target *the attacker chose*.

The permission question is asked about the **caller** and the answer is given to the **target**. A
deputy lets the attacker control the target while remaining the caller. See
[README §5.3](../README.md) and [README §4.4](../README.md).

> Both apps are deliberately vulnerable. Device you own; uninstall afterwards. See
> [SECURITY.md](../../SECURITY.md) for the handling rules.

---

## Setup

```bash
# host
cd 30-Activities/examples
./build.sh --install

adb shell "dumpsys package com.pentest.ch30.victim   | grep userId=" | head -1   # VICTIM_UID
adb shell "dumpsys package com.pentest.ch30.attacker | grep userId=" | head -1   # ATTACKER_UID
```

```bash
# host
logs() { adb shell "logcat -d -s CH30:I"; }
reset() { adb shell "am force-stop com.pentest.ch30.victim; am force-stop com.pentest.ch30.attacker"
          adb shell logcat -c; sleep 1; }
```

---

## Part 1 — Read the code before you attack it

```bash
# host
cat ../examples/DeputyActivity.java
cat ../examples/victim-app/SecretProvider.java
grep -A6 "SecretProvider\|InternalActivity\|DeputyActivity" ../examples/victim-app/AndroidManifest.xml
```

> **Question 1.** `DeputyActivity` casts the extra to `Intent`. Is that validation? What exactly does
> the cast check, and what does it not check?
>
> **Question 2.** The provider is `exported="false"` **and** `grantUriPermissions="true"`. Explain, in
> your own words, what each attribute does and why the pair is the precondition for laundering.
>
> **Question 3.** `InternalActivity` is `exported="false"`. Name three things a developer might
> reasonably put behind that attribute, believing it unreachable.
>
> **Question 4.** Read `../examples/hijacker-app/DeputyExploitActivity.java`. Why can this payload not
> be sent with `adb shell am start`? Find the specific missing feature.

---

## Part 2 — The controls

**Do this first. Nothing later means anything without it.**

### Control A — the non-exported Activity, from a privileged shell

```bash
# host — adb shell runs as uid 2000, which is PRIVILEGED
adb shell "am start -n com.pentest.ch30.victim/.InternalActivity" 2>&1 | head -6
```

> **Question 5.** Quote the exception verbatim. Which uid does it name at the end, and what is that
> uid? Why is it useful to an attacker that the platform names it?
>
> **Question 6.** `adb shell` holds permissions no third-party app holds, and it was still refused.
> What does that tell you about how strong `exported="false"` is when it is the only thing being
> tested?

### Control B — the non-exported provider, from the attacker app

```bash
# host
reset
adb shell "am start -n com.pentest.ch30.attacker/.DeputyExploitActivity --es mode grant"
sleep 3
logs | grep "EXPLOIT control"
```

You should see a `SecurityException`. Read [Part 6](#part-6--the-package-visibility-trap) **now** if
you instead see either of these:

```text
EXPLOIT INCONCLUSIVE: direct query returned a NULL CURSOR ...
EXPLOIT UNEXPECTED: direct query SUCCEEDED
```

> **Question 7.** Quote the control line. Which uid is refused, and which uid owns the provider?
>
> **Question 8.** Three outcomes are possible from that query — an exception, a null cursor, and a
> row. Write down what each one means, and which one is the control you need.

---

## Part 3 — Prize 1: reachability

```bash
# host
reset
adb shell "am start -n com.pentest.ch30.attacker/.DeputyExploitActivity --es mode reach"
sleep 3
logs
```

Expected, from the reference device:

```text
I CH30 : EXPLOIT mode=reach outer=Intent { act=com.pentest.ch30.victim.FORWARD
         pkg=com.pentest.ch30.victim (has extras) }
         inner=Intent { cmp=com.pentest.ch30.victim/.InternalActivity }
I CH30 : DeputyActivity forwarding: Intent { cmp=com.pentest.ch30.victim/.InternalActivity }
I CH30 : onCreate InternalActivity taskId=299 instance=25596899 callingActivity=null
I CH30 : InternalActivity REACHED -- exported=false, so the starter had this app's identity.
```

> **Question 9.** `InternalActivity` was refused to uid 2000 in Control A and reached here. What
> changed about `InternalActivity` between the two runs?
>
> **Question 10.** The `InternalActivity` log line shows `callingActivity=null`. Could the victim's
> own code have detected that this start came from an attacker rather than from its own UI? Work
> through the identity table in [README §3.6](../README.md) before answering.
>
> **Question 11.** Which task did `InternalActivity` land in — the attacker's or the victim's? Why?
> (Check `dumpsys`; consider what flags the deputy's `startActivity` had.)
>
> **Question 12.** Write the finding for reachability **alone**, with no provider involved. What is
> its severity, and what evidence would raise it?

---

## Part 4 — Prize 2: grant laundering

```bash
# host
reset
adb shell "am start -n com.pentest.ch30.attacker/.DeputyExploitActivity --es mode grant"
sleep 3
logs
```

Expected, from the reference device (Redmi M2101K6P, Android 11 / API 30):

```text
I CH30 : EXPLOIT control OK: direct query DENIED (Permission Denial: opening provider
         com.pentest.ch30.victim.SecretProvider from ... (pid=22309, uid=10312)
         that is not exported from UID 10311)
I CH30 : EXPLOIT mode=grant outer=... inner=Intent {
           dat=content://com.pentest.ch30.victim.secrets/secret/1
           flg=0x2000001 cmp=com.pentest.ch30.attacker/.GrantSinkActivity }
I CH30 : DeputyActivity forwarding: Intent { dat=content://...secrets/secret/1
           flg=0x2000001 cmp=com.pentest.ch30.attacker/.GrantSinkActivity }
I CH30 : SINK reached. data=content://...secrets/secret/1 flags=0x2000001
I CH30 : SecretProvider.query uri=content://...secrets/secret/1
           callingUid=10312 callingPackage=com.pentest.ch30.attacker
I CH30 : SINK STOLE: CH30{the_deputy_handed_you_a_grant_it_never_meant_to_give}
```

> **Question 13.** Decode `flg=0x2000001` into named flags. (Two of them. Check
> [README §3.5](../README.md).)
>
> **Question 14.** The `SecretProvider.query` line prints `Binder.getCallingUid()` from **inside the
> provider**. Which uid is it? Why is that the strongest possible evidence for this finding — what
> would a weaker piece of evidence look like, and why would a developer be able to argue with it?
>
> **Question 15.** The nested Intent names a component belonging to the **attacker**. Explain why the
> grant is issued at all, given that the victim would never deliberately grant anything to the
> attacker.
>
> **Question 16.** The URI is set with `setData()`. What would happen if the attacker put it in a
> string extra instead, and why?
>
> **Question 17.** `FLAG_ACTIVITY_FORWARD_RESULT` is also set. It is not needed for this particular
> exploit. Describe a variant of the deputy where it *would* be the thing that made the attack work.

---

## Part 5 — How long does the grant last?

```bash
# host — start the sink on its own, with no deputy in the chain
adb shell logcat -c
adb shell "am start -n com.pentest.ch30.attacker/.GrantSinkActivity"
sleep 2
logs | grep SINK
```

> **Question 18.** Did the grant survive? Quote the result.
>
> **Question 19.** A plain `FLAG_GRANT_READ_URI_PERMISSION` grant is scoped to the receiving
> component. What flag would an attacker add to try to keep it, and what API call would they then
> have to make? (This is [27-ContentProviders](../../27-ContentProviders/README.md)'s ground —
> name it, do not re-derive it.)
>
> **Question 20.** How does the grant's short lifetime affect the severity you assign? Does it change
> the rating for a provider serving a **session token** versus one serving a **document list**?

---

## Part 6 — The package-visibility trap

If your Control B produced a null cursor rather than an exception, this section is why. It is worth
doing even if it did not, because it will catch you on a real engagement.

```bash
# host
grep -B3 -A6 "queries" ../examples/hijacker-app/AndroidManifest.xml
```

Now break it deliberately:

1. Comment out the `<queries>` block in `../examples/hijacker-app/AndroidManifest.xml`.
2. `./build.sh --install`
3. Re-run Part 2 Control B.

```bash
# host
reset
adb shell "am start -n com.pentest.ch30.attacker/.DeputyExploitActivity --es mode grant"
sleep 3
logs | grep "EXPLOIT control"
```

> **Question 21.** What does the control print now? Did `ContentResolver.query()` throw, or return
> something?
>
> **Question 22.** A tester who does not know about package visibility reads that result and concludes
> what? Why is that conclusion wrong, and how much time would it cost them?
>
> **Question 23.** Does the **exploit** still work without `<queries>`? Run the full `mode grant` and
> find out. Explain the result: which operations are subject to package visibility and which are not.
>
> **Question 24.** Restore the `<queries>` block and rebuild. Write the one-sentence rule you would
> tell a colleague about null cursors on API 30+.

---

## Part 7 — The fix, and its residue

```bash
# host
cat ../examples/DeputyActivityFixed.java
reset
adb shell "am start -n com.pentest.ch30.attacker/.DeputyExploitActivity --es mode fixed"
sleep 3
logs
```

> **Question 25.** Was the nested Intent read at all? Which line tells you?
>
> **Question 26.** Was any grant issued? Was the sink reached?
>
> **Question 27.** Look carefully at the last two lines of the log. `InternalActivity` — the
> `exported="false"` Activity — **was still reached**. Explain why, and say whether that is a bug in
> the fix or a separate decision.
>
> **Question 28.** Rewrite the allow-list so that the residual issue in Question 27 goes away. What
> did you have to decide, and who in a real team would have to make that decision?

Now try to break the fix:

> **Question 29.** Try `--es mode fixed` with `dest` set to a value that is not on the allow-list.
> (You will need to edit `DeputyExploitActivity.java`, or use `am` to hit
> `DeputyActivityFixed` directly with `--es dest something`.) What happens, and what is logged? Why
> does the fixed deputy log rejections?
>
> **Question 30.** For each of the five half-fixes in the table in [README §5.3](../README.md), state
> in one sentence why it fails. Then say which single property makes the allow-list approach
> different from all of them.

---

## Part 8 — Watch it with Frida

```bash
# host — terminal 1
cd 30-Activities
frida -U -f com.pentest.ch30.victim -l scripts/activity-trace.js
```

```bash
# host — terminal 2
adb shell "am start -n com.pentest.ch30.attacker/.DeputyExploitActivity --es mode grant"
```

> **Question 31.** The script decodes the flags on the deputy's outgoing `startActivity`. Which
> security-relevant flags does it name, and did you have to compute `0x2000001` by hand this time?
>
> **Question 32.** The script warns on every plain `startActivity` that it has no
> `FLAG_ACTIVITY_NEW_TASK`. Relate that warning to Question 11.
>
> **Question 33.** Run `26-Intent/scripts/intent-surface-map.py --redirect` over a decompiled build of
> the victim. What does it find that `activity-trace.js` does not, and vice versa? Why do the two
> chapters ship different tools rather than one?

---

## Hints

<details>
<summary>Hint for Question 4</summary>

Run `adb shell am start --help` and read the list of extra types. There is `--es`, `--ei`, `--ez`,
`--eu`, `--ecn`, and several array forms. There is no `--eparcelable`, and an `Intent` is a
`Parcelable`. The consequence, spelled out in [README §7.3](../README.md), is that the Parcelable
flavour of this bug is **invisible** to shell probing.
</details>

<details>
<summary>Hint for Question 10</summary>

`getCallingActivity()` is non-null only when the caller used `startActivityForResult`. The deputy used
plain `startActivity`. And even if it were set, it would name the **deputy**, not the attacker — the
deputy is genuinely the caller. There is no mechanism by which `InternalActivity` could learn that
the deputy was acting for somebody else.
</details>

<details>
<summary>Hint for Question 14</summary>

`Binder.getCallingUid()` inside a provider's `query()` is a live Binder transaction, so the uid is
stamped by the kernel and cannot be forged — [25-Binder](../../25-Binder/README.md) demonstrates
exactly that by trying and failing. A weaker piece of evidence would be the sink printing the secret:
a developer can argue the sink got it some other way. The provider naming the attacker's uid closes
that argument.
</details>

<details>
<summary>Hint for Question 23</summary>

Package visibility filters what your app can **see** — resolving a provider authority, querying
package info, resolving components. It does not filter an explicit `startActivity` at a component you
name outright, nor does it un-issue a grant the system already made. So the control breaks and the
exploit does not, which is the worst possible combination for a confused tester.
</details>

<details>
<summary>Hint for Question 27</summary>

The exploit passes `--es mode fixed`, and `DeputyExploitActivity` sets `dest` to `"internal"` for
that mode. `"internal"` is on the allow-list. The fix removed *arbitrary* redirection and grant
laundering; it did not answer the separate question of whether a non-exported screen should be
reachable from outside at all.
</details>

---

## Success criteria

You have completed this lab when you can produce, as evidence:

- [ ] **Control A**: the verbatim `SecurityException` refusing `adb shell` (uid 2000) from starting
      `InternalActivity`, with the owning uid named.
- [ ] **Control B**: the verbatim `SecurityException` refusing the attacker's uid from opening
      `SecretProvider`.
- [ ] A log capture showing `InternalActivity REACHED` through the deputy.
- [ ] A log capture showing the full laundering chain: the send with `flg=0x2000001`, the deputy
      forwarding, the sink reached, and — critically — `SecretProvider.query ... callingUid=<attacker>`.
- [ ] The stolen flag value.
- [ ] A capture showing the grant **not** surviving a later, standalone start of the sink.
- [ ] A capture showing `DeputyActivityFixed` ignoring the identical payload.
- [ ] A written explanation of the residual issue in Question 27, and a rewritten allow-list.
- [ ] A capture of the package-visibility trap: the **null cursor** without `<queries>` and the
      **exception** with it.
- [ ] Two finding write-ups — one for reachability, one for laundering — each with its own severity,
      its own precondition stated in the title, and remediation as code.
- [ ] A one-sentence statement of which chapter owns what: the primitive, the deputy, the grant.

---

## Clean up

```bash
# host
cd 30-Activities/examples
git checkout hijacker-app/AndroidManifest.xml 2>/dev/null || true   # if you edited <queries>
./build.sh --uninstall
```

---

## Where to go next

- [Lab 04 — Tapjacking a consent screen](lab-04-tapjacking-consent.md): a different subsystem
  entirely, and the one lab that needs an unlocked device.
- [27-ContentProviders §5.4](../../27-ContentProviders/README.md) continues from the moment the grant
  is issued: what it is worth, how long it can be made to last, and how to enumerate live grants.
- [26-Intent §5.2](../../26-Intent/README.md) covers the redirection primitive's other flavours,
  including the string/`Intent.parseUri` form that is reachable from a **web page**.
