# Lab 04 — CTF: The Courier

**Difficulty:** Advanced
**Time:** 3–5 hours
**Prerequisites:** [Lab 01](lab-01-intent-redirection.md), [Lab 02](lab-02-resolution-forensics.md),
[Lab 03](lab-03-applink-verification.md), and all of
[Chapter 26 §3](../README.md#3-deep-internal-working)
**Target:** [`../examples/deputy-app/`](../examples/deputy-app/), which you build yourself
**Tooling:** [`../scripts/intent-surface-map.py`](../scripts/intent-surface-map.py),
[`../scripts/intent-monitor.js`](../scripts/intent-monitor.js),
[`../scripts/appstate-linkcheck.sh`](../scripts/appstate-linkcheck.sh)

---

## The brief

A courier does not open the parcel. It carries what it is given, to where it is
told, and it carries the sender's authority with it because that is what a courier
*is*.

`com.pentest.deputy` is a courier. It has four flags. Each one is behind a
different mechanism from this chapter, and each one is reachable only by
understanding that mechanism — there is nothing to brute force, nothing to guess,
and no string hidden in a resource file.

| Flag | Mechanism | Where the answer lives in the chapter |
|---|---|---|
| **A** | Resolution: the `<data>` cross product | [§3.4](../README.md#how-multiple-data-elements-combine--the-cross-product) |
| **B** | Intent redirection | [§5.2](../README.md#52-intent-redirection--the-primitive-in-full) |
| **C** | `PendingIntent` mutability | [§3.9](../README.md#39-pendingintent--a-capability-you-hand-to-someone-else) |
| **D** | `CATEGORY_DEFAULT` | [§3.4](../README.md#test-2--category) |

All four flags are of the form `FLAG{lower_snake_case_words}`.

### Rules

1. **You may not read the target's Java source until you have the flag.** Read the
   manifest, the smali, and the device. That is the engagement you would actually
   have. The sources are in the repository; the discipline is yours to keep.
2. `adb shell` is allowed for *reconnaissance*. Flag B must be obtained from an
   **unprivileged app**, and you must be able to show the negative control.
3. Every flag needs a **write-up**: the command or code that produced it, and one
   paragraph explaining the mechanism. A flag without a mechanism is a guess.

### Scoring

| | Points |
|---|---|
| Each flag | 15 |
| Each write-up that correctly names the mechanism | 10 |
| Negative control captured for flag B | 10 |
| The remediation for each flag, written as code or XML | 5 each |
| **Bonus:** flag A obtained *without ever firing an Intent* — from `dumpsys` alone | 15 |
| **Bonus:** explaining why flag C cannot be obtained by redirection | 15 |
| **Penalty:** reading the target's `.java` before capturing a flag | −20 per flag |
| **Total available** | **150** |

---

## Setup

```bash
# host
cd 26-Intent/examples/deputy-app
./build.sh
adb install -r out/deputy.apk
adb install -r out/attacker.apk
```

> **If `adb install` fails**
> Some OEM builds refuse with `INSTALL_FAILED_USER_RESTRICTED` — measured on the
> Redmi / MIUI 12.5 / Android 11 device used to write this chapter. MIUI gates USB
> installation behind a developer-options toggle tied to a vendor account. Use an
> emulator (`emulator -avd <name>`), where none of this applies.

```bash
# host — terminal 1, leave running
adb logcat -c
adb logcat -s DEPUTY:* ATTACKER:I AndroidRuntime:E ActivityTaskManager:E
```

Grep for flags with:

```bash
# host
adb logcat -d | grep -o 'FLAG{[^}]*}' | sort -u
```

---

## Reconnaissance — do this before touching anything

```bash
# host — what did the platform record?
python3 ../scripts/intent-surface-map.py --package com.pentest.deputy --components --verify

# host — the manifest as the platform parsed it
adb shell "dumpsys package com.pentest.deputy" | sed -n '/Activity Resolver Table/,/Key Set Manager/p'

# host — the manifest as shipped
aapt2 dump xmltree --file AndroidManifest.xml out/deputy.apk | sed -n '/E: activity/,$p' | head -80

# host — the declaration audit belongs to chapter 32; run it, it is free
aapt2 dump xmltree --file AndroidManifest.xml out/deputy.apk > tree.txt
python3 ../../32-Manifest/scripts/manifest-audit.py --format xmltree tree.txt --min-severity LOW
```

**R1.** List every activity, its export state, and whether it has a filter. Which
ones are in the resolver tables and which are not? Why is that not the same
question as "which ones are reachable"?

**R2.** One component has **two** filters with very different shapes. Which, and
what is different about the second one?

**R3.** One filter declares more `<data>` elements than it looks like it needs.
Which, and how many URIs does it actually accept?

---

## Flag A — the cross product

**Difficulty:** 2/5

> *The developer wrote down two addresses. The courier accepts four.*

`VaultActivity` declares a `BROWSABLE` filter with two `<data>` elements. The
developer wrote two pairs. The platform stores schemes and authorities as
**independent sets**, so it accepts every combination.

**A1.** From `dumpsys package com.pentest.deputy` alone — without firing anything —
enumerate every URI that filter accepts. There are four. Write them down.

```bash
# host
adb shell "dumpsys package com.pentest.deputy" | grep -A12 VaultActivity
```

The bucket structure is the giveaway: `Scheme:` lines and `Authority:` lines are
printed as two **flat lists**, not as a list of pairs. That is the platform's own
data structure telling you the answer, and getting the flag this way is worth the
first bonus.

**A2.** Two of the four are meant to work. Two are not. Confirm all four
resolve:

```bash
# host
for u in "deputy://locker" "vault://open" "deputy://open" "vault://locker"; do
  printf '%-20s ' "$u"
  adb shell "cmd package query-activities -a android.intent.action.VIEW \
      -c android.intent.category.BROWSABLE -d '$u'" | head -1
done
```

**A3.** Fire the one the developer never intended:

```bash
# host
adb shell "am start -a android.intent.action.VIEW \
    -c android.intent.category.BROWSABLE -d '<the unintended URI>'"
```

**A4.** Flag A is in logcat under tag `DEPUTY`. Capture it.

**A5.** Write-up: explain in one paragraph *why* a filter with two `<data>`
elements accepts four URIs. Name the class and method in AOSP where the sets are
stored and compared.

**A6.** Remediation: rewrite the filter so it accepts exactly the two URIs the
developer meant, and explain why your version cannot be got wrong again.

**A7.** This filter is `BROWSABLE`. What does that add to the severity, in one
sentence?

---

## Flag B — the courier carries your parcel

**Difficulty:** 3/5

> *You are refused at the door. So you post the parcel to somebody who is not.*

`SecretActivity` is `android:exported="false"`. Reaching it from an unprivileged
app is flag B, and this is lab 01's exercise — do it again, cold, and this time
produce the artefacts as evidence rather than as a walkthrough.

**B1.** Prove first that you cannot reach it. From the attacker app — **not** from
`adb shell`:

```java
Intent direct = new Intent();
direct.setComponent(new ComponentName("com.pentest.deputy",
                                      "com.pentest.deputy.SecretActivity"));
direct.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
startActivity(direct);   // must throw
```

Capture the `Permission Denial` line. It names both UIDs; that is your negative
control and it is worth 10 points on its own.

**B2.** Now reach it through the courier. Use `../examples/attacker-app/` as
supplied, or write your own — fifteen lines is the whole thing.

**B3.** Flag B appears in logcat. Capture it.

**B4.** Run the exploit again with the monitor attached to the deputy:

```bash
# host
frida -U -f com.pentest.deputy -l ../scripts/intent-monitor.js
```

Quote the `[taint]` line and the `[!!] REDIRECTION` block. What did the `flags`
line decode to?

**B5.** Write-up: explain precisely why the second `startActivity` succeeded when
the first was refused. Your paragraph must name the comparison
`ActivityStarter` performs and say which value changed between the two starts.

**B6.** There is a second, **web-reachable** way into the courier. Find it in the
manifest, and reach `SecretActivity` using only `am` and a string — no attacker
app.

```bash
# host — mind the inner quotes; ';' is a device-shell separator
adb shell "am start -n com.pentest.deputy/.RedirectorActivity \
    --es next_uri 'intent:#Intent;component=...;end'"
```

**B7.** Which of the two flavours is more severe, and why? Answer in terms of what
the attacker needs to have on the device.

**B8.** Remediation: write the validation. Then run your identical payload at
`.RedirectorActivityFixed` and show it refused. (If you write your own fix, test it
against variants (d) and (e) from lab 01 — a null component, and a package hint
with no component.)

---

## Flag C — the blank cheque

**Difficulty:** 4/5

> *The courier hands you a signed form with the destination left empty.*

`TokenActivity` is exported and hands out two `PendingIntent`s. One of them is
mutable and wraps an under-specified Intent. `VaultActivity` will print flag C —
but only when the arriving Intent carries a **nonce** that lives inside the token's
wrapped Intent.

That nonce is the point of the challenge:

- You cannot read it. On modern platforms the holder of a `PendingIntent` cannot
  inspect the wrapped Intent's extras.
- You cannot guess it. It is 64 random bits, regenerated per process.
- You cannot reach `VaultActivity` with it by **redirection**, because redirection
  builds *your* Intent, and you do not have the nonce to put in it.
- `Intent.fillIn` preserves the base Intent's extras while letting you supply the
  fields the base left unset — including the **component**.

So arriving at `VaultActivity` with a valid nonce is proof that you filled in and
fired the mutable token. That is exactly the property the flag is testing.

**C1.** Get the token. `TokenActivity` returns both tokens as extras of its result,
so you must call it with `startActivityForResult`:

```java
Intent ask = new Intent();
ask.setComponent(new ComponentName("com.pentest.deputy",
                                   "com.pentest.deputy.TokenActivity"));
ask.setAction("com.pentest.deputy.GET_TOKEN");
startActivityForResult(ask, 7001);
```

In the supplied attacker app this is on the **long-press** of the button.

**C2.** Before you fire anything, interrogate the token:

```java
PendingIntent pi = data.getParcelableExtra("vulnerable_token");
Log.i("ATTACKER", "creatorPackage=" + pi.getCreatorPackage()
                + " creatorUid="    + pi.getCreatorUid());
```

**C3.** What do `getCreatorPackage()` and `getCreatorUid()` return, and — this is
the interesting part — **who stamped those values**? Which of the three identity
tiers from [§3.8](../README.md#38-caller-identity--the-honest-answer) is this?

**C4.** Fire it with a fill-in that names `VaultActivity`:

```java
Intent fillIn = new Intent();
fillIn.setComponent(new ComponentName("com.pentest.deputy",
                                      "com.pentest.deputy.VaultActivity"));
pi.send(this, 0, fillIn);
```

You will need to edit `ExploitActivity.java`'s `PRIZE` constant, or add a second
fill-in. Rebuild with `./build.sh`.

**C5.** Flag C appears in logcat. Capture it.

**C6.** Now fire the **safe** token with the identical fill-in.

**C7.** Where did you land? Explain, in terms of `Intent.fillIn`, why the fill-in's
component was ignored. Then explain why the *nonce* still arrived.

**C8.** Write-up: describe the order of operations inside `PendingIntentRecord`.
Which happens first, the merge of attacker data or the assumption of the creator's
identity? Why does that order make this a vulnerability rather than a curiosity?

**C9.** Bonus (15 points): explain why you could **not** have obtained flag C by
intent redirection through `.RedirectorActivity`, even though redirection also
reaches `VaultActivity`. Be precise; the answer is one sentence about what you do
and do not possess.

**C10.** Remediation: rewrite `blankCheque()` so it is safe, and say what you would
tell a developer who replies "but I need it mutable for a notification reply". Then
say what changes about this whole challenge on `targetSdk` 31 — and prove it:

```bash
# host
./build.sh --target-sdk 31 && adb install -r out/deputy.apk
```

**C11.** On an API 31+ device, what happens when `TokenActivity` runs after that
rebuild if you *remove* the `FLAG_MUTABLE` it passes? Quote the exception.

---

## Flag D — the door with no handle

**Difficulty:** 3/5

> *There is a door in the plans. It has no handle on the outside. It is still a door.*

One of `VaultActivity`'s filters declares an action and **no**
`android.intent.category.DEFAULT`.

**D1.** Find it. Two commands will do:

```bash
# host
adb shell "dumpsys package com.pentest.deputy" | grep -B4 -A6 VAULT_DIRECT
adb shell "cmd package query-activities -a com.pentest.deputy.VAULT_DIRECT"
```

**D2.** Try to reach it implicitly:

```bash
# host
adb shell "am start -a com.pentest.deputy.VAULT_DIRECT"
```

What happened, and why? Answer before reading on.

**D3.** `cmd package query-activities` **found** the component in D1, and
`am start` **failed** in D2, with the same action. Those two facts look
contradictory. Reconcile them. (Hint: one of the two adds a category and the other
does not.)

**D4.** Now reach it. Flag D appears in logcat.

**D5.** Write-up: explain the difference between "not reachable implicitly" and
"not reachable", and write the single sentence you would put in a report to
describe this component's reachability. Neither "reachable" nor "not reachable" is
correct.

**D6.** Remediation: is there one? Think carefully. Is the absence of
`CATEGORY_DEFAULT` a vulnerability, a mitigation, or neither? Argue it, then say
what you would actually recommend for a component in this position.

---

## Final challenge — the report

Write the engagement report for `com.pentest.deputy`. Not four flags: one document.

It must contain:

1. **An executive summary** in three sentences, naming the impact, not the
   mechanism.
2. **A findings table** with severity, component, reachability and consequence for
   each issue. Severities must be defensible — re-read
   [§5.2](../README.md#52-intent-redirection--the-primitive-in-full)'s
   honest-severity warning before you assign any of them.
3. **Reachability evidence** for every finding, from an unprivileged app where the
   finding claims an unprivileged attacker, plus the negative control.
4. **Remediation as code**, not as advice, for every finding.
5. **A "not a finding" section.** At least two things in this app look wrong and
   are not. Name them and say why. (Candidates: the exported `TokenActivity`, the
   `BROWSABLE` filter itself, the exported `.RedirectorActivityFixed`, the absence
   of `CATEGORY_DEFAULT` on the second filter.) This section is what separates a
   report from a scanner dump, and a reviewer will read it first.

---

## Success criteria

- [ ] All four flags captured, each with the command or code that produced it
- [ ] A mechanism write-up for each flag that names the AOSP class or method involved
- [ ] Flag A obtained from `dumpsys` alone, before any Intent was fired (bonus)
- [ ] Flag B obtained from an **unprivileged app**, with the `Permission Denial`
      negative control captured and both UIDs recorded
- [ ] Flag B also obtained via the string/URI flavour, from `am` alone, and the two
      flavours' severities compared
- [ ] Flag C obtained by filling in and firing the mutable token; the safe token
      fired with the same fill-in and the difference explained
- [ ] The explanation of why flag C is unreachable by redirection (bonus)
- [ ] Flag D obtained, and the reachability sentence written correctly
- [ ] The `--target-sdk 31` rebuild performed, and the API-31 mandate demonstrated
      rather than described
- [ ] Remediation written as code or XML for every flag
- [ ] A report produced, including a **"not a finding"** section with at least two
      entries
- [ ] `./build.sh --clean` run and both apps uninstalled

---

## Debrief

1. Rank the four flags by the severity you would assign them in a real engagement,
   and justify the ordering. Does it match the difficulty ordering? If not, what
   does that tell you about difficulty as a proxy for severity?

2. Three of the four flags are *not* memory-safety bugs, *not* crypto bugs, and
   *not* injection. What class are they? Name the single property of the Intent
   subsystem that makes all three possible.

3. For each flag, say what an automated scanner would report and whether it would
   be right. Be specific about the false positives.

4. Flag C's nonce is what makes the challenge honest. Design an equivalent
   safeguard for flag B — something that would prove the solver used redirection
   and not some other route. Is it possible? Why is it harder than flag C's?

5. `TokenActivity` can see its caller (`getCallingActivity()` is non-null, because
   the attacker used `startActivityForResult`) and hands over the token anyway.
   Write the two-sentence lesson.

6. The deputy app declares nine components. Six are non-exported. How many of the
   six did you reach during this CTF, and by how many distinct routes?

7. You are the platform engineer. Pick **one** change to Android that would kill
   the largest number of these four flags at once, and defend the choice against
   the compatibility cost.

8. Write the paragraph you would put at the top of a client report explaining why
   "we do not export anything sensitive" is not a sufficient answer to any of this.

---

## Cleanup

```bash
# host
adb uninstall com.pentest.attacker
adb uninstall com.pentest.deputy
cd 26-Intent/examples/deputy-app && ./build.sh --clean
rm -f tree.txt
```

Leaving the deputy installed leaves an exported router with a nested-Intent bug on
your device. It will be found by the next Intent-surface scan run on that device,
and there is a reasonable chance the person running that scan will be you, in six
months, on a real engagement, wondering why the client's phone has a "Deputy
(vulnerable)" app on it.
