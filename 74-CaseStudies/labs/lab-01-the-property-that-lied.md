# Lab 01 — The property that lied

> **Level:** Beginner · **Time:** 90 minutes · **Device:** any Android device or AVD; root helps for
> Part 4 but the lab works without it.

---

## What this lab is

You are going to be handed evidence **in the order the original investigator had it**, and asked to
write down a conclusion at three separate points. Then you will be shown what came next.

**The point is not to get it right.** Most readers reach the same wrong conclusion at Step 2 that the
original investigation did, and that is the experience the lab exists to give you. A case study you
read passively teaches you that somebody else was once wrong. A case study you are walked into
teaches you what being wrong *feels like from the inside*, which is the only useful version.

> **⚠️ Write your answers down before scrolling.** Every stop point below is a fold with the answer
> underneath it. Reading ahead costs you the entire lab and takes ninety seconds. Use a text file.

**Objective.** By the end you will be able to say precisely why a client-side verified-boot check is
not a control, distinguish four possible values of one property, and explain why the fix is an
allow-list rather than more values in a deny-list.

> **📖 Provenance — this lab is COMPOSED, and you should notice that.**
> The evidence you are handed comes from **two different devices**: a rooted Redmi `M2101K6P`
> (Android 11 / API 30) in Parts 2–4, and the AVD `sdk_gphone16k_x86_64` (Android 15 / API 35) in
> Part 5. It is assembled from separate measurement sessions into one narrative — a
> **reconstruction, not a transcript.** A transcript would prove the *order* of events; this proves
> only the events.
>
> Both are legitimate artefacts. Presenting a composition as a transcript is not, because narrative
> order then does persuasive work it has not earned. Chapter 74 §1.5 makes this a rule, and Lab 04
> scores you on catching a report that breaks it.

**Prerequisites.** [20-Security-Architecture](../../20-Security-Architecture/README.md) §3.5 helps but
is not required. You need `adb` on your PATH and one device attached.

---

## Part 0 — Establish your instrument

Before any evidence, do what every investigation in this repository does first. This is not
ceremony: every claim you make for the rest of the lab is a claim about this device.

```bash
# host
adb devices -l
adb shell getprop ro.product.model
adb shell getprop ro.build.version.sdk
adb shell getprop ro.build.fingerprint
```

Write the four answers into your notes now. If more than one device is listed, **stop and add `-s
<serial>` to every command below.** A silent wrong-device attach is the worst kind of error, because
every subsequent measurement is internally consistent and about the wrong target.

Then determine your root convention, because getting it wrong reads as *"not rooted"*:

```bash
# host -- try BOTH. Physical devices with Magisk usually take the first;
# the AOSP emulator takes the second and REJECTS the first.
adb shell "su -c id"
adb shell "su 0 id"
```

| Your device | Record it |
|---|---|
| Model | |
| API level | |
| Fingerprint | |
| Root form (`su -c` / `su 0` / none) | |

> **⚠️ Warning — the quoting bug.** Write `adb shell "su -c 'cmd'"`, with the quotes inside. Written
> as `adb shell su -c 'cmd'`, the host shell splits on spaces, `adb` sends `su -c cmd`, and `su` <!-- lint:allow SU-DASH-C SU-DASH-C-BARE -- the broken form, quoted as the counter-example this warning teaches; covers the next line too -->
> consumes the fragments. The symptom is confusing: `adb shell su -c 'magisk -v'` prints *su's*
> version, because `-v` is eaten by `su`.

---

## Part 1 — The first reading

An application wants to know whether the device it is running on booted a verified, unmodified
system. Android exposes the bootloader's verdict as a property. Read it:

```bash
# host
adb shell getprop ro.boot.verifiedbootstate
```

Android documents four values:

| Value | Meaning |
|---|---|
| `green` | Verified, and signed by the OEM key |
| `yellow` | Verified, signed by a user-supplied key |
| `orange` | Bootloader unlocked, nothing verified |
| `red` | Verification was attempted and **failed** |

Here is the check that ships in an enormous amount of real code:

```java
boolean bootIsTrusted() {
    return !"orange".equals(SystemProperties.get("ro.boot.verifiedbootstate"));
}
```

### ⏸ STOP 1 — write your answers

1. What did your device print?
2. What does `bootIsTrusted()` return on your device?
3. On a scale of "I would build a fraud rule on this" to "I would ignore it", how much do you trust
   the answer? **Write one sentence saying why.**

---

## Part 2 — A second device, and the evidence you would actually have had

You do not have the phone the original investigation used, so this part hands you its readings. It
is a **rooted Redmi `M2101K6P`, Android 11 / API 30**, with an unlocked bootloader. The tester knows
it is rooted — they rooted it themselves.

```
# adb shell, on the rooted Redmi
$ adb shell getprop ro.boot.verifiedbootstate
green

$ adb shell getprop ro.boot.veritymode
enforcing
```

### ⏸ STOP 2 — the important one

The device is definitely rooted and its bootloader is definitely unlocked. The property says `green`,
which means *verified and signed by the OEM key*.

1. Write down **every explanation you can think of** for that pair of facts. Aim for at least three.
2. Which is most likely? Commit to one.
3. **What single measurement would distinguish them?** This is the real question, and it is the skill
   the lab is teaching. Write the command if you can.

<details>
<summary><b>Only after writing your answers — the explanations most people produce</b></summary>

Typical lists include:

- **The property is stale**, set at some earlier boot and not updated.
- **The property was never implemented properly** by this OEM, and always says `green`.
- **The property is being lied about** by something on the device.
- **The device is not actually as unlocked as I think** — maybe root came another way.
- **`green` does not mean what I think it means.**

All five are reasonable. Notice that four of them are about the *property*, and only one is about the
*device*. That bias is the trap: it is much easier to doubt your interpretation than to doubt the
data source.

Now the second question. **What would distinguish them?** Almost everyone reaches for *another
reading of the same property*, or for a different property. Both fail, and for the same reason —
whatever rewrote one value can rewrite the others.

The measurement that works has a specific shape: **a source with a different trust story.** Not a
second reading. A reading the adversary could not have produced.

</details>

---

## Part 3 — The hardware answers

The original investigation asked the TEE. A key attestation certificate is signed inside the secure
processor, and it carries a `rootOfTrust` structure with the same three facts. Root cannot forge it,
because the signing key never leaves the hardware.

Taken on the same device, seconds after the `getprop` above:

```
  attestationSecurityLevel : TrustedEnvironment
  HARDWARE-ENFORCED (trustworthy)
    rootOfTrust:
      verifiedBootState : Unverified
      deviceLocked      : False
      verifiedBootKey   : 0000000000000000000000000000000000000000000000000000000000000000
```

### ⏸ STOP 3

1. Which of your Part 2 explanations survives?
2. Why is this evidence stronger than the `getprop` reading, in one sentence? **Do not answer "it is
   more accurate."**
3. What does the all-zero `verifiedBootKey` add that `verifiedBootState: Unverified` does not?

<details>
<summary><b>Answers</b></summary>

**1.** Only "the property is being lied about." The hardware reports an unlocked device with nothing
verified, so the property is not stale, not unimplemented, and `green` means exactly what you thought.

**2.** Not accuracy — **provenance.** The property is a string in a shared-memory region that any
root process can rewrite. The attestation is signed by a key that never leaves the TEE. When two
sources disagree, the question is never which is more recent or more specific; it is **which one the
attacker could have written.**

**3.** `Unverified` is a *state*. The all-zero key says **no key verified this boot at all** — it is
not a key that failed to match, it is the absence of any verification having taken place. A device
that had genuinely attempted verification and failed would show `red` and a real key.

</details>

---

## Part 4 — Where did the lie come from?

`init` derives every `ro.boot.X` property from an `androidboot.X` parameter supplied by the
bootloader, on the kernel command line or in bootconfig. So there is a source to compare against.

Try it on your own device first:

```bash
# host -- as root. Substitute your device's form.
adb shell "su 0 cat /proc/bootconfig"
adb shell "su 0 cat /proc/cmdline"
```

Then, without root:

```bash
# host -- as shell, uid 2000
adb shell "cat /proc/bootconfig"
adb shell "cat /proc/cmdline"
```

### ⏸ STOP 4

1. Could you read them without root? Record the exact error.
2. **What does that imply about the application performing the check?**

<details>
<summary><b>Answer</b></summary>

On the reference AVD both return `Permission denied` to uid 2000. On the Redmi, `/proc/cmdline` is
mode `-r--r----- root radio`, so an ordinary application cannot read it either.

**The cross-check that catches the forgery cannot be performed by the process doing the checking.**
The application can read the forgeable source and cannot read the honest one.

That single sentence is the difference between "this check is badly implemented" and "this check is
structurally unsound", and they have completely different remediations. The first invites "we'll add
more checks." The second forces the answer in Part 6.

</details>

Here is what the original investigation found on the Redmi:

```
getprop ro.boot.verifiedbootstate     ->  green
getprop ro.boot.vbmeta.device_state   ->  locked
getprop ro.boot.flash.locked          ->  1

androidboot.verifiedbootstate=orange
androidboot.vbmeta.device_state=unlocked
androidboot.vbmeta.digest=e8ff1960b98291b6a5ee5ffba80da2be5cdde2594a5a79966871675a47abe7d3
androidboot.veritymode=enforcing
```

### ⏸ STOP 5 — the subtle one

Fill in this table from the data above, then answer the question underneath.

| Claim | Kernel command line | `getprop` | Forged? |
|---|---|---|---|
| Verified boot state | | | |
| Device state | | | |
| Bootloader lock | | | |
| vbmeta digest | | | |
| verity mode | | | |

**The question: what did the attacker NOT change, and what should you conclude from that?**

<details>
<summary><b>Answer</b></summary>

| Claim | Kernel command line | `getprop` | Forged? |
|---|---|---|---|
| Verified boot state | `orange` | **`green`** | **yes** |
| Device state | `unlocked` | **`locked`** | **yes** |
| Bootloader lock | *(not present)* | `1` | **yes** |
| vbmeta digest | `e8ff1960…e7d3` | `e8ff1960…e7d3` | no |
| verity mode | `enforcing` | `enforcing` | no |

**Three fields changed; two left honest.** The hiding module edited exactly the fields detection code
reads, because every extra edit is another chance to be caught in an inconsistency.

And the conclusion most people draw is **wrong**. "This device failed the boot-state check, so
nothing on it can be trusted" sounds right and throws away your two best signals. `vbmeta.digest` and
`veritymode` came through honestly and are still usable — indeed they are what caught the forgery.

**Expect targeted forgery. Grade per-signal, never per-device.**

</details>

---

## Part 5 — The fourth value

Run this on an emulator if you have one, and read it carefully:

```bash
# host
adb shell getprop ro.boot.verifiedbootstate | cat -A
```

The `| cat -A` matters. Without it you cannot distinguish "the property is empty" from "the command
failed and printed nothing" — they look identical on a terminal. With it, an empty property shows as
a line terminator and nothing else.

On the reference AVD `sdk_gphone16k_x86_64` (API 35) the property is **the empty string**. Not
`orange`. Not any documented value. And the cause is visible in bootconfig: there is no
`androidboot.verifiedbootstate` for `init` to derive it from, while `androidboot.veritymode` and
`androidboot.vbmeta.digest` are both present and both produce populated properties.

### ⏸ STOP 6

1. What does `!"orange".equals("")` evaluate to?
2. State the consequence in one sentence, as you would write it in a report.

<details>
<summary><b>Answer</b></summary>

**1.** `true`.

**2.** *"The check passes on an emulator — the least trustworthy platform it can possibly
encounter — because the property is absent rather than bad, and the implementation treats every
value except one as acceptable."*

"Absent" and "reported a bad state" are different conditions. Code that conflates them gets the
wrong answer, and it gets it in the failing-open direction.

</details>

---

## Part 6 — Write the fix, and write the finding

### The fix

Two lines. Write them before looking.

<details>
<summary><b>Answer</b></summary>

```java
// Allow-list the good value. Never deny-list the bad one.
// "", "orange", "red", "yellow" and any future value all fall through to false.
boolean bootIsTrusted() {
    return "green".equals(SystemProperties.get("ro.boot.verifiedbootstate"));
}
```

Note the argument order: `"green".equals(x)` and not `x.equals("green")`. The second throws
`NullPointerException` if the property read returns `null`, which is a different failure mode you do
not want to discover in production.

**But this is a mitigation, not a fix.** It closes the empty-string hole and leaves the forgery hole
wide open, because a root process rewrites `green` just as easily as it rewrites anything else. The
real remediation is architectural: generate an attestation-backed key, send the certificate chain to
your server, and read `rootOfTrust` **there**. See
[50-HardwareBackedSecurity](../../50-HardwareBackedSecurity/README.md).

</details>

### The finding

Write the finding as it would appear in a report: one title, one severity, three sentences of
evidence, one remediation.

<details>
<summary><b>A defensible version</b></summary>

> **Client-side verified-boot check provides no integrity assurance — Medium (design)**
>
> The application determines device integrity by reading `ro.boot.verifiedbootstate` and accepting
> any value other than `orange`. On a rooted test device the property read `green` while a TEE-signed
> key attestation taken seconds later on the same device reported `verifiedBootState=Unverified`,
> `deviceLocked=false` and an all-zero `verifiedBootKey`; the kernel command line for the same boot
> carried `androidboot.verifiedbootstate=orange`. On an emulator the property is the empty string and
> the check therefore passes.
>
> The property is not authenticated: any process with root can rewrite it, and the source that would
> reveal the rewrite (`/proc/cmdline`, `/proc/bootconfig`) is unreadable to the application. Move the
> decision server-side using Android Key Attestation and validate `rootOfTrust` against Google's
> roots. If the client-side signal is retained, allow-list `"green"` and treat it as telemetry, never
> as evidence.

Note what it does **not** say. Not "verified boot bypass" — nothing was bypassed. Not Critical — the
application is asking a client-side check to do something no client-side check can do, which is a
design finding. And it names the *structural* reason rather than only the symptom, so the developer
cannot close it by adding another property to the deny-list.

</details>

---

## Part 7 — Automate the replay

```bash
# host -- from the chapter's scripts directory
./case-replay.sh -s <serial> --case A
```

This re-runs every assertion in Part 1, 5 and 6 and prints `REPRODUCED` or `DIVERGED` per line. On
the reference AVD it reports eight reproduced and zero diverged.

If you see `DIVERGED`, that is a **question, not a verdict on anybody.** Rule out, in order: a
different device; a different vantage (root, shell or app); a different tool version; a different
command than the one printed. If none explains it, the honest verdict is *diverged, cause not
established* — and publishing that, with the evidence, is more useful than a confident guess.

---

## Success criteria

You have finished when you can do all six without looking anything up:

- [ ] Name the **four** values of `ro.boot.verifiedbootstate` observed in this repository, including
      the one that is not in any documentation table.
- [ ] Explain why a TEE attestation beats a property **without using the word "accurate"**.
- [ ] State which two fields the hiding module left honest, and why that matters to your grading.
- [ ] Explain why the application cannot perform the `/proc/cmdline` cross-check itself.
- [ ] Write the allow-list fix from memory, with the argument order right, and say why it is a
      mitigation rather than a fix.
- [ ] Say what is wrong with the phrase "verified boot bypass" as a finding title.

---

## What to carry into Lab 02

The technique that broke this case is **find a source with a different trust story**. Not a second
reading, not a better tool — a reading the adversary could not have produced.

Lab 02 uses a different technique for a different failure: **check the proposition you actually care
about.** There, everything you measure will be true and you will still be wrong, because you will
have proved something adjacent to what you meant.

---

## Related

| Chapter | Why |
|---|---|
| [20-Security-Architecture](../../20-Security-Architecture/README.md) | Owns the `/proc/cmdline` forgery; its `lab-01` builds a full posture classification |
| [50-HardwareBackedSecurity](../../50-HardwareBackedSecurity/README.md) | Owns attestation; ships the probe and parser scripts |
| [61-Fastboot](../../61-Fastboot/README.md) | Owns the empty-string measurement and the bootconfig inventory |
| [37-RootDetection](../../37-RootDetection/README.md) | The property is one signal among many; owns the catalogue |
