# Lab 03 — Live triage, and saying "I do not know" correctly

> **Difficulty:** Senior
> **Time:** 45 minutes live, 30 minutes marking.
> **Prerequisites:** an emulator or a device **you own**, `adb` on `PATH`, and this
> repository. A partner is ideal; section 4.2 makes it work solo.
> **Constraint:** observed, timed, and **four of the eleven questions cannot be answered from
> the evidence available.** Answering them anyway is the failure this lab measures.

---

## 1. Why this lab exists

[Lab 01](lab-01-timed-mock-technical-round.md) measures whether you can scope an answer.
[Lab 02](lab-02-take-home-with-a-rubric.md) measures what you produce on paper. Neither
measures the thing that decides most senior interviews: **what you do when the evidence in
front of you does not support the claim you are being invited to make.**

That moment is common in real work and constant in interviews. Someone asks a question whose
answer sounds obtainable, you have a terminal open, and the honest answer is "the data in
front of me does not settle that". Under observation, with a clock, almost everybody produces
something instead.

This lab is eleven questions during a live device session. **Seven are answerable from the
device. Four are not** — either the evidence is not present, or the vantage is wrong, or the
question is unanswerable in principle. You are graded as much on correctly refusing the four
as on correctly answering the seven, and a candidate who "answers" all eleven scores lower
than one who answers seven and refuses four.

> **Mental Model**
> This is calibration measured directly. In interviews the interviewer estimates it
> indirectly, by seeding questions whose answer they know is counter-intuitive and watching
> whether you hedge. Here the seeding is explicit and the marking key is published, so you can
> see your own false-positive rate as a number.

---

## 2. Objective

By the end of this lab you will have:

1. Run a live 45-minute device triage under observation, on a device you own.
2. Answered or refused eleven questions, aloud, with a running clock.
3. A **calibration score**: how many of the four unanswerable questions you correctly refused,
   and how many of the seven answerable ones you actually answered.
4. A recording, and a marked transcript against the four-part refusal structure.

---

## 3. Authorisation and setup

Everything in this lab runs against a device you own — an emulator you created, or your own
spare handset. Every command below is **read-only**: it prints, it does not modify. Nothing is
installed, no setting is changed, nothing is written to the device. See
[SECURITY.md](../../SECURITY.md) for authorised-testing scope.

```bash
# host — confirm exactly one device, and identify it. Never skip this.
adb devices -l
adb shell getprop ro.product.model
adb shell getprop ro.build.version.release
adb shell getprop ro.build.version.sdk
```

Write the model, release and API level at the top of your notes. **Every answer you give in
the next 45 minutes is an answer about that device**, and an answer that cannot name its
device is an anecdote. Interviewers notice when a candidate says "on this device" and they
notice when a candidate does not.

The transcript in this lab was produced against:

```
sdk_gphone16k_x86_64 (emu64xa16k) — Android 15 / API 35 — x86_64 — userdebug/dev-keys
```

Your device will differ. **Where your device disagrees with the outputs quoted here, your
device is right** and the interesting exercise is working out why.

### 3.1 Recording

Record audio. As in Lab 01, this is not optional: you cannot mark your own refusals from
memory, because memory reconstructs the careful answer you meant to give.

---

## 4. Running the round

### 4.1 With a partner (preferred)

Your partner reads the eleven questions from section 5 in order, one at a time, and does
**not** look at the marking key in section 6 first. They:

- give you the question, and start a stopwatch;
- say nothing while you work;
- after each answer, ask exactly one follow-up: **"how do you know?"**;
- move on after four minutes regardless.

That single follow-up is the whole apparatus. It is what real interviewers use, it costs
nothing, and it separates an answer from a guess with high reliability.

### 4.2 Solo

Cover section 5 with your hand and reveal one question at a time. Set a four-minute timer per
question. After each answer, say "how do you know?" out loud and answer that too — it feels
absurd and it works, because the failure being trained is a reflex, and reflexes are trained
by repetition rather than by insight.

**Solo has one weakness you must compensate for:** you know four of the eleven are traps, so
you will be primed to refuse. Real interviews do not warn you. Compensate by running section 8
in four weeks with a partner who has not read this file.

---

## 5. The eleven questions

Answer each **aloud**, using the terminal freely. Four minutes each. Do not read section 6.

---

**Q1.** Is this device rooted? Show me.

---

**Q2.** Is there a `su` binary on this device, and does an app see it?

---

**Q3.** Would the most commonly published `isEmulator()` function return `true` here?

```java
return Build.FINGERPRINT.startsWith("generic")
    || Build.MODEL.contains("Emulator")
    || new File("/dev/qemu_pipe").exists();
```

---

**Q4.** Is verified boot enabled on this device?

---

**Q5.** How many system properties can an ordinary application read on this device?

---

**Q6.** Is this device faster or slower than a physical phone of the same generation?

---

**Q7.** Does this device's system CA store contain an interception certificate?

---

**Q8.** Which mounted filesystems on this device are integrity-protected at runtime?

---

**Q9.** An application on this device performs a root check by calling
`new File("/system/xbin/su").exists()`. Will the check fire?

---

**Q10.** Is the Android build on this device patched against the most recent Android Security
Bulletin?

---

**Q11.** If an app on this device stores a secret in an Android Keystore key, is that key
hardware-backed?

---

## 6. The marking key

**Only read this after you have answered all eleven.**

### 6.1 Which are which

| Q | Answerable? | Why |
|---:|---|---|
| 1 | **Yes** | directly observable, several independent ways |
| 2 | **Yes** | observable, and the interesting half is the vantage |
| 3 | **Yes** | all three inputs are readable in one command each |
| 4 | **Partly — and the honest answer is a refusal to answer as asked** | the property may be *empty*, which is not the same as any of its documented values |
| 5 | **No, not from `adb shell`** | the shell is a different SELinux domain; the app's count is not measurable from where you are standing |
| 6 | **No, not without the other device** | a comparison needs two measurements and you have one |
| 7 | **Yes** | observable from the mount table and the store's contents |
| 8 | **Yes** | observable from the device-mapper tables, and **not** from the image's own descriptors |
| 9 | **Yes** | and the answer is the opposite of the obvious one |
| 10 | **No** | the property is a *claim*, and it is not verifiable from the device |
| 11 | **No, not from the shell** | requires a key, an attestation and a verifier — and the answer would be about *that key*, not the device |

**Four unanswerable: Q5, Q6, Q10, Q11.** Q4 is a fifth, softer one, where the correct move is
to answer a *different, precise* question and say that you are doing so.

### 6.2 Question by question

---

#### Q1 — Is this device rooted?

**Answerable.** The strongest evidence needs no permission at all:

```bash
# adb shell — on the reference AVD, 2026-08-16
$ grep -c magisk /proc/self/mountinfo
3
```

Three mount entries whose source is literally `magisk`. That reproduces
[63-LSPosed](../../63-LSPosed/README.md)'s measurement on a second occasion, and it is readable
from every vantage tested including an app uid.

Corroboration:

```bash
# adb shell — note su 0, NOT su -c, on an emulator
$ su 0 id
uid=0(root) gid=0(root) ... context=u:r:su:s0
```

**Weak answer:** "yes, `su` worked." True and thin.
**Strong answer:** names the mountinfo evidence, notes it needs no privilege, corroborates
with `su 0`, and says which rooting stack — because the answer to "what grants root here" is
not the same as "is there a `su` on disk". On this device Magisk 30.7 does, from
`/debug_ramdisk`.

**Trap to avoid:** `adb shell su -c id` on an emulator returns `su: invalid uid/gid '-c'`, <!-- lint:allow SU-DASH-C SU-DASH-C-BARE -- the broken form, named as the trap the candidate is being tested on -->
which reads exactly like *not rooted*. A candidate who concludes "not rooted" from that has
made a real and previously-recorded mistake.

---

#### Q2 — Is there a `su` binary, and does an app see it?

**Answerable, and the second half is the point.**

```bash
# adb shell — reference AVD
$ ls -ld /system/xbin ; ls -l /system/xbin/su
drwxr-x--- 2 root shell  4096 /system/xbin
-rwsr-x--- 1 root shell 51224 /system/xbin/su
```

**Weak answer:** "yes, `/system/xbin/su` exists."
**Strong answer:** "Yes from here, and **no from an app.** `/system/xbin` is `0750
root:shell`, so `adb shell` — uid 2000, group `shell` — can traverse it and an app uid gets
`EACCES`. `File.exists()` maps `EACCES` and `ENOENT` alike to `false`. And that binary is not
what grants root here anyway; it is AOSP's `userdebug` `su`, which is present by design on a
`userdebug` build."

This is the single highest-value answer in the lab, because it is a fact, a mechanism, a
vantage caveat and a correction of a widely-held belief, in four sentences.

---

#### Q3 — Would the published `isEmulator()` return `true`?

**Answerable, and the answer is no.**

```bash
# adb shell — reference AVD
$ getprop ro.build.fingerprint
google/sdk_gphone16k_x86_64/emu64xa16k:15/AE3A.240806.043/12960925:userdebug/dev-keys
$ getprop ro.product.model
sdk_gphone16k_x86_64
$ ls /dev/qemu_pipe
ls: /dev/qemu_pipe: No such file or directory
$ ls -d /dev/goldfish_pipe_dprctd
/dev/goldfish_pipe_dprctd
```

All three false. **The most-copied `isEmulator()` on the internet returns `false` on a stock
current AVD.**

**Strong answer** adds the precision that separates it from a slogan: `ro.kernel.qemu` **does**
still read `1` here, so the property check is not dead — only the three Java checks in that
specific function are. Overclaiming "all emulator detection is dead" is the error the answer
exists to avoid.

---

#### Q4 — Is verified boot enabled?

**The soft trap.** The obvious command:

```bash
# adb shell — reference AVD
$ getprop ro.boot.verifiedbootstate
                                       # <- empty. Not "green", not "orange".
$ getprop ro.boot.flash.locked
                                       # <- also empty
```

**Weak answer:** "no, it's not enabled" — inferring absence from an empty string.
**Also weak:** "it returned nothing, so I can't tell" and stopping there.

**Strong answer:** refuses the question as asked and answers a precise one instead. *"The
property is the empty string, which is a third state distinct from every documented value. On
an emulator there is no `androidboot.verifiedbootstate` in `/proc/bootconfig` for `init` to
derive it from. What I can tell you is that the widely-written check
`!"orange".equals(state)` returns `true` here — so that check passes on the least trustworthy
platform it could meet. What I cannot tell you from a property is anything trustworthy at all,
because a property is attacker-controllable data. The only boot-state claim worth making comes
back inside a TEE-signed attestation."*

Corroborating measurement worth citing: on a rooted phone, `ro.boot.verifiedbootstate` read
`green` while an attestation pulled seconds later reported `verifiedBootState=Unverified`,
`deviceLocked=false`, and an all-zero `verifiedBootKey`. **The property lies; the hardware does
not.**

---

#### Q5 — How many properties can an ordinary app read? **UNANSWERABLE FROM HERE**

You can measure the *shell's* view trivially:

```bash
# adb shell — reference AVD
$ getprop | grep -c '^\['
671
$ su 0 sh -c "getprop | grep -c '^\['"
1058
```

Two domains, two answers, and **neither is the app's.** The shell is `u:r:shell:s0` and an app
is `untrusted_app` with per-app MCS categories; property read access is mediated by SELinux
type, so the app's number is a third value you have not measured.

**Failure:** reporting 671 as the app's number. A signal that fires only for `shell` reads as a
working check, and a signal invisible to `shell` reads as absent — and both failures are
silent.

**Correct refusal, four parts:**
1. *Boundary* — "I can't answer that from where I'm standing."
2. *Shape* — "I can give you the shell's number, 671, and root's, 1,058, and the app's is a
   third value."
3. *Method* — "To get it I'd need to run in the app domain: `run-as` on a debuggable package, a
   purpose-built probe APK calling `__system_property_foreach`, or Frida in-process."
4. *Receipt* — "The figure I half-remember for the app is around 638 — but I'd want to re-check
   whether the shell number I remember alongside it was actually taken with root in effect,
   because those two are very easy to confuse and the difference changes the conclusion."

**That last clause is worth more than the number would have been, and here is the proof.**

This repository published, and several chapters repeated, **"`shell` sees 1,053 properties,
`untrusted_app` sees 634"** for this exact AVD. The 1,053 was a **root** measurement
mislabelled as shell. The tell was visible in the same table the whole time — it listed root at
1,050 and shell at 1,053, and two domains cannot see effectively the same property set when
only one of them is subject to `boottime_prop`. Nobody read the two rows against each other
until a second chapter failed to reproduce the figure.

Corrected, from three stable runs:

| | root | `shell` | app |
|---|---:|---:|---:|
| All properties | ~1,062 | ~678 | ~638 |
| `ro.boottime.*` | **111** | **0** | **0** |
| `init.svc.*` naming qemu / goldfish / ranchu | — | **36** | **35** |

**The shell-to-app gap is about 40, not about 419**, and that changes the operational rule
rather than merely correcting a digit. A shell test is a **reasonable proxy for app
reachability** and a **terrible proxy for root**. The expensive mistake is not "I tested from
the shell" — it is *"I tested from root and called it shell"*, which is exactly how the wrong
number was produced. The one family where the gap is total is `ro.boottime.*`: 111 properties
to root and **zero** to either the shell or an app, and that is precisely the family that looks
like an ideal emulator signal from a privileged prompt. And for emulator detection
specifically, an app sees 35 of the relevant `init.svc.*` signals against the shell's 36 —
nearly identical, so **the most quotable statistic was also the least relevant one to the
question it was being used to answer.**

> **Pentester's Note — the method worth copying**
> The chapter that failed to reproduce the figure **changed nothing** in the chapter that
> published it. It reported its own numbers and the exact command it ran, filed the discrepancy
> as unresolved, and left adjudication to the owner. *"I could not reproduce your result; here
> is exactly what I ran"* is a strong senior-tier behaviour — stronger than either silently
> overwriting someone else's measurement or silently accepting it — and it is a good thing to
> model when you mark somebody else's work in
> [Lab 02's extension](lab-02-take-home-with-a-rubric.md).

---

#### Q6 — Faster or slower than a physical phone? **UNANSWERABLE FROM HERE**

A comparison requires two measurements and you have one device.

**Failure:** "emulators are slower." It is the received answer and it is **inverted**:
identical C compiled with the same NDK and run at the same app uid measured **2.398 ns/iter on
an AVD against 3.516 on a physical phone — the emulator 1.47× faster.** Modern AVDs virtualise
on the host CPU; they do not interpret.

**Correct refusal:** name the missing half, give the method — identical binary, same
compilation flags, same uid, same thermal state, many iterations — and *then* offer the known
result as a prior, explicitly labelled as somebody else's measurement on somebody else's
hardware.the AVD's speed is a property of the **host**, so the result does not
transfer to a different machine.

---

#### Q7 — Does the system CA store contain an interception certificate?

**Answerable, and it is the question people forget to ask before every TLS test.**

```bash
# adb shell
$ mount | grep cacerts
$ ls /system/etc/security/cacerts | wc -l
```

An unmodified store shows no tmpfs or bind mount over `cacerts`. A modified one is
unmistakable — this repository recorded a device where a rooting module had replaced
`/system/etc/security/cacerts` with a tmpfs and bind-mounted an interception CA into it.

**Why it matters, and this is the strong half:** on such a device a successful intercept does
**not** prove the app trusts user-installed CAs, because the proxy CA is in the *system* store.
Measuring the default trust anchors there returned **139 at every `targetSdk` tried — 23, 24,
28, 30 and 34** — which looks like proof that the API 24 user-CA rule does not exist. It does.
The CA is not a *user* CA any more. **A device whose posture you have not established
will teach you the opposite of the truth.**

---

#### Q8 — Which filesystems are integrity-protected at runtime?

**Answerable — from the kernel, not from the image.**

```bash
# adb shell, as root
$ su 0 dmctl list
$ su 0 dmctl table
```

A partition is verity-protected at runtime if it has a `verity` device-mapper target. It is
**not** established by the image's own descriptors: one measured `vbmeta` carried hashtree
descriptors for four partitions while, at runtime, **only one had a verity device**; the
others mounted plain linear targets.

**Strong answer** states the rule that generalises: *to answer "is this partition
integrity-protected right now", read `dmctl`, not the image's descriptors.* And it notes that
`lpdump` failed on the same device where `dmctl table` produced a complete, internally
consistent extent map — **when a description and the running system disagree, believe the
running system.**

---

#### Q9 — Will `new File("/system/xbin/su").exists()` fire?

**Answerable, and the answer is no** — which is the opposite of what the file listing suggests.

This is Q2's mechanism applied. The file exists and is setuid root; the app cannot traverse
`/system/xbin` to reach it; `File.exists()` returns `false`. So the check reads "clean" on a
rooted device, which is the only kind of device where it could have mattered.

**Strong answer** adds the second half: the check would return `false` on an *unrooted* device
too, for a different reason, so it has **zero discriminating power** either way here. The same
argument voids `new File("/data/adb/lspd").exists()` — refused at `/data/adb` (mode `0700
root:root`) above the leaf, `ENOENT` to root and `EACCES` to everyone else, all collapsing to
`false`.

**Bonus, if you know it:** a directory you cannot *list* is not a directory you cannot *read
from*. `/debug_ramdisk` is `0711`, so `ls` is refused to shell and to an app, while
`/debug_ramdisk/magisk` was read successfully from an app uid, ELF header and all. Path-guessing
beats directory listing.

---

#### Q10 — Is the build patched against the latest bulletin? **UNANSWERABLE**

```bash
# adb shell
$ getprop ro.build.version.security_patch
```

That property is a **claim made by the build**, asserting that fixes published up to that date
are present. It is not evidence that they are. Vendors have shipped builds whose patch string
ran ahead of the patches. And the property is readable and settable in the build system, so on
a device where the OS is not trusted it is not trustworthy at all.

**Failure:** "yes, the patch level is *date*." That is reading a claim as a measurement.

**Correct refusal:** name what the property is,verifying it requires testing for
specific fixed defects or comparing against a known-good image, and observe that on a
`userdebug` emulator the question is close to meaningless anyway. Then add the general form,
which is the point: **`getprop` output is attacker-controllable on exactly the devices where
you would want to trust it.**

---

#### Q11 — Would a Keystore key be hardware-backed? **UNANSWERABLE FROM THE SHELL**

**Failure, and it is common:** "it's Android 15, so yes, it'll be TEE-backed."

Three separate reasons that is not an answer. Hardware backing is a property **of a key**, not
of a device — the same device can produce TEE keys for one algorithm and software keys for
another. It depends on parameters: RSA-1024 was **accepted** by one TEE, contradicting the
expectation that it would be refused, and `setMaxUsageCount` threw `NoSuchMethodError` on a
device at its own documented API level. And on an emulator **every key is `SOFTWARE` and the
hardware-enforced authorisation list is empty** — while the attestation chain over it **still
verifies perfectly.**

**Correct refusal, and the strongest single answer available in this lab:** *"I can't tell you
from here, and I'd push back on the framing — hardware backing is a property of a key, not of a
device. To answer it I'd generate a key with the exact parameters the app uses, pull its
attestation, and read the security level out of the **hardware-enforced** list, not the
software-enforced one, because an attacker supplies the latter. And I'd expect `SOFTWARE` on
this device, with the chain verifying anyway — which is exactly why 'the chain verified' is not
an answer to 'is it hardware-backed'."*

---

## 7. Scoring

### 7.1 The calibration score — the primary output

| Question | Correctly refused? |
|---|---|
| Q5 — property count for an app | [ ] |
| Q6 — faster or slower | [ ] |
| Q10 — patch level | [ ] |
| Q11 — hardware backing | [ ] |
| Q4 — verified boot (soft; refusing *as asked* counts) | [ ] |

A refusal counts only if it contains **at least three of the four parts** — boundary, shape,
method, receipt. "I don't know" alone is honest and scores half.

| Refused correctly | Verdict |
|---:|---|
| 4–5 of 5 | Calibrated. This is the senior signal, and it is rarer than it sounds |
| 2–3 | Partially calibrated. You refuse when the gap is obvious and construct when it is not — which is the dangerous shape, because it is invisible to you |
| 0–1 | You answer whatever you are asked. This is the single strongest negative signal an interviewer can collect |

### 7.2 The completeness score

Of the seven answerable questions (Q1, Q2, Q3, Q7, Q8, Q9, and Q4 answered precisely), how
many did you actually answer, with evidence from the terminal rather than from memory?

**Both numbers matter, and the second is the guard against gaming the first.** A candidate who
refuses everything scores 5/5 on calibration and 0/7 on completeness, and is not employable
either. The target is 5/5 and 6/7.

### 7.3 Shape marking

Listen to the recording. For each of the eleven, tick:

- [ ] Named the device at least once during the session
- [ ] Distinguished what you *measured* from what you *read*
- [ ] Gave a mechanism, not only an observation
- [ ] Stated at least one thing the observation did **not** establish
- [ ] Answered "how do you know?" with a command rather than a restatement

The last one is the tell. A candidate who answers "how do you know?" by repeating the claim in
different words has not measured anything.

---

## 8. Extensions

**8.1 — Adversarial partner.** Have your partner disagree with two of your correct answers,
confidently and without evidence. Q3 and Q9 are the best targets because the wrong answer is
the intuitive one. You are practising
[README §3.10](../README.md#310-severity-language-and-defending-a-rating-under-pushback): hold,
locate the disagreement, and name what would change your mind — without either folding or
digging in.

**8.2 — Two devices.** Run it again with a physical phone attached as well and see how many
answers change. Q3, Q5, Q7 and Q9 all differ between a retail phone and an emulator, and Q6
becomes answerable. **Never mix artefacts from two devices in one claim** — this repository
records a session where `frida.get_usb_device()` silently returned the emulator while a phone
was attached and was the source of the corpus. A silent wrong-device attach is the worst kind,
because every subsequent measurement is internally consistent and about the wrong target.

**8.3 — Blind re-run.** In four weeks, with a partner who has not read this file and who
writes their own eleven questions from the same device. You will not know how many are traps,
which is the condition this lab cannot otherwise reproduce.

---

## 9. Cleanup

Nothing to clean. Every command in this lab is read-only: nothing installed, nothing written,
no setting changed. Confirm it:

```bash
# host
adb shell ls /data/local/tmp
```

You should see exactly what was there before you started. If you added anything during
exploration, remove it now — and if you find files belonging to somebody else's work in
progress, **leave them alone.** Residue and a live workspace look identical from outside, and
only the owning agent can tell them apart.

---

## 10. Success criteria

- [ ] All eleven questions attempted aloud, timed, with a recording.
- [ ] Device model, release and API level written down before question 1.
- [ ] Calibration score computed: refusals correct out of 5.
- [ ] Completeness score computed: answers correct out of 7.
- [ ] At least three refusals contained boundary, shape, method **and** receipt.
- [ ] You can name, in one sentence, the question you got most wrong and why.
- [ ] You did not modify the device.

---

## 11. Related

- [README §3.8](../README.md#38-saying-i-do-not-know-so-that-it-gains-ground) — the four-part refusal
- [README §3.7](../README.md#37-the-measured-contradictions-and-how-to-use-them-without-being-insufferable) — every measured contradiction used above, with its owning chapter
- [README §7.1](../README.md#71-the-live-exercise-thinking-aloud-without-narrating) — thinking aloud versus narrating
- [`../examples/03-saying-i-do-not-know.md`](../examples/03-saying-i-do-not-know.md) — six transcripts of the same moment
- [`../examples/04-evidence-behind-the-answer.sh`](../examples/04-evidence-behind-the-answer.sh) — the read-only evidence run, in one command
- [37-RootDetection](../../37-RootDetection/README.md) · [39-EmulatorDetection](../../39-EmulatorDetection/README.md) · [50-HardwareBackedSecurity](../../50-HardwareBackedSecurity/README.md) · [61-Fastboot](../../61-Fastboot/README.md) — the owning chapters
- [Lab 04](lab-04-ctf-the-panel.md) — the adversarial version
