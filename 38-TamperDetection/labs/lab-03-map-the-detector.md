# Lab 03 — Map before you bypass

**Difficulty:** Advanced
**Time:** 2–3 hours
**Chapter:** [38 — Tamper Detection](../README.md) · §2.5, §7.1, §8

---

## Objective

Apply the whole chapter to applications you did not write. Build a corpus, map its tamper surface
with [`../scripts/tamper-surface-map.py`](../scripts/tamper-surface-map.py), **adjudicate the output
by hand**, and quantify the tool's false-positive rate.

Then — before touching a device — predict what each app will do at runtime, and check your
prediction.

The skill this lab teaches is not "run the mapper". It is the discipline that chapters 33, 36 and 52
each arrived at independently by measurement: **a sweep produces leads, not findings**, and a tool
that flags everything flags nothing. You will prove that on this chapter's own tool.

---

## Why this lab exists

The first version of `tamper-surface-map.py` reported a self-signature check in **18 of 18** apps.
That is not a finding, that is a broken tool — `getPackageInfo` is how every analytics SDK reads its
own `versionName`.

The fix was to grade every pattern STRONG or WEAK and to anchor several regexes. You are going to
repeat that adjudication yourself, on your own corpus, and find out what the residual error rate is.
Because it is not zero, and knowing your tool's error rate is the difference between a report people
trust and a report people argue with.

---

## Prerequisites

**Knowledge.** Chapter 38 §8 in full; labs 01 and 02.
[52-StaticAnalysis](../../52-StaticAnalysis/README.md) for sweep discipline;
[56-JADX](../../56-JADX/README.md) for reading the results.

**Tools.** `python3`, `adb`, `jadx`, `apktool`, `apksigner`, `llvm-readelf`.

> **⚠️ Authorisation — read this before you build a corpus**
> Static analysis of an APK you legitimately possess is normally fine, and it is all this lab does:
> the mapper **never modifies an APK and never touches a device**. But:
>
> - **Detection only on third-party apps.** Do not patch, repackage or instrument anything you did
>   not write. The only app you may attack is the one you built in lab 01.
> - **Check your engagement scope** if this is client work.
> - **If you publish your results, do not name commercial apps.** Chapter 38's own corpus results are
>   published in aggregate for exactly this reason; only Google's own packages and deliberately
>   vulnerable training apps are named.

---

## Part A — Build a corpus

Twelve to twenty APKs, spread across sectors. Diversity matters more than count: eighteen banking
apps teach you less than six apps from six sectors.

### A1 — From your own device

```bash
# host — what is installed
adb shell pm list packages -3 | sed 's/package://' | sort

# host — where does one live
adb shell pm path com.example.app

# host — pull it
adb pull /data/app/~~XXXX==/com.example.app-YYYY==/base.apk ./corpus/com.example.app.apk
```

> **⚠️ Split APKs — the trap that inverts conclusions**
> `pm path` often prints **several** lines: `base.apk`, plus `split_config.arm64_v8a.apk`,
> `split_config.en.apk`, and feature splits. **The native libraries frequently live in the splits,
> not in the base.**
>
> Measured while writing this chapter: one large, well-known app showed **zero** STRONG controls in
> its `base.apk`, because its native code and much of its logic ship in splits. A conclusion drawn
> from `base.apk` alone would have been exactly backwards.
>
> Pull every line `pm path` prints, and analyse them all.

### A2 — Deliberately vulnerable targets

Add at least two training apps built to be attacked. They are useful here precisely because you can
compare "what the mapper says" against "what the app is documented to do".

### A3 — Your own build

Include `clean.apk` from lab 01. You know exactly what is in it, so it is your control sample: if
the mapper misses something you *know* is there, that is a tool bug worth understanding.

**Checkpoint A.** You have `./corpus/` with 12+ APKs, including splits where they exist.

---

## Part B — Run the mapper

```bash
# host — human-readable, one app
python3 -B ../scripts/tamper-surface-map.py corpus/com.example.app.apk

# host — the whole corpus, machine-readable
python3 -B ../scripts/tamper-surface-map.py --json corpus/ > surface.json
```

A 200 MB APK takes a while; the reference corpus of 18 APKs (651 MB total) took **1 minute 43
seconds**.

### B1 — Build the summary table

```bash
# host
python3 -B - <<'PY'
import json, collections
d = json.load(open('surface.json'))
order = ["T3-NATIVE-EARLY", "T2-NATIVE-JNI", "T1-JAVA"]
cnt = collections.Counter()
print(f"{'apk':<44}{'MB':>6}{'libs':>5}  early  STRONG controls")
for r in sorted(d, key=lambda x: x['apk']):
    strong = sorted({c for t, rows in r['tiers'].items()
                       for c, v in rows.items() if v.get('conf') == 'STRONG'})
    for c in strong:
        cnt[c] += 1
    early = next((t for t in order if t in r['tiers']), '-')
    print(f"{r['apk']:<44}{r['size']/1048576:6.1f}{len(r['libs']):>5}  "
          f"{early.split('-')[0]:<6} {','.join(c for c in strong if c != 'SIGBLOCK')}")
print()
for k, v in cnt.most_common():
    print(f"   {k:<18}{v:>3}")
PY
```

### B2 — Compare against the chapter's reference numbers

Reference corpus, 18 APKs (chapter 38 §8.3):

| STRONG control | Count |
|---|---|
| v2+ signing block | 18 |
| APK/DEX self-hashing surface | 14 |
| Root-detection strings (ch 37) | 13 |
| **Self-signature verification** | **13** |
| Installer check | 10 |
| Emulator strings (ch 39) | 9 |
| `isDebuggerConnected` | 8 |
| `JNI_OnLoad` present | 7 |
| `TracerPid` | 5 |
| Peer signature | 5 |
| **Remote attestation** | **5** |
| maps scan (Java) | 3 |
| maps scan (native) | 2 |
| Frida artefacts | 2 |
| Key attestation | 2 |
| **`ptrace` imported** | **1** |

**Question B1.** Compare your distribution against this one. Where does yours differ, and is the
difference explained by your corpus composition or by something about your tooling?

**Question B2.** Only **one** app in eighteen imports `ptrace`. Before you read the answer, write
down what you expected that number to be. Then explain what the real number implies about the common
mental image of app hardening.

<details>
<summary>Answer B2</summary>

Most people guess something between a third and a half, because published material about anti-debug
gives the impression that serious apps are bristling with it.

One in eighteen. And in the reference corpus it was not a bank — it was a grocery delivery app.

The implication is that **native anti-debug is rare**, and that an app which has it is unusual enough
to be worth a note. The corollary matters more for your time budget: if you go into every engagement
expecting a hardened native tier, you will over-prepare for a case that occurs once in eighteen, and
under-prepare for the actually common case, which is a handful of Java-tier checks and a server that
enforces nothing.
</details>

---

## Part C — Adjudicate by hand

This is the part that matters, and it is the part people skip.

Take the **STRONG** rows for four apps and verify each one by hand. For each row, decide:

- **TRUE POSITIVE** — the app really implements this control.
- **FALSE POSITIVE** — the string is there for another reason.
- **UNDECIDABLE** — you cannot tell from static analysis alone. This is a legitimate verdict; record
  it as such.

Method for each:

```bash
# host
jadx -d j corpus/app.apk 2>/dev/null
grep -rn "134217728\|getApkContentsSigners" j/sources/ | head -20
```

Then open the hit and read the surrounding code. Ask three questions:

1. Is the result **compared against anything**?
2. Does anything **branch** on that comparison?
3. Does the branch **do** anything?

An app can call `getApkContentsSigners`, log the result, and never act on it. That is a true positive
for "reads its own signature" and a false positive for "implements anti-tampering".

### C1 — Record your results

| App | Control | Verdict | Evidence |
|---|---|---|---|
| | SIG-SELF | | |
| | DBG-JDWP | | |
| | ANA-MAPS | | |
| | ATT-REMOTE | | |

**Question C1.** What false-positive rate did you get on STRONG rows? If it is above about 20%, which
patterns are responsible, and how would you tighten them?

**Question C2.** The mapper prints WEAK rows under a banner saying not to put them in a report. You
have now seen the STRONG rows misfire too. Does that mean the STRONG/WEAK split is worthless?

<details>
<summary>Answer C2</summary>

No — it means the split is a **triage aid**, not a verdict, and it should be read as one.

STRONG means "there is essentially one reason for this string to exist". That is a claim about the
*string*, not about the app's behaviour. `GET_SIGNING_CERTIFICATES` really is only called by code
that reads its own signature — but that code might be an SDK doing telemetry, or a Play Billing
library, or dead code R8 did not shake out.

The split does its job if it changes what you read first. Going from "18 of 18 apps have a signature
check" to "13 apps have a real signature-reading call site, here are the line numbers" is the whole
value. The remaining adjudication is human work and always will be.

The alternative — trying to make the tool decide — produces a tool that is confidently wrong, which
is strictly worse than a tool that is usefully approximate. This is the same conclusion chapter 52
reached when 15 of 17 of its HIGH-confidence hits were rejected by hand.
</details>

---

## Part D — Predict, then verify

Before running anything on a device, **write down a prediction** for three apps.

| App | Earliest tier | Will it run under Frida? | If not, which check fires first? | Will a repackaged build run? |
|---|---|---|---|---|
| | | | | |

Base the prediction on the map, not on a hunch. The reasoning matters more than the answer:

- No `ANA-*` or `NAT-FRIDA` rows → probably runs fine under Frida.
- `NAT-INITARRAY` **and** `NAT-FRIDA` in the same library → a check may run before you can attach.
- `SIG-SELF` STRONG → a repackaged build probably will not work.
- `ATT-REMOTE` → the interesting behaviour is on the network, not in the process.

Now verify — **on your own lab-01 app only** if you do not have permission to instrument the others.
For third-party apps, verify only what you can observe passively:

```bash
# host — does it start normally
adb logcat -c
adb shell monkey -p com.example.app -c android.intent.category.LAUNCHER 1
sleep 5
adb logcat -d | grep -iE "integrity|tamper|signature|FATAL|died" | head
```

**Question D1.** For each of the three apps, was your prediction right? Where it was wrong, was the
error in the map or in your reasoning from the map?

**Question D2.** One app in your corpus almost certainly has `ATT-REMOTE` (Play Integrity). From
static analysis alone, can you tell whether its integration is correct — server-issued nonce, opaque
token, server enforcement?

<details>
<summary>Answer D2</summary>

**No, and this is the single most important limitation of static mapping.**

The static surface tells you the app *requests* an integrity token. It cannot tell you:

- Whether the nonce came from the server or was generated locally.
- Whether the token is parsed on the client.
- Whether the server verifies the signature.
- Whether the server consumes the nonce.
- Whether the server enforces anything at all.

Every one of those is where the real findings live (§5.4, §5.5), and every one of them requires
watching the **network**, not the code.

That is why §5.12's methodology ends with "now test the server" and why the mapper's header says it
produces leads. A perfect static map of an app's client-side controls tells you almost nothing about
whether the app is actually protected.
</details>

---

## Part E — Stress the tool

Find out where it breaks. This is how you learn to read its silence correctly.

### E1 — An app with no checks

Take a simple open-source app. Run the mapper.

**Question E1.** It reports nothing (or only WEAK rows). Is that a true negative or a failure?

<details>
<summary>Answer E1</summary>

Almost certainly a true negative, and you should be comfortable saying so.

Most apps have no tamper detection, because most apps have no threat model that calls for it. Section
5.3's whole argument is that this is a reasonable engineering decision.

The mistake to avoid is treating an empty report as suspicious. The five signals in §8.6 tell you
when to doubt it: a tiny DEX beside a large `.so`, a high-entropy string table, an `.so` with a big
`.text` and no strings, or an app that dies under Frida while the map is empty. Absent those, believe
the tool.
</details>

### E2 — A packed app

If your corpus has a packed app — tiny `classes.dex`, large native libraries, an unfamiliar packer
package name — run the mapper on it.

**Question E2.** What does the mapper report, and what should you conclude?

<details>
<summary>Answer E2</summary>

Usually very little from the DEX, because the shipped DEX is a loader stub — the real code is
decrypted at runtime.

What you *can* see: the native libraries (which are not packed), their imports and exports, and
whether they have `.init_array` entries. That is often enough to identify the packer.

The correct conclusion is "the static map is not applicable to this app; I need the runtime DEX".
[13-ART](../../13-ART/README.md) ships `dump-loaded-dex.js` for exactly that, and
[40-Obfuscation](../../40-Obfuscation/README.md) covers unpacking. Then re-run the mapper on the
dumped DEX.
</details>

### E3 — Feed it something malformed

```bash
# host — a truncated APK
head -c 100000 corpus/app.apk > /tmp/broken.apk
python3 -B ../scripts/tamper-surface-map.py /tmp/broken.apk
```

**Question E3.** The mapper's DEX parser caps `string_ids_size` against the file size rather than
trusting the header. Why is that not just defensive coding but a *security* consideration?

<details>
<summary>Answer E3</summary>

Because inflating `string_ids_size` is a known anti-analysis trick. A hostile DEX can declare a
string table far larger than the file, and a parser that trusts the field either crashes, hangs, or
allocates absurdly.

Your analysis tools process **attacker-controlled input by definition**. A parser that assumes
well-formed input is a parser that the target can crash — which is itself a very effective
anti-analysis technique, and one that costs the app author nothing.

The same reasoning applies to the ELF reader: a deliberately corrupted section header table is itself
a signal, so the mapper catches the parse failure, reports `ELF headers unparsable (packed?)`, and
carries on with the other libraries rather than dying.
</details>

---

## Part F — Extend it

Pick one and implement it. Each is 20–60 lines.

### F1 — Detect the split-APK problem automatically

Make the mapper accept a **directory of splits belonging to one app**, merge their surfaces, and warn
loudly when `base.apk` has no native libraries but a sibling split does. This addresses the failure
that inverted a conclusion in the reference corpus.

### F2 — Diff two versions of the same app

```bash
# host
python3 -B ../scripts/tamper-surface-map.py --json app-v1.apk > v1.json
python3 -B ../scripts/tamper-surface-map.py --json app-v2.apk > v2.json
```

Write a differ that reports controls added, removed, or moved between tiers.

**Why this is the highest-value extension:** an app that moves a check from T1 to T2 between releases
is an app whose vendor is actively hardening — which tells you they have an adversary, which tells
you where to look. A control that *disappears* is even more interesting.

### F3 — Confidence scoring instead of two buckets

Replace STRONG/WEAK with a 0.0–1.0 score combining pattern specificity, hit count, and
**co-occurrence**: `TracerPid` alone is weak; `TracerPid` **and** `/proc/self/maps` **and** an
`isDebuggerConnected` in the same DEX is much stronger than the sum of three weak signals.

> **⚠️ Before you build this, read [52-StaticAnalysis](../../52-StaticAnalysis/README.md).** It
> measured 15 of 17 HIGH-confidence hits rejected by hand, and its conclusion is blunt: **confidence
> ranking is not severity ranking.** A score that looks precise invites people to stop adjudicating,
> which is worse than two honest buckets.

### F4 — Manifest tier

The mapper deliberately does not parse binary AXML. Wire in
[`10-APK-Internals`](../../10-APK-Internals/README.md)'s `parse_axml.py` to add a T0 row for
`android:debuggable` and `android:extractNativeLibs`.

---

## Part G — Write it up

Produce a one-page report on **one** app from your corpus, following §5.3's wording.

It must contain:

1. **What the app implements** — STRONG rows only, adjudicated, with file and line evidence.
2. **What the earliest tier is**, and what that means for anyone assessing it.
3. **What you could not determine statically** — explicitly. The attestation question from D2 belongs
   here.
4. **A severity**, worded per §5.3, with the threat model named.
5. **What you would test next**, and it should be the server.

**Question G1.** Your report says the app implements a self-signature check, a debugger check and
Play Integrity. A junior colleague drafts: *"The application implements robust anti-tampering
controls."* What is wrong with that sentence?

<details>
<summary>Answer G1</summary>

Three things, and each is a habit worth breaking:

1. **"Robust" is unmeasured.** You established that strings exist. You did not measure what it costs
   to defeat them. Without a cost, "robust" is decoration.
2. **It conflates presence with efficacy.** An app can implement all three and evaluate the Play
   Integrity verdict on the client, which makes the whole apparatus equivalent to one boolean.
3. **It answers the wrong question.** The question the client cares about is whether the *server*
   enforces anything, and you explicitly could not determine that statically. Saying the client is
   robust invites exactly the wrong conclusion.

Better: *"The application reads its own signing certificate (`SigningInfo` at ClassA:120), checks for
a connected debugger, and requests a Play Integrity token. Whether the integrity verdict is enforced
server-side could not be determined statically and is the recommended next test; the client-side
controls are consistent with a hardening posture but were not assessed for bypass cost."*
</details>

---

## Success criteria

- [ ] A corpus of 12+ APKs including splits, with the split trap understood.
- [ ] A summary table by app and by control, compared against the chapter's reference numbers.
- [ ] STRONG rows for four apps adjudicated by hand, with a measured false-positive rate.
- [ ] A written prediction for three apps, and a comparison against observed behaviour.
- [ ] An explanation of why static analysis cannot assess an attestation integration.
- [ ] One extension implemented (F1–F4).
- [ ] A one-page report whose severity is worded per §5.3 and whose "next test" is the server.

---

## Clean up

```bash
# host
rm -rf corpus surface.json v1.json v2.json j /tmp/broken.apk
cd 38-TamperDetection && find . -name "__pycache__" -o -name "*.pyc" -o -name "*.apk"
```

Nothing should print. If a `__pycache__` appeared, you ran Python without `-B` — see chapter 38's
note on `importlib.util.module_from_spec`.

---

## What to take away

1. **A sweep produces leads, not findings.** You measured your own false-positive rate. Quote it.
2. **Analyse the splits.** One app in the reference corpus would have been assessed exactly backwards
   from its `base.apk`.
3. **The earliest tier is the number that changes your plan.** Everything else is detail.
4. **Static analysis cannot assess an attestation integration.** The findings are on the network.
5. **`ptrace` appeared in 1 of 18 apps.** Calibrate your expectations to measurements, not to blog
   posts — including this chapter's, which is why it publishes its numbers and its device.

---

## Next

[Lab 04 — CTF: the app that works fine and then does not](lab-04-ctf-silent-integrity.md) — where the
app gives you nothing at all to work with.
