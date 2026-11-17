# Lab 02 — Resolution forensics: predict, then measure

**Difficulty:** Beginner → Intermediate
**Time:** 1.5–3 hours
**Prerequisites:** [Chapter 26 §3.4, §3.5, §3.6, §4.2, §4.5](../README.md)
**Needs:** any Android device or emulator with a handful of ordinary apps
installed. **No app-building required** — this lab is done entirely against the
apps already on the device, which is deliberate: the resolver is a property of the
platform, not of any one app.

---

## Objective

Get to the point where, given an arbitrary `Intent`, you can state **before running
anything**:

1. Which components will match it.
2. Which one will win.
3. What `match` value the winner will report, and therefore *which test it won on*.
4. Which components would have matched if you changed one field.

And then prove each prediction with one command.

This sounds like a drill because it is one. Resolution is the mechanism underneath
deep links, scheme hijacking, chooser interception and half of the redirection
findings you will ever write. People who guess at it produce reports that get
rejected; people who can derive it produce reports that get paid.

> **Why "predict, then measure" and not just "measure"**
> Measuring teaches you what this device does. Predicting first teaches you the
> *algorithm*, and the algorithm is what transfers to the next device, the next
> Android version, and the app whose filters you can only read in a manifest
> because you do not have the device at all. **Write your prediction down before
> each command. A prediction you did not write down was not a prediction.**

---

## The rules you are testing

Keep these visible. Everything in this lab is a consequence of them.

| Test | Rule |
|---|---|
| **Action** | If the Intent's action is non-null, the filter must list it. A **null** action matches every filter. A filter with **no** `<action>` matches only an action-less Intent. |
| **Category** | **Every** category on the Intent must appear on the filter. Categories on the filter that the Intent does not name are ignored. |
| **`CATEGORY_DEFAULT`** | `startActivity`/`startActivityForResult` **add** it to implicit Intents. An Activity filter without it is unreachable implicitly. Broadcasts and services are unaffected. |
| **Data** | The URI's scheme/host/port/path and the MIME type are matched against the filter's **independent sets**. Multiple `<data>` elements produce a **cross product**, not tuples. |
| **MIME wildcards** | `type/*` and `*/*` work from **both** sides. |
| **Match value** | On success `match()` returns `MATCH_CATEGORY_* \| MATCH_ADJUSTMENT_NORMAL`, describing how *specifically* the data matched. On failure it returns −1…−4, naming the test that failed. |

Match value decoding, which you will use constantly:

| Value | Category part | Means |
|---|---|---|
| `0x108000` | `0x00100000` | `EMPTY` — matched with no data at all |
| `0x208000` | `0x00200000` | `SCHEME` |
| `0x308000` | `0x00300000` | `HOST` |
| `0x408000` | `0x00400000` | `PORT` |
| `0x508000` | `0x00500000` | `PATH` |
| `0x588000` | `0x00580000` | `SCHEME_SPECIFIC_PART` |
| `0x608000` | `0x00600000` | `TYPE` |

---

## Setup

```bash
# host
adb devices
adb shell getprop ro.build.version.sdk
adb shell getprop ro.build.version.release
```

Record the API level. Two things in this lab depend on it: package-visibility
filtering (API 30+) and the App Links command set (lab 03's subject).

> **Quote for TWO shells, every single time**
> `adb shell "…"` hands the whole string to the **device's** `sh`, which re-parses
> it. `*`, `;`, `?`, `&`, `|` and `$` are metacharacters *there*. Wrap the entire
> device command in one set of quotes on the host, and use a second, inner set for
> any argument. You will reproduce both failure modes deliberately in step 6, so
> you recognise them when they happen for real.

---

## Step 1 — The match value, four ways

Predict the `match` value for each of these before running it.

```bash
# host — (a) no data at all
adb shell "cmd package query-activities -a android.intent.action.MAIN \
    -c android.intent.category.LAUNCHER" | head -3

# host — (b) scheme only
adb shell "cmd package query-activities -a android.intent.action.VIEW -d 'tel:12345'" | head -3

# host — (c) a real https path
adb shell "cmd package query-activities -a android.intent.action.VIEW \
    -c android.intent.category.BROWSABLE -d 'https://www.youtube.com/watch?v=abc'" | head -3

# host — (d) a MIME type
adb shell "cmd package query-activities -a android.intent.action.SEND -t 'text/plain'" | head -3
```

**Q1.** Fill this in, prediction first:

| | Intent | Predicted `match` | Measured `match` | Decodes to |
|---|---|---|---|---|
| a | `MAIN` + `LAUNCHER` | | | |
| b | `VIEW tel:12345` | | | |
| c | `VIEW https://www.youtube.com/watch` | | | |
| d | `SEND text/plain` | | | |

For reference, these are the values measured on a Redmi running Android 11 / API 30
while this chapter was written — your device will differ in *which components* it
reports, and should agree on the *values*:

```text
a  match=0x108000     MATCH_CATEGORY_EMPTY
b  match=0x208000     MATCH_CATEGORY_SCHEME
c  match=0x508000     MATCH_CATEGORY_PATH
d  match=0x608000     MATCH_CATEGORY_TYPE
```

**Q2.** In case (c) the winner was `com.google.android.youtube/.UrlActivity` with
`match=0x508000`. It matched on **path**. Look at YouTube's filters and say which
path expression matched:

```bash
# host
python3 ../scripts/intent-surface-map.py --package com.google.android.youtube --components \
    | sed -n '/UrlActivity/,/^$/p'
```

(Substitute a browser or any app with `https` filters if YouTube is not installed.)

**Q3.** Case (b) on the reference device reported two candidates, one of them with
`priority=-1`:

```text
priority=0  ... com.android.dialer.main.impl.MainActivity
priority=-1 ... com.google.android.apps.contacts.activities.NonPhoneActivity
```

What is a **negative** priority for, and what does it tell you about how the
Contacts app expects to be used? Does your device show the same thing?

---

## Step 2 — The category rule, in the direction people get wrong

```bash
# host — how many handlers for a plain VIEW on an https URL?
adb shell "cmd package query-activities -a android.intent.action.VIEW -d 'https://example.com/'" | head -1

# host — the same, plus BROWSABLE
adb shell "cmd package query-activities -a android.intent.action.VIEW \
    -c android.intent.category.BROWSABLE -d 'https://example.com/'" | head -1

# host — plus a category nobody declares
adb shell "cmd package query-activities -a android.intent.action.VIEW \
    -c android.intent.category.BROWSABLE \
    -c android.intent.category.CAR_MODE -d 'https://example.com/'" | head -1
```

**Q4.** Predict all three counts before running. Which direction does adding a
category move the count, and why? State the rule in one sentence without looking at
it.

**Q5.** Adding `CAR_MODE` almost certainly took the count to zero or near it. Now
explain the *other* direction: a filter that declares ten categories is not "harder
to satisfy" than one that declares two. Why not? Point at the loop in
`IntentFilter.matchCategories` ([README §4.2](../README.md#42-intentfiltermatch--the-algorithm-traced))
and say what it iterates.

---

## Step 3 — `CATEGORY_DEFAULT`, the rule that breaks everybody's test

`cmd package query-activities` does **not** add `CATEGORY_DEFAULT` for you.
`startActivity` does. That difference is measurable.

Pick any app on the device with a `LAUNCHER` filter — its filter declares
`DEFAULT` and `LAUNCHER`.

```bash
# host — query WITHOUT default
adb shell "cmd package query-activities -a android.intent.action.MAIN" | head -1

# host — query WITH default, as startActivity would
adb shell "cmd package query-activities -a android.intent.action.MAIN \
    -c android.intent.category.DEFAULT" | head -1
```

**Q6.** Are the counts the same? If not, what kind of component is in the first
list and not the second, and what does that tell you about how it is started in
practice?

Now the practical half. Find a component whose filter does **not** declare
`DEFAULT`:

```bash
# host
adb shell "dumpsys package" | grep -B8 'android.intent.category.LAUNCHER' | head -40
```

**Q7.** Take any component you can find whose filter has an action and **no**
`CATEGORY_DEFAULT`. Try to start it implicitly:

```bash
# host
adb shell "am start -a <that action>"
```

Then try explicitly:

```bash
# host
adb shell "am start -n <pkg>/<class>"
```

Which worked? Write the sentence you would put in a report to describe this
component's reachability — it is neither "reachable" nor "not reachable".

---

## Step 4 — MIME matching in both directions

This is where the wildcard rules become concrete.

```bash
# host — note the INNER quotes on '*/*'
for t in "text/plain" "text/*" "*/*" "image/png" "application/pdf" "application/x-made-up"; do
  printf '%-24s ' "$t"
  adb shell "cmd package query-activities -a android.intent.action.SEND -t '$t'" | head -1
done
```

**Q8.** Predict all six counts. Then measure. Reference numbers from the Redmi /
API 30 device:

```text
text/plain              14 activities found:
text/*                  14 activities found:
*/*                     25 activities found:
image/png               18 activities found:
application/pdf         11 activities found:
application/x-made-up   11 activities found:
```

Four separate rules fall out of those six numbers. Name them:

- **Q8a.** Why do `text/plain` and `text/*` give the same count?
- **Q8b.** Why is `*/*` the largest?
- **Q8c.** Why do `application/pdf` and a completely invented type give the *same*
  count on that device?
- **Q8d.** What are those 11 components, and what is the security significance of a
  component that declares `android:mimeType="*/*"` on an exported filter?

**Q9.** Answer Q8d with evidence, not assertion:

```bash
# host
adb shell "cmd package query-activities -a android.intent.action.SEND \
    -t 'application/x-made-up'" | grep -E 'name=|exported='
```

Pick one of them. Would you report it? Under what circumstances? (Re-read
[README §5.2](../README.md#52-intent-redirection--the-primitive-in-full)'s
honest-severity warning first.)

---

## Step 5 — The cross product

The claim from [§3.4](../README.md#how-multiple-data-elements-combine--the-cross-product):
**a filter does not store `<data>` tuples. It stores independent sets, so multiple
`<data>` elements produce a cross product.**

Find a filter with several schemes and several types. Chrome is the reliable
example:

```bash
# host
adb shell "dumpsys package com.android.chrome" | sed -n '/Activity Resolver Table/,/Receiver Resolver/p' | head -40
```

Reference output from the Redmi / API 30 device:

```text
      text/html:
        e9c3255 com.android.chrome/com.google.android.apps.chrome.IntentDispatcher filter 3eb29f8
          Action: "android.intent.action.VIEW"
          Category: "android.intent.category.DEFAULT"
          Category: "android.intent.category.BROWSABLE"
          Scheme: "googlechrome"
          Scheme: "http"
          Scheme: "https"
          Scheme: "about"
          StaticType: "text/html"
          StaticType: "text/plain"
          StaticType: "application/xhtml+xml"
```

**Q10.** That is **one** filter. How many scheme/type combinations does it accept?
Write the number, then justify it from the shape of the output — what data
structure is `dumpsys` printing?

**Q11.** Test a combination the developer plainly did not have in mind:

```bash
# host
adb shell "cmd package query-activities -a android.intent.action.VIEW \
    -d 'about:blank' -t 'application/xhtml+xml'"
adb shell "cmd package query-activities -a android.intent.action.VIEW \
    -d 'googlechrome://x' -t 'text/plain'"
```

Did they match? What `match` value?

**Q12.** Do the same enumeration mechanically:

```bash
# host
python3 ../scripts/intent-surface-map.py --package com.android.chrome --components \
    | grep -A12 'data cross product'
```

**Q13.** Now the reason this matters. You are testing an app whose deep-link
handler declares:

```xml
<data android:scheme="https" android:host="checkout.example.com" />
<data android:scheme="myapp" android:host="legacy" />
```

and whose code contains `if ("https".equals(uri.getScheme())) { requireAuth(); }`.
Write the exact URI you would test with, and say what you expect to happen.

---

## Step 6 — Reproduce the two quoting failures deliberately

You will hit both of these for real, at the worst possible moment, and both look
like resolution failures rather than quoting failures.

### Failure 1 — the glob

```bash
# host — WRONG
adb shell cmd package query-activities -a android.intent.action.SEND -t "*/*"

# host — RIGHT
adb shell "cmd package query-activities -a android.intent.action.SEND -t '*/*'"
```

**Q14.** What did the wrong form return, and why? What did the device's shell do to
`*/*` before `cmd` ever saw it?

### Failure 2 — the semicolon

```bash
# host — WRONG
adb shell am start "intent:#Intent;action=android.intent.action.VIEW;scheme=https;S.k=v;end"

# host — RIGHT
adb shell "am start 'intent:#Intent;action=android.intent.action.VIEW;scheme=https;S.k=v;end'"
```

Reference output for the wrong form, measured:

```text
Error: Activity not started, unable to resolve Intent { act=android.intent.action.VIEW dat=intent: }
/system/bin/sh: S.k=v: inaccessible or not found
/system/bin/sh: end: inaccessible or not found
```

and for the right form:

```text
Starting: Intent { act=android.intent.action.VIEW dat=https:///... (has extras) }
```

**Q15.** The first line of the wrong output says "unable to resolve Intent". A
tester in a hurry concludes the target does not accept the Intent. Write down, in
one sentence, the difference between what that message says and what actually
happened.

**Q16.** The `intent:` URI grammar supports `S.` (String), `i.` (int), `l.`, `f.`,
`d.`, `b.`, `B.`, `c.`, `s.`. What is **not** in that list, and what does its
absence mean for testing intent redirection? (See lab 01 if you need the answer.)

---

## Step 7 — Ranking, and who actually wins

Matching produces a *list*. Something has to pick one.

```bash
# host — the full candidate list
adb shell "cmd package query-activities -a android.intent.action.VIEW \
    -c android.intent.category.BROWSABLE -d 'https://example.com/'"

# host — the single winner
adb shell "pm resolve-activity --brief -a android.intent.action.VIEW \
    -c android.intent.category.BROWSABLE -d 'https://example.com/'"
```

**Q17.** Each candidate line carries three numbers: `priority`, `preferredOrder`
and `match`. Define each one. Which of the three is a property of the *filter*,
which of the *user*, and which of the *match itself*?

**Q18.** Run `pm resolve-activity` for a URI where several apps compete. Did it
return a single component, or `com.android.internal.app.ResolverActivity`? What
does the latter mean?

**Q19.** A fourth thing outranks all three of those numbers. Name it. (Lab 03 is
entirely about measuring it.)

**Q20.** An app declares `android:priority="999"` on a filter for a common action.
Is that a finding? Argue both sides, then commit to an answer. What would you need
to measure to be sure?

---

## Step 8 — Read the buckets

`IntentResolver` is a bucketed index, and `dumpsys` prints the buckets by name.
Knowing them makes the output legible instantly.

```bash
# host
adb shell "dumpsys package com.android.chrome" \
  | sed -n '/Activity Resolver Table/,/Receiver Resolver/p' \
  | grep -E '^  [A-Z]' 
```

**Q21.** Which bucket headings did you see? Match each to the `IntentResolver`
field it comes from:

| Heading | Field | Holds filters that… |
|---|---|---|
| `Non-Data Actions:` | `mActionToFilter` | |
| `MIME Typed Actions:` | `mTypedActionToFilter` | |
| `Full MIME Types:` | `mTypeToFilter` | |
| `Base MIME Types:` | `mBaseTypeToFilter` | |
| `Wild MIME Types:` | `mWildTypeToFilter` | |
| `Schemes:` | `mSchemeToFilter` | |

**Q22.** A filter declaring `<data android:mimeType="audio/*"/>` appears under
`Base MIME Types` and is printed as `StaticType: "audio"` — with no `/*`. Why does
the platform store it that way, and what would you get wrong if you grepped the
dump for `audio/\*`?

---

## Step 9 — Reconstruct a filter from the dump alone

Pick any app on the device. Using **only** `dumpsys package <pkg>`, write out the
`<intent-filter>` XML you believe is in its manifest.

```bash
# host
adb shell "dumpsys package <your choice>" | sed -n '/Activity Resolver Table/,/Receiver/p'
```

Then check yourself against the APK:

```bash
# host
adb shell "pm path <your choice>"
adb pull <the path> app.apk
aapt2 dump xmltree --file AndroidManifest.xml app.apk | sed -n '/intent-filter/,/^ *E:/p'
```

**Q23.** Where did your reconstruction differ from the manifest? Two differences
are expected and are the interesting ones:

- The dump shows filters contributed by **libraries**, which the app's own source
  manifest never contained.
- The dump shows **resolved** values where the manifest has resource references.

Did you find either?

**Q24.** Which of the two sources would you cite in a report, and why? (Consider
what a developer can dispute.)

---

## Success criteria

- [ ] A written prediction recorded **before** every command in steps 1–5
- [ ] All four match values from step 1 measured and decoded correctly
- [ ] The category rule stated correctly, in the right direction, without notes
- [ ] `CATEGORY_DEFAULT`'s effect demonstrated with two commands that differ only
      by that category
- [ ] A component found that is reachable explicitly but not implicitly, and the
      report sentence for it written
- [ ] All six MIME counts measured, and all four rules in Q8 named
- [ ] The `*/*`-declaring components on your device enumerated
- [ ] A multi-scheme, multi-type filter found, its cross product computed by hand
      and confirmed by `intent-surface-map.py`
- [ ] One cross-product combination the developer never intended, tested
      and matched
- [ ] Both quoting failures reproduced deliberately, with the difference between
      the real and apparent cause written down
- [ ] `priority`, `preferredOrder` and `match` each defined, and the fourth,
      overriding factor named
- [ ] All six resolver buckets matched to their fields
- [ ] One filter reconstructed from `dumpsys` and diffed against the real manifest

---

## Debrief

1. Write the three matching tests from memory, in order, with the direction of each
   comparison. Then write the one that has an exception (`CATEGORY_DEFAULT`) and
   say what the exception is.

2. Explain why `IntentFilter.match()` returns an `int` rather than a `boolean`, and
   what the resolver does with the number.

3. A colleague says "the filter requires `DEFAULT`, `BROWSABLE` and `LAUNCHER`, so
   I need to send all three". Correct them, precisely.

4. You have an APK but no device. Which of this lab's questions can you still
   answer, and which can you not? Be specific — this is exactly the situation on a
   remote engagement.

5. Explain the cross-product rule to a developer who has just told you their filter
   "only handles `https://checkout.example.com` and `myapp://legacy`". Include the
   one command that will convince them.

6. Why does `cmd package query-activities` see components that the app under test
   cannot? Name the mechanism and the API level it arrived in, and say how it
   changes the sentence you write in a report.

7. On the reference device, eleven components accept `application/x-made-up` for
   `ACTION_SEND`. Is that a vulnerability in eleven apps? Answer in terms of the
   two questions from §5.2.

8. `match=0x508000` beats `match=0x208000`. Construct a scenario where that
   ordering is the difference between an attacker winning and losing a contested
   URI, and say what the defender should do about it.

---

## Cleanup

Nothing to clean up — this lab only reads. If you set any app-link preferences
while experimenting, reset them:

```bash
# host — API 31+
adb shell "pm reset-app-links <pkg>"
# host — API 30 and below
adb shell "pm set-app-link <pkg> undefined"
```
