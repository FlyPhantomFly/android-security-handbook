# 52 — Static Analysis · FAQ

Real questions, answered directly. Including the ones people are embarrassed to ask, which are
usually the ones worth answering.

---

## 1. I have an APK and no idea what to do. Where do I actually start?

Three commands, in this order, and do not skip to a decompiler:

```bash
sha256sum target.apk
unzip -l target.apk | head -40
aapt2 dump badging target.apk | head -20
```

You now know the file's identity, roughly what is inside it, and its package name, versions and SDK
levels. That is enough to decide what kind of app it is and therefore what kind of analysis will
work. Then, and only then, `jadx -d out target.apk` — which will take a while, so start it and go
read the manifest while it runs.

The mistake almost everyone makes on their first APK is opening jadx-gui, scrolling through class
names for twenty minutes, and feeling lost. You are lost because you skipped the part that gives you
orientation. See [README §8.1](README.md#81-the-five-minute-pass).

---

## 2. Is jadx enough on its own?

For understanding, usually. For evidence, no.

jadx produces a *reconstruction* of Java from Dalvik bytecode. It can be wrong, and it tells you when
it is unsure — on a 2,783-class test app it reported `finished with errors, count: 17` and still
wrote `.java` files for those seventeen classes. If a finding depends on the exact semantics of a
method, read the Smali or the `dexdump` output, because those are transliterations of the bytecode
and cannot be wrong about it.

You also need at least two other views that jadx does not give you well:

- **`aapt2 dump xmltree`**, because it is the platform's own manifest parser and is the tiebreaker
  when your tools disagree.
- **`apktool`**, because it decodes `res/xml/` — the network security config, FileProvider paths,
  backup rules and accessibility config — which is where several whole finding classes live.

---

## 3. Why does my grep return thousands of hits?

Because you are grepping a tree that is mostly not the application. A modern APK bundles AndroidX,
the Kotlin runtime, Play Services, an HTTP client, an image loader and a dozen SDKs. On a trivial
5.8 MB test app, 2,759 of 3,655 files were third-party and only **3** were the app's own code.

Measured on that app: the word `password` appears **137 times**, and 136 of those are framework or
generated code. The remaining one is a resource identifier in `R.java`.

So: classify by package before you read anything. `static-sweep.py` does it automatically from the
manifest's `package=` attribute, and `--files app` skips library files without even opening them —
which on a 20,091-file tree turned a six-minute sweep into a one-minute one.

---

## 4. How do I know if a finding is real?

Answer four questions, in order. A lead becomes a finding only when all four have answers:

1. **Is the construct really there?** Read the code, not the grep output. Read Smali if the semantics
   matter.
2. **Is it reachable?** Build a caller closure to a manifest-declared entry point, or hook it at
   runtime and see whether it fires.
3. **Who can reach it?** Another app? The network? Only the app itself?
4. **What does reaching it get them?** That answer *is* the severity.

Then try to *kill* it. `validate-lead.sh` prints an eight-item kill list; a lead you have not tried
to refute is a lead you have not validated.

---

## 5. Can I automate all of this?

Stages 1 through 6, yes, and you should. Stage 7 — validation — no, and the reason is not that the
tooling is immature.

A tool can tell you a string has the shape of a credential. It cannot tell you what that credential
authorises, because that fact is not in the file; it is in the vendor's documentation, in the
client's architecture, and sometimes only in a conversation. Severity is question four of four and
question four is never in the artefact.

What you *can* automate is making stage 7 fast: aggregate hits into leads, print a next step for
each, and gather the evidence pack automatically so the human only has to make the judgement.

---

## 6. What is the difference between a hit, a lead and a finding?

- A **hit** is one regex match on one line of one file.
- A **lead** is one distinct value or construct, with every site it appears at attached, plus a
  confidence and a next step.
- A **finding** is a lead that has survived validation.

The ratios are brutal and they are the whole argument for the distinction: on one real tree, 7,346
hits became 9 leads became 2 confirmed items became 1 reportable finding.

---

## 7. The scanner says HIGH. Isn't that the severity?

No, and this confusion causes more bad reports than any other.

**Confidence** answers "is this worth my next ten minutes" — a property of the lead, which a tool can
estimate. **Severity** answers "how bad is this" — a property of the finding, which depends on
reachability, on who can reach it, and on what it protects.

Measured: on a real commercial app, **15 of the 17 highest-confidence leads were rejected on
inspection** — seven were `slf4j` documentation URLs, three were Compose preview fixtures, one was an
XMP namespace. Meanwhile the single most interesting row in the run sat in the MEDIUM band.

`static-sweep.py` deliberately has no severity column. If you add one, you will start believing it.

---

## 8. Everything in my sweep is a false positive. Am I doing it wrong?

Almost certainly not. That is the normal experience and this repository has published the numbers:

- Chapter 33's leak hunter: **132 high-confidence hits, 132 false positives**, all of them Chrome
  component-updater signature manifests that match a JWT rule because they genuinely are signed JSON.
- This chapter, on a commercial app: **15 of 17** high-confidence leads rejected.
- Chapter 36: **12 of 14** apps presented a pinning surface; **4** actually pinned.

In every case the rules fired correctly. They were answering "does this look like X", and the
question that mattered was "is this X". Those are different questions and no regex closes the gap.

What you should worry about is a sweep with a *low* false-positive rate on a keyword rule — that
usually means the rule is not firing at all.

---

## 9. Should I use MobSF or write my own tooling?

Both, for different things.

MobSF gives breadth quickly and is a reasonable first inventory on an app you have never seen. What
it cannot do is stage 7: it reports every exported component at the same severity, cannot resolve
custom permission protection levels, and cannot know what a component does. Its output is a queue.

Write your own catalogue for the rules you personally can defend in a client meeting. A rule you
wrote, whose precision you chose, whose hand-run grep you have executed, is a rule you can stand
behind. A rule from a tool you have never inspected is a rule you will have to say "the scanner
flagged it" about, which is the worst sentence in a debrief.

---

## 10. What can static analysis definitely NOT see?

Five things, structurally:

| Blind spot | Scale |
|---|---|
| Receivers registered at runtime | **299 of 431 distinct broadcast actions (69%)** on a real device had no manifest-declared receiver anywhere |
| Native methods bound with `RegisterNatives` | No symbol exists in the `.so`; universal in anything deliberately hidden |
| Reflection targets | Chosen by string at runtime; no static edge |
| DEX loaded after installation | The code is not in the artefact you swept |
| Server-side behaviour and remote-config flags | Not on the device at all |

Which is why "the sweep was clean" and "the app is clean" are different statements, and why the
report needs a limits section that names each mechanism and says whether *this* app uses it.

---

## 11. My decompiled tree has no readable strings at all. What does that mean?

It is a signal, not a dead end. Three explanations, in order of likelihood:

1. **String encryption.** The literals are ciphertext plus a decryptor. Go to
   [40-Obfuscation](../40-Obfuscation/README.md) §6.1 Phase 4: hook `java.lang.String.<init>([B)`,
   look at the stack traces, and the top one or two callers are your decryptors.
2. **A packer.** The real DEX is decrypted at runtime and your tree is a stub. Check the class count
   against the asset sizes.
3. **A cross-platform framework.** The logic is in `index.android.bundle`, `global-metadata.dat` or a
   Dart AOT snapshot, and the DEX genuinely has nothing in it.

An app whose string table contains no URLs at all is doing one of those three, and the second and
third change your entire plan.

---

## 12. Do I need a device for static analysis?

No — that is the point of it. But a device turns claims into evidence, and you should use one when
you have it:

```bash
adb shell dumpsys package PKG | grep 'flags='
# flags=[ DEBUGGABLE HAS_CODE ALLOW_CLEAR_USER_DATA ALLOW_BACKUP ]
```

That single line converts "the manifest says `debuggable=true`" into "the platform installed it with
`DEBUGGABLE` and enforces it". A file's claim about itself is weaker than the system's record of what
it did with that file.

---

## 13. What is "reachability" and why does everyone keep saying it?

Whether any execution path can actually get to the code you found. It matters because a
vulnerability in code nothing calls is not a vulnerability — it is a maintenance issue.

Statically you approximate it with a **caller closure**: find every class that names the class
holding your lead, then every class that names those, until you meet a class the manifest declares as
a component. That is evidence, not proof, and it has four holes — reflection, dependency injection,
service loading, and framework or native callbacks — each of which creates a real edge with no
textual reference.

So the honest sentence is never "unreachable". It is **"no static path found"**, plus what you did
to check the four holes, plus — if it matters — a runtime hook that either fired or did not, with the
observation window stated.

---

## 14. The reachability tool printed "FRONTIER EXPLODED". Is it broken?

No, it is being honest. Past a few hundred classes the closure has escaped into framework and utility
code, where name references connect everything to everything, and any "reachable" verdict from there
would be an artefact of the method rather than a fact about the app.

Measured on a 3,655-file tree, starting from an ordinary Activity: depth 1 gave 1 class, depth 2 gave
2, depth 3 gave 14, depth 4 gave 6, and depth 5 gave **540**. Stopping there is correct.

Narrow instead: start from the specific *method* rather than the class, use jadx-gui's Find Usage on
the field, or settle it dynamically.

---

## 15. Do I have to read Smali?

Not fluently. You need five constructs on sight and that is the whole list:

| Construct | Smali | Meaning |
|---|---|---|
| Literal loaded | `const-string vX, "…"` | The value is right there in the artefact |
| Field read | `sget-object` / `iget-object` | Static vs instance; `sget` on a singleton is a Kotlin `object` |
| Comparison | `if-ne v0, v1, :label` | The gate — read the constant loaded into `v1` |
| Call | `invoke-virtual` / `-static` / `-direct` | Full callee signature is on the line |
| Cast | `check-cast vX, LType;` | The compiler's proof of the static type |

With those five you can confirm any finding that a decompiler might have got wrong.

---

## 16. An app has a `TrustManager`. Does it pin certificates?

Unknown, and the presence of the class is weak evidence in either direction. Chapter 36 measured 14
real applications: **12 presented a pinning surface and only 4 actually pinned.**

Do three things before writing anything: read `checkServerTrusted` (an empty body accepts every
certificate), look for configured pin *values* (a `CertificatePinner.Builder` with no `.add()` pins
nothing), and check `res/xml/network_security_config.xml`, because pins frequently live there and not
in code. Then attempt an intercept — and first check that your own device's trust store has not been
modified, because a device with an interception CA in the *system* store will happily lie to you.

---

## 17. Why does the sweeper refuse to give me a severity?

Because it cannot know one, and a number it invents would be believed.

Severity depends on what the thing protects. A 40-character hex string in `Application.onCreate` is
Informational if it is a translation-SDK project token that grants read access to published string
bundles, and it is a serious finding if the same token grants write access. Nothing in the file
distinguishes those two cases. Only the vendor's documentation and the client do.

So the tool gives you a confidence — "worth ten minutes?" — and a next step, and stops. The stopping
is the feature.

---

## 18. How long should a static pass take?

For one medium app, roughly: 10 minutes to acquire, 10 to unpack, 5 of your time to start the
decompile, 30 to enumerate, 5 to sweep, 15 to triage — and **the rest of the day to validate**, plus
two hours to write.

If your day looks inverted, with hours in the decompiler and twenty minutes of validation at the end,
the output will be 90% scanner content and everyone downstream will be able to tell.

---

## 19. What do I write when I find nothing?

"The sweep produced no leads above threshold", followed immediately by the limits section. Never "no
issues found".

Then check the four reasons a sweep comes back empty: you swept the wrong tree (a split you did not
decompile), the app is genuinely small and clean, the strings are encrypted, or the code is not in
the artefact at all.

---

## 20. Static or dynamic — which should I learn first?

Static, and for a specific reason: it teaches you the shape of the system. You cannot write a useful
Frida hook for a class you cannot find, and you find classes by reading artefacts.

After that, the professional rule is the one chapter 40 states from the other side: **use dynamic
analysis to understand and static analysis to be exhaustive**, in that order, whenever both are
available. Dynamic tells you what the app really does; static tells you everything else it could do,
and how many places it does it.
