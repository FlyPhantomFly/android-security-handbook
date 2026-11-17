# 64 — Xposed · FAQ

Real questions, answered directly. The obvious ones are here too, because they are the ones people
are embarrassed to ask and they are load-bearing.

**Measured versus documentation-derived.** Answers citing a number from a device or a corpus were
measured on `sdk_gphone16k_x86_64` (Android 15 / API 35, Magisk 30.7). Answers about classic
Xposed's *internals* are documentation-derived — **it is not installed anywhere here and no session
with it was fabricated.** [README.md](README.md)'s opening callout has the full split.

---

### 1. Is Xposed dead?

**The framework, yes. The API, no. The detection code, unfortunately no.**

Official support for classic Xposed ended at Android 8.1 / API 27. It cannot be installed on a device
with Verified Boot, because installing it means writing six files to `/system`. Measured on the AVD:
`/` is mounted `ro`, `ro.boot.veritymode = enforcing`, and every one of those six paths is `ENOENT`
**to root**.

But `de.robv.android.xposed` is what a module written this year still imports, because
[63-LSPosed](../63-LSPosed/README.md) implements the same API. And applications are still shipping
checks for `/system/framework/XposedBridge.jar` — a file that cannot exist on any device they
support.

---

### 2. Then why is there a whole chapter about it?

Three reasons, all present-tense:

1. **It explains why LSPosed is built the way it is.** Systemless because `/system` became
   unwritable; scoped because global was catastrophic; runtime-derived `ArtMethod` offsets because
   tabulated ones broke. You cannot evaluate a successor without knowing what it succeeded.
2. **You will read module source written against this API.** The documentation those authors read
   describes a framework they cannot install.
3. **Xposed-detection code is a live finding.** Knowing that a check cannot fire — and being able to
   demonstrate it from three vantages on a device the developer can reproduce on — is a deliverable.

---

### 3. What is `app_process`, and why did replacing it matter so much?

`app_process` is the program that starts the Android runtime. Given `--zygote` it becomes Zygote, the
process every application is forked from; otherwise it runs a named Java class, which is what `am`,
`pm` and `dumpsys` actually are.

**Every Java process on Android starts there.** One binary, one `main`. Replacing it gave total
coverage with no injection technique at all — which is why classic Xposed never needed `LD_PRELOAD`,
`ptrace`, `RegisterNatives` rewriting or a root daemon at runtime. Riru, Zygisk and Frida are all
answers to a question Xposed never had to ask, and every one of them appeared *after* replacing the
binary stopped being possible.

---

### 4. Did Xposed "inject into Zygote"?

**No, and getting this backwards makes the whole lineage incomprehensible.**

Classic Xposed **replaced the program that becomes Zygote**, so its code was present from the
process's first instruction. Injecting a library into a *running* Zygote is Riru's and Zygisk's
answer, invented precisely because replacing the binary had become impossible.

The distinction matters because it explains a capability difference: Xposed's code ran before Zygote
preloaded a single class, which is earlier than any modern framework gets.

---

### 5. What did `hookMethodNative` actually do?

Four operations on the target's `ArtMethod`:

1. **Copy the whole structure** — the backup, so the original body stays reachable.
2. **Set `kAccNative`** in `access_flags_` — the runtime stops looking for bytecode.
3. **Point the entry point at the generic JNI trampoline**, with `data_` set to Xposed's dispatcher.
4. **Set `kAccCompileDontBother`** — otherwise the JIT compiles the method and writes a *new* entry
   point over yours, and the hook silently stops firing.

On Dalvik the same idea used the `Method` structure's `nativeFunc`. The name is a description of
step 2: *make the method native.*

[13-ART §3.15–3.17](../13-ART/README.md) owns the structure. This is what one framework did with it.

---

### 6. Why does the Xposed API use `Object[]` for arguments? It is ugly.

Because the original dispatcher was a **native** function.

A native method receives a `JNIEnv*`, a receiver, and its arguments. Xposed's generic dispatcher had
to box those into something a Java callback could read and rewrite, and `Object[]` is what that is.
`param.args[0] = "x"` works because the array is passed to the invocation of the original.

That is a 2012 implementation detail that leaked into the API surface and became permanent — every
subsequent engine has had to reproduce it. It is the one place the abstraction leaked, and it is why
question 22's answer is what it is.

---

### 7. What is the difference between Xposed, EdXposed, LSPosed, Riru and Zygisk?

Four *layers*, not five products. This is the single most common source of wrong answers.

| Layer | What it does | Examples |
|---|---|---|
| **Root** | Gives you privilege | Magisk, KernelSU, APatch |
| **Injection** | Gets a native library into Zygote | Riru, Zygisk. **Classic Xposed needed none — it was the program** |
| **Framework** | Decides whose code runs where; provides the API | classic Xposed, EdXposed, LSPosed |
| **Engine** | Installs the actual method hook | `hookMethodNative`, YAHFA, SandHook, LSPlant |

**The break between eras is at the injection layer, not the hooking layer.** Everything after classic
Xposed still rewrites an ART method's entry point.

---

### 8. Can I install classic Xposed to try it?

**No, and you should not want to.** It requires disabling Verified Boot.
[61-Fastboot](../61-Fastboot/README.md) measured what `--disable-verity` actually does: it flips one
byte inside the region AVB hashes, invalidating the image's own signature. It is not a supported
option the platform honours — it is a deliberate corruption that only an unlocked bootloader will
accept, and a device left in that state and then relocked is a brick.

If you want managed-code hooking, use [63-LSPosed](../63-LSPosed/README.md). README §7.5 maps every
classic behaviour onto a modern reproduction.

---

### 9. My module compiles and loads but hooks nothing, and there is no error anywhere. What is wrong?

**Almost always `implementation` instead of `compileOnly`.**

The framework supplies `de.robv.android.xposed.*` at runtime. If your module packages its own copy,
your code calls *your* `XposedBridge` — a different class from the one the framework loaded — so
every hook installs into nothing. The module loads cleanly, `handleLoadPackage` runs,
`findAndHookMethod` returns, and nothing happens. **No stage of the build, the install or the load
reports a problem.**

Check it in one command:

```bash
unzip -l module.apk | grep de/robv     # must be EMPTY
```

If that is not it, work through README §3.13's checklist. The next most likely causes are: the target
process never restarted (`am force-stop`), the module is not scoped to the package, or the method was
inlined (`cmd package compile -m verify -f <pkg>`).

---

### 10. What actually makes an APK a module?

Three things, none structural:

1. `xposedmodule` meta-data in the manifest, value `true`. Without it the manager will not list it.
2. `assets/xposed_init` — a plain text file, one fully-qualified entry class name per line.
3. DEX references to `de.robv.android.xposed` types **that the APK does not define**.

That third one is the interesting one. Measured on this chapter's own module: the DEX **references
ten `de.robv` types and defines none of them.** On an ordinary Android app that is a broken build; on
a module it is the format.

---

### 11. Can I tell from an APK whether it is a classic Xposed module or an LSPosed module?

**No, and any tool claiming otherwise is guessing.** The manifest meta-data, `assets/xposed_init` and
the `de.robv` references are identical, because LSPosed consumes the same format deliberately.

What you *can* read from the APK:

- **The capability list**, from the type references. `XC_MethodReplacement` means it replaces bodies;
  `IXposedHookZygoteInit` means it wants to run in Zygote.
- **The target list**, from the string constants, because reflection is string-based.

The framework is a property of the **device**, not of the APK.

---

### 12. Why can an obfuscated module not hide its entry class?

Because the framework reads `assets/xposed_init` with **no knowledge of any obfuscation mapping**.
Rename the entry class and R8 does not update the asset, so the framework looks for a class that no
longer exists and the module does nothing.

Every module therefore needs a `-keep` on its entry classes, which means the entry class name is in
plaintext in every module ever shipped. **There is no configuration in which that is not true.**

`unzip -p module.apk assets/xposed_init` is the first command of any module triage.

---

### 13. A module's DEX has no `setResult` or `XC_MethodReplacement`. Is it safe to enable?

**No, and this is measured rather than argued.** [63-LSPosed §6.3](../63-LSPosed/README.md) compiled
a module whose source contained `param.setResult(Boolean.TRUE)` behind a
`private static final boolean OBSERVE = true` guard. `javac` folded the constant condition and
eliminated the entire branch. The field survived with its value; the code did not. Grepping the DEX
for `setResult` returned **0 across all nine classes.**

So: **presence is strong evidence a module modifies behaviour; absence is weak evidence of anything.**
Triaging a module APK tells you what *that build* does, not what the same author can ship tomorrow
from the same source with a one-character change, the same package name and the same signature.

When the question is trust, review the source and the build.

---

### 14. Why is `new File("/system/framework/XposedBridge.jar").exists()` such a bad check?

Three reasons, stacking:

1. **The file cannot exist.** Measured `ENOENT` **to root** on API 35, with `/` mounted `ro` and
   verity enforcing.
2. **Only classic Xposed ever created it.** LSPosed never has, EdXposed never did.
3. **`File.exists()` cannot tell you why it said `false`.** It maps `ENOENT` and `EACCES` alike to
   `false`.

Point 3 is the one that generalises. `/data/adb/lspd` also returns `false` from an app — but for the
*opposite* reason: the path is refused at `/data/adb` (mode `0700 root:root`), so it returns `false`
whether LSPosed is installed or not. **Same output, opposite causes, and only one of them could ever
change.**

---

### 15. What about checking `app_process`'s size or hash? That seems sound.

It *was* sound in principle — classic Xposed genuinely did replace that binary. It is now the worst
check in the family, because it produces **false positives on clean devices**.

Four reasons, three measured:

- **There is no device-independent expected value.** 51,616 bytes on this API 35 x86_64 AVD; a
  different number on every other build, ABI and vendor image.
- **It is a symlink on many images** (`app_process -> app_process64`), and there is no
  `app_process32` on a 64-bit-only image at all.
- **LSPosed leaves the file byte-identical**, so a match proves nothing.
- **A platform update changes it legitimately**, so a fleet running this check generates a support
  incident on every release.

The correct behaviour is to **report the value with the build fingerprint** and let a server with
population data judge it. Chapter 64's CTF ([Lab 04](labs/lab-04-ctf-the-ghost-of-app-process.md))
is built entirely around this one check.

---

### 16. So is *any* Xposed check worth keeping?

Yes, in ascending order:

| Check | Verdict |
|---|---|
| `Class.forName("de.robv.android.xposed.XposedBridge")` | **Keep.** It asks about *this process*, so hiding files does not defeat it |
| A dispatcher frame in a deliberately-thrown stack trace | **Keep, and look for both names** — `handleHookedMethod` (classic) *and* `LSPHooker` (LSPlant) |
| A method with bytecode whose flags claim `kAccNative` | **Strongest.** Not a state ART produces; needs no baseline. Requires native code or Frida |
| Signals sent to a server with a hardware-attested token | **The only one that changes the outcome rather than the cost** |

All of the first three run in the attacker's address space and can therefore be hooked. That is not a
reason to skip them; it is a reason to be honest that they raise cost rather than creating a
boundary.

---

### 17. `Class.forName` on `XposedBridge` — did it not always mean the same thing?

No, and this is the subtlest thing in the chapter.

Under **classic Xposed**, `XposedBridge.jar` was on the **boot class path**, so the class was
resolvable in *every process on the device*. The check answered: *"is the framework installed on this
device?"*

Under **LSPosed**, the class is on a class loader inside the process, put there only where a module is
scoped. The same line answers: *"is a module loaded into THIS process?"*

Narrower, and for an application more useful. **Same code, different question, and nobody updated the
comment.**

---

### 18. I ran `grep -i xposed` over a pile of APKs and got loads of hits. Did I find something?

**Almost certainly not.** Measured across 237 real APKs from a stock Android 15 image:

```
APKs containing the substring 'xposed' : 58
total occurrences                      : 1141
accounted for by 'exposed'/'Exposed'   : 1141
unexplained                            : 0
```

**The English word "exposed" contains the substring "xposed".** Fifty-eight of 237 applications
"match", and every single occurrence is that word. Verified per-app: Chrome had 4 and 4; Settings had
113 against 15 + 98; GMS had 30 against 15 + 15.

Anchor every signature on something that cannot occur in English — `de.robv`,
`/system/framework/XposedBridge.jar`, `Lde/robv/android/xposed/`. Never match a bare `xposed`.

---

### 19. Fine, I anchored my signatures. Now what can go wrong?

**Short tokens, because obfuscators manufacture them.**

This chapter's own scanner briefly carried a STRONG-tier signature matching the three-character token
`vxp`. It reported **16 STRONG hits** across the corpus. Every one was an R8-generated class name —
`Lvxp;`, `Lavxp;`, `Lbvxp;` — sitting in an alphabetical run of minified identifiers.

Worse than the `exposed` trap in one specific way: **it gets more likely as applications get better
protected**, because the more aggressively minified an app is, the more short lowercase identifiers
exist. The population you most care about is the one most likely to false-positive.

**Rule: never put a token shorter than about eight characters in a high-confidence tier.**

And the general form, which this repository has now measured three times: **if a detector agrees with
you about a lot of samples, suspect the detector.** Adjudicate the highest-confidence band by hand
*first*, because that is where a bad signature does the most damage.

---

### 20. Can I just grep the APKs on the device instead of pulling them?

You can, and it has a **measured** blind spot that is worse than the number suggests.

Modern APKs store `classes.dex` uncompressed so Android can `mmap` it, so a raw grep over the `.apk`
usually works. Measured on the corpus: **234 `classes*.dex` STORED, 16 DEFLATED.**

But look at *which* sixteen. All of them are in **`/data/app`** — sideloaded or Play-updated — across
four APKs, and **ten of the sixteen are Chrome's.** Every preinstalled APK on `/system`, `/product`
and `/system_ext` is STORED.

So the device-side shortcut is blind to exactly the population worth scanning, and in that corpus it
would silently have skipped the largest and most interesting third-party application present. Pull
and scan properly, or at minimum report which APKs the shortcut could not see.

---

### 21. How many real apps actually check for Xposed?

**This chapter cannot tell you, and says so.** Its corpus was 237 APKs from a stock Google emulator
image, of which **four** were third-party. The result — zero genuine detection code — supports
*"the Android platform and Google's own applications do not ship Xposed-detection code"*, which is a
real and slightly surprising finding.

It supports **nothing** about banking, wallet, DRM, gaming or enterprise applications, because there
are none in the corpus. To answer that question, build a corpus that matches it:

```bash
./scripts/pull-apk-corpus.sh --serial <a real phone> --third-party-only --out /tmp/apks
python3 -B scripts/xposed-detection-scan.py /tmp/apks --recursive --min-tier 2 --verbose
```

Then adjudicate by hand and **report the denominator you used.**

---

### 22. The API survived eight years past its framework. Is that just luck?

Partly, and partly good factoring. The API names *what to hook* and *what to do*, and says nothing
about *how the framework arrived* or *what rewrites the method*. Everything that changed —
`app_process` replacement → Riru → Zygisk; `hookMethodNative` → YAHFA → SandHook → LSPlant; Dalvik
`nativeFunc` → `ArtMethod` entry points — changed **below** the surface, because none of it had leaked
into the surface.

The one place it *did* leak is instructive: `MethodHookParam.args` is an `Object[]` because the
original dispatcher had to box arguments (question 6). That is a 2012 implementation detail which
every subsequent engine has had to reproduce.

**An API outlives its implementation exactly to the extent that the implementation did not leak into
it** — and the one leak became a permanent constraint.

---

### 23. Should I report "the app doesn't detect Xposed" as a finding?

**No**, unless the threat model explicitly includes a compromised device. MASVS-RESILIENCE is scoped
that way in the standard's own words, and reporting resilience gaps against an application with no
resilience requirement is the fastest way to lose a developer's attention.

**And do not report "the app detects Xposed" as a mitigation either.** It will be read as
anti-instrumentation, and usually it is dead code.

The finding worth writing is the one underneath: *"control X is enforced only by a client-side check
which cannot fire on any device the application supports, therefore X is unprotected"* — and then the
severity is **X's severity, not the check's**.

---

### 24. Why did Xposed die if the technique still works?

Because the **injection** stopped being possible, not the hooking. Five forces, and none was aimed at
it: dm-verity and mandatory Verified Boot; the annual release cadence plus Treble making per-release
`app_process` ports impractical; ART becoming a Mainline module so the `ArtMethod` layout was no
longer determined by the OS version; A/B block-level OTA removing the framework on every update; and
successors that solved injection without touching any partition.

**The decisive one is not the obvious one.** Support ended at API 27, *before* the last of those
landed — what actually ended it was the maintenance cost of hand-porting a binary to every release
across a fragmented vendor matrix.

The generalisable lesson: **architectural changes are often better security controls than security
features.** dm-verity exists because a persistent `/system` rootkit is the worst outcome for a phone,
not because of Xposed.

---

### 25. What is the one thing to remember from this chapter?

That a client-side integrity check has an **expiry date and no expiry mechanism**.

Nothing warns you when a check's premise stops being true. The check goes on compiling, running,
returning `false`, and looking healthy — while the security documentation goes on claiming the
control exists. Applications are shipping checks for `/system/framework/XposedBridge.jar` today, and
the file has not been creatable since roughly 2018.

When you find a client-side check, the useful question is not "can I bypass it?" — you can — but
**"on what devices can this fire at all?"** Answer that with a number and you have written a finding
the developer can act on.

---

## Still stuck?

| Question | Where |
|---|---|
| How the *modern* framework works | [63-LSPosed](../63-LSPosed/README.md) |
| `ArtMethod`, entry points, why a hook does not fire | [13-ART](../13-ART/README.md) |
| What a hook physically is, across all five types | [65-Hooking](../65-Hooking/README.md) |
| Systemless root, Zygisk, `/data/adb/modules` | [62-Magisk](../62-Magisk/README.md) |
| Verified Boot, `vbmeta`, unlocking | [61-Fastboot](../61-Fastboot/README.md) |
| Root/tamper detection in general | [37-RootDetection](../37-RootDetection/README.md) · [38-TamperDetection](../38-TamperDetection/README.md) |
| Bypassing protections, and the cost model | [67-BypassingProtections](../67-BypassingProtections/README.md) |
| Why a sweep produces leads, not findings | [52-StaticAnalysis](../52-StaticAnalysis/README.md) |
