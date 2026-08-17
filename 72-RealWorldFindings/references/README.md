# 72 — Real World Findings: references

Annotated. Where a link is to a chapter in this repository, the annotation says **what number or
result this chapter took from it**, so that any figure in the README can be traced to its owner and
re-checked there.

> **The rule this list exists to serve:** every number in chapter 72 that came from another chapter
> was verified against that chapter before it was cited. Where a brief or a memory disagreed with
> the owning chapter, the chapter won. Three such corrections are recorded below — including one
> where **the owning chapter itself was wrong**, which is the most instructive of the three.

---

## 1. Chapters this one is built on

### The measurement sources

| Chapter | What chapter 72 took from it |
|---|---|
| [52-StaticAnalysis](../../52-StaticAnalysis/README.md) | The 17 MB commercial sweep: whole-tree run **16,836 raw hits → 168 leads**; a separate `--files app` run producing **17 HIGH / 49 MEDIUM / 23 LOW**, of which **15 of 17 HIGH were rejected by hand (88%)**; the real finding at **MEDIUM 0.50** — a `Domain` enum shipping 13 environments (production, pre-production, eight QA, three staging). Also the second target: **7,346 hits → 9 leads → 2 survived** |
| [33-Storage](../../33-Storage/README.md) | **132 of 132** high-confidence secret hits false, all component-updater signature manifests. The zero-permission cross-app file read rated **Informational**, and the DAC/MAC/content three-gate model this chapter adopts for Gate 3. The SQLite WAL result: 2 rows deleted, four secrets readable in a **61,832-byte** `-wal` |
| [36-CertificatePinning](../../36-CertificatePinning/README.md) | **12 of 14** apps have a pinning *surface*, **4 of 14** carry a pin value — the surface-versus-configuration distinction. Also why `sha256/` grep hits on everything: the constant belongs to OkHttp's own parser |
| [64-Xposed](../../64-Xposed/README.md) | The 237-APK sweep: 58 matched, **1,141 occurrences, 1,141 explained by "exposed", 0 unexplained**. The `vxp` signature's **16 STRONG hits, all R8 class names**, and the rule that follows: **never put a token shorter than about eight characters in a high-confidence tier**. Also **234 STORED vs 16 DEFLATED** DEX entries and the `adb`-eats-stdin trap |
| [38-TamperDetection](../../38-TamperDetection/README.md) | The detector that reported a self-signature check in **18 of 18** APKs and was corrected to **13 of 18** after a STRONG/WEAK split — the "if a detector agrees with you about every sample, suspect the detector" rule. Also **only 1 of 18** apps imports `ptrace`; **6 of 198** packages carry a signing lineage; and that a `classes.dex` CRC check does not detect re-signing |
| [47-Authentication](../../47-Authentication/README.md) | The `FLAG_SECURE` constant-folding result — the identifier absent from both `.class` and DEX, giving a **true-positive rate of zero**. Also its **17-APK** sweep (18 pulled, one excluded by the THIN APK rule) and its warning that a 15-of-17 "local gate" row is a count of string matches, not of gates |
| [39-EmulatorDetection](../../39-EmulatorDetection/README.md) | The vantage rule with numbers: **~1062 properties to root, ~678 to `shell`, ~638 to an app**; the `ro.boottime.*` family (111 properties) is typed `boottime_prop` and is invisible to `shell` *and* to an app. **This chapter originally quoted a superseded figure — see §2 below and README §3.3a** |
| [60-ADB](../../60-ADB/README.md) | Why `adb shell` is privileged: not the shell GID (which `platform.xml` grants only `INTERNET`) but the `com.android.shell` package — **200 permissions requested, 183 at install, 16 runtime permissions pre-granted `SYSTEM_FIXED`** |
| [51-DynamicAnalysis](../../51-DynamicAnalysis/README.md) | **67% or 50% coverage from identical evidence** (4 components statically, 3 in the device's resolver tables, 2 reached) — runtime evidence cannot supply its own denominator. Also the void-run result and the liveness checks |
| [29-BroadcastReceivers](../../29-BroadcastReceivers/README.md) | **299 of 431 distinct actions (69%)** registered by third-party processes have no manifest receiver anywhere — the largest measured blind spot in any manifest-based sweep, including this chapter's own. Also that `INSTALL_REFERRER`, `c2dm.intent.RECEIVE` and `PROVIDER_CHANGED` are forgeable |
| [56-JADX](../../56-JADX/README.md) | jadx under-reporting its failures by ~30× (**console said 61; tree held 2,104 refused methods across 1,424 files**), and the constructed case where decompiled Java returns 100 while the bytecode returns 105 |
| [30-Activities](../../30-Activities/README.md) | Task hijacking measured **mitigated** on a real device, with the working attack rated High and a squatted affinity INFO — the inverse of most published checklists, and this chapter's example of a received severity being backwards |
| [46-Tokens](../../46-Tokens/README.md) | **Half the JWT failure classes involve no forgery at all** — two accepted attacks carried genuine valid signatures and failed on claim validation |
| [28-Services](../../28-Services/README.md) | `getCallingUid()` in `onBind` returns the service's own uid (victim 10310 logging 10310 while the attacker was 10313) — why this chapter's Frida script labels its `onBind` output unreliable for identity |
| [25-Binder](../../25-Binder/README.md) | Caller identity is unforgeable, demonstrated: a chosen UID written into `sender_euid` produced the same `SecurityException` naming the real uid. This is why `getCallingUid()` in evidence *is* evidence |
| [65-Hooking](../../65-Hooking/README.md) | A perfectly-installed hook against an inlined function changes nothing — the reason a quiet instrumentation log is ambiguous |
| [54-Objection](../../54-Objection/README.md) | `android sslpinning disable` reporting three successful hooks against an app with no network code: a bypass message is evidence a hook installed, not that the app pinned |
| [68-ReverseEngineering](../../68-ReverseEngineering/README.md) | **12.9%** of methods declared `native` resolve to an exported symbol — quoted here only with its denominator, per that chapter's own instruction. Also its decision to identify the AVD and deliberately not use it |
| [42-R8](../../42-R8/README.md) / [40-Obfuscation](../../40-Obfuscation/README.md) | What minification does to corpus statistics: 1,393 empty Kotlin metadata shells producing 1,393 false positives; Kotlin *property* names surviving where JVM member names do not; three builds byte-identical at 12,757 bytes despite different DEX sizes |
| [10-APK-Internals](../../10-APK-Internals/README.md) | `examples/parse_axml.py`, the independent binary-XML reader this chapter's sweep imports — and its ordering rule: when a parser and the device disagree, **the device is right** |
| [23-Permissions](../../23-Permissions/README.md) / [32-Manifest](../../32-Manifest/README.md) | The custom-permission squatting **precondition**: with both apps declaring the name, the second install is refused symmetrically, so the attack needs a declare/use mismatch. This is why 126 of 243 apps at `protectionLevel="normal"` is a lead count, not a finding count |
| [27-ContentProviders](../../27-ContentProviders/README.md) / [26-Intent](../../26-Intent/README.md) | Provider access control, URI permission grants, and the confused-deputy primitive behind the Smali shape in §6.2 |
| [37-RootDetection](../../37-RootDetection/README.md) / [63-LSPosed](../../63-LSPosed/README.md) | Vantage-dependence of detection probes; `new File("/data/adb/lspd").exists()` returning `false` whether or not the path exists, because `File.exists()` maps `ENOENT` and `EACCES` alike |

### The framework and the templates

| Chapter | Relationship |
|---|---|
| [71-OWASP-Mobile](../../71-OWASP-Mobile/README.md) | **Owns MASVS/MASTG and the mapping.** This chapter owns what is found in practice, and §5.6 catalogues where the two diverge. 71 contains no real-world frequency statistics by design, so nothing here duplicates it. Its position that "the control violation is a *fact*; the severity is an *argument*" is the principle §3.7 builds on |
| [80-Appendix §5–§6](../../80-Appendix/README.md#5-severity-cvss-and-business-impact) | **Owns the severity rubric, the CVSS discussion, the finding template and the executive summary skeleton.** This chapter defers to it exactly as 71 does, and covers the failure modes around it rather than the scale itself |
| [74-CaseStudies](../../74-CaseStudies/README.md) | The narrative counterpart. Its unit is the **story** — whole engagements with the reasoning and dead ends; this chapter's unit is the **finding class** with counts across many apps |
| [`73-Labs`](../../73-Labs/) | Where deliberately vulnerable practice targets are collected. This chapter's labs are adjudication drills and need no target |
| [75-InterviewQuestions](../../75-InterviewQuestions/README.md) | §10's questions in a chapter-independent form |
| [`76-CheatSheets`](../../76-CheatSheets/) | Aggregates this chapter's [`cheatsheet.md`](../cheatsheet.md) with the other 79 |

---

## 2. Three corrections made while writing this chapter

Recorded so that nobody restores the wrong version from memory.

**The system-property vantage figures were wrong at source, and this chapter propagated them.**
[39-EmulatorDetection](../../39-EmulatorDetection/README.md) published `shell` at **1,053**
properties against an app's **634**, and this chapter quoted it in six places before the figure was
re-measured. The published "shell" number was in fact **root**, taken with `adb root` in effect or
through `su`. Corrected and stable across three runs: **~1062 to root, ~678 to `shell`, ~638 to an
app**, with the 111-strong `ro.boottime.*` family invisible to `shell` *and* to an app.

The tell had been visible in the original table all along — it listed `root` at 1050 and `shell` at
1053, and two SELinux domains cannot see effectively the same property set when only one is subject
to `boottime_prop`. The correction inverts the practical advice: the shell-to-app gap is ~40
properties and the root-to-shell gap is ~384, so `adb shell` is a mediocre proxy for an app and a
catastrophic proxy for root. For chapter 39's own subject the gap nearly vanishes — 36
emulator-indicating `init.svc.*` properties from the shell against 35 from an app.

Two things about this belong in a chapter about adjudication, and both are written up in
[README §3.3a](../README.md#33a-a-worked-gate-1-failure-committed-by-this-repository):

- **The claim survived because it was dramatic, not because it was checked**, and six citations of
  one measurement is still one measurement.
- The divergence was found by [74-CaseStudies](../../74-CaseStudies/README.md), which **changed nothing in
  chapter 39** — it published its own numbers and command and filed the discrepancy as unresolved,
  leaving adjudication to the owning chapter. That is the correct protocol, and this chapter adopts
  it as a rule: **an irreproducible measurement is a discrepancy, not a correction.**

**The 17-HIGH band does not belong to the 16,836-hit run.** An early draft of §2.3 wrote "16,836 raw
hits → 168 leads, of which 15 of 17 HIGH were rejected". That splices two different invocations of
the same tool over the same app: the whole-tree run produced 16,836 → 168, while the **17 HIGH leads
came from a narrower `--files app` run** (6,883 raw hits → 96 leads → 89 displayed). Both figures are
real and they never shared a denominator. This is the commonest way a true number becomes a false
one — not by invention, but by joining two statistics that were never joined.

**`FLAG_SECURE` has two correct spellings, and which one is right depends on where you are
looking.** AOSP *declares* the constant as `0x2000`, and
[47-Authentication](../../47-Authentication/README.md) writes it that way in its source-constant
tables. javac then *folds* it, so the DEX literal renders as `const/16 v0, #int 8192 // #2000` and
the decimal form is what a bytecode search must match. **Both appear in 47, deliberately.** An
earlier version of this paragraph claimed the chapter used only the decimal form; it does not, and
the presentation was never the finding. The finding is that **grepping the source-level identifier
has a true-positive rate of zero**, because the identifier survives in neither the `.class` nor the
DEX.

A third figure was checked and deliberately **not** cited as a bare app count, and the caution
turned out to be justified. [68-ReverseEngineering](../../68-ReverseEngineering/README.md) described
its corpus as 18 APKs in its method paragraph and 19 in four other places — **an inconsistency this
chapter recorded as unresolved, and which the release audit has since resolved: 18 is correct.**
That chapter's own [`68-ReverseEngineering/examples/worked-journal.md`](../../68-ReverseEngineering/examples/worked-journal.md) records the corpus being re-measured and every figure
updated from `19/7,562/1,050/13.9%` to `18/8,140/1,049/12.9%`; four sites were missed in that update
and have now been corrected.

**The rule this vindicates: cite the substantive figure with its denominator, not the headline
count.** This chapter cited **12.9% of 8,140 declared native methods** and was therefore correct
throughout, while the app count beside it was wrong in the source chapter for weeks. A ratio carries
its own audit trail; a bare count does not.

> **Do not "fix" chapter 68's four remaining `19`s.** They refer to
> [42-R8](../../42-R8/README.md)'s **separate** 19-APK Kotlin-metadata corpus, which is a different
> sweep entirely. Two corpora of similar size in adjacent chapters is exactly how a correct number
> gets edited into a wrong one.

---

## 3. This chapter's own measurements

Everything here was measured for this chapter, on **AVD `sdk_gphone16k_x86_64` (`emulator-5554`),
Android 15 / API 35, x86_64, rooted with Magisk 30.7, Zygisk off** — the only device attached on
2026-08-16. The two physical phones in this repository's rotation were **not** connected, and no
claim here is attributed to them.

| File | What it is |
|---|---|
| [`../scripts/manifest-corpus-sweep.py`](../scripts/manifest-corpus-sweep.py) | The sweep. **Executed**: 243 packages listed, 243 manifests extracted, 243 parsed. Produces the funnel in §3.5 |
| [`../scripts/provider-reachability-probe.py`](../scripts/provider-reachability-probe.py) | The read-only reachability probe. **Executed** against 82 authorities |
| [`../scripts/component-reachability.js`](../scripts/component-reachability.js) | Frida hooks for in-process reachability. **Parsed with `node --check`, not run against a target** — frida-server does not link on this AVD image, and the header says so rather than implying a verification that did not happen |
| [`../examples/corpus-sweep-output.txt`](../examples/corpus-sweep-output.txt) | The raw, unedited sweep output behind every number in §3.5, with its provenance header |
| [`../examples/ProviderReachProbe.java`](../examples/ProviderReachProbe.java) | The zero-permission app-vantage probe. **Compiles clean** against `android-35` with `javac 24.0.2 -Xlint:all --release 8`; **not installed or run**, and labelled as such |
| [`../examples/finding-writeups-graded.md`](../examples/finding-writeups-graded.md) | Six findings written badly and well against the same observations |

### Corpus caveat, repeated because it bounds everything above

**Four of the 243 packages are third-party.** This is a *platform* corpus. It supports statements
about how Android and its bundled applications are built and supports **nothing** about banking,
retail, or any category a commercial assessment targets. Manifests were read from `base.apk` only,
so components shipped in split APKs are absent — and the reachability figures were taken at a
**shell vantage (uid 2000)**, which is not an application.

---

## 4. Corpus pseudonyms

Several chapters in this repository measured **commercial applications that happened to be installed
on the author's own test device**. The measurements are published; the applications' identities are
not. Every such app is written throughout as `com.vendor.<category>`, and the same pseudonym is used
in every chapter, so a reader can follow one app across chapters 28, 33, 36, 43, 44, 48, 55, 56 and
68 without being able to name it.

**What is preserved:** every package size, `targetSdk`, component count, pin count, expiry date,
domain count, DEX/native-library count, measured percentage and assigned severity is the real,
unmodified value. **What is removed:** the vendor's identity — package name, brand name, and the
hostnames and pin values that would reconstruct it.

| Pseudonym | Category of application |
|---|---|
| `com.vendor.socialmedia` | A large social-media app |
| `com.vendor.professionalnet` | A professional-network app |
| `com.vendor.streaming` | A video-streaming client |
| `com.vendor.marketplace` | A large e-commerce marketplace app |
| `com.vendor.grocery` | A grocery-delivery app |
| `com.vendor.homeservices` | An on-demand home-services app |
| `com.vendor.hrapp` | An HR / payroll app (the 17 MB target of [52-StaticAnalysis](../../52-StaticAnalysis/README.md)) |
| `com.vendor.loyalty` | A restaurant loyalty and ordering app, built with Flutter |
| `com.vendor.oemshop` | An OEM-branded e-commerce app, built with Flutter |
| `com.vendor.appstore` | A third-party application store |
| `com.vendor.filemanager` | A third-party file-manager utility |
| `com.vendor.fileexplorer` | A root-capable file-explorer utility |
| `com.vendor.officesuite` | A bundled office-document app |
| `com.vendor.remotectl` | An infrared remote-control app |
| `com.vendor.shortvideo` | A short-video social app |
| `com.vendor.keyboard` | A third-party keyboard app |
| `com.vendor.learning` | An enterprise learning-management app |
| `com.vendor.fieldmgr`, `com.vendor.fieldapp` | The [51-DynamicAnalysis](../../51-DynamicAnalysis/README.md) targets — see that chapter's own note |
| `com.client.app` | The [42-R8](../../42-R8/README.md) "Enterprise app A" |

A small number of **bundled SDKs** are pseudonymised too, for the reason given under "an inventory is
a fingerprint" below:

| Pseudonym | Category of SDK |
|---|---|
| `io.vendorchat.android` / `io/vendorchat/android` | A support-chat SDK |
| `io.vendorrealtime.lib` / `io/vendorrealtime/lib` | A realtime-messaging SDK |
| `com.vendor.identitysdk` | A federated-identity SDK |
| `com.vendor.paymentsdk` | A payments SDK |

**This table maps pseudonym to category only, and deliberately does not record which real package
each pseudonym stands for.** A mapping file that reverses the anonymisation would defeat it.

### Why this is applied globally, and not per chapter

**Partial anonymisation is not anonymisation. It is a puzzle with the answer printed on the next
page.** This repository learned that on itself.

[52-StaticAnalysis](../../52-StaticAnalysis/examples/README.md) did the careful thing: it wrote its
target as `com.vendor.hrapp`, replaced the bundled SDK names with `<sdk>`, redacted the internal
hostnames, and wrote out its reasoning. Four other chapters then named the same application outright
— and [56-JADX](../../56-JADX/README.md) additionally described it as *"a 17.5 MB commercial HR
application, pulled and decompiled on this device"*, printed its SDK inventory by package, and gave
per-package class counts. Chapter 52's anonymisation was fully reversible by anyone who read chapter
56, and the reader did not even have to be trying.

Three rules follow, and they are the reason the table above exists at all:

1. **One pseudonym per real application, used in every chapter.** A pseudonym that is local to one
   chapter protects nothing, because the cross-references in this repository are dense by design.
2. **An inventory is a fingerprint.** A size, a targetSdk, an SDK list and a per-package class count
   identify a vendor as reliably as the package name. If the package name is worth withholding, so is
   the combination that reconstructs it. This is why a handful of SDK names are pseudonymised while
   the SDK-identification tables in [17-Libraries](../../17-Libraries/README.md) are not: there the
   SDK is the subject, here it is a property of a withheld app.
3. **Anonymise the identity, never the measurement.** Every count, ratio, date, size and severity in
   this repository is the real measured value. If a substitution would cost a number, the number wins
   and the section gets rewritten around it.

### What is deliberately not pseudonymised

Three classes of package name are **not** pseudonymised anywhere in this repository, because naming
them is what makes the material usable:

| Kept | Why |
|---|---|
| AOSP, Google and OEM **system-image** packages (`com.android.*`, `com.google.android.*`, `com.miui.*`, `com.xiaomi.*`, `com.mediatek.*`, `com.qualcomm.*`, `com.ubx.*`, `com.udroid.*`) | These are the operating system under test. No severity verdict is attached to any of them, and [51-DynamicAnalysis](../../51-DynamicAnalysis/examples/README.md) states the same rule for its own vendor firmware rows |
| **Library and SDK** identifiers in an import, a dependency table or a vendor-identification list (`com.squareup.*`, `org.bouncycastle.*`, `com.stripe.*`, [17-Libraries §7](../../17-Libraries/README.md)'s whole vendor table, …) | A library identifier with no verdict attached is a fact about the library, not a finding about an app. **The test is the verdict, not the identifier:** the moment a severity, a reachability result or a "leaks / insecure / weak" claim attaches to a named SDK, it stops being reference data and becomes a named finding against an identifiable vendor — and is pseudonymised, as the four SDK rows above were. An *unadjudicated* severity against a named vendor is the worst case of all: chapter 52 measured **15 of 17** HIGH-band leads rejected on hand adjudication, so publishing an unresolved HIGH with a vendor's name on it contradicts this repository's most-repeated finding |
| **Root, hooking and detection-signature** packages (`com.topjohnwu.magisk`, `org.lsposed.manager`, `me.bmax.apatch`, and the canonical root-detection lists in [37-RootDetection](../../37-RootDetection/README.md)) and **deliberately-vulnerable training apps** (CMPen, DIVA, OVAA, InsecureBankv2, the MobileHackingLab targets) | These are published signatures and public training targets. Chapters 37 and 38 do not work without them, and the training apps exist to be named and attacked |

---

## 5. External references

### Android platform documentation

- **App manifest overview** — the `<activity>`, `<service>`, `<receiver>` and `<provider>` elements.
  The rows worth reading closely are `android:exported` (and the API 31 requirement that it be
  explicit whenever an `<intent-filter>` is present) and the provider's *three* separate guards:
  `android:permission`, `android:readPermission` and `android:writePermission`.
- **Back up user data with Auto Backup** — `android:allowBackup`, `android:fullBackupContent`, and
  `android:dataExtractionRules`, which since API 31 separates cloud backup from device-to-device
  transfer. Read it before writing any backup finding: the two have different threat models.
- **Network security configuration** — and the `usesCleartextTraffic` default at `targetSdkVersion`
  28 and above, which is the fact that makes the absent-attribute finding a false positive.
- **Behaviour changes** pages, per API level — the authoritative record of which finding classes the
  platform has closed. Worth re-reading annually against your own checklist.
- **Android Security Bulletins** — the correct source for CVE identifiers. Quote the bulletin month
  alongside any ID so a reader can verify it. If you cannot produce the bulletin, describe the class
  instead.

### AOSP source

Paths only; this chapter cites no line numbers, because they move.

- `frameworks/base/core/java/android/content/pm/ComponentInfo.java` — where the parsed `exported`
  boolean lives.
- `frameworks/base/core/java/android/content/pm/PermissionInfo.java` — the protection-level
  constants and flags, including the deprecated `PROTECTION_SIGNATURE_OR_SYSTEM` (value 3) and
  API 31's `PROTECTION_INTERNAL` (value 4). Those two are the entire explanation of the eleven
  cross-check disagreements in §3.8.
- `frameworks/base/core/java/android/content/ContentProvider.java` — `enforceReadPermissionInner`,
  whose ordering (own uid → permission → URI grant → throw) decides most provider severities, and
  whose exception text is what the probe in §7.3 classifies on.
- `frameworks/base/services/core/java/com/android/server/am/ActivityManagerService.java` — the
  enforcement point for component starts.

### Standards and scoring

- **OWASP MASVS v2** — the eight categories. A completeness check, not a work plan; see §5.6.
- **OWASP MASTG** — test procedures, and the best available shared vocabulary for describing what
  you did.
- **OWASP Mobile Top 10** — coarser than MASVS and better for executive framing than for technical
  work. Its category names are exactly the "titles that are categories" the write-up rubric rejects.
- **FIRST — CVSS v3.1 Specification**, and, more importantly, the **CVSS v3.1 User Guide**. Read the
  User Guide before using CVSS on a mobile finding: the *environmental* metrics are what make it
  usable for a client-specific threat model, and they are what most reports omit. A base score
  applied to a mobile finding without them is the mechanical-scoring problem
  [80-Appendix §5](../../80-Appendix/README.md#5-severity-cvss-and-business-impact) opens with.
- **CWE** — useful for classifying a finding's *root cause* in a way that survives across platforms,
  and a better cross-reference than a Top 10 category when you want the developer to search for
  prior art.

### Reporting practice

- **NIST SP 800-115**, *Technical Guide to Information Security Testing and Assessment* — dated in
  its techniques and still sound on the separation between testing, analysis and reporting, which is
  the separation this chapter's three gates formalise.
- **PTES** (Penetration Testing Execution Standard) — its reporting section is the clearest short
  statement of why the executive summary and the technical findings are different documents with
  different readers.

> **On external "statistics" about mobile vulnerability prevalence.** Vendor reports quoting
> percentages of apps affected by a class are usually unusable for the three reasons in
> [`../faq.md`](../faq.md#21-my-corpus-is-243-apps-can-i-say-56-of-android-apps-expose-components):
> the corpus composition is undisclosed, the mechanical definition of the class is undisclosed, and
> the adjudication — if any — is undisclosed. Treat any such figure as a lead about the vendor's
> tooling rather than a fact about Android, and never quote one in a client report without its
> denominator.

---

## 6. Related chapters

| Chapter | Relationship to this one |
|---|---|
| [52-StaticAnalysis](../../52-StaticAnalysis/README.md) | Produces the leads this chapter adjudicates |
| [51-DynamicAnalysis](../../51-DynamicAnalysis/README.md) | Produces the runtime evidence that carries a lead through Gate 2 |
| [71-OWASP-Mobile](../../71-OWASP-Mobile/README.md) | The control framework; this chapter is what is found in practice, and says where the two disagree |
| [80-Appendix](../../80-Appendix/README.md) | The severity rubric and the report templates this chapter defers to |
| [70-VulnerabilityResearch](../../70-VulnerabilityResearch/README.md) | Novel vulnerability discovery; this chapter covers what recurs |
| [69-MalwareAnalysis](../../69-MalwareAnalysis/README.md) | The same taxonomy read as capability rather than risk |
| [74-CaseStudies](../../74-CaseStudies/README.md) | Depth and narrative, where this chapter is breadth and taxonomy |
| [`73-Labs`](../../73-Labs/) | Practice targets |
| [75-InterviewQuestions](../../75-InterviewQuestions/README.md) | §10 in chapter-independent form |
| [`76-CheatSheets`](../../76-CheatSheets/) | Aggregates [`../cheatsheet.md`](../cheatsheet.md) |
