# 52 — Static Analysis

> After this chapter you can take an APK you have never seen, run a repeatable eight-stage pipeline
> over it, turn thousands of grep hits into a short queue of leads, validate each lead until it is
> either a defensible finding or a recorded rejection, and state precisely which parts of the
> application your analysis could not see.

**Prerequisites:** [10-APK-Internals](../10-APK-Internals/README.md),
[12-DEX-Internals](../12-DEX-Internals/README.md),
[32-Manifest](../32-Manifest/README.md),
[17-Libraries](../17-Libraries/README.md),
[04-Java](../04-Java/README.md)

**Applies to:** every Android version. The pipeline is version-independent; individual findings are
not, and the chapter says so at each point. Everything measured here was measured on a Redmi
`M2101K6P` running **Android 11 / API 30**, rooted, with jadx 1.5.3 and Python 3.13 on the host.

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [High-Level Architecture](#2-high-level-architecture)
3. [Deep Internal Working](#3-deep-internal-working)
4. [Source Code Walkthrough (AOSP)](#4-source-code-walkthrough-aosp)
5. [Security Perspective](#5-security-perspective)
6. [Reverse Engineering Perspective](#6-reverse-engineering-perspective)
7. [Dynamic Analysis](#7-dynamic-analysis)
8. [Static Analysis](#8-static-analysis)
9. [Examples](#9-examples)
10. [Common Interview Questions](#10-common-interview-questions)
11. [Common Mistakes](#11-common-mistakes)
12. [Hands-on Labs](#12-hands-on-labs)
13. [Summary](#13-summary)
14. [References](#14-references)

---

## 1. Introduction

### 1.1 The problem that existed before

Suppose someone hands you a sealed machine and asks whether it is safe to install in a hospital. You
have two ways to find out. You can switch it on and watch what it does — which tells you the truth
about the things it happens to do while you are watching, and nothing at all about the things it
does on the third Tuesday of the month. Or you can take it apart on a bench, lay out every component,
and read the wiring — which tells you about every path the machine *can* take, including the ones it
never took in front of you, but tells you nothing about what actually happens when the current flows.

Those two methods are dynamic analysis and static analysis. Neither is a substitute for the other,
and the entire professional skill is knowing which question belongs to which.

> **📖 Definition**
> **Static analysis** is the examination of a program's *artefacts* — its files, its bytecode, its
> resources, its manifest — without executing it. **Dynamic analysis** is the examination of a
> program's *behaviour* while it runs. The distinguishing feature of static analysis is not that it
> is "safer" or "offline". It is that static analysis observes what is **possible**, and dynamic
> analysis observes what **happened**.

Before there was a discipline here, mobile assessment looked like this: install the app, proxy it,
click every button, report whatever appeared in Burp. That approach has one fatal property. **It only
ever finds the code you managed to trigger.** An app has a login screen you can reach and a
"corporate SSO" branch you cannot, an ordinary payment path and an emergency refund path behind a
feature flag, a debug menu that appears only when a particular file exists. Clicking finds the first
of each pair. The APK contains both.

### 1.2 What would break without it

Take away static analysis and four things become impossible:

- **Completeness.** You could never say "there are eleven places this app writes to disk". You could
  only say "I saw three".
- **Analysis of what you cannot run.** Malware that refuses to execute on your device. An app that
  detects root and exits. A build for hardware you do not have. A sample that would exfiltrate a real
  victim's data if you let it run.
- **Inventory.** You cannot ask a running app "which library versions are you built from" and get a
  complete answer. You can read it off the artefact. That is why MASVS-CODE asks for a dependency
  inventory *with versions* and why [17-Libraries](../17-Libraries/README.md) exists.
- **Evidence that survives.** A finding backed by "file `X`, line 88, in the artefact whose SHA-256
  is `…`" can be re-checked by anyone, a year later, with no device. A finding backed by "I saw it in
  Burp on Tuesday" cannot.

### 1.3 What it costs

Static analysis pays for those four properties with three weaknesses, and a tester who does not
carry all three in their head will publish something embarrassing.

| Weakness | What it means in practice |
|---|---|
| **It cannot see what is not there** | Code loaded at runtime, decrypted at runtime, or produced by the server is not in the artefact. Your sweep of it is complete and irrelevant. |
| **It over-approximates** | Everything the code *could* do is reported, including code no execution ever reaches. This is the source of every false positive you will ever argue about. |
| **It is defeated by indirection** | Reflection, dependency injection, `RegisterNatives`, and runtime receiver registration all break the textual link between caller and callee. The link still exists; your tool cannot see it. |

The second of those has a number attached, and this repository measured it. Chapter 33's
`leak-hunter.py`, run against a real Chrome installation, produced **132 high-confidence hits, of
which 132 were false positives** — every one a component-updater signature manifest that matched a
JWT-shaped rule because it genuinely *is* signed JSON. Not one of them was a mistake by the tool.
Every rule fired correctly. The tool was answering "does this look like a credential", and the
question that mattered was "is this a credential", and those are different questions.

> **🧠 Mental Model**
> A static analyser is a metal detector on a beach. It is extremely good at telling you where the
> metal is. It has no opinion about whether you have found a Roman coin or a bottle cap, and the
> ratio on a real beach is roughly a hundred bottle caps to one coin. The skill being taught in this
> chapter is not sweeping. It is digging, quickly, and putting the caps back.

### 1.4 Why this chapter exists separately from the others

Eighteen chapters in this repository perform static analysis in their §8, and each does it *for one
thing*: [32-Manifest](../32-Manifest/README.md) audits manifests,
[17-Libraries](../17-Libraries/README.md) inventories dependencies,
[40-Obfuscation](../40-Obfuscation/README.md) recovers meaning from renamed code,
[10-APK-Internals](../10-APK-Internals/README.md) reads the container. Each of those is an *instance*
of a method. This chapter is the method.

What the method owns, and none of those chapters owns:

1. **The pipeline** — the order of operations, and why that order and no other.
2. **Triage** — turning a mass of hits into a ranked, workable queue.
3. **Validation** — the discipline that converts a lead into a finding or, far more often, into a
   recorded rejection. This is the centre of gravity of the chapter.
4. **The blind spots** — a plain statement of what static analysis structurally cannot see, so that a
   clean sweep is never reported as a clean application.
5. **Honest severity** — a string in a DEX is not a finding. Reachability decides.

> **⚠️ Warning**
> If you are here for manifest auditing, library fingerprinting, or deobfuscation, you are in the
> wrong chapter and the right chapters are linked above. This chapter deliberately does not re-teach
> them, and its tooling deliberately does not re-implement theirs.

### 1.5 A first look at the whole thing

Here is the entire chapter in nine lines, so that everything that follows has somewhere to attach:

```
1. ACQUIRE     get the exact artefact the user gets, and hash it
2. UNPACK      open the container; know what is inside before decompiling
3. DECOMPILE   produce something readable, from more than one tool
4. ENUMERATE   list what exists: components, classes, endpoints, libraries
5. SWEEP       apply the rule catalogue; produce hits
6. TRIAGE      collapse hits into leads; rank them; assign a next step
7. VALIDATE    confirm or kill each lead, in writing
8. REPORT      findings with evidence, honest severity, and the fix
0. THROUGHOUT  record what you could not see
```

Stage 7 is the one that separates a professional from a scanner operator, and it is the stage that
almost every published methodology skips. Stage 0 is the one that separates an honest report from a
dangerous one.

---

## 2. High-Level Architecture

### 2.1 The pipeline

```mermaid
flowchart TD
    subgraph Acquisition["Stage 1-2 — Acquisition (the artefact is evidence)"]
        A1["adb shell pm path pkg<br/>ALL splits"] --> A2["pull + SHA-256"]
        A2 --> A3["signature: schemes, signer DN"]
        A3 --> A4["unzip -l : what is in the container?"]
    end

    subgraph Views["Stage 3 — Views (no single tool is enough)"]
        V1["jadx<br/>Java-like source"]
        V2["apktool<br/>smali + decoded resources"]
        V3["aapt2 dump<br/>the platform's own parser"]
        V4["strings / DEX string table<br/>ground truth for literals"]
    end

    subgraph Enum["Stage 4 — Enumeration"]
        E1["components + entry points"]
        E2["class + package inventory"]
        E3["endpoints, keys, crypto, storage"]
        E4["native libs, assets, extra code"]
    end

    S["Stage 5 — SWEEP<br/>rule catalogue over the tree"]
    T["Stage 6 — TRIAGE<br/>hits collapse to LEADS<br/>ranked, each with a next step"]
    V["Stage 7 — VALIDATE<br/>confirm or KILL, in writing"]
    R["Stage 8 — REPORT<br/>evidence, honest severity, fix"]
    B["Stage 0 — BLIND SPOTS<br/>recorded continuously"]

    A4 --> V1 & V2 & V3 & V4
    V1 & V2 & V3 & V4 --> E1 & E2 & E3 & E4
    E1 & E2 & E3 & E4 --> S --> T --> V
    V -- "survives" --> R
    V -- "killed" --> L["LEDGER<br/>rejected, with the reason"]
    V -- "cannot be answered statically" --> D["hand to 51-DynamicAnalysis"]
    S -.-> B
    V -.-> B
    B --> R

    style V fill:#f9d0d0
    style B fill:#f9e0c0
    style L fill:#d0e8f9
```

Read that diagram in three parts. The **left column** is acquisition and it is short, because it is
short in practice — twenty minutes of hashing and listing. The **middle** is where most people spend
their entire engagement, and it produces hits, which are worth almost nothing on their own. The
**red box** is the stage this chapter is about: every lead either becomes a finding, becomes a
recorded rejection in the ledger, or is handed to dynamic analysis because the question is not a
static question. The **amber box** runs the whole time and feeds the report: everything you could not
see is part of the deliverable.

Note what the diagram does **not** contain: an arrow from SWEEP straight to REPORT. There is no such
arrow anywhere in professional practice, and its absence is the single most important line in this
chapter.

### 2.2 What each view can and cannot see

An APK is one file that four tools read four different ways, and the differences are not cosmetic.

```mermaid
flowchart LR
    APK["base.apk<br/>(ZIP)"]

    APK --> M["AndroidManifest.xml<br/>binary AXML"]
    APK --> D["classes*.dex"]
    APK --> R["resources.arsc + res/"]
    APK --> N["lib/*/*.so"]
    APK --> AS["assets/"]
    APK --> MI["META-INF/<br/>signatures + .version"]

    M --> M1["aapt2 dump xmltree<br/>= what the PLATFORM parses"]
    M --> M2["apktool<br/>= readable, resolves @refs"]
    D --> D1["jadx<br/>= Java-like; can be WRONG"]
    D --> D2["baksmali<br/>= smali; never wrong"]
    D --> D3["string_ids table<br/>= exact literals"]
    R --> R1["apktool res/values/*.xml"]
    N --> N1["readelf / Ghidra"]
    AS --> A1["your eyes"]
    MI --> S1["apksigner -v --print-certs"]

    style D1 fill:#f9e0c0
    style AS fill:#f9d0d0
```

The two coloured boxes are the ones that cost people findings.

**jadx output can be wrong.** It is a *reconstruction*. On the test app used throughout this chapter,
jadx 1.5.3 reported `finished with errors, count: 17` while decompiling 2,783 classes — and it still
wrote Java files for the classes it failed on, containing whatever it could salvage. A decompiler
that fails loudly is a gift; one that fails quietly is a trap. When a finding depends on the exact
semantics of a method, read the Smali.

**`assets/` is opaque and nothing will tell you what is in it.** No tool decodes an asset, because an
asset is by definition a file the build system did not process. A 4 MB `assets/data.bin` is either a
font atlas or an encrypted DEX, and the only way to know is to look.

### 2.3 The life of a lead

The pipeline diagram shows the flow of work. This one shows the flow of a *single lead*, and it is
the state machine the ledger records.

```mermaid
stateDiagram-v2
    [*] --> Hit : a rule matches a line
    Hit --> Lead : aggregated by identity,<br/>scored, given a next step
    Hit --> Killed : validator rejects the shape<br/>(3,591 of 7,346 on a real tree)
    Lead --> Demoted : on the known-noise list<br/>(counted, never hidden)
    Lead --> Working : a human opens the file
    Working --> Rejected : fails a kill-list question
    Working --> Deferred : the question is not a static one
    Working --> Confirmed : construct is real AND reachable
    Confirmed --> Finding : impact established
    Confirmed --> Informational : real, but protects nothing
    Deferred --> [*] : handed to dynamic analysis
    Rejected --> [*] : recorded in the ledger, with the reason
    Demoted --> [*] : counted in the summary
    Killed --> [*] : counted in the summary
    Finding --> [*] : report, with evidence and honest severity
    Informational --> [*] : observations section

    note right of Rejected
        This is the most common
        terminal state, and the
        reasons are a deliverable.
    end note
```

Four things in that diagram are worth arguing about, so they are stated explicitly:

- **`Killed` and `Demoted` are counted, never silent.** A tool that discards without a count is a
  tool that will one day discard your finding.
- **`Deferred` is a legitimate outcome.** "This is not a static question" is a professional answer,
  not a failure, and it is how the boundary with dynamic analysis gets respected instead of blurred.
- **`Confirmed` splits.** A construct can be entirely real and protect nothing — that is
  Informational, and §9.2 works a real example.
- **`Rejected` has a reason attached, always.** The reason is what turns a rejection from "I did not
  look" into "I looked and here is why it is not a finding".

### 2.4 The trust boundary you are standing on

```mermaid
flowchart TD
    subgraph Untrusted["Untrusted input — everything in the APK"]
        Z["ZIP entries with attacker-chosen names"]
        X["binary XML with crafted headers"]
        DX["DEX with a lying header"]
    end
    subgraph Host["Your analysis host"]
        T1["unzip / apktool / jadx"]
        T2["your scripts"]
        FS(["your filesystem"])
    end
    Z -- "zip slip: ../../.ssh/authorized_keys" --> T1
    X -- "parser divergence" --> T1
    DX -- "resource exhaustion" --> T1
    T1 --> FS
    T2 --> FS

    style Z fill:#f9d0d0
    style X fill:#f9d0d0
    style DX fill:#f9d0d0
```

An APK you are analysing is a file written by the person you are analysing. Three consequences,
all of which have bitten real analysts:

- **Path traversal on extraction.** A ZIP entry named `../../../.ssh/authorized_keys` will be written
  there by a naive extractor. `17-Libraries/scripts/lib-inventory.sh` refuses such entries explicitly
  and says why; copy that behaviour rather than re-deriving it.
- **Parser divergence.** The manifest your tool shows you and the manifest the platform parses can
  differ, deliberately. That is the entire subject of `32-Manifest/labs/lab-06` and
  `10-APK-Internals`' CTF, and it is why stage 3 uses `aapt2` — the platform's own parser — alongside
  apktool.
- **Resource exhaustion.** A DEX header can claim four billion strings. Tools that trust it die or
  hang. `04-Java/scripts/dump-strings.py` validates the claim against the file size before allocating,
  and says so in its error message.

> **🔍 Pentester's Note**
> Do your unpacking in a container or a throwaway directory, and never in your home directory. This
> is not paranoia about malware; it is about the boring case where `apktool` writes 40,000 files
> where you did not expect them.

---

## 3. Deep Internal Working

This is the long section. It walks the eight stages, and for each: **what** it is, **why** it is in
that position, **when** you can skip it, **where** its output goes, and **how** it fails.

### 3.1 Stage 1 — Acquire

**What.** Obtain the exact bytes the user's device receives, and record their identity.

**Why first, and why it is not a formality.** Three separate published mistakes live here.

1. **Analysing a build you compiled.** If the client sends you source and you build it, you have
   analysed a debug build. Debug builds are debuggable, log more, ship test fixtures, and skip R8.
   Every "finding" that follows is a finding about your own build. This mistake has appeared in
   public reports repeatedly.
2. **Analysing only `base.apk`.** App Bundle delivery splits an application across
   `base.apk`, `split_config.arm64_v8a.apk`, `split_config.en.apk` and any number of dynamic feature
   modules. Native libraries live in the ABI split. An inventory built from `base.apk` alone reports
   zero `.so` files and is simply wrong.
3. **Analysing a file someone emailed you.** It may be the wrong version, the wrong flavour, or
   modified.

**How.**

```bash
# host — every path the platform knows about, not just the first
adb shell pm path com.example.target
# package:/data/app/~~AbC==/com.example.target-XyZ==/base.apk
# package:/data/app/~~AbC==/com.example.target-XyZ==/split_config.arm64_v8a.apk

# pull each one, then record identity
adb pull /data/app/~~AbC==/com.example.target-XyZ==/base.apk .
sha256sum base.apk | tee -a evidence/hashes.txt
```

The hash goes in your notes and in the report. It is what makes a finding re-checkable.

**Where the platform's own answer lives.** `pm path` reads the same data the package manager holds,
so it is authoritative about what is installed. Cross-check the version you are about to spend a day
on:

```bash
# adb shell — the platform's view, which beats any file you decoded
dumpsys package com.example.target | grep -E \
  "versionName|versionCode|targetSdk|minSdk|flags=|privateFlags=|installerPackageName"
```

That `flags=` line is worth its own paragraph. On the test device, for the app used throughout this
chapter, it reads:

```
flags=[ DEBUGGABLE HAS_CODE ALLOW_CLEAR_USER_DATA ALLOW_BACKUP ]
```

`DEBUGGABLE` there is the **platform's own confirmation** of a manifest flag — not a file's claim
about itself, but the system's record of what it installed and enforces. When a static lead and the
platform disagree, the platform wins.

**How this stage fails.** Silently, and later. You will not notice you pulled the wrong split until
the finding you are chasing is "missing" from the code. Write the split list in your notes.

**When you can skip it.** Never. Even for a file handed to you, hash it.

### 3.2 Stage 2 — Unpack

**What.** Open the ZIP and look at the inventory *before* you decompile.

**Why before decompilation.** Decompiling a 90 MB app takes minutes to hours. Two minutes of
`unzip -l` tells you whether that time will be well spent, and occasionally tells you the whole
answer.

```bash
# host — the two-minute triage that decides everything after it
unzip -l target.apk | head -40
unzip -l target.apk | grep -cE '\.dex$'                 # multidex? how many?
unzip -l target.apk | grep -E 'lib/[^/]+/' | \
      awk -F/ '{print $2}' | sort -u                     # which ABIs
unzip -l target.apk | grep -E '^\s+[0-9]+.*assets/' | \
      sort -k1 -rn | head -20                            # biggest assets first
unzip -l target.apk | grep -E 'META-INF/.*\.version$' | wc -l
```

**What the numbers mean.** These are heuristics, and each has a reason:

| Observation | What it suggests | What to do |
|---|---|---|
| One `classes.dex`, under 1 MB, in a commercial app | The real code is elsewhere: a packer, or a cross-platform framework | Check `assets/` size and `lib/`; go to [40-Obfuscation](../40-Obfuscation/README.md) §3.7 |
| `assets/index.android.bundle` | React Native — the logic is JavaScript, not DEX | The DEX sweep will be complete and useless; read the bundle |
| `assets/bin/Data/` or `libil2cpp.so` | Unity | `global-metadata.dat` holds the type names |
| `flutter_assets/` and `libflutter.so` | Flutter — Dart, AOT-compiled into the `.so` | Neither jadx nor grep will help; this is a native-analysis job |
| Twelve `classes*.dex` files | An ordinary large app | Nothing special, but remember each DEX has its own string table |
| A large, high-entropy `.bin`/`.dat`/`.jar` in `assets/` | Possibly an encrypted payload | Entropy alone proves nothing — see the warning below |

> **⚠️ Warning**
> **High entropy is not evidence of encryption.** Compressed data, PNGs, ZIPs, ML model weights and
> font atlases are all high entropy. The signal is *entropy plus context*: a high-entropy asset
> **plus** an unusually small DEX **plus** an `<application android:name>` you do not recognise
> **plus** a `System.loadLibrary` in that class. Any one of those alone is nothing.
> [11-Android-Runtime](../11-Android-Runtime/README.md)'s lab on dynamic DEX loading points at this
> chapter for exactly this reason.

**How this stage fails.** By being skipped. People decompile first and discover an hour later that
the app is Flutter.

### 3.3 Stage 3 — Decompile

**What.** Produce something you can read and search.

**Why more than one tool.** Because they lose different things.

| Tool | Produces | Loses |
|---|---|---|
| `jadx` | Java-like source, readable, greppable | Correctness under stress: obfuscated or unusual bytecode may decompile wrongly or not at all. Records errors — read them |
| `apktool` | Smali plus fully decoded resources | Readability. Smali is verbose and slow to read |
| `baksmali` | Smali only | Resources, manifest |
| `aapt2 dump` | The platform's own parse of the manifest and resources | Code |
| DEX string table | Every literal the app declared, exactly | Where each one is used |

The practical rule: **jadx to understand, Smali to be certain, `aapt2` to check what the platform
sees.** A finding that rests on a subtlety of control flow should be confirmed in Smali, because
Smali is a transliteration of the bytecode and cannot be wrong about it, while decompiled Java is a
reconstruction and can be.

```bash
# host — the three views, produced once
jadx -d out target.apk                       # readable
apktool d -f target.apk -o work              # smali + resources
aapt2 dump xmltree --file AndroidManifest.xml target.apk > manifest-aapt2.txt
python3 -B ../04-Java/scripts/dump-strings.py target.apk --min-len 8 > strings.txt
```

> **🔬 Under the Hood**
> jadx is a native launcher on Windows, and on this machine `jadx` on `PATH` was the GUI binary: it
> detached, printed four log lines, exited 0, and produced no output directory. The CLI lives inside
> the shipped jar. If a decompile "succeeds" instantly and produces nothing, that is what happened:
>
> ```bash
> # host — Git Bash on Windows, when the CLI wrapper is missing
> java -Xmx6g -cp "/c/Program Files/jadx/lib/jadx-gui-1.5.3-all.jar" \
>      jadx.cli.JadxCLI -d out target.apk
> ```
>
> Measured on the 5.8 MB test app: 1 minute 57 seconds, 2,783 classes,
> `finished with errors, count: 17`.

**How this stage fails.**

- **Silently succeeding.** As above.
- **Out of memory.** Large apps need `-Xmx`. jadx will otherwise take a very long time and then die.
- **Being trusted.** See §6.2.

**When you can skip it.** When the question is about literals only — endpoints, keys, SQL — the DEX
string table answers faster and more accurately than any decompiler. See
[04-Java](../04-Java/README.md) §3.2.

### 3.4 Stage 4 — Enumerate

**What.** Build the lists. Not findings — lists. There are four, and they are the skeleton of the
report's appendix.

| List | Produced by | Owned by |
|---|---|---|
| Components and entry points | `aapt2 dump xmltree`, apktool manifest | [32-Manifest](../32-Manifest/README.md) |
| Classes and package prefixes | `baksmali list classes`, `dexdump -f`, jadx tree | [17-Libraries](../17-Libraries/README.md) |
| Libraries with versions | `META-INF/*.version`, class prefixes, `.so` banners | [17-Libraries](../17-Libraries/README.md) |
| Endpoints, keys, storage calls | the sweep, §8 | this chapter |

**Why enumeration comes before the sweep.** Because the sweep's results are meaningless without it.
"This app uses `MODE_WORLD_READABLE`" means one thing if the call is in the app's own code and
another entirely if it is in a vendored copy of a 2013 library. You cannot tell those apart until you
know which packages are the app's.

That single distinction is the highest-value input to triage, and here is what it is worth,
measured. On the 5.8 MB test app, the word `password` appears **137 times** across the decompiled
tree. Grouped by package:

```
      4  com/google/android/...
      3  androidx/core/view/...
      1  com/mobilehackinglab/FridaThree/   <- R.java, a resource identifier
      1  androidx/emoji2/viewsintegration/
      1  androidx/customview/widget/
      1  androidx/core/widget/
      1  androidx/appcompat/widget/
```

Every single one is framework code or generated code. The app's own hand-written classes contain the
word zero times. A tester who greps for `password` and reads 137 results learns nothing in twenty
minutes; a tester who classifies first reads one line and moves on.

**The entry-point list deserves special attention** because it is the only reachability anchor static
analysis gets for free. The classes the *platform* can start — activities, services, receivers,
providers, the `Application` — are named in the manifest, and every other class is reached from one
of them, or by reflection, or not at all.

```bash
# host — entry points, and only entry points. <action> and <meta-data> also
# carry android:name and are NOT entry points; a naive grep collects them and
# then android.intent.action.MAIN looks like a class.
awk '
  /<(intent-filter|meta-data|action|category|data|uses-permission)[ \t>\/]/ { t=0 }
  /<(activity|activity-alias|service|receiver|provider|application)([ \t>\/]|$)/ { t=1 }
  t && match($0, /android:name="[^"]+"/) {
      print substr($0, RSTART+14, RLENGTH-15); t=0
  }' work/AndroidManifest.xml | sort -u
```

### 3.5 Stage 5 — Sweep

**What.** Apply the rule catalogue (§8) to the decompiled tree and collect hits.

**Why it is stage five and not stage one.** Because a hit that you cannot place is not information.
Running the catalogue before enumeration produces the same output but you cannot rank it.

**What a rule actually is.** Three things, and conflating them is why scanners have bad reputations:

| Rule class | Example | Base precision | What a hit means |
|---|---|---|---|
| **Format** | `AKIA[0-9A-Z]{16}`, `-----BEGIN PRIVATE KEY-----` | High | This *is* the thing. The remaining questions are scope and reachability |
| **API** | `Cipher.getInstance("AES/ECB/…")`, `addJavascriptInterface(` | Medium | This construct exists. Whether it is dangerous depends on its arguments and its callers |
| **Shape** | a 32-character base64 blob, a 40-character hex run | Low | Something has the right silhouette. Most of these are wrong |
| **Keyword** | the word `password` | Very low | Someone typed a word |

A scanner that presents all four at the same severity is the reason nobody reads scanner output.
`static-sweep.py` assigns each rule a precision, prints it, and lets you argue with it.

**How this stage fails.** By producing a number so large that the human gives up. That is not a
failure of the sweep; it is a failure to have a stage six.

### 3.6 Stage 6 — Triage

**What.** Convert hits into **leads**, rank them, and attach a next step to each.

> **📖 Definition**
> A **hit** is one match on one line of one file. A **lead** is one distinct value or construct,
> with every site it appears at attached to it. The distinction is the whole of triage.

Measured, on the two applications used in this chapter:

| Tree | Files | Raw hits | Killed by validators | Distinct leads | Ratio |
|---|---|---|---|---|---|
| `com.mobilehackinglab.FridaThree` (5.8 MB training app) | 3,655 | 7,346 | 3,591 | **9** | 816 : 1 |
| A 17 MB commercial app, `--files app` | 13,050 | 6,883 | 4,375 | **96** | 72 : 1 |
| The same commercial app, whole tree | 20,091 | 16,836 | 13,220 | **168** | 100 : 1 |

Seven thousand hits is not a report. Nine leads is a morning's work. The three mechanisms that
produce that collapse are worth understanding because you will implement them yourself sooner or
later:

**1. Aggregation by identity.** A construct rule's identity is the construct, not the matched text.
Forty `Log.d` calls are one lead with forty sites. A value rule's identity is the value, so the same
API key in six files is one lead.

**2. Validators.** A regex says "this has the right shape"; a validator says "and it is not the
thousand things that share that shape". Two measured examples from building the tool for this
chapter:

- The base64 rule matched `actionModeCloseContentDescription` — 33 characters of pure letters, a
  resource identifier — and 90 similar names. Requiring character variety, a length that is a
  multiple of four, and a successful `b64decode` removed all of them.
- The non-production-hostname rule matched `kotlin.jvm.internal.Intrinsics`,
  `androidx.core.internal.view.menu` and `Debug.common.kt` — **75 spurious leads** — because a Java
  package name and a hostname are both dotted lowercase labels. Requiring a plausible TLD and
  rejecting capitalised labels removed all of them.

Across the small test app, validators rejected **3,591 of 7,346 raw hits (49%)** before a human saw
anything. That is not the tool hiding evidence; every rejection is countable and the rule's plain
grep is printed so you can check it by hand.

**3. Scope weighting.** A hit in `androidx/` is worth less than the same hit in the app's own
package. Not zero — a library the app ships is the app's responsibility — but less, and it belongs in
a different section of the report.

**The output of triage is a queue, and every item in it carries a next step.** Not a verdict. The
next step is the specific command or observation that will settle the question. A lead with no next
step is a lead nobody will ever work.

### 3.7 Stage 7 — Validate

**This is the chapter.** Everything before it is preparation; everything after it is writing.

**What.** For each lead, gather the evidence that would confirm it *and* the evidence that would kill
it, and record which happened.

**Why it is a separate, named stage.** Because when it is not a named stage it does not happen. The
economics are hostile: confirming a lead is slow and produces one line in a report, while pasting the
scanner output is instant and produces forty. The only defence is to make validation a stage with a
deliverable — the ledger — so that its absence is visible.

**The four questions.** A lead becomes a finding when all four have answers:

| # | Question | How you answer it | If the answer is "no" |
|---|---|---|---|
| 1 | **Is the construct really there?** | Read the code, not the grep. Read Smali if the semantics matter | Reject: rule artefact |
| 2 | **Is it reachable?** | Caller closure to an entry point; or a runtime hook that fires | Reject or downgrade: dead code |
| 3 | **Who can reach it?** | Exported component? network input? only the app itself? | Downgrade: self-reachable only |
| 4 | **What does reaching it get them?** | The asset behind it. **This is the severity** | Downgrade: no asset |

**Reachability, honestly.** There is no complete static reachability answer on Android, and anyone
who tells you otherwise is selling something. What you can build cheaply is a **caller closure**:
start at the class holding the lead, find every class that names it, then every class that names
those, until you meet a class the manifest declares.

`validate-lead.sh --reach` does exactly this, and its output is deliberately hedged, because the
method has four holes big enough to drive a finding through:

```
depth 1: 1 new referencing class(es)
depth 2: 2 new referencing class(es)
depth 3: 14 new referencing class(es)
depth 4: 6 new referencing class(es)
depth 5: 540 new referencing class(es)

FRONTIER EXPLODED (540 classes at depth 5).
```

That explosion is real output from this chapter's tooling and it is the honest answer. Past a few
hundred classes the closure has reached the framework, where everything names everything, and any
"reachable" verdict from there is an artefact of the method rather than a fact about the app.

The four holes:

1. **Reflection.** `Class.forName("com.x.Y").getMethod("z").invoke(...)` creates no textual edge.
2. **Dependency injection.** Dagger, Hilt and Koin wire by *type*, and the generated factory may not
   name your class in a form your grep matches.
3. **Service loading.** `META-INF/services/` entries are strings in a resource file.
4. **Framework callbacks and native code.** A lambda handed to the framework, or a method bound with
   `RegisterNatives`, is called from somewhere your tree does not contain.

> **⚠️ Warning**
> Never write "unreachable" in a report on the strength of a static closure. Write **"no static path
> found"**, list the four holes you checked, and — if it matters to the severity — settle it
> dynamically with a hook that either fires or does not.

**The best case.** Sometimes reachability is not a question at all. When the class holding the lead
is *itself* declared in the manifest, the platform can start it directly and the closure is
unnecessary:

```
DEPTH 0: the holding class is ITSELF declared in the manifest:
    com.mobilehackinglab.FridaThree.MainActivity
```

That is a stronger result than any closure could produce, it costs one grep, and it is why
`validate-lead.sh` checks it before doing anything expensive.

**The kill list.** Validation means *trying to refute*. Eight questions, in the order that kills the
most leads soonest:

1. Is it in the app's own code, or in a library?
2. Is the value a value, or a **name**?
3. Does it decode to something meaningful?
4. Is the code dead, or behind `BuildConfig.DEBUG`?
5. Did you analyse the **shipped** artefact?
6. Is the mechanism actually dangerous *here*? (Some keys are designed to ship.)
7. Does the control you think is missing exist somewhere else?
8. Would the client's own logs or console corroborate it?

**How this stage fails.** It fails by being performed only on the leads you already believe. Working
the queue top-down, including the ones you expect to reject, is what produces the rejection reasons
that make a report credible.

### 3.8 Stage 8 — Report

Owned by [80-Appendix](../80-Appendix/README.md), which holds the template and the severity rubric.
Three things this chapter insists on adding:

- **The artefact hash**, so the finding is re-checkable.
- **The ledger of rejected leads with reasons.** A report that shows only what survived looks like
  luck. A report that shows 96 leads worked down to 4 findings, with a reason against each rejection,
  looks like a method.
- **The blind-spot statement.** In its own section, not a footnote. See §5.3.

### 3.9 Stage 0 — The blind spots, stated plainly

This subsection exists early and in full because a tester who does not know it will report a clean
sweep as a clean application.

| Blind spot | Why static cannot see it | Measured scale | Where it is handled |
|---|---|---|---|
| **Runtime-registered receivers** | `registerReceiver()` takes an `IntentFilter` built at runtime; nothing is written to the manifest | **299 of 431 distinct broadcast actions (69%)** registered by third-party processes on the test device had *no* manifest-declared receiver anywhere — [29-BroadcastReceivers](../29-BroadcastReceivers/README.md) | `dumpsys activity broadcasts` on a live device |
| **`RegisterNatives` bindings** | The mapping from Java method to native function is built inside `JNI_OnLoad`; no `Java_`-prefixed symbol exists | Universal in any library that wants to hide | [16-JNI](../16-JNI/README.md); hook `RegisterNatives` |
| **Reflection** | Target chosen by string at runtime | Present in essentially every app, mostly benign | Hook `Method.invoke` |
| **Dynamically loaded DEX** | The code is not in the artefact | Rare, and almost always the most severe row when present | [40-Obfuscation](../40-Obfuscation/README.md) §3.7.3 |
| **Server-side behaviour** | It is not on the device at all | Every remote-config flag can turn a control off after you finish testing | Ask for the flag inventory; test both values |
| **Anything behind a feature flag** | The branch exists but you cannot know which side runs | — | Same |

Two of those deserve emphasis because they invert intuitions.

**The broadcast number is not a curiosity, it is the norm.** Chapter 29 got it by parsing the live
registration table out of ActivityManagerService and subtracting
`cmd package query-receivers`. `query-receivers` returns "No receivers found" for
`VOLUME_CHANGED_ACTION` while AMS shows six live registrations. **Every APK-based tool, including
this repository's own manifest scanners and this chapter's sweeper, is blind to the majority of the
broadcast surface.** The counts are timestamped rather than stable: three snapshots of the same idle
device gave 1,151 / 1,281 / 1,290 registrations.

**A native method with no `Java_` symbol is not missing.** It is registered. Finding `JNI_OnLoad` in
a `.so`'s dynamic symbol table and no `Java_*` symbols at all is the signature, and
`17-Libraries/scripts/lib-inventory.sh` prints exactly that warning when it sees it.

> **🧠 Mental Model**
> Static analysis draws the map. Dynamic analysis drives the roads. The map shows roads nobody drives
> and — this is the part people forget — **the driver keeps finding roads the map does not have**,
> because on Android roads are built at runtime.

### 3.10 The confidence model, worked

A confidence number you cannot reconstruct is a number you will either believe blindly or ignore
entirely, and both are worse than no number. So the model is deliberately small enough to do in your
head, and the tool prints every term.

**Base, from the rule's precision class:**

| Class | Base | Reasoning |
|---|---|---|
| `format` | 0.75 | An unambiguous format. `AKIA…` is an AWS key id or nothing |
| `api` | 0.55 | A specific call. Real, but its meaning depends on arguments |
| `shape` | 0.30 | The right silhouette. Most are wrong |
| `keyword` | 0.15 | Someone typed a word |

**Modifiers:**

| Condition | Delta | Reasoning |
|---|---|---|
| Site in the app's own package | +0.25 | The dominant signal, by a distance |
| Package not recognised as a known library | +0.05 | Half of a real tree; could be vendored app code |
| Site only in third-party packages | −0.30 | A library's behaviour, reported in the library's section |
| Site only in generated code (`R`, `BuildConfig`, `*Binding`) | −0.35 | Generated code contains no developer decisions |
| Site only in resources | −0.10 | Real, but a different kind of evidence |
| Value appears in more than 8 distinct files | −0.25 | A constant that widespread is a shared constant |
| Single site, in app code | +0.10 | A one-off literal in the app's own code is what you are hunting |
| Construct rule with at least one app-code site | +0.10 | For rules aggregated by construct rather than value |
| Construct rule with no app-code site | −0.15 | Library behaviour until shown otherwise |
| Value on the known-noise list | −0.45 | Namespaces, framework hosts, loopback, placeholder words |
| The same file also does crypto / networking / sets headers | +0.10 | Weak corroboration, weighted like one |

Clamp to `[0.05, 0.95]`, then band: **HIGH ≥ 0.65**, **MEDIUM ≥ 0.40**, **LOW** below that.

**Three real leads, with the arithmetic:**

```
L001  [HIGH 0.90]  DBG-01  android:debuggable="true"
      0.55 (api) + 0.25 (app package) + 0.10 (single site, app code)  = 0.90

L002  [HIGH 0.65]  CRED-09  TUhMe01PRElGSUVEX1ZBUklBQkxFfQ==
      0.30 (shape) + 0.25 (app package) + 0.10 (single site, app code) = 0.65

L003  [LOW  0.30]  NET-01  http://schemas.android.com/apk/res/android
      0.75 (format) + 0.25 (app package: it is in the manifest)
                    - 0.25 (627 distinct files) - 0.45 (known noise)   = 0.30
```

That third one is worth staring at. A **format**-class rule — the class you are supposed to act on —
fired on a value in the app's own manifest, and the model still pushed it to LOW, because two
independent signals said "shared constant" and "known noise". It was also demoted, so it only
appears at all under `--show-suppressed`.

The same lead scored **0.45 (MEDIUM)** in an earlier build of this tool, when the noise penalty was
−0.30 rather than −0.45. The number moved because the model was wrong, and it was possible to *see*
that it was wrong because the terms are printed. A single opaque score would have moved silently.

> **🔬 Under the Hood**
> These weights are **judgements, not measurements**, and this section says so rather than dressing
> them up. They were tuned against two real trees until the ordering matched what a human triager
> did by hand. Tune yours against your own corpus. What must not change is that the terms are
> printed: a scoring model you cannot audit will eventually rank a documentation URL above a
> credential and nobody will notice.

**Two things the model deliberately refuses to do:**

- **It never outputs severity.** Confidence answers "is this worth ten minutes"; severity answers
  "how bad is this". The second needs the asset, and no tool reading files knows the asset.
- **It never hides anything permanently.** Demoted leads are counted, and `--show-suppressed` prints
  them with the reason. A filter you cannot inspect will one day eat your finding silently.

### 3.11 The other half of a real tree: what to do with "unknown"

On the 20,091-file commercial application in §9.4, the package classifier produced:

```
      app            2210     (the package the manifest names)
      third-party    6967     (androidx, kotlin, okhttp, gms, ...)
      generated      74
      unknown        10840    (54%)
```

**More than half the tree is neither obviously the app nor obviously a library.** That is not a
defect in the classifier; it is what a modern APK contains. Four things land in "unknown", and they
need four different responses:

| What it is | How to recognise it | Response |
|---|---|---|
| **A vendored SDK** with its own top-level package | `io.<vendor>.`, `com.<vendor>.sdk.`, a coherent package tree with its own resources | Identify the vendor and treat it as a dependency — [17-Libraries](../17-Libraries/README.md) |
| **A shaded dependency** relocated by the build | `com.app.shaded.okhttp3.`, or a familiar class layout under an unfamiliar root | Same, but the version fingerprint has to come from class shape rather than a stamp |
| **R8 output** — synthetic and merged classes | `$$ExternalSyntheticLambda`, single-letter package roots, classes with no package at all | Ignore for classification; they belong to whatever produced them |
| **The app's own code under a second root** | The company owns two package prefixes, or an internal library shares the codebase | **Reclassify as app code**, and re-run |

The practical procedure takes ten minutes and is worth doing once per engagement:

```bash
# host — the top package roots in the unknown bucket, by file count
find out/sources -name '*.java' | sed 's#^out/sources/##' \
  | awk -F/ 'NF>=3 {print $1"/"$2"/"$3}' | sort | uniq -c | sort -rn | head -40
```

Then, for each root you do not recognise, one question: **is this the app's code, a third party's
code, or the compiler's?** Answer it by opening one file. If it is the app's, add the prefix:

```bash
# host — a second app prefix changes the score of every lead beneath it
python3 -B scripts/static-sweep.py ./out --app-package com.vendor.hrapp
grep -rn 'package com.vendor.internal' out/sources/ | head -3   # found a second root
```

> **🔍 Pentester's Note**
> This is the highest-leverage ten minutes in the whole pipeline on a large app, and almost nobody
> spends it. Every lead in an unrecognised app-owned package is currently scoring `+0.05` when it
> should be scoring `+0.25`, which is the difference between LOW and MEDIUM — and MEDIUM is where the
> best lead in §9.4 turned out to be.

### 3.12 A time budget for the whole pipeline

The pipeline fails in practice by running out of day at stage 5. Here is a budget that does not, for
a single medium-sized application, assuming you have the artefact.

| Stage | Budget | What you have at the end |
|---|---|---|
| 1 Acquire | 10 min | Hashes, splits, signer, versions |
| 2 Unpack | 10 min | DEX count, ABIs, assets, framework identification |
| 3 Decompile | 5 min of your time, up to an hour of the machine's | Three views; start it and go to stage 4 on the manifest |
| 4 Enumerate | 30 min | Entry points, package classification, dependency inventory |
| 5 Sweep | 5 min of your time | The raw hit count |
| 6 Triage | 15 min | A ranked queue with a next step per lead |
| **7 Validate** | **the rest of the day** | Verdicts, with reasons, for every lead |
| 8 Report | 2 hours | Findings, ledger, limits section |

The shape of that table is the argument. Stages 1–6 are ninety minutes of largely mechanical work.
Stage 7 is the job. A methodology that spends its day in stages 3–5 and its last twenty minutes on
stage 7 produces a report that is 90% scanner output, and everyone downstream can tell.

**If you have half a day**, cut stage 4's dependency inventory (hand it to
`17-Libraries/scripts/lib-inventory.sh` and read the summary), sweep with `--files app`, and validate
only leads at 0.5 and above — but say in the report that you did exactly that.

---

## 4. Source Code Walkthrough (AOSP)

Static analysis is an act of **prediction**: you read a file and predict what the platform will do
with it. Every disagreement between your prediction and the platform's behaviour is a false positive
or a missed finding. So the code worth reading here is not a static-analysis tool's source — it is
the platform code that produces the ground truth you are trying to guess.

Four paths, each answering "why is my static reading wrong sometimes?".

### 4.1 The manifest: what the platform actually parses

**Path:** `frameworks/base/core/java/android/content/pm/parsing/ParsingPackageUtils.java`
(the modern parser, from API 30 onward) and the older
`frameworks/base/core/java/android/content/pm/PackageParser.java`.

The install path is, in outline:

```
PackageManagerService.installPackageLI
  -> ParsingPackageUtils.parsePackage(File, flags)
       -> parseMonolithicPackage / parseClusterPackage      (splits!)
            -> parseBaseApk(ApkLite, ...)
                 -> AssetManager.openXmlResourceParser("AndroidManifest.xml")
                 -> parseBaseApplication(...)
                      -> parseActivity / parseService / parseProvider
```

Three things in that flow change how you read a manifest.

**First, the parser reads *binary* XML through the resource system**, not text. The file inside the
APK is AXML: a string pool plus a tree of typed nodes. Your `apktool` output is a *rendering* of that
tree, and a rendering can differ from the parse. That is the mechanism behind every manifest-parser
divergence trick, and [32-Manifest](../32-Manifest/README.md) and
[10-APK-Internals](../10-APK-Internals/README.md) each ship a CTF built on a different variant of it.
The defence is cheap: read the manifest with `aapt2 dump xmltree` as well, because `aapt2` uses the
platform's own `androidfw` code.

**Second, `parseClusterPackage` is where splits are merged.** The manifest the platform ends up with
is the *base* manifest plus contributions from the splits, and the merged result is what
`dumpsys package` shows. If you read only `base.apk`'s manifest, you read an input, not the result.

**Third, defaults are computed here, not written in the file.** The most consequential is
`exported`. In `parseActivityOrAlias` the effective value is, in substance:

```java
// Sense of the AOSP logic, not a verbatim quote — read the file for the exact form.
boolean exported;
if (sa.hasValue(R.styleable.AndroidManifestActivity_exported)) {
    exported = sa.getBoolean(R.styleable.AndroidManifestActivity_exported, false);
} else {
    exported = activity.getIntents().size() > 0;   // an intent-filter implies exported
}
```

Which is why a component with an `<intent-filter>` and **no** `android:exported` attribute is
exported — and why, on `targetSdk` 31 and above, the platform refuses to install a package that
leaves it unspecified. A static tool that greps for `exported="true"` finds the explicit cases and
misses the implicit ones, which are the interesting ones. `32-Manifest` §8.2 ships the Python that
gets this right; do not re-implement it.

### 4.2 Binary XML: why two tools disagree about the same bytes

**Path:** `frameworks/base/libs/androidfw/ResourceTypes.cpp`, with the structures declared in
`frameworks/base/include/androidfw/ResourceTypes.h`.

`ResStringPool::setTo` and `ResXMLParser::next` are the functions that turn AXML bytes into events.
Two properties of that code matter to you:

- **Strings are read from a pool with an explicit style/flags word**, and the UTF-8 versus UTF-16
  distinction is a flag, not a guess. A crafted pool can be valid to the platform and confusing to a
  third-party re-implementation.
- **Attribute records have a declared size** (`attributeSize` in the header). The platform strides by
  the declared size; a re-implementation that assumes the standard stride reads a different set of
  attributes. `10-APK-Internals`' CTF is built on exactly that: a widened stride, deliberately chosen
  to be a different primitive from `32-Manifest`'s `rawValue`/`typedValue` trick.

> **🔬 Under the Hood**
> This is why "the manifest says X" is a weaker sentence than it looks. The strong sentence is
> "`aapt2 dump xmltree` and `apktool` agree that the manifest says X, and `dumpsys package` on a
> device confirms the platform applied it."

### 4.3 The DEX: what the runtime validates before your tool ever sees it

**Paths:** `art/libdexfile/dex/dex_file.cc`, `art/libdexfile/dex/dex_file_verifier.cc`,
`libcore/dalvik/src/main/java/dalvik/system/DexFile.java`, and `art/runtime/class_linker.cc`.

Two facts from this code shape static analysis:

**Header fields are claims.** `header->string_ids_size` and `string_ids_off` are numbers written by
whoever produced the file. `DexFileVerifier::CheckHeader` bounds-checks them; your tool must too.
`04-Java/scripts/dump-strings.py` rejects a table that runs past end-of-file with a message that
names the two likely causes, and warns when `header.file_size` disagrees with the actual size —
because trailing data after a DEX is a packer fingerprint, which `12-DEX-Internals` covers in depth.

**Strings are Modified UTF-8, not UTF-8.** `DexFile::StringDataByIdx` walks MUTF-8, in which U+0000
is encoded `C0 80` and astral characters are a CESU-8 surrogate pair. Python's `utf-8` codec rejects
both. A tool that decodes the string table with the wrong codec will silently mangle or drop exactly
the strings an obfuscator chose to be awkward.

**And the loading path is where the artefact stops being the program.**
`DexFile.openInMemoryDexFile` and `InMemoryDexClassLoader` let an app hand the runtime a
`ByteBuffer` that never touched the filesystem. From the moment that call executes, the code running
in the process is not code you have. `22-SELinux` measured why this became the standard packer
technique: app domains kept `execmem` but lost `file:execute_no_trans` and `file:execmod` on
`app_data_file`, so writing a `.so` and loading it stopped working while loading a DEX from memory
did not.

### 4.4 `RegisterNatives`: the blind spot, in source

**Path:** `art/runtime/jni/java_vm_ext.cc`, function `JavaVMExt::RegisterNatives`, reached from
`art/runtime/jni/jni_internal.cc`.

There are two ways a `native` Java method gets an implementation:

| Mechanism | What appears in the `.so` symbol table | Visible statically? |
|---|---|---|
| Name mangling | `Java_com_example_Foo_bar` | **Yes.** `readelf --dyn-syms` lists it, and the name gives you the Java class and method |
| `RegisterNatives` | Nothing. The mapping is a `JNINativeMethod[]` array passed at runtime, usually from `JNI_OnLoad` | **No** |

`ClassLinker::LinkCode` consults the registered map first and falls back to `dlsym` on the mangled
name. So an app that wants its native surface hidden simply registers it, and your `readelf` output
is empty of `Java_*` symbols while the app has twenty native methods.

This is the source of the blind spot in §3.9. It is also the reason
`17-Libraries/scripts/lib-inventory.sh` prints a specific warning when it sees `JNI_OnLoad` present
and no `Java_*` symbols: absence of the symbols is not absence of JNI.

### 4.5 Resources: why `strings.xml` values are the easiest secrets in the APK

**Paths:** `frameworks/base/libs/androidfw/ResourceTypes.cpp` (again — `ResTable` this time), and
`frameworks/base/tools/aapt2/` for the compiler that produces `resources.arsc`.

A string resource is not code. It is an entry in a typed table with an integer identifier, and three
consequences follow that people get wrong in both directions:

| Property | Consequence for you |
|---|---|
| R8 renames classes and methods, **not resource values** | A key in `strings.xml` survives obfuscation completely. "Enable obfuscation" is a wrong remediation for it |
| Resource *names* can be stripped by resource shrinking, values cannot | You may see `@string/0x7f110042` in a decoded manifest and still read the value from `resources.arsc` |
| The table is per-configuration | `aapt2 dump resources` prints **all** configurations, and a value can differ per locale or per density. A single-configuration read can miss one |

```bash
# host — read every configuration, not just the default
aapt2 dump resources target.apk | grep -A3 -i 'api_key\|token\|secret\|url' | head -40

# host — and the decoded form, which is easier to grep
grep -rniE 'key|token|secret|password|https?://' work/res/values*/strings.xml | head -40
```

The build path that puts secrets here is worth recognising because it is so common:

```kotlin
// build.gradle.kts -- this writes the value into res/values/strings.xml at build time
android {
    defaultConfig {
        resValue("string", "maps_api_key", providers.gradleProperty("MAPS_KEY").get())
    }
}
```

The developer's mental model is "the key is not in my source, it is in a Gradle property" — which is
true, and irrelevant, because the *artefact* contains it in plain text in a file named
`res/values/strings.xml`. This is the same trap as `manifestPlaceholders` in §8.7: **audit the built
artefact, use the source to explain it.**

### 4.6 R8's mapping file, and what "obfuscated" costs a static reading

**Path:** `external/r8` in AOSP; the mapping format is R8's own.

R8 renames, inlines, merges classes and rewrites control flow. For static analysis the consequences
are ordered by how much they hurt:

| R8 effect | Cost to static analysis |
|---|---|
| Class and method renaming | Names carry no meaning; grep for names stops working. Strings still work — which is why [40-Obfuscation](../40-Obfuscation/README.md) recovers strings *first* |
| Inlining | **A patched or audited method may be called by nobody.** `18-ARM` §5.4 measured exactly this: a check function patched to `return 1`, verified returning 1, and the caller still refused — because the compiler had inlined the check and the patched copy was dead |
| Class merging | Your "which class holds this" answer becomes "a class that used to be three classes" |
| Dead-code removal | Good for you: what is left is closer to what runs |
| `mapping.txt` | If the client gives you this, deobfuscation is free. **Ask.** Many teams will hand it over without hesitation and it converts a three-day job into a three-hour one |

Note the ordering: inlining hurts *reachability reasoning* far more than renaming hurts *reading*.
Renaming makes the code ugly; inlining makes your call graph wrong.

---

## 5. Security Perspective

### 5.1 What static analysis is genuinely good at

Not everything is a coin toss. These classes of finding are reliably and cheaply found statically,
and a review that misses them was not done:

| Finding class | Why static wins | Chapter that owns the detail |
|---|---|---|
| Shipped credentials and keys | The value is a literal in the artefact | this chapter, §8 |
| Debuggable / backup-enabled release builds | A manifest flag | [32-Manifest](../32-Manifest/README.md) |
| Cleartext traffic configuration | An XML file | [44-NetworkSecurityConfig](../44-NetworkSecurityConfig/README.md) |
| Weak or misused cryptography | A specific API with specific arguments | [34-Cryptography](../34-Cryptography/README.md) |
| Outdated dependencies with versions | Versions are stamped into the artefact | [17-Libraries](../17-Libraries/README.md) |
| Exported component inventory | The manifest is the definition | [32-Manifest](../32-Manifest/README.md) |
| Debug artefacts shipped to production | Test fixtures, staging hosts, preview data | this chapter, §9.4 |
| Signing weaknesses (debug key, v1-only) | The signature block is in the file | [10-APK-Internals](../10-APK-Internals/README.md) |

The last row has a concrete test worth memorising, because it is a genuine High and it is common:

```bash
# host — is this release build signed with the universally-known debug key?
apksigner verify -v --print-certs target.apk | grep -i "certificate DN"
# CN=Android Debug, O=Android, C=US   <- everyone has this private key
```

### 5.2 What it is bad at, and what to do instead

| Question | Static answer | Why it fails | Who answers it |
|---|---|---|---|
| "Is this token ever sent?" | You can see the field | You cannot see the request | Proxy, or a Frida hook |
| "Does this app pin?" | You can see a `TrustManager` | Presence is not behaviour | Attempt an intercept — see below |
| "Which receivers exist?" | The manifest's | 69% register at runtime | `dumpsys activity broadcasts` |
| "Is this code reachable?" | A closure that explodes | Reflection, DI, callbacks | A hook that fires or does not |
| "What does the server enforce?" | Nothing | It is not on the device | Test the API directly |
| "What does this obfuscated method do?" | Read 300 lines of flattened control flow | Expensive | Hook the boundary, tabulate input and output |

The pinning row is the one to internalise, and this repository has the number.
[36-CertificatePinning](../36-CertificatePinning/README.md) examined 14 real applications:
**12 of 14 presented a pinning surface — a `TrustManager`, a `CertificatePinner`, a
`<pin-set>` element — and only 4 actually pinned.** Seven of the fourteen had four or more distinct
layers of surface. A static review that reports "the app implements certificate pinning" because it
found `CertificatePinner` in the class list is wrong roughly two times in three.

> **🔍 Pentester's Note**
> The inverse error is just as common and more embarrassing: concluding "no pinning" from the absence
> of a `TrustManager`, when the pins are declared in `res/xml/network_security_config.xml`. Static
> analysis has to check every layer before it may make a negative claim, and the layers live in four
> different places. That is precisely why 36 is its own chapter and why this one only tells you to go
> read it.

### 5.3 The blind-spot statement belongs in the report

Every report this method produces contains a section that says, in the client's language, what was
not examined and why. A workable template:

```
SCOPE AND LIMITS OF STATIC ANALYSIS

This assessment examined the artefact base.apk (SHA-256 <hash>) plus 2 splits,
as pulled from a device on <date>. Static analysis of an APK cannot observe:

  - broadcast receivers registered at runtime. On a comparable device, 69% of
    the broadcast actions in use by third-party apps had no manifest-declared
    receiver at all. We enumerated the live registrations for this app in
    section <x> using dumpsys, which is the only reliable method.
  - native methods bound with RegisterNatives. The application's libX.so
    exports JNI_OnLoad and no Java_-prefixed symbols, which means its native
    surface is registered at runtime and is not enumerable from the file.
  - code loaded after installation. We found no evidence of runtime DEX
    loading; absence of evidence is recorded as such.
  - server-side behaviour and remote configuration. <N> feature flags were
    identified; we tested <M> of them in both states.

<N> leads were generated by automated sweeping. <M> were validated as
findings; the remaining <N-M> were rejected, with reasons, in Appendix B.
```

That last paragraph is the one clients remember, and the one that stops the next scanner-output
"report" from being taken seriously in the same room.

### 5.4 How developers create static findings

Not malice — process. The recurring causes, each with the fix:

| Cause | What it produces | Fix |
|---|---|---|
| A key needed at build time is put in a constant | A credential in the DEX | Inject at build; better, move the operation server-side |
| "We'll remove the debug flag before release" | `debuggable="true"` in production | Build-type configuration, plus a release-blocking lint rule |
| A staging URL kept "for convenience" | A non-production host in a production build | One `BuildConfig` field per flavour; fail the build if a QA host appears in a release |
| Compose `@Preview` and test fixtures compiled in | Sample URLs and fake data in the shipped APK | Keep previews in `debug` source sets; R8 rules |
| A library vendored years ago and forgotten | An outdated dependency with a known issue | Dependency locking plus an SBOM — MASVS-CODE |
| Obfuscation treated as a security control | A false sense of protection | It raises cost; it does not remove a secret |

The fourth row is not theoretical. On the 17 MB commercial application analysed for §9.4, **three of
the fifteen highest-confidence leads were URLs baked into Compose preview functions of a bundled SDK**
— `http://www.google.com/lol`, `http://test.com`, `http://external.source.com` — shipped inside
`ComposableSingletons$…` classes in the production APK. They are harmless, they are noise, and they
sit at the very top of a naive confidence ranking.

### 5.5 The four questions, as a rubric

Severity comes from question 4, never from question 1. Written out as a table you can put next to a
lead:

| | Not reachable | Reachable by the app only | Reachable by another app | Reachable from the network |
|---|---|---|---|---|
| **No asset behind it** | Informational | Informational | Informational | Low |
| **Device metadata** | Informational | Informational | Low | Low |
| **User data** | Informational | Low | Medium | High |
| **Credentials / financial** | Low | Medium | High | Critical |

Two rules that override the table, both learned the hard way in this repository:

- **A shipped key that the vendor designs to ship is not automatically a finding.** Google API keys,
  Firebase app IDs, Play Billing public keys, and translation-SDK project tokens are *client*
  credentials. The finding, when there is one, is "this key has no application restriction and this
  scope" — and you have to go and check the restriction before you write it.
- **A control that can be turned off remotely is capped at the strength of the remote control.** If
  a feature flag can disable pinning, the pinning finding is about the flag.

For the full severity rubric and the report template, see [80-Appendix](../80-Appendix/README.md).
This chapter does not restage them.

### 5.6 OWASP MASVS and MASTG mapping

| MASVS control | What static analysis contributes | This chapter's part |
|---|---|---|
| **MASVS-STORAGE** | Finds `MODE_WORLD_*`, external-storage writes, sensitive preference keys | The sweep; [33-Storage](../33-Storage/README.md) validates |
| **MASVS-CRYPTO** | Finds ECB, fixed IVs, seeded `SecureRandom`, weak KDF parameters | The sweep; [34-Cryptography](../34-Cryptography/README.md) rates |
| **MASVS-AUTH** | Finds hardcoded credentials and token handling | Validation decides whether it matters |
| **MASVS-NETWORK** | Finds cleartext URLs, custom trust managers, the NSC file | [44](../44-NetworkSecurityConfig/README.md), [35](../35-SSL/README.md), [36](../36-CertificatePinning/README.md) |
| **MASVS-PLATFORM** | Component inventory, deep links, WebView configuration | [32-Manifest](../32-Manifest/README.md), [43-WebView](../43-WebView/README.md) |
| **MASVS-CODE** | **Dependency inventory with versions**, debug artefact sweep, build configuration | [17-Libraries](../17-Libraries/README.md) produces the inventory; this chapter's pipeline is where it fits |
| **MASVS-RESILIENCE** | Detects the presence of anti-tamper and obfuscation | [40-Obfuscation](../40-Obfuscation/README.md), [37-RootDetection](../37-RootDetection/README.md) |

**MASVS-CODE deserves the emphasis it gets in [71-OWASP-Mobile](../71-OWASP-Mobile/README.md).** The
control asks for a dependency inventory *with versions*, and versions are the part people skip
because they are hard. An inventory that says "uses OkHttp" is not an inventory; one that says
"OkHttp 4.9.3, high confidence, from the `META-INF` version stamp corroborated by the class set" is.
`17-Libraries/scripts/lib-fingerprint.py` exists precisely to produce the second kind, and the
pipeline in §3 is where its output belongs: stage 4, feeding stage 6.

### 5.7 Four vulnerability classes this chapter owns, end to end

Other chapters own storage, crypto, TLS and IPC findings. These four are *static analysis's own*:
they exist because something was left in an artefact, they are found by reading files, and no other
chapter claims them. Each is given the repository's full treatment — vulnerable code, why developers
write it, static and dynamic detection, exploitation, the fix as code, and honest severity.

#### 5.7.1 A third-party credential shipped in the client

**Vulnerable code** (shape taken from the measured example in §9.4; value redacted):

```java
// app/src/main/java/com/vendor/hrapp/HrApplication.java
@Override
public void onCreate() {
    super.onCreate();
    Lokalise.init(this,
        "63601e3d…b610240",          // SDK project token
        "754340…72375444",           // project id
        LokaliseFallbackStrategy.WITH_BUNDLE_DEFAULT_LANGUAGE);
}
```

**Why developers write it.** The SDK's own quick-start prints exactly this. The token is required
before the first network call, there is no server round trip to fetch it from, and the vendor's
documentation does not say "this value is public". Nothing in the developer's day pushes back.

**Static detection.**

```bash
# host
grep -rnoE '"[0-9a-fA-F]{40,}"' out/sources/com/vendor/ | sort -u        # CRED-10
python3 -B scripts/static-sweep.py ./out --app-package com.vendor.hrapp --min-confidence 0.6
```

**Dynamic detection.** Proxy the app and watch the first request the SDK makes; the token appears as
a header or query parameter. That also answers the question static analysis cannot: *what the token
is actually used for.*

**Exploitation.** Extract the token from the APK — one `grep` — and call the vendor's API directly
with it, from anywhere. What that gets you depends entirely on scope. For a translation SDK it is
usually read access to the application's translation bundles: real, low-value, and occasionally
embarrassing because bundles can contain unreleased feature strings.

**Fix, as code.**

```kotlin
// The two-line version, when the vendor supports it: keep the token out of VCS
// and out of the source, but understand it is STILL in the artefact.
// build.gradle.kts
android {
    defaultConfig {
        buildConfigField("String", "LOKALISE_TOKEN",
            "\"${providers.gradleProperty("LOKALISE_TOKEN").get()}\"")
    }
}
```

```kotlin
// The version that actually removes the exposure: the client never holds the
// credential. It asks your backend, which holds it, and which can revoke,
// rate-limit and audit per user.
val bundle = api.fetchTranslationBundle(locale)     // your server calls the vendor
```

**Honest severity.** **Informational to Medium, and it depends on the token's scope.** Write it as:
"a `<vendor>` project token is embedded in the client. We confirmed the literal at
`HrApplication.onCreate`. Client-side embedding is the vendor's documented pattern, so the question
is scope: if this token permits only reading published translation bundles, the exposure is
Informational; if it permits writing them, an attacker can change every string the app displays,
which is a High." Then go and check, or ask the client to.

> **⚠️ Warning**
> Do not exercise a credential you found unless the engagement scope says in writing that you may.
> Reading a secret and using a secret are different authorisations, and the second one is where
> testers get into trouble.

#### 5.7.2 A debuggable release build

**Vulnerable code.**

```xml
<!-- AndroidManifest.xml, in the shipped artefact -->
<application
    android:debuggable="true"
    android:allowBackup="true"
    ...>
```

**Why developers write it.** Almost never deliberately. It arrives one of three ways: someone set it
in the main manifest to debug a release build and forgot; a library merged it in (the manifest merger
will happily take `debuggable` from a dependency); or the release was built from the debug variant by
a misconfigured CI job.

**Static detection.**

```bash
# host — check the SHIPPED artefact, not the source manifest
apktool d -f target.apk -o work
grep -n 'debuggable' work/AndroidManifest.xml
aapt2 dump xmltree --file AndroidManifest.xml target.apk | grep -i debuggable
```

**Dynamic detection — and this is the evidence:**

```bash
# adb shell
dumpsys package com.example.target | grep 'flags='
# flags=[ DEBUGGABLE HAS_CODE ALLOW_CLEAR_USER_DATA ALLOW_BACKUP ]
```

**Exploitation.**

```bash
# host — no root required
adb shell run-as com.example.target ls -la /data/data/com.example.target/shared_prefs
adb shell run-as com.example.target cat /data/data/com.example.target/shared_prefs/auth.xml

# and a JDWP attach exposes process memory and live objects
adb jdwp
```

`run-as` is the whole finding in one command: an attacker with ADB access reads the app's private
storage without root, which is exactly the boundary the sandbox exists to hold.

**Fix, as code.**

```kotlin
// build.gradle.kts — let the build type own it, and never write it in the manifest
android {
    buildTypes {
        debug   { isDebuggable = true }
        release { isDebuggable = false }
    }
    lint {
        // fail the build rather than warn: this is exactly the mistake a
        // warning does not prevent
        error += setOf("HardcodedDebugMode")
        abortOnError = true
    }
}
```

**Honest severity.** **High** for any app handling user data, **Critical** if the app is preinstalled
or holds financial credentials — but the impact sentence must name the precondition: *ADB access to
an unlocked device*. That precondition is real (lost devices, malicious chargers, shared kiosks,
enterprise fleets with USB debugging on) and stating it honestly makes the finding harder to argue
with, not easier.

#### 5.7.3 Internal environment disclosure

**Vulnerable code** (measured, §9.4; hostnames substituted):

```java
public enum Domain {
    PRODUCTION("app.vendor.example"),
    PRE_PROD("preprod.vendor-internal.biz"),
    QA8("qa8.qa.vendor-internal.biz"),
    QA7("qa7.qa.vendor-internal.biz"),
    // ... eight QA hosts and three staging hosts in total
}
```

**Why developers write it.** An in-app environment switcher is genuinely useful for QA, and an enum
is the natural way to write one. The switcher is usually hidden behind a debug gate — and the *enum*
is not, because the enum is just data and R8 keeps data that is referenced.

**Static detection.**

```bash
# host
grep -rnEi '(staging|preprod|uat|sandbox|qa)[0-9]*\.[a-z0-9-]+\.[a-z]{2,}' out/sources/com/vendor/
python3 -B scripts/static-sweep.py ./out --app-package com.vendor.hrapp | grep NET-04
```

Note that this is a **MEDIUM**-confidence rule and it produced the best lead in the whole run.

**Dynamic detection.** None, usually — the production build never contacts these hosts, so a proxy
log will never show them. **This is a finding only static analysis can produce**, which is worth
saying out loud in a chapter about the limits of static analysis.

**Exploitation.**

```bash
# host — the entire attack, and none of it touches the app
for h in preprod.vendor-internal.biz qa1.qa.vendor-internal.biz; do
    echo "== $h"; getent hosts "$h"; curl -sS -o /dev/null -w '%{http_code}\n' "https://$h/"
done
```

Non-production estates are routinely weaker: older builds, verbose errors, test accounts with
predictable passwords, no rate limiting, and sometimes a copy of production data. The APK just
handed you the target list.

**Fix, as code.**

```kotlin
// One host per build type. The QA enum lives in the debug source set and is
// not compiled into the release variant at all.
// src/release/java/com/vendor/hrapp/api/Environments.kt
object Environments { val base = "https://app.vendor.example" }

// src/debug/java/com/vendor/hrapp/api/Environments.kt
object Environments {
    val base get() = DebugPrefs.selectedHost ?: "https://qa1.qa.vendor-internal.biz"
}
```

```kotlin
// and a release gate, because source sets are easy to bypass by accident
tasks.register("failOnQaHosts") {
    doLast {
        val bad = Regex("""(qa\d|preprod|staging)\.[a-z0-9-]+\.[a-z]{2,}""")
        // scan the merged resources and the release DEX mapping output
    }
}
```

**Honest severity.** **Low to Medium on its own** — it is information disclosure, not access. It
becomes **High** the moment one of the hosts is reachable from the internet and authenticates
weakly, and that is a five-minute check you should do before writing the severity rather than after.

#### 5.7.4 Test fixtures and preview data shipped in the release build

**Vulnerable code.**

```kotlin
@Preview
@Composable
fun MessageRowPreview() {
    MessageRow(
        avatarUrl = "http://www.google.com/lol",
        author = "Test User",
        body = "http://test.com",
        token = "test-bearer-abc123"
    )
}
```

**Why developers write it.** Compose previews live next to the composable they preview — that is the
whole point of the feature. `@Preview` functions are annotated, referenced by the tooling, and
survive into the release variant unless the project deliberately keeps them in a `debug` source set.
The same happens with JUnit fixtures pulled in by a shared module.

**Static detection.**

```bash
# host — preview and fixture data has a recognisable home
grep -rln 'ComposableSingletons' out/sources/ | head
grep -rnE '"(test|example|foo|bar|dummy|sample)[^"]*"' out/sources/com/vendor/ | head -40
```

Measured: three of the fifteen highest-confidence leads on the commercial app in §9.4 were URLs
inside `ComposableSingletons$…` classes belonging to a bundled SDK.

**Exploitation.** Usually none — and that is the point of including this class here. **The impact of
most preview data is zero, and its impact on your report is large**, because it sits at the top of a
confidence ranking and consumes the first hour of triage. Occasionally, though, a fixture contains a
real test credential for a real staging system, and then it is §5.7.1 with worse hygiene.

**Fix, as code.**

```kotlin
// Keep previews out of the release variant entirely.
// src/debug/java/com/vendor/hrapp/ui/MessageRowPreviews.kt   <- moved here
```

```proguard
# and, for previews you cannot move, let R8 remove them
-assumenosideeffects class androidx.compose.ui.tooling.preview.** { *; }
```

**Honest severity.** **Informational**, and often not worth a finding at all — one line in the
observations section. Report it when the fixture contains a credential, an internal hostname, or
personal data; otherwise note it and move on. A report that lists seven preview URLs as findings has
told the client that the tester cannot distinguish signal from noise.

### 5.8 Bug bounty: how your static report gets triaged

Worth knowing from the other side, because a bounty programme's triage is the kill list from §3.7
applied to *you*, usually in under five minutes.

| What the triager checks | What kills a submission |
|---|---|
| Is it in the app's own code? | "This is in okhttp / AndroidX / the Facebook SDK" — closed as not-applicable, and it is the single most common closure |
| Is the credential a *client* credential? | Google API keys, Firebase app IDs, Play Billing public keys, Mapbox public tokens — closed as by-design unless you show a missing restriction |
| Did you demonstrate impact? | "A string exists in the APK" with no demonstration — closed as informative |
| Is it reachable? | Debug-only code, dead compatibility branches, unreferenced classes — closed as not-applicable |
| Is it already known? | The same string has been reported eleven times — closed as duplicate |
| Did you test the shipped build? | A finding derived from a debug APK you built — closed, and it damages your reputation on the programme |

**The three submissions that consistently pay from a static pass**, in the order they are worth
looking for:

1. **A server-side secret in a client** — `sk_live_`, an AWS secret access key next to its id, a
   database connection string, a private key. Unambiguous, high impact, hard to argue with.
2. **An exported component that reaches a sink with attacker-controlled input** — the §8.5 loop.
   This is the finding class that produces the highest median payout, because it is a real attack
   with a real demonstration.
3. **A debuggable or debug-signed release build.** Rare, embarrassing, and instantly verifiable with
   `dumpsys package | grep flags=`.

**The three that consistently waste everyone's time:**

1. Client API keys reported as "hardcoded credentials" with no scope analysis.
2. Cleartext URLs that are namespaces, documentation links or preview fixtures — measured at 13 of
   17 high-confidence leads on a real app in §9.4.
3. "No obfuscation / no root detection / no pinning" reported as vulnerabilities. They are
   observations about missing hardening, and most programmes say so in their policy.

> **🔍 Pentester's Note**
> Before submitting anything from a static pass, run your own kill list against it and put the
> answers *in the submission*. "This is in the app's own package (`com/vendor/pay/`), reachable from
> the exported `CheckoutActivity`, and here is the request it signs" converts a five-minute triage
> into a five-second acceptance.

### 5.9 How malware analysts and forensic examiners use the same pipeline

The stages are identical; the emphasis moves.

- **Malware.** Stage 2 dominates. Packing is the norm, so the first question is "is the code even
  here", and stage 3 often has to wait for a dynamic unpack. The blind-spot list becomes the
  *analysis plan* rather than a caveat. [69-MalwareAnalysis](../69-MalwareAnalysis/) will cover this.
- **Forensics.** Stage 1 dominates: chain of custody, hashes, and the fact that the artefact is
  evidence. Findings must be reproducible from the recorded hash by a third party who was not there.
- **Bug bounty.** Stage 7 dominates, because an unvalidated report is a closed report. The kill list
  in §3.7 is, almost verbatim, the triage a good bounty programme applies to your submission before
  a human reads it.

---

## 6. Reverse Engineering Perspective

### 6.1 One lead, four views

Take a single real lead: a base64 literal in a training application, recovered by the sweep at
confidence 0.65. Here is the *same* fact as each tool presents it.

**View 1 — jadx (readable, reconstructed):**

```java
// out/sources/com/mobilehackinglab/FridaThree/MainActivity.java:50
public static final void onCreate$lambda$0(MainActivity this$0, View it) {
    Intrinsics.checkNotNullParameter(this$0, "this$0");
    if (Checker.INSTANCE.getCode() == 256) {
        Toast.makeText(this$0, "Congrats you got the flag", 1).show();
        byte[] bArrDecode = Base64.getDecoder().decode("TUhMe01PRElGSUVEX1ZBUklBQkxFfQ==");
        ...
```

**View 2 — the DEX string table (exact, positionless):**

```bash
# host
python3 -B ../04-Java/scripts/dump-strings.py target.apk --min-len 16 | grep TUhM
#   [    43]  TUhMe01PRElGSUVEX1ZBUklBQkxFfQ==
```

The index `43` is the number you use to find every `const-string` that loads it.

**View 3 — Dalvik bytecode (authoritative):**

```
# host: dexdump -d classes3.dex   (build-tools; real output, trimmed)
0005a6: 1301 0001   |000b: const/16 v1, #int 256 // #100
0005ac: 3310 4800   |000e: if-ne v0, v1, 0056 // +0048
0005ce: 1a00 2b00   |001f: const-string v0, "TUhMe01PRElGSUVEX1ZBUklBQkxFfQ==" // string@002b
0005d2: 7100 1700   |0021: invoke-static {}, Ljava/util/Base64;.getDecoder:()Ljava/util/Base64$Decoder;
0005da: 6e20 1600   |0025: invoke-virtual {v1, v0}, Ljava/util/Base64$Decoder;.decode:(Ljava/lang/String;)[B
```

`string@002b` is 43 in hexadecimal — the same index the string table gave you. That correspondence
is what lets you correlate a string dump back to code at scale, and it is the basis of
`40-Obfuscation/scripts/annotate-smali-strings.py`.

**View 4 — the platform (`dumpsys`, on a device):**

```
flags=[ DEBUGGABLE HAS_CODE ALLOW_CLEAR_USER_DATA ALLOW_BACKUP ]
```

Not about this string at all — but the same command, in the same minute, converted a *different*
lead from "the manifest claims" into "the platform enforces".

> **🧠 Mental Model**
> jadx tells you what the code *means*. dexdump tells you what the code *is*. The string table tells
> you what the code *contains*. `dumpsys` tells you what the platform *did*. Reach for the cheapest
> one that can settle your question, and reach for the authoritative one before you write it down.

### 6.2 How decompilers fail, and what that costs you

jadx 1.5.3 on the 5.8 MB test app: 2,783 classes, 1 minute 57 seconds,
`finished with errors, count: 17`. Those seventeen classes still produced `.java` files.

| Failure mode | What you see | What to do |
|---|---|---|
| Reports an error, writes partial output | `// JADX WARN`, `/* JADX INFO */`, truncated methods | Read the Smali for that class. Never quote partial output in a report |
| Silently produces wrong control flow | Plausible Java that does not match the bytecode | Confirm anything load-bearing in Smali |
| Renames to avoid collisions | `p001a.b.c` | Cosmetic |
| Fails to resolve a lambda | `$$ExternalSyntheticLambda0` classes | Follow the synthetic class; the body is in the outer class as `onCreate$lambda$0` |
| Fabricates locals | `bArrDecode`, `viewFindViewById2` | Harmless, and a useful tell that you are reading jadx output rather than source |

The last row is worth a note in a report's methodology section: names like `bArrDecode` are jadx's
invention, not the developer's. Quoting them as if they were the app's identifiers is a small
credibility leak that reviewers notice.

> **⚠️ Warning**
> `jadx --show-bad-code` (or `-f`) will emit output for classes it could not decompile properly. It
> is useful for orientation and dangerous in evidence. If a finding depends on a method jadx flagged,
> the evidence is the Smali.

### 6.3 What obfuscation does to each rule class

Obfuscation does not degrade the sweep uniformly. Knowing which rules survive tells you what to run
first on a protected app.

| Rule class | Effect of R8 renaming | Effect of string encryption | Effect of packing |
|---|---|---|---|
| **Format** (PEM header, `AKIA…`) | None — the value is data | **Destroyed** — the literal is gone | Destroyed until unpacked |
| **API** (`Cipher.getInstance`) | Little — framework names cannot be renamed | None | Destroyed until unpacked |
| **Shape** (base64, hex) | None | Changes shape; a decryptor call replaces it | Destroyed |
| **Keyword** (`password`) | Field and method names go; **string literals stay** | Destroyed | Destroyed |
| **Manifest facts** | **None at all** | None | None |

Three consequences follow, and they are the practical reason to run the pipeline in the stated order:

1. **Framework API names are un-obfuscatable.** `Landroid/widget/Toast;.makeText` is a reference into
   `android.jar` and R8 cannot rename it. An app can be a wall of `a.b.c` and still yield a complete
   inventory of every `Cipher`, `WebView` and `SharedPreferences` call. Rule class "API" is your
   highest-yield catalogue on an obfuscated target.
2. **The manifest survives everything.** Component names may be obfuscated, but authorities,
   permissions, actions and flags are resolved by the platform as strings and cannot be. That is why
   `17-Libraries` uses initialisation providers as an obfuscation-proof SDK inventory.
3. **No readable strings at all is itself a finding-shaped signal.** An app whose string table
   contains no URLs is either tiny or is building them at runtime, and the second case is where the
   interesting code is. `04-Java/scripts/dump-strings.py` says exactly this when its heuristics match
   nothing.

### 6.4 Reading Smali when the Java lies

You do not need to read Smali fluently. You need to read five constructs on sight, and this is the
whole list.

| Construct | Smali | What it tells you |
|---|---|---|
| A literal is loaded | `const-string vX, "…"` | The value is in the artefact, right there |
| A field is read | `sget-object` / `iget-object` | Static versus instance — and `sget` on a singleton is how Kotlin `object` compiles |
| A comparison | `if-ne v0, v1, :label` | The gate. Read the constant loaded into `v1` |
| A call | `invoke-virtual`, `invoke-static`, `invoke-direct` | The callee's full signature is on the line |
| A cast | `check-cast vX, LType;` | The compiler's proof of the static type |

Applied to the listing in §6.1: `const/16 v1, #int 256` then `if-ne v0, v1` is the entire security
logic of that screen, and it is legible in two lines of bytecode. The Java view says the same thing;
the bytecode view *cannot be wrong* about it.

### 6.5 Correlating strings back to code, at scale

The single technique that makes static analysis of a large or obfuscated app tractable: the DEX
string table gives you *what*, the bytecode gives you *where*, and the index joins them.

Recall from §6.1 that `dump-strings.py` reported the flag literal at index 43, and `dexdump` showed
`const-string v0, … // string@002b` — the same number in hexadecimal. That correspondence is
mechanical, so it can be automated:

```bash
# host — 1. every literal, with its index
python3 -B ../04-Java/scripts/dump-strings.py target.apk --min-len 8 > strings.txt

# host — 2. every const-string site, with the index it loads
dexdump -d classes3.dex | grep -oE 'const-string v[0-9]+, "[^"]*" // string@[0-9a-f]+' \
    | sed -E 's/.*\/\/ string@([0-9a-f]+)/\1/' | sort | uniq -c | sort -rn | head -20
```

Two uses, both high value:

**Use 1 — find the strings nobody loads.** A literal in the table that no `const-string` references
is either dead data or a string used only through reflection. On a lean app that set is small and
interesting.

**Use 2 — annotate an obfuscated method.** When names are gone, the string a method loads is the only
semantics left. A method `a()` containing `"/v2/payments/authorize"` is `postAuthorizePayment`, and
you can rename it in jadx-gui and persist the rename in a `.jobf` file next to the APK — commit that
file to your engagement notes so a colleague inherits your work.
[40-Obfuscation](../40-Obfuscation/README.md) §6.1 Phase 4 automates the whole substitution with
`annotate-smali-strings.py`; this chapter's contribution is only to tell you to do it **before**
control-flow work, because "what" is what you are being paid to find out and "how" is not.

### 6.6 What a packed application looks like from the static side

You will meet one eventually and the tell is a *combination*, never a single observation:

| Observation | Alone | In combination |
|---|---|---|
| `classes.dex` under 200 KB | An ordinary tiny app | Suspicious |
| Fewer than 400 defined classes | A small app | Strongly suspicious |
| A large opaque file in `assets/` | A font atlas, a model, a database | Diagnostic |
| An `<application android:name>` you do not recognise | A DI framework's Application | Diagnostic |
| That class calls `System.loadLibrary` in `<clinit>` or `attachBaseContext` | Normal for NDK apps | Diagnostic |
| `InMemoryDexClassLoader` referenced | A dynamic-feature app | Diagnostic |

```bash
# host — the packer triage, in four commands
unzip -l target.apk | grep -E 'classes.*\.dex'
python3 -B ../04-Java/scripts/dump-strings.py target.apk --min-len 8 | wc -l
unzip -l target.apk | grep -E 'assets/' | sort -k1 -rn | head -5
aapt2 dump xmltree --file AndroidManifest.xml target.apk | grep -A2 'android:name.*application'
```

If the triage says "packed", **stop the static pass**. Everything downstream of stage 3 is about to
describe a stub. Go to [40-Obfuscation](../40-Obfuscation/README.md) §3.7.3, unpack dynamically, and
restart this pipeline at stage 3 with the dumped DEX. The success criterion for the unpack is
concrete: jadx opens your dump and you can see classes whose names match the manifest's component
names.

> **⚠️ Warning**
> "Few classes plus a big asset" is also what a legitimate Unity or Flutter app looks like. Check the
> framework markers *first* — `assets/bin/Data/`, `flutter_assets/`, `libil2cpp.so`, `libhermes.so`
> — because the response is completely different: a Unity app is not packed, its code simply is not
> in the DEX and never was.

### 6.7 The finding a static pass can make that dynamic analysis was supposed to own

The training app used above is from a Frida course. Its intended solution is dynamic: attach, hook
`Checker.getCode()`, force it to return 256, read the flag off the screen.

The static pass reaches the answer without running the app at all:

```bash
# host — three commands, about forty seconds after the tree exists
grep -rn 'Base64' out/sources/com/mobilehackinglab/ | head
echo 'TUhMe01PRElGSUVEX1ZBUklBQkxFfQ==' | base64 -d
# MHL{MODIFIED_VARIABLE}
```

That is not a criticism of the exercise; the exercise teaches hooking. It is a demonstration of the
asymmetry that decides which tool to reach for:

- **Static beat dynamic here** because the secret was a *constant*. Constants are static's home
  ground: no gate, no state, no timing.
- **Dynamic would have beaten static** if the flag had been derived from the click count, or fetched
  from a server, or decrypted with a key held in native code.
- **Neither approach tells you the whole story alone.** Static recovered the value and never
  observed that the app also refuses to display it until a counter reaches 256; dynamic observed the
  gate and would never have known the value was a plain constant sitting in the string table.

> **🔍 Pentester's Note**
> When a target's secret is a constant, static analysis is faster than any hook you can write. Check
> the string table *first*, always. It costs one command and it occasionally ends the engagement's
> hardest question in the first ten minutes.

---

## 7. Dynamic Analysis

This chapter owns static analysis. This section exists to mark the boundary precisely, because a
boundary you have not marked is a boundary you will cross without noticing.

[51-DynamicAnalysis](../51-DynamicAnalysis/README.md) is the other half of this loop, and it is
written: it owns the runtime methodology, and it measured the case that makes the pairing concrete —
**the same session scored 67% or 50% coverage depending on whether the manifest or the device's
resolver tables defined the denominator.** Static analysis supplies the denominator that runtime
evidence alone cannot. [53-Frida](../53-Frida/README.md) is the practical companion for the
instrumentation itself.

### 7.1 Where static hands over — the boundary table

| Static produced | Static cannot finish | Hand to |
|---|---|---|
| "A `TrustManager` exists" | "Does the app accept my CA?" | An intercept attempt, and read the caveat below |
| "`registerReceiver` is called" | "With which actions?" | `dumpsys activity broadcasts` while the app runs |
| "A native method is declared" | "Which native function implements it?" | Hook `RegisterNatives` |
| "This class holds a token" | "Is the token ever sent?" | Proxy plus a hook on the request builder |
| "There is a call to `Method.invoke`" | "Invoking what?" | Hook `Method.invoke`, log the target |
| "`InMemoryDexClassLoader` is referenced" | "What DEX gets loaded?" | Hook the constructor, dump the buffer |
| "This code has no static caller" | "Does it ever run?" | A hook that either fires or does not |
| "A remote-config flag guards this" | "What does the server send?" | Capture the config response |

> **⚠️ Warning — this device cannot answer trust-store questions**
> The test device's system CA store has been replaced by APatch with a tmpfs containing 139
> certificates, including an interception CA. **A successful intercept here does not prove an app
> trusts user-installed CAs**, because the proxy CA is in the *system* store. Run
> `adb shell mount | grep cacerts` before any trust claim. Chapter 44 wrote this up as a methodology
> trap rather than publish a conclusion it could not support; chapter 35 diagnosed the mechanism (a
> `trustusercerts` module promoting the CA into the system store). Do not repeat the mistake.

### 7.2 The blind-spot recorder

The single most useful dynamic script *for a static analyst* is not a bypass. It is an instrument
that records the four things §3.9 says you cannot see, so that your report's limits section is
measured rather than assumed.

`scripts/blindspot-recorder.js` in this chapter does that. It hooks:

- `ContextWrapper.registerReceiver` — every runtime receiver, with its actions
- `java.lang.reflect.Method.invoke` — every reflective call, with the target
- `DexClassLoader` / `InMemoryDexClassLoader` / `PathClassLoader` — every runtime code load
- `System.loadLibrary` / `System.load` — every native library load
- `art::JNI::RegisterNatives` in `libart.so` — every natively registered method

and prints, on exit, a **delta report**: what ran that a file-based sweep could not have known about.

```bash
# host — spawn the app under the recorder and drive it for a few minutes
frida -U -f com.example.target -l scripts/blindspot-recorder.js --no-pause

# or attach to a running process
frida -U -n com.example.target -l scripts/blindspot-recorder.js

# ask for the summary at any point, from the REPL
rpc.exports.report()
```

The output section that matters looks like this:

```
=== DELTA: what static analysis could not have told you ===
  runtime-registered receivers   14 actions across 6 registrations
      android.intent.action.SCREEN_ON            (not in the manifest)
      com.example.internal.SYNC_DONE             (not in the manifest)
      ...
  reflective invocations          212 calls, 37 distinct targets
      com.example.pay.Signer.sign
      ...
  RegisterNatives bindings        41 methods in libcore.so
      com.example.crypto.Native.seal  -> libcore.so+0x3f180
```

Every line in that report is a line your static pass either got wrong or never had.

### 7.3 Confirming reachability with a hook

The static closure in §3.7 gives you evidence, not proof. This is the proof, and it is four lines:

```javascript
// frida -U -n com.example.target -l reach.js
// Does the method holding the lead actually run during normal use?
Java.perform(function () {
    var C = Java.use("com.example.pay.PaymentSigner");
    C.signRequest.overload("java.lang.String").implementation = function (body) {
        console.log("[reach] signRequest CALLED from:\n" +
            Java.use("android.util.Log").getStackTraceString(
                Java.use("java.lang.Exception").$new()));
        return this.signRequest(body);
    };
});
```

Drive the app for ten minutes of ordinary use. Then write one of two sentences, and no others:

- "The method executes during normal use; the stack trace shows it is reached from
  `CheckoutActivity.onPay`." — reachability confirmed, severity proceeds.
- "The method did not execute during ten minutes of ordinary use covering login, browse and
  checkout." — an honest, useful, *bounded* statement. It is not "unreachable"; it is a measurement
  with its scope attached.

### 7.4 Confirming a static finding on the device

The `debuggable` lead from §9.3 is the model for how a static finding gets closed out:

```bash
# host — 1. the file's claim
grep -n 'debuggable' work/AndroidManifest.xml
#   android:debuggable="true"

# adb shell — 2. the platform's record  (this is the evidence)
dumpsys package com.mobilehackinglab.FridaThree | grep -E 'flags='
#   flags=[ DEBUGGABLE HAS_CODE ALLOW_CLEAR_USER_DATA ALLOW_BACKUP ]

# host — 3. the consequence, demonstrated
adb shell run-as com.mobilehackinglab.FridaThree ls -la /data/data/com.mobilehackinglab.FridaThree
# `run-as` works for a debuggable app. That is the impact sentence, and it is
# a demonstration rather than an assertion.
```

Three steps, three different kinds of evidence: the claim, the platform's agreement, and the
consequence. A finding with all three is not arguable.

### 7.5 Which tool answers this question?

```mermaid
flowchart TD
    Q["I have a question about the app"] --> C1{"Is the answer a CONSTANT<br/>in the artefact?"}
    C1 -- "yes" --> S1["STATIC wins.<br/>string table / grep / manifest"]
    C1 -- "no" --> C2{"Does it depend on<br/>runtime state or input?"}
    C2 -- "yes" --> C3{"Can you run the app?"}
    C3 -- "no" --> S2["STATIC, with a stated limit.<br/>Describe the branch, not the outcome"]
    C3 -- "yes" --> D1["DYNAMIC.<br/>hook, proxy, dumpsys"]
    C2 -- "no" --> C4{"Is it about COMPLETENESS<br/>-- 'how many places...'?"}
    C4 -- "yes" --> S3["STATIC.<br/>Dynamic sees only what you triggered"]
    C4 -- "no" --> C5{"Is it about the SERVER?"}
    C5 -- "yes" --> D2["NEITHER.<br/>Test the API directly"]
    C5 -- "no" --> B["BOTH.<br/>Dynamic to understand,<br/>static to be exhaustive"]

    style S1 fill:#d0e8f9
    style S2 fill:#f9e0c0
    style D2 fill:#f9d0d0
```

The amber box is the one people mishandle. When you cannot run the app, static analysis can still
tell you a branch exists and what it would do — and the honest write-up describes the branch and
states that the condition was not evaluated. That is a real, useful finding. What it is not is
permission to write "the app does X".

### 7.6 What dynamic analysis cannot give back

It is worth stating the reverse, because teams that discover Frida sometimes stop doing static work
entirely:

- **Completeness.** Dynamic analysis sees the paths you triggered. On the 17 MB app in §9.4, the
  `Domain` enum contains thirteen environments; twelve of them will never appear in a proxy log
  because the build points at production.
- **Inventory with versions.** MASVS-CODE's dependency inventory is a property of the artefact.
- **Anything about builds you cannot run**, including the one the client shipped last quarter.
- **Evidence that outlives the device.** A hash and a line number are still checkable next year.

> **🧠 Mental Model**
> Use **dynamic analysis to understand** and **static analysis to be exhaustive**, in that order,
> whenever both are available. [40-Obfuscation](../40-Obfuscation/README.md) §6.1 phrases the same
> rule from the other side, and it is the single most transferable sentence in either chapter.

---

## 8. Static Analysis

This is the chapter's own §8: the catalogue, the commands, and the decision table. Everything above
was why; this is what you run.

### 8.1 The five-minute pass

Before anything else, on any APK, in any engagement:

```bash
# host
APK=target.apk

sha256sum "$APK"
apksigner verify -v --print-certs "$APK" | head -20
aapt2 dump badging "$APK" | head -20                  # package, versions, sdk
unzip -l "$APK" | grep -cE '\.dex$'
unzip -l "$APK" | grep -E 'lib/[^/]+/' | awk -F/ '{print $2}' | sort -u
unzip -l "$APK" | grep -E 'assets/' | sort -k1 -rn | head
aapt2 dump xmltree --file AndroidManifest.xml "$APK" | grep -E \
    'debuggable|allowBackup|usesCleartextTraffic|networkSecurityConfig|testOnly'
```

If that pass finds `CN=Android Debug` or `debuggable=true`, you already have a finding and the rest
of the day is about how much worse it gets.

### 8.2 The grep catalogue

Every rule below exists in `scripts/static-sweep.py` with an identifier, a precision, and a next
step; `--print-catalogue` prints them. The hand-run form is given here because **a tool you have
never checked by hand is a tool you cannot defend in a report**.

Run these from the root of a decompiled tree.

**Credentials — format rules (high precision, act on a hit):**

```bash
# host
grep -rn -- '-----BEGIN' .                                   # CRED-01 PEM key material
grep -rnE 'AKIA[0-9A-Z]{16}' .                               # CRED-02 AWS access key id
grep -rnE 'AIza[0-9A-Za-z_-]{35}' .                          # CRED-03 Google API key
grep -rnE '[sr]k_(live|test)_[0-9A-Za-z]{10,}' .             # CRED-04 Stripe
grep -rnE 'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.' .    # CRED-05 JWT literal
grep -rnE 'gh[pousr]_[0-9A-Za-z]{20,}|xox[abprs]-' .         # CRED-06 GitHub / Slack
```

**Credentials — keyword and shape rules (low precision, triage before acting):**

```bash
# host
grep -rnEi 'api[_-]?key|client[_-]?secret|access[_-]?key|x-api-key' .   # CRED-07
grep -rnEi 'password\s*=\s*"' .                                         # CRED-08
grep -rnoE '"[A-Za-z0-9+/=]{20,}"' . | sort -u                          # CRED-09 base64
grep -rnoE '"[0-9a-fA-F]{40,}"' . | sort -u                             # CRED-10 long hex
```

**Endpoints:**

```bash
# host
grep -rnoE 'http://[^"]+' .  | sort -u          # NET-01 cleartext
grep -rnoE 'https://[^"]+' . | sort -u          # NET-02 inventory, not a finding
grep -rnoE '"([0-9]{1,3}\.){3}[0-9]{1,3}"' .    # NET-03 hardcoded IP
grep -rnEi '(staging|preprod|uat|sandbox|qa)[0-9]*\.[a-z0-9-]+\.[a-z]{2,}' .   # NET-04
```

**Cryptography** (find here; rate in [34-Cryptography](../34-Cryptography/README.md)):

```bash
# host
grep -rn 'ECB' .                                        # CRY-01
grep -rn 'IvParameterSpec\|GCMParameterSpec' .          # CRY-02
grep -rn 'setSeed\|new SecureRandom(' .                 # CRY-03
grep -rnE 'getInstance\("(MD5|SHA-?1)"\)' .             # CRY-04
grep -rn 'PBEKeySpec' .                                 # CRY-05
```

**TLS trust** (find here; rate in [35](../35-SSL/README.md), [36](../36-CertificatePinning/README.md),
[44](../44-NetworkSecurityConfig/README.md)):

```bash
# host
grep -rn 'checkServerTrusted\|X509TrustManager' .       # TLS-01
grep -rn 'HostnameVerifier\|ALLOW_ALL_HOSTNAME' .       # TLS-02
grep -rn 'onReceivedSslError' .                         # TLS-03
grep -rn 'CertificatePinner\|pin-set\|network_security_config' .   # TLS-04
```

**Storage and platform** (find here; rate in [33-Storage](../33-Storage/README.md),
[43-WebView](../43-WebView/README.md)):

```bash
# host
grep -rn 'MODE_WORLD_READABLE\|MODE_WORLD_WRITEABLE' .  # STO-01
grep -rn 'getExternalStorage' .                         # STO-02
grep -rnEi 'putString\("[^"]*(token|password|secret|key|pin|session|auth)' .   # STO-03
grep -rn 'addJavascriptInterface\|setJavaScriptEnabled(true)' .                # STO-04
```

**Debug residue:**

```bash
# host
grep -rn 'debuggable' AndroidManifest.xml               # DBG-01
grep -rn 'Log\.[dvi](' .                                # DBG-02
grep -rnE 'TODO|FIXME|HACK|XXX' .                       # DBG-03
grep -rn 'printStackTrace' .                            # DBG-04
```

**Blind-spot markers — these are not leads, they are limits on your report:**

```bash
# host
grep -rn 'registerReceiver' .                                          # BLIND-01
grep -rnE 'Class\.forName|getDeclaredMethod|\.invoke\(' .              # BLIND-02
grep -rn 'DexClassLoader\|InMemoryDexClassLoader' .                    # BLIND-03
grep -rn 'loadLibrary\|System\.load(' .                                # BLIND-04
grep -rni 'remoteconfig\|featureflag' .                                # BLIND-05
unzip -l target.apk | grep -E 'assets/.*\.(dex|so|bin|dat|enc)$'       # BLIND-06
```

### 8.3 Running the catalogue with the sweeper

```bash
# host — the whole catalogue, aggregated and ranked
python3 -B scripts/static-sweep.py ./out

# name the app's package when the tree has no manifest -- without it
# EVERYTHING scores as third-party and the app's own code is buried
python3 -B scripts/static-sweep.py ./out --app-package com.example.target

# first pass on a large app: skip library files before reading them
python3 -B scripts/static-sweep.py ./out --files app

# only what is worth the first hour
python3 -B scripts/static-sweep.py ./out --min-confidence 0.5

# audit the filter: what did it demote, and why?
python3 -B scripts/static-sweep.py ./out --show-suppressed

# the ledger, with empty verdict and reason columns for you to fill in
python3 -B scripts/static-sweep.py ./out --csv leads.csv
```

Measured behaviour, so you know what to expect: about one minute over a 3,655-file tree and about
six minutes over a 20,091-file one; `--files app` cut the second to one minute by skipping 7,041
library files unopened.

### 8.4 The triage decision table

This is the table to keep beside you. Given a hit, it says what to do next without thinking.

| What you have | Where it is | Decision | Next action |
|---|---|---|---|
| Format-rule hit (PEM, `AKIA`, `sk_live_`) | App code | **Work it now** | Read the class; establish scope; check whether the vendor intends client-side use |
| Format-rule hit | Library code | **Work it, then reassign** | It is a finding about the library, in the dependency section |
| API-rule hit (`ECB`, `addJavascriptInterface`) | App code | **Read the arguments** | The construct is not the finding; its arguments and callers are |
| API-rule hit | Library code | **Note and move on** | Unless the library is unmaintained or the call is on a data path you care about |
| Shape-rule hit (base64, hex) | Anywhere | **Decode before reading anything else** | Decodes to text: usually resolved in ten seconds. Decodes to 16/32 bytes near a `Cipher`: escalate |
| Keyword hit (`password`) | Library code | **Reject** | 136 of 137 on the test app. Do not spend the twenty minutes |
| Keyword hit | App code | **One look** | Is the value next to the name, or is the name a lookup? |
| Cleartext URL | Namespace or documentation host | **Reject** | `schemas.android.com`, `w3.org`, `slf4j.org`, vendor doc links |
| Cleartext URL | App code, resolves, app-controlled | **Work it** | Check the network security config before writing severity |
| Non-production hostname | App code | **Work it** | Frequently the best lead in the whole run — see §9.4 |
| Manifest flag (`debuggable`, `allowBackup`) | Manifest | **Confirm on device** | `dumpsys package | grep flags=` is the evidence |
| Blind-spot marker | Anywhere | **Not a lead** | It goes in the limits section of the report |
| Anything at all | Generated code (`R.java`, `BuildConfig`, `*Binding`) | **Reject** | Generated code contains no developer decisions |

### 8.5 Cross-referencing the manifest with the code

The highest-value pass that neither the manifest chapter nor the code sweep does alone: take every
exported component and find what it does with its input.

```bash
# host — for each exported component, open the class and look for the sinks
for c in $(awk '
    /<(intent-filter|meta-data|action|category)[ \t>\/]/ { t=0 }
    /<(activity|activity-alias|service|receiver|provider)([ \t>\/]|$)/ { t=1 }
    t && match($0, /android:name="[^"]+"/) { print substr($0,RSTART+14,RLENGTH-15); t=0 }
  ' work/AndroidManifest.xml | sort -u); do
    f="out/sources/$(printf '%s' "$c" | tr '.' '/').java"
    [ -f "$f" ] || continue
    echo "=== $c"
    grep -nE 'getIntent|getStringExtra|getData\(\)|getQueryParameter|openFile|query\(|exec\(|loadUrl' "$f"
done
```

That loop is the shape of most real Android findings: **attacker-controlled input reaching a sink,
in a component another app can start.** [32-Manifest](../32-Manifest/README.md) tells you which
components are reachable; [26-Intent](../26-Intent/README.md), [27](../27-ContentProviders/README.md),
[28](../28-Services/README.md) and [30](../30-Activities/README.md) tell you what the sinks mean.

### 8.6 Resources, assets and the files people forget

```bash
# host
cat work/res/xml/network_security_config.xml 2>/dev/null
for f in work/res/xml/*.xml; do echo "== $f"; cat "$f"; done
grep -rn 'http\|key\|token\|secret' work/res/values/strings.xml | head -40
ls -laS work/assets/ 2>/dev/null | head -20
file work/assets/* 2>/dev/null | grep -v ASCII
grep -rn '' work/res/raw/*.json 2>/dev/null | head
```

Two things live here that the DEX sweep will not find:

- **`res/values/strings.xml`** frequently holds API keys, because a build system put them there via
  `resValue`. They survive R8 renaming completely, and `strings.xml` is the first place a lazy
  attacker looks.
- **`res/xml/`** holds the network security config, the FileProvider paths, the backup rules, the
  accessibility-service config and the device-admin policy — five separate finding classes, each in a
  file the manifest merely *points at*. `32-Manifest` §8.3 tabulates them; open every one.

### 8.7 Gradle and source, when you have them

```bash
# host, in a source checkout
grep -rnE 'minSdk|targetSdk|applicationId|signingConfig|debuggable' --include='build.gradle*' .
grep -rn 'manifestPlaceholders\|buildConfigField\|resValue' --include='build.gradle*' .
find . -name 'AndroidManifest.xml' -not -path './build/*'      # every flavour
ls gradle/verification-metadata.xml gradle/dependency-locks/ 2>/dev/null
./gradlew :app:dependencies --configuration releaseRuntimeClasspath > deps.txt
```

> **⚠️ Warning**
> Source access changes what you can see and **does not replace analysing the artefact**.
> `manifestPlaceholders` and `buildConfigField` substitute values at build time, so the source can
> contain `${API_KEY}` while the shipped APK contains the key. Audit the built artefact; use the
> source to explain it.

### 8.8 The native side, in the ten minutes it deserves here

[15-Native-Code](../15-Native-Code/README.md), [16-JNI](../16-JNI/README.md) and
[57-Ghidra](../57-Ghidra/README.md) own native analysis. What belongs in a *static pass* is the
inventory and the two questions that change your plan.

```bash
# host
mkdir -p x && cd x && unzip -o -q ../target.apk 'lib/*'
find lib -name '*.so' | while read -r so; do
    echo "=== $so  ($(wc -c < "$so") bytes)"
    readelf -d "$so" 2>/dev/null | grep NEEDED | head
    echo -n "  Java_ exports: "
    readelf --dyn-syms --wide "$so" 2>/dev/null | grep -c ' Java_' 
    echo -n "  JNI_OnLoad:    "
    readelf --dyn-syms --wide "$so" 2>/dev/null | grep -c 'JNI_OnLoad'
    strings -a -n 6 "$so" | grep -aoiE 'OpenSSL [0-9][^ ]*|libcurl/[0-9.]+' | sort -u
done
```

**Question 1: how much of the app is native?** A 40 MB `.so` next to a 2 MB DEX means the managed
sweep you just ran covered a rounding error of the program. Say so in the limits section.

**Question 2: `JNI_OnLoad` present and zero `Java_` exports?** Then the native surface is bound with
`RegisterNatives` and is not enumerable from the file at all (§4.4). That is a blind-spot entry, and
the only way to enumerate it is the recorder in §7.2.

> **🔬 Under the Hood**
> No `readelf` on this machine? The Android NDK ships the LLVM binutils, and they are drop-in:
> `.../ndk/25.2.9519653/toolchains/llvm/prebuilt/<host>/bin/llvm-readelf`.
> `17-Libraries/scripts/lib-inventory.sh` already falls back through
> `readelf → llvm-readelf → objdump → a pure-Python ELF parser`, and reports which link of the chain
> answered — copy that pattern rather than assuming a tool exists.

### 8.9 The tools, and exactly where each one stops

| Tool | Stage it serves | What it is genuinely good at | Where it stops |
|---|---|---|---|
| `jadx` | 3 | Readability; the fastest route to understanding | Reconstruction can be wrong; errors are reported and ignored by most users |
| `apktool` | 3 | Smali plus fully decoded resources, including `res/xml/` | Not a decompiler; slow on large apps |
| `aapt2 dump` | 3, 4 | The platform's own parse — the tiebreaker in a divergence | Code |
| `baksmali` | 3, 6 | Ground truth for bytecode | Verbose; no resources |
| `dexdump -d` | 6 | Authoritative instruction listing with string indices | Hard to read at volume |
| `dump-strings.py` ([04](../04-Java/README.md)) | 4, 5 | Exact literals with table indices; MUTF-8 correct | No locations |
| `lib-inventory.sh` ([17](../17-Libraries/README.md)) | 4 | Dependency inventory with fallbacks, MASVS-CODE | Not reachability |
| `manifest-audit.py` ([32](../32-Manifest/README.md)) | 4 | Component semantics, including implicit `exported` | Not code |
| `apkid` | 2 | Packer, obfuscator and compiler identification | Narrow by design, and excellent within it |
| `semgrep` | 5 | Syntax-aware rules over decompiled Java; far fewer shape false positives than grep | Needs parseable output; obfuscated code defeats it |
| **MobSF** | 5 | Breadth, and a fast first inventory for someone else's app | **No stage 7.** It reports every exported component at one severity and cannot know what a component does |
| `static-sweep.py` (here) | 5, 6 | Aggregation, scoring with printed terms, a next step per lead | It is not a decompiler, a manifest auditor, a dependency scanner or a judge |

**A note on `semgrep`,** because it is the one tool in that list that meaningfully reduces false
positives rather than reorganising them. A grep for `password` matches a comment; a semgrep rule can
require an *assignment of a string literal to a field whose name matches*, which is a different and
much smaller set:

```yaml
# semgrep — rules/hardcoded-secret.yaml, run over jadx output
rules:
  - id: literal-assigned-to-secret-field
    languages: [java]
    severity: INFO          # INFO deliberately: this is a lead, not a finding
    message: >
      A string literal is assigned to a field whose name suggests a credential.
      Confirm whether the literal IS the credential or merely a key name.
    patterns:
      - pattern-either:
          - pattern: $T $NAME = "...";
          - pattern: this.$NAME = "...";
      - metavariable-regex:
          metavariable: $NAME
          regex: (?i).*(secret|token|apikey|api_key|password|passphrase).*
```

Two caveats that keep semgrep honest on Android: it needs *parseable* Java, so a heavily obfuscated
or partially-decompiled tree will silently cover less than you think; and its `severity` field is
about the rule, not about your client's risk — set it to `INFO` and let stage 7 decide, exactly as
this chapter's own tooling does.

### 8.10 The one-page runbook

Everything above, in the order you actually type it:

```bash
# ---------------------------------------------------------------- stage 1-2
PKG=com.example.target
adb shell pm path "$PKG"                       # note EVERY path
adb pull <each path> .
sha256sum *.apk | tee evidence/hashes.txt
apksigner verify -v --print-certs base.apk | head -20
unzip -l base.apk | grep -cE '\.dex$'
unzip -l base.apk | grep -E 'lib/[^/]+/' | awk -F/ '{print $2}' | sort -u
unzip -l base.apk | grep -E 'assets/' | sort -k1 -rn | head

# ---------------------------------------------------------------- stage 3
jadx -d out base.apk &                          # slow; start it now
apktool d -f base.apk -o work
aapt2 dump xmltree --file AndroidManifest.xml base.apk > manifest-aapt2.txt

# ---------------------------------------------------------------- stage 4
awk '/<(intent-filter|meta-data|action|category)[ \t>\/]/{t=0}
     /<(activity|activity-alias|service|receiver|provider|application)([ \t>\/]|$)/{t=1}
     t && match($0,/android:name="[^"]+"/){print substr($0,RSTART+14,RLENGTH-15);t=0}' \
    work/AndroidManifest.xml | sort -u > entrypoints.txt
../17-Libraries/scripts/lib-inventory.sh base.apk -o inventory/
for f in work/res/xml/*.xml; do echo "== $f"; cat "$f"; done

# ---------------------------------------------------------------- stage 5-6
python3 -B scripts/static-sweep.py ./out ./work --app-package "$PKG" \
        --csv leads.csv | tee sweep.txt

# ---------------------------------------------------------------- stage 7
bash scripts/validate-lead.sh --tree ./out --value '<value>' --reach \
     --package "$PKG" --out evidence/L001
#   ... repeat for every lead, recording a verdict and a reason in leads.csv

# ---------------------------------------------------------------- stage 8
#   findings + the ledger + the limits section. Template: ../80-Appendix/
```

Print it, tape it to the monitor, and note the one line that has no command next to it: stage 7 is
a loop you run by hand, once per lead, and it is the only stage that produces a finding.

### 8.11 What to do when the sweep is empty

An empty result is a result, and it has four explanations, in descending order of likelihood:

1. **You swept the wrong tree** — the app's classes are in a split you did not decompile.
2. **The app is small or genuinely clean** — possible, and more common than cynics expect for a
   focused app with a competent team.
3. **Strings are encrypted** — check the string table: an app with no URLs at all is building them.
   [40-Obfuscation](../40-Obfuscation/README.md) §6.1 Phase 4.
4. **The code is not in the artefact** — packing, or a cross-platform framework. Check `assets/`
   size against DEX size.

Report it as "the sweep produced no leads above threshold", never as "no issues found", and put the
blind-spot section immediately underneath.

---

## 9. Examples

Five worked examples, simple to enterprise. The third and fourth are real runs against real
applications on the test device, with the numbers those runs produced.

> **A note on naming.** This repository may be published. The training applications named below are
> public, deliberately vulnerable teaching targets and naming them is fine. The commercial
> application in §9.4 is **anonymised**: its package is written as `com.vendor.hrapp`, its hostnames
> are substituted, its credential value is redacted, and its hash is omitted. Every count, ratio and
> timing is the real measured number.

### 9.1 Simple — one lead, from grep to closed finding

The smallest complete instance of the whole pipeline. Two commands find it; two more close it.

```bash
# host — stage 5, the sweep
grep -n 'debuggable' work/AndroidManifest.xml
#   21:        android:debuggable="true"
```

Stage 6 says this is a format-class hit in the manifest, in app scope, single site: work it now.
Stage 7 asks the four questions:

| Question | Answer | How |
|---|---|---|
| Is the construct really there? | Yes | The attribute is in the decoded manifest |
| Is it reachable? | Not applicable — it is a process attribute, not code | — |
| Who can reach it? | Anyone with ADB access to the device | `run-as`, `am set-debug-app`, a JDWP attach |
| What does it get them? | Read of the app's private data directory, and of process memory over JDWP | The `run-as` step below is how you demonstrate it |

```bash
# adb shell — the platform's own confirmation, which is the evidence
dumpsys package com.mobilehackinglab.FridaThree | grep 'flags='
#   flags=[ DEBUGGABLE HAS_CODE ALLOW_CLEAR_USER_DATA ALLOW_BACKUP ]

# host — the consequence. Run it: a finding you have demonstrated is not
# arguable, and a finding you have only reasoned about is.
adb shell run-as com.mobilehackinglab.FridaThree ls -la /data/data/com.mobilehackinglab.FridaThree
```

> **Measured versus prescribed, stated honestly.** The `dumpsys` line above is a real measurement
> taken on the test device while this chapter was written. The `run-as` step is prescribed: the test
> device was disconnected before it was executed, so this chapter does **not** claim to have run it.
> That distinction is exactly the discipline the chapter is about, and it would be absurd to blur it
> here of all places.

**Written finding:**

> **Release build is debuggable.** The shipped artefact declares
> `android:debuggable="true"`, and the platform confirms it: `dumpsys package` reports
> `flags=[ DEBUGGABLE … ]`. Any party with ADB access — including a malicious USB host, an
> attacker with a stolen unlocked device, or any application that can reach the JDWP socket —
> can attach a debugger to the process, read its memory, and use `run-as` to read its private
> data directory without root. Fix: set `debuggable` per build type and add a release-blocking
> lint rule; never rely on remembering.

Note what makes this a finding rather than a lead: the platform agreed, and the consequence was
demonstrated.

### 9.2 Intermediate — a base64 constant, and honest severity

The sweeper's second-ranked lead on the same app:

```
L002  [HIGH 0.65]  CRED-09  (credential)
  what      long base64-looking literal
  value     TUhMe01PRElGSUVEX1ZBUklBQkxFfQ==
  sites     1 occurrence(s) in 1 file(s); 1 in app code
            sources/com/mobilehackinglab/FridaThree/MainActivity.java:50  [app]
  score     rule CRED-09 precision (+0.30); in the app's own package (+0.25);
            single site, in app code (+0.10)
  NEXT STEP Decode it. If it decodes to readable text the obfuscation is already
            defeated and you know what it is. [...]
```

Follow the next step, exactly as written:

```bash
# host
echo 'TUhMe01PRElGSUVEX1ZBUklBQkxFfQ==' | base64 -d
# MHL{MODIFIED_VARIABLE}
```

Then confirm the construct in bytecode rather than trusting the decompiler:

```
# host: dexdump -d classes3.dex
0005ce: 1a00 2b00   |001f: const-string v0, "TUhMe01PRElGSUVEX1ZBUklBQkxFfQ==" // string@002b
0005da: 6e20 1600   |0025: invoke-virtual {v1, v0}, Ljava/util/Base64$Decoder;.decode:(Ljava/lang/String;)[B
```

Both halves confirmed: the literal is there, and it is passed to a Base64 decoder whose result is
displayed. **And now the honest part.** The four questions:

1. Real? Yes.
2. Reachable? Yes — the holding class is a manifest-declared, exported `MainActivity`.
3. Who? Anyone who runs the app, but only after a counter reaches 256.
4. **What does it get them?** A string that the app displays on screen anyway.

In the CTF this is the answer. **In a commercial report it is Informational**, because the "secret"
protects nothing. Encoding is not encryption, and the correct sentence is "a value the developer
appears to have intended to obscure is recoverable in one command", not "hardcoded secret found".

> **🔍 Pentester's Note**
> This is the most common inflation in mobile reporting. `base64` in a DEX gets written up as a
> "hardcoded credential" hundreds of times a year. Decode it before you name it, and then ask what
> it protects.

### 9.3 Advanced — a complete static pass, ending in a validated finding

**Target:** `com.mobilehackinglab.FridaThree`, a public MobileHackingLab training application, pulled
from the test device (Redmi `M2101K6P`, Android 11 / API 30).

**Stage 1 — acquire.**

```bash
# host
adb shell pm path com.mobilehackinglab.FridaThree
# package:/data/app/~~Ot4l…==/com.mobilehackinglab.FridaThree-biNE…==/base.apk
adb pull /data/app/~~Ot4l…==/com.mobilehackinglab.FridaThree-biNE…==/base.apk fridathree.apk
sha256sum fridathree.apk
# 37299c1488934e53e316a57bd0a0d9ea8145598888c193ebdfa77971eb611d49
```

One path printed, so no splits. 5,785,227 bytes.

**Stage 2 — unpack.** Three DEX files (`classes.dex` 9.9 MB uncompressed, `classes2.dex` 513 KB,
`classes3.dex` **4,180 bytes**). No `lib/`, no `assets/`. That 4 KB third DEX is where the
application's own three classes live; everything else is Kotlin and AndroidX.

**Stage 3 — decompile.** jadx 1.5.3, 1 minute 57 seconds, 2,783 classes,
`finished with errors, count: 17`.

**Stage 4 — enumerate.** 3,655 files in the tree, of which the classifier puts **3 in the app's own
package**, 2,759 third-party, 42 generated, 850 resources, 1 unknown. The manifest declares three
entry points.

**Stage 5 and 6 — sweep and triage.**

```
files scanned      3655
raw hits           7346
killed by a rule's own validator  3591
distinct leads     9
demoted as noise   7
blind-spot notices 2

Aggregation ratio: 7346 raw hits collapsed to 9 leads (816.2x).
```

The full queue, in order:

| ID | Conf | Rule | Value | Sites | App sites |
|---|---|---|---|---|---|
| L001 | 0.90 | DBG-01 | `android:debuggable="true"` | 1 | 1 |
| L002 | 0.65 | CRED-09 | `TUhMe01PRElGSUVEX1ZBUklBQkxFfQ==` | 1 | 1 |
| L003 | 0.30 | NET-01 | `http://schemas.android.com/apk/res/android` | 627 | 1 |
| L004 | 0.10 | STO-02 | legacy external storage path | 2 | 0 |
| L005 | 0.05 | DBG-02 | log call with a variable message | 18 | 0 |
| L006 | 0.05 | DBG-04 | stack trace printed | 36 | 0 |
| L007 | 0.05 | NET-01 | `http://schemas.android.com/aapt` | 60 | 0 |
| L008 | 0.05 | NET-01 | `http://schemas.android.com/apk/res-auto` | 40 | 0 |
| L009 | 0.05 | NET-03 | `127.0.0.1` | 1 | 0 |

That table is transcribed from [`examples/sweep-output-fridathree.txt`](examples/sweep-output-fridathree.txt),
which is the unedited tool output; check it rather than trusting this table.

**Stage 7 — validate. Two survive, seven are rejected**, and here is why each was rejected:

| ID | Verdict | Reason |
|---|---|---|
| L001 | **FINDING** | Confirmed by `dumpsys package … flags=[ DEBUGGABLE … ]`; `run-as` demonstrated |
| L002 | **Confirmed, Informational** | Decodes to a UI string the app displays anyway (§9.2) |
| L003 | Rejected | XML namespace URI, not an endpoint. Present in 627 of 3,655 files |
| L004 | Rejected | Zero sites in app code; AndroidX `FileProvider` and `EnvironmentCompat` |
| L005 | Rejected | Zero sites in app code; AndroidX and ConstraintLayout logging |
| L006 | Rejected | Zero sites in app code |
| L007 | Rejected | Namespace URI |
| L008 | Rejected | Namespace URI |
| L009 | Rejected | Loopback literal inside ConstraintLayout's `Utils`; not reachable from app code |

Four of those nine — the three `schemas.android.com` URIs and `127.0.0.1` — were also **demoted as
noise** by the tool and are only visible because the run used `--show-suppressed`. Working them
anyway costs about two minutes and produces four checkable rejection reasons.

**Stage 0 — blind spots.** Two markers fired, and both go in the report's limits section:

```
BLIND-01  receiver registered at runtime
    12 occurrence(s) across 3 file(s); none in app code
BLIND-02  reflective dispatch
    313 file(s); none in app code
```

Neither is in the app's own code, which is the best case: the app itself does not register receivers
at runtime or reflect, so for *this* app the blind spot is narrower than usual. That sentence is only
available because the tool classified by package.

**Stage 8 — the finding**, in the form it would ship:

> **F-01 — Release build is debuggable (High)**
> Artefact `base.apk`, SHA-256 `37299c14…b611d49`. `AndroidManifest.xml` line 21 declares
> `android:debuggable="true"`, and the platform confirms the flag was applied:
> `dumpsys package com.mobilehackinglab.FridaThree` reports
> `flags=[ DEBUGGABLE HAS_CODE ALLOW_CLEAR_USER_DATA ALLOW_BACKUP ]`. Impact, to be demonstrated
> with `adb shell run-as <pkg> ls /data/data/<pkg>`: a debuggable application grants `run-as` and
> JDWP access to any party with ADB, giving read and write access to its private data directory and
> to process memory, without root.
> **Fix:** remove the attribute and let the build type control it
> (`debug { isDebuggable = true }` only), and add a release lint gate.
> **Validated leads:** 9 generated, 2 confirmed, 7 rejected with reasons (Appendix B).
> **Limits:** runtime-registered receivers and reflective dispatch are not observable from the
> artefact; neither occurs in the application's own code in this build.

Total elapsed, excluding the decompile: about twenty minutes.

### 9.4 Real application — the false-positive arithmetic, measured

**Target:** a 17 MB commercial HR application installed on the test device. Anonymised as
`com.vendor.hrapp`; hostnames substituted; the credential value redacted.

**The tree:** 20,091 decompiled `.java` files. This is what a real app looks like, and note the
classification breakdown, because it is the most surprising number in this chapter:

```
  files scanned      20091
      app            2210     (the package the manifest names)
      third-party    6967     (androidx, kotlin, okhttp, gms, …)
      generated      74
      unknown        10840    (54% -- neither obviously app nor obviously library)
```

**More than half of a real application's tree is unclassifiable by package prefix.** Vendored SDKs,
shaded dependencies, relocated packages and R8 output all land in "unknown". The honest response is
what the tool does: score them slightly above library code, print the count, and leave the judgement
to a human who can spend ten minutes on the prefixes that matter.

**The two runs:**

| Run | Files read | Raw hits | Validator kills | Leads | Time |
|---|---|---|---|---|---|
| Whole tree | 20,091 | 16,836 | 13,220 | 168 | 6 min 01 s |
| `--files app` | 13,050 (7,041 skipped unopened) | 6,883 | 4,375 | 96 | 1 min 02 s |

**Now the arithmetic that matters.** The `--files app` run produced 89 displayed leads in three
bands: **17 HIGH, 49 MEDIUM, 23 LOW**. Working the HIGH band top-down by hand:

| Leads | Adjudication | Why |
|---|---|---|
| L001, L005, L007 | **Rejected** | `http://external.source.com`, `http://test.com`, `http://www.google.com/lol` — sample data compiled into `ComposableSingletons$…` **Compose preview functions** of a bundled support SDK, shipped in the release build |
| L002 | **Rejected** | `http://g.co/dev/packagevisibility` — a framework diagnostic message |
| L003, L006, L008 | **Rejected** | Vendor documentation and marketing URLs inside an SDK |
| L004 | **Rejected** | `http://ns.adobe.com/xap/1.0/` — an XMP **namespace URI** in an image library |
| L009–L015 | **Rejected** | Seven `http://www.slf4j.org/codes.html#…` documentation links from the logging façade |
| L016 | **Downgraded to a lead needing dynamic work** | `setJavaScriptEnabled(true)` in the app's own `AuthWebView`. Real construct, real app code — but no `addJavascriptInterface` in that class, so the finding requires showing the loaded URL is attacker-influenced |
| L017 | **Confirmed literal, severity pending scope** | A 40-character hex value in the app's `Application.onCreate`, passed with a second literal to a translation SDK's `init()`. It **is** a live third-party project token; whether it is a finding depends entirely on what that token authorises |

**Fifteen of seventeen high-confidence leads were rejected on inspection — 88%.** Not one of the
seventeen became a High-severity finding by itself. That is the same shape as chapter 33's
`leak-hunter.py` returning 132 high-confidence hits of which 132 were false positives, and chapter
36 finding 12 of 14 apps with a pinning surface and 4 that pinned.

**And here is the lesson that costs people findings.** The most interesting row in the whole run was
**not** in the HIGH band:

```
L018  [MEDIUM 0.50]  NET-04  (endpoint)
  what      non-production hostname
  value     preprod.vendor-internal.biz
  sites     1 occurrence(s) in 1 file(s); 1 in app code
            sources/com/vendor/hrapp/api/service/Domain.java:29  [app]
```

Opening that file:

```java
// out/sources/com/vendor/hrapp/api/service/Domain.java  (hostnames substituted)
public static final Domain QA7  = new Domain("QA7",  3, "qa7.qa.vendor-internal.biz");
public static final Domain QA6  = new Domain("QA6",  4, "qa6.qa.vendor-internal.biz");
...
public static final Domain STG2 = new Domain("STG2", 10, "timeoff-staging.example");
public static final Domain S50  = new Domain("S50",  12, "preprodsage.preprod.vendor-internal.biz");
```

**Thirteen environments — production, pre-production, eight QA hosts and three staging hosts —
enumerated in the shipped production build.** That is a genuine lead: internal hostname disclosure,
and a map of the vendor's non-production estate handed to anyone who unzips the APK. Its severity
depends on whether those hosts are reachable and whether they hold real data, which is a question for
the client and for DNS, not for a decompiler.

> **🧠 Mental Model**
> **Confidence orders your queue; it does not rank importance.** The tool was right that the
> cleartext URLs were the most *format-certain* matches. It has no way to know that seven of them
> are logging documentation and one MEDIUM row is a map of the client's internal estate. That
> judgement is the job, and it is why stage 7 is performed by a person.

### 9.5 Enterprise — sweeping every build, and reporting the delta

At one app the pipeline is a method. At forty apps and a release every two weeks it has to become
infrastructure, and the shape changes in three ways.

**1. The unit of work becomes the diff, not the build.** Nobody re-triages 96 leads every fortnight.
You triage the *new* ones.

```bash
# CI — one baseline per app, committed next to the app's config
python3 -B static-sweep.py ./out --app-package com.vendor.hrapp \
        --csv "leads/$APP-$BUILD.csv"

# new leads only: compare on (rule_id, value), not on lead_id, which renumbers
join -v2 -t, -j1 \
     <(cut -d, -f2,6 "leads/$APP-baseline.csv" | sort) \
     <(cut -d, -f2,6 "leads/$APP-$BUILD.csv"   | sort) > new-leads.csv

wc -l < new-leads.csv
```

Fail the build on a new **format-class** lead in app scope. Do not fail it on keyword or shape
classes: a gate that fires on `password` will be disabled within a month, and a disabled gate is
worse than no gate because everyone believes it is running.

**2. The ledger becomes a persistent artefact.** A rejected lead should stay rejected. The ledger in
`examples/findings-ledger.csv` has `verdict` and `reason` columns for exactly this: re-import it,
carry the previous verdict forward, and only surface leads with no recorded verdict. The value of
this compounds — after three releases a team is triaging five leads a fortnight instead of ninety.

**3. MASVS-CODE gets satisfied as a by-product.** The dependency inventory is stage 4, and stage 4
runs anyway:

```bash
# CI — the inventory that MASVS-CODE asks for, with versions
../17-Libraries/scripts/lib-inventory.sh "$APK" -o "sbom/$APP-$BUILD"
python3 -B ../17-Libraries/scripts/lib-fingerprint.py "$APK" > "sbom/$APP-$BUILD/versions.txt"
```

Diff the inventory between releases too. A new `.so`, a new initialisation provider, or a new
package prefix appearing between two builds is a supply-chain event, and it is invisible to a tool
that only looks at one build.

**What to measure about the pipeline itself.** Four numbers, tracked per release, that tell you
whether the process is healthy:

| Metric | Healthy trend | What a bad trend means |
|---|---|---|
| New leads per release | Falling toward a small constant | Rising: the sweep's noise floor is drifting; tune validators |
| Rejection rate of new leads | Falling | Stuck near 90%: your rules are shape-based; add format rules |
| Median time from lead to verdict | Under a day | Growing: nobody is working the queue |
| Findings found by the sweep vs found by hand | Sweep share rising slowly | Sweep share near 100%: you have stopped looking, and the sweep cannot see the blind spots |

That last row is the one to watch. A team whose findings all come from the scanner has quietly
adopted the scanner's blind spots as its threat model.

---

## 10. Common Interview Questions

### Beginner

**Q. What is the difference between static and dynamic analysis?**
Static analysis examines the artefact without running it and observes what is *possible*; dynamic
analysis observes what *happened* during execution. Static gives completeness over the code that is
present; dynamic gives ground truth about behaviour. Neither subsumes the other.

**Q. What is the first thing you do with an APK?**
Hash it, check the signature, and list the ZIP contents — before decompiling. `pm path` first, so
that splits are not missed. The five-minute pass in §8.1.

**Q. Why is `apktool` output not enough?**
It gives Smali and decoded resources but no readable Java, and it is a third-party re-implementation
of the platform's parser, so it can disagree with what the platform reads. Use it alongside `aapt2`
(the platform's own code) and jadx (readability).

**Q. You grep for `password` and get 137 results. What now?**
Classify by package first. On a real measurement of a small app, 136 of those 137 were framework or
generated code and the remaining one was a resource identifier in `R.java`. Sorting by location is
worth more than reading faster.

### Intermediate

**Q. What is the difference between a hit, a lead and a finding?**
A hit is one regex match on one line. A lead is one distinct value or construct with all of its sites
attached, carrying a confidence and a next step. A finding is a lead that has survived validation:
the construct is real, it is reachable, you know who can reach it, and you know what reaching it
gets them.

**Q. A scanner reports 132 high-confidence secrets. How do you proceed?**
Assume most are wrong until shown otherwise — in the measured case, all 132 were. Aggregate to
distinct values, classify by package, decode anything encoded, and work the queue top-down recording
a reason against each rejection. The rejections are part of the deliverable.

**Q. How do you decide the severity of a hardcoded API key?**
By what the key authorises, not by the fact it exists. Some keys are designed to ship in clients —
Google API keys, Firebase app IDs, Play Billing public keys, translation-SDK project tokens. The
finding, if there is one, is that the key has no application restriction or an over-broad scope, and
that requires checking the restriction.

**Q. What can static analysis not see on Android?**
Runtime-registered receivers (measured at 69% of the broadcast surface on a live device),
`RegisterNatives` bindings, reflective dispatch, dynamically loaded DEX, and all server-side
behaviour including remote-config flags.

### Senior

**Q. How would you establish that a piece of code is reachable?**
Statically, build a caller closure from the holding class outward until it meets a manifest-declared
entry point — and treat the result as evidence, not proof, because reflection, dependency injection,
service loading and framework callbacks all create edges with no textual reference. If the class is
itself declared in the manifest, you are done at depth zero. If the closure explodes past a few
hundred classes, it has reached the framework and is telling you nothing; switch to a runtime hook
that either fires or does not, and report the observation window.

**Q. An app contains a `CertificatePinner`. Does it pin?**
Unknown, and the presence of the class is weak evidence. Measured across 14 real applications, 12
presented a pinning surface and 4 actually pinned. Look for configured pin *values*, check
`res/xml/network_security_config.xml` as well as code, and settle it with an intercept attempt —
being careful that the test device's own trust store has not been modified, which invalidates the
test.

**Q. How do you keep a static pipeline from becoming a noise generator in CI?**
Gate only on high-precision rule classes in app scope; keep a persistent ledger so rejected leads
stay rejected; diff against a baseline so the unit of work is the new lead; and track the rejection
rate as a health metric. A gate that fires on keyword rules gets disabled, and a disabled gate is
worse than none.

**Q. What goes in the "limits" section of a static report?**
The artefact hashes and split list; the specific mechanisms not observable from files, each with
whether the app uses it; the lead count, the validated count and the rejected count; and, for any
dynamic observation, the length and coverage of the observation window.

### Staff Engineer

**Q. Design a triage system for static findings across forty applications.**
Rules carry an explicit precision class and a validator, not just a regex. Leads are aggregated by
identity — value for value-rules, construct for API-rules — and scored with published factors so
engineers can argue with the number. Scope classification (app / third-party / generated / unknown)
is the dominant term. Verdicts persist in a ledger keyed on `(rule_id, value)` so re-triage is
incremental. CI gates on new format-class leads in app scope only. Track four metrics: new leads per
release, rejection rate, time-to-verdict, and the share of findings that came from the sweep versus
from a human — the last one detects the team quietly adopting the tool's blind spots.

**Q. Where does static analysis fit against SAST products and MobSF?**
They are stage 5 with a bigger catalogue. They do not do stage 7, and cannot: reachability and
impact need a person who knows what the asset is worth. Use them for breadth, keep your own
catalogue for the rules you can defend, and never ship their output as a report.

**Q. How do you handle an obfuscated target efficiently?**
Reorder the pipeline by what survives. Manifest facts survive everything; framework API names cannot
be renamed; string literals survive renaming but not string encryption. So: manifest first, API-class
rules second, and if strings are encrypted, recover them dynamically before spending time on control
flow — chapter 40 §6.1. Ask the client for `mapping.txt`; it is often given freely and it changes the
economics completely.

### Principal Engineer

**Q. Argue the case for and against making static analysis a release gate.**
For: it catches a specific, recurring, expensive class of mistake — shipped credentials, debuggable
builds, staging endpoints — at the cheapest possible point, and it produces the dependency inventory
a compliance regime will ask for anyway. Against: it over-approximates by construction, so a gate
tuned for recall trains engineers to bypass it, and a gate tuned for precision misses most of what
matters. The resolution is not a threshold; it is rule classes. Gate on format-class rules in app
scope, where precision is high and the fix is unambiguous. Everything else is advisory, tracked as a
queue with an owner and a time-to-verdict metric.

**Q. Your team's report says "no issues found". What do you ask?**
Which artefact, and which splits. What the lead count was before triage, and what the rejection
reasons were. Whether the app registers receivers at runtime, reflects, loads code, or uses remote
config — and if the answer is "we did not check", the report says "the sweep produced no leads",
not "no issues found". Whether anyone opened `assets/` and `res/xml/`. And whether the artefact was
the shipped one or a build we made.

**Q. How do you know your static analysis capability is improving?**
Not by lead count, which measures noise. By the rejection rate falling while the finding count holds
— that is precision improving. By the time from lead to verdict falling — that is the process
working. And by the proportion of findings that the sweep *could not* have produced staying healthy,
because that measures whether humans are still looking at the parts of the system that files cannot
describe.

---

## 11. Common Mistakes

### 11.1 Developer mistakes

| Mistake | Why it happens | What it produces | Fix |
|---|---|---|---|
| Secrets in constants, `strings.xml` or `BuildConfig` | The build needs the value and this is the path of least resistance | A credential in the shipped artefact | Move the operation server-side; if impossible, restrict the key and treat it as public |
| Shipping a debuggable build | A flag set during development and forgotten | Full private-data and memory access over ADB | Build-type configuration plus a release-blocking lint rule |
| Non-production hosts left in an enum or config | Convenience for QA | A map of the internal estate in the public APK (§9.4) | One host per flavour; fail the release build if a QA pattern appears |
| Compose `@Preview` and test fixtures in the release variant | Previews live next to the code they preview | Sample URLs and fake data shipped to users | Keep previews in a `debug` source set |
| `allowBackup="true"` with sensitive local data | It is the historical default | `adb backup`-adjacent extraction paths | Set it false, and use `dataExtractionRules` deliberately |
| Believing obfuscation hides a secret | It makes code unreadable, so it feels protective | A secret that costs ten more minutes to find | Obfuscation raises cost; it never removes data from the artefact |
| Logging objects that contain tokens | `Log.d(TAG, response)` during debugging | Credentials in logcat | Structured logging with redaction; strip logs in release |

### 11.2 Pentester mistakes

**Pasting scanner output into a report.** The defining mistake of the discipline. Measured
counter-examples: 132 of 132 high-confidence hits false on a real browser; 15 of 17 high-confidence
leads false on a real commercial app. The output is a queue, not a report.

**Reporting a string as a finding.** "Hardcoded API key found" with no statement of what the key
authorises, whether the code is reachable, or whether the vendor intends the key to ship. Severity is
question four of four, never question one.

**Confusing confidence with severity.** They are different axes and no tool can produce the second.
`static-sweep.py` deliberately has no severity column, and if you add one you will start believing
it. §9.4's best lead sat in the MEDIUM band under seven documentation URLs.

**Analysing the wrong artefact.** A build you compiled from source, a debug flavour, a file from an
APK-mirror site, or `base.apk` without its splits. Pull from the device, hash it, list every split.

**Declaring code unreachable.** A static closure cannot prove absence of a path. The defensible
sentence is "no static path found, and the method did not execute during N minutes of use covering
X, Y and Z".

**Reporting a clean sweep as a clean app.** The sweep did not examine runtime receivers, native
registrations, reflection targets, loaded code or the server. Say so, in a section, with the app's
specific usage of each mechanism.

**Skipping `res/xml/` and `assets/`.** The network security config, FileProvider paths, backup rules,
accessibility config and device-admin policy are five finding classes in files the manifest only
points at. Assets are undecodable by any tool and are the first place a packer hides.

**Trusting one decompiler.** jadx reported 17 errors on a 2,783-class app and still wrote files for
those classes. Confirm anything load-bearing in Smali.

**Testing the trust store on a device whose trust store is modified.** On this repository's test
device, an interception CA has been promoted into the *system* store, so a successful intercept
proves nothing about user-CA trust. Run `mount | grep cacerts` before any trust claim.

### 11.3 Mistakes in the tooling itself — five real bugs from building this chapter

Every tool in this chapter had a bug that produced *plausible wrong output*, which is the dangerous
kind. They are recorded because you will write the same ones.

**1. `\b` in an awk regex is a backspace character, not a word boundary.**
`/<activity\b/` matched nothing, so the entry-point list came out empty, so the reachability closure
reported "no path to any entry point" for a class that was declared in the manifest three lines
further down. POSIX awk has no word-boundary escape; gawk spells it `\y`. Anchor on a character
class instead: `/<activity([ \t>\/]|$)/`.

**2. `${hit%%:*}` splits a Windows path at the drive letter.**
`grep` prints `path:line:text`. On `C:/Users/…` the first colon is the drive, so the path became
`C`, which classified as `unknown`, which cascaded into every downstream section. The fix is a
regex that tolerates an optional drive prefix.

**3. `grep -c … || echo 0` prints two lines when there is no match.**
`grep -c` prints its own `0` *and* returns non-zero, so the fallback fires too. `[ "0\n0" -gt 0 ]` is
a syntax error rather than a false, and the whole loop failed noisily. Pipe through `head -1`.

**4. A regex without a validator reports identifiers as secrets.**
The base64 rule matched `actionModeCloseContentDescription` and ninety similar resource names — 33
characters of pure letters is a legal base64 alphabet. The hostname rule matched
`kotlin.jvm.internal.Intrinsics` and `androidx.core.internal.view.menu`: **75 spurious leads**,
because a Java package name and a hostname are both dotted lowercase labels. Every shape rule needs
a validator, and the validators removed 3,591 of 7,346 raw hits on one tree.

**5. Matching `/res/` anywhere in a path classifies code as a resource.**
`androidx/core/content/res/ResourcesCompat.java` is code. An early version of the classifier called
it a resource, which silently changed the score of every lead in the report. Anchor to the tree roots
your tools actually produce: `res/`, `resources/res/`, `assets/`.

> **🧠 Mental Model**
> All five bugs shared one property: **the tool kept running and produced output that looked right.**
> That is the failure mode to design against. Print your counts — files scanned, hits, kills,
> demotions — every run, because a count that suddenly changes is how you notice a classifier broke.

### 11.4 Reverse engineer mistakes

**Reading decompiled Java as if it were source.** Local names like `bArrDecode` are jadx's
invention. Quoting them as the developer's identifiers is a small, visible credibility leak.

**Starting with control flow instead of strings.** On an obfuscated target, strings are the seeds
from which naming regrows; control-flow recovery before string recovery is expensive and usually
wasted. Chapter 40 §6.1 Phase 4.

**Assuming no `Java_*` symbol means no JNI.** It means `RegisterNatives`, which is the normal case
for anything deliberately hidden.

**Patching a check that the compiler inlined.** Measured in this repository: `lc_verify_signature`
was patched to `return 1`, verified returning 1, and the dependent function still refused, because
clang had inlined the check and the patched copy was called by nothing. Verify the *effect*, not the
patch.

**Treating high entropy as proof of encryption.** Compressed data, images, archives and model weights
are all high entropy. The signal is entropy plus a small DEX plus an unfamiliar `Application` class.

**Forgetting that each DEX has its own string table.** Indices repeat across `classes.dex`,
`classes2.dex` and `classes3.dex`. An index without a DEX name is ambiguous.

---

## 12. Hands-on Labs

Four labs, in order. Lab 1 teaches the pipeline; lab 2 teaches the discipline that makes it worth
anything; lab 3 teaches the limits; lab 4 is the CTF that will fail you for reporting something you
did not validate.

| Lab | What you do | Why it is here |
|---|---|---|
| [Lab 01 — Your first complete static pass](labs/lab-01-first-static-pass.md) | Pull a real APK from a device and run all eight stages, ending in one written, validated finding | The whole method, once, on something real |
| [Lab 02 — The false-positive gauntlet](labs/lab-02-false-positive-gauntlet.md) | Work a queue of leads in which most are wrong, and reject them correctly, with reasons | The skill this chapter exists to teach |
| [Lab 03 — Mapping the blind spots](labs/lab-03-blind-spots.md) | Measure, on a live app, how much of the real behaviour your static pass could not see | So you never write "clean sweep" and mean "clean app" |
| [Lab 04 — CTF: the honest report](labs/lab-04-ctf-honest-report.md) | Produce a report from a prepared tree. Points are deducted for unvalidated findings | Because the failure mode being tested is over-claiming, not under-finding |

**Before you start**, produce the tooling once:

```bash
# host
python3 -B scripts/static-sweep.py --print-catalogue | less
bash scripts/validate-lead.sh --help
```

All four labs use the same two scripts and no others. Lab 3 additionally uses
[`scripts/blindspot-recorder.js`](scripts/blindspot-recorder.js) with Frida.

**Targets.** Labs 1 and 3 use a public, deliberately vulnerable training application, and the lab
text names alternatives if you do not have that one. Lab 2 ships its own tree in the lab file, so it
needs no target at all. Lab 4 is self-contained.

> **⚠️ Warning**
> Only run any of this against applications you own or have written permission to test. On a shared
> or daily-driver device, pull and analyse — do not install, broadcast, or modify state. Every
> command in these labs that touches a device is read-only unless the lab says otherwise in bold.

---

## 13. Summary

### 13.1 Key points

- **Static analysis observes what is possible; dynamic analysis observes what happened.** The skill
  is knowing which question belongs to which, not preferring one.
- **The pipeline is: acquire, unpack, decompile, enumerate, sweep, triage, validate, report** — with
  blind-spot recording running throughout. There is no arrow from sweep to report.
- **A hit is not a lead and a lead is not a finding.** Measured on real trees: 7,346 raw hits
  collapsed to 9 leads; 16,836 collapsed to 168.
- **Validation is the chapter.** A lead becomes a finding only when you can answer: is it real, is it
  reachable, who can reach it, and what does reaching it get them. Severity is the fourth question.
- **Expect to be wrong most of the time in the high-confidence band.** 132 of 132 high-confidence
  hits false on a real browser; 15 of 17 false on a real commercial app. This is normal and it is not
  a defect in the tool.
- **The best lead is often not the highest-confidence one.** In the measured run, seven documentation
  URLs outranked an enumeration of thirteen internal environments.
- **Static analysis cannot see** runtime-registered receivers (69% of the broadcast surface on a real
  device), `RegisterNatives` bindings, reflection, dynamically loaded DEX, or anything the server
  decides. A clean sweep is not a clean application, and the report must say so.
- **Classify by package before you read anything.** 136 of 137 `password` hits on a small app were
  framework code.
- **Confirm on the platform where you can.** `dumpsys package … flags=` beats any file's claim about
  itself.
- **Never fabricate certainty.** "No static path found" is a defensible sentence; "unreachable" is
  not.

### 13.2 Mind map

```mermaid
mindmap
  root((Static Analysis))
    Pipeline
      1 Acquire
        pm path -- ALL splits
        sha256 + apksigner
      2 Unpack
        unzip -l before decompiling
        assets and ABIs
      3 Decompile
        jadx to understand
        smali to be certain
        aapt2 for the platform view
        string table for literals
      4 Enumerate
        entry points
        packages -- app vs library
        dependency inventory MASVS-CODE
      5 Sweep
        format / api / shape / keyword
      6 Triage
        hits become leads
        aggregate, validate, weight by scope
        every lead gets a NEXT STEP
      7 Validate
        real? reachable? who? so what?
        the kill list
        the ledger of rejections
      8 Report
        hash, evidence, honest severity
        limits section
    Blind spots
      runtime receivers 69 percent
      RegisterNatives
      reflection
      dynamic DEX
      server side
    False positives
      132 of 132 -- chapter 33
      15 of 17 -- this chapter
      12 of 14 pinning surface, 4 pin -- chapter 36
      136 of 137 password hits are library code
    Boundaries
      manifest -> chapter 32
      libraries -> chapter 17
      obfuscation -> chapter 40
      container -> chapter 10
      report template -> chapter 80
```

### 13.3 Condensed cheat-sheet

| Situation | Command or decision |
|---|---|
| New APK | `pm path` (all splits) → `sha256sum` → `apksigner verify -v --print-certs` |
| Before decompiling | `unzip -l` — DEX count, ABIs, biggest assets |
| Decompile | `jadx -d out` + `apktool d` + `aapt2 dump xmltree` |
| Which code is the app's? | Manifest `package=`, then classify every path |
| Sweep | `python3 -B scripts/static-sweep.py ./out --app-package PKG` |
| Big app, first pass | add `--files app` |
| Audit the filter | add `--show-suppressed` |
| Work a lead | `bash scripts/validate-lead.sh --tree ./out --value 'X' --reach` |
| Confirm a manifest flag | `adb shell dumpsys package PKG \| grep flags=` |
| Confirm reachability | A Frida hook that fires, plus the observation window |
| Measure the blind spots | `frida -U -f PKG -l scripts/blindspot-recorder.js --no-pause` |
| Keyword hit in `androidx/` | Reject |
| Base64 hit | Decode before anything else |
| Cleartext URL that is a namespace | Reject |
| Empty sweep | "no leads above threshold" — never "no issues found" |

### 13.4 Quick revision

- Eight stages, in order — name them.
- What is the difference between a hit, a lead and a finding?
- Which of the four questions produces severity?
- Name five things static analysis cannot see.
- What fraction of the broadcast surface is registered at runtime, and where does that number come
  from?
- What did the leak hunter's 132 high-confidence hits turn out to be?
- How many of 14 apps presented a pinning surface, and how many pinned?
- Why is `--files app` a different flag from `--scope app`?
- Why does the sweeper have no severity column?
- What must a report say when the sweep finds nothing?
- Why do you read the Smali when jadx already gave you Java?
- What does a `JNI_OnLoad` with no `Java_*` symbols mean?
- Which survives R8: a framework API name, a string literal, or a method name?
- What is the correct sentence when a static closure finds no path to an entry point?

---

## 14. References

Annotated links live in [`references/README.md`](references/README.md), including the
related-chapters table. The essentials:

**AOSP source** (file paths are stable; no line numbers are quoted anywhere in this chapter)

- `frameworks/base/core/java/android/content/pm/parsing/ParsingPackageUtils.java` — the modern
  manifest parser; where `exported` defaults are computed
- `frameworks/base/core/java/android/content/pm/PackageParser.java` — the historical parser
- `frameworks/base/libs/androidfw/ResourceTypes.cpp` — binary XML and the resource string pool
- `art/libdexfile/dex/dex_file.cc`, `art/libdexfile/dex/dex_file_verifier.cc` — DEX structure and the
  checks the runtime performs on a header you are also parsing
- `libcore/dalvik/src/main/java/dalvik/system/DexFile.java` — the loading API, including in-memory
- `art/runtime/jni/java_vm_ext.cc` — `JavaVMExt::RegisterNatives`, the source of the JNI blind spot
- `art/runtime/class_linker.cc` — how a `native` method finds its implementation

**Official documentation**

- Android Developers — *Application Signing*, *App Bundles and split APKs*, *Network security
  configuration*, *R8 shrinking and obfuscation*
- `source.android.com/docs/core/runtime/dex-format` — the DEX format reference

**OWASP**

- MASVS v2 — MASVS-CODE (dependency inventory with versions), MASVS-STORAGE, MASVS-CRYPTO,
  MASVS-NETWORK, MASVS-PLATFORM, MASVS-RESILIENCE
- MASTG — the static analysis procedures assume the methodology in this chapter

**Tools**

- `jadx`, `apktool`, `baksmali`/`smali`, `aapt2`, `apksigner`, `dexdump`, `apkid`, `semgrep`, MobSF

**Related chapters**

| Chapter | Relationship |
|---|---|
| [10-APK-Internals](../10-APK-Internals/README.md) | The container this chapter opens |
| [12-DEX-Internals](../12-DEX-Internals/README.md) | The bytecode format underneath every rule |
| [04-Java](../04-Java/README.md) | `dump-strings.py`: the string table, when you have no decompiler |
| [17-Libraries](../17-Libraries/README.md) | Stage 4's dependency inventory — MASVS-CODE |
| [32-Manifest](../32-Manifest/README.md) | Manifest auditing; the entry-point list |
| [33-Storage](../33-Storage/README.md) | The 132-of-132 false-positive measurement |
| [36-CertificatePinning](../36-CertificatePinning/README.md) | The 12-of-14 pinning-surface measurement |
| [29-BroadcastReceivers](../29-BroadcastReceivers/README.md) | The 69% runtime-registration measurement |
| [40-Obfuscation](../40-Obfuscation/README.md) | What to do when the sweep returns nothing readable |
| [53-Frida](../53-Frida/README.md) | The dynamic half of every unanswered question |
| [80-Appendix](../80-Appendix/README.md) | The report template and the severity rubric |

[51-DynamicAnalysis](../51-DynamicAnalysis/README.md), [55-MobSF](../55-MobSF/README.md),
[56-JADX](../56-JADX/README.md) and [68-ReverseEngineering](../68-ReverseEngineering/README.md) are
referenced in the text as topics, and are all now written.

