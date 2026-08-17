# 55 — MobSF

> After this chapter you can run MobSF across a corpus of applications in minutes, read its report as
> a queue of leads rather than a list of findings, state precisely which of its sentences you may
> repeat to a client and which you must check first, name the six classes of thing it structurally
> cannot see, and defend or reject every line of its output — including the lines where it is wrong
> in the dangerous direction.

**Prerequisites:** [52-StaticAnalysis](../52-StaticAnalysis/README.md),
[32-Manifest](../32-Manifest/README.md),
[10-APK-Internals](../10-APK-Internals/README.md),
[36-CertificatePinning](../36-CertificatePinning/README.md),
[17-Libraries](../17-Libraries/README.md),
[51-DynamicAnalysis](../51-DynamicAnalysis/README.md)

**Applies to:** MobSF 3.x and 4.x. The analysis targets every Android version; the *report schema*
is version-dependent and this chapter says so repeatedly, because that dependence is the source of
a whole class of confusion.

**Measured on:** analysis host, Windows 11, Python 3.13.3, `aapt2`/`apksigner` from build-tools
35.0.1, jadx 1.5.3. Device present but not required: `i9000S`, Android 13 / API 33, **not rooted,
no frida-server** — verified with `adb devices -l && adb shell getprop ro.product.model &&
adb shell getprop ro.build.version.sdk`. No claim in this chapter depends on the device.

> **⚠️ Warning — read §1.6 before you read anything else**
> **MobSF was not run while this chapter was written.** Docker's Linux engine does not start on this
> machine. Every listing in this chapter is therefore labelled: **`MEASURED`** (produced by a tool
> that really ran, here, on a real artefact) or **`EXPECTED SHAPE`** (what MobSF's own documentation
> and report schema say the output looks like, written out so you can recognise it). There is no
> invented scan transcript anywhere in this chapter, and §1.6 explains exactly what that costs you.

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

Imagine you are handed twenty sealed boxes and told that one of them contains something dangerous.
You have a week. You could open each box carefully, catalogue every component, and reason about what
it does — and you would get through three boxes.

Or you could build a machine that shakes each box, weighs it, X-rays it, and prints a page per box
saying "this one rattles, this one is unusually heavy, this one contains something metal". The
machine tells you nothing about danger. It tells you where to spend your week.

That machine is what MobSF is. It is not an assessment. It is a **census**.

Before automated mobile scanners existed, the first day of every mobile engagement looked the same
and was almost entirely mechanical: unzip the APK, decode the manifest, list the components, list
the permissions, decompile, grep for URLs, grep for keys, check the signature, look at the native
libraries. Every tester in the world did the same seven hours of work, by hand, badly and
inconsistently, before the actual analysis could start.

> **📖 Definition**
> **MobSF** — the *Mobile Security Framework* — is an open-source application that performs
> automated **static analysis** of mobile application artefacts (Android APK/AAB/source,
> iOS IPA/source, Windows APPX), optional **dynamic analysis** on an instrumented Android device or
> emulator, and exposes both through a **web interface** and a **REST API**. Its output is an HTML
> or JSON report containing an inventory, a rules-based finding list, and a numeric score.

Three words in that definition do the work: *automated*, *rules-based*, and *inventory*. Everything
good about MobSF comes from the first and the third. Everything that goes wrong comes from people
reading the second word as if it said *assessment*.

### 1.2 What would break without it — the honest case FOR MobSF

This chapter is going to spend a lot of pages on MobSF's limits, so it is important to start by
being clear that they are the limits of a genuinely useful tool, not excuses for a bad one. Take
MobSF away and four things get worse:

| What you lose | Why it matters |
|---|---|
| **Breadth in minutes** | A complete component, permission, endpoint, library and pattern inventory for an application you have never seen, in the time it takes to make coffee. Doing that by hand is seven hours and you will miss something |
| **Corpus work** | Twenty APKs, one command, one comparable report each. This is the thing MobSF does that nothing else in this repository does, and §8.3 is built entirely around it |
| **A checklist you did not have to remember** | It will check `allowBackup`, the signature scheme, the `<pin-set>`, the exported components, the tracker list and forty other things every single time, including the day you are tired |
| **A shared vocabulary with the client** | Your client's security team runs MobSF too. Being able to say "your scan flagged fourteen items; here is why nine of them are not findings" is a **more** valuable conversation than never mentioning it |

That last row is under-appreciated. [STYLE-GUIDE §7](../STYLE-GUIDE.md) defines senior as being able
to *"explain why an automated tool's finding is a false positive"*. You cannot do that for a tool you
refuse to run.

> **🧠 Mental Model**
> MobSF is a **metal detector with a very loud speaker**. It is genuinely excellent at telling you
> where the metal is, it covers the whole beach in an hour, and it will beep at a bottle cap and a
> Roman coin with exactly the same enthusiasm. [52-StaticAnalysis](../52-StaticAnalysis/README.md)
> teaches digging. This chapter teaches which beeps to dig at, and what to say to the person who
> printed out the beeps and called it a treasure map.

### 1.3 The one sentence that decides whether you use it well

Here it is, and the rest of the chapter is elaboration:

> **MobSF implements stages 1 through 5 of a static-analysis pipeline, about half of stage 6, and
> none of stage 7.**

Those stage numbers are [52-StaticAnalysis §1.5](../52-StaticAnalysis/README.md#15-a-first-look-at-the-whole-thing)'s,
and they are the spine of this chapter:

```
1. ACQUIRE     get the exact artefact the user gets, and hash it        MobSF: yes
2. UNPACK      open the container; know what is inside                  MobSF: yes
3. DECOMPILE   produce something readable, from more than one tool      MobSF: yes (one tool)
4. ENUMERATE   list what exists: components, classes, endpoints, libs   MobSF: yes, excellently
5. SWEEP       apply the rule catalogue; produce hits                   MobSF: yes
6. TRIAGE      collapse hits into leads; rank them; assign a next step  MobSF: PARTLY
7. VALIDATE    confirm or kill each lead, in writing                    MobSF: NO
8. REPORT      findings with evidence, honest severity, and the fix     MobSF: NO
0. THROUGHOUT  record what you could not see                            MobSF: NO
```

51-DynamicAnalysis' tool-tier table already says this in one line — MobSF rates **5 for breadth**
with the note *"**No stage 6.** It reports observations; correlation and coverage are yours"* — and
52's says *"**No stage 7.** It reports every exported component at one severity and cannot know what
a component does"*. The two chapters disagree by one stage number, and the disagreement is
instructive rather than an error: MobSF *does* aggregate and group, which is half of triage, and it
*does not* rank by anything that predicts analyst value, which is the other half. This chapter's
position is stated exactly once so it can be argued with: **half of 6, none of 7.**

**Stage 7 is where a finding is made.** A tool that stops before it has produced leads, and leads are
not findings. That is not a criticism of MobSF any more than "a metal detector does not dig" is a
criticism of a metal detector.

### 1.4 What this chapter owns

Eighteen chapters in this repository mention MobSF, and almost all of them say a version of *"treat
its output as a lead"*. This chapter is where that sentence is cashed out. Specifically, it owns:

1. **The tool** — what MobSF actually does to an APK, stage by stage, in enough detail that you can
   predict its output before you run it.
2. **The report** — every section, what generated it, and what it is worth.
3. **The blind spots** — the six classes of thing no report of this kind can contain, with the
   numbers this repository measured for each.
4. **Severity, and why MobSF's is not yours** — the CVSS in a MobSF finding is rule metadata; it is
   the same number for every application that ever matched the rule.
5. **The API and CI** — the place MobSF is genuinely better than a human, and the correct way to
   consume it.
6. **The rewrite** — turning a scanner line into a defensible report entry, and turning the other
   thirty into a ledger of rejections with reasons.

> **⚠️ Warning — what this chapter deliberately does NOT do**
> It does not re-teach manifest analysis ([32](../32-Manifest/README.md)), pinning
> ([36](../36-CertificatePinning/README.md)), library inventory ([17](../17-Libraries/README.md)),
> the APK container ([10](../10-APK-Internals/README.md)), WebView
> ([43](../43-WebView/README.md)), crypto ([34](../34-Cryptography/README.md)) or the static
> pipeline itself ([52](../52-StaticAnalysis/README.md)). When a MobSF finding lands in one of
> those domains, this chapter tells you which chapter validates it and stops. Its scripts
> deliberately do not re-implement `manifest-audit.py`, `pinning-surface.py`, `lib-inventory.sh` or
> `static-sweep.py`; they *call out to* the discipline those tools embody.

### 1.5 A first look at the whole thing

```
        THE ARTEFACT                MobSF                     YOU
        ------------                -----                     ---
        base.apk        ------>   unzip, hash        ------>  is this the right artefact?
                                  decompile                   are there splits?
                                  parse manifest     ------>  32-Manifest validates each row
                                  match patterns     ------>  each hit is a HYPOTHESIS
                                  read the ELF       ------>  15/16/57 own the native side
                                  score it           ------>  ignore the score
                                       |
                                       v
                                  a report of
                                  N observations
                                       |
                                       v
                                                     ------>  STAGE 7: confirm or kill each one
                                                     ------>  join findings across sections
                                                     ------>  name the asset; assign severity
                                                     ------>  write the blind-spot statement
                                                     ------>  publish the ledger of rejections
                                       |
                                       v
                                                              M findings, where M << N
```

On this chapter's worked example, **N was 39 and M was 8** — and two of the eight were things MobSF
never mentioned at all. Those numbers are measured, not illustrative, and §9.3 shows the arithmetic.

### 1.6 Installation reality — MobSF was not run here

This section exists because the alternative was to invent a scan transcript, and a chapter about not
trusting unverified output cannot be built on unverified output.

**What was checked, in order, and what each check returned.**

```bash
# host - is MobSF installed as a Python package?
python -m pip show mobsf
# WARNING: Package(s) not found: mobsf

# host - is a MobSF server already listening on its default port?
curl -s -m 3 -o /dev/null -w "%{http_code}" http://127.0.0.1:8000/
# 000        (no listener; curl exit code 7, connection refused)

# host - is Docker available? The image is the documented install route.
docker --version
# Docker version 28.0.4, build b8034c0

docker info --format '{{.ServerVersion}}'
# request returned 500 Internal Server Error for API route and version
# http://%2F%2F.%2Fpipe%2FdockerDesktopLinuxEngine/v1.48/info
```

Docker Desktop is installed and its Windows-side processes run. The **Linux engine does not start**:

```bash
# host
wsl -l -v
#   NAME              STATE           VERSION
# * Ubuntu            Stopped         2
#   docker-desktop    Stopped         2       <- the engine's own distro, never starts
#   kali-linux        Stopped         2
```

Docker Desktop was launched and given roughly forty minutes. `docker-desktop` stayed `Stopped` and
every API call kept returning `500`. Separately, the disk is at **94% (31 GB free of 511 GB)**, and
`opensecurity/mobile-security-framework-mobsf` is a multi-gigabyte image; pulling it would be a
large, slow download on a machine that has no room to spare, in service of a tool whose output this
chapter is going to tell you to distrust anyway.

**So: MobSF has not been run, and this chapter does not pretend otherwise.**

#### What that costs, stated plainly

| Cost | Mitigation used here |
|---|---|
| No real MobSF report to quote | Two **fixtures** in MobSF's report shape ship in `examples/`. Every *value* in them is a real measurement of a real APK; every *structural* element is a reconstruction, and each file says so in its first key |
| Cannot verify MobSF's exact rule identifiers | Rule ids are named as **plausible reconstructions**, never as fact. Where this chapter needs a rule to make a point, it makes the point about the rule's *class*, which is stable |
| Cannot confirm the current JSON schema | §3.12 covers schema drift as a first-class topic instead. The shipped parser is deliberately tolerant of three known shapes and **prints which one it recognised** |
| Cannot demonstrate the dynamic analyser | §7 describes it from its documentation, labelled `EXPECTED SHAPE`, and spends its length on the question that actually matters: what you would cross-check with it |

#### What was measured instead, and it is not nothing

Everything below really ran, on this machine, on 2026-08-12, against two real APKs:

| Measurement | Tool | Where |
|---|---|---|
| Manifest, components, protection levels of both APKs | `aapt2 dump xmltree` (build-tools 35.0.1) | §5.3, §9.3, §9.4 |
| Decompilation: 234 and 1,995 `.java` files; `finished with errors, count: 8` on v1.0 | jadx 1.5.3 CLI | §6.3, §9.4 |
| Signing certificate: `CN=Android Debug` on both, different keys | `apksigner verify -v --print-certs` | §9.3 |
| **The pinning surface of both APKs** | [`36-CertificatePinning/scripts/pinning-surface.py`](../36-CertificatePinning/scripts/pinning-surface.py) | §5.3 |
| **Automated manifest audit of the target** | [`32-Manifest/scripts/manifest-audit.py`](../32-Manifest/scripts/manifest-audit.py) | §5.6 |
| **Report validation: 39 items → 17 corroborated → 8 findings** | this chapter's [`scripts/mobsf-validate.py`](scripts/mobsf-validate.py) | §9.3 |
| **Corpus triage across two applications** | this chapter's [`scripts/mobsf-triage.py`](scripts/mobsf-triage.py) | §9.5 |

Both of this chapter's scripts run **offline, against a saved JSON report**, precisely so that a
reader without MobSF is not blocked. That was a design constraint imposed by this failure and it
turned out to be the right design anyway: in real work you receive a JSON report far more often than
you receive a server.

> **🔍 Pentester's Note**
> This is the ordinary condition of the job, not an unusual one. You will be handed a MobSF report
> by a client, a colleague or a CI pipeline far more often than you will run MobSF yourself, and the
> skill that matters is reading somebody else's report against the artefact. That is exactly what
> `mobsf-validate.py` does, and it is the reason it takes `--report` and `--apk` as two separate
> arguments rather than doing the scan itself.

#### Installing it, for when you can

```bash
# host - the documented route, and the one to prefer. Large image; check disk first.
docker pull opensecurity/mobile-security-framework-mobsf:latest
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest
# then: http://127.0.0.1:8000
```

```bash
# host - from source, when you need to edit rules or run the dynamic analyser
git clone https://github.com/MobSF/Mobile-Security-Framework-MobSF.git
cd Mobile-Security-Framework-MobSF
./setup.sh          # Linux / macOS
.\setup.bat         # Windows
./run.sh            # or run.bat
```

Recent 4.x releases also publish to PyPI, which is the lightest route when it works:

```bash
# host - inside a virtualenv, always. MobSF, Frida and Objection have conflicting deps.
python3 -m venv ~/venv/mobsf && . ~/venv/mobsf/bin/activate
pip install mobsf
mobsf
```

**The API key** is printed on startup and shown in the web UI's API documentation page. Everything
in §8.2 needs it. Set it once:

```bash
export MOBSF_API_KEY='<the key>'
export MOBSF_SERVER='http://127.0.0.1:8000'
```

> **⚠️ Warning — before you upload a client's APK anywhere**
> A MobSF instance holds every artefact ever uploaded to it, decompiled, on disk, indefinitely. A
> shared or internet-reachable instance is therefore a repository of your clients' unreleased
> binaries, guarded by one static API key. §5.11 treats this as a first-class operational-security
> problem, because it is one, and because the fastest way to lose an engagement is to put a
> pre-release banking APK on a scanner somebody else administers.

### 1.7 How to read the rest of this chapter

- **§2 and §3** are the tool: what it does, in what order, and why each stage produces what it does.
- **§4** walks MobSF's own source tree and — more importantly — the AOSP code MobSF is *trying to
  predict*, because every divergence between the two is a false positive or a miss.
- **§5** is the chapter's centre of gravity: the false-positive taxonomy, the pinning case worked
  with real numbers, the false *negative* nobody talks about, and honest severity.
- **§6, §7, §8** are the three angles the style guide requires, and each is written as "how do I
  check what the report told me".
- **§9** is five graded worked examples, three of which are real runs with real numbers.
- **§12** is four labs, and lab 02 is the one that matters: run a scan, validate every finding by
  hand, and publish the survival rate.

---

## 2. High-Level Architecture

### 2.1 What happens when you upload an APK

```mermaid
flowchart TD
    subgraph Client["Your machine"]
        U["APK / AAB / IPA / zipped source"]
    end

    subgraph Server["MobSF server process - a Django application"]
        UP["upload handler<br/>hash, store, dedupe by hash"]
        Q{"already scanned<br/>this hash?"}
        CACHE[("scan database<br/>SQLite by default")]
        UNZ["unzip + inventory<br/>entries, sizes, types"]
        DEC["decompile<br/>DEX to Java, AXML to XML,<br/>ARSC to resources"]
        MAN["manifest analyser<br/>rule list over the parsed XML"]
        CERT["certificate analyser<br/>signature schemes, DN, digests"]
        CODE["code analyser<br/>regex + AST-ish rules over<br/>the decompiled tree"]
        SEC["secrets scanner<br/>shape rules over strings"]
        BIN["binary analyser<br/>ELF hardening flags"]
        NET["URL / domain / tracker<br/>extraction and lookup"]
        SCORE["scorecard<br/>counts x rule metadata"]
        REP["report: HTML, PDF, JSON"]
    end

    subgraph Out["What you get"]
        HTML["web page"]
        JSON["report_json"]
    end

    U -- "POST /api/v1/upload" --> UP
    UP --> Q
    Q -- "yes" --> CACHE
    Q -- "no" --> UNZ
    UNZ --> DEC
    DEC --> MAN & CODE & SEC & BIN & NET
    UNZ --> CERT
    MAN & CERT & CODE & SEC & BIN & NET --> SCORE
    SCORE --> CACHE
    CACHE --> REP
    REP --> HTML & JSON

    style U fill:#f9d0d0
    style SCORE fill:#f9e0c0
    style CODE fill:#f9e0c0
```

Read that diagram in three parts.

**The red box is attacker-controlled.** The APK is a file written by the person whose application you
are analysing. It flows straight into an unzipper, a DEX parser, an AXML parser and a decompiler,
all of which are large programs written in memory-safe-ish languages that nonetheless have to make
sense of deliberately malformed input. §2.6 and §5.11 return to this.

**The two amber boxes are where every argument you will ever have with a client originates.** The
code analyser produces hits from patterns, and the scorecard converts counts of those hits into a
number that looks like a risk assessment and is not one.

**The `Q` diamond is why two people scanning the same file get different reports.** MobSF keys its
cache on the file hash. Upload the same APK twice and the second "scan" is a database read — with
the *old* rule set's results, from whenever it was actually scanned. Upgrade MobSF and re-upload,
and you get the cached report, not a re-analysis, until you delete the scan. This is the single most
common cause of the "why do two runs differ" question in §3.12 and the FAQ.

### 2.2 Where MobSF sits inside 52's pipeline

```mermaid
flowchart LR
    subgraph MobSF["What MobSF does for you"]
        direction TB
        S1["1 ACQUIRE<br/>hash, store"]
        S2["2 UNPACK<br/>entries, sizes"]
        S3["3 DECOMPILE<br/>one decompiler"]
        S4["4 ENUMERATE<br/>components, perms,<br/>libs, endpoints"]
        S5["5 SWEEP<br/>the rule catalogue"]
        S6a["6a GROUP<br/>hits collapsed per rule"]
    end

    subgraph Yours["What is still entirely yours"]
        direction TB
        S6b["6b RANK<br/>by analyst value,<br/>not by rule metadata"]
        S7["7 VALIDATE<br/>confirm or KILL,<br/>in writing"]
        S8["8 REPORT<br/>evidence, honest<br/>severity, the fix"]
        S0["0 BLIND SPOTS<br/>recorded continuously"]
    end

    S1 --> S2 --> S3 --> S4 --> S5 --> S6a
    S6a -- "the report" --> S6b --> S7 --> S8
    S0 -.-> S8

    style S6b fill:#f9e0c0
    style S7 fill:#f9d0d0
    style S0 fill:#f9e0c0
```

The red box is the one MobSF does not enter, and the reason is not laziness on its authors' part: it
is **structurally impossible for a file-reading tool**. Stage 7 asks "who can reach this, and what do
they get" — and the answer requires knowing what the application is *for*, which is information that
exists in the client's head and nowhere in the artefact.

Note also the two amber boxes, which are the ones people get wrong in a subtler way. MobSF *does*
group: forty `Log.d` calls become one code-analysis entry with forty file references. What it does
not do is **rank by anything that predicts where your time pays**, because its ordering comes from
per-rule severity and CVSS constants. §3.9 shows exactly how that number is built, and
[`scripts/mobsf-triage.py`](scripts/mobsf-triage.py) is this chapter's answer to it.

### 2.3 The report, as a data structure

You will spend more time reading MobSF's JSON than its web page, so it is worth having a mental
model of its shape rather than scrolling.

```mermaid
classDiagram
    class Report {
        +string package_name
        +string sha256
        +string version_name
        +string min_sdk / target_sdk
        +float average_cvss
    }
    class Inventory {
        +list activities / services
        +list receivers / providers
        +list exported_activities
        +map browsable_activities
        +map permissions
        +list libraries
    }
    class ManifestAnalysis {
        +list manifest_anal
        +map manifest_summary
    }
    class CodeAnalysis {
        +map findings
        +map summary
    }
    class CertificateAnalysis {
        +string certificate_info
        +list certificate_findings
    }
    class BinaryAnalysis {
        +list per .so : nx, pie, canary, relro
    }
    class Extracted {
        +list urls / domains / emails
        +list secrets
        +list firebase_urls
        +map trackers
    }
    class AppSec {
        +int security_score
        +list high / warning / info
        +list secure / hotspot
    }

    Report *-- Inventory
    Report *-- ManifestAnalysis
    Report *-- CodeAnalysis
    Report *-- CertificateAnalysis
    Report *-- BinaryAnalysis
    Report *-- Extracted
    Report *-- AppSec
    AppSec ..> ManifestAnalysis : restates
    AppSec ..> CodeAnalysis : restates
    AppSec ..> CertificateAnalysis : restates
```

Two relationships in that diagram are the whole of §3.9 and half of §5.

**`AppSec` restates the other sections.** The scorecard is not a seventh source of findings; it is a
summary of the previous six. On this chapter's worked example, **11 of 39 normalised report items
were scorecard restatements** — 28% of the "findings" in the report were the report summarising
itself. Counting them separately is how a 12-item scan becomes a 39-item "report", and it is done
constantly, usually unintentionally.

**`Inventory` and `ManifestAnalysis` are different things and only one of them is opinionated.** The
inventory — the component lists, the permission map, the browsable-activity map — is MobSF at its
best: a factual census you can use directly, subject only to the caveats in §4.6. The analysis is a
rule list, and every entry in it is a hypothesis.

### 2.4 The REST API, as a conversation

```mermaid
sequenceDiagram
    autonumber
    participant S as your script
    participant M as MobSF (HTTP, port 8000)
    participant D as scan database

    S->>M: POST /api/v1/upload  (multipart: file)<br/>Authorization: <api_key>
    Note over S,M: transport: HTTP. The key is a bare header value,<br/>not a Bearer token.
    M->>M: hash the upload, store it
    M-->>S: {hash, scan_type, file_name}

    S->>M: POST /api/v1/scan  (hash, scan_type, file_name)
    M->>M: unzip, decompile, run every analyser
    M->>D: persist the result, keyed by hash
    M-->>S: the full report (JSON)

    S->>M: POST /api/v1/report_json  (hash)
    M->>D: read
    M-->>S: the full report (JSON)

    opt cleanup - do this, especially on a shared instance
        S->>M: POST /api/v1/delete_scan  (hash)
        M->>D: delete
        M-->>S: {"deleted": "yes"}
    end
```

Four things about that sequence matter in practice.

**`/scan` returns the report as well.** You do not strictly need the `report_json` call after a fresh
scan — but you *do* need it for anything already in the database, which is why
[`scripts/mobsf-triage.py`](scripts/mobsf-triage.py) calls both. The extra round trip costs nothing
and makes the code work for cached and fresh scans identically.

**`/scan` is synchronous and can take a very long time.** A 90 MB application with twelve DEX files
will hold that connection open for many minutes. Any client that sets a 60-second timeout will fail
on exactly the applications you most want to scan. The shipped client defaults to a 900-second
timeout, and says so.

**The key is a bare header.** `Authorization: <key>`, not `Authorization: Bearer <key>`. Getting this
wrong produces a `401` that looks like a wrong key.

**`delete_scan` is not housekeeping, it is hygiene.** See §5.11.

### 2.5 Static and dynamic, as two different machines

```mermaid
flowchart TD
    subgraph Static["Static analyser - needs nothing but the file"]
        A1["APK on disk"] --> A2["unzip / decompile"] --> A3["rules"] --> A4["report sections:<br/>manifest, code, certificate,<br/>binary, secrets, urls"]
    end

    subgraph Dynamic["Dynamic analyser - needs an instrumented Android"]
        B1(["rooted device or<br/>MobSF's own AVD"]) --> B2["install the app"]
        B2 --> B3["exercise it: activity<br/>launcher, exported<br/>component starts"]
        B3 --> B4["capture: HTTPS traffic,<br/>logcat, filesystem diff,<br/>Frida instrumentation,<br/>screenshots"]
        B4 --> B5["report sections:<br/>traffic, runtime API calls,<br/>files created, screenshots"]
    end

    A4 --> R["one report,<br/>two provenances"]
    B5 --> R

    style B1 fill:#f9e0c0
    style R fill:#d0e8f9
```

The single most important consequence of that diagram is on the arrow at the bottom: **both halves
write into one report, and the report does not shout about which half produced a given line.** A
reader who does not know the difference will treat "the app writes to `/sdcard/log.txt`" (observed,
strong) and "the app *may* write to external storage" (a pattern match, weak) as the same kind of
statement. They are not remotely the same kind of statement — the first is an observation of
behaviour, the second is an observation that a string exists in a file.

The kernel-space stadium on `B1` is deliberate: the dynamic analyser needs a device where MobSF can
run as root and inject an agent, which is a real, awkward prerequisite. §7.2 is honest about it.

### 2.6 The trust boundary you are standing on

```mermaid
flowchart TD
    subgraph Untrusted["Untrusted input - the artefact under analysis"]
        Z["ZIP entries with<br/>attacker-chosen names"]
        X["binary XML with<br/>crafted headers"]
        DX["DEX with a lying header"]
        NM["filenames, package names,<br/>strings - all rendered<br/>into the HTML report"]
    end
    subgraph Host["The MobSF host"]
        P["unzip / AXML / DEX parsers"]
        DEC["the bundled decompiler"]
        WEB["the Django web app"]
        FS(["the server's filesystem"])
        DB[("every artefact ever<br/>uploaded, decompiled,<br/>retained")]
    end
    subgraph Others["Everyone who can reach port 8000"]
        OP["colleagues, CI, and<br/>whoever found the key"]
    end

    Z --> P
    X --> P
    DX --> DEC
    NM --> WEB
    P --> FS
    DEC --> FS
    WEB --> DB
    DB --> OP

    style Z fill:#f9d0d0
    style X fill:#f9d0d0
    style DX fill:#f9d0d0
    style NM fill:#f9d0d0
    style DB fill:#f9e0c0
```

Three consequences, all of which have bitten real teams.

**A scanner is a program that parses hostile input for a living.** MobSF has had security issues of
its own over the years — the recurring classes are path traversal in archive extraction, injection
into the report renderer from attacker-chosen strings, and authenticated remote code execution
through analysis features that shell out. This chapter does not cite specific identifiers, because
inventing one would be worse than useless; what matters is the *class*, and the class is permanent:
**anything that unpacks an untrusted archive is a target.** Run MobSF in a container, on a host you
do not care about, not on your engagement laptop.

**The report itself renders attacker-chosen text.** Package names, activity names, strings and URLs
from the APK are placed into the HTML report. A malicious sample can therefore attempt to attack the
person reading the report. This is a real technique in malware analysis and is why
[69-MalwareAnalysis is a separate discipline](#14-references) with its own containment rules.

**The database is the crown jewels.** See §5.11.

> **🔬 Under the Hood**
> The same argument applies to *your own* tooling and this repository takes it seriously.
> [`52-StaticAnalysis §2.4`](../52-StaticAnalysis/README.md#24-the-trust-boundary-you-are-standing-on)
> makes it for `apktool` and `jadx`; `17-Libraries/scripts/lib-inventory.sh` explicitly refuses ZIP
> entries containing `..`; `04-Java/scripts/dump-strings.py` validates a DEX header's claimed string
> count against the actual file size before allocating. Both scripts in this chapter open the APK
> read-only through `zipfile` and never extract to disk, for exactly this reason.

---

## 3. Deep Internal Working

This is the long section. For each stage of a MobSF scan it answers **what** it does, **why** it is
where it is, **when** you can trust it, **where** its output lands in the report, and **how** it
fails.

### 3.1 Upload, hash, and the cache that surprises everyone

**What.** The upload handler receives the file, computes its hashes (MD5, SHA-1, SHA-256), stores it
under a hash-derived name, and records it in the scan database.

**Why the hash is the key.** It makes scans idempotent and makes re-opening a report free. It also
means the *file* is the unit of identity, not the package name and not the version.

**How it fails, and this one costs people hours.** A second upload of the same bytes does not
re-analyse anything; it returns the stored result. The stored result was produced by whatever rule
set was installed **when the scan actually ran**. So:

| You did | You get | Why |
|---|---|---|
| Upload `app.apk`, then upload it again | The first scan's report | Cache hit on the hash |
| Upgrade MobSF, re-upload the same file | **Still** the first scan's report | Same hash, cache hit |
| Rebuild the app with no source changes | A *different* hash, so a fresh scan | The signature block and ZIP metadata differ |

The fix is one call:

```bash
# host - force a genuine re-analysis. EXPECTED SHAPE.
curl -s -H "Authorization: $MOBSF_API_KEY" -X POST \
     --data "hash=$SHA256" "$MOBSF_SERVER/api/v1/delete_scan"
# {"deleted": "yes"}
```

> **⚠️ Warning**
> If you are comparing two MobSF reports — two app versions, before and after a fix, your scan
> against the client's — **check that both were produced by the same MobSF version**, and say so in
> the report. The `version` key at the top of the JSON is there for this. Two reports from different
> MobSF versions are not comparable, and the differences will look like application changes.

**When you can skip thinking about this.** Never, in a re-test.

### 3.2 Unpack — the container, before any analysis

**What.** MobSF opens the ZIP, enumerates entries, records sizes and types, and identifies the app
type: APK, split/AAB, iOS, Windows, or a source zip.

**What the entry list tells you before any rule runs.** This is the two-minute triage from
[52 §3.2](../52-StaticAnalysis/README.md#32-stage-2--unpack), and MobSF gives it to you free in its
"Files" and "APKiD" sections. The interpretations are yours:

| Observation in the file list | What it means for the rest of the report |
|---|---|
| One small `classes.dex` in a large app | A packer or a cross-platform framework. **Every code-analysis section below is describing a stub.** Go to [40-Obfuscation §3.7](../40-Obfuscation/README.md) |
| `assets/index.android.bundle` | React Native. The logic is JavaScript; the DEX rules will be complete and useless |
| `libflutter.so` + `flutter_assets/` | Flutter. Dart is AOT-compiled into the `.so`. **Neither MobSF's code analyser nor its network rules see the app's real HTTP stack** — 36 measured three such apps in a fourteen-app sample |
| `libil2cpp.so`, `assets/bin/Data/` | Unity. `global-metadata.dat` holds the type names |
| No `lib/` at all in a big app | The native code ships in an ABI split you were not given (§3.13) |

**How it fails.** By being skipped by the reader. MobSF prints the file list near the *bottom* of its
HTML report, below sixty findings, so almost nobody reads it — and it is the section that tells you
whether the sixty findings above it are about the application at all.

> **🔍 Pentester's Note**
> Read MobSF's report **bottom-up on the first pass**: file list, then libraries, then the manifest
> inventory, then the findings. The findings only mean something once you know what kind of
> application produced them.

### 3.3 Decompile — one decompiler, and what that costs

**What.** MobSF converts DEX to Java-like source, AXML to readable XML, and `resources.arsc` to a
resource tree, then runs its code rules over the result.

**Why it matters that it is one decompiler.** 52's stage 3 rule is *"jadx to understand, Smali to be
certain, `aapt2` to check what the platform sees"*, and the reason is that decompilers lose different
things. MobSF gives you one view. When a code-analysis finding depends on the exact semantics of a
method, that one view is not enough, and you must go to the bytecode yourself.

The scale of the problem is measured, in this repository, and it is larger than people expect:

> [56-JADX](../56-JADX/README.md) measured jadx **under-reporting its own failures by 30×**. On a
> real 17.5 MB APK the console said `finished with errors, count: 61` while the output tree contained
> **2,104 refused methods across 1,424 files**. Anyone trusting the summary believes a decompilation
> succeeded when two thousand methods are missing.

MobSF's report does not surface a decompiler error count at all. So the question "how much of this
application did the code analyser actually read?" has **no answer inside the report**. That is a
blind spot with no warning label, and §6.3 gives you the check.

`MEASURED`, this chapter, on the two example APKs:

```bash
# host - jadx 1.5.3 CLI, on the analysis machine
java -Xmx3g -cp "/c/Program Files/jadx/lib/jadx-gui-1.5.3-all.jar" jadx.cli.JadxCLI -d out  cmpen-v1.2.apk
# INFO  - done                                      -> 234 .java files, 171 classes, no errors

java -Xmx3g -cp "/c/Program Files/jadx/lib/jadx-gui-1.5.3-all.jar" jadx.cli.JadxCLI -d out10 cmpen-v1.0.apk
# ERROR - finished with errors, count: 8            -> 1,995 .java files, 1,757 classes
```

Two applications from the same family, and the larger one refuses eight classes. Nothing in a MobSF
report would tell you which eight, or that the number is not zero.

**How this stage fails.**

- **Silently, on obfuscated code.** Heavily transformed bytecode decompiles to something that parses
  but does not mean what it appears to mean. 56 built a case where a method decompiles to clean,
  warning-free Java returning **100** while the bytecode returns **105**.
- **By omission.** Refused methods produce no code-analysis hits, so an unreadable class is
  indistinguishable from a clean one.

### 3.4 The manifest analyser

**What.** MobSF parses `AndroidManifest.xml` and applies a fixed list of rules to the parsed tree,
emitting one entry per match with a `title`, a `severity`, a `description` and a `component`.

**Where its output lands.** `manifest_analysis.manifest_anal` (a list) plus
`manifest_analysis.manifest_summary` (counts). Older versions put the list at the top level. §3.12.

**What it checks, by class.** The exact rule identifiers vary by version; the classes do not:

| Rule class | Examples | Base reliability |
|---|---|---|
| **Application flags** | `debuggable`, `allowBackup`, `usesCleartextTraffic`, `networkSecurityConfig` present | **High.** It is reading an attribute. If it says the attribute is there, it is there |
| **Component export** | exported activity / service / receiver / provider, with or without a permission | **High for the fact, useless for the severity.** See below |
| **Deep links** | browsable activities, schemes, hosts, paths | **High**, and one of the most useful things in the whole report |
| **Permissions** | declared, requested, protection levels, "dangerous" grouping | **High for the list**, weak for custom permissions (§5.6) |
| **Version gates** | `minSdk` below a threshold | **Boilerplate.** It fires on an integer comparison |
| **Task and intent semantics** | `taskAffinity`, `launchMode`, `intent-filter` shapes | Real, and severity depends entirely on the platform version — [30-Activities](../30-Activities/README.md) measured the mitigation |

**The export rule is the one to understand deeply**, because it produces more report lines than
anything else and almost none of them are findings.

MobSF reports every exported component at essentially one severity, because it has no way to
distinguish them. It cannot know that:

- `MainActivity` is exported because it is the launcher and **must** be;
- an exported `Activity` that immediately calls `finish()` unless it receives a signed token is not
  a finding;
- an exported provider whose `readPermission` is `normal` is **less** protected than an unprotected
  one is *reported* to be (§5.6, and this chapter measured it);
- an exported `Service` that does something interesting is worth a day.

`MEASURED`, this chapter: on `CMPen-Android-App-v1.2.apk`, the manifest yields **5 exported
activities and 2 exported providers**. After validation, exactly **two** of those seven produced a
finding on their own; two more were merged into other findings; three were rejected or left as
leads. §9.3 has the table.

> **🧠 Mental Model**
> An exported-component line in a MobSF report is the tool saying *"there is a door here"*. It has
> not tried the handle, it does not know what is behind it, and it does not know whether the door is
> the front door that has to be there. Every one of them is a lead;
> [32-Manifest](../32-Manifest/README.md) tells you which questions to ask about each kind of door,
> and [`32-Manifest/scripts/manifest-audit.py`](../32-Manifest/scripts/manifest-audit.py) asks them
> mechanically.

### 3.5 The certificate analyser

**What.** MobSF reads the signature block and reports which schemes verified (v1/v2/v3/v4), the
signer's distinguished name, validity dates, the signature and hash algorithms, the key algorithm
and size, and the certificate digests.

**This is MobSF at its most trustworthy.** It is reading structured data with a well-specified
format, and the two findings it produces from it are genuinely high value:

| Finding | Reliability | What to do |
|---|---|---|
| **Signed with a debug certificate** | Very high, and usually a real High-severity finding | Confirm with `apksigner`, then state the consequence: the debug key ships with the SDK, so anyone can build an update-compatible package |
| **v1 signature present** (Janus-class exposure on old platforms) | High for the fact | Check the direction — see below |
| Weak signature/hash algorithm | High | Real, but rarely the most important thing in a report |

`MEASURED`, this chapter, on both example APKs:

```bash
# host - build-tools 35.0.1
apksigner verify -v --print-certs CMPen-Android-App-v1.2.apk
# Verified using v1 scheme (JAR signing): false
# Verified using v2 scheme (APK Signature Scheme v2): true
# Verified using v3 scheme (APK Signature Scheme v3): false
# Signer #1 certificate DN: C=US, O=Android, CN=Android Debug
# Signer #1 certificate SHA-256 digest: 5b571963d738e3b631162671e82ce4a4e67cd4ea76882c427c16a3fec54d3266
```

Both APKs are signed `CN=Android Debug`, with **different** debug keys (`5b571963…` and
`045bc19b…`). That is expected — every developer machine generates its own debug key — and it is
also the point: the private key for *your* debug certificate is on your disk in `~/.android/debug.keystore`
with the password `android`, and so is everyone else's.

**The direction error to watch for.** A rule that says *"the application is not signed with the v1
scheme"* is reporting a **compatibility** fact, not a security one, for any app with `minSdk >= 24`.
The security-relevant case is the inverse: v1 present without v2, which is the shape the Janus class
of attack needed. Reporting the harmless direction as a weakness is a real thing scanners do, and
this chapter's example ledger rejects exactly that row.

> **⚠️ Warning**
> One thing no certificate analyser will tell you: whether the app *checks its own* signature at
> runtime, and whether that check handles rotation. [38-TamperDetection](../38-TamperDetection/README.md)
> measured **6 of 198 installed packages carrying a signing lineage** — so a self-check that reads
> `signatures[0]` and compares one hash is wrong on real devices. That is a code finding, not a
> certificate finding, and no rule produces it.

### 3.6 The code analyser — what a MobSF rule actually is

**What.** MobSF walks the decompiled tree and applies a rule catalogue. A rule is, in substance, a
pattern plus a block of fixed metadata.

`EXPECTED SHAPE` — the rules live in a YAML file in MobSF's source tree (in the 4.x layout, under
`mobsf/StaticAnalyzer/views/android/rules/`; run `find . -name '*rules*.yaml'` in your checkout if
it has moved). A rule looks like this:

```yaml
- id: android_ecb_cipher
  message: >
    The App uses ECB mode in Cryptographic encryption algorithm. ECB mode is known to be
    weak as it results in the same ciphertext for identical blocks of plaintext.
  type: regex
  pattern: Cipher\.getInstance\(\s*"\s*AES\/ECB
  severity: high
  input_case: exact
  cvss: 5.9
  cwe: cwe-327
  owasp-mobile: m5
  masvs: crypto-2
```

**Read that block again, because it contains the single most consequential fact in this chapter.**

`severity: high` and `cvss: 5.9` are **properties of the rule**. They are written once, by a rule
author, for every application that will ever match. They are not computed from your app. They do not
know what the cipher protects, whether the code is reachable, whether it is in the app's own package
or in a vendored library from 2014, or whether the ciphertext ever leaves the process.

When you read `"cvss": 5.9` in a MobSF JSON report, you are reading a constant.

**Rule classes, on 52's precision ladder.** [52 §3.5](../52-StaticAnalysis/README.md#35-stage-5--sweep)
classifies rules by base precision, and MobSF's catalogue spans all four:

| 52's class | Base precision | MobSF examples | What a hit means |
|---|---|---|---|
| **Format** | 0.75 | `-----BEGIN PRIVATE KEY-----`, an AWS key id, a Firebase URL | This *is* the thing. Remaining questions: scope and reachability |
| **API** | 0.55 | `Cipher.getInstance("AES/ECB…")`, `addJavascriptInterface(`, `setJavaScriptEnabled(true)` | The construct exists. Danger depends on arguments and callers |
| **Shape** | 0.30 | a long base64 blob, a 40-character hex run, "hardcoded secrets" | Right silhouette. **Most of these are wrong** |
| **Keyword** | 0.15 | the word `password` in a file | Someone typed a word |

**MobSF presents all four at rule-defined severity, in one list.** A `format`-class hit on a private
key and a `shape`-class hit on a base64 string can both arrive as `high`. That is the mechanism
behind "nobody reads scanner output", and it is fixable on your side: classify each hit's rule class
before you read the severity.

`MEASURED`, this chapter: of the seven values in the example report's `secrets` section, the shipped
classifier put **one** in the "interesting" bucket, **four** in "ciphertext", **one** in "digest" and
**one** in "public key pin". Six of the seven were not secrets in any sense that a report should use
the word. §9.2 works it.

**How this stage fails.**

- **On obfuscated code**, by finding nothing. Renamed types defeat name-based rules. §5.3.
- **On library code**, by finding everything. A rule that fires inside `androidx/` or a vendored SDK
  is reporting somebody else's code, and MobSF's finding entry does not distinguish the app's
  package from a dependency's. 52's sweeper scores that difference at **+0.25 versus −0.30**, the
  single largest term in its model, because it is the dominant signal.
- **On unparsed code**, by silence (§3.3).

### 3.7 The secrets scanner

**What.** Shape rules over the extracted string data, looking for things that look like credentials.

**Why it exists and why it is nearly always the noisiest section of the report.** Real credentials
*are* shipped in real APKs, constantly, and the check is cheap. But "looks like a credential" and
"is a credential" are different questions, and this repository has measured the gap three separate
times:

| Measurement | Result | Where |
|---|---|---|
| `leak-hunter.py` against real Chrome data | **132 high-confidence hits, 132 false positives** — every one a component-updater signature manifest | [33-Storage](../33-Storage/README.md) |
| Static sweep of a 17 MB commercial app, HIGH band adjudicated by hand | **15 of 17 rejected (88%)** — doc links, Compose `@Preview` fixtures, an XMP namespace, marketing URLs | [52 §9.4](../52-StaticAnalysis/README.md#94-real-application--the-false-positive-arithmetic-measured) |
| Pinning surface across 14 real apps | **12 had a surface; 4 had a pin** | [36 §8.1](../36-CertificatePinning/README.md#81-pinning-surfacepy--and-what-it-measured) |

**The classification that kills most of them takes one function.** Before you call anything a secret,
answer *what is this value*:

| Shape | What it usually is | Verdict |
|---|---|---|
| `sha256/` + 43 base64 chars + `=` | An **SPKI pin** — the hash of a *public* key, published in every handshake | Not a secret. Ever |
| 32 / 40 / 64 hex characters | A digest: MD5, SHA-1, SHA-256 | Not a key. If it is a password verifier, the finding is the *algorithm* |
| base64 that decodes to readable text | Obfuscation, defeated | Real, but "encoding is not encryption" — severity from what it protects |
| base64 that decodes to high-entropy bytes | Ciphertext or a key blob | **Only a finding if the key is also in the artefact** |
| A URL | An endpoint | Belongs in the endpoint inventory, not the secrets list |
| A Google API key, Firebase app id, Play Billing key | A **client** credential the vendor designed to ship | The finding, if any, is the *restriction* on it — go and check |

That last row is the one that gets junior testers into arguments they lose. Some keys are meant to be
public. The professional sentence is not "hardcoded API key found"; it is *"this key has no
application restriction and this scope"*, and you have to go and check the restriction before you
write it.

### 3.8 The binary (ELF) analyser

**What.** For each `lib/*/*.so`, MobSF reports hardening properties: NX, PIE, stack canary, RELRO,
`RPATH`/`RUNPATH`, fortified functions, and whether symbols are stripped.

**What that section is worth.** It is a **build-configuration table**, and it should be reported as
one. "This library was built without a stack canary" is not a vulnerability; it is a property that
makes some future memory-safety bug easier to exploit. Modern NDK toolchains set most of these
correctly by default, so a long list of green rows tells you the vendor used a normal toolchain.

**What it does not tell you, and this is the important part.** Two things:

**The native surface may not be enumerable at all.** [52 §4.4](../52-StaticAnalysis/README.md#44-registernatives-the-blind-spot-in-source)
and [16-JNI](../16-JNI/README.md) cover the mechanism: a `native` Java method gets an implementation
either by name mangling (`Java_com_example_Foo_bar`, visible in `readelf --dyn-syms`) or by
`RegisterNatives` (a `JNINativeMethod[]` array passed at runtime, usually from `JNI_OnLoad`, visible
nowhere). An app that wants its native surface hidden simply registers it.

```bash
# host - the check MobSF's binary section does not make. MEASURED-CAPABLE: run it yourself.
mkdir -p x && cd x && unzip -o -q ../target.apk 'lib/*'
for so in $(find lib -name '*.so'); do
    printf '%-48s Java_:%-4s JNI_OnLoad:%s\n' "$so" \
        "$(readelf --dyn-syms --wide "$so" 2>/dev/null | grep -c ' Java_')" \
        "$(readelf --dyn-syms --wide "$so" 2>/dev/null | grep -c 'JNI_OnLoad')"
done
```

`JNI_OnLoad: 1` with `Java_: 0` is the signature of a registered native surface.
[`17-Libraries/scripts/lib-inventory.sh`](../17-Libraries/scripts/lib-inventory.sh) already prints
exactly this warning, and falls back through `readelf → llvm-readelf → objdump → a pure-Python ELF
parser` while reporting which link answered — copy that rather than assuming `readelf` exists.

**The proportion of the app that is native is not in the report either.** A 40 MB `.so` beside a 2 MB
DEX means MobSF's code analysis covered a rounding error of the program. Compute the ratio yourself
and put it in the limits section.

> **🔬 Under the Hood**
> This repository has an NDK at
> `C:\Users\harsh\AppData\Local\Android\Sdk\ndk\25.2.9519653\toolchains\llvm\prebuilt\windows-x86_64\bin\`,
> which ships `llvm-readelf`, `llvm-readobj`, `llvm-objdump` and `llvm-nm` as drop-in replacements.
> Two chapter briefs previously asserted there was no toolchain on this machine. Check before you
> claim a tool is missing.

### 3.9 The security score, and why you must never quote it

**What.** MobSF computes a single number — the "security score", 0–100 — plus an "average CVSS", and
displays them at the top of the report where they are the first and often only thing anyone reads.

**How it is built.** In substance: start from a baseline, subtract for each `high` finding, subtract
less for each `warning`, add for each `secure` finding, and fold in the average of the per-rule CVSS
constants. Every input is a **count of rule matches** weighted by **rule metadata**.

Write out what that means:

> The security score is a function of how many of MobSF's patterns matched, weighted by numbers a
> rule author typed. It contains **no information about your application's assets, users, threat
> model, deployment, or the reachability of anything it counted.**

`MEASURED`, this chapter, and the arithmetic is worth staring at. The two example fixtures carry
scores of **38** (v1.2) and **34** (v1.0). Now compare them properly:

| | v1.0 | v1.2 |
|---|---|---|
| `android:debuggable` in the shipped manifest | **true** | absent |
| Exported providers | 0 | **2**, one unprotected, one guarded by a `normal` permission |
| Browsable deep link | none | **`ctfapp://open/admin`** |
| WebView JavaScript bridge with an attacker-controllable URL | none | **yes** |
| Weak crypto | DES, key from a resource string | AES-ECB, key = truncated single-round SHA-256 |
| Score | 34 | 38 |

The scores say v1.0 is *worse*. A tester reading only the number would work v1.0 first. But v1.2
carries a remotely-triggerable JavaScript bridge that leaks an auth token to any co-installed app,
an unprotected content provider over the app's private files, and a deep link that grants access on
a literal comparison — and v1.0's headline problem, `debuggable=true`, requires ADB access to an
unlocked device. **The ranking is inverted relative to attacker value**, and it is inverted because
the score counts rule matches and `debuggable` happens to be one high-severity match while "a bridge
plus an export plus an unvalidated URL" is three separate mid-severity ones in three different
sections that nothing joins.

This chapter's [`scripts/mobsf-triage.py`](scripts/mobsf-triage.py) scores the same two reports at
**82 and 58**, in the other order, and prints every term of the arithmetic so you can disagree with
it:

```
# MEASURED - python3 -B scripts/mobsf-triage.py --from-reports examples/
  #    package                        version   triage  MobSF  cvss  top signal
  1    org.android.cmpen              2.0           82     38   6.6  debug_cert x1
  2    org.android.cmpen              1.0           58     34   5.0  debuggable x1
```

> **⚠️ Warning**
> Do not put MobSF's security score in a client report, and do not let a client put it in a
> requirement. "The app must score above 60 in MobSF" is a specification for passing a rule set, not
> for being secure, and it is trivially gamed: suppress rules, remove a `<meta-data>` element, ship
> the `secure`-band items. Score-driven security produces applications that pass scanners.

> **🧠 Mental Model**
> **Confidence ranking is not severity ranking.** This repository has now measured that four
> separate times — 33's 132/132, 52's 15-of-17-rejected HIGH band, 36's 12-surface/4-pin, and 38's
> detector that reported 18/18 until it was split into STRONG and WEAK patterns and became a
> defensible 13/18. A tool's ordering tells you how sure the *tool* is that its pattern matched. It
> cannot tell you how much it matters, because mattering requires an asset.

### 3.10 The dynamic analyser

**What.** MobSF can install an application on an instrumented Android instance, exercise it, and
capture behaviour: HTTPS traffic through its own proxy and CA, logcat, the filesystem before and
after, runtime API calls via Frida instrumentation, and screenshots. Its output joins the same
report.

**What it needs.** A device or emulator where MobSF can act as root: install a CA into the system
store, push and run `frida-server`, and read the app's private directories. In practice that is
MobSF's own prepared AVD image, Genymotion, or a rooted physical device. **A stock, unrooted phone
will not do**, and §7.2 is explicit about it — this chapter's own test device (`i9000S`, API 33) is
unrooted with no `frida-server`, which is one of the reasons §7 is descriptive rather than measured.

**Where it is genuinely valuable.** Three things, and they are exactly the three things static
analysis cannot do:

1. **Traffic.** What the app actually sends, to where, with which headers.
2. **Filesystem effects.** Which files it really creates, with which modes.
3. **The runtime API trace.** Which of the static hits actually execute.

**Where it is weak.**

- **Coverage.** It launches activities and pokes exported components. It does not log in, does not
  complete a purchase, and does not reach the branch behind a feature flag. The dynamic report
  describes the app's front porch.
- **It cannot know what it missed.** Which is [51-DynamicAnalysis](../51-DynamicAnalysis/README.md)'s
  central point, and 51 measured the failure mode exactly: *"a void run and a clean negative produce
  identical reports"* — an `am start` absorbed by a permission dialog left all nine capture channels
  silent, and the report looked precisely like a well-behaved app doing nothing wrong. **Every
  dynamic session needs a liveness check before its silence means anything**, and MobSF does not
  provide one.
- **It is detectable.** An app with emulator or root detection may take a different path, or refuse
  to start. That is [37-RootDetection](../37-RootDetection/README.md)'s and
  [39-EmulatorDetection](../39-EmulatorDetection/README.md)'s territory, and it means the dynamic
  section can be a report about the app's *evasion* rather than about the app.
  **MobSF's dynamic analysis runs in an emulator**, so a clean dynamic report on an app with working
  emulator detection means the analysis was blocked, not that the app is safe. Chapter 39 measured
  which of the published emulator signals still fire — nine of the best-known ones do not.

### 3.11 The REST API surface

The endpoints this chapter's tooling uses, and what each is for. `EXPECTED SHAPE`; open `/api_docs`
on your own instance, because the set grows between versions.

| Endpoint | Method | Fields | Returns |
|---|---|---|---|
| `/api/v1/upload` | POST | multipart `file` | `{hash, scan_type, file_name}` |
| `/api/v1/scan` | POST | `hash`, `scan_type`, `file_name` | The full report. **Slow** — minutes on a large app |
| `/api/v1/report_json` | POST | `hash` | The full report, from the database |
| `/api/v1/scans` | GET | — | Recent scans, paginated |
| `/api/v1/delete_scan` | POST | `hash` | `{"deleted": "yes"}` |
| `/api/v1/download_pdf` | POST | `hash` | The PDF report |
| `/api/v1/scorecard` | POST | `hash` | Just the `appsec` block |
| `/api/v1/compare` | POST | `hash1`, `hash2` | A diff between two scans |

Authentication is the header `Authorization: <api_key>` — a bare value, not `Bearer`.

`/api/v1/compare` deserves a mention because it is under-used and it is the right primitive for a
re-test: give it the previous version's hash and the new one, and it tells you what changed. The
[36 §8.5](../36-CertificatePinning/README.md#85-diffing-pins-across-app-versions) discussion of
version diffing applies directly — a pin appearing, disappearing, or moving from the DEX into a
`.so` is a real and observable hardening signal.

### 3.12 Schema drift, and the four reasons two runs differ

The FAQ question "why do two runs give different results" has four distinct answers, and confusing
them wastes days.

| Cause | Symptom | How to tell |
|---|---|---|
| **1. The cache** (§3.1) | The "new" scan is identical to the old one, including a finding you know was fixed | The report's timestamp is older than your upload |
| **2. Rule-set change** | Findings appear or vanish after a MobSF upgrade | The `version` key differs between the two JSONs |
| **3. Schema change** | Your parser breaks, or silently reads zero findings | `manifest_analysis` is a list in one and a dict in the other |
| **4. A different artefact** | Everything differs | The `sha256` differs. **Check this first, always** |

Cause 3 is worth spelling out because it silently produces empty sections rather than errors. Across
MobSF's 3.x and 4.x line, at least these shapes have existed:

```python
# EXPECTED SHAPE - the three manifest shapes a tolerant parser must accept
report["manifest_analysis"]                       # a bare list of finding dicts
report["manifest_analysis"]["manifest_anal"]      # a dict with the list under a key
report["manifest_analysis"]["manifest_findings"]  # the same, renamed

# and code analysis, similarly
report["code_analysis"]["findings"]               # {title: {files: {...}, metadata: {...}}}
report["code_analysis"]                           # the same map, flat, minus a "summary" key
```

[`scripts/mobsf-validate.py`](scripts/mobsf-validate.py) accepts all of them and **prints which one
it recognised**, on the `schema seen:` line:

```
# MEASURED
  schema seen : manifest_analysis: dict; certificate_analysis: dict; code_analysis: dict;
                network_security: dict; appsec: dict
```

That line exists so that "the report has no manifest findings" and "my parser did not find the
manifest findings" are distinguishable. A parser that silently returns zero is worse than one that
crashes.

> **🔍 Pentester's Note**
> Record the MobSF version alongside the report hash in your engagement notes, exactly as you record
> the artefact's SHA-256. A finding is reproducible only against a stated tool version, and "MobSF
> flagged it" is not a citation.

### 3.13 Splits: the failure mode with no warning

**What.** App Bundle delivery splits an application across `base.apk`,
`split_config.arm64_v8a.apk`, `split_config.en.apk`, and any number of dynamic feature modules.

**What MobSF does with that.** It scans what you gave it. If you gave it `base.apk`, the report
describes `base.apk`, completely and accurately, and says nothing about the rest.

**Why this is the most dangerous single mistake in this chapter.** The report will not be empty. It
will be a full, plausible, professional-looking report — with a component list, a permission list, a
score — describing a fraction of the application. Nothing in it says "the native libraries are
elsewhere".

The measurement is in this repository:

> [38-TamperDetection](../38-TamperDetection/README.md), across 18 real APKs: **one large app showed
> *zero* controls in `base.apk` because its code ships in splits.** A report on that base alone would
> have concluded the application had no integrity protection whatsoever.

**The check costs one command:**

```bash
# adb shell - every path the platform knows about, not just the first
adb shell pm path com.example.target
# package:/data/app/~~AbC==/com.example.target-XyZ==/base.apk
# package:/data/app/~~AbC==/com.example.target-XyZ==/split_config.arm64_v8a.apk
# package:/data/app/~~AbC==/com.example.target-XyZ==/split_config.en.apk
```

Pull every one, scan every one, and say in the report how many you scanned.
[`scripts/mobsf-validate.py`](scripts/mobsf-validate.py) raises the flag automatically when the
artefact it is handed is named `base.apk`:

```
# MEASURED - blind-spot block, emitted on any artefact named base*.apk
  * split APKs
      the artefact is named base.apk. Splits carry code, native libraries and
      manifest contributions. Confirm with: adb shell pm path <pkg>
```

### 3.14 The six blind spots, with numbers

Everything below is invisible to MobSF *and to any other tool that reads only the artefact*,
including every script in this repository. This table belongs in your report's limits section, not
in a footnote.

| Blind spot | Why no artefact analysis sees it | Measured scale | Who answers it |
|---|---|---|---|
| **Runtime-registered receivers** | `registerReceiver()` builds an `IntentFilter` at runtime; nothing is written to the manifest | **299 of 431 distinct actions (69%)** registered by third-party processes had no manifest-declared receiver anywhere on the device — [29](../29-BroadcastReceivers/README.md). Independently corroborated at **67% (214 of 321) on API 33** | `adb shell dumpsys activity broadcasts` |
| **`RegisterNatives` bindings** | The Java-to-native map is built inside `JNI_OnLoad`; no `Java_` symbol exists | Universal in any library that wants to hide | [16-JNI](../16-JNI/README.md); hook `RegisterNatives` |
| **Reflection** | The target is chosen by a string at runtime, creating no textual edge | Present in essentially every app | Hook `Method.invoke` |
| **Dynamically loaded DEX** | The code is not in the artefact | Rare, and almost always the most severe row when present | [40-Obfuscation §3.7](../40-Obfuscation/README.md) |
| **Server-side behaviour and remote config** | It is not on the device | Every flag can turn a control off after you finish testing | Ask for the flag inventory; test both values |
| **Splits you were not given** | §3.13 | One app in 18 had zero controls in `base.apk` | `adb shell pm path` |

Two of these invert intuitions and are worth restating.

**The broadcast number is the norm, not a curiosity.** Chapter 29 got it by parsing the live
registration table out of `ActivityManagerService` and subtracting `cmd package query-receivers`.
`query-receivers` returns "No receivers found" for `VOLUME_CHANGED_ACTION` while AMS shows six live
registrations. So when a MobSF report lists three receivers, the honest reading is *"three receivers
are declared in the manifest"*, and the runtime surface is probably several times larger. The counts
are also timestamped rather than stable: three snapshots of the same idle device gave 1,151 / 1,281 /
1,290 registrations.

**A native method with no `Java_` symbol is not missing.** It is registered, and MobSF's binary
section will show you a library with a clean symbol table and tell you nothing is there.

---

## 4. Source Code Walkthrough (AOSP)

MobSF is not part of AOSP, so this section has two halves and they are both necessary.

**The first half** walks MobSF's own tree, because knowing where a finding was generated is what lets
you predict, suppress or extend it.

**The second half — and this is the more important one — walks the AOSP code MobSF is trying to
predict.** Static analysis is an act of prediction: you read a file and predict what the platform
will do with it. **Every divergence between MobSF's reading and the platform's behaviour is either a
false positive or a miss**, and the only way to know which is to read the platform.

> **⚠️ Warning — on the paths in §4.1–§4.5**
> MobSF's internal layout has been reorganised more than once. The paths below describe the 4.x tree
> as documented by the project. If a path is wrong in your checkout, `find . -name '<basename>'`
> will locate it in a second — and the *structure* of the argument does not depend on the path.
> **No line numbers are quoted anywhere in this section**, deliberately: a line number in someone
> else's fast-moving repository is a fabrication waiting to happen.

### 4.1 The scan entry point

**Path:** `mobsf/StaticAnalyzer/views/android/static_analyzer.py`

This is the orchestrator. Its job, in outline, is:

```
static_analyzer(request, api=False)
  -> validate the hash and the scan type
  -> look the hash up in the database                      # the cache of section 3.1
       hit  -> render the STORED result and return
       miss -> continue
  -> unzip the APK, build the file inventory
  -> parse the manifest                     -> manifest_analysis.py
  -> analyse the certificate                -> cert_analysis.py
  -> decompile                              -> converter.py  (dex -> jar -> java, or jadx)
  -> run the code rules                     -> code_analysis.py
  -> run the ELF checks                     -> ../shared_func/ / binary analysis
  -> extract urls, emails, firebase, trackers
  -> compute the scorecard                  -> views/appsec.py
  -> persist, then render
```

Two things in that outline are worth internalising.

**The cache check happens before anything else.** That is §3.1's surprise, in one line of control
flow.

**The order is fixed and one-pass.** There is no second pass in which a code finding is re-weighted
because of a manifest fact. `code_analysis.py` never learns that the class it just flagged belongs to
an exported component; `manifest_analysis.py` never learns that the exported Activity it just flagged
contains an `addJavascriptInterface` call. **That architectural fact is the reason §5.4 exists** —
the join is not skipped by choice, it is not expressible in this pipeline.

### 4.2 `manifest_analysis.py`, and the AOSP function it is guessing

**Path:** `mobsf/StaticAnalyzer/views/android/manifest_analysis.py`, with the parsing helper in
`manifest_view.py`.

The module's shape is a long series of independent checks over a parsed DOM, each appending a dict to
a findings list. That structure explains three properties of the output you will otherwise find
mysterious:

- **Findings are independent.** Two rules can fire on the same component and produce two entries
  (this chapter's example report has `DeepLinkActivity` reported twice, under `exported_activity` and
  `browsable_activity`). Neither knows about the other.
- **Severity is per rule, written inline.** Not computed.
- **The `component` field is a string the rule chose.** Sometimes a class name, sometimes an
  attribute name like `allowBackup`. A parser must not assume it is a component.

**Now the platform side, which is what decides whether the output is right.**

**Path:** `frameworks/base/core/java/android/content/pm/parsing/ParsingPackageUtils.java`
(the modern parser, API 30 onward), and the older
`frameworks/base/core/java/android/content/pm/PackageParser.java`.

The install path, in outline:

```
PackageManagerService.installPackageLI
  -> ParsingPackageUtils.parsePackage(File, flags)
       -> parseMonolithicPackage / parseClusterPackage        <- splits are merged HERE
            -> parseBaseApk(ApkLite, ...)
                 -> AssetManager.openXmlResourceParser("AndroidManifest.xml")
                 -> parseBaseApplication(...)
                      -> parseActivity / parseService / parseProvider
```

Three facts from that path change how you read every manifest row in a MobSF report.

**First: the platform reads *binary* XML through the resource system, not text.** The file inside the
APK is AXML — a string pool plus a tree of typed nodes. Anything MobSF shows you is a *rendering* of
that tree, and a rendering can differ from the parse. That divergence is a deliberate technique;
[32-Manifest](../32-Manifest/README.md) and [10-APK-Internals](../10-APK-Internals/README.md) each
ship a CTF built on a different variant of it (a `rawValue`/`typedValue` trick and a widened
`attributeSize` stride respectively). The defence is cheap and this chapter's validator uses it:
read the manifest with `aapt2 dump xmltree` as well, because `aapt2` uses the platform's own
`androidfw` code.

**Second: `parseClusterPackage` is where splits are merged.** The manifest the platform ends up with
is the base manifest *plus* contributions from the splits. If MobSF read only `base.apk`, it read an
input, not the result. §3.13.

**Third: defaults are computed here, not written in the file.** The most consequential is `exported`.
In substance:

```java
// Sense of the AOSP logic in parseActivityOrAlias, not a verbatim quote.
// Read frameworks/base/core/java/android/content/pm/parsing/ParsingPackageUtils.java for the exact form.
boolean exported;
if (sa.hasValue(R.styleable.AndroidManifestActivity_exported)) {
    exported = sa.getBoolean(R.styleable.AndroidManifestActivity_exported, false);
} else {
    exported = activity.getIntents().size() > 0;   // an intent-filter IMPLIES exported
}
```

So a component with an `<intent-filter>` and **no** `android:exported` attribute is exported — and on
`targetSdk` 31 and above the platform refuses to install a package that leaves it unspecified. A tool
that greps for `exported="true"` finds the explicit cases and misses the implicit ones, which are
the interesting ones. MobSF handles this correctly for activities with filters (its title text even
says *"An intent-filter exists"*), which is a point in its favour worth knowing.
[32-Manifest §8.2](../32-Manifest/README.md) ships the Python that gets the whole rule right; do not
re-implement it.

### 4.3 `code_analysis.py` and the rules file

**Paths:** `mobsf/StaticAnalyzer/views/android/code_analysis.py` and the rule catalogue under
`mobsf/StaticAnalyzer/views/android/rules/`.

The analyser walks the decompiled tree and, per file, applies each rule. The rule types you will see
in the YAML are, in substance:

| `type` | Meaning | Precision consequence |
|---|---|---|
| `regex` | One pattern must match | Whatever the pattern's precision is |
| `regex_and` | Several patterns must all match in the same file | Materially better. This is how the good rules are written |
| `regex_or` | Any of several patterns | Broader, noisier |
| `regex_and_or` | A pattern plus any of a set | The most expressive form available |
| `string` variants | Literal substring matching over the extracted strings | Fast, and the source of the noisiest sections |

`input_case: exact` versus `lower` decides case sensitivity, and it matters more than it looks: a
case-insensitive rule on the word `key` matches `keyboard`, `monkey`, `KeyEvent` and
`RSAPublicKeySpec`.

**The single most useful thing you can do with this file is read it.** Ten minutes with your
instance's rule catalogue tells you, permanently, why a finding fired:

```bash
# host - in a MobSF checkout or inside the container
find . -path '*android/rules*' -name '*.yaml' | head
grep -n -A6 'AES/ECB' mobsf/StaticAnalyzer/views/android/rules/*.yaml
```

**Extending it is legitimate and under-used.** If your engagements repeatedly involve one SDK, one
in-house crypto helper, or one company-specific credential format, a `regex_and` rule for it costs
ten minutes and runs on every future scan. Two disciplines make an added rule useful rather than
harmful:

1. **Set `severity: info`, always**, whatever you think it is worth. Severity belongs to stage 7.
   [52 §8.9](../52-StaticAnalysis/README.md#89-the-tools-and-exactly-where-each-one-stops) makes the
   same argument about `semgrep`'s severity field.
2. **Write the rule with `regex_and`**, so it requires two independent signals. A single-pattern rule
   over a decompiled tree will find you a hundred hits in `androidx/`.

### 4.4 The API middleware, and the key

**Path:** `mobsf/MobSF/views/api/api_middleware.py`, with the routes in `mobsf/MobSF/urls.py`.

The middleware is short and its behaviour is worth knowing exactly:

- It applies to paths under `/api/`.
- It reads the `Authorization` header and compares it to the configured key. **A plain string
  comparison against a single static key** — there are no users, no scopes, and no per-key
  permissions.
- It rejects with `401` on mismatch.

Three operational consequences:

| Fact | Consequence |
|---|---|
| One key, no scopes | Anyone with the key can upload, read **every** stored report, and delete scans |
| No rate limiting by default | A key leaked into CI logs is a full compromise of the instance's contents |
| The key is in the environment and the config file | It ends up in shell history, `docker inspect`, and CI variables. Treat it as a credential, because it is one |

That is the mechanical basis for §5.11.

### 4.5 Where the report lives, and what `report_json` serialises

**Paths:** `mobsf/StaticAnalyzer/models.py` (the ORM models) and
`mobsf/StaticAnalyzer/views/android/db_interaction.py` (read/write helpers).

The scan result is stored as a row keyed by the file hash, with the large sub-structures serialised
into text columns. `report_json` reconstructs the dict from that row.

Two things follow, and both explain observed behaviour:

**The JSON is the database row, not a re-analysis.** Which is §3.1 again, from the other end.

**Field names in the JSON are the model's field names.** That is *why* the schema drifts: a rename in
`models.py` propagates straight into everyone's parser. It also means the JSON is the authoritative
form and the HTML is a rendering of it — so when the web page and the JSON appear to disagree, the
JSON is what MobSF actually decided.

```bash
# host - the two-line habit that makes all of this concrete. EXPECTED SHAPE.
curl -s -H "Authorization: $MOBSF_API_KEY" -X POST --data "hash=$SHA" \
     "$MOBSF_SERVER/api/v1/report_json" > report.json
python3 -B -c "import json;d=json.load(open('report.json'));print('\n'.join(sorted(d)))"
```

Reading that key list once, on your own instance, is worth more than any schema documentation
including this chapter's.

### 4.6 The AOSP code that decides whether the inventory is right

MobSF's component inventory is the part of the report you are most likely to use directly, so it is
worth knowing the three ways it can differ from what the platform believes.

**Path:** `frameworks/base/services/core/java/com/android/server/pm/PackageManagerService.java`,
plus the parsing package above.

| Divergence | Cause | How to settle it |
|---|---|---|
| A component in the manifest is **disabled** | `android:enabled="false"`, or `setComponentEnabledSetting` called at runtime | `adb shell dumpsys package com.example \| grep -A5 'disabled'` |
| A component exists that the manifest does not show | Contributed by a **split**, or by manifest merging from a dependency | `dumpsys package` shows the merged, installed truth |
| The platform's `exported` differs from the file's | Implicit export via `<intent-filter>`; or `targetSdk` gating | `aapt2 dump xmltree` plus `dumpsys package` |

**The platform's own record always wins.** [52 §3.1](../52-StaticAnalysis/README.md#31-stage-1--acquire)
puts it exactly right: *"When a static lead and the platform disagree, the platform wins."* The
one-line habit:

```bash
# adb shell - the installed truth, which beats any file you decoded
dumpsys package com.example.target | grep -E \
  "versionName|versionCode|targetSdk|minSdk|flags=|privateFlags=|installerPackageName"
```

That `flags=` line is the platform confirming a manifest attribute rather than a file claiming
something about itself. On the app used throughout [52 §9.3](../52-StaticAnalysis/README.md#93-advanced--a-complete-static-pass-ending-in-a-validated-finding)
it read:

```
flags=[ DEBUGGABLE HAS_CODE ALLOW_CLEAR_USER_DATA ALLOW_BACKUP ]
```

A MobSF `debuggable` finding plus that line is a *finding*. A MobSF `debuggable` finding alone is a
lead — a strong one, but a lead.

### 4.7 One more AOSP path: why a "secret" in `strings.xml` survives everything

**Paths:** `frameworks/base/libs/androidfw/ResourceTypes.cpp` (the `ResTable` implementation) and
`frameworks/base/tools/aapt2/`.

A string resource is not code. It is an entry in a typed table with an integer identifier, and three
consequences follow that people get wrong in both directions:

| Property | Consequence for a MobSF finding |
|---|---|
| R8 renames classes and methods, **not resource values** | A key in `strings.xml` survives obfuscation completely. "Enable obfuscation" is a **wrong** remediation for it |
| Resource *names* can be stripped by shrinking; values cannot | You may see `@string/0x7f110042` in a decoded manifest and still read the value out of `resources.arsc` |
| The table is per-configuration | `aapt2 dump resources` prints **all** configurations, and a value can differ per locale. A single-configuration read can miss one |

The build path that puts secrets there is common enough to recognise on sight:

```kotlin
// build.gradle.kts -- this writes the value into res/values/strings.xml at BUILD time
android {
    defaultConfig {
        resValue("string", "maps_api_key", providers.gradleProperty("MAPS_KEY").get())
    }
}
```

The developer's model is "the key is not in my source, it is in a Gradle property", which is true and
irrelevant: the *artefact* contains it in plain text. **Audit the built artefact; use the source to
explain it.** `MEASURED`, this chapter: the v1.0 example APK's DES key is exactly this shape —
`<string name="encryption_key">MyS3cReT</string>` in `res/values/strings.xml`, read at runtime by
`getString(R.string.encryption_key)` and passed straight to `new SecretKeySpec(key.getBytes(), "DES")`.

---

## 5. Security Perspective

### 5.1 The false-positive taxonomy

Not all wrong findings are wrong in the same way, and the differences matter because they need
different rebuttals. Six classes, each with a worked example.

#### Class 1 — the rule is right and the code is somebody else's

The most common class by volume. A rule fires inside `androidx/`, `kotlin/`, `okhttp3/` or a
vendored SDK. The construct is real; it is not the developer's decision.

`MEASURED`, [52 §9.3](../52-StaticAnalysis/README.md#93-advanced--a-complete-static-pass-ending-in-a-validated-finding):
of nine leads on a small training app, **four were rejected purely because they had zero sites in
app code** — `MODE_WORLD_*` style storage paths in AndroidX `FileProvider`, logging in
ConstraintLayout, a `127.0.0.1` literal inside ConstraintLayout's `Utils`.

**The rebuttal.** *"This construct is in `<library> <version>`, not in the application's code. It is
reported in the dependency section. The application's own packages contain zero instances."* Then
back it with the package classification.

**MobSF does not make this distinction for you.** Its code-analysis entry lists file paths; it is on
you to notice that all of them start with `androidx/`.

#### Class 2 — the rule is right and the value is not what the rule thinks

The secrets section, almost entirely. A 64-character hex string is a digest, not a key. A
`sha256/…=` value is a *public* key hash. A base64 blob is ciphertext.

`MEASURED`, this chapter, on the example report's seven "secrets":

```
# MEASURED - mobsf-validate.py classification of the secrets section
V021  "sha256/+xpjwBQ7+BLhq1r+/AU3qLNIaXPt+JgXAJ9yIQaHNkQ="   -> SPKI pin        REFUTED
V022  "abdd1bd1e110321baca9bff06c9199402c4a5238ca0d64c7b0b59e8a64a75adb"
                                                              -> 256-bit hex     OVER-RATED
V023  "ZmxhZ3tLSkJKSGRTT0ZRQ1hMTWRHNEQ0OWpiODREYUFIcHBtT30=" -> base64 of TEXT  CORROBORATED
V024  "n8qhwbn+IyvfEIwOQgznb1lXWTWUuUsnxI57Lp1CEUPMb9ntxAimu/SB8O3UnLKK"
                                                              -> base64 BINARY   NEEDS-HUMAN
```

One of the four is what the section claims. The `sha256/` value is the strongest case: it is the
base64 SHA-256 of a **public** key, transmitted in cleartext during every TLS handshake the server
performs. Calling it a hardcoded secret is a category error, and it is one a scanner will make on
**every application that pins**.

**The rebuttal.** Decode it, in front of them, and say what it is.

#### Class 3 — the construct is real and nothing can reach it

Dead code, debug-only branches, `@Preview` fixtures, test doubles compiled into the release build.

`MEASURED`, [52 §5.4](../52-StaticAnalysis/README.md#54-how-developers-create-static-findings): on a
17 MB commercial application, **three of the fifteen highest-confidence leads were URLs baked into
Compose preview functions of a bundled SDK** — `http://www.google.com/lol`, `http://test.com`,
`http://external.source.com` — shipped inside `ComposableSingletons$…` classes in the production APK.
Harmless, noise, and sitting at the very top of a naive ranking.

**The rebuttal is harder than it looks**, because "unreachable" is a claim static analysis cannot
make. The professional form is *"no static path found from any manifest-declared entry point; the
four indirection mechanisms we checked are reflection, dependency injection, service loading and
framework callbacks"*, and if severity depends on it, settle it with a hook that fires or does not.
[`52-StaticAnalysis/scripts/validate-lead.sh`](../52-StaticAnalysis/scripts/validate-lead.sh)
`--reach` builds the closure and is honest when it explodes:

```
depth 5: 540 new referencing class(es)
FRONTIER EXPLODED (540 classes at depth 5).
```

#### Class 4 — the rule fires on a number, not a weakness

`minSdk` below a threshold. "Application can be installed on a vulnerable Android version." The rule
performs an integer comparison and produces prose about "multiple unfixed vulnerabilities" without
naming one.

**The rebuttal.** *"Which vulnerability, and how does this application touch it?"* If you cannot
answer, the item is not a finding. Reporting it spends the client's remediation budget on a support
decision and costs you credibility on the items that matter.

#### Class 5 — the finding is real and the severity is inverted

Rarer, and much more damaging than the first four, because it points the wrong way.

`MEASURED`, this chapter. The example report rates this **`info`**:

```
Content Provider (org.android.cmpen.FlagProvider) is Protected by a permission, but the
protection level of the permission should be checked. [android:exported=true]
[android:readPermission=org.android.cmpen.permission.ACCESS_FLAG]
```

Read the title: the tool is telling you it has not done the check. So do it:

```bash
# host - MEASURED, aapt2 build-tools 35.0.1
aapt2 dump xmltree --file AndroidManifest.xml CMPen-Android-App-v1.2.apk | grep -A2 'E: permission'
#       E: permission (line=23)
#         A: ...:name(0x01010003)="org.android.cmpen.permission.ACCESS_FLAG"
#         A: ...:protectionLevel(0x01010009)=0x00000000
```

`0x00000000` is `normal`. **Any application may declare `<uses-permission>` for it and receive it at
install time, with no prompt and no signature check.** The guard is decorative, and the provider
returns a token from `query()`. An `info` row is a Medium finding.

The validator makes this call automatically, and it is the only place in the whole run where it
raises a severity:

```
# MEASURED
V004  [INFO]  manifest
    FOR     provider declares a permission
    AGAINST permission org.android.cmpen.permission.ACCESS_FLAG has protectionLevel=normal
            - ANY app can hold it, so the provider is effectively unprotected
  VERDICT   UNDER-RATED
```

[23-Permissions](../23-Permissions/README.md) owns the level semantics, including the trap that
23 measured and that [32-Manifest](../32-Manifest/README.md) had to be corrected for: when **both**
apps declare a custom permission, the second install is refused with
`INSTALL_FAILED_DUPLICATE_PERMISSION`, **symmetrically** — so permission squatting only works where
the victim `<uses-permission>` a name it does not itself `<permission>`-declare.

#### Class 6 — the finding is a restatement of another finding

The `appsec` scorecard. `MEASURED`, this chapter: **11 of 39 normalised report items (28%) were
scorecard entries duplicating the manifest, code and certificate sections.**

```
# MEASURED - mobsf-validate.py summary, CMPen v1.2
  CORROBORATED     16   (41.0%)
  UNDER-RATED       1   ( 2.6%)
  OVER-RATED        3   ( 7.7%)
  REFUTED           2   ( 5.1%)
  RESTATES         11   (28.2%)
  NEEDS-HUMAN       6   (15.4%)
```

**The rebuttal is to your own report**, not to the client: never count scorecard entries as findings,
and never quote the scorecard. Validate the underlying section.

### 5.2 The pinning finding, worked — the chapter's flagship example

Every chapter in this repository that touches TLS points here for this, so it is done properly.

#### What a scanner says, and what it means

| Scanner output | What it usually means |
|---|---|
| "App uses certificate pinning" | `okhttp3.CertificatePinner` is **on the classpath**. It is on the classpath in every OkHttp application ever built |
| "App does not use certificate pinning" | May be true. May be a build flag that folded the branch away. May be native. **May be R8** (§5.3) |
| "Insecure TrustManager found" | Usually correct, and usually the highest-severity *real* TLS finding in the report. Confirm the method body is empty |
| "Certificate/pin found in resources" | Could be a bundled **trust store** rather than a pin. 36 calls this `MATRL` and gives it its own confidence class for exactly this reason |

#### The measurement

[36-CertificatePinning §8.1](../36-CertificatePinning/README.md#81-pinning-surfacepy--and-what-it-measured)
ran `pinning-surface.py` against **fourteen third-party packages already installed** on a Redmi
`M2101K6P`, Android 11 / API 30. Detection only; nothing was instrumented, intercepted or modified.

**Twelve of the fourteen presented a pinning surface. Four had a pin value anywhere in the APK.**

> Reporting the surface would have produced twelve findings, **eight of them wrong**.

Three further facts from that table matter here:

- **Seven of fourteen showed four or five layers of surface.** A single-layer bypass addresses a
  fifth of the problem on half the sample.
- **Three were Flutter apps**, where every Java hook is irrelevant to the Dart traffic — and MobSF's
  Java-oriented rules see none of it.
- **Two rows described a stub APK, not an application.** `com.vendor.professionalnet`'s installed
  `base.apk` measured 334 KB. When a scan reports implausibly little for a large app, check the APK
  size before drawing any conclusion. That is §3.13's failure mode appearing in real data.

#### The four layers, and why one grep is not enough

36 grades the surface into four confidence levels, and the distinction between the top two is the
whole point:

| Level | Means | Evidence |
|---|---|---|
| `HIGH` | A configured **pin value** | `sha256/` + 43 base64 chars + `=`; or a `<pin-set>` element |
| `MATRL` | Embedded **trust material**, purpose ambiguous | A PEM certificate in the DEX or a `.so` |
| `MED` | The app **took control of trust** | Custom `X509TrustManager`; `X509TrustManagerExtensions` |
| `LOW` | A library **containing** pinning code is present | `okhttp3.CertificatePinner` in the type pool |

`MATRL` exists as its own class because **a pinned CA and a bundled private trust store are
byte-identical from outside**, and calling a bundled root list "certificate pinning" is a real and
common error.

#### Doing it by hand, in one command

```bash
# host - the 43-character form. `grep sha256/` ALONE matches OkHttp's own parser
# constant and therefore hits essentially every app that uses OkHttp.
mkdir -p /tmp/dexes && unzip -o -j target.apk 'classes*.dex' -d /tmp/dexes
grep -a -o -h -E 'sha256/[A-Za-z0-9+/]{43}=' /tmp/dexes/*.dex | sort -u
```

And the negative claim needs all four layers checked, not one:

```bash
# host - before writing "the app does not pin"
python3 -B ../36-CertificatePinning/scripts/pinning-surface.py --apk target.apk
```

#### How to write it

> **Do not write:** "The application implements certificate pinning."
>
> **Write:** "The application configures one SPKI pin (`sha256/+xpjw…HNkQ=`) for
> `ninja.secops.group` on a process-wide `OkHttpClient`. We confirmed the pin value in
> `classes.dex` and the construction site in the decompiled code. **Presence of a pin is not proof
> of enforcement**; whether a mismatched certificate is actually rejected is recorded in section
> `<x>`, where we attempted interception."

> **🔍 Pentester's Note**
> The inverse error is just as common and more embarrassing: concluding "no pinning" from the absence
> of a `TrustManager`, when the pins are declared in `res/xml/network_security_config.xml`. Static
> analysis has to check every layer before it may make a *negative* claim, and the layers live in
> four different places.

### 5.3 The false negative nobody talks about — measured, twice, on the same app

Everything above is about MobSF saying too much. This section is about MobSF saying too little, in
the one place where a reader has no reason to check: a **negative claim** in the reassuring band of
the report.

The experiment is a controlled one, and this chapter ran it.

**The two artefacts.** The same public training application, two versions, differing in one property
that matters to a name-based detector:

| | v1.0 | v1.2 |
|---|---|---|
| SHA-256 | `f7daada6…f501ff` | `13718667…c39638` |
| R8 / obfuscation | **no** | **yes** |
| The pinner's type name in the DEX | `okhttp3.CertificatePinner` | `m.e` / `m.d` / `m.g` |
| Configured SPKI pin values | **3** | **1** |
| A class-name-based pinning detector | **finds it** | **finds nothing** |

**The v1.2 construction site, decompiled** (`MEASURED`, jadx 1.5.3):

```java
// out/sources/b/h.java  -- every type name here is R8 output
static {
    t tVar = new t();                                    // OkHttpClient.Builder
    m.d dVar = new m.d(0);                               // CertificatePinner.Builder
    dVar.f117a.add(new m.e(new String[]{                 // CertificatePinner.Pin
        "sha256/+xpjwBQ7+BLhq1r+/AU3qLNIaXPt+JgXAJ9yIQaHNkQ="}[0]));
    m.g gVarB = dVar.b();
    tVar.f212q = gVarB;
    f19a = new u(tVar);                                  // the shared OkHttpClient
}
```

**The v1.0 construction site, decompiled** (`MEASURED`, same tool, same version):

```java
// out10/sources/org/android/cmpen/RetrofitClient.java:21
builder.certificatePinner(new CertificatePinner.Builder()
    .add("ninja.secops.group", "sha256/jWseeY2GFCMiPCL39cf2IabLpYKO4uIBxLEHs7iE+00=")
    .add("ninja.secops.group", "sha256/jQJTbIh0grw0/1TkHSumWb+Fs0Ggogr621gT3PvPKG0=")
    .add("ninja.secops.group", "sha256/C5+lpZ7tcVwmwQIMcRtPbsQtWLABXhQzejna0wHFr8M=")
    .build());
```

Same library, same API, same intent. **One variable changed — whether R8 ran — and a name-based
detector's answer flips from correct to backwards.**

**The value survives, because R8 does not rename string literals.** `MEASURED`, this chapter:

```bash
# host - the 43-character grep, on the OBFUSCATED build
grep -a -o -h -E 'sha256/[A-Za-z0-9+/]{43}=' /tmp/dexes/*.dex | sort -u
# sha256/+xpjwBQ7+BLhq1r+/AU3qLNIaXPt+JgXAJ9yIQaHNkQ=
```

And 36's own detector, run against the obfuscated build (`MEASURED`, this chapter, unedited output):

```
==============================================================================
  pinning surface: cmpen.apk
==============================================================================
  1 dex, ABIs: none, 0 native libs

  [1. SSLContext / X509TrustManager]
      + [MED  ] Custom X509TrustManager
      + [MED  ] SSLContext.init with own TrustManager
  [1b. X509TrustManagerExtensions]
      + [MED  ] X509TrustManagerExtensions
  [3. OkHttp CertificatePinner]
      + [HIGH ] CONFIGURED OkHttp/NSC pin value
                value: 1 distinct value(s): sha256/+xpjwBQ7+BLhq1r+/AU3qLNIaXPt+JgXAJ9yIQaHNkQ=
      + [LOW  ] OkHttp pin failure message
  [4. HostnameVerifier]
      + [MED  ] Custom HostnameVerifier

  VERDICT: PIN CONFIGURED at 1 layer(s): 3. OkHttp CertificatePinner
==============================================================================
```

**Look at that output twice.** Six detections, and only **one** of them is the pin. The four `MED`
rows are OkHttp's own internal `X509TrustManager`, `SSLContext` usage, `X509TrustManagerExtensions`
and `HostnameVerifier` implementations — surface that ships with the library, unconditionally, in
every OkHttp application. That is 36's 12-of-14 measurement reproducing itself on a fresh sample: the
*surface* is everywhere and the *pin* is one line.

**And the value-based detector is immune to the obfuscation that defeated the name-based one**,
because a 43-character base64 string is not a symbol.

`mobsf-validate.py` therefore treats a negative pinning claim as a claim to be tested, and refutes
it (`MEASURED`, unedited):

```
V033  [WARNING]  appsec:network
  claim     This application does not implement certificate pinning
    FOR     configured SPKI pin value(s) in the DEX: sha256/+xpjwBQ7+BLhq1r+/AU3qLNIaXPt+JgXAJ9yIQaHNkQ=
  VERDICT   REFUTED
  NEXT STEP The report is WRONG in the dangerous direction. The scanner looked
            for a class name; R8 renamed the class. Grep for the 43-character
            pin instead - see 36-CertificatePinning section 8.2.
```

> **⚠️ Warning — the general rule this case is an instance of**
> **Every name-based detection in a scanner degrades to a false negative under obfuscation, silently
> and without any signal in the report.** That covers root detection, tamper detection, crypto
> libraries, tracker identification, and anything else keyed on a type or method name. The
> detections that survive R8 are the ones keyed on **values** — string literals, resource contents,
> manifest attributes, and file structure — because R8 renames symbols, not data.
> [40-Obfuscation](../40-Obfuscation/README.md) recovers strings *first*, for exactly this reason.

There is a second-order consequence worth stating: **a scanner's report on an obfuscated app is
systematically shorter than its report on the same app unobfuscated.** A reader who does not know
this will read "fewer findings" as "more secure". It is neither; it is less visibility.
[42-R8](../42-R8/README.md) measured a related trap: three APKs that were **byte-identical in size
(12,757 B) despite DEX sizes of 7,384 / 2,920 / 7,180**, because `apksigner` pads the signing block
to a 4 KiB boundary. Compare the DEX, not the APK — and do not read a scanner's item count as a
security metric in either direction.

### 5.4 The join MobSF does not make

MobSF's analysers run independently and write into separate report sections (§4.1). Nothing
re-reads the manifest findings in the light of the code findings. **Almost every high-severity mobile
finding is a join across those sections.**

`MEASURED`, this chapter, on `CMPen-Android-App-v1.2.apk`. Three facts, in three different places in
the report, none of them individually a High:

| Fact | Report section | On its own |
|---|---|---|
| `WebViewActivity` is `android:exported="true"` | `manifest_analysis` — `warning`, one of five identical rows | Surface |
| `setJavaScriptEnabled(true)` at `WebViewActivity.java:14` | `code_analysis` — `warning` | Almost every WebView does this |
| `addJavascriptInterface(new WebAppInterface(), "AndroidBridge")` at `:15` | `code_analysis` — `high` | A bridge, danger depends on the page |

And a fourth fact **no rule fires on at all**, because it is not a pattern — it is a data flow:

```java
// out/sources/org/android/cmpen/WebViewActivity.java:17  (MEASURED, jadx 1.5.3)
String stringExtra = getIntent().getStringExtra("load_url");
if (stringExtra == null) { stringExtra = "data:text/html,<html>...</html>"; }
webView.loadUrl(stringExtra);                                        // :20
```

**Join all four and it is a High.** Any application on the device, holding no permissions, can start
this Activity with a `load_url` extra pointing at a page it controls; that page runs in the victim's
WebView and calls `AndroidBridge.getAuthToken()`. The bridge method returns a token the app
obfuscates with base64 and a single-byte XOR (`MEASURED`: `B/g.java:36-38` XORs each decoded byte
with `0x5A`).

Four report lines in three sections, plus one line nothing reported, equals one finding. **The
joining is the work**, and it is the reason a scanner cannot write your report even in principle.
[`examples/finding-rewritten.md`](examples/finding-rewritten.md) writes this one out in full, next to
the raw scanner output.

Three more joins worth knowing by name, because they recur:

| Join | Section A | Section B | Result |
|---|---|---|---|
| **Cleartext that is actually used** | `usesCleartextTraffic=true` (manifest) | an `http://` endpoint in `urls` that is not a namespace URI | Real MITM exposure. Either half alone is nearly nothing |
| **Backup that matters** | `allowBackup=true` with no rules file (manifest) | a credential store named in `file_analysis` or found by hand | A named file leaves the device |
| **Exported provider over real data** | exported provider (manifest) | a `query()`/`openFile()` that returns something (code) | Data disclosure to any installed app |

Notice the shape: in every case, section A is the *reachability* half and section B is the *asset*
half. MobSF reports both halves and joins neither, because §4.1's pipeline is one-pass.

### 5.5 What MobSF is genuinely, reliably good at

A chapter this critical has to be equally precise about the other direction. These are the things
MobSF does that you should simply use, subject only to the caveat in the last column.

| What | Why it is reliable | Caveat |
|---|---|---|
| **Component inventory** | It is reading the manifest | Merged splits and runtime-enabled components; §4.6 |
| **Permission list** | Same | Custom permissions' levels are yours to resolve |
| **Browsable / deep-link map** | Same, and this is genuinely excellent | It tells you the filter, not what the Activity does with the URI |
| **Signature scheme and signer DN** | Structured data, well-specified format | None worth mentioning. This section is trustworthy |
| **File and library inventory** | It is listing ZIP entries | §3.13 |
| **URL and domain extraction** | String extraction, done thoroughly | Namespace URIs and doc links dominate the raw list |
| **Tracker identification** | A curated database of known SDK signatures | Name-based, so §5.3 applies under obfuscation |
| **Native hardening table** | Reading ELF headers | It is a build-config table, not a finding list |
| **Doing all of it in ninety seconds, for twenty apps** | This is the whole point | — |

`MEASURED`, this chapter — an independent cross-check of the inventory half. Running
[32-Manifest](../32-Manifest/README.md)'s own auditor over the same manifest produces a compatible
component census and a materially better severity assignment:

```
# MEASURED - python3 -B ../32-Manifest/scripts/manifest-audit.py manifest-aapt2.txt --target-sdk 35
  ANDROID MANIFEST AUDIT - org.android.cmpen
  minSdk        : 24
  targetSdk     : 35
  components    : activity 5/7 exported, provider 2/2 exported
  CRITICAL: 0 | HIGH: 6 | MEDIUM: 6 | LOW: 0 | INFO: 12 | POSITIVE: 1
  ...
  * = UNPROVEN: depends on reachability, on data you have not inspected,
      or on a referenced file you have not yet opened.
```

Two differences from a scanner report are worth pointing at. It prints a `POSITIVE` band — things the
app got *right* — and it marks rows `UNPROVEN` with an explicit legend saying why. Both are stage-7
discipline expressed in a tool's output format, and both are things you can adopt in your own
reporting whatever tool produced the input.

### 5.6 Honest severity for MobSF's finding categories

The rubric is [52 §5.5](../52-StaticAnalysis/README.md#55-the-four-questions-as-a-rubric)'s and
[80-Appendix](../80-Appendix/README.md) owns the full version. Severity comes from **what reaching it
gets an attacker**, never from what the construct is:

| | Not reachable | Reachable by the app only | Reachable by another app | Reachable from the network |
|---|---|---|---|---|
| **No asset behind it** | Informational | Informational | Informational | Low |
| **Device metadata** | Informational | Informational | Low | Low |
| **User data** | Informational | Low | Medium | High |
| **Credentials / financial** | Low | Medium | High | Critical |

Applied to the categories MobSF actually emits:

| MobSF category | Default read | Severity comes from |
|---|---|---|
| Exported activity | **Lead** | What an unprivileged caller achieves. Demonstrate from an *app*, not from `adb shell` |
| Exported provider, unprotected | **Lead, often a finding** | What `query()`/`openFile()` returns |
| Exported provider, "protected" | **Check the level first** | §5.1 class 5 |
| Browsable activity | **Lead** | What the Activity does with the URI parameters |
| `debuggable=true` | **Near-finding** | Confirm with `dumpsys package … flags=`; the precondition is ADB access |
| `allowBackup=true` | **Lead** | Name the file that leaves the device |
| Debug certificate | **Finding** | The key is public; anyone can sign an update-compatible package |
| Cleartext traffic flag | **Lead** | Find an actual `http://` endpoint that is used |
| Weak crypto (ECB, DES, MD5) | **Lead** | What it protects, and often the *key derivation* is worse |
| `addJavascriptInterface` | **Lead until joined** | Whether the loaded URL is attacker-influenced |
| Hardcoded secret | **Classify first** | §5.1 class 2 |
| Native hardening flags | **Not findings** | Report as a build-configuration table |
| `minSdk` warning | **Reject** | §5.1 class 4 |
| Trackers | **Informational** | A privacy/compliance topic, not a vulnerability |
| Security score | **Never report it** | §3.9 |

Two rules override the table, both learned the hard way in this repository:

- **A shipped key the vendor designs to ship is not automatically a finding.** Google API keys,
  Firebase app IDs, Play Billing public keys and SDK project tokens are *client* credentials. The
  finding, when there is one, is *"this key has no application restriction and this scope"* — and you
  must check the restriction before writing it.
- **A control that can be turned off remotely is capped at the strength of the remote control.** If a
  feature flag can disable pinning, the pinning finding is about the flag.

### 5.7 OWASP MASVS and MASTG mapping — and the limits of MobSF's own mapping

MobSF attaches MASVS identifiers and OWASP Mobile Top 10 categories to its findings, and this is
genuinely useful for report structure. Two caveats.

| MASVS control | What MobSF contributes | What it cannot |
|---|---|---|
| **MASVS-STORAGE** | Finds external-storage and preference APIs | Cannot tell you whether the data is sensitive. [33-Storage](../33-Storage/README.md) validates |
| **MASVS-CRYPTO** | Finds ECB, DES, MD5, fixed IVs, seeded `SecureRandom` | Cannot see a **key derivation** defect. §9.3 measured exactly this gap |
| **MASVS-AUTH** | Finds credential-shaped literals | Cannot tell a hash from a password |
| **MASVS-NETWORK** | The NSC file, cleartext flags, trust managers | Cannot tell surface from enforcement. §5.2 |
| **MASVS-PLATFORM** | The component inventory, deep links, WebView configuration | Cannot join them. §5.4 |
| **MASVS-CODE** | Library list | **Not versions.** See below |
| **MASVS-RESILIENCE** | Detects the presence of anti-tamper and obfuscation | Presence is not enforcement. [38](../38-TamperDetection/README.md) |

**MASVS-CODE deserves the emphasis [71-OWASP-Mobile](../71-OWASP-Mobile/README.md) gives it.** The
control asks for a dependency inventory **with versions**, and versions are the part everyone skips
because they are hard. An inventory that says "uses OkHttp" is not an inventory; one that says
"OkHttp 4.9.3, high confidence, from the `META-INF` version stamp corroborated by the class set" is.
[`17-Libraries/scripts/lib-fingerprint.py`](../17-Libraries/scripts/lib-fingerprint.py) exists to
produce the second kind. MobSF's library list is a starting inventory and 17's own tool table says so
plainly: *"Library detection is prefix-based and shallow; treat as a starting inventory."*

The second caveat is subtler: **a MASVS identifier on a finding does not mean the control was
tested.** It means a rule that someone tagged with that identifier matched. A report that claims
MASVS coverage on the strength of scanner tags is claiming test coverage it does not have.

### 5.8 How malware defeats it

Everything in §5.3 applies to an adversary who is *trying*. Malware authors are.

| Technique | What MobSF sees | Chapter |
|---|---|---|
| **Packing** — the real DEX is an encrypted asset, decrypted and loaded at runtime | A tiny stub. The whole code-analysis section describes a loader | [40-Obfuscation §3.7](../40-Obfuscation/README.md) |
| **Reflection for sensitive APIs** | Nothing. `Class.forName("…").getMethod("…").invoke(…)` matches no API rule | [04-Java](../04-Java/README.md) |
| **String encryption** | An app with no URLs at all — which is itself the signal | [40-Obfuscation §6.1](../40-Obfuscation/README.md) |
| **`RegisterNatives`** | A `.so` with a clean symbol table | [16-JNI](../16-JNI/README.md) |
| **Runtime receiver registration** | A short receiver list | [29](../29-BroadcastReceivers/README.md) |
| **Server-controlled behaviour** | A benign app. The payload arrives after review | — |
| **Emulator and root detection** | A dynamic-analysis section describing an app that did nothing | [37](../37-RootDetection/README.md) |

> **🧠 Mental Model**
> **A clean MobSF report on a sophisticated sample is not evidence of anything.** It is what a
> sophisticated sample is designed to produce. The signals that survive are structural: a
> disproportionate asset directory, a tiny DEX, an app with zero string literals, a `.so` with
> `JNI_OnLoad` and no `Java_` exports. None of those are findings; all of them are reasons to stop
> reading the report and start reading the file.

### 5.9 How MobSF is misused, and what it costs

The failure is not running MobSF. The failure is a deliverable that is MobSF's output with a cover
page. Six symptoms, in the order a reviewer notices them:

1. **The finding count matches the scan's item count.** Nobody validated anything.
2. **Every exported component is a separate finding at the same severity.** §3.4.
3. **The severities are MobSF's**, including a CVSS that is identical to the rule's constant.
4. **The security score appears in the executive summary.** §3.9.
5. **There is no limits section.** So the reader cannot tell what was not examined. §3.14.
6. **There is no ledger.** So the reader cannot tell whether the eight findings were selected or
   were simply all that the tool produced.

The cost is concrete and it is not just embarrassment:

| Cost | Mechanism |
|---|---|
| The client fixes the wrong things | Remediation budget goes to `minSdk` and exported launcher activities |
| The client stops believing the *real* findings | Once two items are shown to be nonsense, the rest is discounted |
| A missing control is reported as present | §5.3's false negative, in the reassuring band |
| The next tester inherits a false baseline | "The previous test found nothing here" |

[00-Introduction's FAQ](../00-Introduction/faq.md) puts it bluntly and it is worth repeating:
delivering a MobSF export as a penetration test report is the fastest way to lose a client.

### 5.10 How pentesters test what MobSF reports

The whole of §7 and §8 is this, but in one table, because it is the reference people come back for:

| MobSF says | The test that settles it |
|---|---|
| Exported activity | Start it **from an unprivileged app**, not `adb shell`. 60-ADB measured that `com.android.shell` holds **200 permissions**, 16 of them pre-granted `SYSTEM_FIXED` — a shell result proves nothing about app reachability |
| Exported provider | `content query --uri content://<authority>` from an app, then `openFile` with a traversal candidate |
| Browsable activity | `am start -a android.intent.action.VIEW -d '<scheme>://<host><path>'` and read what it does with the parameters |
| `debuggable=true` | `dumpsys package <pkg> \| grep flags=` then `run-as <pkg> ls /data/data/<pkg>` |
| `allowBackup=true` | Name the file. `run-as <pkg> ls -la shared_prefs databases` |
| Cleartext traffic | Proxy it and watch for an actual plaintext request |
| Pinning claim | Attempt interception; attribute the rejection with 36's `pin-attribution.js` |
| Weak crypto | Hook the `Cipher` boundary and tabulate input and output |
| Hardcoded secret | Decode it, classify it, then check its scope with the vendor |
| Root/tamper detection present | Show the app **refusing to run**, not the string being present |

### 5.11 Operational security of running MobSF

This is not a footnote. A MobSF instance accumulates, on disk, indefinitely:

- Every artefact ever uploaded — including your clients' unreleased binaries.
- The **decompiled source** of every one of them.
- Extracted secrets, endpoints and certificates, indexed and searchable.

Guarded by a **single static API key with no scopes** (§4.4).

| Rule | Why |
|---|---|
| **Never upload a client artefact to a MobSF instance you do not control** | Public and shared instances exist. Uploading a pre-release binary to one is a disclosure, and probably a contract breach |
| **Bind to localhost** | `-p 127.0.0.1:8000:8000`, not `-p 8000:8000`. The latter listens on every interface |
| **One instance per engagement, deleted afterwards** | `delete_scan` per hash, then destroy the container |
| **Treat the key as a credential** | It will end up in CI logs. Rotate it |
| **Run it in a container on a host you can lose** | It parses hostile input for a living (§2.6) |
| **Check the engagement scope before uploading anywhere** | Some contracts prohibit third-party processing of the artefact entirely |

> **⚠️ Warning**
> MobSF's dynamic analyser also uploads and installs the application on a device it controls, and can
> route its traffic through its own proxy. On a shared instance, that means a third party's
> infrastructure sees your client's API traffic and, potentially, credentials used during testing.
> [29-BroadcastReceivers](../29-BroadcastReceivers/README.md) measured a related lesson worth
> carrying: **`dumpsys` records broadcast extras in cleartext** — a test broadcast carrying
> `token=SUPERSECRET123` was readable afterwards. Anything you send while testing is recoverable by
> anything that can read the logs.

### 5.12 Where MobSF sits against the alternatives

| Tool | Stage it serves | Genuinely good at | Where it stops |
|---|---|---|---|
| **MobSF** | 1–5, half of 6 | **Breadth**, and a fast first inventory of someone else's app | No stage 7. One severity per rule; cannot join sections |
| `jadx` ([56](../56-JADX/README.md)) | 3 | Readability; the fastest route to understanding | Reconstruction can be wrong, and it under-reports its own failures |
| `apktool` | 3 | Smali plus fully decoded resources | Not a decompiler; slow |
| `aapt2 dump` | 3, 4 | **The platform's own parse** — the tiebreaker in a divergence | Code |
| `apkid` | 2 | Packer, obfuscator and compiler identification | Narrow by design, excellent within it |
| `semgrep` | 5 | Syntax-aware rules; far fewer shape false positives than regex | Needs parseable output; obfuscation defeats it |
| `static-sweep.py` ([52](../52-StaticAnalysis/README.md)) | 5, 6 | Aggregation, **scoring with printed terms**, a next step per lead | Not a decompiler, manifest auditor or judge |
| `manifest-audit.py` ([32](../32-Manifest/README.md)) | 4 | Component semantics including implicit `exported` | Not code |
| `pinning-surface.py` ([36](../36-CertificatePinning/README.md)) | 4 | Four-layer pinning surface with confidence grading | Detection only |
| `lib-inventory.sh` ([17](../17-Libraries/README.md)) | 4 | Dependency inventory with versions, MASVS-CODE | Not reachability |
| Drozer | 7 | **Reachability from an unprivileged app** — the thing that matters | Needs an agent installed; some modules are dated |
| Frida ([53](../53-Frida/README.md)) | 7 | Settling any question static analysis cannot | Needs the app to run |

**The honest summary:** MobSF is the widest and the shallowest. Use it first, believe it least, and
own the stage it does not have.

---

## 6. Reverse Engineering Perspective

MobSF is, internally, a reverse-engineering toolchain with a report generator bolted on. This section
is about reading its output *as* an RE artefact — and, more importantly, about the checks that tell
you how much of the application it actually managed to read.

### 6.1 What MobSF shows you, in RE terms

| Report section | The RE operation behind it | The tool you would use by hand |
|---|---|---|
| "Java source" viewer | DEX to Java-like source | `jadx -d out target.apk` |
| "Smali" viewer | DEX to Smali | `apktool d -f target.apk -o work`, or `baksmali` |
| Manifest viewer | AXML to XML | `aapt2 dump xmltree --file AndroidManifest.xml target.apk` |
| Strings | The DEX string table plus resources | [`04-Java/scripts/dump-strings.py`](../04-Java/scripts/dump-strings.py) |
| Files | ZIP entries | `unzip -l target.apk` |
| Binary analysis | ELF header parsing | `readelf -d`, `readelf --dyn-syms` |
| Certificate | The signature block | `apksigner verify -v --print-certs` |
| APKiD | Packer/obfuscator/compiler fingerprints | `apkid target.apk` |

**Nothing in that right-hand column is hard.** MobSF's contribution is that it runs all eight without
being asked and puts the results next to each other. That is worth something on an app you have never
seen, and worth nothing once you know what you are looking for.

### 6.2 The three checks that tell you how much MobSF actually read

This is the most valuable subsection in §6, because none of the three appears in the report.

#### Check 1 — how much of the app is even in the DEX?

```bash
# host
unzip -l target.apk | grep -E '\.dex$'
unzip -l target.apk | grep -E 'lib/[^/]+/' | awk -F/ '{print $2}' | sort -u
unzip -l target.apk | grep -E 'assets/' | sort -k1 -rn | head -10
```

A 2 MB DEX beside a 40 MB `.so` means the code analysis covered a rounding error. A 300 KB DEX in a
50 MB app means a packer or a cross-platform runtime. Both belong in the limits section, in numbers.

#### Check 2 — did the decompiler succeed?

MobSF's report has no answer. Produce one:

```bash
# host - jadx's own count, which 56-JADX measured to be 30x optimistic
jadx -d out target.apk 2>&1 | tail -3
# INFO  - finished with errors, count: 61

# host - the count that is actually true: refused methods in the OUTPUT TREE
grep -rl 'JADX ERROR\|Failed to decompile\|// decompilation failed' out/sources | wc -l
grep -rho 'JADX ERROR[^\n]*' out/sources | sort | uniq -c | sort -rn | head
```

> **🔬 Under the Hood**
> [56-JADX](../56-JADX/README.md) is the chapter that measured the gap: console said
> `count: 61`, the tree contained **2,104 refused methods across 1,424 files**. *"Chapter 56 counts
> the tree, not the summary."* Adopt that habit here: a MobSF code-analysis section over a tree with
> two thousand refused methods is not a scan of the application, and nothing in the report says so.

`MEASURED`, this chapter, on the two example APKs — and note that the *smaller*, obfuscated build
decompiled cleanly while the larger one did not:

| APK | jadx console | `.java` files produced |
|---|---|---|
| v1.2 (287 KB, R8) | clean | 234 |
| v1.0 (5.6 MB, no R8) | `finished with errors, count: 8` | 1,995 |

Chapter 56 found a related and counter-intuitive result worth carrying: **more debug information made
decompilation worse** — a method that decompiles cleanly from a release DEX was *refused* from the
debug DEX. "Always build with debug info" is not universally good advice for an analyst.

#### Check 3 — is the code even there?

```bash
# host - an app with no URLs at all is building them, not lacking them
python3 -B ../04-Java/scripts/dump-strings.py target.apk --min-len 8 | grep -c 'http'
apkid target.apk           # packers, obfuscators, compiler fingerprints
```

### 6.3 What obfuscation does to each report section — measured

The controlled pair from §5.3 lets this be a measurement rather than a claim. Same application
family, one built with R8 and one without.

| Report section | Unobfuscated (v1.0) | R8 (v1.2) | Why |
|---|---|---|---|
| **Manifest analysis** | Full | **Full — unchanged** | R8 does not rename manifest-declared component names; it cannot, the platform resolves them by string |
| **Certificate** | Full | **Full — unchanged** | Nothing to obfuscate |
| **Component inventory** | Full | **Full — unchanged** | Same reason as the manifest |
| **URLs / domains** | Found `https://ninja.secops.group/` | Found `https://ninja.secops.group` | **String literals survive R8 completely** |
| **Secrets** | Found all six literals | Found all seven literals | Same reason |
| **Code analysis — API rules** | Fires on `Cipher.getInstance("DES")` | Fires on `Cipher.getInstance("AES/ECB/…")` | The *framework* API names are not renamed — R8 cannot rename `javax.crypto` |
| **Code analysis — type-name rules** | `okhttp3.CertificatePinner` **found** | `m.e` — **found nothing** | §5.3. This is the whole difference |
| **Library / tracker identification** | Package prefixes intact | Prefixes destroyed | Name-based detection |
| **Readability of the cited file** | `RetrofitClient.java`, obvious | `b/h.java`, requires work | Renaming |

**The pattern is exact and it is worth memorising:**

> **Anything a scanner derives from DATA survives obfuscation. Anything it derives from NAMES does
> not.** Manifest attributes, string literals, resource values, ZIP structure and framework API names
> are data. Application class names, method names, field names and package prefixes are names.

That is why [40-Obfuscation](../40-Obfuscation/README.md) recovers strings first, and why 36's
pinning detector is built on a 43-character value rather than a type name.

One correction this repository already had to make, recorded so nobody restores the wrong version:
[42-R8](../42-R8/README.md) scanned **19 real APKs, 316,000+ classes** for `kotlin.Metadata` and
found **zero wholesale name recovery** — 10 carried no metadata at all, and one carried **1,393 empty
shells**, so a naive `grep` reports 1,393 false positives. What *does* survive is **Kotlin property
names**, structurally, because R8 renames JVM members and a property is not one. If a scanner claims
to have deobfuscated an app from Kotlin metadata, that is the claim to check.

### 6.4 Confirming a report claim at the bytecode level

The rule from [52 §3.3](../52-StaticAnalysis/README.md#33-stage-3--decompile): **jadx to understand,
Smali to be certain.** When a finding rests on the exact semantics of a method, read the Smali,
because Smali is a transliteration of the bytecode and cannot be wrong about it, while decompiled
Java is a reconstruction and can be.

The worked instance from [52 §9.2](../52-StaticAnalysis/README.md#92-intermediate--a-base64-constant-and-honest-severity),
confirming a base64 literal really is passed to a decoder:

```
# host: dexdump -d classes3.dex
0005ce: 1a00 2b00   |001f: const-string v0, "TUhMe01PRElGSUVEX1ZBUklBQkxFfQ==" // string@002b
0005da: 6e20 1600   |0025: invoke-virtual {v1, v0}, Ljava/util/Base64$Decoder;.decode:(Ljava/lang/String;)[B
```

Both halves confirmed: the literal is there, and it is passed to a decoder.

The general habit, per report section:

| Report claim | Bytecode-level confirmation |
|---|---|
| A code rule fired at `X.java:N` | `apktool d`, open the corresponding `.smali`, find the `invoke-` |
| A string is a "secret" | `dexdump -d` and find the `const-string`, then follow the register |
| A manifest attribute | `aapt2 dump xmltree` — the platform's own parser, not a re-implementation |
| A native symbol is present | `readelf --dyn-syms --wide lib/*/lib*.so` |
| A library version | `META-INF/*.version`, corroborated by the class set — [17](../17-Libraries/README.md) |

> **⚠️ Warning**
> [56-JADX](../56-JADX/README.md) built a case where a method **decompiles to clean, warning-free
> Java that returns 100 while the bytecode returns 105**, and ships `Proof.java` which runs both
> readings and prints both numbers. It then failed to isolate the trigger across four variants and
> **says so** rather than inventing a cause. Decompiled Java is *evidence toward* a finding, not the
> finding — and that applies with full force to every line of a MobSF code-analysis section, because
> those lines were produced from decompiled Java.

### 6.5 Packers: when the report describes the stub

The worst case, and the one where a MobSF report is actively misleading rather than merely thin.

**The shape.** A commercial application with one small `classes.dex`, a large high-entropy asset, an
`<application android:name>` you do not recognise, and a `System.loadLibrary` in that class. The DEX
that runs is decrypted into memory at startup and handed to `InMemoryDexClassLoader`.

**What MobSF reports.** A complete, professional analysis of the loader. Few findings, a decent
score, and not one statement about the application.

```bash
# host - the four-signal check. Any one alone is nothing; together they are conclusive.
unzip -l target.apk | grep -E '\.dex$'                       # 1. one small DEX?
unzip -l target.apk | grep -E 'assets/' | sort -k1 -rn | head # 2. a large opaque asset?
aapt2 dump xmltree --file AndroidManifest.xml target.apk \
    | grep -A1 'E: application' | grep 'android:name'         # 3. an unfamiliar Application class?
apkid target.apk                                             # 4. a named packer?
```

> **⚠️ Warning**
> **High entropy is not evidence of encryption.** Compressed data, PNGs, ZIPs, ML model weights and
> font atlases are all high entropy. The signal is entropy **plus** context, which is why the check
> above has four parts.

[40-Obfuscation §8.4](../40-Obfuscation/README.md) states the consequence in one sentence:
*"a report that forwards MobSF output verbatim on a packed app is worthless, because MobSF only ever
saw the stub."*

The AOSP mechanism, for completeness: `DexFile.openInMemoryDexFile` and `InMemoryDexClassLoader`
(`art/libdexfile/dex/dex_file.cc`, `libcore/dalvik/src/main/java/dalvik/system/DexFile.java`) let an
app hand the runtime a `ByteBuffer` that never touched the filesystem. [22-SELinux](../22-SELinux/README.md)
measured *why* this became the standard technique: app domains kept `execmem` —
`(allow appdomain self (process (execmem)))`, quoted from a device's own `plat_sepolicy.cil` — but
lost `file:execute_no_trans` and `file:execmod` on `app_data_file`. Writing a `.so` and loading it
stopped working; loading a DEX from memory did not.

---

## 7. Dynamic Analysis

`EXPECTED SHAPE` throughout this section unless a line is marked otherwise. MobSF's dynamic analyser
was **not run** (§1.6), and this chapter's device (`i9000S`, API 33) is unrooted with no
`frida-server`, so it could not have been run against it either. What follows is what the analyser
does according to its documentation, and — the part that is actually useful and *is* grounded — what
you should cross-check with it.

### 7.1 What the dynamic analyser is

An orchestrator around an instrumented Android instance. Given a scan hash and a connected device, it
installs the application, exercises it, captures behaviour through several channels, and merges the
results into the same report.

| Channel | What it produces |
|---|---|
| **HTTPS interception** | A traffic log, via MobSF's own proxy and CA |
| **Activity exercise** | Launches the main activity, then exported activities, capturing screenshots |
| **Exported-component probing** | Attempts to start exported activities and services |
| **Filesystem snapshot** | The app's private directory before and after |
| **Logcat capture** | Filtered to the app's process |
| **Frida instrumentation** | Runtime API tracing, plus optional bypass scripts and your own hooks |
| **TLS/SSL tests** | Whether interception succeeded — which is the pinning question |

### 7.2 Does it need root? Effectively, yes

This is the FAQ's most common practical question and the answer has parts:

| Requirement | Why | Can you avoid it? |
|---|---|---|
| **A CA in the system trust store** | To intercept traffic from an app targeting API 24+ that does not opt into user CAs | Only by patching the app's NSC, which changes what you are testing |
| **`frida-server` running as root** | Runtime instrumentation | No |
| **Read access to the app's private directory** | The filesystem diff | `run-as` works *only* if the app is debuggable |
| **Ability to install and drive arbitrary packages** | Everything else | On a normal device, mostly yes |

So: **MobSF's own prepared AVD, Genymotion, or a rooted physical device.** A stock retail phone will
not do.

> **⚠️ Warning — a trap this repository measured, and it invalidates naive TLS tests**
> On the rooted device used by several chapters here, **APatch had replaced
> `/system/etc/security/cacerts` with a tmpfs and bind-mounted an interception CA into it**, with 139
> certificates present. The consequence is severe and easy to miss: **a successful intercept on that
> device does not prove the app trusts user-installed CAs**, because the proxy CA is in the *system*
> store. Before any trust-store claim:
>
> ```bash
> # adb shell
> mount | grep cacerts
> ```
>
> If a rooting stack appears, the device cannot answer user-store-versus-system-store questions.
> [44-NetworkSecurityConfig](../44-NetworkSecurityConfig/README.md) hit this and wrote it up as a
> first-class methodology trap rather than publishing a conclusion it could not support, and
> [35-SSL](../35-SSL/README.md) diagnosed the mechanism: a `trustusercerts` module had *promoted* the
> CA into the system store. **A device whose posture you have not established will teach you the
> opposite of the truth.**

### 7.3 The liveness problem — and why it is fatal to unattended dynamic scanning

[51-DynamicAnalysis](../51-DynamicAnalysis/README.md)'s most valuable result was a failure, and it
applies directly to every automated dynamic run:

> **A void run and a clean negative produce identical reports.** `am start` was absorbed by a pending
> permission dialog, all nine capture channels went silent, and the report looked exactly like a
> well-behaved app doing nothing wrong. **Every dynamic session needs a liveness check before its
> silence means anything.**

MobSF's dynamic analyser does not provide one. So provide one:

```bash
# adb shell - is the process even alive, and did anything happen?
pidof com.example.target
dumpsys activity activities | grep -A3 'mResumedActivity'
dumpsys package com.example.target | grep -E 'flags=|firstInstallTime|lastUpdateTime'
logcat -d --pid=$(pidof com.example.target) | wc -l     # zero lines is a RED FLAG, not a pass
```

And a second one, from the same chapter, for the denominator problem:

> **The same session scored 67% or 50% coverage depending on who defined the denominator.** Chapter
> 51 measured 4 components in the manifest against 3 in the device's resolver tables — and the
> flattering number comes from letting the *device* define the total. **Runtime evidence cannot
> supply its own denominator.** A MobSF dynamic report that says "all exported activities were
> exercised" is using the manifest as its denominator, and §3.14's blind spots say why that is the
> wrong one.

There is a third trap on OEM devices worth knowing before you conclude an app is inert:

> **While the keyguard is up, some OEM builds refuse every activity start that originates from an
> app — including an app starting its own Activity.** `adb shell am start` still works, so half your
> commands succeed and half fail and the pattern looks random. Check first:
> `adb shell "dumpsys trust" | grep -o "deviceLocked=[01]"`.

### 7.4 What to cross-check, per static finding class

This is the table to keep. Left column: what the static report claimed. Right column: the runtime
observation that converts it into a finding or kills it.

| Static claim | Dynamic confirmation | Chapter |
|---|---|---|
| `debuggable=true` | `dumpsys package … flags=[ DEBUGGABLE … ]`, then `run-as <pkg> ls /data/data/<pkg>` | [21](../21-App-Sandbox/README.md) |
| Exported activity | Start it **from an app**, and observe what the caller receives | [30](../30-Activities/README.md) |
| Exported provider | `query()` and `openFile()` from an app; read the returned rows | [27](../27-ContentProviders/README.md) |
| Browsable deep link | `am start -a android.intent.action.VIEW -d '<uri>'`, then read the UI and the logs | [26](../26-Intent/README.md) |
| Cleartext traffic | Proxy; observe an actual plaintext request | [44](../44-NetworkSecurityConfig/README.md) |
| Pinning claim (either direction) | Attempt interception; **attribute the failure** with 36's `pin-attribution.js` | [36](../36-CertificatePinning/README.md) |
| Weak crypto | Hook `Cipher.getInstance`/`doFinal` and tabulate transform, key and IV | [34](../34-Cryptography/README.md) |
| Hardcoded secret | Hook the consumer and see whether the value is ever used | [53](../53-Frida/README.md) |
| Root/tamper detection | Show the app **refusing to run** | [37](../37-RootDetection/README.md), [38](../38-TamperDetection/README.md) |
| Receiver list | `dumpsys activity broadcasts` — this is where the missing 69% lives | [29](../29-BroadcastReceivers/README.md) |

The pinning row deserves its own emphasis because "no traffic appeared" has at least six causes, only
one of which is pinning. 36 ships `pin-attribution.js` specifically to attribute the rejection, and
its §7 makes the argument: **run a universal bypass before mapping the surface and you cannot
interpret the result.**

### 7.5 A Frida script for the one thing MobSF cannot tell you

The recurring question after a MobSF scan is *"is this code ever executed?"*. Static analysis cannot
answer it (§5.1 class 3), and MobSF's dynamic analyser reports what it happened to trigger, not
whether your specific lead fired.

This script takes a list of class-and-method leads straight out of a MobSF report and tells you which
of them execute during your session. It is deliberately small; [53-Frida](../53-Frida/README.md) owns
the technique.

**The listing below is abridged.** The full version ships at
[`scripts/lead-liveness.js`](scripts/lead-liveness.js) and adds per-overload arming, an `ABSENT`
state with its own diagnosis, a caller-stack print on first hit, `rpc.exports.reset()` and
`rpc.exports.counts()`, and a loud warning when *nothing* fired — which is the case §7.3 is about.

```javascript
// abridged from scripts/lead-liveness.js
// frida -U -f com.example.target -l scripts/lead-liveness.js --no-pause
//
// Purpose: answer "did this MobSF finding's code actually run?" for a list of leads.
// What this will NOT tell you: that a lead which did not fire is dead. It tells you
// only that it did not fire IN THIS SESSION, which is a much weaker statement, and
// the script prints that sentence at the end so you cannot forget it.

'use strict';

// Paste the class/method pairs your MobSF report cited. Obfuscated names are fine -
// use whatever the DEX contains, not what the source used to be called.
const LEADS = [
    { clazz: 'org.android.cmpen.WebViewActivity',  method: 'onCreate'  },
    { clazz: 'org.android.cmpen.FlagProvider',     method: 'query'     },
    { clazz: 'org.android.cmpen.LeakyFileProvider', method: 'openFile' },
    { clazz: 'B.g',                                 method: 'a'        },
];

const fired = {};

Java.perform(function () {
    LEADS.forEach(function (lead) {
        const key = lead.clazz + '.' + lead.method;
        fired[key] = 0;
        let cls;
        try {
            cls = Java.use(lead.clazz);
        } catch (e) {
            console.log('[!] ABSENT  ' + key + '  -- class not loaded (yet). ' +
                        'A class the report cited that is not in the process is ' +
                        'itself a result: check you analysed the right artefact.');
            return;
        }
        const overloads = cls[lead.method] ? cls[lead.method].overloads : [];
        if (!overloads.length) {
            console.log('[!] ABSENT  ' + key + '  -- method not found on the class');
            return;
        }
        overloads.forEach(function (ovl) {
            ovl.implementation = function () {
                fired[key] = fired[key] + 1;
                if (fired[key] === 1) {
                    console.log('[+] FIRED   ' + key);
                    // The first hit is the interesting one. Print the caller so you
                    // learn WHO reached it, which is question 3 of 52's four.
                    console.log(Java.use('android.util.Log')
                        .getStackTraceString(Java.use('java.lang.Exception').$new())
                        .split('\n').slice(1, 6).join('\n'));
                }
                return ovl.apply(this, arguments);
            };
        });
        console.log('[ ] armed   ' + key + '  (' + overloads.length + ' overload(s))');
    });
});

// Call from the REPL when you have finished exercising the app: rpc.exports.summary()
rpc.exports = {
    summary: function () {
        const lines = ['', '=== LEAD LIVENESS ==='];
        Object.keys(fired).forEach(function (k) {
            lines.push((fired[k] ? 'EXECUTED ' : 'NOT SEEN ') +
                       String(fired[k]).padStart(5) + '  ' + k);
        });
        lines.push('');
        lines.push('"NOT SEEN" means NOT SEEN IN THIS SESSION. It is not evidence of');
        lines.push('dead code. Reflection, a feature flag, a server response or a code');
        lines.push('path you did not exercise all produce the same output.');
        return lines.join('\n');
    }
};
```

Two disciplines make it honest, and both are written into the script itself:

- **A lead that does not fire is not dead.** It did not fire *in this session*. 52's warning is
  explicit: never write "unreachable" on the strength of a static closure, and the dynamic version of
  that mistake is just as easy to make.
- **A class the report cited that is not in the process is itself a result.** Either you analysed a
  different artefact, or the class ships in a split, or the code is loaded dynamically.

### 7.6 MobSF's dynamic analyser versus driving Frida yourself

| | MobSF dynamic | Frida / Objection directly |
|---|---|---|
| Setup cost | High once, low thereafter | Low once you know it |
| Coverage | Whatever its exerciser reaches | Whatever you reach |
| Reproducibility | Good — it is scripted | Depends on your discipline |
| Answering a **specific** question | Poor | **This is the whole point** |
| Corpus work | **Good** | Poor |
| Knowing what it missed | **No** | Also no, unless you build it |

The honest split: **use MobSF's dynamic analyser for breadth on an unfamiliar app, and Frida for
every question you actually care about.** [53-Frida](../53-Frida/README.md) is the technique;
Objection (chapter 54) wraps the common cases.

### 7.7 What a dynamic run adds to the report — and what it must not be allowed to imply

The most valuable output of a dynamic run is not its findings. It is its **traffic log**, because
that is the one artefact that shows what the app really does with the network.

But there is a reporting trap. A merged report shows static and dynamic findings in one list without
shouting about which is which (§2.5). A reader will treat *"the app writes to `/sdcard/log.txt`"*
(observed) and *"the app may write to external storage"* (a pattern matched) as the same kind of
statement. They are not. Mark provenance on every line of your own report:

```
F-04  (observed)   The application wrote /sdcard/Android/data/<pkg>/logs/session.txt
                   containing the bearer token, during an ordinary login. Captured
                   at <time>, session <id>. Reproduced twice.

F-05  (static)     The application contains a call to getExternalFilesDir() in
                   <class>. We did not observe a write during dynamic testing;
                   this is reported as a lead, not a confirmed exposure.
```

That distinction takes ten seconds per line and it is the difference between a report that survives
review and one that does not.

---

## 8. Static Analysis

This section is the operational one: how to run MobSF, how to read its JSON, and how to check every
class of thing it says. It is deliberately command-heavy.

### 8.1 Running a scan, three ways

```bash
# host - 1. the web UI. Drag the APK onto http://127.0.0.1:8000 and read the page.
#            Fine for one app. Useless for twenty, and not reproducible.

# host - 2. the REST API, one file
export MOBSF_API_KEY='<key>'; export MOBSF_SERVER='http://127.0.0.1:8000'
RESP=$(curl -s -H "Authorization: $MOBSF_API_KEY" \
            -F "file=@target.apk" "$MOBSF_SERVER/api/v1/upload")
HASH=$(python3 -B -c "import sys,json;print(json.load(sys.stdin)['hash'])" <<<"$RESP")
curl -s -H "Authorization: $MOBSF_API_KEY" -X POST \
     --data "hash=$HASH&scan_type=apk&file_name=target.apk" \
     "$MOBSF_SERVER/api/v1/scan" > /dev/null
curl -s -H "Authorization: $MOBSF_API_KEY" -X POST --data "hash=$HASH" \
     "$MOBSF_SERVER/api/v1/report_json" > report.json

# host - 3. a directory of APKs, ranked. This chapter's driver.
python3 -B scripts/mobsf-triage.py --dir ./apks --server "$MOBSF_SERVER" --cache ./reports
```

**Always keep the JSON.** The HTML is a rendering; the JSON is what MobSF decided (§4.5), it is what
you can diff, and it is what both of this chapter's scripts consume. Store it next to the artefact's
SHA-256.

### 8.2 Reading the JSON directly

The habits that make a report navigable in a terminal. These use `python3` rather than `jq` so they
work everywhere:

```bash
# host - what sections does this report even have?
python3 -B -c "import json;print('\n'.join(sorted(json.load(open('report.json')))))"

# host - identity first, always
python3 -B -c "
import json; d=json.load(open('report.json'))
for k in ('package_name','version_name','version_code','sha256','min_sdk','target_sdk','size','version'):
    print('%-16s %s' % (k, d.get(k)))"

# host - the manifest finding list, severity first
python3 -B -c "
import json; d=json.load(open('report.json'))
ma=d.get('manifest_analysis'); items = ma.get('manifest_anal', ma) if isinstance(ma,dict) else ma
for it in sorted(items, key=lambda x: x.get('severity','')):
    print('%-8s %s' % (it.get('severity'), it.get('title','')[:110]))"

# host - code findings with their file citations
python3 -B -c "
import json; d=json.load(open('report.json'))
ca=d.get('code_analysis',{}); f=ca.get('findings',ca)
for title, body in f.items():
    if not isinstance(body,dict): continue
    m=body.get('metadata',body)
    print('%-8s cvss=%-4s %s' % (m.get('severity'), m.get('cvss'), title[:80]))
    for path,lines in (body.get('files') or {}).items():
        print('             %s:%s' % (path, lines))"

# host - the secrets section, which is the one you must classify before reading
python3 -B -c "
import json; print('\n'.join(str(s) for s in json.load(open('report.json')).get('secrets',[])))"

# host - every extracted URL, deduped, http first
python3 -B -c "
import json; d=json.load(open('report.json'))
u=set()
for e in d.get('urls',[]):
    u.update(e.get('urls',[]) if isinstance(e,dict) else [e])
for x in sorted(u, key=lambda s:(not s.startswith('http://'), s)): print(x)"
```

> **🔍 Pentester's Note**
> Run the URL command on any real report and the first thing you will see is
> `http://schemas.android.com/apk/res/android` and its siblings. 52 measured one of those appearing
> in **627 of 3,655 files**, and its scoring model pushes it to LOW through two independent penalties.
> XML namespace URIs are not endpoints. Filter them before you count anything.

### 8.3 Scanning a corpus, and ranking it

This is the thing MobSF does that nothing else in this repository does, and it is worth building
properly. [`scripts/mobsf-triage.py`](scripts/mobsf-triage.py) takes a directory of APKs, scans each
through the API, caches the JSON by hash, and emits a **ranking with the arithmetic printed**.

```bash
# host - online
export MOBSF_API_KEY='<key>'
python3 -B scripts/mobsf-triage.py --dir ./apks --cache ./reports --csv triage.csv

# host - offline, against reports you already have (works with the shipped fixtures)
python3 -B scripts/mobsf-triage.py --from-reports ./examples --explain
```

`MEASURED`, this chapter, across the two example reports:

```
==============================================================================
  TRIAGE RANKING - where the next four hours go
==============================================================================
  #    package                        version   triage  MobSF  cvss  top signal
------------------------------------------------------------------------------
  1    org.android.cmpen              2.0           82     38   6.6  debug_cert x1
  2    org.android.cmpen              1.0           58     34   5.0  debuggable x1
------------------------------------------------------------------------------
  'MobSF' is MobSF's own security_score. It is shown so you can see that the
  two columns do not have to agree - and when they disagree, ask which one
  knows what the application is FOR. Neither does; only one pretends to.
==============================================================================
```

**The two columns rank the two applications in opposite orders**, and §3.9 explains why: MobSF's
score counts rule matches, and this model counts things that predict where analyst time pays. The
model is small enough to argue with, and every term is printed:

```
# MEASURED - the arithmetic for the top-ranked app
  1. org.android.cmpen   [triage 82]
     ranking terms:
         +12  debug_cert x1                the debug private key ships with the SDK; anyone can sign an
         +14  unprotected_provider x1      a reachable data surface an ordinary app can call TODAY (per
         +10  permission_level_unknown x1  a component whose guard is a permission whose LEVEL nobody r
         +16  js_bridge x1                 addJavascriptInterface plus attacker-influenced URL is remot
          +9  browsable x1                 an entry point reachable from a web page, per deep-linked ac
          +6  secrets_interesting x1       secret candidates that survived classification, per value
         +10  exported_activities x5       surface, per activity. Cheap to enumerate, usually nothing
          +5  weak_crypto x1               a specific API with specific arguments; fast to confirm, oft
          +3  cleartext x1                 the FLAG alone. Permits cleartext; proves none is sent
          +3  backup x1                    config note until you name the file that leaves the device
          -6  pin_claimed                  a configured pin: budget an extra session for interception b
     secrets: 7 raw -> ciphertext=4, digest=1, pin=1, plaintext=1
              1 are noise by classification alone (pin / URL / too short)
     first three moves:
       - read the @JavascriptInterface methods, then find who controls the loaded URL (43-WebView)
       - resolve every provider's protectionLevel, then query the authority from an unprivileged app
       - adb shell am start -a android.intent.action.VIEW -d '<scheme>://...' (26-Intent)
```

Four design decisions in that output are worth copying into any tool you build:

1. **Every weight is printed with its rationale.** 52 makes the same argument about its confidence
   model: *"a scoring model you cannot audit will eventually rank a documentation URL above a
   credential and nobody will notice."*
2. **The weights are judgements, not measurements, and the script says so in a comment.** Tune them
   against your own corpus.
3. **A penalty exists.** A configured pin *reduces* expected yield, because it costs you a session
   before you see traffic. A triage that ignores cost is not a triage.
4. **Every ranked app carries three next steps.** A rank with no next step is a number.

> **⚠️ Warning**
> The counts are **capped at 8 per signal**, deliberately. An app with forty exported activities is
> not twenty times more interesting than one with two; it is a bigger app. Without a cap, component
> count dominates every ranking and you will spend your week on whichever application is largest.

### 8.4 Validating a report — the core loop

[`scripts/mobsf-validate.py`](scripts/mobsf-validate.py) is the stage MobSF does not have. It takes
a report and the artefact it describes, and for each finding gathers the evidence that would confirm
it and the evidence that would kill it.

```bash
# host
jadx -d out target.apk
python3 -B scripts/mobsf-validate.py --report report.json --apk target.apk \
        --tree ./out --csv ledger.csv
```

Its verdict vocabulary is deliberately missing one word:

| Verdict | Meaning |
|---|---|
| `CORROBORATED` | The artefact independently shows the claimed construct where it is claimed |
| `REFUTED` | A measurement contradicts the report outright |
| `UNSUPPORTED` | The cited evidence is not where the report says it is |
| `UNDER-RATED` | Real, and the report's severity is too low |
| `OVER-RATED` | Real, and the report's severity is too high |
| `RESTATES` | A scorecard entry duplicating another section — not a lead at all |
| `NEEDS-HUMAN` | No automated check applies; a next step is printed |

**There is no `FINDING`.** A finding is written by a person who can name the asset, and the script's
header says so. That is [52 §3.7](../52-StaticAnalysis/README.md#37-stage-7--validate)'s discipline
expressed as a design constraint.

`MEASURED`, this chapter, on the v1.2 report:

```
  CORROBORATED     16   (41.0%)
  UNDER-RATED       1   ( 2.6%)
  OVER-RATED        3   ( 7.7%)
  REFUTED           2   ( 5.1%)
  RESTATES         11   (28.2%)
  NEEDS-HUMAN       6   (15.4%)
------------------------------------------------------------------------------
  all items          : 17 of 39 survived first-pass corroboration (43.6%)
  excluding scorecard: 17 of 27 (63.0%)
```

The tool also prints a blind-spot block on every run, derived from the artefact rather than from the
report, so the limits section writes itself:

```
# MEASURED
  BLIND SPOTS - present in the artefact, absent from any report of this kind
  * reflective dispatch
      a reflected call creates no textual edge, so no static reachability
      answer covers it. Hook Method.invoke to enumerate.
  * server-side behaviour
      no artefact analysis observes what the backend enforces, or what a
      remote config flag turns off after you finish testing.
```

And the CSV it writes has **two deliberately blank columns**, `human_verdict` and `human_reason`.
Filling them in is the job. [`examples/findings-ledger.csv`](examples/findings-ledger.csv) is what
they look like when filled.

### 8.5 Doing MobSF's checks by hand — the ten commands

If MobSF is unavailable, unwanted, or untrusted, this is the whole static half of its report in ten
commands. It is also the right thing to run *alongside* MobSF, because a second reading is how
divergences surface.

```bash
# ------------------------------------------------------------------ identity
sha256sum target.apk | tee -a evidence/hashes.txt
apksigner verify -v --print-certs target.apk | head -20

# ------------------------------------------------------------------ container
unzip -l target.apk | grep -cE '\.dex$'
unzip -l target.apk | grep -E 'lib/[^/]+/' | awk -F/ '{print $2}' | sort -u
unzip -l target.apk | grep -E 'assets/' | sort -k1 -rn | head

# ------------------------------------------------------------------ manifest
aapt2 dump xmltree --file AndroidManifest.xml target.apk > manifest-aapt2.txt
python3 -B ../32-Manifest/scripts/manifest-audit.py manifest-aapt2.txt

# ------------------------------------------------------------------ libraries
bash ../17-Libraries/scripts/lib-inventory.sh target.apk -o inventory/

# ------------------------------------------------------------------ pinning
python3 -B ../36-CertificatePinning/scripts/pinning-surface.py --apk target.apk

# ------------------------------------------------------------------ strings + sweep
jadx -d out target.apk
python3 -B ../52-StaticAnalysis/scripts/static-sweep.py ./out --app-package <pkg> --csv leads.csv
```

**Every one of those tools is owned by another chapter, and that is the point.** This chapter's
scripts do not re-implement any of them. What MobSF gives you over that list is that it is one
command instead of ten, it produces a comparable report per app, and it has a REST API.

### 8.6 A concrete comparison, on the same artefact

`MEASURED`, this chapter. Three tools, one APK (`CMPen-Android-App-v1.2.apk`), what each produced:

| Tool | Output | The distinguishing feature |
|---|---|---|
| The example MobSF-shaped report | 39 normalised items across 6 sections, one score | **Breadth.** Six analysers, one file |
| `manifest-audit.py` ([32](../32-Manifest/README.md)) | 0 CRITICAL, 6 HIGH, 6 MEDIUM, 0 LOW, 12 INFO, **1 POSITIVE** | A `POSITIVE` band, and every row marked `UNPROVEN` with a reason |
| `pinning-surface.py` ([36](../36-CertificatePinning/README.md)) | 6 detections across 4 layers, **1 of them a pin** | Confidence *classes*, so surface and pin cannot be confused |

The second and third are narrow and deep; MobSF is wide and shallow. **The professional move is to
run MobSF for the census and the specialist tools for anything you intend to write down.**

### 8.7 CI integration — the place MobSF genuinely shines

An engineering team scanning every build is a completely different use case from a pentester scanning
one app, and MobSF is *good* at it. Three rules make it work.

**Rule 1: gate on deltas, not on absolutes.** A build that introduces a new exported component or a
new `http://` endpoint should fail. A build that has the same forty items it had yesterday should
pass. Absolute gates get suppressed within a month.

**Rule 2: gate on a hand-picked subset, never on the score.** The list that is worth failing a build
over is short, and every item on it is a *fact* rather than a judgement:

| Gate | Why it is safe to automate |
|---|---|
| `android:debuggable="true"` in a release build | Unambiguous, always wrong, one attribute |
| Signed with a debug certificate | Unambiguous |
| A new `http://` endpoint that is not a namespace URI | Cheap to check, high signal |
| `allowBackup="true"` with no rules file | Unambiguous |
| A new exported component | Delta, not absolute |
| A new dependency, or a version change | MASVS-CODE; [17](../17-Libraries/README.md) |

**Rule 3: file leads as leads.** Everything else becomes a ticket for a human to triage, not a build
failure. A pipeline that fails on `minSdk` will be disabled by the third sprint.

```bash
# host - CI shape. EXPECTED SHAPE; the gate logic is yours.
python3 -B scripts/mobsf-triage.py --dir ./build/outputs/apk/release \
        --server "$MOBSF_SERVER" --cache ./ci-reports --csv triage.csv
python3 -B scripts/mobsf-validate.py --report ./ci-reports/$SHA.json \
        --apk ./build/outputs/apk/release/app-release.apk --csv ledger.csv --quiet
# then diff ledger.csv against the previous build's, and fail only on the gate list
```

> **🔍 Pentester's Note**
> When a client tells you "we run MobSF in CI", the useful follow-up is not "what does it find" but
> **"what does it fail the build on, and how many suppressions do you have?"** The suppression list
> is a map of everything the team has decided not to look at, and it is frequently the most
> interesting document in the engagement.

### 8.8 What to do when the report is nearly empty

An empty result is a result, and it has five explanations in descending order of likelihood:

1. **You scanned the wrong artefact** — `base.apk` of a split app (§3.13), or a stub APK like the
   334 KB `base.apk` 36 measured for a major social application.
2. **The app is packed or cross-platform** (§6.5). Check `assets/` size against DEX size.
3. **Obfuscation defeated the name-based rules** (§5.3). The value-based sections — URLs, secrets,
   manifest — will still be populated, so a report with a full URL list and an empty code-analysis
   section is a *signature* of this case.
4. **Strings are encrypted.** An app with no URLs at all is building them.
5. **The app is small and genuinely clean.** More common than cynics expect.

**Report it as "the scan produced no findings above threshold", never as "no issues found"**, and put
the blind-spot section immediately underneath.

### 8.9 The one-page runbook

```bash
# ---------------------------------------------------------------- 0. identity
PKG=com.example.target
adb shell pm path "$PKG"                        # EVERY path. Splits.
adb pull <each path> .
sha256sum *.apk | tee evidence/hashes.txt

# ---------------------------------------------------------------- 1. scan
python3 -B scripts/mobsf-triage.py --dir . --cache ./reports --csv triage.csv
#   -> read the ranking and the "first three moves" per app. Do not read the score.

# ---------------------------------------------------------------- 2. orient
python3 -B -c "import json;d=json.load(open('reports/$SHA.json'));print(d['app_type'],d['size'])"
unzip -l base.apk | grep -cE '\.dex$'           # is the code even here?
apkid base.apk                                  # packer? obfuscator?

# ---------------------------------------------------------------- 3. validate
jadx -d out base.apk
python3 -B scripts/mobsf-validate.py --report reports/$SHA.json --apk base.apk \
        --tree ./out --csv ledger.csv

# ---------------------------------------------------------------- 4. specialists
python3 -B ../32-Manifest/scripts/manifest-audit.py manifest-aapt2.txt
python3 -B ../36-CertificatePinning/scripts/pinning-surface.py --apk base.apk
bash     ../17-Libraries/scripts/lib-inventory.sh base.apk -o inventory/

# ---------------------------------------------------------------- 5. the loop
#   For each row of ledger.csv: open the code, answer 52's four questions,
#   write human_verdict and human_reason. THIS is the engagement.

# ---------------------------------------------------------------- 6. write
#   findings + the ledger (Appendix B) + the limits section.
#   Template: ../80-Appendix/
```

Note the one step with no command next to it. Step 5 is a loop you run by hand, once per item, and it
is the only step that produces a finding.

---

## 9. Examples

Five worked examples, simple to enterprise. Three are real runs on this machine with the numbers
those runs produced.

> **A note on naming.** This repository may be published. The applications named below are
> **public, deliberately-vulnerable training targets** and naming them is fine — the same precedent
> [52 §9](../52-StaticAnalysis/README.md#9-examples) sets. Any commercial application discussed
> anywhere in this repository is anonymised.
>
> **And a note on provenance.** The MobSF reports quoted are the shipped **fixtures** (§1.6):
> real values, reconstructed structure. Every command shown as `MEASURED` really ran.

### 9.1 Simple — one report line, from JSON to closed

The smallest complete instance of the whole method.

**The line, in the report:**

```json
{ "rule": "app_allowbackup",
  "title": "Application Data can be Backed up [android:allowBackup=true]",
  "severity": "warning",
  "component": ["allowBackup"] }
```

**Step 1 — corroborate it against the artefact.** Never quote a report you have not checked:

```bash
# host - MEASURED
aapt2 dump xmltree --file AndroidManifest.xml CMPen-Android-App-v1.2.apk | grep -i backup
#     A: http://schemas.android.com/apk/res/android:allowBackup(0x01010280)=true
```

Confirmed. And the second half, which the report does not check:

```bash
# host - MEASURED. No rules file means EVERYTHING is in scope.
aapt2 dump xmltree --file AndroidManifest.xml CMPen-Android-App-v1.2.apk \
    | grep -cE 'dataExtractionRules|fullBackupContent'
# 0
```

The validator does both in one step:

```
# MEASURED
V001  [WARNING]  manifest
  claim     Application Data can be Backed up [android:allowBackup=true]
    FOR     aapt2: android:allowBackup=true
    FOR     no dataExtractionRules and no fullBackupContent: EVERYTHING is in scope
  VERDICT   CORROBORATED
  NEXT STEP Name the file that leaves the device. 33-Storage tells you where the
            credential store is; without that sentence this is a config note,
            not a finding.
```

**Step 2 — 52's four questions.**

| Question | Answer | How |
|---|---|---|
| Is the construct really there? | Yes | The attribute, from the platform's own parser |
| Is it reachable? | Not code — it is a process attribute | — |
| Who can reach it? | Anyone with ADB access to an unlocked device | `adb backup`, where the platform still supports it |
| **What does it get them?** | **This is the whole question.** Whatever is in the private directory | Name the file |

**Step 3 — name the file.** `MEASURED`, by reading the Application class:

```java
// out/sources/org/android/cmpen/CmpenApp.java:17
m.s(new File(file, "secrets.db"), "secret_flag=" + g.b("PDY7PSFpaTsO…KCc=") + "\n");
```

The app writes `databases/secrets.db` on every start, containing a value it obfuscates with base64
and XOR. That file is inside the backup scope.

**Step 4 — the finding, as it ships:**

> **F-05 — Application data is backed up with no exclusions (Low)**
> The shipped manifest declares `android:allowBackup="true"` and provides neither
> `android:dataExtractionRules` nor `android:fullBackupContent`, so the entire private data
> directory is in scope for backup and device-transfer, except `no_backup/` and `cache/`. The
> application writes `databases/secrets.db` at every start (`CmpenApp.java:17`) containing an
> obfuscated token, and that file is included.
> **Precondition:** ADB access to an unlocked device, on a platform where `adb backup` still
> functions. Stating the precondition is what makes this Low rather than Medium — and what makes it
> hard to argue with.
> **Fix:** `android:allowBackup="false"`, or a `dataExtractionRules` XML that excludes every
> credential store from **both** `<cloud-backup>` and `<device-transfer>`.

Note what turned a scanner line into a finding: **one sentence naming the file**, and one naming the
precondition. Neither is in the report.

### 9.2 Intermediate — the secrets section, classified

The report's `secrets` array has seven entries. A report that lists seven "hardcoded secrets" is
wrong six times.

```bash
# host - MEASURED, the shipped classifier, run over the report's own secrets section
python3 -B scripts/mobsf-validate.py --report examples/synthetic-mobsf-report.json \
        --apk cmpen.apk --tree ./out --only warning | grep -A4 '  secrets'
```

The four that matter, with the reasoning the tool prints:

```
# MEASURED
V021  "sha256/+xpjwBQ7+BLhq1r+/AU3qLNIaXPt+JgXAJ9yIQaHNkQ="
    FOR     classified as: SPKI pin
    note    a base64 SHA-256 of a public key. Public by construction: it is
            published in every TLS handshake. Not a secret.
  VERDICT   REFUTED

V022  "abdd1bd1e110321baca9bff06c9199402c4a5238ca0d64c7b0b59e8a64a75adb"
    FOR     classified as: 256-bit hex
    note    hex of that length is usually a DIGEST, not a key. If it is a
            password hash, the finding is the algorithm and the absence of a
            salt, not the value.
  VERDICT   OVER-RATED

V023  "ZmxhZ3tLSkJKSGRTT0ZRQ1hMTWRHNEQ0OWpiODREYUFIcHBtT30="
    FOR     classified as: base64 of TEXT
    note    decodes to: 'flag{KJBJHdSOFQCXLMdG4D49jb84DaAHppmO}' - read it
            before you name it.
  VERDICT   CORROBORATED

V024  "n8qhwbn+IyvfEIwOQgznb1lXWTWUuUsnxI57Lp1CEUPMb9ntxAimu/SB8O3UnLKK"
    FOR     classified as: base64 of BINARY
    note    decodes to 48 high-entropy bytes; probably ciphertext or a key
            blob. Ciphertext in the artefact is only a finding if the key is too.
  VERDICT   NEEDS-HUMAN
```

**Four values, four different correct responses.** Now the human pass on each:

| Value | What it is | Report entry |
|---|---|---|
| The `sha256/` pin | A **public** key hash | **Rejected.** Move to the TLS section as evidence the app pins |
| The 64-hex digest | An unsalted single-round SHA-256 password verifier, evaluated **on the client** | **Medium.** The finding is the design, not the literal: it is brute-forceable offline and bypassable by patching the comparison |
| The base64 that decodes to text | Obfuscation, defeated in one command — and it is returned by an **exported** provider | **Medium**, and the severity comes from the provider (§5.4's join), not from the encoding |
| The ciphertext | A ciphertext whose key derivation is in the same APK | **Merged** into the crypto finding |

> **🔍 Pentester's Note**
> This is the most common inflation in mobile reporting. A base64 blob in a DEX gets written up as a
> "hardcoded credential" hundreds of times a year. **Decode it before you name it, and then ask what
> it protects.** 52 makes the same point about the same class of value, and its example decoded to a
> string the app displays on screen anyway — real, confirmed, and Informational.

### 9.3 Advanced — the complete validation run, measured

**Target:** `CMPen-Android-App-v1.2.apk`, SHA-256 `137186672dd93517bd6c85637c04c7f7cf912458e3ea9c887072dbbf00c39638`,
287,060 bytes, `org.android.cmpen`, `minSdk` 24 / `targetSdk` 35, one DEX, no native libraries, no
assets.

**Stage 0 — orient.** One DEX, 287 KB, no `lib/`, no `assets/`. Nothing hidden; the code analysis
will describe the whole application. That sentence is worth writing down, because on most real apps
you cannot write it.

**Stage 1 — decompile.** `MEASURED`, jadx 1.5.3 CLI: 171 classes, **234 `.java` files**, no errors.
The application's own package `org/android/cmpen/` holds **13 files**; the rest is Kotlin stdlib,
OkHttp and Retrofit, R8-renamed into single-letter packages.

**Stage 2 — normalise the report.** `MEASURED`:

```
  manifest via: aapt2
  schema seen : manifest_analysis: dict; certificate_analysis: dict; code_analysis: dict;
                network_security: dict; appsec: dict
  findings    : 39
```

**Stage 3 — gather evidence.** `MEASURED`, the full summary:

```
  CORROBORATED     16   (41.0%)
  UNDER-RATED       1   ( 2.6%)
  OVER-RATED        3   ( 7.7%)
  REFUTED           2   ( 5.1%)
  RESTATES         11   (28.2%)
  NEEDS-HUMAN       6   (15.4%)
------------------------------------------------------------------------------
  all items          : 17 of 39 survived first-pass corroboration (43.6%)
  excluding scorecard: 17 of 27 (63.0%)
```

**Stage 4 — the human pass.** Every one of the 39 was worked by hand and written into
[`examples/findings-ledger.csv`](examples/findings-ledger.csv). The outcome:

| Outcome | Count | Examples |
|---|---|---|
| **FINDING** | **8** | The WebView bridge; the unprotected provider; the `normal`-permission provider; the debug certificate; the deep link; the password-verifier design; the encoded flag; backup with no exclusions |
| MERGED into another finding | 6 | `setJavaScriptEnabled` into the bridge; `WebViewActivity` export into the bridge; the duplicate `DeepLinkActivity` row; two secrets already reported as code findings |
| LEAD (real, not yet a finding) | 2 | `InsecureActivity` and `HiddenFlagActivity` — exported, and what a caller gains is not yet demonstrated |
| **REJECTED, with a written reason** | **15** | The launcher activity; `minSdk`; the missing-v1 direction error; the SPKI pin as a "secret"; base64-is-used; the mis-categorised "temporary file"; the 11 scorecard restatements |
| Recorded as a **limit** | 1 | The runtime broadcast surface |

**Stage 5 — the two findings the scan never made.** These came out of reading the files the scanner
pointed at, and they are the most valuable output of the whole exercise.

**(a) A hash used directly as a key derivation function.** The report's ECB rule cited `B/g.java:28`.
Opening the file shows the ECB is the *second*-worst thing in it:

```java
// out/sources/B/g.java:20-28  (MEASURED, jadx 1.5.3)
MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
byte[] bArrDigest = messageDigest.digest(str2.getBytes(charset));   // str2 = caller-supplied
byte[] bArrCopyOf = Arrays.copyOf(bArrDigest, 16);                  // truncate to 128 bits
Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
cipher.init(2, new SecretKeySpec(bArrCopyOf, "AES"));
```

One unsalted SHA-256 round over a caller-supplied string, truncated to 16 bytes, used directly as an
AES key, with no IV because the mode is ECB. **No MobSF rule exists for "hash used as a KDF"**, so
the defect with the widest blast radius in the application appears nowhere in the report.
[34-Cryptography](../34-Cryptography/README.md) rates it.

**(b) The provider's file handling.** `LeakyFileProvider.openFile` opens
`new File(context.getFilesDir(), uri.getLastPathSegment())`. `getLastPathSegment()` limits classic
`../` traversal, because a path segment cannot contain an unencoded slash — but the provider still
opens **any file directly under `files/`** for **any caller**, and percent-encoded separator handling
must be tested on a device before either sentence is written. That is a **lead**, recorded as such,
not a finding. Recording it as a lead rather than inflating it is the same discipline as rejecting
the fifteen.

**The arithmetic, stated once:**

> **39 report items → 17 corroborated → 8 findings, 2 of which the scan never mentioned.**

### 9.4 Real application — the R8 comparison

The controlled experiment from §5.3, presented as an engagement would present it.

**The setup.** Two builds of the same application, one before and one after enabling R8. This is the
exact situation of a re-test after a client "adds obfuscation" as a remediation.

| | v1.0 | v1.2 |
|---|---|---|
| SHA-256 | `f7daada6…f501ff` | `13718667…c39638` |
| Report items normalised | **29** | **39** |
| `CORROBORATED` | 10 | 16 |
| `REFUTED` | 3 | 2 |
| Survival, excluding the scorecard | 9/19 = **47.4%** | 17/27 = **63.0%** |
| MobSF-style security score | 34 | 38 |
| This chapter's triage rank | 58 | **82** |
| Pinning verdict from a name-based rule | "implements pinning" (**correct**) | "does not implement pinning" (**wrong**) |
| Configured pin values actually present | **3** | **1** |

**Three readings of that table, in increasing order of usefulness.**

**Reading 1, naive:** the score went from 34 to 38, so the app got better. This is wrong and it is
what a score-driven process concludes.

**Reading 2, better:** v1.2 has *more* report items, so it got worse. Also wrong — v1.2 is a
different application with more features, and item count is not a security metric in either
direction.

**Reading 3, correct:** the two reports are **not comparable at the item level at all**, because
obfuscation changed what the tool can see (§6.3). What *is* comparable is the value-derived half:
manifest attributes, string literals, resource contents, ZIP structure. Compare those, say so
explicitly, and note in the report that the name-derived half of the newer scan is **less reliable,
not more reassuring**.

**And the specific correction that must appear:**

> The automated scan reports that v1.2 does not implement certificate pinning. **That is incorrect.**
> The application configures one SPKI pin for `ninja.secops.group` on a process-wide `OkHttpClient`
> (`b/h.java`, static initialiser). The scanner's rule matches the type name
> `okhttp3.CertificatePinner`; R8 renamed that type to `m.e`, so the rule found nothing. Version 1.0
> of the same application, which ships unobfuscated, is detected correctly by the identical rule.

`MEASURED`, the command that settles it in three seconds:

```bash
# host
grep -a -o -h -E 'sha256/[A-Za-z0-9+/]{43}=' /tmp/dexes/*.dex | sort -u
# sha256/+xpjwBQ7+BLhq1r+/AU3qLNIaXPt+JgXAJ9yIQaHNkQ=
```

> **🧠 Mental Model**
> When a client enables obfuscation between two tests, **expect the scanner's report to shrink and do
> not read the shrinkage as improvement.** Re-baseline on the value-derived sections, and re-check
> every *negative* claim by hand. The negatives are where obfuscation does its damage, because
> nobody audits a reassurance.

### 9.5 Enterprise — a corpus, ranked, with a CI gate

The scenario: forty applications from one organisation, a two-week engagement, and a question from
the client's security lead that is really a resourcing question — *"which of these should we fix
first?"*

**Step 1 — scan everything, once, overnight.**

```bash
# host
export MOBSF_API_KEY='<key>'
python3 -B scripts/mobsf-triage.py --dir ./corpus --cache ./reports --csv triage.csv
```

**Step 2 — read the ranking, not the scores.** `MEASURED` on the two-app corpus this chapter has:

```
  #    package                        version   triage  MobSF  cvss  top signal
  1    org.android.cmpen              2.0           82     38   6.6  debug_cert x1
  2    org.android.cmpen              1.0           58     34   5.0  debuggable x1
```

**Step 3 — validate the top of the queue, deeply, and the tail shallowly.** With forty apps and two
weeks you cannot validate forty reports. What you *can* do, honestly, is:

- Validate the top five completely — every item, ledger and all.
- Run `mobsf-validate.py --quiet` over the remaining thirty-five and report only the verdicts a
  measurement settled outright: `REFUTED`, `UNDER-RATED`, and the debug-certificate corroborations.
- **Say exactly that in the report.** A methodology section that reads *"five applications received
  full manual validation; thirty-five received automated corroboration only, and their leads are
  listed as leads"* is defensible. Presenting forty as equal is not.

**Step 4 — the deliverable the client actually needs.** Not forty reports. Three artefacts:

| Artefact | Content |
|---|---|
| **The ranked queue** | With the reasoning printed, so their team can re-run it next quarter |
| **The findings** | From the five deep validations, with evidence and honest severity |
| **The systemic list** | The things that recur across the corpus |

That third one is where corpus work pays and single-app work cannot. Patterns like *"eleven of forty
ship with `allowBackup="true"` and no rules file"*, *"six are signed with a debug certificate"*,
*"the internal networking SDK sets `usesCleartextTraffic` in its own manifest and the merger
propagates it into every consumer"* are **one fix each, across the estate**, and they are invisible
from a single app.

**Step 5 — the CI gate.** §8.7's rules, made concrete for this client:

```
FAIL the build on:   debuggable=true | debug certificate | allowBackup with no rules file
                     | a NEW exported component | a NEW http:// endpoint
FILE a ticket on:    everything else
NEVER gate on:       the security score, the item count, minSdk
```

> **🔍 Pentester's Note**
> The systemic finding is also the one with the best economics for the client, and saying so is how
> a report becomes an engagement rather than a document. "Fix the manifest in your shared networking
> SDK and eleven applications stop permitting cleartext" is a sentence that gets budget. "App 27 has
> `usesCleartextTraffic=true`" is a sentence that gets a Jira ticket that closes as Won't Fix.

---

## 10. Common Interview Questions

### Beginner

**Q. What is MobSF, in one sentence?**
An open-source framework that performs automated static analysis of mobile application artefacts —
and optional dynamic analysis on an instrumented device — exposing the results through a web UI and
a REST API. It produces an inventory and a rules-based finding list, not an assessment.

**Q. Do you need root to use MobSF?**
For **static** analysis, no — you need only the file. For **dynamic** analysis, effectively yes: it
needs to install a CA into the system trust store, run `frida-server` as root, and read the app's
private directories. Its own prepared AVD, Genymotion, or a rooted device.

**Q. What is the security score and should I put it in a report?**
It is a number computed from counts of rule matches weighted by rule metadata. It contains no
information about your application's assets, users or threat model. **No** — see §3.9, where two
builds of the same app score 34 and 38 in the inverse order of their actual attacker value.

**Q. MobSF says the app has fourteen exported activities. Is that fourteen findings?**
No. It is fourteen *doors*. MobSF has not tried any of the handles and does not know what is behind
them — and one of them is the launcher activity, which is exported because it must be.

**Q. Where does MobSF store what I upload?**
On the server, indefinitely, along with the decompiled source, keyed by file hash and guarded by one
static API key with no scopes. That is why you never upload a client's artefact to an instance you
do not control.

### Intermediate

**Q. Explain the difference between MobSF's severity and the severity you would put in a report.**
MobSF's severity is a constant written into the rule by its author; it is identical for every
application that ever matched. Report severity comes from what an attacker gains by reaching the
construct, which requires knowing the asset. The clearest demonstration is a CVSS field in a code
finding: 8.8 for `addJavascriptInterface` whether the WebView loads an attacker-controlled URL or a
bundled help page.

**Q. Why does MobSF report every exported component at roughly one severity?**
Because it is reading the manifest, and the manifest says a component is exported without saying
what the component does. Severity requires knowing what an unprivileged caller achieves, and that is
not in the artefact.

**Q. You scan the same APK twice and get identical reports even though you upgraded MobSF. Why?**
MobSF caches by file hash. The second "scan" is a database read of the first result, produced under
the old rule set. `POST /api/v1/delete_scan` with the hash, then re-upload.

**Q. A MobSF report says "the app does not implement certificate pinning". How much do you trust it?**
Not much, and specifically because it is a *negative* claim in a reassuring band, which nobody
audits. It may be true; it may be R8 renaming the pinner's type; it may be a build flag that folded
the branch away; it may be native; it may be a `<pin-set>` in the network security config. Check all
four layers, and start with the 43-character grep for a configured pin value, which survives
obfuscation because R8 does not rename string literals.

**Q. What is the first thing you read in a MobSF report?**
The file list and the app type, at the bottom. One small DEX beside a large asset, or a
`libflutter.so`, means every finding above it describes a stub or the wrong language.

**Q. Distinguish MobSF's `manifest_analysis` from its component inventory.**
The inventory is a factual census you can use directly. The analysis is a rule list, and every entry
in it is a hypothesis. Confusing the two is how people end up trusting opinions and ignoring facts.

### Senior

**Q. MobSF flags `addJavascriptInterface` at CVSS 8.8. Walk me through turning that into a finding.**
Open the cited line. Then answer three questions the report cannot: what does the exposed object's
`@JavascriptInterface` method return; can an attacker influence the URL loaded into that WebView; and
who can trigger the load. The third answer lives in a **different section of the same report** — the
manifest's `exported` attribute. Join them and you have either a High (exported, attacker-controlled
URL, credential behind the bridge) or nothing much (internal, fixed asset URL). MobSF's pipeline is
one-pass and cannot make that join; §5.4 is the architectural reason.

**Q. A client's CI fails builds below a MobSF score of 60. What do you tell them?**
That they have specified passing a rule set, not being secure, and that the specification is
trivially gamed — suppress rules, remove a `<meta-data>`, ship the `secure`-band items. Then offer
the replacement: gate on a short list of unambiguous facts (`debuggable`, debug certificate,
`allowBackup` without rules, a *new* exported component, a *new* cleartext endpoint), gate on deltas
rather than absolutes, and file everything else as a lead.

**Q. How do you report the things MobSF could not see?**
In a named limits section, with numbers, not a footnote. Runtime-registered receivers — 29 measured
**299 of 431 distinct actions (69%)** with no manifest-declared receiver anywhere on the device, and
67% independently on a different device at API 33. `RegisterNatives` bindings. Reflection.
Dynamically loaded DEX. Server-side enforcement. Splits you were not given — 38 measured one app in
eighteen with **zero controls in `base.apk`** because its code shipped in splits.

**Q. Two MobSF reports for the same package disagree. Diagnose it.**
Four causes, in this order: the SHA-256 differs, so it is a different artefact; the cache returned a
stale result; the MobSF versions differ, so the rule sets differ; the schema changed and one parser
silently read zero findings. Check the hash first, always.

**Q. What does obfuscation do to a MobSF report, precisely?**
It removes the name-derived half and leaves the value-derived half intact. Manifest analysis,
component inventory, certificate analysis, URLs, secrets and framework-API rules are unaffected,
because R8 cannot rename manifest strings, string literals, resource values or `javax.crypto`.
Type-name rules — pinning, trackers, library identification, root-detection libraries — degrade to
false negatives with no signal in the report. The measured consequence is §5.3's controlled pair.

### Staff Engineer

**Q. Design a scanner-consumption process for an organisation with forty apps and three security
engineers.**
Three components. **(1) Ingestion**: scan every release build through the API, cache the JSON by
hash, never gate on the score. **(2) Ranking**: a model that scores by things predicting analyst
value — reachable data surfaces, bridges with attacker-controlled input, new cleartext endpoints,
non-production hostnames — with **every term printed** so engineers can argue with it rather than
obey it, and capped per signal so component count does not dominate. **(3) Adjudication**: a ledger
per app with a written reason against every rejection, so the next scan starts from decisions rather
than from zero. The systemic findings — one manifest in a shared SDK propagating into eleven apps —
are where three engineers beat forty individual reviews.

**Q. Where would you extend MobSF's rules, and how do you keep the extension from making things
worse?**
Extend it where your engagements repeat: an in-house crypto helper, a company credential format, a
specific SDK. Two disciplines. Write the rule with `regex_and` so it needs two independent signals —
a single-pattern rule over a decompiled tree yields a hundred hits in `androidx/`. And set
`severity: info` whatever you think it is worth, because severity belongs to stage 7. The same
argument applies to `semgrep`'s severity field, and 52 makes it there.

**Q. Justify running MobSF at all, given everything this chapter says about it.**
Because breadth is a real property with real value, and nothing else in the toolchain provides it.
Seven hours of mechanical work per unfamiliar app, done consistently, in ninety seconds, with a REST
API. The failure mode is not the tool; it is stopping where the tool stops. Refusing to run it is
also a failure mode — it means you cannot explain the client's own scan to them, which is the
definition of senior this repository uses.

**Q. Your junior hands you a report that is MobSF's output with a cover page. What are the six things
you look for?**
Finding count equal to item count. Every exported component as a separate finding at one severity.
MobSF's severities and CVSS constants preserved verbatim. The security score in the executive
summary. No limits section. No ledger of rejections. Each of those is diagnosable in thirty seconds
and together they establish that no validation happened.

### Principal Engineer

**Q. Argue the case that automated mobile scanning has a structural ceiling, and say where it is.**
The ceiling is **reachability plus asset**. Everything below it — inventory, pattern matching,
configuration checks, structural facts — is mechanisable and MobSF mechanises it well. Everything
above it requires two pieces of information that are not in the artefact: what the application is
*for*, which lives in the client's head, and what actually executes, which lives in a running
process. No amount of rule sophistication crosses that line, because it is an information boundary
rather than an engineering one. The practical consequence is that investment in scanners should go
into *breadth, speed and machine-readability* — the things below the ceiling — and investment in
crossing it should go into instrumentation and into structured ways of capturing the client's own
knowledge, not into more rules.

**Q. How would you measure whether your team's use of a scanner is working?**
Publish the survival rate per engagement — report items in, findings out, with reasons for every
rejection — and watch it over time. If it is near 100% you are transcribing; if it is near 0% you are
scanning the wrong things or the wrong artefacts. Track separately how many findings *originated*
outside the scanner: on this chapter's worked example that was **2 of 8**, and it is the number that
distinguishes an analyst from an operator. Also track how often a *negative* scanner claim was
overturned, because that is the metric nobody collects and it is where the damage is.

**Q. A regulator asks whether a scanner report constitutes evidence of a security assessment.**
No, and the reason is precise rather than rhetorical: a scanner report is evidence that a rule set
was executed against an artefact. It establishes neither coverage nor severity. Coverage is
unestablished because the artefact excludes the runtime surface — 69% of the broadcast surface in one
measurement — and may exclude the code entirely under packing or splits. Severity is unestablished
because it is per-rule metadata. What *does* constitute evidence is the pairing of a scan with a
documented validation pass: the artefact hash, the tool version, the items generated, the items
validated, the reasons for each rejection, and an explicit statement of what could not be examined.

**Q. Where does this repository's position on MobSF come from, and what would change it?**
From four independent measurements that all point the same way: 132 high-confidence hits with 132
false positives; 15 of 17 high-band leads rejected on inspection; 12 of 14 apps with a pinning
surface and 4 that pin; and a detector that agreed with its author on 18 of 18 samples until it was
split into strong and weak patterns and became a defensible 13 of 18. The generalisation is that
**confidence ranking is not severity ranking**. What would change the position is a tool that
consumes the asset inventory and the threat model as *inputs* and reasons about reachability with
runtime evidence — and at that point it would no longer be a scanner.

---

## 11. Common Mistakes

### 11.1 Developer mistakes

| Mistake | What it produces | Fix |
|---|---|---|
| **Treating the score as the goal** | Rules suppressed, `<meta-data>` removed, real defects untouched | Gate on a short list of facts; never on the score |
| **"We ran MobSF, we're fine"** | A false baseline nobody revisits | The scan is stage 5. Ask what happened at stage 7 |
| **Fixing the noisy items first** | `minSdk` raised, launcher activity `exported="false"` (which breaks the app) | Fix what an attacker can reach. Ask the tester which items they validated |
| **Adding obfuscation as a remediation for a shipped secret** | The secret is still there. R8 renames symbols, not string literals or resource values | Remove the secret. §4.7 |
| **Reading a shrinking report as improvement** | Obfuscation removed the name-based half of the scan | §6.3 |
| **`android:debuggable` set to debug a release build** | The single most impactful manifest finding there is | `debug { isDebuggable = true }` only, plus a release-blocking lint rule |
| **Shipping a build signed with the debug key** | Anyone can sign an update-compatible package | Check the DN in CI |
| **A custom permission at `protectionLevel="normal"`** | A guard any app can hold, which scanners rate as *protected* | `signature`, or `exported="false"` |
| **Suppressing rules without recording why** | The suppression list becomes a map of what nobody looks at | Every suppression gets a dated reason |

The debuggable fix, as code:

```kotlin
// build.gradle.kts - let the build type own it, and never write it in the manifest
android {
    buildTypes {
        debug   { isDebuggable = true }
        release { isDebuggable = false }
    }
    lint {
        // fail the build rather than warn: this is exactly the mistake a warning
        // does not prevent
        error += setOf("HardcodedDebugMode")
        abortOnError = true
    }
}
```

### 11.2 Pentester mistakes

| Mistake | Why it is wrong | What to do |
|---|---|---|
| **Pasting the output into the report** | Every failure in §5.9 at once | Validate, merge, reject, and publish the ledger |
| **Keeping MobSF's severities and CVSS** | They are rule constants (§3.6) | Re-derive from the asset |
| **Counting scorecard entries as findings** | 28% of items in this chapter's run were restatements | Validate the underlying section |
| **Reporting every exported component** | Fourteen findings, one of which is the launcher | Reachability is the finding, not export |
| **Trusting a negative claim** | §5.3's false negative, in the reassuring band | Check every negative by hand, especially pinning |
| **Scanning `base.apk` of a split app** | A complete, plausible report of a fraction of the app | `adb shell pm path`, scan every path, say how many |
| **Not checking whether the app is packed** | The report describes the stub | The four-signal check in §6.5 |
| **`am start` from `adb shell` as proof of reachability** | 60 measured that `com.android.shell` holds **200 permissions**, 16 pre-granted `SYSTEM_FIXED` | Prove it from an app |
| **Calling an SPKI pin a hardcoded secret** | It is a *public* key hash | Classify every value before naming it |
| **"Encryption found" for a base64 blob** | Encoding is not encryption | Decode it, then ask what it protects |
| **Reporting native hardening flags as vulnerabilities** | They are build configuration | A hardening table |
| **No limits section** | The reader cannot tell what was not examined | §3.14, in the report, with numbers |
| **Uploading a client artefact to a shared instance** | A disclosure, possibly a contract breach | §5.11 |
| **Comparing two reports from different MobSF versions** | Rule-set differences look like app changes | Record the tool version with the hash |

### 11.3 Reverse engineer mistakes

| Mistake | Why it is wrong | What to do |
|---|---|---|
| **Trusting decompiled Java for semantics** | 56 built a case decompiling to a clean method returning **100** where the bytecode returns **105** | Read the Smali when the finding depends on the semantics |
| **Assuming the decompiler read everything** | 56 measured jadx under-reporting its own failures by **30×**: console `count: 61`, tree **2,104 refused methods** | Count the tree, not the summary |
| **Concluding "no native code" from an empty binary section** | The libraries may ship in an ABI split | `pm path`, and check the `lib/` entries |
| **Concluding "no JNI" from no `Java_` exports** | `RegisterNatives` binds at runtime; `JNI_OnLoad` present with zero `Java_` symbols is the signature | [16-JNI](../16-JNI/README.md) |
| **Reading "no findings" as "clean"** | Packing, splits, obfuscation and cross-platform runtimes all produce quiet reports | §8.8's five explanations |
| **Believing an entropy heuristic alone** | Compressed data, PNGs, ZIPs and model weights are all high entropy | Entropy **plus** context: small DEX, unfamiliar `Application` class, `System.loadLibrary` |
| **Believing a "patched the check" result** | 18-ARM patched `lc_verify_signature` to `return 1`, **verified it returning 1**, and the caller still refused — clang had inlined the check and the patched copy was dead | Verify the *effect*, not the patch |
| **Assuming `kotlin.Metadata` deobfuscates the app** | 42 scanned **19 APKs, 316,000+ classes**: zero wholesale recovery, and one APK held **1,393 empty shells** that a grep counts as hits | Property names survive; class names do not |
| **Comparing APK sizes to judge shrinking** | 42 measured three APKs **byte-identical at 12,757 B** with DEX sizes 7,384 / 2,920 / 7,180 — `apksigner` pads the signing block | Compare the DEX |

---

## 12. Hands-on Labs

Four labs, increasing in difficulty, the last a CTF. Full instructions live in
[`labs/`](labs/); the summaries below say what each is for and why it exists.

| Lab | Level | Time | What you produce |
|---|---|---|---|
| [01 — The first scan, and reading it bottom-up](labs/lab-01-first-scan-and-inventory.md) | Beginner | 60–90 min | An inventory you trust, a list of report claims you do not, and a written statement of what the scan could not see |
| [02 — The survival rate](labs/lab-02-survival-rate.md) | **Core** | 3–4 hours | **A number**: how many of the report's items survived hand validation, with a written reason against every rejection |
| [03 — Obfuscation blindness](labs/lab-03-obfuscation-blindness.md) | Advanced | 2–3 hours | A measured demonstration that a scanner's negative claims are unreliable, using two builds of one app |
| [04 — CTF: the report that lies](labs/lab-04-ctf-the-report-that-lies.md) | CTF | 3–5 hours | Four flags, each recovered by disbelieving a different line of a scanner report |

**Every lab runs without MobSF.** Each ships or points at a saved JSON report, because §1.6. If you
*do* have MobSF, each lab says which step to replace with a real scan.

### 12.1 Lab 01 — the first scan, and reading it bottom-up

**Objective.** Take an application you have never seen, produce an inventory you would be willing to
put your name on, and produce a *separate* list of the report's claims that you would not.

**Why it exists.** Beginners read a scanner report top-down: score, then high-severity findings, then
nothing. Every one of those is the least reliable part. This lab enforces the opposite order — file
list, app type, libraries, component inventory, and only then the findings — and by the end you will
never read one the other way again.

**Success criteria.** You can state, in writing: what kind of application it is, how much of it the
scan actually read, which report sections are facts and which are opinions, and at least four things
the scan structurally could not see.

### 12.2 Lab 02 — the survival rate (the one that matters)

**Objective.** Run a scan, validate **every** finding by hand, and report the survival rate as a
number.

**This lab is the point of the chapter.** The number is the deliverable — not the findings, the
*ratio*, plus a written reason against every rejection. It is the single most useful thing you can
produce about a scanner, it takes an afternoon, and almost nobody has ever done it.

The method, in outline:

```bash
# host
python3 -B ../scripts/mobsf-validate.py --report report.json --apk target.apk \
        --tree ./out --csv ledger.csv
# then: fill in human_verdict and human_reason for EVERY row. All of them.
```

**Success criteria.** A completed ledger where every row has a verdict and a reason, and a summary
paragraph of the form:

> *N* report items were generated. *A* were corroborated against the artefact; *B* were refuted or
> found to be over-rated; *C* were scorecard restatements of other sections. After manual
> adjudication, *M* findings were reported and *R* items were rejected with reasons (Appendix B).
> *K* findings did not originate from the scan at all.

`MEASURED` reference values from this chapter's own run, so you have something to compare against:
**N=39, A=17, B=5, C=11, M=8, R=15, K=2.**

**The trap the lab is built to catch.** Most people validate the items they already believe and skip
the rest. Working the queue **top-down including the ones you expect to reject** is what produces the
rejection reasons that make a report credible — and, on this chapter's run, it is what surfaced the
`UNDER-RATED` provider that a skim would have left at `info`.

### 12.3 Lab 03 — obfuscation blindness

**Objective.** Demonstrate, with two builds of one application, that a scanner's *negative* claims
degrade silently under obfuscation.

**Why it exists.** §5.3 is the chapter's most important single argument and it is much more
convincing when you produce it yourself. The lab has you build or obtain an obfuscated and an
unobfuscated build, scan both, and diff the reports section by section — establishing which sections
are value-derived (unchanged) and which are name-derived (gone).

**Success criteria.** A table like §6.3's, filled in from your own two builds, plus a written answer
to: *"which of these report sections would you still trust on an obfuscated app, and why?"*

### 12.4 Lab 04 — CTF: the report that lies

**Objective.** Four flags. Each is reachable only by disbelieving a specific line of a scanner report
and going to the artefact instead.

| Flag | The lie |
|---|---|
| 1 | A section rated `info` that is a Medium |
| 2 | A negative claim in the reassuring band that is false |
| 3 | A `high` finding whose value is not what the section calls it |
| 4 | A finding that is in no section at all, reachable only by reading the file a different finding cited |

**Success criteria.** Four flags, plus — and this is graded harder than the flags — a one-paragraph
report entry for each, written to the standard of
[`examples/finding-rewritten.md`](examples/finding-rewritten.md). A flag with no defensible write-up
scores zero, which is the point of the exercise.

---

## 13. Summary

### 13.1 Key points

- **MobSF is a census, not an assessment.** It implements stages 1–5 of a static pipeline, about
  half of stage 6, and none of stage 7. Stage 7 is where findings are made.
- **Its value is breadth and speed**, and that value is real. Seven hours of mechanical work per
  unfamiliar application, done consistently, in ninety seconds, with a REST API.
- **Severity in a MobSF finding is rule metadata.** The CVSS is a constant written by a rule author
  for every application that will ever match. It knows nothing about your app.
- **The security score is a count of rule matches.** Two builds of one application scored 34 and 38 in
  the *inverse* order of their attacker value. Never report it; never let a client gate on it.
- **Confidence ranking is not severity ranking**, and this repository has measured it four separate
  times: 132/132 false positives, 15 of 17 HIGH-band leads rejected, 12 surfaces to 4 pins, and a
  detector that agreed 18/18 until it was made honest and became 13/18.
- **The scorecard restates the other sections.** 11 of 39 items in this chapter's run — 28% — were
  the report summarising itself.
- **Almost every real finding is a join across report sections**, and MobSF's pipeline is one-pass,
  so it cannot make one. The exported WebView plus the JavaScript bridge plus the unvalidated URL
  extra are three sections and one High.
- **Its negative claims are the dangerous ones.** *"Does not implement certificate pinning"* was
  false on a measured, R8-processed build that configures a pin — and nobody audits a reassurance.
- **Anything derived from DATA survives obfuscation; anything derived from NAMES does not.** Manifest
  attributes, string literals, resource values and framework API names are data.
- **Six blind spots, with numbers**: runtime receivers (**69%** of the broadcast surface), 
  `RegisterNatives`, reflection, dynamic DEX, server-side behaviour, and splits (one app in eighteen
  had **zero** controls in `base.apk`).
- **The API is where MobSF genuinely shines.** A scriptable first pass over many APKs, cached by
  hash, emitting comparable JSON.
- **The deliverable is findings plus a ledger plus a limits section.** A report showing 39 items
  worked down to 8 findings, with a reason against each of the 15 rejections, is read completely
  differently from a report showing 8 findings and nothing else.

### 13.2 The chapter as a mind map

```mermaid
mindmap
  root((55 MobSF))
    What it is
      Static analysis
        unzip and inventory
        decompile once
        parse the manifest
        match patterns
        read the ELF
      Optional dynamic
        needs root effectively
        traffic, logcat, filesystem
        no liveness check
      Web UI plus REST API
      A census not an assessment
    Where it sits
      Stages one to five
      Half of stage six
      No stage seven
      No stage zero
    Its strengths
      Breadth in ninety seconds
      Component inventory
      Deep link map
      Certificate analysis
      Corpus work through the API
      A shared vocabulary with the client
    Its limits
      Severity is rule metadata
      CVSS is a constant
      Score counts rule matches
      One pass so no joins
      Scorecard restates sections
      Cache returns stale reports
      Schema drifts between versions
    False positives
      Somebody elses library code
      Value is not what the rule thinks
      Real but unreachable
      Fires on a number
      Severity inverted
      Restatement of another finding
    False negatives
      Name based rules die under R8
      Pinning claim measured wrong
      Packed apps report the stub
      Splits report a fraction
      Reflection is invisible
    Blind spots
      Runtime receivers sixty nine percent
      RegisterNatives
      Reflection
      Dynamic DEX
      Server side and remote config
      Splits you were not given
    What you owe it
      Validate every item
      Join across sections
      Name the asset
      Publish the ledger
      Write the limits section
    Tooling here
      mobsf triage ranks a corpus
      mobsf validate gathers evidence
      Neither assigns a finding
```

### 13.3 Condensed cheat-sheet

| Report section | What it is | Default read | Validate with |
|---|---|---|---|
| Component inventory | Fact | **Use it** | `dumpsys package`; splits |
| Permissions | Fact | **Use it** | Resolve custom `protectionLevel` yourself |
| Browsable activities | Fact | **Use it** | `am start -a VIEW -d '<uri>'` |
| Certificate | Fact | **Use it** | `apksigner verify -v --print-certs` |
| Files / libraries | Fact | **Use it**, and read it first | `unzip -l`; `lib-inventory.sh` |
| Manifest analysis | Opinion | Lead | [32](../32-Manifest/README.md)'s `manifest-audit.py` |
| Code analysis | Opinion | Lead | Open the cited line; then the Smali |
| Secrets | Opinion | **Classify before reading** | Decode; check the shape |
| Binary analysis | Fact | A hardening table, not findings | `readelf` |
| URLs / domains | Fact, noisy | Filter namespace URIs first | — |
| Trackers | Fact | Informational | Name-based, so R8-fragile |
| Network security | Opinion | Lead | Read `res/xml/` yourself |
| **appsec / score** | **Derived** | **Do not report it** | §3.9 |

| Question | Command |
|---|---|
| Is this the whole app? | `adb shell pm path <pkg>` |
| How much is native? | `unzip -l a.apk \| grep -E 'lib/.*\.so'` |
| Is it packed? | `apkid a.apk`; DEX size versus `assets/` size |
| Does it really pin? | `grep -a -o -h -E 'sha256/[A-Za-z0-9+/]{43}=' classes*.dex` |
| Is that permission real? | `aapt2 dump xmltree … \| grep -A2 'E: permission'` |
| Is it really debuggable? | `adb shell dumpsys package <pkg> \| grep flags=` |
| What did the decompiler refuse? | `grep -rl 'JADX ERROR' out/sources \| wc -l` |
| Force a re-scan | `POST /api/v1/delete_scan` with the hash |
| Rank a corpus | `python3 -B scripts/mobsf-triage.py --dir ./apks` |
| Validate a report | `python3 -B scripts/mobsf-validate.py --report r.json --apk a.apk --tree ./out` |

### 13.4 Quick revision

- MobSF covers stages ___ of 52's pipeline, and does not cover stage ___.
- The CVSS in a MobSF code finding is a property of the ___, not of the application.
- Two builds of one app scored 34 and 38; the ranking was ___ relative to attacker value.
- ___ of 39 items in this chapter's run were scorecard restatements.
- The pinning measurement: ___ of 14 apps had a surface, ___ actually pinned.
- Anything derived from ___ survives obfuscation; anything derived from ___ does not.
- The 43-character grep that finds a configured pin is ___.
- ___% of the broadcast surface is invisible to any artefact-based tool.
- One app in eighteen had zero controls in `base.apk` because ___.
- A negative claim in a scanner report is dangerous because ___.
- The survival rate on this chapter's worked example was ___ of 39 corroborated, ___ findings.
- Two of the eight findings originated ___.
- The deliverable is findings plus ___ plus ___.
- Before uploading a client's APK anywhere, check ___.

---

## 14. References

### MobSF itself

- **MobSF repository** — <https://github.com/MobSF/Mobile-Security-Framework-MobSF> — the source. The
  rule catalogue under `mobsf/StaticAnalyzer/views/android/rules/` is the single most useful file to
  read, and reading it once permanently changes how you interpret a finding.
- **MobSF documentation** — <https://mobsf.github.io/docs/> — installation, the REST API reference,
  and the dynamic analyser's device requirements.
- **MobSF Docker image** — <https://hub.docker.com/r/opensecurity/mobile-security-framework-mobsf> —
  the install route to prefer.
- **The API documentation page on your own instance** — `http://127.0.0.1:8000/api_docs` — the
  authoritative endpoint list for *your* version, which is the only one that matters.

### OWASP

- **OWASP MASVS** — <https://mas.owasp.org/MASVS/> — the control set MobSF tags its findings against.
  A MASVS identifier on a finding means a rule tagged with it matched, **not** that the control was
  tested.
- **OWASP MASTG** — <https://mas.owasp.org/MASTG/> — the testing procedures. Where MobSF gives you a
  lead, MASTG usually gives you the procedure that settles it.
- **OWASP Mobile Top 10** — <https://owasp.org/www-project-mobile-top-10/> — the category labels in
  MobSF's `owasp-mobile` metadata field.

### AOSP paths cited in this chapter

All are stable file paths; no line numbers are cited anywhere.

| Path | Why it matters here |
|---|---|
| `frameworks/base/core/java/android/content/pm/parsing/ParsingPackageUtils.java` | The manifest parse MobSF is predicting, including implicit `exported` and split merging |
| `frameworks/base/core/java/android/content/pm/PackageParser.java` | The legacy parser |
| `frameworks/base/libs/androidfw/ResourceTypes.cpp` | AXML and `resources.arsc` — why two tools can disagree about the same bytes |
| `frameworks/base/tools/aapt2/` | The compiler behind `aapt2 dump`, i.e. the platform's own reading |
| `art/libdexfile/dex/dex_file.cc`, `dex_file_verifier.cc` | DEX header fields are claims; the verifier bounds-checks them |
| `libcore/dalvik/src/main/java/dalvik/system/DexFile.java` | `openInMemoryDexFile` — where the artefact stops being the program |
| `art/runtime/jni/java_vm_ext.cc` | `JavaVMExt::RegisterNatives` — the native blind spot, in source |
| `frameworks/base/services/core/java/com/android/server/pm/PackageManagerService.java` | The installed truth that beats any file you decoded |

### Tools this chapter tells you to run instead of, or alongside, MobSF

- **jadx** — <https://github.com/skylot/jadx> — and read its error count against the tree, not the
  console.
- **apktool** — <https://apktool.org/> — Smali plus fully decoded resources.
- **APKiD** — <https://github.com/rednaga/APKiD> — packer, obfuscator and compiler fingerprints.
  Narrow by design and excellent within it.
- **semgrep** — <https://semgrep.dev/> — syntax-aware rules over decompiled Java; materially fewer
  shape false positives than regex.
- **Frida** — <https://frida.re/> — the answer to every question static analysis cannot settle.
- **`aapt2` / `apksigner`** — Android build-tools — the platform's own parser and signature verifier.

### Related chapters

| Chapter | Why it is here |
|---|---|
| [52-StaticAnalysis](../52-StaticAnalysis/README.md) | **The method MobSF automates.** The eight stages, triage, validation, and honest severity. Cited on nearly every page of this chapter |
| [32-Manifest](../32-Manifest/README.md) | Validates every manifest row MobSF emits. `manifest-audit.py` resolves implicit `exported` and custom protection levels |
| [36-CertificatePinning](../36-CertificatePinning/README.md) | The 12-of-14 measurement, the four-layer surface model, and `pinning-surface.py` |
| [10-APK-Internals](../10-APK-Internals/README.md) | The container, the signature block, and AXML parser divergence |
| [17-Libraries](../17-Libraries/README.md) | Dependency inventory **with versions** — MASVS-CODE, which MobSF's library list does not satisfy |
| [51-DynamicAnalysis](../51-DynamicAnalysis/README.md) | The runtime half, the liveness problem, and the denominator problem |
| [56-JADX](../56-JADX/README.md) | The decompiler underneath, and the 30× under-reporting of its own failures |
| [40-Obfuscation](../40-Obfuscation/README.md) | What obfuscation does to every name-based rule; packers and the stub |
| [42-R8](../42-R8/README.md) | Why type names vanish and string literals do not |
| [43-WebView](../43-WebView/README.md) | The bridge finding this chapter uses as its worked join |
| [34-Cryptography](../34-Cryptography/README.md) | Rates the ECB row, and owns the KDF defect no rule reports |
| [27-ContentProviders](../27-ContentProviders/README.md) | What an exported provider finding actually needs |
| [23-Permissions](../23-Permissions/README.md) | Protection levels — the check MobSF explicitly does not make |
| [29-BroadcastReceivers](../29-BroadcastReceivers/README.md) | The 69% of the broadcast surface no artefact-based tool sees |
| [16-JNI](../16-JNI/README.md) | `RegisterNatives`, and why an empty symbol table means nothing |
| [38-TamperDetection](../38-TamperDetection/README.md) | Splits, self-signature checks, and the detector that agreed with itself 18/18 |
| [44-NetworkSecurityConfig](../44-NetworkSecurityConfig/README.md) | The two false positives the network-security section reliably produces |
| [33-Storage](../33-Storage/README.md) | 132 hits, 132 false positives — and what a backup finding must name |
| [53-Frida](../53-Frida/README.md) | Settling what static analysis cannot |
| [37-RootDetection](../37-RootDetection/README.md) | Presence of a check is not enforcement |
| [60-ADB](../60-ADB/README.md) | Why an `adb shell` result does not prove app reachability |
| [71-OWASP-Mobile](../71-OWASP-Mobile/README.md) | MASVS-CODE, and what a MASVS tag does and does not mean |
| [80-Appendix](../80-Appendix/README.md) | The report template and the severity rubric this chapter deliberately does not restage |

Chapter 54 (Objection) wraps many of the runtime checks this chapter hands to Frida; chapters 39
(EmulatorDetection), 69 (MalwareAnalysis) and 76 (CheatSheets) are referenced in the text and are not
yet written.

### This chapter's own files

| File | What it is |
|---|---|
| [`cheatsheet.md`](cheatsheet.md) | Every MobSF finding category mapped to *what it actually detected* and *what you must do to confirm it* |
| [`mindmap.md`](mindmap.md) | The whole chapter as one Mermaid mind map |
| [`faq.md`](faq.md) | Twenty questions, including the ones people are embarrassed to ask |
| [`references/README.md`](references/README.md) | Annotated links and the related-chapters table |
| [`scripts/mobsf-triage.py`](scripts/mobsf-triage.py) | REST-API driver: scans a directory, emits a **triage-ranked** summary with every term printed |
| [`scripts/mobsf-validate.py`](scripts/mobsf-validate.py) | Takes a report and the artefact; gathers the evidence that would confirm or kill each finding |
| [`examples/`](examples/README.md) | Two report fixtures, two unedited tool runs, the ledger, and four findings rewritten |
| [`labs/`](labs/) | Four labs; lab 02 is the survival-rate measurement that is the point of the chapter |





