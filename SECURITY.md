# Security Policy

This repository teaches offensive mobile security. It contains **deliberately vulnerable
applications, working exploit code, and root, hooking and instrumentation tooling**. That is the
point of it, and it is why this file is longer than the template one.

Read this before you run anything.

---

## 1. Authorised testing only

Every technique here is written for **authorised** work, and for nothing else:

- Devices you own.
- Applications you wrote.
- Applications you have **written** permission to test.
- Deliberately vulnerable training targets, built from the sources in this repository.
- CTFs, and coordinated vulnerability disclosure inside a published scope.

Testing an application you do not own and are not authorised to test is a crime in most
jurisdictions — including the UK Computer Misuse Act, the US CFAA, and India's IT Act §43/§66. A bug
bounty program's scope document **is** your authorisation. Read it before you touch anything, and
stay inside it.

> **A lab is not a licence.** A lab teaches a technique against a target you built. It confers no
> authorisation to use that technique anywhere else. [73-Labs §5.4](73-Labs/README.md) makes this
> argument in full, and [00-Introduction lab 03](00-Introduction/labs/lab-03-legal-scope-triage.md)
> is an entire lab on scope triage. Neither is optional reading.

Techniques for defeating root detection, certificate pinning and integrity checks are documented
here because **you cannot assess an app you cannot observe**, and because developers need to
understand why their controls fail. They are not documented so that you can pirate software or
commit fraud.

---

## 2. The deliberately vulnerable applications

Several chapters ship applications that are **insecure on purpose** — `vulnerable-webview`,
`leaky-vault`, `victim-app`, `deputy-app`, the CTF targets, and others. They exist to be attacked.

**Rules for running them:**

| Rule | Why |
|---|---|
| Install only on a device or emulator **you own** | They are exploitable by any co-installed app. Several export components with no permission at all. |
| Never install on a device with a **real account signed in** | An exported provider or a world-readable file is a real data leak on a real profile. |
| Never install on a device carrying **client or engagement data** | The device you test on is evidence. See [73-Labs §5.3](73-Labs/README.md). |
| **Uninstall when you are finished** | Every lab in this repository ends with a cleanup section naming the package. |
| Prefer a **disposable emulator** | Nothing here requires a physical device except the eight `physical`-tagged labs, which [73-Labs](73-Labs/README.md) identifies. |

### Why this repository ships sources and not APKs

A downloaded "vulnerable app" binary is an unsigned-by-you executable of unknown provenance that you
are about to install on a device with developer options enabled. **The category has been abused.**

So this repository ships the **source** of every target plus the script that builds it, and never
the built binary. You can read what you are about to run. Build scripts generate a throwaway signing
key at build time, into an output directory outside the tree — no key and no certificate is ever
committed. [`43-WebView/examples/build.sh`](43-WebView/examples/build.sh) is the reference
implementation. The rule is enforced mechanically by [`.gitignore`](.gitignore) and by the
repository's own artefact check.

---

## 3. What this repository does not publish

### 3.1 No undisclosed third-party vulnerability

**No unfixed, undisclosed vulnerability in a third-party application or service is published here.**

Where a chapter discusses a real vulnerability, it is one that is already public: a CVE with an
assigned identifier, a disclosed bug bounty report, or an AOSP fix that has shipped.
[74-CaseStudies](74-CaseStudies/README.md) works exclusively from public material.

The repository also **fabricates nothing**. It names no CVE it has not verified, invents no bug
bounty report URL, and cites no AOSP line number it has not read. Where the honest answer is "this
is a known class and I am not certain of the identifier", the chapter says so and describes the
class instead. See [72-RealWorldFindings §1.5](72-RealWorldFindings/README.md).

### 3.2 Findings are labelled by adjudication state

A signal is not a finding. [72-RealWorldFindings](72-RealWorldFindings/README.md) describes the
pipeline that turns cheap signals into expensive claims, and every stage discards material.

**An unadjudicated lead is labelled as one.** This is not caution for its own sake:
[52-StaticAnalysis](52-StaticAnalysis/README.md) measured **15 of 17** HIGH-band leads rejected on
hand adjudication. Publishing an unresolved HIGH as though it were a finding contradicts this
repository's single most-repeated result.

### 3.3 The corpus is anonymised, deliberately and globally

Several chapters measured **commercial applications that happened to be installed on the author's
own test device**. The measurements are published; the applications' identities are not. Every such
app appears throughout as `com.vendor.<category>`, with the **same pseudonym in every chapter**.

**[`72-RealWorldFindings/references/README.md` §4](72-RealWorldFindings/references/README.md#4-corpus-pseudonyms)
documents this in full, and you should read it before adding any measurement of your own.** Three
things from it govern contributions:

1. **Partial anonymisation is not anonymisation. It is a puzzle with the answer printed on the next
   page.** This repository learned that on itself: one chapter carefully anonymised its target, and
   four other chapters then named the same application outright. The careful chapter's anonymisation
   was fully reversible by anyone who read the others, without even trying.

2. **An inventory is a fingerprint.** A size, a `targetSdk`, an SDK list and a per-package class
   count identify a vendor as reliably as the package name does. If the package name is worth
   withholding, so is the combination that reconstructs it.

3. **Anonymise the identity, never the measurement.** Every count, ratio, date, size and severity in
   this repository is the real, unmodified measured value. If a substitution would cost a number,
   the number wins and the section is rewritten around it.

There is **no mapping file**, and there will not be one. A file reversing the pseudonyms would
defeat the anonymisation.

**What is deliberately *not* anonymised:** AOSP, Google and OEM system-image packages (they are the
operating system under test, and no severity verdict attaches to them); library and SDK identifiers
used as reference data with no verdict attached; root/hooking packages and published detection
signatures; and the public deliberately-vulnerable training apps, which exist to be named. §4 of the
document above gives the test: **the verdict, not the identifier.** The moment a severity or a
"leaks / insecure / weak" claim attaches to a named vendor, it becomes a named finding and is
pseudonymised.

### 3.4 Never name a real vendor as vulnerable

Naming a real application alongside a security finding is, at best, a disclosure you were not
authorised to make and, at worst, defamatory if your adjudication was wrong.

The rule this repository follows: **describe the class, quantify the population, anonymise the
instance.** "Twelve of fourteen apps present a pinning surface and four pin" is publishable and
useful. The same sentence with product names attached is neither.

---

## 4. Reporting a security problem **in this repository**

This section is about defects in *this material*, not about vulnerabilities you found in someone
else's app.

### 4.1 What is in scope

Please report:

| Class | Example |
|---|---|
| **A lab that is unsafe as written** | A lab that tells you to disable a protection and never restores it; a target that binds to `0.0.0.0` instead of loopback; a cleanup section that misses a package. |
| **A command that is destructive or wrong** | A `dd`, `rm -rf`, `fastboot flash` or `pm uninstall` that can hit the wrong target or brick a device. |
| **De-anonymisation** | Any place where a `com.vendor.*` pseudonym can be resolved to a real vendor using material in this repository. This is treated as a security issue, not a typo. |
| **Leaked material** | A real hostname, pin value, API key, token, certificate or internal identifier that survived anonymisation. |
| **A supply-chain problem** | A script that downloads something over plain HTTP, without a hash, or from a URL that is no longer controlled by who you think. |
| **Harmful capability beyond teaching value** | Something that works as a weapon and teaches nothing. |

### 4.2 What is not in scope

- Vulnerabilities in third-party applications. Report those to the vendor, under their disclosure
  policy or bug bounty program. **Do not send them here, and do not open a public issue about them.**
- Vulnerabilities in the tools this repository documents (Frida, Magisk, JADX, apktool, …). Report
  those upstream.
- "This app on my phone is insecure." That is an engagement finding and it belongs to whoever
  authorised the engagement.
- The deliberately vulnerable applications being vulnerable. That is their function. If one is
  vulnerable in a way the chapter does *not* document, that is worth reporting — the chapter's claim
  is then incomplete.

### 4.2a Why the fake secrets in this repository look deliberately broken

Several chapters ship **fake credentials as the teaching object** — a Stripe-shaped key in a
manifest, a Google API key in a `strings.xml`, a JWT in a `<meta-data>` element. Every one is
invented; none has ever been valid.

They are written so they **do not match a real secret-scanner pattern**. `sk_live_` is followed by
underscores, and `AIzaSy` by dots, because GitHub's Stripe rule is `sk_live_[0-9a-zA-Z]{24,}` and
its Google rule allows hyphens and underscores but not dots. Breaking the character class defeats
the match without weakening the lesson.

This is deliberate and worth keeping:

- A realistic-looking fake secret **blocks `git push` for every contributor and every fork**, and the
  only way past is the "allow this secret" button. **Teaching people to click that button is worse
  than any lesson a realistic prefix could convey.**
- A scanner match generates work for whoever triages it, on a value that was never real.

**If you add an example credential, break the pattern the same way**, and never paste a real one —
not even an expired or revoked one.

### 4.3 How to report

**For anything that leaks identity or key material, or that could damage a reader's device: report
it privately first.** Do not open a public issue.

> **Private contact — use GitHub's private vulnerability reporting.**
> Go to this repository's **Security** tab and click **Report a vulnerability**. That opens a private
> advisory visible only to you and the maintainer; it is not a public issue and is not indexed.
>
> No email address is published here on purpose. This repository documents a deliberate
> anonymisation pass — personal identifiers were removed from its prose, transcripts and example
> paths — and publishing a contact address would quietly undo part of it. GitHub's advisory flow
> gives you a private channel without one.

For everything else — a wrong command, a broken lab, an unclear warning — open a normal issue.

**Please include:**

- The **chapter and file path**, e.g.
  [`43-WebView/labs/lab-02-onreceivedsslerror-defeats-a-correct-config.md`](43-WebView/labs/lab-02-onreceivedsslerror-defeats-a-correct-config.md).
- The **exact command or step**, copied, not paraphrased.
- **What happened**, with the real output. This repository's standard is that a claim carries the
  command that produced it; a report is held to the same standard.
- Your **device and environment**: Android version and API level, whether rooted and with what,
  emulator or physical, host OS and shell.
- What you think the **correct** text should be, if you know.

### 4.4 What to expect

This is a single-maintainer teaching repository, not a product with an on-call rotation. There is no
paid bounty and no guaranteed response time.

What is promised instead: **anything that endangers a reader's device, or that de-anonymises a
vendor, is treated as the highest priority and fixed ahead of any content work.** Corrections are
made in place, and where a correction changes a measured claim, the old claim and the reason it was
wrong are recorded rather than quietly deleted — that is how the rest of this repository handles
being wrong, and this file gets no exemption.

---

## 5. Handling your own findings

If you use this material on an authorised engagement and find something real:

1. **Adjudicate before you report.** Real, reachable, impactful — in that order. Most HIGH-band
   leads do not survive the first gate.
2. **Report to the vendor**, through their disclosure policy or bug bounty program, before anyone
   else.
3. **Do not publish** the vendor's name, the package, the hostnames or the pin values while the
   issue is unfixed.
4. **When you do write it up**, describe the class, quantify the population, and anonymise the
   instance — globally, not per document. Section 3.3 explains why "per document" fails.

---

## 6. Related documents

| Document | What it covers |
|---|---|
| [`README.md`](README.md) | What this repository is, and the authorised-testing notice |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | The conventions, and the checks that gate a change |
| [`STYLE-GUIDE.md`](STYLE-GUIDE.md) | How every chapter is written |
| [`LICENSE`](LICENSE) | Licensing for prose and for code |
| [`72-RealWorldFindings/references/README.md` §4](72-RealWorldFindings/references/README.md#4-corpus-pseudonyms) | The anonymisation policy in full — the authoritative text |
| [`73-Labs/README.md` §5](73-Labs/README.md) | Lab-environment safety, authorisation, and the supply-chain argument |
| [`00-Introduction/labs/lab-03-legal-scope-triage.md`](00-Introduction/labs/lab-03-legal-scope-triage.md) | Scope triage, as a lab |
