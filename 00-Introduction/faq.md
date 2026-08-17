# 00 — Introduction · FAQ

The questions people actually ask before they start, including the ones they are embarrassed to ask
out loud. Every answer here is the answer you would get from someone who has done the job, not the
answer that makes the field sound easy.

---

## Prerequisites — what you need before chapter 01

### Do I need to know how to code first?

You need to be able to *read* code before you can do anything useful, and you need to be able to
*write* small programs before you can do anything advanced. Those are two different bars, and you
clear them at different times. Reading is the immediate requirement: almost every task in this field
ends with a human looking at decompiled Java and deciding whether a line is dangerous. If you cannot
follow an `if` statement, a loop, or a method call, no tool will save you.

Writing comes later but it does come. Frida scripts are JavaScript. Automation is Python or shell.
Proof-of-concept exploit apps are Java or Kotlin. Reproducing a bug often means writing the twenty
lines of code that trigger it. You do not need to be a professional software engineer, but "I don't
write code" is a ceiling you will hit within a year.

The order this repository uses is deliberate. Chapters
[03-Programming-Fundamentals](../03-Programming-Fundamentals/README.md),
[04-Java](../04-Java/README.md) and [05-Kotlin](../05-Kotlin/README.md) assume you have never written
a line, and they come before any Android content, because reading a decompiled Android app is reading
Java. Do not skip them because you are impatient to get to Frida — the people who skip them are the
people who are still stuck two years later.

> **🧠 Mental Model** — Reverse engineering is reading comprehension in a language you did not choose,
> about a program you did not write, with half the words removed by the compiler. Learning to code
> first is learning the language. Everything else in this repository is learning to read fast under
> those bad conditions.

### Should I learn Java or Kotlin first?

Java first, then Kotlin. This is not a matter of taste, it is a consequence of what you will actually
be looking at. Whatever language an app was written in, it is compiled to DEX bytecode, and when you
decompile that bytecode with [JADX](../56-JADX/README.md) you get *Java*. A Kotlin `data class` comes
back as a Java class with a generated `equals`, `hashCode`, `toString`, `copy` and a pile of
`component1()` methods. Coroutines come back as state-machine classes implementing
`Continuation` with a `label` field and a `switch`. If you learned Kotlin only, decompiler output
will look alien.

Learn Java to the point where you can read classes, interfaces, inheritance, generics, collections,
exceptions and reflection. Then learn Kotlin, mostly so you can recognise what Kotlin constructs look
like *after* compilation, and so you can read modern app source when you are handed it. Modern
Android development is Kotlin-first, so if you ever work inside a product team you will write Kotlin.

> **🔬 Under the Hood** — The compiler pipeline is Java or Kotlin source, then `.class` JVM bytecode,
> then `d8`/`r8` produces DEX, and ART executes DEX. Both languages converge at the `.class` stage,
> which is precisely why the decompiler can only ever give you Java back. Details are in
> [12-DEX-Internals](../12-DEX-Internals/README.md) and [42-R8](../42-R8/README.md).

### How much maths do I need?

For application-level Android pentesting, almost none. You need arithmetic, you need to be
comfortable with hexadecimal and binary because addresses and flags are written that way, and you
need to understand bitwise AND, OR, XOR and shifts because permission flags and DEX access modifiers
are bitfields. That is genuinely it for the first year.

Cryptography is where a little more shows up, and even there the requirement is usually conceptual
rather than computational. You need to know what a key size means, why a nonce must not repeat, what
a modulus is in RSA, and roughly why elliptic curves are hard — not how to compute a point
multiplication by hand. [34-Cryptography](../34-Cryptography/README.md) teaches this at the level a
tester needs, which is "recognise the misuse", not "design the primitive".

Exploit development and cryptanalysis do want more: probability for fuzzing coverage arguments, modular
arithmetic for real crypto attacks, and some formal reasoning. That is level four or five on the
ladder, years away, and by then you will know exactly which maths you are missing.

### Do I need a Mac?

No. macOS is convenient, mainly because the Unix shell is native and Homebrew makes installation
painless, but there is nothing in Android security work that requires it — unlike iOS work, where a
Mac is effectively mandatory.

| Host OS | Strengths | Friction |
|---|---|---|
| Linux | Native shell, KVM makes the emulator fast, every tool ships for it, `udev` gives clean USB access | You must be willing to fix your own driver and permission problems |
| macOS | Unix shell, Homebrew, excellent hardware, good emulator performance on Apple silicon with arm64 images | Cost; some x86 system images and older tooling need translation |
| Windows | Works for everything; WSL2 gives you a real Linux shell alongside it | USB passthrough into WSL2 is awkward, so run `adb` on the Windows side; path and line-ending issues bite occasionally |

The practical recommendation is: use whatever you already own, and add WSL2 if you are on Windows.
Install commands for all three platforms are in [cheatsheet.md](cheatsheet.md).

> **⚠️ Warning** — If you are on Windows and run `adb` inside WSL2 while the device is attached to
> Windows, the two `adb` servers will fight over port 5037 and USB. Pick one side to own the device.
> Running `adb` on the Windows host and reaching it from WSL2 over TCP is the least painful pattern.

### I have never opened a terminal. Is that a problem?

It is a temporary problem and this repository was written specifically for you. Chapter
[02-Linux-Basics](../02-Linux-Basics/README.md) starts from what a shell *is* — a program that reads
what you type, finds a program with that name, and runs it — and builds up through the filesystem,
permissions, processes, signals and `/proc`. Android is Linux underneath, so every hour you put into
that chapter pays off twice: once on your host machine, and again inside `adb shell`.

Expect roughly two to three weeks of daily practice before the terminal stops feeling hostile. The
milestone to aim for is being able to move around, find files, read logs, and chain commands with
pipes without looking anything up.

---

## The lab — devices, emulators, and money

### Do I need a rooted phone?

You need root *somewhere*, but not necessarily on a phone. Root is what lets you read another app's
private data under `/data/data/<pkg>`, install a certificate into the system trust store, and run
`frida-server` as a privileged process so it can attach to arbitrary targets. Without any privileged
access, large parts of dynamic analysis are closed to you.

There are three ways to get it. The cheapest is an emulator running a `google_apis` system image,
where `adb root` simply works — no unlocking, no warranty questions, no risk. The second is a
physical device with an unlockable bootloader patched with [Magisk](../62-Magisk/README.md), which
gives you systemless root. The third, for situations where root is unavailable, is repackaging: patch
the APK, add a `networkSecurityConfig` that trusts your CA, inject a Frida gadget library, re-sign,
and install. That last route is how you test on devices you are not allowed to root, and it is a real
professional skill rather than a fallback for beginners.

> **⚠️ Warning** — Unlocking a bootloader wipes the device, and on many models it permanently trips a
> hardware-backed flag that some banking and payment apps check via Play Integrity. Never do this to
> the phone that holds your own banking apps, your authenticator, or your only SIM.

### Emulator or real device?

Both, eventually. Start with the emulator, because it costs nothing, roots instantly, snapshots so
you can undo a mistake in seconds, and cannot be bricked. Ninety percent of what you do in the first
six months works perfectly on it.

Move to hardware when the emulator stops being able to answer your question:

| Situation | Emulator | Physical device |
|---|---|---|
| Learning, labs, vulnerable apps | Ideal | Overkill |
| Root without unlocking anything | Yes, `adb root` on `google_apis` images | Requires bootloader unlock + Magisk |
| Snapshot and roll back | Yes | No |
| Hardware-backed KeyStore and StrongBox | Emulated only, attestation is not real | Real TEE, real attestation |
| Biometrics | Simulated fingerprint | Real sensor behaviour |
| Emulator detection in hardened apps | Frequently detected and blocked | Passes |
| Play Integrity / SafetyNet-style checks | Fails | Can be made to pass with effort |
| NFC, telephony, real SIM, sensors | Limited or absent | Real |
| Performance on ARM apps | Poor unless the image matches your host arch | Native |

> **🔍 Pentester's Note** — On a client engagement the target app very often refuses to run on an
> emulator, and you will not have time to discover that on day one. Test your device setup against
> the target before the engagement window opens, not during it.

### Which phone should I buy?

A Google Pixel, one or two generations old, bought second-hand, that is not your daily phone. The
reasons are practical rather than brand loyalty: Pixels have an officially supported bootloader
unlock, Google publishes factory images and full OTA images for them so you can restore a bricked
device, AOSP builds target them, and every published guide and Magisk workflow assumes them.

Pick a model that still receives security updates if you want to test modern behaviour, and check
before buying that the specific variant can be unlocked — carrier-locked units, especially US
carrier variants, frequently cannot. Older models are perfectly good for learning; API level matters
far more than screen quality.

What to avoid: any device whose manufacturer requires an unlock permission request or has stopped
issuing unlock codes, any device where the community has not published a working root method, and any
device you cannot afford to destroy. A rooted phone with an unlocked bootloader is not a secure
device and should never hold real accounts.

> **🧠 Mental Model** — Treat the test phone the way a chemist treats glassware: it is equipment, not
> property. It gets wiped, reflashed, and misconfigured constantly. The moment you start protecting
> it, it stops being useful.

### What if I cannot afford Burp Suite Professional?

You will be fine for a long time. Burp Suite Community intercepts, repeats and decodes traffic, and
interception plus `Repeater` is where nearly all real mobile findings come from. The features you
lose are the automated scanner, saved projects, `Intruder` at full speed, and the extension
ecosystem's paid corners. None of those find mobile-specific bugs — they find server-side bugs, and
they find them slower than a careful human.

The free alternatives are genuinely good. OWASP ZAP is fully featured and open source. `mitmproxy` is
excellent for scripted interception and for traffic that is not HTTP. For non-HTTP protocols you will
end up in `tcpdump` and Wireshark regardless of which proxy you paid for.

> **🔍 Pentester's Note** — Buy Burp Professional when a client is paying for your time, not while you
> are learning. Employers supply licences. The skill that gets you hired is knowing *what* to send in
> Repeater, and Community teaches that identically.

### Is MobSF enough?

No, and treating it as enough is one of the most visible marks of a beginner. MobSF is a triage tool.
It unpacks the APK, reads the manifest, greps for interesting strings and API calls, and produces a
report in a few minutes. That is real value — it tells you where to look first, and it catches the
obvious cases of hardcoded secrets, exported components and debuggable builds.

What it cannot do is understand your target's business logic, which is where the findings that matter
live. It cannot tell you that the `userId` in a request body is not validated server-side. It cannot
tell you that a signed-out user's session token stays valid. It cannot decide whether an exported
activity is actually reachable with attacker-controlled data. It also produces a steady stream of
false positives — flagged permissions the app legitimately needs, "insecure" API usages that are in
dead code, and third-party SDK findings that are not your client's problem.

The professional standard is to run MobSF early for orientation, then verify or discard every single
line of it by hand. See [55-MobSF](../55-MobSF/README.md) for how to use it correctly, and
[71-OWASP-Mobile](../71-OWASP-Mobile/README.md) for the manual methodology it is supposed to
accelerate rather than replace.

> **⚠️ Warning** — Delivering a MobSF export as a penetration test report is the fastest way to lose a
> client and a reputation. A report is what *you* concluded, with evidence; a scanner export is input
> to that process.

---

## Legality — what you are allowed to touch

### Is it legal to decompile an app?

In most cases, for personal study of software you legally obtained, yes — but the honest answer is
that it depends on three separate things that people habitually confuse: copyright law,
anti-circumvention law, and contract law.

Copyright law in many jurisdictions permits reverse engineering for interoperability and, in some,
for security research; the EU Software Directive and the US fair-use doctrine both have room for it.
Anti-circumvention law is narrower: the US DMCA §1201 forbids defeating technological protection
measures, with a security-research exemption that is real but conditional and periodically renewed.
Contract law is the one that catches people — the app's end-user licence agreement almost certainly
forbids reverse engineering outright, and violating it is a contract matter even where the law would
otherwise permit the act.

The practical rule that keeps you safe: decompile deliberately vulnerable apps, your own apps, and
apps you have written authorisation to test. Study techniques on those. If you want to look at a
commercial app for learning, understand that you are relying on jurisdiction-specific permissions,
and that publishing what you found is a very different act from looking at it privately. The
jurisdiction table in [cheatsheet.md](cheatsheet.md) lists the statutes by name.

> **📖 Definition** — **Authorisation** in this field means a specific, written, dated statement from
> someone with the authority to grant it, naming what you may test and how. A verbal "sure, go
> ahead", a forum post, or your own belief that the owner would not mind are not authorisation.

### Can I test apps that are on the Play Store?

Only within a programme that invites it, or under a contract. Downloading and statically analysing an
APK on your own machine is a very different act from sending traffic to the vendor's production
servers. The moment your testing touches their backend, you are interacting with a computer system
you do not own, and that is exactly what the CFAA, the UK Computer Misuse Act and India's IT Act §43
and §66 prohibit.

The legitimate routes are: a public bug bounty programme whose scope explicitly lists the app, a
vulnerability disclosure programme, or a signed engagement. In every one of those, the scope document
*is* your authorisation. Read it fully, save a dated copy, and stay inside it. Note that "the app is
in scope" does not automatically mean the API is in scope, and it never means other users' accounts
are in scope.

> **⚠️ Warning** — Automated scanning against production is prohibited by most bounty programmes even
> when the target is in scope. Firing a scanner at an in-scope host without checking the rules is one
> of the most common ways researchers get banned from a platform.

### What if I find a bug by accident in an app with no bug bounty programme?

Report it, carefully, and stop testing. Write down what you observed and how, without gathering any
further evidence — every additional request you send after you know you have found something is
harder to defend as accidental. Look for a `security.txt` file at the vendor's domain, a security
contact page, or a `security@` address. If none exists, a national CERT or CSIRT can act as an
intermediary, and several do so routinely for exactly this situation.

Set a disclosure timeline, tell the vendor what it is, and be professional in tone. Do not ask for
money — an unsolicited report plus a request for payment reads like extortion regardless of your
intent, and has landed researchers in serious trouble. Do not publish details until the issue is
fixed or your stated timeline has expired and you have warned them.

Accept that some vendors respond badly. Weigh what you gain from reporting against the risk of a
legal response, especially if you found the bug in a jurisdiction with aggressive computer-crime
enforcement and the vendor has lawyers.

---

## The path — is this worth it, and how long

### Is Android pentesting still worth learning in 2026?

Yes, and the reason is structural rather than fashionable. Android runs on the majority of the world's
computing devices, and the applications on it now carry banking, identity documents, health records,
payments, and physical access control. That value keeps growing, and every one of those apps is a
client running on hardware the attacker fully controls — a threat model that cannot be engineered
away, only mitigated.

The market has also thinned at the top rather than the bottom. Automated scanners and AI-assisted
triage have commoditised the shallow end: anyone can produce a list of exported components and
hardcoded strings. What has become *more* valuable is the person who can defeat a commercial
obfuscator, reverse a native anti-tamper library, understand why a KeyStore-backed key is not
actually protecting anything, and explain the business impact to an engineering team. Those skills are
scarce and getting scarcer, because they take a year or more to build and most people quit at
month three.

The honest caveat: the easy entry point is gone. Being able to run Frida scripts from a blog post is
not a differentiator and has not been for years. The path in this repository — internals first, tools
last — is longer specifically because the short path no longer leads anywhere.

### Why does this repository teach Frida so late?

Because Frida is a consequence, not a foundation. To use it beyond copy-paste you need to already
understand what a process is, what a thread is, how memory is laid out, how ART represents a loaded
class and a compiled method, what `ptrace` does, how a shared library gets injected into a running
process, and how JNI bridges managed and native code. Every one of those is a chapter in stages one
through three of this repository.

If you learn Frida first, you get a specific and very common failure: the script from the blog post
works on a demo app, does not work on your target, and you have no way to reason about why. Is the
method name obfuscated? Is the class loaded by a different `ClassLoader`? Is the check in native code
instead of Java? Is the app detecting the injected thread? Is the app crashing on purpose? Each of
those has a different fix, and none of them is discoverable by trying more scripts.

Reaching [53-Frida](../53-Frida/README.md) after
[19-Memory](../19-Memory/README.md) and [16-JNI](../16-JNI/README.md) means the tool stops being
magic. `Java.perform` becomes "attach to the ART runtime on a thread that has a JNI environment".
`Interceptor.attach` becomes "rewrite the prologue and trampoline out". At that point you can write
your own hooks for a target nobody has blogged about, which is the entire job.

> **🧠 Mental Model** — Learning Frida before internals is learning to drive by memorising the route to
> one shop. It works until you need to go anywhere else.

### How long until I am employable?

For a junior mobile security role with no prior technical background, plan on twelve to eighteen
months of consistent part-time study — meaning ten to fifteen hours a week that you actually do, not
hours you intend to do. If you already write software professionally, six to nine months is realistic
because stages one and three collapse dramatically. If you are already a web pentester, you may be
looking at three to six months, since methodology, reporting and HTTP are already yours.

What makes you employable is not elapsed time, it is demonstrable output. Concretely, a hiring manager
wants to see that you can take an unfamiliar APK, find something real in it, and explain it clearly.
The portfolio that gets interviews is roughly: two or three full write-ups of vulnerable apps done
properly rather than at walkthrough depth, at least one bypass you performed and explained yourself,
one small tool or Frida script you wrote, and a couple of accepted bug bounty reports or a CVE if you
can get them.

> **🔍 Pentester's Note** — In interviews the differentiating question is almost always "walk me
> through how you approach an app you have never seen". Candidates who name tools fail it. Candidates
> who describe a methodology — enumerate the surface, map trust boundaries, test the assumptions —
> pass it, even when their tool knowledge is thinner.

### Do I have to read the chapters in order?

The first time, yes, if you are starting from little or no technical background. The numbering is a
dependency graph, not a menu: [12-DEX-Internals](../12-DEX-Internals/README.md) assumes
[01-Computer-Science-Basics](../01-Computer-Science-Basics/README.md),
[36-CertificatePinning](../36-CertificatePinning/README.md) assumes
[35-SSL](../35-SSL/README.md), and [67-BypassingProtections](../67-BypassingProtections/README.md)
assumes most of what precedes it.

If you already have relevant background, skip forward honestly rather than optimistically. A working
developer can usually start at [06-Android-Architecture](../06-Android-Architecture/README.md). A web
pentester who has never seen bytecode should still do stage three. The self-test for whether you may
skip a chapter is at the end of the style guide: can you explain the mechanism without saying
"somehow", find the relevant code in AOSP, test it manually with no tool, and write the fix as code?
If not, you have not learned it, however familiar it feels.

### What certifications actually matter?

Fewer than the marketing suggests, and none of them substitute for output. The ones with genuine
recognition in mobile security are practical and exam-based rather than multiple-choice.

| Certification | What it proves | Realistic weight |
|---|---|---|
| Offensive Security OSCP | General offensive competence and persistence under time pressure | Widely recognised by HR; not mobile-specific but opens doors |
| Practical mobile-focused certs from established training providers | Hands-on mobile testing to a defined syllabus | Useful signal for junior roles; verify the exam is practical, not quiz-based |
| Vendor mobile-development certs | Development knowledge, not security | Low for security roles |
| Broad management certifications | Governance vocabulary | Irrelevant early; relevant if you move into leadership |

What actually moves hiring decisions, in descending order: accepted CVEs or vendor acknowledgements,
public bug bounty reports, a clear technical blog or write-up portfolio, a conference talk, an
open-source tool people use, and then certifications. Certifications get your CV past a filter;
nothing else on that list needs to.

> **⚠️ Warning** — Collecting certificates instead of producing findings is a recognised failure mode.
> If you have three certifications and have never written a full report on an app, you are optimising
> the wrong variable.

### What is the difference between a mobile pentester and a security researcher?

They are different jobs with overlapping skills, and confusing them causes people to aim at the wrong
target. A mobile pentester is engaged to assess a specific application within a fixed window and
deliver a report. The work is bounded, client-facing, and deadline-driven; the skill that pays is
breadth and communication. You will test a fintech app one month and a logistics app the next, and
your value is that you reliably find what matters in each and explain it to people who must fix it.

A security researcher is trying to find something nobody knew existed, usually in the platform, an
SDK, a browser engine, or an OEM's code. The work is unbounded and open-ended; the skill that pays is
depth and stubbornness. Output is a CVE, an advisory, a talk, or a tool rather than a client report,
and it is measured in months of failure per success.

| Dimension | Mobile pentester | Security researcher |
|---|---|---|
| Target | One customer application | Platform, framework, SDK, or a class of apps |
| Time frame | Days to weeks per engagement | Weeks to months per question |
| Success looks like | A report with reproducible findings | A CVE, an advisory, novel technique |
| Core skill | Breadth, methodology, communication | Depth, tooling, tolerance of dead ends |
| Income shape | Salary or day rate, predictable | Salary plus bounties, or grants; lumpy |
| This repo covers it in | Stages 5 to 11 | [70-VulnerabilityResearch](../70-VulnerabilityResearch/README.md) and the internals stages |

Most people start as testers and drift toward research as their depth grows. That is the normal
trajectory and this repository is built for it.

---

## Doing the work — practical problems

### Why did my Burp proxy stop working on Android 7 and later?

Because Android 7.0 (API 24) changed the default trust behaviour: an app that targets API 24 or above
no longer trusts certificate authorities that the user installed. Your Burp CA lands in the *user*
trust store, the app ignores it, TLS validation fails, and you see either nothing at all or a wall of
handshake errors.

This was a deliberate change. Before it, anyone who could talk a user into tapping "install
certificate" could intercept every app on the device. After it, an app only trusts the system store
unless its own `network_security_config.xml` explicitly opts into user certificates — which release
builds essentially never do.

There are four ways through it, in rough order of how often professionals reach for them:

| Approach | Requires | Persistence | Notes |
|---|---|---|---|
| Install the CA into the system trust store | Root or an emulator with `-writable-system` | Reboot-safe on emulator; tmpfs mounts are lost | Filename must be `<subject_hash_old>.0` |
| Magisk certificate module | Magisk | Survives reboot, systemless | Cleanest option on a rooted phone |
| Repackage the APK with a permissive `networkSecurityConfig` | Ability to modify and re-sign the APK | Permanent in your build | Works with no root at all |
| Hook the trust manager at runtime with Frida | `frida-server` or a gadget | Per-run | Also handles pinning |

```bash
# host — the hash-naming step people get wrong
openssl x509 -inform DER -in cacert.der -out cacert.pem
openssl x509 -inform PEM -subject_hash_old -in cacert.pem | head -1   # -> 9a5ba580
cat cacert.pem > 9a5ba580.0
openssl x509 -inform PEM -text -in cacert.pem -noout >> 9a5ba580.0
```

If the CA is in the system store and interception *still* fails, you are looking at certificate
pinning, which is a separate control with separate bypasses. Note also that Android 14 moved the
trust store into an updatable APEX module, so the path you need may be under `/apex/` rather than
`/system/`. Full treatment lives in [44-NetworkSecurityConfig](../44-NetworkSecurityConfig/README.md)
and [36-CertificatePinning](../36-CertificatePinning/README.md).

> **🔬 Under the Hood** — Android's `TrustManagerImpl` builds its trust anchors from the system store,
> and the `subject_hash_old` filename is inherited from OpenSSL's directory-hash lookup format, which
> lets the lookup find an issuer certificate by hashing the subject name instead of scanning every
> file. That is why the filename is not arbitrary.

### How do I get my first bug bounty?

Lower your target and raise your patience. Almost nobody's first accepted report is on a
household-name programme, because those have been examined by thousands of researchers with more
experience than you. Start where competition is thin: newly launched programmes, smaller
organisations' apps, programmes on platforms with less traffic, and vulnerability disclosure
programmes that pay nothing but accept reports and build your record.

Then pick a niche and go deep rather than testing many apps shallowly. Mobile-specific classes still
produce findings consistently: exported components that accept attacker-controlled data, deep-link
handlers that skip authentication, `PendingIntent` mutability issues, WebView bridges reachable from
untrusted content, secrets in `shared_prefs` or in the APK, backup and export paths that leak data,
and — most reliably of all — the API behind the app, where the mobile client is simply the map to
undocumented server endpoints.

Read the scope document properly before you touch anything, and read the programme's list of known
issues and out-of-scope categories so you do not spend a weekend on something that will be closed as
informative. When you report, write it for the triager: one clear impact statement, exact reproduction
steps, the request and response, and a suggested fix. A well-written medium beats a badly written high
in both payout speed and reputation.

> **🔍 Pentester's Note** — Duplicates are not wasted work. A duplicate means you found a real bug that
> someone else found first, which is proof your methodology works. Keep a record of them; they are
> legitimate interview material even though they paid nothing.

### What do I do when I get stuck?

Recognise first that being stuck is the working state of this profession, not a deviation from it.
Professionals are stuck most of the time; the difference is that they have a routine for it instead of
a feeling about it.

The routine that works is to shrink the problem until something becomes observable. If a Frida script
does not work, stop debugging the script and prove the basics: does `frida-ps -U` list the process at
all, does an empty script attach cleanly, does hooking `System.exit` produce any output. If traffic is
not appearing in Burp, prove that the device reaches the proxy at all by browsing to `http://burpsuite`
before you theorise about pinning. Change exactly one variable per attempt and write down what
happened, because after an hour you will not remember which combinations you already tried.

When the mechanical checks are exhausted, go up a level and ask what you are *assuming*. Most long
blockages are a wrong assumption rather than a wrong command: assuming the class is loaded when it is
not, assuming the check is in Java when it is in a `.so`, assuming the app uses HTTP when it uses a
custom socket protocol. Reread the relevant chapter — the fix for a stuck afternoon is very often a
paragraph you skimmed.

Finally, set a hard time limit and then walk away. Two hours of frustrated retrying produces less than
twenty minutes after a break. If a full day passes with no movement, ask for help publicly with the
detail of what you already tried, because a well-formed question gets answered and "it doesn't work"
does not.

> **🧠 Mental Model** — Debugging is binary search over your own assumptions. Every experiment should
> eliminate half of what could be wrong. If an experiment cannot possibly eliminate anything, do not
> run it.

### Do I need to learn C and assembly?

Eventually yes, but not on day one, and not to the depth of writing production C. Serious apps put
their interesting logic — root detection, integrity checks, key derivation, DRM, licence validation —
in native libraries precisely because native code is harder to reverse than DEX. If you cannot read
AArch64 disassembly, those libraries are opaque to you and there is a hard ceiling on what you can
assess.

The requirement is reading fluency, not authorship. You need to recognise a function prologue and
epilogue, follow the AArch64 calling convention so you know which register holds which argument,
identify a loop and a comparison, spot a string reference, and follow calls through the PLT. You need
enough C to understand what the decompiler in [Ghidra](../57-Ghidra/README.md) is showing you, and
enough about ELF to know what a section, a symbol and a relocation are.

This repository builds that in [15-Native-Code](../15-Native-Code/README.md),
[18-ARM](../18-ARM/README.md) and [16-JNI](../16-JNI/README.md), all of which sit well after the Java
material — because the natural first year is spent in managed code, and native analysis is what
distinguishes level three from level two on the ladder.

### Do I really need to read AOSP source code?

Yes, and this is one of the clearest dividing lines between people who plateau and people who do not.
Documentation tells you what an API is supposed to do. AOSP tells you what it actually does, including
the special cases, the version-specific behaviour, and the check that is missing. When you want to
know whether a permission is enforced, the authoritative answer is the line in `system_server` that
enforces it, not a paragraph on a documentation page.

You do not need to build AOSP to benefit from reading it, and you do not need to read it linearly —
nobody does. What you need is the ability to find a class quickly, follow a call from a public API
down through the framework into Binder and, where relevant, into native code and the kernel. That
skill is the subject of [07-AOSP](../07-AOSP/README.md), and every later chapter in this repository
cites real file paths so you practise it continually.

> **🔬 Under the Hood** — A typical trace looks like this: an app calls a framework method in
> `frameworks/base/core/java/android/...`, which is a thin client-side proxy that marshals a Binder
> transaction, which is received by a service in `frameworks/base/services/core/java/...` running
> inside `system_server`, which performs the permission check and does the real work, possibly
> descending into a HAL or a syscall. Being able to walk that path unaided is the practical definition
> of "knowing Android".

### How do I know when I have actually learned a chapter?

Use the repository's own standard, from [STYLE-GUIDE.md](../STYLE-GUIDE.md). A chapter is finished
when you can explain the mechanism to a developer without using the words "somehow" or "under the
hood", find the relevant code in AOSP unaided, test the behaviour manually with no automated tool,
explain why a scanner's finding about it is a false positive, and write the remediation as code.

The most reliable self-test is teaching. Write your own summary of the chapter from memory, in your
own words, without looking at it — then compare. The gaps are exactly what you did not learn, and
they are never the parts you expected. Answering the chapter's interview questions out loud, at
speaking pace, catches the same gaps faster than rereading ever will.

Do not use "I finished the labs" as the standard. Finishing a lab with the hints open proves you can
follow instructions. Redoing it a week later from a blank page proves you learned something.
