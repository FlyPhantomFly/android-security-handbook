# 00 — Introduction · References

Everything linked here is a primary source: official documentation, the tool's own homepage, the
standard body's own text, or the project repository. Every entry says what it is and why you would
open it. Where a specific page is what you want but the exact URL is version-dependent, the project
root is linked and the page is described instead.

---

## Official Android and AOSP documentation

- **Android Open Source Project** — https://source.android.com — The platform's own documentation:
  architecture, security model, Verified Boot, SELinux policy, compatibility requirements. Open this
  when you need to know how the *platform* behaves, not how an app API is used.
- **AOSP source browser** — https://cs.android.com — Google's code search over the whole Android
  tree. This is where you go to answer "what does this method actually do" instead of guessing.
- **AOSP Gerrit / repositories** — https://android.googlesource.com — The canonical git hosting for
  every AOSP project. Use it to read commit history and see *when* a security check was added.
- **Android Developers documentation** — https://developer.android.com — The app-developer-facing
  reference for every framework API, manifest attribute and Jetpack library. Open it to learn what a
  developer was told to do, which is often not what they did.
- **Android security overview** — https://source.android.com/docs/security — The platform security
  model in Google's own words: sandbox, permissions, keystore, trusty, verified boot.
- **Android Security Bulletins** — https://source.android.com/docs/security/bulletin — Monthly list
  of patched platform vulnerabilities with CVE identifiers and severity. The best single source for
  seeing what real Android platform bugs look like.
- **Android Compatibility Definition Document** — https://source.android.com/docs/compatibility/cdd —
  What every OEM must implement to call a device Android. Useful when you need to argue that a
  vendor's deviation is non-conformant.
- **Network security configuration guide** — https://developer.android.com — Search for "Network
  security configuration". The document that explains why your proxy stopped working on API 24+.
- **Android platform release notes and behaviour changes** — https://developer.android.com — Each
  release has a "Behavior changes" page. Read the one for your target's `targetSdkVersion` before
  testing; it explains half of what you will observe.
- **Play Integrity API documentation** — https://developer.android.com/google/play/integrity — The
  modern attestation mechanism apps use to decide whether your rooted test device is acceptable.

---

## Tooling homepages and documentation

- **Frida** — https://frida.re — The dynamic instrumentation toolkit this whole field runs on. The
  JavaScript API reference on that site is the document you will keep open while writing hooks.
- **Frida releases** — https://github.com/frida/frida/releases — Where `frida-server` binaries live.
  Download the build matching your device architecture *and* your host `frida` version exactly.
- **Objection** — https://github.com/sensepost/objection — A prepackaged Frida agent giving you
  filesystem, keystore, pinning-bypass and memory commands without writing a script. Read its source
  to learn what it is doing on your behalf.
- **jadx** — https://github.com/skylot/jadx — The DEX-to-Java decompiler. The GUI's cross-reference
  and search features are what make an unfamiliar APK navigable.
- **Apktool** — https://apktool.org — Decodes resources and disassembles DEX to Smali, and rebuilds
  the result. The documentation's troubleshooting page covers the framework errors everyone hits.
- **Apktool repository** — https://github.com/iBotPeaches/Apktool — Source and issue tracker; check
  the issues when a rebuild fails on a new Android version.
- **smali/baksmali** — https://github.com/google/smali — The assembler and disassembler for DEX.
  Useful when you want to patch bytecode precisely rather than round-tripping through Apktool.
- **MobSF** — https://github.com/MobSF/Mobile-Security-Framework-MobSF — Automated static and dynamic
  analysis for mobile apps. Open the repository for setup, the Docker image, and the REST API docs.
- **Ghidra** — https://ghidra-sre.org — The NSA's free reverse-engineering suite with a decompiler
  good enough for Android native libraries. Start here for `.so` analysis.
- **Ghidra releases** — https://github.com/NationalSecurityAgency/ghidra — Source, releases, and the
  extension ecosystem.
- **Burp Suite** — https://portswigger.net/burp — The intercepting proxy. The Community edition is
  enough to learn on; the documentation section on mobile device configuration is worth reading in
  full.
- **PortSwigger Web Security Academy** — https://portswigger.net/web-security — Free, high-quality
  labs on the server-side vulnerability classes you will find behind mobile apps.
- **OWASP ZAP** — https://www.zaproxy.org — Fully open-source alternative to Burp with an active
  automation framework.
- **mitmproxy** — https://mitmproxy.org — Scriptable interception in Python, and far better than a
  GUI proxy when you need to rewrite traffic programmatically or handle non-browser protocols.
- **Magisk** — https://github.com/topjohnwu/Magisk — Systemless root plus Zygisk and DenyList. The
  releases page has the APK; the documentation explains boot image patching properly.
- **Android Studio** — https://developer.android.com/studio — Ships the SDK, `adb`, the emulator,
  `avdmanager` and `sdkmanager`. Even if you never write an app, you need what is in the box.
- **Android command-line tools** — https://developer.android.com/tools — Reference for `adb`,
  `fastboot`, `sdkmanager`, `avdmanager`, `apksigner`, `zipalign` and `aapt2`.
- **LSPosed** — https://github.com/LSPosed/LSPosed — Modern Xposed framework running under Zygisk,
  for persistent hooks that survive app restarts.
- **Drozer** — https://github.com/WithSecureLabs/drozer — IPC attack-surface enumeration: activities,
  services, providers and receivers, queried interactively.
- **radare2** — https://rada.re — Scriptable reverse-engineering framework; pairs with Cutter for a
  GUI.
- **apkleaks** — https://github.com/dwisiswant0/apkleaks — Fast scan of an APK for URIs, endpoints
  and secrets. A triage aid, not a substitute for reading the code.
- **Frida CodeShare** — https://codeshare.frida.re — Community-published Frida scripts. Read them to
  learn technique; never run one against a client target without understanding every line.

---

## Standards and methodology

- **OWASP Mobile Application Security project** — https://mas.owasp.org — The umbrella site for
  MASVS, MASTG and MASWE. This is the methodology backbone of professional mobile testing.
- **OWASP MASVS** — https://mas.owasp.org/MASVS — The Mobile Application Security Verification
  Standard: the requirements an app is measured against, grouped by control area. Use it to define
  scope and to structure a report.
- **OWASP MASTG** — https://mas.owasp.org/MASTG — The Mobile Application Security Testing Guide: the
  concrete tests, tools and techniques that prove or disprove each MASVS requirement. The single most
  useful practical document in the field.
- **OWASP MASWE** — https://mas.owasp.org/MASWE — The Mobile Application Security Weakness
  Enumeration: named weaknesses that map MASVS controls to concrete failure modes.
- **OWASP Mobile Top 10** — https://owasp.org/www-project-mobile-top-10 — The awareness-level list.
  Good for talking to management; too coarse to test against on its own.
- **OWASP Top 10** — https://owasp.org/www-project-top-ten — The web equivalent, which still applies
  to every backend your mobile client talks to.
- **MITRE CWE** — https://cwe.mitre.org — The weakness taxonomy your findings should cite so that
  developers and other tools can match them.
- **MITRE ATT&CK for Mobile** — https://attack.mitre.org/matrices/mobile — Adversary techniques on
  mobile platforms; the vocabulary threat-intel and detection teams use.
- **NIST SP 800-163 Rev. 1, Vetting the Security of Mobile Applications** —
  https://csrc.nist.gov/publications — The US government's app-vetting methodology; useful for
  enterprise and public-sector engagement scoping.
- **NIST SP 800-124, Guidelines for Managing the Security of Mobile Devices** —
  https://csrc.nist.gov/publications — Device and enterprise mobility management guidance, relevant
  when the engagement includes MDM.
- **NIST National Vulnerability Database** — https://nvd.nist.gov — Authoritative CVE records with
  CVSS vectors. Use it to check severity claims rather than repeating a vendor's number.
- **FIRST CVSS specification** — https://www.first.org/cvss — The scoring standard. Read the
  specification once so your severity ratings are defensible rather than instinctive.
- **PCI Mobile Payment Acceptance Security Guidelines** — https://www.pcisecuritystandards.org — What
  payment apps are contractually held to; relevant on any fintech engagement.

---

## Legal texts

> These are the primary sources. They are not legal advice, and the summary next to each is a
> pointer, not an interpretation. Get written authorisation for every engagement and consult a
> qualified lawyer for anything ambiguous.

- **US Computer Fraud and Abuse Act, 18 U.S.C. §1030** — https://www.law.cornell.edu/uscode/text/18/1030
  — The core US computer-crime statute prohibiting access without authorisation and exceeding
  authorised access. Read it before doing anything against a US-hosted system without a contract.
- **US Department of Justice CFAA charging policy** — https://www.justice.gov — Search for the
  department's policy on charging under the CFAA, which sets out a good-faith security research
  position. It binds federal prosecutors, not private plaintiffs.
- **US DMCA, 17 U.S.C. §1201** — https://www.law.cornell.edu/uscode/text/17/1201 — The
  anti-circumvention provision. The security-research exemption is granted through periodic
  rulemaking by the Copyright Office, so check its current form at https://www.copyright.gov.
- **UK Computer Misuse Act 1990** — https://www.legislation.gov.uk/ukpga/1990/18 — Sections 1 to 3A
  cover unauthorised access, unauthorised acts impairing operation, and making or supplying articles
  for use in computer misuse. The full text is short; read it once end to end.
- **UK Crown Prosecution Service guidance on the Computer Misuse Act** — https://www.cps.gov.uk —
  Search for "Computer Misuse Act"; explains how the offences are charged in practice.
- **India Information Technology Act 2000** — https://www.meity.gov.in — The Ministry of Electronics
  and Information Technology publishes the Act and its amendments. §43 creates civil liability for
  unauthorised access, downloading, damage and denial of service; §66 makes the same acts criminal
  when done dishonestly or fraudulently.
- **India CERT-In** — https://www.cert-in.org.in — The national CERT, including its vulnerability
  reporting channel and its incident-reporting directions.
- **EU Directive 2013/40/EU on attacks against information systems** — https://eur-lex.europa.eu —
  Search the directive number. It harmonises computer-crime offences across member states; each state
  implements it in its own criminal code, so the national text is what actually applies to you.
- **EU General Data Protection Regulation, Regulation 2016/679** — https://eur-lex.europa.eu — Search
  for the regulation number, or use https://gdpr-info.eu for a readable structured copy. Relevant
  because any real user data you touch during testing is personal data: minimise what you collect,
  protect it while you hold it, and delete it when the engagement ends.
- **EU Cyber Resilience Act and NIS2** — https://eur-lex.europa.eu — Increasingly shape vendor
  disclosure obligations in Europe; worth knowing by name when advising clients.
- **CVE Program** — https://www.cve.org — How identifiers are assigned and which CNA to approach when
  you have found something that deserves one.

---

## Vulnerable practice apps

Every app in this section exists to be attacked. They are the only targets you can practise on with
no authorisation question at all.

- **DIVA Android** — https://github.com/payatu/diva-android — "Damn Insecure and Vulnerable App": the
  classic first target, with small self-contained challenges covering insecure logging, storage,
  input validation and hardcoded secrets. Start here on your first day of hands-on work.
- **InsecureBankv2** — https://github.com/dineshshetty/Android-InsecureBankv2 — A deliberately broken
  banking app with a companion backend, so you can practise the client *and* the API together. The
  closest thing to a realistic first engagement.
- **OWASP MASTG crackmes** — https://mas.owasp.org/crackmes — Official reversing challenges tied to
  the MASTG, covering obfuscation, root detection, anti-debugging and native code. The graded path
  from "readable Java" to "packed native library".
- **Damn Vulnerable Bank** — https://github.com/rewanthtammana/Damn-Vulnerable-Bank — A modern
  vulnerable banking app that includes root detection, emulator detection and pinning, so you can
  practise bypasses rather than just discovery.
- **AndroGoat** — https://github.com/satishpatnayak/AndroGoat — Kotlin-based vulnerable app with a
  broad list of scenarios including deep links, WebView issues and insecure IPC. Useful because it
  is Kotlin, so decompiled output looks like a modern real app.
- **PIVAA** — https://github.com/HTBridge/pivaa — "Pretty Insecure and Vulnerable Android App", a
  compact target with a documented vulnerability list, good for quick regression practice of a
  checklist.
- **InjuredAndroid** — https://github.com/B3nac/InjuredAndroid — CTF-style vulnerable app with flags,
  covering deep links, Firebase misconfiguration, exported components and native code. The flag
  format makes progress unambiguous.
- **Frida Labs** — https://github.com/DERE-ad2001/Frida-Labs — A graded series of small binaries and
  apps designed purely to teach Frida hooking step by step. Work through it *after*
  [53-Frida](../../53-Frida/README.md), not before.
- **OWASP GoatDroid** — https://owasp.org — Search the OWASP project list for GoatDroid. Older but
  still instructive for IPC and storage issues.
- **Vuldroid** — https://github.com/jaiswalakshansh/Vuldroid — Focuses on modern browser-adjacent
  issues: deep links, WebView bridges, exported provider abuse and file access.
- **UnCrackable apps in the MASTG repository** — https://github.com/OWASP/owasp-mastg — The MASTG
  source repository, which contains the UnCrackable series and their write-ups alongside the guide
  text itself.
- **Kotlin and Java sample vulnerable code from the Android security docs** —
  https://developer.android.com — Google documents insecure patterns alongside the secure ones; the
  "app security best practices" pages show both sides.

Chapter [73-Labs](../../73-Labs/README.md) maintains the full catalogue with difficulty ratings and
suggested order.

---

## Bug bounty platforms

- **HackerOne** — https://hackerone.com — The largest platform by programme count. Its Hacktivity
  feed of disclosed reports is one of the best free learning resources in existence.
- **Bugcrowd** — https://www.bugcrowd.com — Large platform with a public Vulnerability Rating
  Taxonomy at https://bugcrowd.com/vulnerability-rating-taxonomy that tells you how mobile findings
  are typically severity-rated.
- **Intigriti** — https://www.intigriti.com — European-focused platform, often with less-saturated
  programmes, which matters a great deal for your first accepted report.
- **YesWeHack** — https://www.yeswehack.com — Another European platform with a good disclosure
  culture and educational content.
- **Google Bug Hunters** — https://bughunters.google.com — Google's own programme, covering Android,
  Chrome, and apps in Google Play through the App Defense-style initiatives. Read the rules page for
  what qualifies on Android specifically.
- **Samsung Mobile Security** — https://security.samsungmobile.com — Vendor programme for Samsung
  devices and preinstalled apps, a productive target area for OEM-specific bugs.
- **Microsoft, Meta, Apple and other vendor programmes** — each vendor publishes its own security
  page; find them from https://www.cve.org or the vendor's `security.txt`.
- **disclose.io** — https://disclose.io — Standard templates and safe-harbour language for
  vulnerability disclosure. Read it before you report anything to an organisation with no programme.
- **security.txt specification, RFC 9116** — https://www.rfc-editor.org/rfc/rfc9116 — The standard
  file at `/.well-known/security.txt` telling you where to send a report. Check for it first, always.

---

## Communities and conferences

- **DEF CON** — https://defcon.org — Talk archives going back decades, much of it free to watch, with
  a long history of Android platform research.
- **Black Hat** — https://www.blackhat.com — Briefings archive; the mobile track regularly carries
  the year's most significant Android platform work, with published whitepapers.
- **OffensiveCon** — https://www.offensivecon.org — Deep offensive research, heavy on exploitation
  and platform internals rather than app testing.
- **Hexacon** — https://www.hexacon.fr — Offensive security conference with consistently strong
  mobile and baseband content.
- **Recon** — https://recon.cx — Reverse engineering specifically; the place for native RE technique.
- **Nullcon and null community** — https://nullcon.net and https://null.community — Large Indian
  security community with regular free local chapter meetings, historically strong on mobile.
- **OWASP local chapters** — https://owasp.org/chapters — Free meetings worldwide; the mobile project
  maintainers are reachable through them.
- **Frida community** — the discussion links on https://frida.re point to the current official
  channels; the GitHub issues on https://github.com/frida/frida are also a de facto knowledge base.
- **r/ReverseEngineering** — https://www.reddit.com/r/ReverseEngineering — Aggregates new research
  and write-ups across platforms.
- **XDA Developers** — https://xdaforums.com — Device-specific rooting, bootloader unlocking and
  custom ROM knowledge. Indispensable when you need to know whether a specific handset can be
  unlocked before you buy it.

---

## Books

- **The Android Hacker's Handbook** — Drake, Lanier, Mulliner, Fora, Ridley, Wicherski. Dated in its
  specifics but still the clearest published explanation of Android's security architecture and the
  structure of platform exploitation.
- **Android Security Internals** — Nikolay Elenkov. The definitive treatment of how the framework's
  security mechanisms are actually implemented: package management, permissions, crypto providers,
  KeyStore, and account management.
- **The Mobile Application Hacker's Handbook** — Chell, Erasmus, Colley, Whitehouse. Covers Android
  and iOS side by side; useful for the methodology and the reporting perspective.
- **Android Internals: A Confectioner's Cookbook** — Jonathan Levin. Extremely deep on boot, init,
  the runtime and the native layer. Reach for it when AOSP itself is not explaining enough.
- **Practical Binary Analysis** — Dennis Andriesse. ELF, disassembly, binary instrumentation and
  taint analysis; the background you need before native Android RE stops being guesswork.
- **The Ghidra Book** — Chris Eagle and Kara Nance. The systematic reference for the tool you will
  use on every `.so` file.
- **The Art of Software Security Assessment** — Dowd, McDonald, Schuh. Not Android-specific and not
  new, but still the best book on how to actually audit code for vulnerabilities.
- **Serious Cryptography** — Jean-Philippe Aumasson. The right depth of cryptography for a security
  tester: enough to recognise misuse, without a mathematics degree.
- **Operating Systems: Three Easy Pieces** — Arpaci-Dusseau, free at https://pages.cs.wisc.edu/~remzi/OSTEP
  — Processes, memory, scheduling and concurrency explained properly. The best free companion to
  [01-Computer-Science-Basics](../../01-Computer-Science-Basics/README.md).

---

## Blogs and researchers worth following

- **Google Project Zero** — https://googleprojectzero.blogspot.com — The highest-quality public
  vulnerability research anywhere, including Android kernel, Chrome, baseband and messaging apps.
  Read their write-ups even when you understand only half; the methodology is the lesson.
- **Android Developers Blog** — https://android-developers.googleblog.com — Announcements of platform
  behaviour changes, often months before they affect your targets.
- **Google Security Blog** — https://security.googleblog.com — Platform-level mitigations and
  ecosystem changes explained by the people who shipped them.
- **NowSecure blog** — https://www.nowsecure.com/blog — Consistent mobile application security
  research and tooling posts from a dedicated mobile shop.
- **Oversecured blog** — https://blog.oversecured.com — Prolific, concrete Android application
  vulnerability research, especially on IPC, deep links and provider abuse. Some of the most directly
  applicable material for app testers anywhere.
- **PortSwigger Research** — https://portswigger.net/research — Server-side and protocol research
  that applies directly to the APIs behind mobile apps.
- **hex-rays and Ghidra release notes** — https://hex-rays.com and https://github.com/NationalSecurityAgency/ghidra
  — Decompiler capabilities change what is practical in native RE; the release notes are worth
  skimming.
- **Ole André Vadla Ravnås and the Frida project blog** — https://frida.re/news — Release notes and
  design write-ups explaining what the instrumentation engine can now do.
- **John Wu, Magisk author** — https://topjohnwu.github.io/Magisk/ and the Magisk repository — Design notes
  on systemless root and Zygisk that explain *why* the hiding mechanisms work.
- **Maddie Stone's public Android research** — published through Project Zero and conference talks;
  particularly good on in-the-wild Android exploitation and malware.
- **XDA and Mishaal Rahman's platform reporting** — https://xdaforums.com — Early, accurate detail on
  undocumented platform changes, often before official documentation exists.
- **Trail of Bits blog** — https://blog.trailofbits.com — Rigorous applied security engineering,
  including mobile cryptography and hardware-backed key storage.

---

## How to use this list

Read the OWASP MASTG alongside chapters 20 to 33 of this repository, because those chapters explain
the mechanisms the MASTG tests. Keep https://cs.android.com open permanently while you read any
chapter with a Source Code Walkthrough section. Treat the vulnerable-app list as a queue rather than
a menu: DIVA first, then InsecureBankv2, then AndroGoat, then InjuredAndroid, then the MASTG
crackmes, then Damn Vulnerable Bank once you have reached
[67-BypassingProtections](../../67-BypassingProtections/README.md). Chapter
[73-Labs](../../73-Labs/README.md) tracks that queue in detail, and
[74-CaseStudies](../../74-CaseStudies/README.md) dissects public reports from the platforms listed
above.
