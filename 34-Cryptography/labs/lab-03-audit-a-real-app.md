# Lab 03 — Audit a Real App, End to End

**Difficulty:** Advanced
**Time:** 4–8 hours (one working day for a first pass)
**Prerequisites:** [Lab 01](lab-01-break-the-vault.md), [Lab 02](lab-02-hook-everything.md),
[Chapter 34 §5–§8](../README.md), [52-StaticAnalysis](../../52-StaticAnalysis/README.md),
[51-DynamicAnalysis](../../51-DynamicAnalysis/README.md)

---

## Objective

Perform a complete cryptographic audit of a **real application you did not write**, using a repeatable
methodology, and produce a deliverable: a findings table with evidence, argued severities, MASVS
mappings and remediation code.

The output is not "I found ECB". The output is a document a developer can act on and a client can pay
for.

## Why this matters

Labs 01 and 02 gave you targets whose answers you already knew. That is the wrong shape for real work
in one crucial way: **you did not have to decide when you were finished.**

A real audit is bounded by time, not by completeness. The skill being built here is triage — knowing
which fifteen minutes of the eight hours produce ninety percent of the findings, knowing when a
negative result is informative and when it just means you did not look properly, and knowing how to
write "we found nothing in this area, and here is what that does and does not mean".

> **Pentester's Note**
> The fastest way to lose a mobile client is a report full of unconfirmed grep hits. The second fastest
> is "hardcoded encryption key — Critical" for a key that encrypts a UI preference cache. Everything in
> this lab is oriented around not doing either.

---

## Choosing a target

Pick something you are **legally permitted to test**. In order of preference:

1. **Your own employer's app**, with written authorisation. Best learning: you can ask the developers
   afterwards why they wrote what they wrote, which is worth more than the finding.
2. **A deliberately vulnerable app.** OWASP MASTG's UnCrackable series, InsecureBankv2, DIVA,
   AndroGoat, or the Damn Vulnerable Bank projects. Real code, legal, and the answers exist so you can
   grade yourself.
3. **An open-source app from F-Droid.** Real, legal, and you can check your reading against the
   source afterwards — which is an unusually good feedback loop.

> Target only apps you own or apps published as open source. If you intend to report a genuine
> finding in a third-party app, go through that vendor's published vulnerability disclosure process,
> and read [70-VulnerabilityResearch](../../70-VulnerabilityResearch/README.md) first. See
> [SECURITY.md](../../SECURITY.md) for authorised-testing scope.

Record the target's identity precisely before you start: package name, `versionName`, `versionCode`,
APK SHA-256, the device model and Android build, and the date. Findings without a version are not
reproducible, and a report that cannot be reproduced cannot be fixed.

```bash
# host
sha256sum target.apk
aapt2 dump badging target.apk | head -5
adb shell getprop ro.build.fingerprint
```

---

## Setup

```bash
# host
mkdir -p audit/{apk,static,dynamic,data,notes} && cd audit
cp ~/target.apk apk/

apktool d apk/target.apk -o static/apktool -f
jadx -d static/jadx apk/target.apk
unzip -o apk/target.apk -d static/raw
```

Prepare the device:

```bash
# host
adb shell cmd package compile -m verify -f <pkg>    # defeat inlining, see 13-ART
adb shell am force-stop <pkg>
adb logcat -c
```

---

## The methodology

Work the phases in order. Each phase has a **time box** — respect it on the first pass and come back
if a phase produced something worth pursuing.

### Phase 1 — Reconnaissance (30 minutes)

Answer the question "what would encryption even be protecting here?" before you look for encryption.

```bash
# host
aapt2 dump badging apk/target.apk
grep -E 'permission|exported|android:name' static/apktool/AndroidManifest.xml | head -60
ls static/raw/lib/*/                              # native libraries?
ls static/raw/assets/                             # bundled payloads?
grep -rn "http" static/apktool/res/xml/           # network security config
```

Write down, in `notes/scope.md`:

- What sensitive data does this app plausibly hold? (credentials, tokens, health, financial, location)
- Where would it be stored? (SharedPreferences, SQLite, Room, files, DataStore, WebView)
- Does it use native code? A native library means the JCA may not be the whole story.
- Does it use a known crypto library? (Tink, Bouncy Castle, SQLCipher, Jetpack Security, libsodium)

```bash
# host
grep -rln "com.google.crypto.tink\|org.bouncycastle\|net.sqlcipher\|androidx.security" \
     static/jadx/sources/ | head
```

**Question 1.** Before running a single crypto rule, write your hypothesis: what do you *expect* to
find, and why? Keep it. Comparing it against the result afterwards is how calibration is built.

### Phase 2 — The fast sweep (30 minutes)

This is the highest-yield half hour in the audit. Run [§8.1](../README.md#81-the-full-sweep-in-order)
in full. The condensed version:

```bash
# host — the single most valuable grep
grep -rEn 'getInstance\("[A-Za-z0-9/]+"\)' static/jadx/sources/ | sort | uniq -c | sort -rn

# the silent-ECB variant
grep -rEn 'getInstance\("(AES|DES|DESede|Blowfish|RC2)"\)' static/jadx/sources/

# key material
grep -rn "SecretKeySpec" static/jadx/sources/
grep -rn "Ljavax/crypto/spec/SecretKeySpec;-><init>" static/apktool/smali*/

# randomness
grep -rn "new Random(\|SHA1PRNG\|setSeed" static/jadx/sources/

# IVs
grep -rn "IvParameterSpec\|GCMParameterSpec" static/jadx/sources/

# integrity
grep -rn "MessageDigest.getInstance\|Mac.getInstance" static/jadx/sources/

# resources and build config
grep -riE "key|secret|password|token" static/apktool/res/values/strings.xml
strings static/raw/classes*.dex | grep -E '^[A-Za-z0-9+/]{24,}={0,2}$' | head -40

# the good sign — is the KeyStore used at all?
grep -rn "AndroidKeyStore\|KeyGenParameterSpec" static/jadx/sources/
```

Then the automated passes:

```bash
# host
python3 ../scripts/detect-ecb.py static/apktool/ > notes/detect-ecb.txt
semgrep --config ../scripts/semgrep-crypto.yml static/jadx/sources/ --json > notes/semgrep.json
semgrep --config ../scripts/semgrep-crypto.yml static/jadx/sources/
```

**Question 2.** How many candidate findings do you have? How many are in the app's own code versus in a
bundled third-party library? Why does that distinction change what you write?

**Question 3.** Did `AndroidKeyStore` appear anywhere? If it did not, that is itself a finding. State
it as one.

### Phase 3 — Triage (45 minutes)

You now have a list. Most of it is noise. Sort every candidate into exactly one bucket:

| Bucket | Meaning | Action |
|---|---|---|
| **Confirmed, reachable** | Real code, real data, an attacker can reach it | Full write-up |
| **Confirmed, unreachable** | Real, but dead code or a debug-only path | One line, Informational |
| **Third-party library** | In a dependency, not the app's code | Note it, name the library and version |
| **False positive** | The rule fired on a shape, not a meaning | Discard, but record why |
| **Needs dynamic confirmation** | Cannot tell statically | Phase 4 |

The distinctions that matter most:

- **MD5 for a cache key is not a finding.** MD5 for integrity, signatures, password hashing or key
  derivation is. Follow the digest to its consumer before deciding.
- **A third-party library's crypto is still your client's risk**, but the finding is "the app bundles
  library X version Y which does Z", and the remediation is "upgrade", not "rewrite".
- **Dead code still ships.** It is reachable by anyone who can load the class — including a malicious
  app abusing an exported component, or the app itself after a future refactor. Report it low, not
  never.

**Question 4.** Take your three most promising candidates. For each, write down what evidence would
*disprove* it. Then go and look for that evidence. This single habit does more for report quality than
any tool.

### Phase 4 — Dynamic confirmation (90 minutes)

```bash
# host
frida -U -f <pkg> -l ../scripts/frida-jca-universal-hook.js \
      -P '{"filterPackage":"<pkg-prefix>","showStacks":true,"maxDump":256}'
```

Exercise the app deliberately, not randomly. Walk the paths where sensitive data is created:

1. First launch and any onboarding.
2. Login / authentication.
3. Storing something sensitive (add a card, save a note, enable a PIN).
4. Backgrounding and resuming the app.
5. Logout, and then log in again — this frequently reveals key derivation you missed.

Then:

```
jca.report()
jca.keys()
```

**Question 5.** Which static candidates did the runtime confirm? Which never fired? For each that never
fired, decide: unreachable, or did you not walk the right path?

Test the AndroidKeyStore claim directly if the app uses it:

```javascript
// Frida REPL
Java.perform(function () {
    var ks = Java.use('java.security.KeyStore').getInstance('AndroidKeyStore');
    ks.load(null);
    var e = ks.aliases();
    while (e.hasMoreElements()) console.log('alias: ' + e.nextElement());
});
```

**Question 6.** Does the app hold keystore aliases? For each, is the key bound to user authentication?
(Read `KeyInfo` — see [`examples/04-keystore-backed-vault.kt`](../examples/04-keystore-backed-vault.kt)
`describeKey()`.) What does the answer change about your severities?

### Phase 5 — Read the data, not the code (60 minutes)

Half of crypto testing does not involve hooking at all, and this phase produces the evidence that
survives disagreement about tooling.

```bash
# host
adb shell "su -c 'tar czf /sdcard/appdata.tgz /data/data/<pkg>'"
adb pull /sdcard/appdata.tgz && tar xzf appdata.tgz -C data/

find data/ -type f | head -50
python3 ../scripts/detect-ecb.py data/data/<pkg> > notes/data-scan.txt
python3 ../scripts/detect-ecb.py --entropy data/data/<pkg> > notes/entropy.txt
```

Apply the tells table from [§7.4](../README.md#74-reading-the-data-not-the-code):

| Observation | Conclusion |
|---|---|
| Two records share their first 16 bytes | Same IV, or no IV |
| Two records share their first 12 bytes and the mode is GCM | **Nonce reuse** |
| A 16-byte block appears twice within one record | ECB |
| Record length is always a multiple of 16 | Block mode with padding |
| Record length is `12 + n + 16` | Likely `nonce ‖ ciphertext ‖ tag` — a good sign |
| Values decode from Base64 to readable text | Not encrypted at all |
| A 32-byte high-entropy value alongside the data | Possibly the key |

Then look for the thing that actually pays:

```bash
# host — is there a PLAINTEXT copy somewhere?
grep -rl "<a string you know is sensitive>" data/ 2>/dev/null
find data/ -path "*cache*" -type f | head -30
adb logcat -d | grep -iE "token|password|key|secret" | head
ls /sdcard/Android/data/<pkg>/ 2>/dev/null
```

**Question 7.** Did you find a plaintext copy of anything the app also encrypts? This is the most
commonly missed finding in mobile testing, and it frequently outranks every crypto defect in the
report.

### Phase 6 — Impact (60 minutes)

For each confirmed finding, do the work that turns an observation into a finding.

- **Hardcoded key?** Decrypt something real and put the plaintext in the report. Redact appropriately.
- **ECB?** Show two identical ciphertext blocks, and if the record format permits it, demonstrate a
  block splice that the app accepts.
- **Fixed IV?** Encrypt the same value twice and show the identical output; if the plaintext space is
  small, build the full lookup table and show that you can read a "PIN" without the key.
- **No integrity?** Flip a bit in a stored ciphertext, restart the app, and show that it accepts the
  modified data.
- **Nonce reuse?** Show the two records sharing a nonce, and compute the XOR of the plaintexts.

```bash
# host — bit flip test, the cheapest high-value experiment in the lab
python3 - <<'PY'
p = "data/data/<pkg>/shared_prefs/prefs.xml"
s = open(p, "rb").read()
# locate the base64 value, decode, flip one byte, re-encode, write back
PY
adb push prefs.xml /data/local/tmp/
adb shell "su -c 'cp /data/local/tmp/prefs.xml /data/data/<pkg>/shared_prefs/'"
adb shell am force-stop <pkg> && adb shell am start -n <pkg>/.MainActivity
adb logcat -d | tail -40
```

**Question 8.** Which of your findings survived the impact step with a demonstration, and which
remained theoretical? Should the theoretical ones stay in the report? Argue it.

### Phase 7 — Write it (60 minutes)

Every finding gets the same seven fields. No exceptions, including for the ones you think are obvious.

```markdown
### F-nn — <mechanism, named precisely>

**Severity:** <level>
**MASVS:** <control id>
**Component:** <class.method>, `smali/…/X.smali:LINE`
**Affects:** <package> versionName <x.y.z> (versionCode <n>), SHA-256 <…>

**Description**
What the code does, in two sentences, without adjectives.

**Evidence**
The commands and their output. Reproducible by the developer on their own machine.

**Impact**
What an attacker obtains, and who the attacker has to be to obtain it.

**Severity reasoning**
Answer the three questions from §5.1 explicitly. Say what would raise or lower it.

**Remediation**
The replacement, as code. Not "use a KeyStore".

**References**
MASVS control, RFC or NIST document, chapter section.
```

**Question 9.** Write your executive summary in three sentences: what the app does well, what the most
important problem is, and what one change would most improve its posture. If you cannot name something
it does well, look harder — a report with no positives reads as adversarial and gets discounted.

**Question 10.** Which findings did you *not* report, and why? Write that down too. A section headed
"tested and found acceptable" is worth real money to a client and takes ten minutes.

---

## Hints

<details>
<summary>Hint 1 — the app detects Frida and exits</summary>

Expected on anything financial. In escalating order of effort:

1. Rename `frida-server` and run it on a non-default port.
2. Use a Frida gadget injected into a repackaged debug build.
3. Hook the detection itself — usually `File.exists` on `/data/local/tmp/frida-server`, a scan of
   `/proc/self/maps`, or a connect to port 27042.
4. Fall back to a fully static audit and say so in the report.

See [37-RootDetection](../../37-RootDetection/README.md) and
[67-BypassingProtections](../../67-BypassingProtections/README.md). Note in the report that anti-
instrumentation was present — it is context that raises the bar for an attacker and belongs in the
narrative even though it is not itself a control.
</details>

<details>
<summary>Hint 2 — jadx output is unusable</summary>

```bash
# host
jadx --show-bad-code --deobf -d static/jadx apk/target.apk
```

Then work from Smali for the classes that failed, and use the string pool as ground truth. Also check
whether the installed bytecode differs from the APK — packers rewrite DEX at install time:

```bash
# adb shell as root
APK=$(pm path <pkg> | head -1 | sed 's/package://')
oatdump --vdex-file=$(dirname $APK)/oat/arm64/base.vdex --export-dex-to=/data/local/tmp/real
```

See [13-ART](../../13-ART/README.md) and [40-Obfuscation](../../40-Obfuscation/README.md).
</details>

<details>
<summary>Hint 3 — no crypto found at all</summary>

Four possibilities, test in this order:

1. It is in native code. `grep -rn "System.loadLibrary" static/jadx/sources/`, then hook
   `libcrypto.so`, then look for a statically linked implementation with a tool that recognises AES
   S-boxes (see [57-Ghidra](../../57-Ghidra/README.md)).
2. It is in a WebView, in JavaScript, using WebCrypto. See [43-WebView](../../43-WebView/README.md).
3. There genuinely is none — and if the app stores sensitive data, *that* is the finding.
4. The app is a thin client and everything sensitive stays server-side, which is a legitimate and good
   design. Say so.
</details>

<details>
<summary>Hint 4 — how much time on each phase?</summary>

For an eight-hour first pass: recon 0.5, sweep 0.5, triage 0.75, dynamic 1.5, data 1, impact 1,
writing 1, contingency 1.75.

If you are over time, cut the impact phase for low-severity findings, never for the top two. A report
with two demonstrated findings and eight observations beats one with ten observations.
</details>

<details>
<summary>Hint 5 — assigning severity when you are unsure</summary>

Walk the three questions and write the answers down rather than reasoning in your head:

1. What is protected, and does it matter?
2. Who is the attacker, and can they reach it?
3. What does exploitation actually produce?

If question 2 requires root on the user's own device, protecting only that user's own data, the
honest answer is usually Low or Informational — and saying so explicitly earns you the credibility to
be believed on the Critical ones. A report where everything is High is a report where nothing is.
</details>

---

## Solution

<details>
<summary>Discussion — there is no single answer, but here is how to grade yourself</summary>

**On Question 1 (the hypothesis).** Compare it against the outcome. Most people over-predict exotic
findings and under-predict the boring ones. Real audits find: a hardcoded key (very common), ECB (very
common), a plaintext copy of data that is encrypted elsewhere (extremely common and usually missed),
`java.util.Random` for a token (common), and almost never a novel cryptographic weakness. Calibrating
toward the boring is what makes you fast.

**On Question 2 (app code versus library).** The distinction changes both remediation and severity.
"Library X 1.2.3 uses ECB internally for its cache" has remediation "upgrade to 1.4.0" and is largely
outside the developer's control; "your `CryptoUtil` class uses ECB" has remediation "here is the
replacement". Merging them produces a report the developer cannot act on. Also: check whether the
library code is actually *reached* — bundled dead library code is very common after R8 fails to strip
a reflective path.

**On Question 3 (no KeyStore).** An app that stores sensitive data with no AndroidKeyStore usage at all
is, by construction, storing its keys somewhere the app process can read — which means somewhere an
attacker with code execution can read. Report it as an architectural finding separate from any
individual defect, because fixing the individual defects without fixing this leaves the same exposure.

**On Question 4 (disproving).** The evidence that disproves a crypto finding is usually one of: the
code path is never called (check with a hook, not by reading); the data it protects is not sensitive
(read what actually goes in); the "key" is a public constant used for a non-security purpose (an
obfuscation XOR key, a protocol magic value); or a second layer of protection exists that you missed
(the whole file is encrypted by SQLCipher, and the inner ECB is irrelevant).

**On Question 5 (static hits that never fired).** Both explanations are common and they need different
treatment. A useful test: put a hook on the *class initialiser* or on the containing method and see
whether it is ever entered at all. If the class never loads, the code is genuinely dead in the paths
you exercised — and you should say exactly that, including which paths you exercised, rather than
claiming it is unreachable.

**On Question 7 (the plaintext copy).** This is the finding that most often outranks everything else,
and it is the one people skip because it is not "crypto". Encryption applied to one copy of the data
while a plaintext copy sits in a cache directory, a log line, a WebView database, an exported backup or
a heap dump is extremely common. Search for the plaintext before you fight the ciphertext.

**On Question 8 (theoretical findings).** They stay in, but labelled honestly, with the reason they
were not demonstrated stated explicitly — "not demonstrated because the affected code path could not be
reached without a valid merchant account" is a sentence that increases trust. What must not happen is
a theoretical finding written in the same register as a demonstrated one.

**On Question 10 (what you did not report).** A "tested and found acceptable" section costs ten minutes
and does three things: it shows scope coverage, it stops the same question being asked next year, and
it makes your positive findings credible by demonstrating you were capable of a negative one.

</details>

---

## Success criteria

- [ ] You recorded package, version, APK hash, device and date before starting
- [ ] You wrote a hypothesis before running any tool, and compared it afterwards
- [ ] You completed the full static sweep and ran both automated tools
- [ ] You triaged every candidate into exactly one bucket, including "false positive, because…"
- [ ] You confirmed findings dynamically and noted which static hits never fired
- [ ] You pulled and analysed the app's stored data independently of its code
- [ ] You searched for a plaintext copy of data the app encrypts elsewhere
- [ ] You demonstrated impact for at least your top two findings
- [ ] Every finding has all seven fields, including remediation as code
- [ ] Severities are argued against the three questions, not asserted
- [ ] You wrote a "tested and found acceptable" section
- [ ] Someone else could reproduce your top finding from your report alone
