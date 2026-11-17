# Lab 01 — Build an app that detects its own repackaging

**Difficulty:** Beginner
**Time:** 60–90 minutes
**Chapter:** [38 — Tamper Detection](../README.md) · §3.2, §3.4, §3.6, §7.8

---

## Objective

Build a real Android application that verifies its own signing certificate at runtime. Then
repackage it — strip the signature, re-sign with a different key — and **watch the check fire**.

The point is not to learn the API. The API is six lines. The point is to see, with your own eyes and
on your own device, exactly *what changes* when an APK is repackaged and exactly *what does not* —
because almost every mistake people make in this area comes from a wrong mental model of that one
thing.

By the end you will have measured:

- That the self-signature check fires on a re-sign, when **nothing else about the APK changed**.
- That the `classes.dex` CRC is **identical** in both builds — so a DEX hash check would have said
  "clean" about the repackaged one.
- That the platform refuses to install a differently-signed update, and what that error looks like.
- That `sha256(Signature.toByteArray())` equals the `keytool` fingerprint equals the `apksigner`
  certificate digest — three tools, one number.
- What `FLAG_DEBUGGABLE` looks like before and after somebody adds `android:debuggable="true"`.

---

## Why this lab exists

Chapter 38 makes a claim in §3.3 that sounds like hand-waving until you have watched it happen:

> An attacker who modifies one byte of the APK **must** re-sign it, because the v2/v3 signature covers
> the file. The app cannot answer "was I modified?" — but it can ask "who signed me?", and the
> platform answers that for it.

There is a second claim, in §3.4, that developers routinely refuse to believe:

> A DEX CRC check adds nothing over a signature check on a modern APK.

Both are testable in an hour. Do not take them on trust; you will remember the measurement and you
will forget the paragraph.

---

## Prerequisites

**Knowledge.** [10-APK-Internals](../../10-APK-Internals/README.md) §6.5 (what the signing schemes
cover), and chapter 38 §3.1–3.4. You do not need to have written Android code before.

**Tools.**

| Tool | Check |
|---|---|
| Android SDK build-tools (`aapt2`, `d8`, `zipalign`, `apksigner`) | `ls $ANDROID_HOME/build-tools/` |
| One platform `android.jar` | `ls $ANDROID_HOME/platforms/*/android.jar` |
| A JDK with `javac` and `keytool` | `javac -version && keytool -help` |
| `python3` | `python3 -VV` |
| `adb`, and a device or emulator | `adb devices -l` |

No Gradle. No Android Studio. No network.

**Device.** Any Android 5+ device or emulator. **Root is not required** — this entire lab was
written and measured on an unrooted Android 13 / API 33 phone.

> **Authorisation**
> Everything you build and attack here is software you compiled yourself, from sources in this
> repository. Install it on a device you own and uninstall it when you are done. The last section
> tells you how.

---

## Part A — Understand the app before you build it

Read [`../examples/repack-detector/IntegrityGate.java`](../examples/repack-detector/IntegrityGate.java)
before running anything. It is heavily commented and the comments are the lesson.

Seven checks:

| ID | Check | What it proves |
|---|---|---|
| D1 | Self-signature | The APK was signed by a specific key |
| D2 | `FLAG_DEBUGGABLE` | *This manifest* sets `debuggable` |
| D3 | Installer package | A string in `packages.xml` |
| D4 | DEX identity | Reports the CRC; does not judge |
| D5 | `TracerPid` | Somebody is ptracing right now |
| D6 | Frida default port | Something listens on 27042 |
| D7 | maps scan | A named artefact is mapped in |

**Question A1.** Open `IntegrityGate.java` and find the `Verdict` enum. Why are there **three**
values rather than two? Write down, in one sentence, why a check that could not run must not report
`PASS`.

**Question A2.** Find `checkDexIdentity`. It computes a CRC and then returns `UNKNOWN` with the
comment "reported, no baseline compiled in". Why can the expected CRC of `classes.dex` not be
written into the source as a constant?

<details>
<summary>Answer A2</summary>

Because adding the constant changes `classes.dex`, which changes the CRC that the constant describes.
This is the **bootstrap problem** (§3.4.1). You cannot compile a file's digest into that file.

The three real solutions all move the value somewhere the digest does not cover: a native library, an
asset injected into the zip after dexing, or the server. Each moves the problem rather than solving
it — which, if you follow the thought to its end, is the argument for remote attestation.

the **signature** check has no such problem: the signature is applied after everything
else, so the expected certificate hash can sit happily in `classes.dex`.
</details>

**Question A3.** Find `checkOwnSignature`. It branches on `si.hasMultipleSigners()`. What is the
difference between "multiple signers" and "past signing certificates", and what goes wrong if you
call the wrong accessor?

---

## Part B — Build the clean APK

```bash
# host
cd 38-TamperDetection/examples
OUTDIR=/tmp/ch38 ./build.sh
```

Read the output carefully. You should see something like:

```
SDK          /home/you/Android/Sdk
build-tools  35.0.1
android.jar  /home/you/Android/Sdk/platforms/android-35/android.jar
outdir       /tmp/ch38

generated throwaway key: /tmp/ch38/dev.ks (alias ch38dev)
generated throwaway key: /tmp/ch38/attacker.ks (alias ch38atk)
developer cert SHA-256  f4a76558cf5fc9e7ccc0eca49458275e926cc54630965c87305168383a49c24f
attacker  cert SHA-256  e9ff1d0f2f5df217eb9ac4bf150d07cb393f2f2d81ccebef448eda82e00385d7

=== building clean APK ===
built /tmp/ch38/clean.apk
    Verifies
    Verified using v1 scheme (JAR signing): true
    Verified using v2 scheme (APK Signature Scheme v2): true
    Verified using v3 scheme (APK Signature Scheme v3): true
    Verified using v3.1 scheme (APK Signature Scheme v3.1): false
    Verified using v4 scheme (APK Signature Scheme v4): false
    Number of signers: 1
```

**Your hashes will differ.** The keys are generated on your machine, on the spot. That is deliberate:
**a repository must never contain a keystore or a private key**, and this one does not. Everything
lands under `$OUTDIR`, outside the repo.

### B1 — Where did the expected hash come from?

The build injects a generated class:

```java
final class ExpectedSignature {
    static final String SHA256 = "f4a76558…";
}
```

That string came from `keytool`:

```bash
# host
keytool -list -v -keystore /tmp/ch38/dev.ks -storepass android -alias ch38dev | grep SHA256
```

```
SHA256: F4:A7:65:58:CF:5F:C9:E7:CC:C0:EC:A4:94:58:27:5E:92:6C:C5:46:30:96:5C:87:30:51:68:38:3A:49:C2:4F
```

Lowercase it and strip the colons and you have the constant. Now confirm the same value from the
other direction:

```bash
# host
apksigner verify -v --print-certs /tmp/ch38/clean.apk | grep 'certificate SHA-256'
```

```
Signer #1 certificate SHA-256 digest: f4a76558cf5fc9e7ccc0eca49458275e926cc54630965c87305168383a49c24f
```

> **Mental Model**
> `keytool`'s SHA-256 fingerprint, `apksigner`'s certificate digest, and
> `sha256(Signature.toByteArray())` are **the same number**, because all three hash the DER encoding
> of the same X.509 certificate. This equivalence is what lets a build system compute the expected
> value without ever running the app. Verify it once yourself and you will never be confused by it
> again.

**Checkpoint B.** You have `clean.apk`, and two independent tools agree on its certificate hash.

---

## Part C — Install it and read the verdicts

```bash
# host
adb install -r /tmp/ch38/clean.apk
adb logcat -c
adb shell am start -n com.pentest.ch38.integrity/.MainActivity
sleep 3
adb logcat -d -s CH38:V
```

Measured output on the reference device (i9000S, Android 13 / API 33, unrooted):

```
D1 self-signature     = PASS    | getSigningCertificateHistory -> 1 cert(s): f4a76558cf5fc9e7... | expected f4a76558cf5fc9e7...
D2 debuggable flag    = PASS    | ApplicationInfo.flags=0x30a83e44 FLAG_DEBUGGABLE=false
D3 installer package  = UNKNOWN | getInstallSourceInfo().getInstallingPackageName() -> null (sideloaded)
D4 dex identity       = UNKNOWN | classes.dex crc=5e504f9e size=15240  (reported, no baseline compiled in)
D5 TracerPid          = PASS    | TracerPid=0
D6 frida default port = PASS    | 127.0.0.1:27042 -> ConnectException
D7 maps scan          = PASS    | 2448 mappings, 0 anonymous executable, hits=[]
SUMMARY checks=7 fail=0 unknown=2 elapsed_us=82411
```

The app also shows all of this on screen; logcat is easier to copy.

**Record three numbers now.** You will compare them in Part E.

| | Your value |
|---|---|
| D1 certificate hash | |
| D2 `flags=` | |
| D4 `crc=` and `size=` | |

### C1 — Interpret the UNKNOWNs

**Question C1.** Two checks returned `UNKNOWN`, not `FAIL`. For each, say why `UNKNOWN` is the honest
answer and what would go wrong if the code returned `PASS` or `FAIL` instead.

<details>
<summary>Answer C1</summary>

**D3, installer package `null`.** You installed over `adb`, so nothing recorded an installing
package. If this returned `FAIL`, every debug build on every developer's desk would report as
tampered, and the check would be turned off within a week. If it returned `PASS`, a sideloaded
modded APK would pass a check whose entire purpose is to notice sideloading. Neither is right;
`UNKNOWN` is.

**D4, DEX identity.** There is no baseline to compare against (question A2), so there is no verdict
to give. Reporting `PASS` would be manufacturing confidence out of nothing — which is exactly the
bug §5.2 calls the most common in the area.
</details>

**Question C2.** D7 reports `2448 mappings, 0 anonymous executable`. Folklore says "an RWX page means
you are being hooked". What does this measurement suggest about that folklore, and what would you
conclude about a process reporting only 12 mappings?

<details>
<summary>Answer C2</summary>

A perfectly ordinary app process on Android 13 has ~2,450 mappings and, at least on a cold start,
zero anonymous executable ones. ART's JIT code cache produces executable anonymous mappings
legitimately on a warm process, so "an executable anonymous page exists" is not by itself evidence of
instrumentation — count them, do not judge on their existence.

A process reporting 12 mappings is a process whose `/proc` reads are being **filtered**. The absence
is the signal. That inversion — where a suspiciously *clean* answer is the anomaly — is worth
remembering.
</details>

---

## Part D — Repackage it

This is the attacker's step, and the whole experiment turns on how **minimal** it is.

```bash
# host
OUTDIR=/tmp/ch38 ./build.sh --repack
```

```
=== repackaging with the attacker key ===
    dropped v1 signature entries: ['META-INF/CH38DEV.SF', 'META-INF/CH38DEV.RSA', 'META-INF/MANIFEST.MF']
    note: the v2/v3 APK Signing Block is not a zip entry at all - it sits
          between the entries and the central directory, and rewriting the
          zip discards it automatically.
built /tmp/ch38/repacked.apk
    Signer #1 certificate DN: CN=CH38 Repackager, O=Android Security Handbook
    Signer #1 certificate SHA-256 digest: e9ff1d0f2f5df217eb9ac4bf150d07cb393f2f2d81ccebef448eda82e00385d7
```

**Read what that step did, and — more importantly — what it did not do.** It removed the three v1
signature entries, rewrote the zip (which discards the v2/v3 signing block, because that block is not
a zip entry), realigned, and re-signed with the attacker key.

**It did not touch a single class.** `classes.dex` is byte-identical. That isolation is what makes
this a clean experiment: if the check fires, it fired because of the key and nothing else.

**Question D1.** The script's note says the APK Signing Block "is not a zip entry at all". Where does
it live, and why does rewriting the zip discard it?

<details>
<summary>Answer D1</summary>

The APK Signing Block sits **between the last local file entry and the central directory** — see
[10-APK-Internals](../../10-APK-Internals/README.md) §5 for the byte layout. It is not listed in the
central directory and no zip tool knows it exists.

So when Python's `zipfile` reads the entries and writes a new archive, it copies entries and rebuilds
the central directory, and the region between them is not carried over. The v2/v3 signature
vanishes without anyone deleting it.

This is also why the v1 entries have to be removed explicitly: those *are* zip entries, and a copy
would preserve them — leaving a v1 signature that no longer verifies.
</details>

### D1 — Try to install it over the top

Do this before uninstalling. The failure is the lesson.

```bash
# host
adb install -r /tmp/ch38/repacked.apk
```

```
Failure [INSTALL_FAILED_UPDATE_INCOMPATIBLE: Existing package
com.pentest.ch38.integrity signatures do not match newer version; ignoring!]
```

**Question D2.** `repacked.apk` is correctly signed — `apksigner verify` passes on it. So why does
the install fail, and what exactly is the platform comparing?

<details>
<summary>Answer D2</summary>

This is not a signature *verification* failure. The APK verifies perfectly; it is signed by a
different key.

What failed is the **continuity** check: the package manager compares the new package's
`SigningDetails` against the ones it recorded when the original was installed — taking any rotation
lineage into account — and refuses an update from a signer that is neither the same nor a valid
successor.

This is the platform's real integrity guarantee (§1.3): not "this APK is unmodified", but "this APK
is signed by the same party as the one already here". It is also why real repackaging campaigns
either change the package name or target users who never installed the genuine app.
</details>

---

## Part E — Watch the check fire

```bash
# host
adb uninstall com.pentest.ch38.integrity
adb install -r /tmp/ch38/repacked.apk
adb logcat -c
adb shell am start -n com.pentest.ch38.integrity/.MainActivity
sleep 3
adb logcat -d -s CH38:V
```

Measured:

```
D1 self-signature     = FAIL    | getSigningCertificateHistory -> 1 cert(s): e9ff1d0f2f5df217... | expected f4a76558cf5fc9e7...
D2 debuggable flag    = PASS    | ApplicationInfo.flags=0x30a83e44 FLAG_DEBUGGABLE=false
D3 installer package  = UNKNOWN | ... -> null (sideloaded)
D4 dex identity       = UNKNOWN | classes.dex crc=5e504f9e size=15240
D5 TracerPid          = PASS    | TracerPid=0
D6 frida default port = PASS    | 127.0.0.1:27042 -> ConnectException
D7 maps scan          = PASS    | 2435 mappings, 0 anonymous executable, hits=[]
SUMMARY checks=7 fail=1 unknown=2 elapsed_us=61514
```

### E1 — The headline result

**D1 flipped from PASS to FAIL.** The certificate the app sees is now `e9ff1d0f…` — the attacker key
— where the baseline still says `f4a76558…`. The app detected its own repackaging.

it detected it **without ever looking at its own code**. It asked the platform who signed
it. That is §3.2's whole argument, now measured.

### E2 — The result people do not expect

Compare the D4 line in Part C and Part E.

```
Part C (clean)     D4  classes.dex crc=5e504f9e size=15240
Part E (repacked)  D4  classes.dex crc=5e504f9e size=15240
```

**Identical.**

**Question E1.** You have just repackaged an application, and its DEX CRC did not change. What does
that tell you about the value of a "DEX integrity check" on a v2+ APK, and in which situations would
such a check still be worth implementing?

<details>
<summary>Answer E1</summary>

Against a repackager on a v2+ APK, a DEX hash check adds **nothing** the signature check did not
already give you. Any change to `classes.dex` invalidates the v2 signature, forces a re-sign, and
changes the certificate — so D1 fires anyway. And when the attacker changes *nothing* but the key, as
here, the DEX check does not fire at all while D1 does.

It is still worth having in four cases:

1. **v1-only APKs**, where the zip structure is not covered and entries can be added or replaced
   without invalidating anything.
2. **Dynamically loaded code** — a downloaded DEX, a plugin JAR, anything the APK signature never
   covered. This is the highest-value version of the check and almost nobody implements it.
3. **Assets that carry policy** — a rules file or a pinning set, where a distinct alarm is useful.
4. When you deliberately want a second, differently-shaped alarm. Just do not count it twice in a
   risk assessment.
</details>

**Question E2.** The maps count changed from 2448 to 2435 between runs of the *same* app. Should a
tamper check treat a change in mapping count as a signal?

<details>
<summary>Answer E2</summary>

No — not an exact count, anyway. The number varies run to run with what the runtime happened to load,
which fonts got mapped, what the JIT did. A check keyed to an exact count is a false-positive
machine.

What *is* usable is an order-of-magnitude floor: a real app process has thousands of mappings, so a
process reporting a dozen has had its `/proc` reads filtered.
`examples/LayeredTamperDetector.verifyMapsClean()` uses `n > 50` for exactly this reason, and the
choice of a very loose bound rather than a tight one is the point.
</details>

---

## Part F — The debuggable variant

Now produce the *other* classic repackaging artefact: an attacker who wants to attach a debugger and
adds the flag to the manifest.

```bash
# host — work on a COPY, so the repository stays clean
cp -r 38-TamperDetection/examples /tmp/ch38-dbg
```

Edit `/tmp/ch38-dbg/repack-detector/AndroidManifest.xml` and change:

```xml
    <application
        android:label="CH38 Integrity"
        android:allowBackup="false">
```

to:

```xml
    <application
        android:label="CH38 Integrity"
        android:allowBackup="false"
        android:debuggable="true">
```

Then:

```bash
# host
cd /tmp/ch38-dbg
OUTDIR=/tmp/ch38dbg ./build.sh --repack
adb uninstall com.pentest.ch38.integrity
adb install -r /tmp/ch38dbg/repacked.apk
adb logcat -c
adb shell am start -n com.pentest.ch38.integrity/.MainActivity
sleep 3
adb logcat -d -s CH38:V
```

Measured:

```
D1 self-signature  = FAIL | ... dd21fe276edfbfe0... | expected 31db7d756bcdf749...
D2 debuggable flag = FAIL | ApplicationInfo.flags=0x30a83e46 FLAG_DEBUGGABLE=true
SUMMARY checks=7 fail=2 unknown=2 elapsed_us=163354
```

`0x30a83e44` became `0x30a83e46`. Bit 1 — `FLAG_DEBUGGABLE = 1<<1` — is set, exactly as
`ApplicationInfo.java` documents.

### F1 — What the flag actually gives an attacker

With this build installed:

```bash
# host — this only works on a debuggable package
adb shell "run-as com.pentest.ch38.integrity ls -la /data/data/com.pentest.ch38.integrity"
```

> **Pentester's Note**
> `run-as` succeeding is a **one-command test** for `FLAG_DEBUGGABLE` on any app. If it works on a
> production app you are assessing, that is worth reporting on its own, independent of any tamper
> question: it means the app's private data directory is readable over `adb` and a JDWP debugger can
> attach.

### F2 — And now the measurement that surprises people

The app is debuggable, so attach a real Java debugger and see what `TracerPid` says.

```bash
# host
PID=$(adb shell pidof com.pentest.ch38.integrity | tr -d '\r')
adb forward tcp:8700 jdwp:$PID
```

In one terminal, attach `jdb` and leave it connected:

```bash
# host
jdb -connect com.sun.jdi.SocketAttach:hostname=localhost,port=8700
```

> **On Windows**, `jdb` defaults to the shared-memory transport and fails with
> `shmemBase_attach failed`. You must pass `-connect com.sun.jdi.SocketAttach:...` explicitly, as
> above.

At the `jdb` prompt, type `threads`. You should see the app's threads, which proves the debugger is
genuinely attached:

```
> Group system:
  (java.lang.Thread)0x595d  Signal Catcher                     cond. waiting
  (java.lang.Thread)0x595e  ADB-JDWP Connection Control Thread cond. waiting
  ...
```

In a *second* terminal, while `jdb` is still connected:

```bash
# host
adb shell "run-as com.pentest.ch38.integrity cat /proc/$PID/status | grep TracerPid"
```

Measured:

```
TracerPid:      0
```

**Question F1.** A debugger is fully attached and enumerating threads, and `TracerPid` is `0`.
Explain why, and name the check that *would* have caught this.

<details>
<summary>Answer F1</summary>

JDWP is a **protocol ART speaks over a socket**, not a `ptrace` attach. The kernel's tracer field
records ptrace relationships, and there is no ptrace relationship here, so the field is untouched.

The check that catches JDWP is `android.os.Debug.isDebuggerConnected()`, which asks the **runtime**
rather than the kernel.

They are different questions with different answers, and an app that ships only one of them has a
hole shaped exactly like the other. A great deal of published material gets this wrong, which is why
this chapter measured it rather than repeating it.

What `TracerPid` *does* catch: `gdb`, `lldb`, `strace`, and `frida-server` when it injects by ptrace.
</details>

Detach `jdb` with `exit`, and clean up the forward:

```bash
# host
adb forward --remove tcp:8700
```

---

## Part G — Break your own check

Now play the attacker against a check you fully understand. This is understanding, not a bypass
playbook — chapter 67 owns methodology.

### G1 — Statically

```bash
# host
apktool d -f -o /tmp/ch38dec /tmp/ch38/clean.apk
grep -rn "0x8000000" /tmp/ch38dec/smali*/
```

You will find the `IntegrityGate` smali. Locate `checkOwnSignature` and the comparison that ends it.

**Exercise G1.** Without changing anything else, make `constantTimeEquals` always return `true`:

```smali
.method static constantTimeEquals(Ljava/lang/String;Ljava/lang/String;)Z
    .locals 1
    const/4 v0, 0x1
    return v0
.end method
```

Rebuild, re-sign with the **attacker** key, install, and run.

**Question G1.** D1 now reports PASS on a build signed by the attacker. How many bytes of change did
that take, and — the interesting part — what did you have to do to the APK to install your
patched version?

<details>
<summary>Answer G1</summary>

Three Smali instructions, which is a handful of bytes in the DEX.

And to install it you had to **re-sign** — which is the thing D1 detects. You defeated the check by
patching the code, and patching the code required doing precisely what the check exists to notice.
The only reason it worked is that you also disabled the noticing.

That is the "**patch both or neither**" rule ([37-RootDetection](../../37-RootDetection/README.md)) in
its purest form: here, the thing you must patch and the thing that would detect your patching are
the same method. On a real app they are usually different methods and you must find them all.
</details>

### G2 — At runtime, if you have a rooted device

If you have root and `frida-server`:

```bash
# host
frida -U -f com.pentest.ch38.integrity -l ../scripts/which-check-fired.js
```

Read which check fires and what it saw.on the **clean** build with Frida attached, D1
still passes — because Frida changed nothing on disk.

**Question G2.** You attach Frida to the clean, correctly-signed build. Which checks fire and which
do not? What does that tell you about the difference between threat T‑A and threat T‑B?

<details>
<summary>Answer G2</summary>

D1 (signature) and D4 (DEX) **pass**, because the file on disk is exactly the one the developer
signed. Frida modifies the process, not the file.

D5, D6 and D7 may fire, depending on how frida-server is running: D6 if it is on the default port,
D7 if the agent's mapping is named, D5 if it injected by ptrace.

That split *is* the T‑A/T‑B distinction from §1.2. A signature check catches repackaging perfectly and
instrumentation not at all; the anti-analysis checks catch instrumentation and repackaging not at all.
An app that ships only one family has covered half the problem and usually does not know which half.
</details>

> **Note.** This lab's reference measurements were taken on an **unrooted** device, so part G2 was
> not executed. If you run it, record what you see — and if it differs from what is written here, the
> device wins.

---

## Success criteria

You have completed this lab when you can:

- [ ] Build `clean.apk` and state where its expected certificate hash came from.
- [ ] Show the same certificate hash from `keytool`, from `apksigner`, and from the app's own log.
- [ ] Produce `repacked.apk` and explain what the repackaging step changed and what it left alone.
- [ ] Show `INSTALL_FAILED_UPDATE_INCOMPATIBLE` and explain that it is a *continuity* failure, not a
      verification failure.
- [ ] Show D1 flipping PASS → FAIL, with the two certificate hashes side by side.
- [ ] Show that the `classes.dex` CRC is **identical** across both builds, and explain what that
      means for DEX integrity checks on modern APKs.
- [ ] Show `FLAG_DEBUGGABLE` flipping `0x…44` → `0x…46` and explain what that flag grants an attacker.
- [ ] Demonstrate that a JDWP debugger leaves `TracerPid` at 0, and name the check that catches it.
- [ ] Patch the check in Smali and explain why doing so required re-signing.

---

## Clean up — leave the device as you found it

```bash
# host
adb uninstall com.pentest.ch38.integrity
adb forward --remove tcp:8700 2>/dev/null
adb shell pm list packages | grep ch38     # should print nothing
rm -rf /tmp/ch38 /tmp/ch38dbg /tmp/ch38-dbg /tmp/ch38dec
```

The `rm` matters for a reason beyond tidiness: `$OUTDIR` contains **two private keys**. They are
throwaway keys for a lab app and are worth nothing, but building the habit of not leaving keystores
lying about is worth something.

Confirm the repository is still clean:

```bash
# host
cd 38-TamperDetection && find . -name "*.apk" -o -name "*.ks" -o -name "*.dex" -o -name "*.class"
```

That must print nothing. The build script writes everything out of tree precisely so this is true.

---

## What to take away

1. **Self-signature verification works because re-signing is forced.** The app cannot answer "was I
   modified?" It can answer "who signed me?", and the platform answers that for it, from a
   verification it performed before your process existed.
2. **The DEX CRC did not change.** You measured that. A DEX integrity check on a v2+ APK adds nothing
   against a repackager — it is worth having for dynamically loaded code, and largely not otherwise.
3. **`TracerPid` does not see a Java debugger.** You measured that too, with `jdb` attached and
   listing threads.
4. **Patching the check required re-signing, which is what the check detects.** Patch both or
   neither.
5. **The check is three Smali instructions away from useless.** Which is not an argument against
   implementing it — it is an argument for never letting a security decision depend on it. That is
   §5.3, and lab 04 makes it concrete.

---

## Next

- [Lab 02 — Anti-analysis in `JNI_OnLoad` and before it](lab-02-jni-onload-anti-analysis.md) — the
  native tiers, and proving the `.init_array` ordering yourself.
- [Lab 03 — Map before you bypass](lab-03-map-the-detector.md) — find these checks in apps you did
  not write.
- [Lab 04 — CTF](lab-04-ctf-silent-integrity.md) — an app that gives you no error message at all.
