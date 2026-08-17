# Lab 01 — Map the authentication surface

> **Difficulty:** Beginner → Intermediate
> **Time:** 90–120 minutes
> **You will need:** a host with Python 3 and the Android SDK build-tools; an Android
> device or emulator you own; optionally Frida.

---

## Objective

Take an application you have never seen and produce, in under two hours, a complete
statement of:

1. every authentication mechanism it contains,
2. **where the authentication decision is made** — on the device or on a server,
3. which credential screens are protected against screen capture,
4. and what you can say about all of the above with evidence rather than inference.

By the end you will have done something that most published methodologies get wrong: you
will have **proved that the standard `FLAG_SECURE` check cannot work**, by compiling an app
that provably sets the flag and failing to find it.

---

## Why this lab exists

An authentication review that starts by opening a decompiler produces a list of interesting
strings and no conclusions. The order that works is: inventory the surface, decide where the
decision lives, and only then read code — and the inventory step is almost entirely
mechanical.

This lab builds the inventory. [Lab 02](lab-02-session-lifecycle-and-logout.md) attacks the
session, [Lab 03](lab-03-enumeration-lockout-and-otp.md) attacks the login flow itself, and
[Lab 04](lab-04-ctf-the-account-that-would-not-close.md) is the CTF that needs all three.

> **⚠️ Authorised testing only**
> Use applications you own, applications you have written permission to assess, or
> deliberately vulnerable ones. The scanning in Part 1 reads local files and sends nothing,
> so it is safe against any APK you legally possess — but **do not act on** what you find in
> a third-party app without authorisation.

---

## Setup

```bash
# host - verify your toolchain
python3 --version                     # 3.8 or later
adb devices -l
which aapt2 apksigner dexdump         # from Android SDK build-tools
```

Add build-tools to your `PATH` if the last command found nothing:

```bash
# host - adjust the version to what you have
export PATH="$PATH:$HOME/Android/Sdk/build-tools/35.0.1"
# Windows / Git Bash:
export PATH="$PATH:/c/Users/$USER/AppData/Local/Android/Sdk/build-tools/35.0.1"
```

Collect some APKs. Anything on your own device will do:

```bash
# host
mkdir -p ~/ch47-lab && cd ~/ch47-lab
adb shell pm list packages -3 | sed 's/package://' | head -20

# pull EVERY path pm returns, not just the first - see the warning below
PKG=com.example.app
for p in $(adb shell pm path $PKG | tr -d '\r' | sed 's/package://'); do
    adb pull "$p" "./$PKG--$(basename $p)"
done
```

> **⚠️ Scan every split, or your result is meaningless**
> An app that ships its code in split APKs shows an almost empty `base.apk`.
> [38-TamperDetection](../../38-TamperDetection/README.md) measured one large application
> presenting **zero** security controls in `base.apk` for exactly this reason. The scanner in
> Part 1 prints a `THIN APK` verdict when it sees under 200 KB of DEX; treat that verdict as
> an instruction, not a comment.

---

## Part 1 — Inventory the surface (30 minutes)

### 1.1 Run the scanner

```bash
# host
python3 -B ../../scripts/auth-surface-scan.py *.apk
```

Read the family list for each app. You are looking for answers to four questions:

| Question | Families to read |
|---|---|
| How does the user sign in? | `CredentialManager`, `FIDO2`, `AccountManager`, `OTP-SMS` |
| What credential does it carry afterwards? | `Session` |
| Does it bind to the device? | `DeviceBinding` |
| Is there a client-side gate? | `LOCAL-GATE` — **leads only** |

### 1.2 Read the roll-up critically

Run it across at least ten applications and look at the cross-app summary. Here is the
result from a sweep of 17 real applications pulled from a consumer handset, reproduced from
[README §8.6](../README.md#86-a-measured-sweep-of-17-real-apks):

| Family | Apps |
|---|---:|
| `Session` | 16/17 |
| `AccountManager` type present | 13/17 |
| SMS Retriever API | 12/17 |
| `READ_SMS`/`RECEIVE_SMS` markers | 9/17 |
| FIDO2 / WebAuthn objects | 8/17 |
| Passkey ceremony | 4/17 |
| `androidx.credentials` entry point | **1/17** |
| Key attestation | 3/17 |
| OS-identifier-as-device-id | 15/17 |
| `LOCAL-GATE` weak identifiers | 15/17 |

**Task 1.** The `LOCAL-GATE` row says 15 of 17. Write one sentence explaining why that
number is **not** "15 apps have a client-side authentication gate".

<details>
<summary>Answer</summary>

Because it means "15 apps contain at least one of the strings `isLoggedIn`, `isPremium`,
`isAdmin` or `savedPassword` somewhere in up to 94 MB of DEX, **including every bundled
third-party SDK**". An advertising SDK's own `isPremium` field is not the app's
authentication gate. The number is a starting point for reading, and the scanner rates every
one of those markers WEAK for precisely this reason.

Three other chapters measured the same lesson independently:
[33-Storage](../../33-Storage/README.md) got 132 hits and 132 false positives;
[36-CertificatePinning](../../36-CertificatePinning/README.md) found 12 of 14 apps with a
pinning surface and only 4 actually pinning;
[52-StaticAnalysis](../../52-StaticAnalysis/README.md) reduced 16,836 raw hits to 168 leads
and rejected 15 of the top 17 by hand. **A sweep produces leads, not findings.**
</details>

**Task 2.** The scanner reports `OTP-SMS` at 12/17 for the permissionless API and 9/17 for
full-inbox SMS markers. Which of those two numbers is a finding, and what would you have to
check before writing it up?

<details>
<summary>Answer</summary>

The **overlap** is the finding, not either number alone: an app that demonstrably ships a
working permissionless path to the one message it needs, and reads the whole inbox anyway,
has a privacy defect that is easy to argue.

Before writing it up, check three things. First, whether the manifest actually **requests**
the permission — only 2 of the 17 did, so a DEX marker frequently comes from a bundled SDK
that the app never invokes. Second, whether the permission is requested at runtime, by
driving the app. Third, whether the app's server is sending the **correct** SMS Retriever
hash: a hash mismatch makes the permissionless API silently fail, and the usual developer
response is to add `READ_SMS`. Part 3 of this lab computes that hash.
</details>

### 1.3 Read the manifest

```bash
# host
apktool d -f -o out app.apk
grep -nE 'GET_ACCOUNTS|READ_SMS|RECEIVE_SMS|USE_BIOMETRIC|BIND_NOTIFICATION_LISTENER' out/AndroidManifest.xml
grep -nE 'allowBackup|android:debuggable|autoVerify' out/AndroidManifest.xml
grep -n -A3 'android.accounts.AccountAuthenticator' out/AndroidManifest.xml
```

**Task 3.** You find `android.permission.GET_ACCOUNTS` in a manifest whose
`android:targetSdkVersion` is 34. What does that tell you about the app?

<details>
<summary>Answer</summary>

That the manifest has accumulated years of copy-paste. **On API 26 and later, `GET_ACCOUNTS`
grants nothing** — account visibility is controlled per-package by the authenticator, through
the `visibility` table in `accounts_de.db` ([README §3.4](../README.md#34-accountmanager--what-is-actually-on-disk)).

It tells you nothing about what the app can actually see. Seven of the seventeen apps in the
sweep still declared it, and five still declared the long-removed `AUTHENTICATE_ACCOUNTS`.
Report it as hygiene, if at all. To find out what the app can genuinely see, hook
`AccountManager.getAccounts()` — Part 4.
</details>

### 1.4 Read the layouts

```bash
# host
grep -rn -E 'inputType|autofillHints|importantForAutofill' out/res/layout/ | grep -iE 'pass|pin|otp|code'
```

**Task 4.** You find this:

```xml
<EditText android:id="@+id/password"
          android:inputType="textPassword"
          android:importantForAutofill="no" />
```

Is `importantForAutofill="no"` on a password field a hardening measure or a defect?

<details>
<summary>Answer</summary>

A **defect**, and a counter-productive one. It appears in hardening checklists and it is
backwards.

It does not stop a malicious autofill service from seeing the rest of the screen, does not
stop a third-party keyboard from seeing keystrokes, and does not stop screenshots. What it
*does* stop is legitimate password managers — which pushes users towards passwords they can
type from memory, and the measurable outcome is weaker credentials.

See [README §3.5](../README.md#35-the-autofill-framework--a-third-party-is-offered-your-password-field).
The correct report says the control is counter-productive and recommends removing it.
</details>

---

## Part 2 — Prove the `FLAG_SECURE` check cannot work (30 minutes)

This is the part of the lab worth doing even if you skip everything else.

### 2.1 The claim under test

Nearly every published mobile checklist says: *decompile the APK and grep for
`FLAG_SECURE`*. You are going to test that by building an app that **provably** sets the
flag, and then looking for it.

### 2.2 Build the specimen

```bash
# host
mkdir -p ~/ch47-flagsec && cd ~/ch47-flagsec
cat > SecureProbe.java <<'EOF'
import android.app.Activity;
import android.os.Bundle;
import android.view.WindowManager;
public class SecureProbe extends Activity {
    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE,
                             WindowManager.LayoutParams.FLAG_SECURE);
    }
}
EOF

AJ=$HOME/Android/Sdk/platforms/android-35/android.jar
javac --release 8 -cp "$AJ" -d cls SecureProbe.java
d8 --release --lib "$AJ" --output . cls/SecureProbe.class
```

### 2.3 Look for the identifier

```bash
# host
grep -c FLAG_SECURE cls/SecureProbe.class ; echo "---"
python3 -B -c "
d = open('classes.dex','rb').read()
print('dex bytes            :', len(d))
print('b\"FLAG_SECURE\" in dex:', b'FLAG_SECURE' in d)
print('b\"setFlags\"    in dex:', b'setFlags' in d)
print('b\"8192\"        in dex:', b'8192' in d)
"
```

**Expected output** — this is the measured result, not a prediction:

```
dex bytes            : 912
b"FLAG_SECURE" in dex: False
b"setFlags"    in dex: True
b"8192"        in dex: False
```

**Task 5.** The class provably sets `FLAG_SECURE`. Why is the string absent from both the
`.class` file and the DEX?

<details>
<summary>Answer</summary>

Because `WindowManager.LayoutParams.FLAG_SECURE` is a `public static final int`. javac
performs **constant folding**: the compiler substitutes the literal value `0x2000` at the use
site and the *name* never reaches the class file at all. There is nothing for a later stage
to preserve.

`8192` is absent as a string for the same kind of reason — the value is encoded as a
bytecode operand, not as text.
</details>

### 2.4 See what actually survives

```bash
# host
dexdump -d classes.dex | sed -n '/onCreate/,/catches/p'
```

```
0003: invoke-virtual {v1}, LSecureProbe;.getWindow:()Landroid/view/Window;
0006: move-result-object v2
0007: const/16 v0, #int 8192 // #2000
0009: invoke-virtual {v2, v0, v0}, Landroid/view/Window;.setFlags:(II)V
```

**Task 6.** A colleague's report says *"we scanned the APK and confirmed 3 of 17 apps use
`FLAG_SECURE`"*. What is wrong with that sentence, in both directions?

<details>
<summary>Answer</summary>

Both halves are wrong.

**The three positives are false positives.** Since the identifier cannot appear in a DEX that
uses the flag, any app whose DEX contains the string contains it for an unrelated reason — a
resource name, a log message, a reflective call.

**The fourteen negatives are unknown, not negative.** Every app that genuinely sets the flag
is invisible to the check.

The detector has a **true-positive rate of zero**. This chapter's own scanner made exactly
this mistake in its first revision and reported 3/17; the correction is recorded in
[README §8.5](../README.md#85-two-false-positives-this-chapters-own-scanner-produced) and in
the scanner's header. A detector that is provably always wrong is worse than no detector,
because it produces confident answers in both directions.
</details>

### 2.5 Detect it properly

Two methods that do work.

**Bytecode**, on disassembled smali where the constant is rendered as text:

```bash
# host
grep -rn -B4 'Landroid/view/Window;->setFlags' out/smali*/ | grep -E '0x2000|8192'
```

**Runtime**, which is far more reliable and gives per-screen coverage:

```bash
# host
frida -U -f com.example.app -l ../../scripts/auth-hooks.js
```

Walk every screen. Screens that never print a `[FLAG_SECURE]` line never set the flag.

**Zero-tooling confirmation**, and the one to paste into a report:

```bash
# host - with the credential screen in the foreground
adb shell screencap -p /sdcard/probe.png
adb pull /sdcard/probe.png && adb shell rm /sdcard/probe.png
```

A black image is the flag working. A readable image on a credential screen is the evidence.

**Task 7.** Run the scanner's bytecode heuristic against a large app and note the
`const/16 vX, #int 8192` site count. On a 94 MB DEX corpus it reported **819**. What does
that number tell you about the heuristic?

<details>
<summary>Answer</summary>

That it is noisy at scale and is a *pointer*, not an answer. 8192 is a popular buffer size,
so most of those 819 sites are `new byte[8192]` and similar.

The heuristic is useful in the **negative** direction: a count of zero is decent evidence the
flag is never set from Java. A non-zero count means "disassemble around these", and for a
large app that is too many to be practical — which is why the runtime hook is the method of
choice, and why the scanner labels this output "candidates, NOT confirmations".
</details>

---

## Part 3 — The SMS Retriever hash (20 minutes)

```bash
# host
python3 -B ../../scripts/sms-retriever-hash.py app.apk
```

**Task 8.** Cross-check the certificate the script extracted against an independent tool:

```bash
# host
apksigner verify --print-certs app.apk | grep 'SHA-256 digest'
```

The two fingerprints must match. Why does this lab insist you check?

<details>
<summary>Answer</summary>

Because the script got it **wrong** in its first revision and did so silently. Its
certificate finder tested only "a SEQUENCE whose first child is a version tag or an
integer", which matched an inner sub-structure of the certificate rather than the certificate
itself. It produced a plausible 425-byte blob and a confident SHA-256 fingerprint that did
not match `apksigner` — with no error of any kind.

The fix was a stricter shape test: an X.509 `Certificate` is a SEQUENCE of exactly
`{SEQUENCE, SEQUENCE, BIT STRING}` that its three children exactly fill. It now agrees with
`apksigner` on 5 of 5 real APKs.

The transferable lesson is the one this chapter keeps repeating: **if the output looks
reasonable, check it against an independent tool before believing it.**
</details>

**Task 9.** An app's OTP autofill "never works" and the developer wants to add `READ_SMS` to
fix it. You compute the hash and find the server is appending a different one. What
happened, and what do you recommend?

<details>
<summary>Answer</summary>

Almost certainly the hash was computed from a **debug build**, which is signed with the debug
key, while production is signed with the release key — different certificate, different hash,
so the release app never matches an inbound message. The API works perfectly; the message is
wrong.

The recommendation is to compute the hash from the **release** signing certificate and fix
the server's message template. Adding `READ_SMS` would "fix" the symptom by giving the app
the user's entire message history for ever, and this is a substantial part of why 9 of 17
real applications carry full-inbox SMS markers alongside a working permissionless API.

Note the anti-clone property you get for free: a repackaged app has a different signing
certificate, so a different hash, so it never receives the code.
</details>

---

## Part 4 — Where is the decision? (30 minutes)

This is the question the whole lab exists to answer.

### 4.1 Observe

```bash
# host
frida -U -f com.example.app -l ../../scripts/auth-hooks.js
```

Log in, visit every screen, background and foreground the app, and log out. The script
observes and does not modify. Note especially:

- every `[GATE]` line — a persistent boolean being read,
- every `[CRED-WRITE]` line — where the credential is stored,
- the `[LOGOUT?]` line — and whether a network request accompanies it.

### 4.2 Force the gate

Edit `CONFIG.FORCE_GATES` to `true` in the script, or use the RPC export:

```bash
# host
frida -U -f com.example.app -l ../../scripts/auth-hooks.js
# in another terminal, with a Frida Python harness, or just edit the file
```

Relaunch and see whether you reach the post-login screens.

### 4.3 The step that decides everything

```bash
# host - replay ONE authenticated request without the app
curl -sS -i https://api.example.invalid/api/v1/dashboard -H 'User-Agent: okhttp/4.12.0'
```

**Task 10.** You forced the gate, the dashboard rendered, and it was full of empty views. The
bare `curl` returned `401`. What is the finding and what is its severity?

<details>
<summary>Answer</summary>

The finding is a **client-side navigation gate that can be bypassed**, and its severity is
**Informational**, reported as defence-in-depth.

The server re-checks. The bypass produced a screen with no data on it, because every request
the screen makes still carries a credential the server evaluates independently. Nothing was
disclosed.

Write it up honestly and briefly. Inflating it costs you credibility on the findings that
matter — and a reviewer who has read [README §5.1](../README.md#51-the-client-side-authentication-gate)
will ask what the server did.
</details>

**Task 11.** Same scenario, except the bare `curl` returned another user's dashboard. What is
the finding, what is its severity, and — the important part — **what do you title it**?

<details>
<summary>Answer</summary>

The severity is **High to Critical**, set by the data behind the endpoint.

But the title must be about the **endpoint**, not the client: something like *"`/api/v1/dashboard`
returns user data to unauthenticated requests"*, not *"client-side authentication bypass"*.

This is the single most consequential reporting decision in the chapter. If you file it as a
client-side issue, the developer will fix the client — add obfuscation, move the boolean,
maybe add root detection — and **the vulnerability will remain**, because it was never in the
client. File it against the endpoint and the right team fixes the right thing.
</details>

---

## Part 5 — The specimen (20 minutes)

Open [`../examples/01-VulnerableLogin.java`](../examples/01-VulnerableLogin.java) and find the
seven defects before reading the tags.

**Task 12.** Without looking at the `[V1]`–`[V7]` comments, list every defect you can find.
Then compare against [`../examples/README.md`](../examples/README.md).

<details>
<summary>The seven</summary>

| Tag | Defect |
|---|---|
| `[V1]` | A boolean on disk *is* the authentication decision |
| `[V2]` | The password itself is persisted for "remember me" |
| `[V3]` | Logout is local only; the server is never told |
| `[V4]` | No `FLAG_SECURE` on a credential screen — a defect of **absence**, invisible to any grep |
| `[V5]` | The password becomes an immutable `String` |
| `[V6]` | The credential is written to logcat |
| `[V7]` | The client decides whether MFA happened |

If you found five or more, you are reading code the right way. `[V4]` is the one almost
everybody misses, for the reason Part 2 proved: there is nothing there to see.
</details>

---

## Success criteria

- [ ] You can name every authentication mechanism in an app you had not seen before.
- [ ] You produced the `FLAG_SECURE` specimen and confirmed the identifier is absent from
      both the `.class` and the DEX, and that `setFlags` survives.
- [ ] You can state in one sentence why grepping an APK for `FLAG_SECURE` cannot work.
- [ ] You computed an SMS Retriever hash and **cross-checked the certificate** against
      `apksigner`.
- [ ] You determined, with evidence, whether the app's authentication decision is made on
      the device or on a server.
- [ ] You can explain why a `LOCAL-GATE` hit rate of 15/17 is a lead count and not a finding
      count.
- [ ] You know which of your findings should be titled against the endpoint rather than the
      app.

---

## What to carry into Lab 02

You now know **where** the decision is made. Lab 02 asks the next question: once a session
exists, what makes it stop existing? Bring the credential you captured and the request that
uses it — [Lab 02](lab-02-session-lifecycle-and-logout.md) starts by replaying it.
