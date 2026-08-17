# Lab 01 — Obfuscation Triage

**Difficulty:** Beginner
**Time:** 90–120 minutes
**Prerequisites:** [Chapter 40 §3.7.2](../README.md#372-how-to-recognise-a-packed-apk) and
[§6.1](../README.md#61-the-deobfuscation-methodology), [10-APK-Internals](../../10-APK-Internals/README.md),
[12-DEX-Internals](../../12-DEX-Internals/README.md), `jadx`, `apktool`, `aapt2`, `python3`

---

## Objective

Build five APKs from the same source, each with a different protection level, then classify all five
**using static triage only** — no decompiler reading, no running the app. Answer the six Phase 1
questions for each, in under five minutes per APK, and produce the triage table that decides your
approach.

Finish by running [`../scripts/apk-obfuscation-triage.sh`](../scripts/apk-obfuscation-triage.sh)
against all five and comparing its verdicts with your own.

## Why this matters

The two most expensive mistakes in this whole chapter are made in the first ten minutes, before any
real work starts:

1. **Reading a stub.** Spending an hour puzzling over forty meaningless classes in `jadx` because
   nobody checked whether the app was packed. The real code was never in the file you were reading.
2. **Grinding control flow before recovering strings.** Deflattening a forty-case method to discover
   it formats a date, when the string dump would have told you in two seconds that the interesting
   method is a different one entirely.

Both are prevented by twenty minutes of triage. Section 6.1 of the chapter puts it plainly: the Phase
1 table determines everything downstream, and it is also the first table in your report — because a
client asking "is our app protected?" is asking for exactly these six rows.

The secondary lesson is calibration. After this lab you will know what a *renamed* APK looks like
versus an *encrypted-strings* APK versus a *packed* one, from the file listing alone, which is a skill
that never stops paying.

---

## Setup

### The common source

One trivial app, built five ways. Package `com.obflab.target`.

**`ApiClient.java`** — deliberately full of the things triage looks for.

```java
package com.obflab.target;

import android.util.Log;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;

public class ApiClient {

    private static final String TAG = "OBFLAB";
    private static final String BASE_URL = "https://api.obflab.example.com/v2";
    private static final String API_KEY = "sk_live_EXAMPLE_NOT_A_REAL_KEY_ch40";
    private static final String LOGIN_PATH = "/auth/login";
    private static final String TRANSFER_PATH = "/payments/transfer";

    public String login(String user, String pass) {
        return post(BASE_URL + LOGIN_PATH, "{\"u\":\"" + user + "\",\"p\":\"" + pass + "\"}");
    }

    public String transfer(String to, long amountMinor) {
        return post(BASE_URL + TRANSFER_PATH,
                    "{\"to\":\"" + to + "\",\"amount\":" + amountMinor + "}");
    }

    private String post(String urlStr, String body) {
        HttpURLConnection c = null;
        try {
            c = (HttpURLConnection) new URL(urlStr).openConnection();
            c.setRequestMethod("POST");
            c.setRequestProperty("Authorization", "Bearer " + API_KEY);
            c.setRequestProperty("Content-Type", "application/json");
            c.setDoOutput(true);
            c.getOutputStream().write(body.getBytes("UTF-8"));

            BufferedReader r = new BufferedReader(new InputStreamReader(c.getInputStream()));
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = r.readLine()) != null) sb.append(line);
            r.close();
            return sb.toString();
        } catch (Exception e) {
            Log.w(TAG, "request failed", e);
            return null;
        } finally {
            if (c != null) c.disconnect();
        }
    }
}
```

**`Classifier.java`** — the method you will flatten in variant D and in
[lab 03](lab-03-deflatten.md).

```java
package com.obflab.target;

public class Classifier {

    public String classify(int score) {
        if (score < 0) {
            return "invalid";
        }
        String label;
        if (score < 50) {
            label = "fail";
        } else if (score < 80) {
            label = "pass";
        } else {
            label = "distinction";
        }
        return label.toUpperCase();
    }
}
```

**`MainActivity.java`**

```java
package com.obflab.target;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;

public class MainActivity extends Activity {

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        TextView tv = new TextView(this);
        tv.setPadding(32, 96, 32, 32);
        setContentView(tv);

        Classifier c = new Classifier();
        String s = c.classify(72);
        Log.i("OBFLAB", "classified: " + s);
        tv.setText("ready: " + s);

        // Never actually called; present so the strings are reachable code.
        if (System.currentTimeMillis() == 1L) {
            new ApiClient().login("u", "p");
            new ApiClient().transfer("acct", 100L);
        }
    }
}
```

### The five variants

Build each into its own APK. Name them `A.apk` … `E.apk` and then **shuffle the names** — or better,
have someone else build them — so you classify blind.

| Variant | Protection | How |
|---|---|---|
| **A** | none | `minifyEnabled false` |
| **B** | R8 renaming only | `minifyEnabled true` with the default rules |
| **C** | renaming + string encryption | B plus the XOR transform below |
| **D** | renaming + strings + flattening | C plus a hand-flattened `Classifier` |
| **E** | packed | A packed with the stub from [`../examples/PackerStub.java`](../examples/PackerStub.java) and [`../examples/pack.py`](../examples/pack.py) |

**Variant B — `app/build.gradle`:**

```groovy
buildTypes {
    release {
        minifyEnabled true
        proguardFiles getDefaultProguardFile('proguard-android-optimize.txt'), 'proguard-rules.pro'
        signingConfig signingConfigs.debug
    }
}
```

**Variant C — string encryption.** Replace the constants in `ApiClient` with calls to a decryptor.
The full worked implementation, with the generator that produces the ciphertext arrays, is
[`../examples/StringEncryption.java`](../examples/StringEncryption.java) and [`../examples/gen-string-table.py`](../examples/gen-string-table.py). The minimum for this lab:

```java
package com.obflab.target;

/** Deliberately the classic shape: XOR with a fixed key, index-addressed. */
public final class S {

    private static final byte[][] D = {
        // generated by ../examples/gen-string-table.py
        // index 0: "https://api.obflab.example.com/v2"
        // index 1: "sk_live_EXAMPLE_NOT_A_REAL_KEY_ch40"
        // index 2: "/auth/login"
        // index 3: "/payments/transfer"
        // index 4: "Authorization"
        // index 5: "Bearer "
        // index 6: "application/json"
    };

    public static String a(int i) {
        byte[] e = D[i];
        char[] out = new char[e.length];
        for (int j = 0; j < e.length; j++) {
            out[j] = (char) (e[j] ^ 0x5A);
        }
        return new String(out);
    }

    private S() { }
}
```

Then `BASE_URL` becomes `S.a(0)`, `API_KEY` becomes `S.a(1)`, and so on. Note that the constants must
become *method calls at the point of use*, not `static final` fields — a `static final String`
initialised once would leave a single decryption at class-init time and only one call site, which is
much easier than the real thing.

**Variant D — flattening.** Replace `Classifier.classify` with the flattened form from
[§3.3.2](../README.md#332-control-flow-flattening--the-important-one) of the chapter. Copy it
verbatim; you will reverse it in [lab 03](lab-03-deflatten.md).

**Variant E — packing.** Build variant A, then run it through the minimal packer in
[`../examples/PackerStub.java`](../examples/PackerStub.java) and [`../examples/pack.py`](../examples/pack.py). You will unpack it in [lab 04](lab-04-unpack.md).

---

## Steps

### Step 1 — Phase 0: acquire and verify

For each APK:

```bash
# host
sha256sum *.apk
apksigner verify --print-certs A.apk
unzip -l A.apk | head -30
```

**Q1.** Why does the methodology insist you pull the APK from a *device* with `adb shell pm path`
rather than analysing a file someone sent you?

**Q2.** `pm path` prints three lines for a real target. What are they, and what is the classic
embarrassing mistake that follows from ignoring two of them?

### Step 2 — Question 1: is it packed?

Do this **first**, for every APK, before opening anything. Three indicators; any two together are
conclusive.

```bash
# host — indicator 1: DEX size and class count
for f in *.apk; do
  echo "== $f"
  unzip -l "$f" | grep -E 'classes.*\.dex'
done

# host — indicator 2: class_defs_size, at offset 0x60 of the DEX header
for f in *.apk; do
  unzip -p "$f" classes.dex > /tmp/c.dex 2>/dev/null || continue
  echo -n "$f: "
  python3 -c "
import struct,sys
h=open('/tmp/c.dex','rb').read(0x70)
print('classes =', struct.unpack_from('<I',h,0x60)[0],
      ' strings =', struct.unpack_from('<I',h,0x38)[0])
"
done

# host — indicator 3: large high-entropy assets
for f in *.apk; do
  echo "== $f"
  unzip -l "$f" | awk '$1 > 200000 && $4 !~ /\.dex$/ {print "   ", $1, $4}'
done

# host — indicator 4: the application class
for f in *.apk; do
  echo "== $f"
  aapt2 dump xmltree "$f" --file AndroidManifest.xml | grep -A4 'E: application' | head -8
done
```

**Q3.** Which APK is packed? State the three pieces of evidence, and say which one alone would have
been enough.

**Q4.** Open the packed APK in `jadx`. How many classes do you see, and what is the name of the
`Application` class? Where did the *original* `Application` class name go, and why did the packer have
to keep it somewhere?

**Q5.** You have a 40 MB APK with a 90 KB `classes.dex`. Before you check anything else, what is your
working hypothesis, and what is the one alternative explanation you must rule out?

### Step 3 — Question 2: are names obfuscated, and how completely?

```bash
# host
jadx -d out_B --no-res B.apk >/dev/null 2>&1
find out_B/sources -name '*.java' | head -30
```

Then measure it rather than eyeballing it:

```bash
# host — class-name length distribution
for f in *.apk; do
  echo -n "$f: "
  unzip -p "$f" classes.dex 2>/dev/null | python3 -c "
import re,sys,collections
d=sys.stdin.buffer.read()
names={m.group(1).decode('ascii','replace') for m in re.finditer(rb'L([A-Za-z0-9_\$/]{1,200});',d)}
SKIP=('java/','javax/','android/','androidx/','kotlin/','dalvik/','org/')
app=[n for n in names if not n.startswith(SKIP)] or list(names)
simple=[n.split('/')[-1] for n in app]
short=sum(1 for s in simple if len(s)<=2)
print(f'{len(simple)} classes, {100*short//max(1,len(simple))}% with <=2 char names')
"
done
```

**Q6.** What percentage of short names does an unobfuscated app show? What does variant B show?

**Q7.** In variant B's `jadx` output, are there classes that kept their real names? Which ones, and
what does that tell you about the app's `-keep` rules? Why is that a **finding** rather than a
curiosity?

**Q8.** Renaming is present in B, C and D. Does its presence change your *approach* at all? Justify
your answer using the survivors table from [§3.1](../README.md#31-identifier-renaming).

### Step 4 — Question 3: are strings encrypted?

The loudest single signal:

```bash
# host
for f in *.apk; do
  n=$(unzip -p "$f" classes.dex 2>/dev/null | strings -n 6 | grep -c 'https\?://')
  echo "$f: $n URL(s) in the string pool"
done

# host — what else the pool contains
unzip -p C.apk classes.dex | strings -n 6 | grep -E 'obflab|sk_live|/auth/|/payments/' | head
unzip -p B.apk classes.dex | strings -n 6 | grep -E 'obflab|sk_live|/auth/|/payments/' | head
```

**Q9.** Which variants have zero URLs? Why is "zero URLs in a networked app" a much stronger signal
than "few readable strings"?

**Q10.** In variant C, find the decryptor **statically**. What Smali instruction is the giveaway, and
why does it have essentially no false-positive rate?

```bash
# host
apktool d -f -o C_out C.apk >/dev/null
grep -rn 'xor-int' C_out/smali*/ | head
```

**Q11.** Variant B contains the API key `sk_live_...` in plain text. Variant C does not. Write the
finding for each, in one sentence, as it would appear in a report. Are they the same finding?

### Step 5 — Question 4: native code

```bash
# host
for f in *.apk; do
  echo "== $f"
  unzip -l "$f" | grep -E '\.so$' || echo "   none"
done
```

For the packed variant, if it ships a `.so`:

```bash
# host
unzip -o E.apk 'lib/*' -d E_libs >/dev/null
for so in $(find E_libs -name '*.so'); do
  echo "== $so"
  readelf --dyn-syms "$so" | awk '{print $8}' | grep -c '^Java_'
  readelf --dyn-syms "$so" | grep -c JNI_OnLoad
  readelf -S "$so" | grep -c '\.init_array'
  readelf -d "$so" | grep NEEDED
done
```

**Q12.** A library with very few `Java_*` exports, a `JNI_OnLoad`, and a populated `.init_array` — what
does that combination tell you, and what does it specifically tell you about *when* you must attach?

**Q13.** `NEEDED libcrypto.so` on an app's own library. What hypothesis does that raise, and which
other chapter does it send you to?

### Step 6 — Question 5: anti-analysis

```bash
# host
for f in *.apk; do
  echo -n "$f: "
  unzip -p "$f" classes.dex 2>/dev/null | strings -a \
    | grep -ciE 'ptrace|TracerPid|frida|xposed|magisk|goldfish|isDebuggerConnected'
done
```

**Q14.** Suppose an app shows zero anti-analysis markers *and* zero URLs. Why is the first result
almost meaningless, and what must you check before concluding "no anti-analysis"?

### Step 7 — Question 6: do the tools work?

```bash
# host
for f in *.apk; do
  echo "== $f"
  apktool d -f -o /tmp/at_$f "$f" >/tmp/at_$f.log 2>&1 && echo "   apktool OK" || echo "   apktool FAILED"
  jadx -d /tmp/jx_$f --no-res "$f" >/tmp/jx_$f.log 2>&1 && echo "   jadx OK" || echo "   jadx FAILED"
done
```

**Q15.** If an APK installs and runs on a device but `apktool` refuses to decode it, what have you
learned? Name the underlying asymmetry that makes this possible, and say what you do next.

### Step 8 — Produce the table, then check yourself

Fill this in for all five, from your own work:

| APK | Packed? | Names | Strings | Native | Anti-analysis | Tools | Approach |
|---|---|---|---|---|---|---|---|

Then run the script:

```bash
# host
for f in *.apk; do ../scripts/apk-obfuscation-triage.sh "$f" --deep; done
```

**Q16.** Where did the script and your manual answers disagree? For each disagreement, decide which is
right and why. Did the script produce any false positive, and can you explain the mechanism that
caused it?

**Q17.** For each APK, write the single next command you would run. Not a plan — one command.

---

## Hints

<details>
<summary>Hint — Q3, reading a DEX header offset by hand</summary>

The header is 0x70 bytes and every field is at a fixed offset. `class_defs_size` is at 0x60,
`string_ids_size` at 0x38, `file_size` at 0x20, `header_size` at 0x24 (always 0x70), `endian_tag` at
0x28 (always 0x12345678). See [12-DEX-Internals](../../12-DEX-Internals/README.md).

A real app has thousands of classes. Under about fifty means you are looking at a stub.
</details>

<details>
<summary>Hint — Q10, the XOR giveaway</summary>

Look for `xor-int/lit8` inside a loop, in a method whose return type is `Ljava/lang/String;`. Also
worth grepping: `xor-int/2addr` (variable key) and `rem-int` (position-dependent key).

The reason the false-positive rate is so low is that ordinary application code almost never XORs bytes
in a loop and builds a `String` out of the result. Hashing does not; parsing does not; compression
does not (it uses a library).
</details>

<details>
<summary>Hint — Q14, why zero markers means little</summary>

Where would the string `"frida-server"` live in an app that encrypts its strings?
</details>

---

## Solution

<details>
<summary>Answers Q1–Q5 — Phase 0 and packing</summary>

**Q1.** Because you must be certain you are analysing the artefact that users actually receive. A file
emailed to you may be a debug build, a previous version, an unprotected internal build, or the wrong
flavour entirely. The device holds the ground truth, and the SHA-256 you record from it is what makes
your findings reproducible six months later when someone disputes them.

**Q2.** `base.apk` plus split APKs (App Bundle delivery — `split_config.arm64_v8a.apk`,
`split_config.xxhdpi.apk`, feature splits). Code can live in feature splits. Analysing only `base.apk`
and reporting "the feature is not present" is the classic embarrassing mistake, and it is embarrassing
precisely because it is so easy to avoid.

**Q3.** Variant E. Evidence: (1) `classes.dex` is tiny — a few tens of KB where A/B/C/D are hundreds;
(2) `class_defs_size` reads a couple of dozen against several hundred; (3) there is a large asset in
`assets/` that is not present in the other four, and its entropy is near 8.0; (4) the manifest's
`<application android:name>` points at a class that is not part of the app's own package structure.

Any *one* of (1)+(2) — they are the same evidence measured two ways — or (4) alone would have been
enough. In combination they are conclusive.

**Q4.** A handful of classes, none of which are the app's. The `Application` class is the packer's
stub. The original name is stashed in a `<meta-data>` element, because the stub must eventually
instantiate the real `Application` and forward the lifecycle to it — the packer cannot simply discard
that name, and that necessity is what makes it recoverable.

**Q5.** Hypothesis: packed. The one alternative to rule out is **multidex with the real code in
`classes2.dex`** and other files — check `unzip -l` for `classes2.dex`, `classes3.dex`. A second
alternative worth a glance is an app that is genuinely tiny and dominated by media assets, which the
manifest and asset entropy will settle in seconds.
</details>

<details>
<summary>Answers Q6–Q8 — renaming</summary>

**Q6.** Variant A shows a low single-digit percentage of short names (the ones that occur naturally
are inner classes and generated code). Variant B typically shows 60–90% depending on how much of the
app is library code.

**Q7.** Yes: `MainActivity` keeps its name, because it is referenced from `AndroidManifest.xml` and R8
must not rename anything the manifest names. Any class with a `-keep` rule, anything reflected upon,
anything annotated for a serialisation library, and `Parcelable.CREATOR` fields likewise survive.

Why it is a finding: **the classes that kept their names are the ones the developer cared about
enough to write a rule for.** A `-keep class com.target.crypto.**` in the rules file is a signed
confession about where to look. More seriously, over-broad keep rules are extremely common and mean
the obfuscation the client is paying for is not applied to the code that matters. That belongs in the
report as a coverage finding, with the specific classes named.

**Q8.** Barely. Renaming is a nuisance, not an obstacle, because of the survivors table: framework
class and method names, all string constants, manifest component names, resource names, JNI symbol
names, reflection target strings, and annotation/Kotlin metadata all pass through unchanged. Those are
enough to navigate by. The approach changes when *strings* go, not when *names* go — which is exactly
why the methodology puts string recovery at Phase 4 and treats renaming as background noise.
</details>

<details>
<summary>Answers Q9–Q11 — strings</summary>

**Q9.** C, D and E have zero. (E has zero because the string pool you are looking at belongs to the
stub — a different reason, and noticing that difference is the point of doing Q3 first.)

"Zero URLs" is stronger than "few readable strings" because it is a *categorical* absence in a
category that must be present. Every networked Android app contains endpoint strings somewhere, and
they cannot be optimised away because they are needed at runtime. Their complete absence from the DEX
string pool means they are stored in some other form, which means encryption. "Few readable strings"
by contrast has innocent explanations: a small app, a heavily resource-driven app, a library-dominated
app.

**Q10.** `xor-int/lit8` in a loop, in a method returning `Ljava/lang/String;`. Near-zero false-positive
rate because normal application code does not XOR a byte array element-by-element and construct a
String from the result. See the Smali listing in
[§3.2](../README.md#variant-a--xor-with-a-fixed-key).

**Q11.** They are the **same finding**, and writing them differently is the mistake this question
exists to prevent.

> **B:** The application embeds a live API credential (`sk_live_…`) as a string constant in
> `classes.dex`. Any party in possession of the binary can recover it with a single `strings`
> invocation. The credential must be treated as public and the design changed accordingly.

> **C:** The application embeds a live API credential, obfuscated by a fixed-key XOR routine in
> `com.obflab.target.S.a(int)`. Recovery required approximately two minutes using standard
> instrumentation, demonstrated below. Obfuscation delays but does not prevent recovery; the
> credential must be treated as public and the design changed accordingly.

Same conclusion, same remediation, different recovery cost. "The secret is obfuscated" is never an
acceptable remediation for a hardcoded secret — and the demonstration in the second version is what
ends the argument, because an assertion invites debate and a recovered key does not.
</details>

<details>
<summary>Answers Q12–Q15 — native, anti-analysis, tools</summary>

**Q12.** Few `Java_*` exports plus `JNI_OnLoad` means the native methods are registered dynamically
with `RegisterNatives` rather than resolved by name — so there are no symbol names for you to anchor
on. A populated `.init_array` means code runs at `dlopen` time, **before** `JNI_OnLoad` and before any
Java code observes the library.

What it tells you about attaching: you must **spawn-gate**, not attach. `.init_array` executes during
`System.loadLibrary` inside `attachBaseContext`, milliseconds into the process's life. `frida -U -n
pkg` is far too late, and even `frida -f pkg` without `--pause` can lose the race. This one detail
explains most "my Frida script never fired" confusion against protected apps
([§3.7.1](../README.md#371-how-a-packer-works-mechanically)).

**Q13.** The app ships its own TLS stack rather than using the platform's. Hypothesis: native
certificate pinning, which your Java-layer pinning bypass will not touch. Go to
[36-CertificatePinning](../../36-CertificatePinning/README.md). It also raises the possibility of
native crypto for the string decryption, which changes your Phase 4 approach.

**Q14.** Because if strings are encrypted, the markers are encrypted too. A grep for `frida` in a DEX
whose string pool is ciphertext returns zero regardless of what the app checks for.

Cross-read against your Question 3 answer. If strings are encrypted, "no anti-analysis markers" means
nothing at all, and the real test is behavioural: run the app under Frida and see whether it dies. If
strings are in the clear and the markers are absent, that is genuine evidence.

**Q15.** You have learned that the APK contains deliberate format abuse — a construct that Android's
own parsers tolerate and third-party tools do not
([§3.8](../README.md#38-anti-decompiler-and-anti-tool-tricks)).

The asymmetry: `PackageManager`, `dexopt` and ART were written for speed and backwards compatibility
and accept a wider range of inputs than `apktool`, `jadx`, `baksmali` and `dex2jar`, which were
written to a stricter reading of the specification.

What you do next: do **not** conclude the file is corrupt — it demonstrably runs. Try
`jadx -J-Xmx8g --show-bad-code --deobf`, drop to `baksmali` which is more tolerant, work on a
case-sensitive filesystem, or skip static analysis entirely and dump the DEX from memory. Also note
it: an app that deliberately breaks analysis tooling is making a statement about its threat model that
belongs in your report.
</details>

<details>
<summary>Answers Q16–Q17 — the table and the next command</summary>

**Q16.** Common disagreements and their causes:

- The script may call variant B "possibly encrypted" if the app is small enough that its handful of
  URLs fall below the heuristic. Statistics on a tiny sample are unreliable; your eyes were right.
- The script's flattening proxy (counting switch-payload byte pairs) is explicitly crude and will
  produce noise. The reliable test is visual, which is why the script says so in its output.
- The script may score variant A as "possibly packed" if the build produced few classes. The
  `<application android:name>` check is what disambiguates, and it is why the script weights that
  indicator heavily.

The meta-point: an automated triage tool reports **capability**, and only manual confirmation reports
**behaviour**. That is the same sentence the chapter applies to MobSF, and it applies equally to the
script shipped in this chapter. Understanding why your own tool is wrong is the skill.

**Q17.** One command each:

| APK | Next command | Why |
|---|---|---|
| A | `jadx-gui A.apk` | Nothing is protected. Read the code. |
| B | `grep -rn 'sk_live\|https://' out_B/sources/` | Names are gone, strings are not. Strings are the map. |
| C | `frida -U -f com.obflab.target -l ../scripts/frida-string-decryptor.js --pause` | Phase 4. Strings first, before anything else. |
| D | Same as C | Flattening is Phase 5 and you have not earned it yet. Strings first will tell you *which* method to deflatten, and it may tell you that you do not need to. |
| E | `frida -U -f com.obflab.target -l ../scripts/frida-classloader-dump.js --pause` | Phase 3. Do not read a stub. |

The ordering discipline is the entire lesson. Variant D is the one that catches people: faced with a
flattened method, the instinct is to start deflattening. The methodology says recover strings first,
and the reason is that strings tell you *what* while control flow only tells you *how* — and "what" is
what you are being paid to find out.
</details>

---

## Success criteria

- [ ] You built or obtained all five variants and classified them without reading decompiled code
- [ ] You recorded a SHA-256 and signer for each
- [ ] You identified the packed APK from three independent indicators
- [ ] You found where the packer stashed the original `Application` class name
- [ ] You measured the class-name length distribution rather than eyeballing it
- [ ] You identified at least one class that survived renaming, and can explain why that is a finding
- [ ] You used the URL count as the string-encryption test and can explain why it beats "few strings"
- [ ] You located the decryptor statically from the `xor-int` pattern
- [ ] You wrote the hardcoded-credential finding for both B and C and recognised they are the same
      finding with different recovery costs
- [ ] You can explain what `JNI_OnLoad` + populated `.init_array` implies about attach timing
- [ ] You can explain why "no anti-analysis markers" is meaningless when strings are encrypted
- [ ] You produced the six-row triage table for all five APKs
- [ ] You compared your answers with the script and explained every disagreement
- [ ] You named exactly one next command per APK, and can defend the ordering for variant D

---

## Next

[Lab 02 — Recover encrypted strings](lab-02-string-recovery.md) is the flagship. You take variant C
and turn it back into readable code.
