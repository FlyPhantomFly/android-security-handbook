# Lab 01 — Reading a Manifest Three Ways

**Difficulty:** Beginner
**Time:** 60–90 minutes
**Prerequisites:** [Chapter 32 §3.1–3.4](../README.md#3-deep-internal-working),
[10-APK-Internals](../../10-APK-Internals/README.md), `adb`, `apktool`, `aapt2`, a device or emulator

---

## Objective

Extract the same `AndroidManifest.xml` three different ways — with `apktool`, with
`aapt2 dump xmltree`, and from the device with `dumpsys package` — reconcile every disagreement
between them, and learn to read raw AXML typed values instead of a decoder's prettified guess.

By the end you will never again write "the manifest says…" without knowing *which* manifest you mean.

## Why this matters

There is no such thing as "the manifest". There is a chunk of binary AXML inside the APK, and there
are several independent programs that each turn those bytes into something you can read.

`aapt2` uses `libandroidfw` — the same C++ code the platform uses. `apktool`, `jadx` and the Python
decoders are **independent reimplementations**. Reimplementations of a binary format written by an
adversary is a classic parser-differential setup, and Android malware has used exactly that to make
analysis tools print a benign manifest while the device installs a malicious one.

> **📖 Definition**
> A **parser differential** is a security bug in which two programs that are supposed to agree on the
> meaning of the same bytes do not. The attacker crafts input that lands in the gap. Here, one
> program is your analysis tool and the other is the device that will actually run the app.

Two facts from [§3.1](../README.md#31-android-binary-xml-axml--the-on-disk-format) make this concrete
and are what this lab drills into you:

1. **The platform matches attributes by resource ID, not by name.** `android:exported` *is*
   `0x01010010`. The name string is decoration.
2. **`TYPE_INT_BOOLEAN` is "non-zero is true", not "0 or 1".** The platform's
   `getAttributeBooleanValue` returns `data != 0`. A crafted APK can store `0xFFFFFFFF` for
   `android:debuggable`. A decoder that prints `-1` and does not flag it has hidden a Critical
   finding from you.

The device is the only authority, because the device is what enforces.

---

## Setup

Pick an app you are authorised to test. Any third-party app from your own phone works; a
deliberately vulnerable app from [80-Appendix](../../80-Appendix/README.md) works better because it
has a rich manifest.

```bash
# host
export PKG=com.example.target
mkdir -p ~/lab32-01 && cd ~/lab32-01

# host — pull the APK the device is actually running
adb shell pm path $PKG
adb pull "$(adb shell pm path $PKG | head -1 | tr -d '\r' | sed 's/package://')" target.apk
ls -la target.apk
```

```bash
# host — identity first, always. Every finding is tied to this hash and this signer.
sha256sum target.apk
apksigner verify -v --print-certs target.apk | head -30
```

> **🔍 Pentester's Note**
> Record the SHA-256 and the signing certificate *before* you look at anything else. A finding
> against an APK you cannot identify later is worthless, and "I downloaded it from the store" is not
> a chain of custody. On a repackaged or sideloaded build, the signer tells you immediately that you
> are not looking at the shipped artefact.

---

## Steps

### Step 1 — Confirm you are holding binary XML, not text

```bash
# host
unzip -p target.apk AndroidManifest.xml | xxd | head -3
```

**Expect** the first four bytes `03 00 08 00`.

**Question 1.** What do those four bytes mean? Break them into two `uint16` values and match them
against the `ResChunk_header` layout in [§3.1](../README.md#31-android-binary-xml-axml--the-on-disk-format).

**Question 2.** What would you conclude if the file began with `<?xml`?

### Step 2 — Read 1: `aapt2 dump xmltree` (closest to the platform)

```bash
# host
aapt2 dump xmltree --file AndroidManifest.xml target.apk > aapt2.txt
wc -l aapt2.txt
head -40 aapt2.txt
```

Read the output carefully. A typical line looks like:

```text
A: android:exported(0x01010010)=(type 0x12)0x0
```

Three parts, and all three matter:

| Part | Meaning |
|---|---|
| `android:exported` | The attribute *name*. Decoration. |
| `(0x01010010)` | The attribute **resource ID**. This is the platform's real key. |
| `(type 0x12)0x0` | `Res_value.dataType` = `TYPE_INT_BOOLEAN`, `data` = 0 → false |

**Question 3.** Find `android:debuggable` and `android:allowBackup` in your output. What are their raw
`data` values? Are any of them something other than `0x0` or `0x1` or `0xffffffff`?

**Question 4.** Find an attribute whose value is printed as `@0x7f0f0021` or similar. What kind of
value is that, and what must you do before you can audit it?

### Step 3 — Read 2: `apktool` (an independent decoder)

```bash
# host
apktool d -f target.apk -o work/ >/dev/null
ls work/
head -40 work/AndroidManifest.xml
```

Note that `apktool` also decoded `res/`, which is how the `@xml/...` references from Question 4
become readable files:

```bash
# host — every referenced res/xml file at once
for f in work/res/xml/*.xml; do echo "== $f"; cat "$f"; echo; done
```

**Question 5.** Which config files did the manifest reference? For each one, say in a sentence what
it controls. (`network_security_config`, `file_paths`, `backup_rules`, `data_extraction_rules`,
`accessibility_config` and `device_admin` are the ones that matter.)

### Step 4 — Reconcile reads 1 and 2

Build a normalised comparison. Both tools list the same components; they may not agree on the values.

```bash
# host — the exported set according to aapt2
grep -B8 'android:exported' aapt2.txt | grep -E 'E: (activity|activity-alias|service|receiver|provider)|android:exported|android:name' > aapt2-exported.txt

# host — the exported set according to apktool
grep -oE '<(activity|activity-alias|service|receiver|provider)[^>]*' work/AndroidManifest.xml > apktool-components.txt
grep -c 'exported="true"' apktool-components.txt
```

Now do it properly, with the script, which reads **both** formats and produces comparable output:

```bash
# host
python3 ../scripts/manifest-audit.py work/AndroidManifest.xml         --markdown > read-apktool.md
python3 ../scripts/manifest-audit.py --format xmltree aapt2.txt       --markdown > read-aapt2.md
diff read-apktool.md read-aapt2.md
```

**Question 6.** Do the two reads agree on every security-relevant attribute — `exported`,
`permission`, `readPermission`, `writePermission`, `debuggable`, `allowBackup`,
`usesCleartextTraffic`, `protectionLevel`? List every difference.

**Question 7.** Some differences are benign. Which categories of difference are *expected*, and which
would you escalate?

### Step 5 — Read 3: the device (ground truth)

```bash
# host
adb shell dumpsys package $PKG > dumpsys.txt
wc -l dumpsys.txt
```

Pull out the parts that correspond to what you read above:

```bash
# host — application flags: DEBUGGABLE, ALLOW_BACKUP, TEST_ONLY appear here
grep -E 'flags=|privateFlags=' dumpsys.txt

# host — the four resolver tables: what the platform will actually dispatch to
sed -n '/Activity Resolver Table:/,/Receiver Resolver Table:/p' dumpsys.txt > act.txt
sed -n '/Receiver Resolver Table:/,/Service Resolver Table:/p'  dumpsys.txt > rcv.txt
sed -n '/Service Resolver Table:/,/Provider Resolver Table:/p'  dumpsys.txt > svc.txt
sed -n '/Provider Resolver Table:/,/Key Set Manager:/p'         dumpsys.txt > prv.txt

# host — declared permissions with their REAL protection levels
adb shell pm list permissions -f | grep -A6 "$(echo $PKG | cut -d. -f1-2)"

# host — components whose enabled state was changed at runtime
grep -A5 -iE 'disabledComponents|enabledComponents' dumpsys.txt

# host — SDK levels as the platform recorded them
grep -E 'targetSdk|minSdk' dumpsys.txt
```

**Question 8.** Does the device agree with `aapt2`? With `apktool`? Where any of the three disagree,
which do you trust, and why?

**Question 9.** Are there components in the `dumpsys` resolver tables that you did *not* see in either
host-side read? What could explain that?

### Step 6 — The fourth read that is not a substitute

```bash
# host
aapt2 dump badging target.apk | head -40
aapt2 dump badging target.apk | grep -iE 'debuggable|launchable|uses-permission|sdkVersion'
```

**Question 10.** `badging` is convenient. Why is it **not** a substitute for `xmltree` in an audit?
(Hint: look at what it does with attributes it does not consider interesting.)

### Step 7 — The runtime read

Now get the fourth independent view: what `PackageManager` parsed, read from inside the app's own
process.

```bash
# host
frida -U -f $PKG -l ../scripts/frida-manifest-runtime.js
```

```text
# frida REPL
mf.flags()
mf.components()
mf.permissions()
mf.export()
```

**Question 11.** Compare `mf.flags()` against the `flags=` line from `dumpsys` and against the
`aapt2` output for `debuggable` / `allowBackup` / `testOnly`. All three should agree. Do they?

**Question 12.** Run `mf.enabled()`. Did any component's live state differ from its manifest value?
What would it mean if one did?

### Step 8 — Learn what a lie looks like

You will not usually have a malicious APK to hand, so build the intuition on the raw bytes instead.

```bash
# host — find the resource-map chunk (type 0x0180) and the string pool (type 0x0001)
unzip -p target.apk AndroidManifest.xml > manifest.axml
xxd manifest.axml | head -20
```

Walk the first two chunks by hand using the table in
[§3.1](../README.md#31-android-binary-xml-axml--the-on-disk-format):

| Offset | Field | Your value |
|---|---|---|
| 0x00 | `type` (uint16) | |
| 0x02 | `headerSize` (uint16) | |
| 0x04 | `size` (uint32) | |
| 0x08 | next chunk `type` | |

**Question 13.** For each row of the malformed-construct table in
[§3.2](../README.md#32-axml-parser-confusion--why-you-cross-check-three-tools), say in one sentence
which of your three reads would notice it and which would not.

### Step 9 — Write the methodology note

Write four sentences you could paste into the methodology section of a report, stating: which tools
you used, which one you treat as authoritative and why, what you did when they disagreed, and what
"the manifest says X" means in your report.

---

## Hints

<details>
<summary>Hint 1 — `aapt2` is not on PATH</summary>

It ships in the Android SDK build-tools:

```bash
# host
ls $ANDROID_HOME/build-tools/
export PATH="$ANDROID_HOME/build-tools/34.0.0:$PATH"
aapt2 version
```

On Windows without the SDK, `apktool` alone will get you through most of the lab, but you will not be
able to answer Questions 3 and 4 properly — the raw typed values are the point.
</details>

<details>
<summary>Hint 2 — `adb pull` of the APK fails</summary>

The app may be a split APK. `pm path` prints several lines:

```bash
# host
adb shell pm path $PKG
# package:/data/app/~~abc==/com.example.target-xyz==/base.apk
# package:/data/app/~~abc==/com.example.target-xyz==/split_config.arm64_v8a.apk
```

The manifest you want is in `base.apk`. Pull all of them if you are also looking for code, and note
that `android:isolatedSplits` changes where classes live.
</details>

<details>
<summary>Hint 3 — `dumpsys package` output is enormous</summary>

Section it first:

```bash
# host
grep -n '^\s*[A-Z][A-Za-z ]*:$' dumpsys.txt | head -40
```

That gives you the section headers so you can `sed -n 'A,Bp'` the one you want.
</details>

<details>
<summary>Hint 4 — the script says "could not parse input"</summary>

Autodetection keys off the first non-space characters. Force it:

```bash
# host
python3 ../scripts/manifest-audit.py --format xmltree aapt2.txt
python3 ../scripts/manifest-audit.py --format xml     work/AndroidManifest.xml
```
</details>

<details>
<summary>Hint 5 — Frida reports "currentApplication() returned null"</summary>

You spawned with `-f` and the `Application` object does not exist yet. Either call `mf.init()` again a
second later, or attach to the already-running process with `-n` instead.
</details>

---

## Solution

<details>
<summary>Answers</summary>

**1.** `03 00` is `type = RES_XML_TYPE (0x0003)` and `08 00` is `headerSize = 8`, both little-endian.
Every AXML document opens with the same 8-byte `ResChunk_header`, so this pair is effectively the
file's magic.

**2.** That it is a source or already-decoded manifest, not one extracted from an APK. Auditing a
source manifest is a different (and much weaker) activity: `debuggable` is typically injected by the
build type, `targetSdk` comes from `build.gradle`, and library-injected components are absent
entirely. Always audit the built artefact.

**3.** In a normal app, `0x0` or `0x1`. `0xffffffff` is legitimate output from some toolchains for
"true" and is not by itself malicious — but any *other* non-zero value, or a boolean value on an
attribute that should not be boolean, is a deliberate malformation and is a finding in its own right.
The important thing is that the platform reads all of them as `true`.

**4.** `TYPE_REFERENCE` (`0x01`) — a resource reference. You must resolve it before you can audit it,
which is what `apktool`'s `res/` output gives you. An unresolved `@xml/network_security_config` is an
unaudited network policy, and that file is frequently the highest-value single file in the APK.

**5.** `network_security_config` decides trust anchors, per-domain cleartext policy and pinning.
`file_paths` decides which directories a `FileProvider` exposes. `backup_rules` /
`data_extraction_rules` decide what leaves the device. `accessibility_config` describes what an
accessibility service may observe and do. `device_admin` lists the device-administration policies
requested.

**6–7.** On a normal app they agree. Expected benign differences: attribute ordering, whether a
decoder resolves a resource reference or prints its ID, whitespace, and how each tool renders
`0xffffffff` for a boolean. Escalate any difference in an **effective value**: a different `exported`,
a different `permission`, an attribute present in one and absent in the other, or a component
present in one and absent in the other. Those mean the file is deliberately malformed, and that is
itself a high-value finding — report it.

**8.** The device is authoritative, because the device is what enforces. `aapt2` is the closest
host-side approximation because it shares `libandroidfw` with the platform. `apktool` is an
independent reimplementation and is the one most likely to be wrong on hostile input. If (1) and (2)
disagree, report the disagreement. If (3) disagrees with both, trust (3) and work out why.

**9.** Several explanations, and they are all worth knowing: components contributed by a **split
APK** you did not pull; components **enabled at runtime** that the manifest declares disabled;
components the platform synthesised or filtered; and, on some builds, entries from an *update* to a
system app where you pulled the base. Resolve it before you write anything down.

**10.** `badging` **summarises**. It prints what its authors considered interesting, resolves some
resources, and silently omits attributes it does not have a printer for — including most
component-level attributes. It is excellent for a 10-second triage of package name, SDK levels,
permissions and launchable activity, and it will happily hide an exported provider from you.

**11.** They should. `dumpsys` reads `PackageManagerService`'s own record; the Frida script reads the
`ApplicationInfo` the same service produced; `aapt2` reads the file. Three views of one truth. A
disagreement between the first two would be extraordinary and worth investigating carefully.

**12.** A component whose live state differs from the manifest was changed by the app at runtime with
`setComponentEnabledSetting`. It means the manifest's `android:enabled` value is not the final word,
and that you must not cross a component off your list because the manifest says it is disabled.

**13.** Working through the table in §3.2: a **duplicate attribute** is visible to `aapt2` (which
prints both) and to a careful reading of the raw bytes, and is resolved by the platform in favour of
the *first* match by resource ID — some decoders show the last. A **name/resource-ID mismatch** is
invisible to a name-based decoder and fully effective on the device, so only `aapt2` (which prints
the ID) and `dumpsys` reveal it. An **oversized `headerSize`** or an **unknown chunk type** is
skipped correctly by the platform and may desynchronise a third-party decoder. A **string-pool
encoding flag mismatch** produces different strings in different readers. In every case the pattern
is the same: the platform is tolerant and deterministic, and the reimplementation is neither.

</details>

---

## Success criteria

- [ ] You pulled the APK the device is actually running and recorded its SHA-256 and signer
- [ ] You proved from its first four bytes that the manifest is binary AXML
- [ ] You read raw `Res_value` types from `aapt2 dump xmltree` and can explain `(type 0x12)`
- [ ] You can state, without looking it up, why "non-zero is true" matters for `android:debuggable`
- [ ] You explained why the platform matches attributes by resource ID rather than by name
- [ ] You resolved every `@xml/...` reference and read the referenced files
- [ ] You produced a normalised diff of the `apktool` read against the `aapt2` read
- [ ] You obtained the device's own view with `dumpsys package` and reconciled all three
- [ ] You obtained a fourth, runtime view with `frida-manifest-runtime.js` and it agreed
- [ ] You can state which read is authoritative and why, in one sentence
- [ ] You wrote a four-sentence methodology note you would put in a real report
