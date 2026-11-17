# Lab 01 — Extract and read a real app's network security config

**Difficulty:** beginner to intermediate
**Time:** 60–90 minutes
**Prerequisites:** [README §2](../README.md#2-high-level-architecture) and
[§3.2](../README.md#3-deep-internal-working); [10-APK-Internals](../../10-APK-Internals/README.md)
§6.3 for the binary XML layout
**Needs:** Python 3.8+, one or more real APKs (a device is ideal but not required),
optionally the Android SDK for `aapt2` as a cross-check

---

## Objective

Take an APK you did not build, and get from *"there is an `android:networkSecurityConfig` attribute
somewhere"* to *"here is the app's complete trust policy, and here is what the platform will do with
it"* — **by hand first**, then with tooling, and then confirm the two agree.

By the end you will be able to:

- explain why `grep` over the manifest finds nothing,
- resolve a `TYPE_REFERENCE` resource ID to an archive path through `resources.arsc`,
- decode Android binary XML with [`parse_axml.py`](../../10-APK-Internals/examples/parse_axml.py),
- read a real config and state, per hostname, what is permitted and who is trusted,
- and produce a finding — or explain, in writing, why there is not one.

---

## Why this lab exists

Every mobile engagement contains a version of this question: *why can't I see the traffic?* The
answer is in a file that is three indirections away from the attribute that names it, stored in a
format a text editor cannot read, under a filename that is not in the manifest.

Most testers get to it by running `apktool` and hoping. That works right up until it does not — a
config that `apktool` misreads, an app with two configs across splits, a resource with different
values per qualifier — and when it stops working you need to know what the steps *are*. So we do them
by hand once.

---

## Setup

### If you have a device

```bash
# host
adb devices -l
adb shell getprop ro.build.version.sdk
adb shell pm list packages -3
```

Pick a few apps that are likely to have interesting configs. Good candidates, in descending order of
hit rate: a social app, a shopping app, a streaming app, a file manager with a bundled ad SDK, and
anything with "lite" in the name.

```bash
# host
PKG=com.example.app
adb shell pm path $PKG
# package:/data/app/~~AbCd…==/com.example.app-XyZ…==/base.apk

adb pull /data/app/~~AbCd…==/com.example.app-XyZ…==/base.apk ./$PKG.apk
```

> **Warning**
> `pm path` can return several lines for a split-installed app: `base.apk`, `split_config.arm64_v8a.apk`,
> `split_config.en.apk` and so on. Pull **all** of them. A network security config normally lives in
> `base.apk`, but nothing forces it to, and the resource table you need to resolve the reference may
> be in a different split than you expect.

> **Pentester's Note — Git Bash on Windows**
> A path starting with `/data` gets mangled into `C:/Program Files/Git/data/...` by MSYS path
> conversion, and `adb pull` fails with "failed to stat remote object". Prefix the command with
> `MSYS_NO_PATHCONV=1`, or use PowerShell for the pull.

### If you do not have a device

Any APK works. Download one from a mirror, or build the sample project from
[lab 02](lab-02-make-an-app-trust-your-ca.md) and use that. The steps are identical.

### Check the tools

```bash
# host
python3 --version                       # 3.8 or newer
ls ../../10-APK-Internals/examples/parse_axml.py
which aapt2 || echo "optional, used only as a cross-check"
```

---

## Part 1 — Prove that `grep` does not work

Before doing it properly, do it the way most people do, so the failure is yours rather than
theoretical.

```bash
# host
unzip -p base.apk AndroidManifest.xml | strings | grep -i cleartext
unzip -p base.apk AndroidManifest.xml | strings | grep -i network_security
```

**Expected result:** the first finds nothing at all. The second may find `networkSecurityConfig` —
the *attribute name*, which lives in the manifest's string pool — but never a filename.

Now try the whole archive:

```bash
# host
unzip -l base.apk | grep -i 'res/xml'
```

You will see a list of `res/xml/*.xml` entries. On an obfuscated build they may be named `a.xml`,
`b.xml`, `c.xml`. Which one is the network security config?

> **Checkpoint 1**
> Write down, in one sentence, why the manifest does not contain the filename. If you cannot, re-read
> [README §2.5](../README.md#2-high-level-architecture).

---

## Part 2 — Read the manifest attribute by hand

```bash
# host
python3 -B ../../10-APK-Internals/examples/parse_axml.py --extract base.apk \
  | grep -iE 'networkSecurityConfig|usesCleartextTraffic|debuggable|targetSdkVersion|minSdkVersion'
```

Real output, from the social-media app's APK on the test device:

```
        android:targetSdkVersion=30   (TYPE_INT_DEC, data=0x0000001e)
        android:networkSecurityConfig=@0x7f0b0000   (TYPE_REFERENCE, data=0x7f0b0000)
```

Four facts to record now, because each one changes what the config means:

| Fact | Why it matters |
|---|---|
| `targetSdkVersion` | Selects the platform defaults: user CAs at 24, cleartext at 28 |
| `android:debuggable` | Decides whether `<debug-overrides>` does anything at all |
| `android:usesCleartextTraffic` | Superseded by the config, but you need to know they disagree |
| `networkSecurityConfig` | The resource ID |

If `android:debuggable` does not appear at all, it is absent from the manifest, which means `false`.

> **Hint**
> `parse_axml.py` prints both the `rawValue` text and the typed value, and flags any disagreement.
> For `networkSecurityConfig` you should see `TYPE_REFERENCE` and no anomaly. If you see an anomaly
> report, read it — a manifest that decodes differently in two tools is itself a finding, and
> [10-APK-Internals lab 04](../../10-APK-Internals/labs/lab-04-ctf-the-lying-manifest.md) is built on
> exactly that.

> **Checkpoint 2**
> You have a 32-bit number. Decompose it: `0x7f0b0000` is package `0x7f`, type `0x0b`, entry
> `0x0000`. Write down all three.

---

## Part 3 — Resolve the reference by hand

The resource ID means nothing without `resources.arsc`. There are three ways to resolve it, and you
should do at least two so you can compare.

### 3a. With `aapt2` (if you have the SDK)

```bash
# host
aapt2 dump resources base.apk | grep -B1 -A2 '0x7f0b0000'
```

```
    resource 0x7f0b0000 xml/alt_network_security_config
      () (file) res/xml/alt_network_security_config.xml type=XML
```

Note the filename. It is **not** `network_security_config.xml`. Any procedure that assumes the
conventional name would have missed it.

### 3b. With this chapter's resolver

```bash
# host
python3 -B ../scripts/nsc-audit.py base.apk | head -20
```

```
-- manifest facts that change what the config MEANS --
   package                      com.vendor.socialmedia
   targetSdkVersion             30
   android:debuggable           False
   android:usesCleartextTraffic None
   android:networkSecurityConfig 0x7f0b0000
   resolved to                  res/xml/alt_network_security_config.xml
```

`nsc-audit.py` implements a minimal `resources.arsc` reader — package chunk, type chunks, entry
offset array, `ResTable_entry`, `Res_value` — so it needs no Android SDK. If it and `aapt2` disagree,
**that is the finding**, and you should stop and read the table by hand.

### 3c. Understand what the resolver did

This is the part worth internalising. A resource ID is three fields:

```
  0x7f       0b        0000
  package    type      entry index
```

Resolution walks:

1. Find the `RES_TABLE_PACKAGE_TYPE` chunk whose `id` is `0x7f`.
2. Inside it, find every `RES_TABLE_TYPE_TYPE` chunk whose `id` is `0x0b`. There is one per
   configuration qualifier — one for the default, one for `-v21`, one for `-xhdpi`, and so on.
3. In each, index the entry-offset array at position `0x0000`.
4. At `chunkStart + entriesStart + offset` sits a `ResTable_entry`, and immediately after it a
   `Res_value`.
5. If the `Res_value`'s `dataType` is `0x03` (`TYPE_STRING`), its `data` field is an index into the
   **global value string pool** at the top of `resources.arsc`, and the string there is the archive
   path.

> **Hint — a bug worth knowing about**
> `Res_value` is `{ uint16 size; uint8 res0; uint8 dataType; uint32 data }`. `dataType` is at byte
> **3**, not byte 2. The first draft of `nsc-audit.py` read byte 2 and reported "dataType 0x00, not
> TYPE_STRING — it does not name a file" for every APK. If your own resolver returns `TYPE_NULL`
> everywhere, check that offset first.

> **Checkpoint 3**
> You have a path like `res/xml/alt_network_security_config.xml`. Confirm it exists in the archive:
> `unzip -l base.apk | grep alt_network_security_config`

---

## Part 4 — Decode the config

```bash
# host
python3 -B ../../10-APK-Internals/examples/parse_axml.py --extract base.apk \
        --entry res/xml/alt_network_security_config.xml
```

> **Warning — Windows**
> If the config contains non-ASCII text, the Windows console codec raises `UnicodeEncodeError`
> partway through the tree and you get a truncated document plus a traceback. Set
> `PYTHONIOENCODING=utf-8` before the command. This is not hypothetical: one of the configs in this
> lab carries a comment in Chinese.

Real output, trimmed:

```
-- document tree --
  <network-security-config>
    <base-config
        cleartextTrafficPermitted=false   (TYPE_INT_BOOLEAN, data=0x00000000)
    >
      <trust-anchors>
        <certificates
            src='system'   (TYPE_STRING, data=0x0000002b)
        >
        </certificates>
        <certificates
            overridePins=false   (TYPE_INT_BOOLEAN, data=0x00000000)
            src='user'   (TYPE_STRING, data=0x0000002e)
        >
        </certificates>
      </trust-anchors>
    </base-config>
    <domain-config
        cleartextTrafficPermitted=false   (TYPE_INT_BOOLEAN, data=0x00000000)
    >
      <domain includeSubdomains=true>'socialvendor.example'</domain>
      … fourteen more domains …
      <pin-set expiration='2021-07-1'>
        <pin digest='SHA-256'>'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='</pin>
        … fourteen more pins …
      </pin-set>
    </domain-config>
    <debug-overrides>
      <trust-anchors>
        <certificates overridePins=true src='user' />
      </trust-anchors>
    </debug-overrides>
  </network-security-config>

-- anomaly report (0) --
  none - every chunk, every offset and every length is self-consistent,
  and no attribute's rawValue contradicts its typedValue.
```

**Do not move on until you have read this.** Three things are visible and each is a different lesson.

> **Checkpoint 4**
> Write down, before reading Part 5:
> 1. Is `<certificates src="user"/>` inside `<base-config>` a finding? Why or why not?
> 2. What is today's date, and what is the `<pin-set>` expiration?
> 3. Is the `<debug-overrides>` block a finding?

---

## Part 5 — Read the policy, per host

Now translate the tree into a policy, host by host. Do it manually first; the tool will check you.

| Host | Which config matches | Cleartext | Trust anchors | Pins |
|---|---|---|---|---|
| `www.socialvendor.example` | the `<domain-config>` (`socialvendor.example`, `includeSubdomains`) | ? | ? | ? |
| `example.com` | none → the default | ? | ? | ? |
| `socialphotos.example` | the `<domain-config>` | ? | ? | ? |
| `10.0.0.5` | none → the default | ? | ? | ? |

Fill it in, remembering that **inheritance is per property**. The `<domain-config>` above declares
`cleartextTrafficPermitted` and a `<pin-set>` but **no `<trust-anchors>`** — so its anchors come from
`<base-config>`, which is system **and user**.

Now check yourself:

```bash
# host
python3 -B ../scripts/nsc-audit.py base.apk | sed -n '/effective policy/,/findings/p'
```

```
-- effective policy, per scope --
   <base-config> / every host no domain-config matches
       cleartext permitted : false   (declared on <base-config>)
       trust anchors       : system, user   (declared on <base-config>)
       pin-set             : none
   *.socialvendor.example, *.socialcdn.example, *.socialsbx.example, … 15 domains …
       cleartext permitted : false   (declared on <domain-config>)
       trust anchors       : system, user   (declared on <base-config>)
       pin-set             : 15 pin(s), expiration=2021-07-1
```

> **Checkpoint 5**
> Your table and the tool's output should agree exactly. If they do not, the interesting question is
> which of you is wrong — work it out before continuing, because the same reasoning is what you will
> use on the app you are actually being paid to test.

---

## Part 6 — Produce findings

```bash
# host
python3 -B ../scripts/nsc-audit.py base.apk | sed -n '/findings/,$p'
```

For the the social-media app APK on the test device, this produces:

```
   [HIGH    ] NSC-004  <certificates src="user"/> outside <debug-overrides>
   [HIGH    ] NSC-014  PIN-SET EXPIRED 1869 days ago - pinning is off
   [INFO    ] NSC-010  <debug-overrides> present but INERT - the app is not debuggable
```

Three verdicts, three different lessons:

**`NSC-004` is a real finding.** The `<base-config>` trusts the user store, in a release build, with
`targetSdkVersion=30`. Anyone who can get a CA into the user store can terminate this app's TLS —
for every host in the app, because it is in `<base-config>`.

**`NSC-014` is a real finding and it is the one nobody reports.** Fifteen pins over fifteen domains,
and an expiration that passed in 2021. The pins have not been enforced since. Nothing broke, nothing
logged, and every static analysis tool that checks for the *presence* of a `<pin-set>` reports that
this app implements certificate pinning.

**`NSC-010` is not a finding.** `android:debuggable` is false, so the `<debug-overrides>` block is
parsed and discarded. Reporting it would be wrong. Lab 03 measures this rather than taking the tool's
word for it.

### Write it up

Produce a short finding for each of the two real ones. Use this shape:

```
TITLE
    Expired certificate pin set - pinning has not been enforced since 2021-07-01

AFFECTED
    com.example.app, res/xml/<name>.xml, <domain-config> covering 15 domains

EVIDENCE
    <pin-set expiration="2021-07-1"> with 15 <pin digest="SHA-256"> entries.
    Read from the APK with:
        python3 -B nsc-audit.py base.apk

MECHANISM
    NetworkSecurityTrustManager.isPinningEnforced() compares PinSet.expirationTime
    against the current time BEFORE applying the pins, and returns false once the
    date has passed. No log entry is produced and no connection fails, so the
    lapse is not observable from the application's behaviour.

IMPACT
    The declared pinning has provided no protection since the expiry date. The
    application's transport security is equivalent to having no <pin-set> at all:
    any certificate issued by any of the ~140 trusted certificate authorities is
    accepted for these domains.

SEVERITY
    <state it, and state what it is chained with. See README section 5.5>

REMEDIATION
    Update the expiration date and the pin values in the same release, and add a
    CI check that fails the build when the expiration is within 90 days:
        python3 -B nsc-audit.py app-release.apk --fail-on MEDIUM
```

> **Checkpoint 6**
> Your write-up must contain a date and a day count. "The pin set is expired" is an assertion; "the
> pin set expired on 2021-07-01, 1869 days before testing" is a measurement.

---

## Part 7 — Do it on four more apps

The point of this part is calibration. Run the audit across several apps and see the *range* of what
a config can be.

```bash
# host
for f in *.apk; do
  echo "########## $f ##########"
  PYTHONIOENCODING=utf-8 python3 -B ../scripts/nsc-audit.py "$f" | grep -E '^   \[|resolved to'
done
```

Results measured on the test device, for reference — yours will differ:

| App | Resolved to | Findings |
|---|---|---|
| `com.vendor.socialmedia` | `res/xml/alt_network_security_config.xml` | HIGH user anchors, HIGH expired pins, INFO inert debug block |
| `com.vendor.marketplace` | `res/xml/network_security_config.xml` | HIGH expired pins (1504 days), INFO manifest/config cleartext disagreement |
| `com.vendor.streaming` | `res/xml/network_security_config.xml` | HIGH global cleartext, INFO inverted per-TLD policy |
| `com.vendor.filemanager` | `res/xml/network_security_config.xml` | HIGH global cleartext, HIGH user anchors on 7 SDK domains |
| `com.vendor.professionalnet` | `res/xml/network_security_config.xml` | INFO only — `<debug-overrides>` and nothing else |
| `com.vendor.fileexplorer` | *(no config)* | INFO — defaults are the safe ones |

Two of those six produce nothing worth reporting. That is the calibration: **a chapter about a file
that is often wrong is also a chapter about recognising when it is right.**

### The one worth reading closely

Decode the file-manager app's config in full:

```bash
# host
PYTHONIOENCODING=utf-8 python3 -B ../../10-APK-Internals/examples/parse_axml.py \
        --extract com.vendor.filemanager.apk \
        --entry res/xml/network_security_config.xml
```

Look inside `<trust-anchors>` and you will find a **text node**, not an element:

```
      <trust-anchors>
        <certificates src='user' />
        '//信任用户自己安装的证书 '
        <certificates src='system' />
      </trust-anchors>
```

The developer wrote a comment using `//`, which is not XML comment syntax, so instead of being
stripped at compile time it was preserved as character data and shipped inside the APK. It says
*"trust certificates the user installed themselves"*.

> **Pentester's Note**
> Two lessons. First, developer intent sometimes ships verbatim, and it is worth reading every text
> node rather than only elements. Second, a tool that reconstructs a DOM and discards whitespace-only
> or unexpected text nodes will lose this entirely — which is one more reason to look at
> `parse_axml.py`'s raw event stream rather than a tidied tree.

> **Checkpoint 7**
> For each app, write one sentence: what would you have to do to intercept its traffic? The answers
> should be different for at least three of them.

---

## Part 8 — Cross-check three tools

Decode the same config three ways and diff them.

```bash
# host
mkdir -p /tmp/nsc && cd /tmp/nsc

# 1. this repository's parser
python3 -B .../10-APK-Internals/examples/parse_axml.py --extract base.apk \
        --entry res/xml/network_security_config.xml > a.txt

# 2. aapt2, which shares libandroidfw with the platform
aapt2 dump xmltree base.apk --file res/xml/network_security_config.xml > b.txt

# 3. apktool, which writes text XML back out
apktool d -f base.apk -o work/ >/dev/null
cat work/res/xml/network_security_config.xml > c.txt

# they are in different formats, so compare the FACTS, not the bytes
grep -oE 'src=.(system|user)' a.txt b.txt c.txt | sort | uniq -c
grep -oE 'expiration=.[0-9-]+' a.txt b.txt c.txt
grep -cE '<pin |name="pin"|"pin"' a.txt b.txt c.txt
```

Any disagreement about the number of pins, the `src` values, or the expiration is a genuine finding
and should be investigated, not smoothed over.
[10-APK-Internals lab 04](../../10-APK-Internals/labs/lab-04-ctf-the-lying-manifest.md) constructs a
document that produces exactly such a disagreement on purpose.

---

## Success criteria

You have finished this lab when you can, without notes:

- [ ] explain in one sentence why the manifest does not contain the config's filename;
- [ ] decompose a resource ID into package, type and entry index;
- [ ] name the three chunk types you walk in `resources.arsc` to resolve one;
- [ ] decode a config from an APK with `parse_axml.py` in a single command;
- [ ] state, for any hostname, which `<domain-config>` matches it and why;
- [ ] apply per-property inheritance correctly to a `<domain-config>` that declares only a `<pin-set>`;
- [ ] look at `<certificates src="user"/>` and say — correctly — whether it is a finding, using
      `android:debuggable` to decide;
- [ ] compute whether a `<pin-set>` is still enforced;
- [ ] and write a finding that contains a date, a day count, and a mechanism, rather than an
      adjective.

---

## Extension exercises

1. **Automate the sweep.** Write a shell loop that pulls every third-party APK from a device, runs
   `nsc-audit.py --json` over each, and produces a single table of packages against highest severity.
   Roughly twenty lines. What proportion of the device's apps declare a config at all?

2. **Find a split-APK config.** Install an app that uses dynamic feature delivery, pull every split,
   and run the audit over each. Does the resolver find the resource in the split you expect?

3. **Break the resolver deliberately.** Take an APK, edit one byte of the `Res_value` `dataType` in
   `resources.arsc`, re-zip, and run both `aapt2` and `nsc-audit.py` over it. Which one notices? This
   is the seed of [lab 04](lab-04-ctf-the-config-that-lies.md).

4. **Multiple qualifiers.** Build an app with two versions of the same config — one in `res/xml/` and
   one in `res/xml-v29/` — and confirm that `nsc-audit.py` reports both values and warns that the
   effective one depends on the device.

---

## Where to go next

- [Lab 02](lab-02-make-an-app-trust-your-ca.md) — make an app you built accept your proxy CA, two
  different ways, and prove which one is live in which variant.
- [Lab 03](lab-03-prove-it-on-the-device.md) — stop trusting the static read and measure what the
  platform actually built.
- [README §5](../README.md#5-security-perspective) — severity, and how to report each of these.
