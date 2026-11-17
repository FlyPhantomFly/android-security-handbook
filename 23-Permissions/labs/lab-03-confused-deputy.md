# Lab 03 — Borrowing a privileged app's permissions

> **Level:** Advanced
> **Time:** 2–4 hours
> **Needs:** a physical device you own (an emulator works but has far fewer vendor apps), `adb`,
> `apktool`, `jadx`, Python 3.6+, the Android SDK build-tools
> **Chapter:** [23-Permissions](../README.md) — §3.9, §3.12, §5.1, §5.5

---

## Why this lab exists

Labs 01 and 02 were about *obtaining* a permission. This one is about the more valuable case:
never obtaining it, and using it anyway.

> **Definition — confused deputy**
> A *deputy* is a program that holds authority and acts on requests. It becomes *confused* when it
> uses **its own** authority to perform an action requested by someone who does not have that
> authority, without checking whether the requester should be allowed to ask.

On Android the shape is: App A holds a permission. App A exposes a component. App B, holding
nothing, calls that component. App A does the thing, as itself. No permission was stolen, no check
was bypassed, and from `system_server`'s point of view nothing unusual happened at all.

The version that produces serious findings is the one this chapter owns:

> **A pre-installed vendor system app holding `signature|privileged` permissions that exposes an
> unguarded component, letting an ordinary app reach a capability it could never be granted.**

Three properties make that class disproportionately productive. The permission population is a set
of one, so finding the deputy *is* the attack. The deputy was written under the assumption that it
lived on a closed system image among trusted peers. And nobody audits it — it is not on a store, it
went through no review, it is often written by a contractor, and it is not removable.

## Objectives

1. Enumerate every system and privileged app on a device and its granted permissions.
2. Compute the **capability gap**: the set of permissions those apps hold that no ordinary app
   could obtain. That set is the shortlist of things worth borrowing.
3. Pull, decode and audit a candidate deputy's manifest with all three chapters' tools.
4. Identify the specific unguarded component and the specific permission it lends.
5. Prove reachability from the unprivileged probe, not from `adb shell`.
6. Grep the deputy's DEX for the `checkCallingOrSelfPermission` pattern and reason about its
   threading.
7. Write the finding with the permission arithmetic that makes it credible.

---

## Scope and honesty

This lab operates on **your own device's pre-installed apps**. That is legal on hardware you own
and is the standard research workflow for OEM findings.

Two rules, and they are not decoration.

- **Do not report a vendor issue you found this way to anyone but the vendor**, through their own
  disclosure programme. OEM system apps are the vendor's, not Google's.
- **Do not fabricate impact.** Most exported components on most system apps do something dull. The
  discipline this lab teaches is subtraction: finding the one that matters by ruling out the
  ninety that do not.

You may find nothing exploitable on your device. That is a legitimate outcome and the lab is
written so that the *method* is the deliverable, not a guaranteed bug.

---

## Setup

```bash
# host
mkdir -p ~/lab-23-03 && cd ~/lab-23-03
adb devices
adb shell getprop ro.build.version.release
adb shell getprop ro.build.version.sdk
adb shell getprop ro.product.manufacturer
adb shell getprop ro.build.fingerprint
```

Record the fingerprint. Every finding in this lab is specific to a build, and a report that does
not name the build is not reproducible.

Build the probe now, so it is ready when you need it:

```bash
# host
cd ~/Android-Security-Handbook/23-Permissions/examples/probe-app
export ANDROID_SDK_ROOT="$HOME/Android/Sdk"
./build-probe.sh
adb install -r out/probe-app.apk
cd ~/lab-23-03
```

---

## Part 1 — Enumerate the deputies

### Step 1.1 — Every privileged app

```bash
# host — apps on the system image, with their APK paths
adb shell pm list packages -s -f > system-packages.txt
wc -l system-packages.txt

# host — the privileged subset: /system/priv-app and its equivalents
grep -E 'priv-app|/product/priv-app|/system_ext/priv-app|/vendor/priv-app' system-packages.txt \
    | sed 's/^package://' > priv-apps.txt
wc -l priv-apps.txt
```

On a stock Pixel this is a few dozen. On a vendor build it is often well over a hundred.

**Question 1.** Why does `/system/priv-app` matter more than `/system/app`?

<details>
<summary>Answer</summary>

The `privileged` flag in a `protectionLevel` admits apps in the privileged partitions **and
allow-listed for that specific permission**. The `preinstalled` flag admits *any* app on the
system image, privileged or not.

So `/system/app` apps can hold `signature|preinstalled` permissions; `/system/priv-app` apps can
hold those **and** `signature|privileged` ones, which is the wider and more interesting set. Both
are worth enumerating; start with priv-app.

The allow-lists themselves are readable without root:

```bash
adb shell ls /system/etc/permissions/ /vendor/etc/permissions/ /product/etc/permissions/
adb shell cat /system/etc/permissions/privapp-permissions-platform.xml | head -40
```

Those files are a map of the vendor's own trust decisions, written down. Read them.

</details>

### Step 1.2 — Dump the permission state of each

```bash
# host — this takes a minute
mkdir -p dumps
while read -r pkg; do
    pkg="${pkg%%=*}"
    pkg="${pkg##*=}"
    :
done < /dev/null

# simpler and correct: the paths and names are separated by '='
sed 's/.*=//' priv-apps.txt | sort -u > priv-names.txt
while read -r p; do
    adb shell dumpsys package "$p" > "dumps/$p.txt" 2>/dev/null
done < priv-names.txt
ls dumps | wc -l
```

### Step 1.3 — Extract the held permissions

```bash
# host — use the chapter's reader so requested/held stay separate
cd ~/Android-Security-Handbook/23-Permissions
for f in ~/lab-23-03/dumps/*.txt; do
    echo "=== $(basename "$f" .txt)"
    python3 -B scripts/grant-state.py "$f" --json 2>/dev/null \
        | python3 -c "import json,sys
try:
    d=json.load(sys.stdin)
except Exception:
    raise SystemExit
for p in d['derived']['held']:
    print(p)"
done > ~/lab-23-03/held-by-priv.txt
cd ~/lab-23-03
wc -l held-by-priv.txt
```

### Step 1.4 — Compute the capability gap

The set worth borrowing is: permissions held by privileged apps whose `protectionLevel` an
ordinary app cannot satisfy.

```bash
# host — the level of every permission on the device
adb shell pm list permissions -f -g > perms.txt

# host — pull out the name/level pairs
python3 - <<'PY' > levels.txt
import re
name = None
for line in open('perms.txt', encoding='utf-8', errors='replace'):
    m = re.match(r'\s*\+?\s*permission:(\S+)', line)
    if m:
        name = m.group(1); continue
    m = re.match(r'\s*protectionLevel:(\S+)', line)
    if m and name:
        print(name, m.group(1)); name = None
PY
wc -l levels.txt

# host — which held permissions are signature-anchored, i.e. unobtainable?
grep -v '^===' held-by-priv.txt | sort -u > held-names.txt
join -1 1 -2 1 <(sort held-names.txt) <(sort -k1,1 levels.txt) \
    | grep -E 'signature|internal' | sort -u > borrowable.txt
wc -l borrowable.txt
head -30 borrowable.txt
```

**Question 2.** Why is this list the shortlist, rather than the list of *dangerous* permissions?

<details>
<summary>Answer</summary>

Because a `dangerous` permission is one an attacker's own app can obtain, at the cost of one
dialog. Borrowing it from a deputy adds nothing except stealth.

A `signature`, `signature|privileged` or `internal` permission is one the attacker can **never**
obtain by acting alone. If a deputy will exercise it on request, the deputy is the *only* route —
which is exactly what makes the finding worth reporting and worth paying for.

The permission arithmetic for every confused-deputy finding is the same single question:
**which permission did the deputy hold that I could not have obtained?** If the answer is "none",
the re-delegation is real and the impact is zero, and saying so is what distinguishes a tester from
a scanner.

</details>

---

## Part 2 — Pick a candidate and audit it

Pick two or three apps from `priv-names.txt` whose entries in `borrowable.txt` look interesting.
Good signals, in rough order of yield:

| Signal | Why |
|---|---|
| `WRITE_SECURE_SETTINGS` | The deputy can change secure settings; you cannot |
| `INSTALL_PACKAGES` / `DELETE_PACKAGES` | The deputy can install and remove apps |
| `MANAGE_USERS`, `INTERACT_ACROSS_USERS_FULL` | Cross-profile reach |
| `READ_PRIVILEGED_PHONE_STATE` | Device identifiers you cannot get |
| `MODIFY_PHONE_STATE`, `CALL_PRIVILEGED` | Telephony |
| Vendor-specific names you have never seen | Nobody has audited these |

### Step 2.1 — Pull and decode

```bash
# host
PKG=com.vendor.settings          # substitute yours
adb shell pm path "$PKG"
#   package:/system/priv-app/VendorSettings/VendorSettings.apk

adb pull /system/priv-app/VendorSettings/VendorSettings.apk .
apktool d -f VendorSettings.apk -o out-vendorsettings/
```

### Step 2.2 — Three tools, three questions

```bash
# host
cd ~/Android-Security-Handbook/23-Permissions
M=~/lab-23-03/out-vendorsettings/AndroidManifest.xml

# 32: the declaration audit and the targetSdk version matrix
python3 -B ../32-Manifest/scripts/manifest-audit.py "$M"

# 21: what this does to the UID boundary
python3 -B ../21-App-Sandbox/scripts/manifest-exposure.py "$M"

# 23: which of ITS OWN permissions are enforceable, resolved against the device
python3 -B scripts/permission-audit.py --manifest "$M" --pm-list ~/lab-23-03/perms.txt
```

**Question 3.** The three outputs will overlap. What does each one tell you that the others do not?

<details>
<summary>Answer</summary>

| Tool | Its question | What only it answers |
|---|---|---|
| `manifest-audit.py` (32) | Does this manifest pass a severity-rated checklist, given its `targetSdk`? | Whether an `exported`-less component with an intent filter defaults to exported on **this** target |
| `manifest-exposure.py` (21) | What does this manifest do to the UID boundary? | The `sharedUserId` picture, `isolatedProcess` versus `android:process`, and the complete exported inventory with its permission posture |
| `permission-audit.py` (23) | Which of this app's own permissions are enforceable, and who owns them? | The population analysis of each `protectionLevel`, and — with `--pm-list` — the device's answer for ownership, which no manifest can supply |

Running one and skipping the others is how you miss a finding. The overlap is the point: where
they agree you have corroboration, and where they diverge you have something to investigate.

</details>

### Step 2.3 — Find the unguarded components

```bash
# host
M=~/lab-23-03/out-vendorsettings/AndroidManifest.xml
grep -nE '<(activity|activity-alias|service|receiver|provider)' -A6 "$M" \
    | grep -B2 -A4 'exported="true"' \
    | grep -v 'android:permission' \
    | head -60
```

That grep is crude on purpose — the structured answer is in `manifest-exposure.py`'s output. Use
both: the tool for completeness, the grep for a feel for the file.

For each exported component with no permission, or with a permission that `permission-audit.py`
called `NOT-A-BOUNDARY`, write down:

1. The component's fully-qualified class name.
2. What it appears to do, from its name.
3. Which of the app's borrowable permissions it could plausibly exercise.

---

## Part 3 — Read the code

### Step 3.1 — The highest-value greps

```bash
# host
jadx -d jadx-vendorsettings/ VendorSettings.apk 2>/dev/null

# the OrSelf vulnerability pattern
grep -rn 'checkCallingOrSelfPermission\|enforceCallingOrSelfPermission' jadx-vendorsettings/

# identity clearing, which converts "the caller asked" into "we did it"
grep -rn 'clearCallingIdentity' jadx-vendorsettings/

# correct caller verification, a POSITIVE finding
grep -rn 'Binder.getCallingUid\|checkSignatures\|getPackagesForUid' jadx-vendorsettings/

# what the deputy does with the permissions you want
grep -rn 'Settings.Secure.put\|Settings.Global.put\|Settings.System.put' jadx-vendorsettings/
grep -rn 'startActivity(\|sendBroadcast(\|bindService(' jadx-vendorsettings/ | head -40
```

**Question 4.** You find `checkCallingOrSelfPermission` inside a `BroadcastReceiver.onReceive`.
Is that a finding?

<details>
<summary>Answer</summary>

It is a strong lead, and whether it is a finding depends on one thing you must check: **what
thread the check runs on.**

`checkCallingOrSelfPermission` evaluates `Binder.getCallingUid()`. Inside a live Binder
transaction that is the caller's UID and the check is correct. Off the Binder thread — posted to a
`Handler`, handed to an `Executor`, done on a background thread, or reached from the app's own
`onCreate` — there is no transaction, `Binder.getCallingUid()` returns the **current process's own
UID**, and the check becomes "do I hold this permission". For a privileged app that is always yes.

Broadcast delivery in particular does not always preserve the sender's identity in the way
developers assume. So: read the method, find out whether it runs synchronously on the incoming
Binder thread, and if it posts anywhere, you have a full authorisation bypass.

The fix is `checkCallingPermission`, which explicitly tests `pid != Process.myPid()` and returns
`PERMISSION_DENIED` when there is no caller — a fail-closed design. See
[`../README.md`](../README.md) §3.8 and §4.4.

</details>

### Step 3.2 — Watch it at runtime

```bash
# host
frida -U -n com.vendor.settings -l ~/Android-Security-Handbook/23-Permissions/scripts/hook-permission-checks.js
```

The script flags every `OrSelf` call with a stack trace and prints
`callingUid=… myUid=…  <-- NO BINDER TRANSACTION IN PROGRESS` when the two match. That line is the
finding, live.

> **Attaching to a system app**
> Frida needs root or a debuggable build to attach to a privileged process. If you cannot attach,
> the static reading in step 3.1 still stands — say in the report that the threading was
> established statically and not confirmed at runtime.

---

## Part 4 — Prove it from an unprivileged UID

This is the step that makes the finding defensible, and the step most reports skip.

### Step 4.1 — Add the target to the probe's `<queries>`

```bash
# host
cd ~/Android-Security-Handbook/23-Permissions/examples/probe-app
```

Edit [`../examples/probe-app/AndroidManifest.xml`](../examples/probe-app/AndroidManifest.xml) and
add your target:

```xml
<queries>
    <package android:name="com.vendor.settings" />
</queries>
```

Then rebuild and reinstall:

```bash
./build-probe.sh && adb install -r out/probe-app.apk
```

**Do not skip this.** A probe that cannot see the package fails in a way that looks exactly like a
permission denial, and you will conclude the component is unreachable when it is not.

### Step 4.2 — Compare the two identities

Run the same call twice: once from `adb shell`, once from the probe.

```bash
# host — from adb shell (UID 2000, privileged by platform policy)
adb shell am start -n com.vendor.settings/.SomeExportedActivity --es key value

# host — from the probe (an ordinary app UID)
adb logcat -c
adb shell am start -n com.probe.unprivileged/.ProbeActivity \
    --es probe activity --es target 'com.vendor.settings/.SomeExportedActivity' \
    --es key value
adb logcat -d -s PROBE:V
```

Record both results in a table:

| Result | Meaning | Report as |
|---|---|---|
| Works from shell, works from probe | Reachable by any app | **Finding** |
| Works from shell, fails from probe | Reachable only by a privileged UID | **Not a finding** against an app attacker |
| Fails from both | Not reachable | Nothing |
| Fails from shell, works from probe | Rare — the shell UID is excluded by an allow-list | Investigate |

### Step 4.3 — What the probe's output looks like

Measured on the test device, probing a guarded system provider from the probe app:

```text
I PROBE  :   package = com.probe.unprivileged
I PROBE  :   uid     = 10146   (adb shell is 2000)
I PROBE  : probe=query target=content://com.android.contacts/contacts
W PROBE  : RESULT: query threw java.lang.SecurityException
W PROBE  :   message: Permission Denial: opening provider
           com.android.providers.contacts.ContactsProvider2 from
           ProcessRecord{1ba6f8b 20054:com.probe.unprivileged/u0a146} (pid=20054, uid=10146)
           requires android.permission.READ_CONTACTS or android.permission.WRITE_CONTACTS
```

That is a correctly-guarded provider refusing an unprivileged caller — the negative control. Your
deputy's exported component should be compared against it: if the probe gets through where this
one does not, you have your result.

**Question 5.** Your probe reaches the deputy's activity and the activity does something. How do
you establish that the *permission* was what made it possible?

<details>
<summary>Answer</summary>

By subtraction, and it is worth being rigorous about it.

1. **Name the operation** the deputy performed on your behalf — a settings write, a package
   install, a telephony call.
2. **Attempt the same operation directly from the probe.** It should fail with a
   `SecurityException` naming the permission.
3. **Resolve that permission's level** with `pm list permissions -f -g`. It must be
   signature-anchored, or there is no escalation — you could have requested it.
4. **Confirm the deputy holds it**, from your `dumps/` capture, in a *grant* block and not merely
   the requested block.

Those four steps are the permission arithmetic. Step 2 is the one that makes the finding: it is a
direct demonstration that the capability was unavailable to you before, and available through the
deputy after.

</details>

---

## Part 5 — The catalogue

Whether or not you found something on your device, work through the shapes and write down, for each,
what you would look for and what the impact would be.

| Shape | What the deputy exposes | What the attacker gets | Where to look |
|---|---|---|---|
| Broadcast-triggered settings write | Exported receiver reading extras into `Settings.Global.putInt` | Arbitrary secure-settings write via `WRITE_SECURE_SETTINGS` | `grep -rn 'Settings\..*\.put' jadx-out/` |
| Intent-forwarding activity | Exported activity reading a `Parcelable` `Intent` extra and calling `startActivity` | The deputy's identity applied to any component, including its own non-exported ones | `grep -rn 'getParcelableExtra' jadx-out/` |
| Unguarded `call()` | Exported provider, no permission, `call()` with privileged method names | Whatever those methods do | `grep -rn 'public Bundle call' jadx-out/` |
| `Messenger` service | `bindService`-able, dispatching messages to privileged operations | Arbitrary invocation of the privileged surface | `grep -rn 'Messenger\|Handler.handleMessage' jadx-out/` |
| Mutable `PendingIntent` | A `PendingIntent` created without `FLAG_IMMUTABLE` and handed out | Fill in the blanks; the deputy sends it as itself | `grep -rn 'PendingIntent.get' jadx-out/` |
| URI grant laundering | Deputy resolves an attacker-supplied URI and grants access to the result | Read of files under the deputy's authority | [27-ContentProviders §5.4](../../27-ContentProviders/README.md) |

The second and last rows are shared with 26-Intent and
[27-ContentProviders](../../27-ContentProviders/README.md). This chapter's contribution to each one
is the arithmetic in Part 4 — the identification of the specific permission that was lent.

---

## Part 6 — Write it up

A confused-deputy finding has six mandatory parts. Missing any one of them makes it arguable.

1. **The deputy.** Package name, APK path on the system partition, version, and the build
   fingerprint of the device.
2. **The borrowed permission.** Its name, its resolved `protectionLevel` from the device, and a
   one-line statement of why an ordinary app cannot obtain it.
3. **The exposed component.** Fully qualified name, its export state, and its permission attribute
   (or the absence of one).
4. **The path.** The exact `am start` / `bindService` / `content call` your probe performed, and
   the code in the deputy that receives it.
5. **The proof, from an unprivileged UID.** The probe's package, its UID, the fact that it holds no
   permissions, and its output — together with the negative control showing the same operation
   failing when attempted directly.
6. **Severity, argued.** Not "High because privileged". "High because an application with no
   permissions and no signature relationship can cause `com.vendor.settings` to perform *X*, which
   requires `Y` at `signature|privileged`, which no installable application can obtain."

A model opening paragraph:

> The pre-installed application `com.vendor.settings`
> (`/system/priv-app/VendorSettings/VendorSettings.apk`, version 12.3.1, build fingerprint
> `<...>`) exports the activity `com.vendor.settings.QuickSetupActivity` with
> `android:exported="true"` and no `android:permission` attribute. The activity reads the string
> extra `setting_key` and the integer extra `setting_value` and writes them via
> `Settings.Secure.putInt`, an operation requiring `android.permission.WRITE_SECURE_SETTINGS`
> (`protectionLevel="signature|privileged"`, confirmed on-device). A purpose-built probe
> application holding no permissions and signed with an unrelated key (`com.probe.unprivileged`,
> UID 10146) reached the activity and caused the write; the same write attempted directly by the
> probe failed with `SecurityException ... requires android.permission.WRITE_SECURE_SETTINGS`.

> **Success criterion for the lab**
> Either a finding with all six parts, or a written negative result naming the apps you audited,
> the borrowable permissions each held, and why each exposed component did not yield. A rigorous
> negative is a legitimate deliverable and is far more useful to a client than a padded positive.

---

## Part 7 — Clean up

```bash
# host
adb uninstall com.probe.unprivileged
cd ~/Android-Security-Handbook/23-Permissions/examples/probe-app && rm -rf out/
```

If you changed any setting during testing — through the deputy or otherwise — change it back and
record that you did.

---

## Hints

<details>
<summary>adb pull from /system/priv-app is permission denied</summary>

Some builds restrict reads. `adb shell pm path <pkg>` still gives you the path; try:

```bash
adb shell cat /system/priv-app/X/X.apk > X.apk
```

or use `adb shell "run-as"` on a debuggable build, or a rooted device. If none works, you can still
audit from `dumpsys package <pkg>`, which lists the resolver-table entries for exported components
— less complete than the manifest, but enough to build a candidate list.

</details>

<details>
<summary>Nothing in borrowable.txt looks interesting</summary>

Widen the net. Include `/system/app` (the `preinstalled` population), and include apps with
vendor-namespaced permissions you have never seen, since those are the least audited. Also check
apps that are *not* on the system image but hold privileged permissions through an allow-list —
`grep -rn 'com.vendor' /system/etc/permissions/` on the device will name them.

</details>

<details>
<summary>The probe cannot see the target package</summary>

`<queries>`. Every time. Add `<package android:name="…" />`, rebuild, reinstall. If you are unsure
whether visibility is the problem, temporarily add `QUERY_ALL_PACKAGES` to the probe — it is
`normal` level and granted on request — confirm the component is visible, then remove it and fix
`<queries>` properly. Do not leave it in for the final test, because a probe holding
`QUERY_ALL_PACKAGES` is slightly less representative of a store-published attacker.

</details>

<details>
<summary>Frida cannot attach to the system app</summary>

Expected on a production build without root. Establish the threading statically and say so. A
finding supported by static reading plus a working unprivileged probe is perfectly credible; what
is not credible is a finding supported by neither.

</details>

---

## What to take away

- The attacker never obtains the privileged permission. They borrow a process that already has it.
- The shortlist is signature-anchored permissions held by privileged apps, not dangerous ones.
- Every confused-deputy finding reduces to one question: **which permission did the deputy hold
  that I could not have obtained?**
- `checkCallingOrSelfPermission` off the Binder thread authorises everybody, and it is one grep.
- Reachability is proven from an unprivileged app or it is not proven.
- A rigorous negative result is a real deliverable.

## Next

[Lab 04 — CTF: The Borrowed Key](lab-04-ctf-the-borrowed-key.md) puts squatting, protection
levels and re-delegation into one chain.

## Related

- [`../README.md`](../README.md) §3.9, §3.12, §5.1, §5.5
- [`../examples/probe-app/`](../examples/probe-app/) — the probe, and why `adb shell` is not one
- [`../scripts/grant-state.py`](../scripts/grant-state.py) — the held-permission extraction in Part 1
- [`../scripts/permission-audit.py`](../scripts/permission-audit.py) — the enforceability audit in Part 2
- [`../scripts/hook-permission-checks.js`](../scripts/hook-permission-checks.js) — the `OrSelf` flag in Part 3
- [21-App-Sandbox](../../21-App-Sandbox/README.md) — `manifest-exposure.py` and the exported inventory
- [32-Manifest](../../32-Manifest/README.md) — `manifest-audit.py` and the `targetSdk` matrix
- [27-ContentProviders](../../27-ContentProviders/README.md) — provider `call()` and URI grant laundering
