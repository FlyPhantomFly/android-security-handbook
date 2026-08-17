# Lab 03 — The Exported-Surface Sweep

**Difficulty:** Intermediate
**Time:** 90–120 minutes
**Prerequisites:** [Lab 02](lab-02-live-manifest-audit.md), [32-Manifest](../../32-Manifest/README.md)

---

## Objective

Enumerate every exported component of a target app, exercise each one by hand with `am` and `content`,
and then — the part that actually matters — **prove which of them are genuinely reachable by an
ordinary app** rather than only by your privileged shell.

## Why this matters

This is the single most common false positive in Android reports, and it gets junior testers' findings
rejected.

`adb shell` runs as UID 2000 (`shell`), which holds privileges an app does not. Components you can
launch from `adb shell` may be completely unreachable by a malicious app. Reporting "exported activity
X is reachable" on the strength of an `am start` that worked is wrong, and a competent developer will
say so.

The discipline this lab teaches — *reproduce from an unprivileged UID before you report* — is what
separates a finding from an observation.

---

## Setup

Pick a target you are authorised to test. A deliberately vulnerable app from
[80-Appendix](../../80-Appendix/README.md) is ideal — InsecureBankv2, OVAA or Injured Android all have
rich exported surfaces.

```bash
# host
export PKG=com.example.target
adb shell pm path $PKG
adb logcat -c
```

Keep a second terminal running:

```bash
# host
adb logcat --pid=$(adb shell pidof -s $PKG) -v threadtime
```

---

## Steps

### Step 1 — Enumerate from the live device

```bash
# host
adb shell dumpsys package $PKG > pkg.txt
grep -n "exported=true" pkg.txt
```

Then pull the four resolver tables:

```bash
# host
sed -n '/Activity Resolver Table:/,/Receiver Resolver Table:/p' pkg.txt > activities.txt
sed -n '/Receiver Resolver Table:/,/Service Resolver Table:/p'  pkg.txt > receivers.txt
sed -n '/Service Resolver Table:/,/Provider Resolver Table:/p'  pkg.txt > services.txt
sed -n '/Provider Resolver Table:/,/Key Set Manager:/p'         pkg.txt > providers.txt
```

**Build an inventory table.** For each component record: type, fully-qualified name, `exported` value,
guarding `permission` (if any), and its intent filters.

**Q1.** How many components are exported? How many of those have **no** `permission` attribute? That
second number is your actual working list.

### Step 2 — Cross-check against the APK

```bash
# host
adb pull $(adb shell pm path $PKG | head -1 | sed 's/package://') target.apk
apktool d -f target.apk -o work/ >/dev/null
grep -oE '<(activity|activity-alias|service|receiver|provider)[^>]*' work/AndroidManifest.xml \
  | grep -c 'exported="true"'
aapt2 dump xmltree target.apk --file AndroidManifest.xml | grep -B2 -A2 'exported'
```

**Q2.** Do `dumpsys`, `apktool` and `aapt2` agree on the exported set? If not, which do you trust, and
what does the disagreement suggest? (See [10-APK-Internals](../../10-APK-Internals/README.md) on AXML
parser confusion.)

**Q3.** Are there components with an `<intent-filter>` but no explicit `android:exported`? What is
their effective export state, and what does it depend on?

### Step 3 — Exercise the activities

```bash
# adb shell — one at a time, watching logcat
am start -n $PKG/.SomeActivity
am start -n $PKG/.SomeActivity --es url "https://example.org/"
am start -n $PKG/.SomeActivity --es token "AAAA" --ez admin true
am start -a android.intent.action.VIEW -d "targetapp://open?next=https://example.org/"
```

Record for each: did it launch, did it crash, what appeared on screen, what appeared in logcat.

**Q4.** Any activity that takes a URL in an extra and renders it? That is the top-3 real-world finding
described in [30-Activities](../../30-Activities/README.md) — note it and continue.

**Q5.** Any activity that produces a result you can read back?

```bash
# adb shell — -W waits and prints the result
am start -W -n $PKG/.SomeActivity
```

### Step 4 — Exercise the receivers

```bash
# adb shell
am broadcast -a com.example.target.ACTION_LOGOUT
am broadcast -n $PKG/.SomeReceiver -a com.example.target.ACTION_SYNC --es data "x"
```

**Q6.** Does any receiver perform a state-changing action — logout, wipe, settings change, sync
trigger — with no permission guard?

### Step 5 — Exercise the services

```bash
# adb shell
am startservice -n $PKG/.SomeService
am start-service -n $PKG/.SomeService --es cmd "test"     # newer syntax
```

**Q7.** Which services start? Does logcat show them acting on the extras you supplied?

### Step 6 — Exercise the providers

```bash
# adb shell
content query --uri content://com.example.target.provider/items
content query --uri content://com.example.target.provider/items --projection "name"
content query --uri content://com.example.target.provider/items --where "1=1"
content query --uri content://com.example.target.provider/items --sort "name"
content call --uri content://com.example.target.provider --method getSecret
content read --uri content://com.example.target.provider/files/config.xml
```

**Q8.** Which of the four injection points (`--projection`, `--where`, `--sort`, and the path itself)
produce an error message that reveals SQL? Which produce data you should not have?

**Q9.** Does `content read` let you reach a file outside the intended directory? Try
`../../../databases/app.db`.

### Step 7 — **The step that makes it a finding**

Everything so far was done as `shell` (UID 2000). Now prove reachability from an ordinary app.

Build a minimal probe app. It needs **no permissions at all**.

**`AndroidManifest.xml`** — note the `<queries>` block, required from Android 11 to see other packages:

```xml
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.artlab.probe">
    <queries>
        <package android:name="com.example.target" />
    </queries>
    <application android:label="Probe">
        <activity android:name=".ProbeActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
```

**`ProbeActivity.java`**

```java
package com.artlab.probe;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Intent;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;

public class ProbeActivity extends Activity {
    private static final String TAG = "PROBE";
    private static final String TARGET = "com.example.target";

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);

        // 1. Try to start an exported activity as an ORDINARY app.
        tryActivity(".SomeActivity");

        // 2. Try a broadcast.
        tryBroadcast("com.example.target.ACTION_LOGOUT");

        // 3. Try to start a service.
        tryService(".SomeService");

        // 4. Try to read a provider.
        tryProvider("content://com.example.target.provider/items");
    }

    private void tryActivity(String cls) {
        try {
            Intent i = new Intent();
            i.setComponent(new ComponentName(TARGET, TARGET + cls));
            i.putExtra("url", "https://example.org/");
            i.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            startActivity(i);
            Log.i(TAG, "ACTIVITY " + cls + " -> LAUNCHED (genuinely reachable)");
        } catch (SecurityException e) {
            Log.i(TAG, "ACTIVITY " + cls + " -> DENIED: " + e.getMessage());
        } catch (Exception e) {
            Log.i(TAG, "ACTIVITY " + cls + " -> ERROR: " + e);
        }
    }

    private void tryBroadcast(String action) {
        try {
            Intent i = new Intent(action);
            i.setPackage(TARGET);
            sendBroadcast(i);
            Log.i(TAG, "BROADCAST " + action + " -> SENT (no exception)");
            // NOTE: sendBroadcast is fire-and-forget. "No exception" does not
            // prove the receiver ran. Confirm from the TARGET's own logcat.
        } catch (SecurityException e) {
            Log.i(TAG, "BROADCAST " + action + " -> DENIED: " + e.getMessage());
        }
    }

    private void tryService(String cls) {
        try {
            Intent i = new Intent();
            i.setComponent(new ComponentName(TARGET, TARGET + cls));
            startService(i);
            Log.i(TAG, "SERVICE " + cls + " -> STARTED (genuinely reachable)");
        } catch (SecurityException e) {
            Log.i(TAG, "SERVICE " + cls + " -> DENIED: " + e.getMessage());
        } catch (Exception e) {
            Log.i(TAG, "SERVICE " + cls + " -> ERROR: " + e);
        }
    }

    private void tryProvider(String uri) {
        try (Cursor c = getContentResolver().query(Uri.parse(uri), null, null, null, null)) {
            if (c == null) {
                Log.i(TAG, "PROVIDER " + uri + " -> null cursor");
                return;
            }
            Log.i(TAG, "PROVIDER " + uri + " -> READABLE, " + c.getCount()
                     + " rows, columns=" + java.util.Arrays.toString(c.getColumnNames()));
            if (c.moveToFirst()) {
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < c.getColumnCount(); i++) {
                    sb.append(c.getColumnName(i)).append('=')
                      .append(c.getString(i)).append(' ');
                }
                Log.i(TAG, "  first row: " + sb);
            }
        } catch (SecurityException e) {
            Log.i(TAG, "PROVIDER " + uri + " -> DENIED: " + e.getMessage());
        } catch (Exception e) {
            Log.i(TAG, "PROVIDER " + uri + " -> ERROR: " + e);
        }
    }
}
```

Build, install and run:

```bash
# host
./gradlew assembleDebug
adb install -r app/build/outputs/apk/debug/app-debug.apk
adb logcat -c
adb shell am start -n com.artlab.probe/.ProbeActivity
adb logcat -s PROBE
```

**Q10.** For each component, compare the `adb shell` result against the probe-app result. Build this
table:

| Component | Reachable from `adb shell` | Reachable from an app | Verdict |
|---|---|---|---|
| | | | |

**Q11.** Any component reachable from `shell` but **not** from the app? Those are the false positives
you would have reported. How many?

### Step 8 — Write it up

For each component that is genuinely app-reachable, write a finding with:

- The component and its declared export state
- The exact `adb` command **and** the probe-app code that demonstrates reachability
- What an attacker gains
- Severity with justification
- The fix as code

**Q12.** For each finding, state explicitly which evidence came from `shell` and which from the
unprivileged app. A report that does not distinguish these is not defensible.

---

## Hints

<details>
<summary>Hint 1 — the probe app cannot see the target package</summary>

From Android 11, package visibility is restricted. Add the `<queries>` block shown above. Without it,
`ComponentName` resolution silently fails and you will misread the result as "not reachable".

```xml
<queries><package android:name="com.example.target" /></queries>
```
</details>

<details>
<summary>Hint 2 — sendBroadcast never throws</summary>

`sendBroadcast` is fire-and-forget: it returns normally even when no receiver was permitted to run.
"No exception" is not proof. Confirm by watching the **target's** logcat, or by using an ordered
broadcast with a result receiver:

```java
sendOrderedBroadcast(i, null, new BroadcastReceiver() {
    @Override public void onReceive(Context c, Intent in) {
        Log.i(TAG, "result=" + getResultCode() + " data=" + getResultData());
    }
}, null, 0, null, null);
```
</details>

<details>
<summary>Hint 3 — everything says DENIED</summary>

Check the target is actually installed and the component names are exact — a typo produces the same
`ActivityNotFoundException` as a genuinely unreachable component. Print what you resolved:

```java
Log.i(TAG, String.valueOf(getPackageManager().resolveActivity(i, 0)));
```
</details>

<details>
<summary>Hint 4 — content query returns nothing from the shell either</summary>

The authority may differ from the package name. Read it from the manifest:

```bash
grep -oE 'android:authorities="[^"]*"' work/AndroidManifest.xml
```
</details>

---

## Solution

<details>
<summary>Answers</summary>

**Q1.** Exported components with no `permission` attribute are the working list. A component guarded by
a `signature`-level permission is reachable only by an app signed with the same key, which for a
third-party attacker means not at all.

**Q2–Q3.** All three should agree. If they do not, the platform (`dumpsys`) is authoritative and the
disagreement is itself a high-value finding — see [10-APK-Internals](../../10-APK-Internals/README.md).
A component with an `<intent-filter>` and no explicit `android:exported` is **implicitly exported** on
`targetSdk` below 31; from 31 the attribute is mandatory and the app would not have installed without
it. So the answer depends on the app's `targetSdk`, which is why that value is the first thing you
check in any manifest audit.

**Q8.** All four are injection points, and `--sort` is the one automated tools most often miss because
scanners tend to fuzz `selection` only. A SQL error message surfacing through any of them is a
confirmed injection.

**Q10–Q11.** This is the whole lab. Typical outcome: several components launch fine from `adb shell`
and throw `SecurityException` from the probe app, because `shell` holds privileges — notably around
starting components and reading providers — that an ordinary app does not. Every one of those would
have been a false positive.

**Q12.** State the provenance of each piece of evidence. "Reachable from `adb shell`" and "reachable
from an unprivileged third-party application" are different claims with different severities, and
conflating them is the fastest way to have a report dismissed.

</details>

---

## Success criteria

- [ ] You produced a complete exported-component inventory from `dumpsys`
- [ ] You cross-checked it against `apktool` and `aapt2` and reconciled any difference
- [ ] You determined the effective export state of filtered components with no explicit attribute
- [ ] You exercised every exported activity, receiver, service and provider from `adb shell`
- [ ] You tested all four provider injection points, including `--sort`
- [ ] You built and ran an **unprivileged probe app** with no permissions
- [ ] You produced the side-by-side reachability table
- [ ] You identified how many `shell`-only components would have been false positives
- [ ] Every finding distinguishes shell evidence from app evidence
- [ ] You can explain, in one sentence, why `adb shell` reachability is not proof
