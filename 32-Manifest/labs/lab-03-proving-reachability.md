# Lab 03 — Proving Reachability

**Difficulty:** Intermediate
**Time:** 2–3 hours
**Prerequisites:** [Lab 02](lab-02-full-audit.md),
[77-UsefulCommands Lab 03 — the exported-surface sweep](../../77-UsefulCommands/labs/lab-03-exported-sweep.md),
Android Studio or a working Gradle command line, a device or emulator

---

## Objective

Take the exported components you found in [Lab 02](lab-02-full-audit.md) and **prove** which of them
are genuinely reachable by an ordinary, unprivileged application — as opposed to reachable only by
your privileged `adb shell`. Then demonstrate task hijacking with a second app, because that class
cannot be proven from a manifest at all.

You will finish with a side-by-side reachability table and, more importantly, a habit.

## Why this matters

**This is the discipline lab.** It exists because the single most common reason a manifest finding is
rejected is that it was proven from `adb shell`.

> **Definition**
> `adb shell` executes as the Unix user `shell`, **UID 2000**. That user is not root, but it is not an
> app either: it holds a set of privileges — notably around starting components, reading providers
> and querying package state — that an ordinary third-party application does not have. It also has
> full package visibility, which apps lost at `targetSdk` 30.

So `am start -n com.victim/.InternalActivity` succeeding tells you that **UID 2000** can start that
component. It does not tell you that an attacker's app can. Those are different claims, with
different severities, and conflating them is the fastest way to have a report dismissed — correctly.

> **Pentester's Note**
> The sentence that separates a finding from an observation is: *"Reproduced from an unprivileged
> third-party application holding no permissions."* If you cannot write that sentence, you have a
> lead, not a finding. Say so explicitly in the report — a report that states what it did **not**
> prove is more credible, not less.

The companion lab [77-UsefulCommands Lab 03](../../77-UsefulCommands/labs/lab-03-exported-sweep.md)
teaches the same methodology from the command-reference side, and builds a simpler probe app. This
lab goes further: it adds provider write and `call()`, deep links delivered as a browser would
deliver them, `PendingIntent` handling, and a second APK for the task-hijacking demonstration.

---

## Setup

```bash
# host
export PKG=com.example.target      # your Lab 02 target
adb shell pm path $PKG
adb logcat -c
```

Keep a second terminal open on the **target's** log, not yours — several of the checks below can only
be confirmed from the target side:

```bash
# host
adb logcat --pid=$(adb shell pidof -s $PKG | tr -d '\r') -v threadtime
```

Have your Lab 02 inventory to hand. You need, for every component: type, fully-qualified name,
effective `exported` value, and guarding permission with its resolved `protectionLevel`.

---

## Steps

### Step 1 — Establish the shell baseline

Do this first, and label every result as **shell evidence**.

```bash
# adb shell — activities
am start -n $PKG/.SomeActivity
am start -n $PKG/.SomeActivity --es url "https://example.org/"
am start -W -n $PKG/.SomeActivity              # -W waits and prints the result

# adb shell — receivers
am broadcast -n $PKG/.SomeReceiver -a com.example.target.ACTION_SYNC --es data x

# adb shell — services
am start-service -n $PKG/.SomeService --es cmd test

# adb shell — providers
content query  --uri content://com.example.target.provider/items
content insert --uri content://com.example.target.provider/items --bind name:s:probe
content call   --uri content://com.example.target.provider --method getSecret
content read   --uri content://com.example.target.provider/files/config.xml
```

**Question 1.** Build the shell column of your table: for each component, `LAUNCHED`, `DENIED` (with
the exception text), or `ERROR`.

**Question 2.** `am broadcast` printed `Broadcast completed: result=0`. Does that prove the receiver
ran? What does it actually tell you?

### Step 2 — Build the unprivileged probe app

This app declares **no permissions at all**. That is the point: anything it can reach, any malicious
app on the Play Store can reach.

**`app/src/main/AndroidManifest.xml`**

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android">

    <!--
      REQUIRED from Android 11 (targetSdk 30). Without this block, package
      visibility filtering makes the target invisible: ComponentName resolution
      silently fails and you will misread the result as "not reachable".
      This is the number one mistake in this lab.
    -->
    <queries>
        <package android:name="com.example.target" />
        <provider android:authorities="com.example.target.provider" />
    </queries>

    <!-- No <uses-permission> anywhere. Deliberately. -->

    <application android:label="Probe" android:allowBackup="false">
        <activity android:name=".ProbeActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
```

**`app/src/main/java/com/probe/ProbeActivity.java`**

```java
package com.probe;

import android.app.Activity;
import android.content.BroadcastReceiver;
import android.content.ComponentName;
import android.content.ContentValues;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.os.IBinder;
import android.util.Log;

import java.io.InputStream;
import java.util.Arrays;

/**
 * Unprivileged reachability probe.
 *
 * Every method below answers ONE question: "can an app with no permissions do
 * this?" It records LAUNCHED / DENIED / ERROR and never guesses. A caught
 * SecurityException is a RESULT, not a failure — it is the evidence that a
 * shell-only finding would have been a false positive.
 */
public class ProbeActivity extends Activity {

    private static final String TAG    = "PROBE";
    private static final String TARGET = "com.example.target";
    private static final String AUTH   = "com.example.target.provider";

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);

        Log.i(TAG, "=== unprivileged probe: uid=" + android.os.Process.myUid() + " ===");

        // 0. Can we even SEE the target? If not, every result below is meaningless.
        checkVisibility();

        // 1. Activities — explicit component, attacker-shaped extras.
        tryActivity(".SomeActivity",     "url",   "https://example.org/");
        tryActivity(".InternalActivity", "admin", "true");

        // 2. Deep links — exactly as a browser would deliver them.
        tryDeepLink("targetapp://open?next=https://example.org/");
        tryDeepLink("https://app.example.com/open/1?next=https://example.org/");

        // 3. Broadcasts — ordered, so we can actually observe delivery.
        tryOrderedBroadcast("com.example.target.ACTION_LOGOUT");
        tryOrderedBroadcast("com.example.target.ACTION_SET_ENDPOINT");

        // 4. Services — start AND bind. Binding is the one that matters.
        tryStartService(".SomeService");
        tryBindService(".AdminService");

        // 5. Providers — read, write, call, and openFile. All four.
        tryProviderQuery("content://" + AUTH + "/items");
        tryProviderInsert("content://" + AUTH + "/items");
        tryProviderCall("getSecret");
        tryProviderOpen("content://" + AUTH + "/files/config.xml");
    }

    /* ------------------------------------------------------------------ */

    private void checkVisibility() {
        try {
            android.content.pm.PackageInfo pi =
                getPackageManager().getPackageInfo(TARGET, 0);
            Log.i(TAG, "VISIBILITY  -> target visible, versionCode=" + pi.versionCode);
        } catch (Exception e) {
            Log.e(TAG, "VISIBILITY  -> TARGET NOT VISIBLE: " + e);
            Log.e(TAG, "  Add a <queries> entry for " + TARGET + " or every result below");
            Log.e(TAG, "  is a false negative. This is not the target being secure.");
        }
    }

    private void tryActivity(String cls, String extraKey, String extraVal) {
        String label = "ACTIVITY  " + cls;
        try {
            Intent i = new Intent();
            i.setComponent(new ComponentName(TARGET, TARGET + cls));
            i.putExtra(extraKey, extraVal);
            i.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            startActivity(i);
            Log.i(TAG, label + " -> LAUNCHED (genuinely reachable by an unprivileged app)");
        } catch (SecurityException e) {
            Log.i(TAG, label + " -> DENIED: " + e.getMessage());
        } catch (android.content.ActivityNotFoundException e) {
            Log.i(TAG, label + " -> NOT FOUND (not exported, or the name is wrong — check both)");
        } catch (Exception e) {
            Log.i(TAG, label + " -> ERROR: " + e);
        }
    }

    private void tryDeepLink(String uri) {
        String label = "DEEPLINK  " + uri;
        try {
            Intent i = new Intent(Intent.ACTION_VIEW, Uri.parse(uri));
            i.addCategory(Intent.CATEGORY_BROWSABLE);
            i.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            // Resolve first, so we learn WHICH app would handle it.
            ComponentName cn = i.resolveActivity(getPackageManager());
            Log.i(TAG, label + " -> resolves to " + cn);
            startActivity(i);
            Log.i(TAG, label + " -> DELIVERED");
        } catch (Exception e) {
            Log.i(TAG, label + " -> " + e);
        }
    }

    private void tryOrderedBroadcast(final String action) {
        final String label = "BROADCAST " + action;
        try {
            Intent i = new Intent(action);
            i.setPackage(TARGET);
            i.putExtra("url", "https://example.org/");
            // Ordered with a result receiver: sendBroadcast alone never throws
            // and never tells you whether anything ran.
            sendOrderedBroadcast(i, null, new BroadcastReceiver() {
                @Override public void onReceive(Context c, Intent in) {
                    Log.i(TAG, label + " -> resultCode=" + getResultCode()
                             + " data=" + getResultData());
                }
            }, null, 0, null, null);
            Log.i(TAG, label + " -> SENT (see result above; and confirm in the TARGET's log)");
        } catch (SecurityException e) {
            Log.i(TAG, label + " -> DENIED: " + e.getMessage());
        }
    }

    private void tryStartService(String cls) {
        String label = "SERVICE-START " + cls;
        try {
            Intent i = new Intent();
            i.setComponent(new ComponentName(TARGET, TARGET + cls));
            startService(i);
            Log.i(TAG, label + " -> STARTED");
        } catch (SecurityException e) {
            Log.i(TAG, label + " -> DENIED: " + e.getMessage());
        } catch (Exception e) {
            Log.i(TAG, label + " -> ERROR: " + e);
        }
    }

    private void tryBindService(String cls) {
        final String label = "SERVICE-BIND " + cls;
        try {
            Intent i = new Intent();
            i.setComponent(new ComponentName(TARGET, TARGET + cls));
            boolean ok = bindService(i, new ServiceConnection() {
                @Override public void onServiceConnected(ComponentName c, IBinder b) {
                    Log.i(TAG, label + " -> BOUND. IBinder=" + b);
                    Log.i(TAG, "   descriptor=" + describe(b));
                    // From here: IYourAidl.Stub.asInterface(b) and call every method.
                }
                @Override public void onServiceDisconnected(ComponentName c) { }
            }, Context.BIND_AUTO_CREATE);
            Log.i(TAG, label + " -> bindService returned " + ok
                     + " (false means the bind was refused)");
        } catch (SecurityException e) {
            Log.i(TAG, label + " -> DENIED: " + e.getMessage());
        }
    }

    private static String describe(IBinder b) {
        try { return b.getInterfaceDescriptor(); }
        catch (Exception e) { return "<" + e + ">"; }
    }

    private void tryProviderQuery(String uri) {
        String label = "PROVIDER-QUERY " + uri;
        try (Cursor c = getContentResolver().query(Uri.parse(uri), null, null, null, null)) {
            if (c == null) { Log.i(TAG, label + " -> null cursor"); return; }
            Log.i(TAG, label + " -> READABLE, " + c.getCount() + " rows, columns="
                     + Arrays.toString(c.getColumnNames()));
            if (c.moveToFirst()) {
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < c.getColumnCount(); i++) {
                    sb.append(c.getColumnName(i)).append('=').append(c.getString(i)).append(' ');
                }
                Log.i(TAG, "   first row: " + sb);
            }
        } catch (SecurityException e) {
            Log.i(TAG, label + " -> DENIED: " + e.getMessage());
        } catch (Exception e) {
            Log.i(TAG, label + " -> ERROR: " + e);
        }
    }

    private void tryProviderInsert(String uri) {
        String label = "PROVIDER-INSERT " + uri;
        try {
            ContentValues v = new ContentValues();
            v.put("name", "probe-" + System.currentTimeMillis());
            Uri out = getContentResolver().insert(Uri.parse(uri), v);
            Log.i(TAG, label + " -> WRITABLE, new uri=" + out);
            Log.i(TAG, "   NOTE: write is gated by writePermission, NOT readPermission.");
        } catch (SecurityException e) {
            Log.i(TAG, label + " -> DENIED: " + e.getMessage());
        } catch (Exception e) {
            Log.i(TAG, label + " -> ERROR: " + e);
        }
    }

    private void tryProviderCall(String method) {
        String label = "PROVIDER-CALL " + method;
        try {
            Bundle out = getContentResolver().call(
                    Uri.parse("content://" + AUTH), method, null, null);
            Log.i(TAG, label + " -> RETURNED " + (out == null ? "null" : out.toString()));
            if (out != null) {
                for (String k : out.keySet()) Log.i(TAG, "   " + k + " = " + out.get(k));
            }
        } catch (SecurityException e) {
            Log.i(TAG, label + " -> DENIED: " + e.getMessage());
        } catch (Exception e) {
            Log.i(TAG, label + " -> ERROR: " + e);
        }
    }

    private void tryProviderOpen(String uri) {
        String label = "PROVIDER-OPEN " + uri;
        try (InputStream in = getContentResolver().openInputStream(Uri.parse(uri))) {
            byte[] buf = new byte[256];
            int n = in == null ? -1 : in.read(buf);
            Log.i(TAG, label + " -> OPENED, first " + n + " bytes: "
                     + new String(buf, 0, Math.max(n, 0)));
        } catch (SecurityException e) {
            Log.i(TAG, label + " -> DENIED: " + e.getMessage());
        } catch (Exception e) {
            Log.i(TAG, label + " -> ERROR: " + e);
        }
    }
}
```

Build, install, run:

```bash
# host
./gradlew assembleDebug
adb install -r app/build/outputs/apk/debug/app-debug.apk
adb logcat -c
adb shell am start -n com.probe/.ProbeActivity
adb logcat -s PROBE:I
```

**Question 3.** Did `VISIBILITY` report the target as visible? If not, stop and fix the `<queries>`
block — every subsequent result is a false negative.

### Step 3 — The table that is the point of this lab

| Component | Reachable from `adb shell` (UID 2000) | Reachable from an unprivileged app | Verdict |
|---|---|---|---|
| | | | |

**Question 4.** How many components were reachable from `shell` but **not** from the probe app? Those
are the false positives you would have reported.

**Question 5.** Was anything reachable from the app but **not** from the shell? What could cause that?

**Question 6.** For each `DENIED` result, quote the `SecurityException` message. What exactly did the
platform enforce — a component permission, a URI permission, a signature check, or package
visibility?

### Step 4 — Acquire the "protecting" permissions

Your Lab 02 audit found components guarded by custom permissions. If any of those resolved to
`normal`, an attacker asks for them. Prove it.

Add to the probe app's manifest:

```xml
<uses-permission android:name="com.example.target.permission.READ_DATA" />
<uses-permission android:name="com.example.target.permission.ADMIN" />
```

Rebuild, reinstall, re-run, and check what is granted:

```bash
# host
adb shell dumpsys package com.probe | sed -n '/requested permissions/,/install permissions/p'
adb shell dumpsys package com.probe | grep -A20 'runtime permissions'
```

**Question 7.** Which of the requested custom permissions were granted **automatically**, with no
prompt? Which components became reachable as a result?

**Question 8.** This is the finding that developers dispute hardest. Write the two sentences you would
say in the debrief meeting, and attach the four lines of attacker manifest that make it undeniable.

> **Warning — the `development` flag false positive**
> A permission whose `protectionLevel` includes `development` can be granted from the shell with
> `pm grant`, **even though a real attacker could not obtain it**. If you granted anything by hand,
> that result does not count. Re-run with a freshly installed probe and no manual grants.

### Step 5 — Deep links delivered as a browser would

An `am start` from the shell is not the same as a link click in Chrome. Prove the remote path.

```bash
# host — 1. what does the platform think of the app's link claims?
adb shell pm get-app-links $PKG

# host — 2. who would actually handle the URL?
adb shell pm resolve-activity --brief \
    -a android.intent.action.VIEW -c android.intent.category.BROWSABLE \
    -d "https://app.example.com/open/1"
```

Then do it for real. Put a page on a local web server:

```html
<!-- probe.html -->
<h1>Deep link probe</h1>
<a href="targetapp://open?next=https://example.org/">custom scheme</a><br>
<a href="https://app.example.com/open/1?next=https://example.org/">https app link</a><br>
<iframe src="targetapp://open?next=https://example.org/" width="1" height="1"></iframe>
<script>
  // A page can also navigate without user interaction.
  // setTimeout(() => location = "targetapp://open?next=https://example.org/", 3000);
</script>
```

```bash
# host
python3 -m http.server 8000
adb reverse tcp:8000 tcp:8000
adb shell am start -a android.intent.action.VIEW -d "http://localhost:8000/probe.html"
```

Tap the links in the device's browser and watch the target's log.

**Question 9.** Did the link reach the target app? Was there a disambiguation dialog? What did
`pm get-app-links` report for the `https` domain — `verified`, or something else?

**Question 10.** If the link reached a `WebView`, you have converted a local finding into a **remote**
one. What does that do to the severity, and what is the minimum evidence you need to claim it?

### Step 6 — Task hijacking, with a second app

This class cannot be proven from a manifest. It needs two apps and a user action.

**Attacker `AndroidManifest.xml`** — one Activity, no permissions:

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application android:label="Free Wallpapers" android:allowBackup="false">
        <activity
            android:name=".HijackActivity"
            android:exported="true"
            android:launchMode="singleTask"
            android:taskAffinity="com.example.target"
            android:excludeFromRecents="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
```

`HijackActivity` needs no interesting code — a layout that visually imitates the victim's login
screen and a `Log.i` on `onResume` is enough for the demonstration. **Do not** capture real
credentials, even your own; log the fact of focus, not the input.

```bash
# host
adb install -r hijack.apk

# 1. Launch the attacker once, under any pretext.
adb shell am start -n com.hijack/.HijackActivity
adb shell input keyevent KEYCODE_HOME

# 2. Now launch the VICTIM from the launcher, exactly as a user would.
adb shell monkey -p $PKG -c android.intent.category.LAUNCHER 1

# 3. Which Activity is actually in the foreground?
adb shell dumpsys activity activities | grep -E 'mResumedActivity|topResumedActivity'
adb shell dumpsys activity activities | grep -A4 'Task{' | head -40
```

**Question 11.** Which Activity is resumed after step 2? Whose task is it in? Show the `dumpsys` line
that proves it.

**Question 12.** Now change the victim's `taskAffinity` — if you control the build — to `""` and
repeat. What changes, and why?

**Question 13.** Try the same on a device running Android 11 or later with the victim targeting API
30+. Does it still work? What does that mean for the severity you report?

> **Warning**
> Test task hijacking only against an app you own or are explicitly authorised to test, on a device
> you own, with no real credentials present. The demonstration is a *screenshot of the wrong Activity
> in the foreground*, not a credential capture.

### Step 7 — Write the reachability section of your report

For each finding, state three things separately and explicitly:

1. **What was proved from `adb shell` (UID 2000).**
2. **What was proved from an unprivileged application holding no permissions.**
3. **What was not proved, and what it would take.**

**Question 14.** Take the two findings you wrote at the end of Lab 02 and rewrite them with this
provenance. How does the severity change?

---

## Hints

<details>
<summary>Hint 1 — everything from the probe app says NOT FOUND</summary>

In order of likelihood:

1. **Missing `<queries>`.** From Android 11 the target is invisible without it and `ComponentName`
   resolution fails silently. The `checkVisibility()` method exists precisely to catch this.
2. **Wrong class name.** A typo produces the same `ActivityNotFoundException` as a genuinely
   unreachable component. Print what you resolved:
   ```java
   Log.i(TAG, String.valueOf(getPackageManager().resolveActivity(i, 0)));
   ```
3. **A leading dot.** `TARGET + ".SomeActivity"` is right; `TARGET + "SomeActivity"` is not.
</details>

<details>
<summary>Hint 2 — `sendBroadcast` never throws, so I cannot tell</summary>

Use `sendOrderedBroadcast` with a result receiver, as the probe does. Even then, "no result" is not
"did not run" — the receiver may not set one. The authoritative confirmation is always the
**target's** own log:

```bash
# host
adb logcat --pid=$(adb shell pidof -s com.example.target | tr -d '\r')
```
</details>

<details>
<summary>Hint 3 — the provider query returns nothing from the shell either</summary>

The authority is often not the package name. Read it from the manifest:

```bash
# host
grep -oE 'android:authorities="[^"]*"' work/AndroidManifest.xml
adb shell dumpsys package $PKG | grep -A3 'Provider Resolver Table'
```
</details>

<details>
<summary>Hint 4 — the task-hijack demo does not work</summary>

Check, in order: the attacker's `taskAffinity` exactly equals the victim's **package name** (not its
`applicationId` if they differ); the attacker Activity really launched once before you launched the
victim; you launched the victim **from the launcher** (`monkey -c LAUNCHER`), not with
`am start -n`, because the launcher path is what triggers task reuse; and the victim does not already
declare `taskAffinity=""`. Android 11 and later tightened the rules considerably, so a
negative result on a modern device is a legitimate outcome — report it as such.
</details>

<details>
<summary>Hint 5 — bindService returns true but onServiceConnected never fires</summary>

`bindService` returning `true` only means the system accepted the request. The bind can still fail
afterwards. Watch logcat for `SecurityException` from `ActivityManager`, and check whether the target
service's `onBind` returns `null` — a service that returns `null` is started but exposes no
interface, which is a materially weaker finding.
</details>

---

## Solution

<details>
<summary>Answers</summary>

**1–2.** `Broadcast completed: result=0` means the *shell command* completed. It says nothing about
whether any receiver was permitted to run or did run. `sendBroadcast` is fire-and-forget by design.
Confirm from the target's log or with an ordered broadcast and a result receiver.

**3.** Without `<queries>`, `getPackageInfo` throws `NameNotFoundException` and every component
lookup fails. Reading that as "the target is secure" is the single most common way this lab produces
a wrong answer — and, on a real engagement, a false negative that hides a genuine finding.

**4–5.** Typical outcome: several components launch fine from `adb shell` and throw
`SecurityException` from the probe app. Each of those would have been a false positive. The reverse —
reachable from the app but not from the shell — is rarer and usually means the app supplied something
the shell command did not (a required extra, a category, a `Uri` grant), or that a background-start
restriction applied to the shell invocation. Investigate rather than assuming.

**6.** Read the message text. `Permission Denial: starting Intent … requires
com.example.permission.X` is a component permission. `Permission Denial: reading
com.example.Provider uri content://… requires com.example.permission.Y, or grantUriPermission()` is
a provider permission and tells you a grant would also work. `NameNotFoundException` is package
visibility, not a security boundary you have hit.

**7–8.** Any custom permission whose `protectionLevel` is `normal` — including one where the
attribute was omitted entirely — is granted automatically at install with no prompt. The two
sentences: *"This permission's protection level is `normal`, which means the platform grants it to
any application that declares it, with no user prompt and no signature check. Here is the four-line
manifest of an app that obtains it, and here is that app reading your data."* The fix is
`android:protectionLevel="signature"`.

**9–10.** If `pm get-app-links` reports anything other than `verified` for a domain, the filter is an
ordinary deep link rather than an App Link, and a competing app can register the same filter. A
`BROWSABLE` filter reachable from a web page converts a local finding into a remote one, which
usually doubles the severity — and the minimum evidence is a hosted page you control plus a
demonstration that clicking (or an iframe loading) reaches the component with your data in it.

**11–13.** On a device where the class is live, `mResumedActivity` names the **attacker's** Activity
after the user launches the victim from the launcher, and the task shown by `dumpsys activity
activities` carries the victim's affinity string. Setting `taskAffinity=""` on the victim removes the
affinity there is to steal and the attack stops working. Android 11 tightened task-reuse rules
substantially, so a modern device plus a modern `targetSdk` frequently defeats the naive version —
report exactly what you observed on the versions you tested, and say which versions those were. A
"works on Android 9, not on Android 14" result is a *better* finding than a bare claim, because it
tells the client which of their users are affected.

**14.** Severity usually falls for anything you could only reach from the shell, and rises for
anything you reached from an unprivileged app, because the second claim needs no preconditions the
attacker cannot meet. Stating the provenance is what makes both numbers defensible.

</details>

---

## Success criteria

- [ ] You recorded a shell baseline and labelled it explicitly as shell evidence
- [ ] You built and installed a probe app that declares **no permissions**
- [ ] The probe confirmed package visibility before testing anything else
- [ ] You probed activities, deep links, ordered broadcasts, `startService` **and** `bindService`
- [ ] You probed providers on all four surfaces: query, insert, `call` and `openFile`
- [ ] You produced the side-by-side reachability table
- [ ] You counted how many `shell`-only results would have been false positives
- [ ] You quoted the `SecurityException` text for every denial and identified what was enforced
- [ ] You demonstrated automatic grant of a `normal`-level custom permission
- [ ] You delivered a deep link from an actual web page in the device browser
- [ ] You built a second app and demonstrated (or disproved) task hijacking, with `dumpsys` evidence
- [ ] Every finding you wrote states separately what shell proved, what the app proved, and what
      remains unproven
- [ ] You can explain in one sentence why `adb shell` reachability is not proof
