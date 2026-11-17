# 26 — Intent · FAQ

Real questions, including the ones people are embarrassed to ask. Answers are direct; the long
version is always in [README.md](README.md).

---

### 1. What actually *is* an Intent? Is it a function call?

No. It is a **data object** — a message. It has twelve fields (an action string, a data URI, a MIME
type, categories, an optional target component, flags, extras and a few others) and it does nothing
at all on its own. You can create one, print it, put it in a list and throw it away.

It becomes an *operation* only when you hand it to something that sends it: `startActivity`,
`startActivityForResult`, `startService`, `bindService`, `sendBroadcast`. At that moment the system —
`system_server`, running as UID 1000 — takes over, works out who should receive it, checks whether
you are allowed to send it there, and delivers it.

The distinction matters because it explains the whole security model. A function call happens in your
process with your stack. An Intent leaves your process, passes through a privileged referee, and
arrives somewhere else as *data*. See [README §1](README.md#1-introduction).

---

### 2. What is the difference between an action and a category? They look the same.

They are both strings, they both live in `<intent-filter>`, and they are both reverse-DNS names. The
difference is what they mean and how they are matched.

**Action = the verb.** What you want done: `VIEW`, `SEND`, `EDIT`, `DIAL`. An Intent has **exactly
one** action (or none).

**Category = an adjective about the receiver.** How the component will be used, or what kind of thing
it is: `LAUNCHER` means "put me in the app drawer", `BROWSABLE` means "a browser may start me",
`OPENABLE` means "the URIs I return can be opened as streams". An Intent has **zero or more**.

The matching rules differ, and this is the part people get wrong:

- **Action:** if the Intent has one, the **filter must list it**. One action, one lookup.
- **Category:** **every** category on the Intent must appear on the filter. Categories the filter
  declares that the Intent does not name are ignored.

So a filter with ten categories is not "harder to match" than one with two — it is *easier*, because
matching only ever iterates the Intent's categories, never the filter's.

---

### 3. Why does my implicit Intent open a chooser dialog?

Because more than one installed component matched it, and there is no recorded preference for which
one wins.

Find out who is competing:

```bash
# host
adb shell "cmd package query-activities -a android.intent.action.VIEW -d 'https://example.com/x'"
```

If you see two or more entries, that is your answer. The `priority`, `preferredOrder` and `match`
values printed for each explain the ordering.

Three ways it stops being a chooser:

- The user picks "always" for one app (a preference is recorded).
- One of the apps has a **verified App Link** for that host, which routes exclusively with no dialog.
- You make the Intent explicit or package-restricted, in which case there is only one candidate.

If a chooser appears where you did not expect one, treat it as a security observation, not a bug:
something else on the device is claiming your Intent.

---

### 4. Can I see who sent me an Intent?

Almost always: **no**, and this is the single most consequential fact in the chapter.

The one narrow exception is `Activity.getCallingActivity()`, which returns the caller's
`ComponentName` — but **only** if they used `startActivityForResult`. A plain `startActivity` gives
you `null`.

Things that look like they answer the question and do not:

- `getReferrer()` and `Intent.EXTRA_REFERRER` — the caller writes these. Forgeable in one line.
- Any extra called `"caller"`, `"from"`, `"source"` — the caller writes these too.
- `Binder.getCallingUid()` inside `onCreate` or `onReceive` — **returns your own UID.** The identity
  stamp exists on the Binder transaction into `system_server`, not on the later delivery from
  `system_server` to you. Code that checks this always passes and its authors always believe it works.

What *does* work:

- A `signature`-level permission on the component. `system_server` enforces it before your code runs,
  and only apps signed by your key can hold it.
- A bound `Service`: inside a Binder transaction, `Binder.getCallingUid()` is live and unforgeable.
- `PendingIntent.getCreatorUid()` / `getCreatorPackage()` on a token somebody handed you — the system
  fills these in.

See [README §3.8](README.md#38-caller-identity--the-honest-answer).

---

### 5. What does `exported` really change?

Exactly one comparison, inside `system_server`. When a component is not exported, `ActivityStarter`
refuses the start unless `Binder.getCallingUid()` equals the target application's UID.

Everything else people believe about it is wrong:

- It does **not** affect matching. A non-exported component with a rich `<intent-filter>` still sits
  in the resolver tables and still appears in `dumpsys package`.
- It does **not** hide the component. Its class name is in the manifest, readable by anyone.
- It does **not** stop the app itself, or any app sharing its UID via `sharedUserId`.
- It does **not** stop a *redirection* attack, because by the time a vulnerable deputy calls
  `startActivity`, the calling UID **is** the victim's.

And the converse: `exported="true"` is a **precondition** for a finding, never a finding on its own.
You still have to prove reachability from an unprivileged app and demonstrate a consequence.

---

### 6. Why did my deep link stop working after I installed another app?

Because a custom URI scheme has no owner. Android imposes no uniqueness constraint: any app may
declare `myapp://` and the platform will happily list both as candidates. The newly installed app
either won a chooser, or a preference got recorded for it, or your app's preference was reset by the
install.

Check the current state:

```bash
# host — API 31+
adb shell "pm get-app-links com.example.target"
# host — API 30 and below
adb shell "pm get-app-link com.example.target"
adb shell "dumpsys package domain-preferred-apps" | grep -A3 com.example.target
```

The only real fix is a **verified App Link**: an `https` filter with `android:autoVerify="true"`, plus
a correctly-served `https://<host>/.well-known/assetlinks.json` naming your package and your
*release* signing certificate. Then the platform routes those links to you exclusively, and no
competing app can take them.

If the target is an OAuth redirect, this is not a cosmetic problem — it is
[45-OAuth lab-03](../45-OAuth/labs/lab-03-scheme-hijack.md).

---

### 7. My `adb shell am start` fails but the app's own navigation works. Is the component protected?

Probably not. Run through these in order:

1. **`CATEGORY_DEFAULT`.** `startActivity` adds it to implicit Intents. If the filter does not declare
   it, no implicit start can ever match. Try `-n <pkg>/<class>` instead — if that works, the component
   is reachable explicitly and your implicit test was the problem, not the target.
2. **Quoting.** `adb shell` hands your line to the *device's* shell. `*`, `;`, `&`, `?` and `$` are
   metacharacters there. Wrap the whole command in one set of quotes and use inner quotes for
   arguments. A `;` in an `intent:` URI silently truncates the command and the error looks like a
   resolution failure.
3. **Look at logcat.** `adb logcat | grep -E 'Permission Denial|ActivityNotFound|SecurityException'`
   tells you which of the three it was: not exported, permission required, or nothing matched.
4. **Check the class name.** R8 renames classes; the manifest names the *renamed* class. Read the
   name out of `dumpsys package <pkg>`, never out of a JADX source tree.

---

### 8. What is intent redirection, in one paragraph?

An app has an exported component. That component takes an `Intent` out of the message it received —
usually with `getIntent().getParcelableExtra("something")` — and starts it. Because the *app* is
doing the starting, the system sees the app's UID as the caller, so the started Intent can reach the
app's own non-exported components, can use permissions the app holds and the attacker does not, and
can carry URI grants the app is entitled to issue. The attacker supplied the Intent; the victim
supplied the authority. That is the whole bug.

---

### 9. Can I demonstrate intent redirection with `adb shell am start`?

**Not the common flavour, no.** `am` has no `Parcelable` extra type — it supports strings, booleans,
ints, longs, floats, URIs, `ComponentName`s and arrays of those, and nothing else. `Intent.parseUri`
(the `intent:#Intent;...;end` syntax) has no nesting syntax either. So there is no way to put an
`Intent` inside an `Intent` from the shell.

You **can** demonstrate the *string* flavour from the shell — where the vulnerable component reads a
`String` extra or a URI query parameter and calls `Intent.parseUri` on it — because that only needs
text.

For the Parcelable flavour you need a real attacker app. That is why
[`labs/lab-01-intent-redirection.md`](labs/lab-01-intent-redirection.md) ships one, with a build
script and no Gradle.

---

### 10. Why is `adb shell` not good enough for proving reachability?

`adb shell` runs as UID 2000 (`shell`), which is a **privileged** identity. It holds several
`signature|privileged` permissions, it is exempt from some background-start restrictions, and on many
builds it can start components an ordinary third-party app cannot.

So "I reached it with `am start`" proves the component exists and does something. It does not prove
an attacker can reach it. A developer who knows this will reject your finding, and they will be
right.

The fix is mechanical: build a two-file attacker APK that does nothing but `startActivity` the
target, install it, and run it. Then run the **negative control** — point the same app at a component
you know is non-exported and show the `Permission Denial` in logcat. That proves your harness would
have noticed a failure, which is what makes the positive result credible.

---

### 11. What does `FLAG_IMMUTABLE` actually stop?

A `PendingIntent` is a token that wraps an Intent **plus your app's identity**. Whoever holds it can
call `send()`, and the system fires the wrapped Intent **as you**.

`send()` accepts a *fill-in* Intent. The system merges it into the wrapped one using `Intent.fillIn`,
whose rule is: a field is taken from the fill-in only if the base Intent's field is unset. So if you
created the token wrapping `new Intent()` — no component, no action, no data — the holder can set all
three, and the system will start whatever they chose, as you, including your own non-exported
components.

`FLAG_IMMUTABLE` makes the system ignore the fill-in entirely. From `targetSdk` 31 you must pass
either `FLAG_IMMUTABLE` or `FLAG_MUTABLE` explicitly, or the constructor throws. That did not fix
anything by itself — plenty of code was "fixed" by pasting `FLAG_MUTABLE` to make the build pass —
but it did make every mutable token a visible, greppable decision.

If you genuinely need mutability (a notification `RemoteInput` reply is the classic case), keep the
wrapped Intent's **component explicit**. Then the only thing the filler-in can contribute is extras.

---

### 12. How do multiple `<data>` elements in one filter combine? I assumed pairs.

They do not pair. Each `<data>` element dumps its attributes into four **independent sets** on the
filter: schemes, authorities (host + port), paths, and MIME types. Matching then tests each set
separately. The result is a **cross product**.

```xml
<data android:scheme="https" android:host="a.example.com"/>
<data android:scheme="myapp"  android:host="b.example.com"/>
```

That filter accepts `https://a.example.com`, `https://b.example.com`, `myapp://a.example.com` **and**
`myapp://b.example.com`. The developer meant two; the platform read four.

You can see the platform's own data structure confirming this:

```bash
# host
adb shell "dumpsys package com.android.chrome" | sed -n '/Activity Resolver Table/,/Receiver/p'
```

It prints one filter with a flat list of `Scheme:` lines and a flat list of `StaticType:` lines. Two
lists, not a list of pairs.

For a tester this is a finding generator: enumerate the combinations the developer never intended and test those, because the handling code usually branches on scheme *or* host, not both.

---

### 13. `android:pathPattern` is a regex, right?

No, and this misconception is responsible for a lot of broken filters and a few vulnerabilities.

`pathPattern` is a **glob** with two metacharacters:

- `*` — zero or more of the **immediately preceding character**.
- `.*` — zero or more of *any* character (because `.` is "any character" and `*` repeats it).

So `/a*b` matches `/b`, `/ab`, `/aab`, `/aaab`. It does **not** mean "a, then anything, then b".
There are no anchors, no character classes, no `+`, no `?`.

If you want something regex-like, API 31 added `android:pathAdvancedPattern`, which supports `\d`,
character ranges, `+`, `*` and `?`. Below API 31 the honest options are `path` (exact),
`pathPrefix` (prefix — and remember `/open` also matches `/openredirect`) and `pathSuffix` (31+).

---

### 14. My app's `assetlinks.json` is deployed but the link still opens a chooser. Why?

Six causes, in rough order of frequency:

1. **The fingerprint is from the debug certificate.** If the app ships through Play App Signing,
   Google re-signs it and the digest changes. Take the fingerprint from the *released* artefact:
   `apksigner verify --print-certs app.apk | grep -i 'SHA-256 digest'`, or from the Play Console.
2. **`package_name` mismatch.** Build flavours add suffixes (`com.example.app.prod`). The file must
   name the *installed* package.
3. **A redirect.** The platform fetches over HTTPS and does not follow a redirect to a different
   host. A CDN that redirects `example.com` to `www.example.com` breaks it.
4. **Content type / JSON validity.** It must be valid JSON served as `application/json`.
5. **Verification has not run.** Force it: `adb shell "pm verify-app-links --re-verify PKG"`
   (API 31+).
6. **You are on Android 11 or earlier** and reading the wrong tool's output — `pm get-app-links` does
   not exist there. Use `pm get-app-link PKG` and `dumpsys package domain-preferred-apps`.

---

### 15. Why can't I send an implicit Intent to a Service any more?

From API 21, `startService`/`bindService` with an implicit Intent throws `IllegalArgumentException`.
The reasoning is that services have no UI and no chooser, so an implicit service Intent silently
picks a winner the user never sees — the worst possible combination.

Two things to note as a tester. First, the check lives in `ContextImpl.validateServiceIntent`, in
**your** process — it is a client-side guard, not an enforcement boundary. Second, it is irrelevant
to an attacker: an attacker always knows exactly which component they want and is therefore always
explicit. Do not report the presence of this check as a mitigation.

---

### 16. Is an exported activity automatically a vulnerability?

No, and reporting it as one is the fastest way to lose credibility.

Two questions decide it:

1. **Reachability.** Can an ordinary, unprivileged, third-party app start it? Not `adb shell` — an
   app. If it is behind a `signature`-level permission, the answer is no. If it is behind a `normal`
   one, the answer is yes, because any app can request and receive a `normal` permission.
2. **Consequence.** What does it do with the Intent? An exported Activity that reads a string extra
   and puts it in a `TextView` is not a vulnerability. One that starts a nested Intent, loads a URL
   into a WebView, writes an attacker-named file, or changes account state, is.

Write both answers into the finding. That is the difference between a report and a scanner dump.

---

### 17. What is the difference between a deep link and an App Link?

A **deep link** is any URI that opens a screen in an app. It can use any scheme. It is **not
exclusive** — anybody can declare the same filter.

An **App Link** is a specific, stronger thing: an `https` filter with `android:autoVerify="true"`
*whose verification has succeeded*. The platform fetched
`https://<host>/.well-known/assetlinks.json` over TLS and confirmed it names your package and your
signing certificate. Verified App Links route exclusively, with no chooser.

The critical nuance: `autoVerify="true"` in a manifest is a **request**, not a state. An app with
`autoVerify` and no deployed `assetlinks.json` behaves exactly like an ordinary deep link. That gap —
between what the manifest claims and what the device recorded — is invisible in the APK and is
frequently the finding. Measure it on a device.

---

### 18. What is a `PendingIntent` for, if it is so dangerous?

It solves a real problem that has no other solution: **another process needs to perform an action as
you, later.**

The notification shade is drawn by `system_server`. When the user taps your notification,
`system_server` must start your Activity — including a non-exported one. It has no way to do that as
you. So you hand it a `PendingIntent`: a token holding your Intent plus your identity. It fires the
token, and the start is attributed to you.

The same mechanism serves `AlarmManager` (fire this in an hour), `AppWidget` (run this when the
widget is tapped), `JobScheduler`, `MediaSession` and every "call me back when you're done" flow
between apps.

It is dangerous only when the wrapped Intent is under-specified and the token is mutable. A
`PendingIntent` wrapping an explicit Intent, created `FLAG_IMMUTABLE`, is one of the safest
constructs on the platform — and, usefully, it is the only Intent-adjacent mechanism where the
*receiver* can learn who created it, via `getCreatorUid()`.

---

### 19. How do I find dynamically registered receivers? They are not in the manifest.

You cannot, statically, with any reliability — which is why a manifest audit alone never enumerates
an app's full receiver surface.

Two approaches:

**Static:** grep the decompiled sources for `registerReceiver` and read the `IntentFilter` constructed
next to each call. Doable, but easy to miss when the filter is built dynamically.

**Dynamic:** hook it.

```javascript
// Frida — sketch; the full version is in scripts/intent-monitor.js
var ContextWrapper = Java.use("android.content.ContextWrapper");
ContextWrapper.registerReceiver.overload(
  "android.content.BroadcastReceiver", "android.content.IntentFilter")
  .implementation = function (r, f) {
    console.log("[registerReceiver] " + (r ? r.$className : "null") + "  filter=" + f.toString());
    return this.registerReceiver(r, f);
  };
```

Note the version rule: below `targetSdk` 33, a context-registered receiver for a non-system broadcast
is **effectively exported** and nothing in the manifest says so. From 33 the app must pass
`RECEIVER_EXPORTED` or `RECEIVER_NOT_EXPORTED`, which at least makes the decision explicit in code.

---

### 20. Why does `setData` followed by `setType` break my Intent?

Because each of those two setters **nulls the other field**. It is a genuine API wart, dating from a
time when data and type were considered alternative descriptions of the same thing.

```java
intent.setData(uri);
intent.setType("application/pdf");   // uri is now null
```

Use `setDataAndType(uri, type)` when you need both. The symptom is a filter that requires a scheme
*and* a MIME type never matching, with no error anywhere — resolution just returns nothing and you
get `ActivityNotFoundException` or a silent no-op.

---

### 21. Which chapter owns what? I keep finding Intent material in three places.

Deliberate division of labour:

| You want | Go to |
|---|---|
| The `<intent-filter>` **declaration**: every attribute, export defaults, the `targetSdk` matrix, an automated manifest audit | [32-Manifest](../32-Manifest/README.md) §3.10 and its `scripts/manifest-audit.py` |
| The **runtime message** and the **matching algorithm** — what this chapter is | Here |
| What a laundered `content://` **grant steals**, and provider exploitation | [27-ContentProviders](../27-ContentProviders/README.md) §5.4 |
| A staged **scheme-hijack attack** against an OAuth redirect | [45-OAuth lab-03](../45-OAuth/labs/lab-03-scheme-hijack.md) |
| **Kernel-stamped caller identity** and Binder transactions | Chapter 25 — Binder |
| Intents among Android's IPC mechanisms generally | [24-IPC](../24-IPC/README.md) |
| `protectionLevel` and why `normal` is not a control | [23-Permissions](../23-Permissions/README.md) |

If you find the same content in two of these, one of them is wrong; the boundaries above are the
intended ones.
