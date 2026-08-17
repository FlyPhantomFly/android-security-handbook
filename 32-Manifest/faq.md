# 32 — Manifest · FAQ

Real questions, answered directly. Including the ones people are embarrassed to ask.

---

**1. Why can't I just open `AndroidManifest.xml` in a text editor after unzipping the APK?**

Because inside an APK it is not text. AAPT2 compiles it into Android Binary XML (AXML) — a chunked
binary format with a string pool and typed values. Unzipping gets you the compiled form, which looks
like garbage in an editor.

```bash
apktool d -f app.apk -o work/        # decodes AXML back to readable XML
aapt2 dump xmltree app.apk --file AndroidManifest.xml
```

See [10-APK-Internals](../10-APK-Internals/README.md) for the format itself.

---

**2. Why do you keep insisting on reading it three ways? Isn't apktool enough?**

Usually, yes. The three-way read exists for the case where it is not.

`apktool`, `aapt2` and `PackageManager` each parse AXML with different code. A crafted manifest can
make them disagree — showing `debuggable="false"` to your tools while the platform installs a
debuggable app. When they disagree, **the platform is right**, and the disagreement itself is a
high-value finding because it means the APK was built to evade analysis.

It costs thirty seconds. Do it on anything you do not trust.

---

**3. What is the single first thing I should look at?**

`targetSdkVersion`.

It is not a compatibility detail — it silently changes the *default security behaviour* of half the
attributes below it. Whether components are exported by default, whether cleartext HTTP is allowed,
whether `PendingIntent` mutability must be explicit, whether user-added CAs are trusted: all of it
keys off `targetSdk`.

Reading `android:exported` without knowing `targetSdk` gives you the wrong answer on older apps.

---

**4. A component has an `<intent-filter>` but no `android:exported`. Is it exported?**

It depends on `targetSdk`, which is exactly why question 3 matters.

Below targetSdk 31, a component with an intent filter is **implicitly exported**. From targetSdk 31,
`android:exported` is **mandatory** when a filter is present — the app will not install without it.

So on a modern app the attribute is always there. On an older one, absence means exported, which is
the opposite of what people intuitively assume.

---

**5. What does `android:debuggable="true"` actually give an attacker?**

`run-as`. Anyone with USB access can run commands as that app's UID:

```bash
adb shell run-as com.example.target sh -c 'tar czf - .' > appdata.tgz
```

That is the app's entire private data directory — databases, SharedPreferences, tokens, everything —
with no root required. JDWP also becomes attachable, so a debugger can be connected to the process.

On a production build it is a High finding, and it is not rare.

---

**6. `allowBackup="true"` is the default. Is it a finding?**

Only if the app stores something worth extracting. The default being `true` means most apps have it,
and reporting it reflexively is noise.

The finding is `allowBackup="true"` **plus** sensitive local state — a session token, credentials,
PII — because `adb backup` (where still supported) extracts it without root. Demonstrate the
extraction, then report.

Note also `android:dataExtractionRules` (Android 12+), which splits cloud backup from device-to-device
transfer. An app can permit one and not the other, so read the rules file rather than assuming.

---

**7. What is `<activity-alias>` and why do you say to audit it separately?**

An alias is a second name for an existing activity, with its **own** `android:exported` and
`android:permission`.

That means an alias can expose a target activity that is itself `exported="false"`. Auditors who
enumerate `<activity>` elements and stop there miss it entirely. It is an easy and genuinely
overlooked way for a component to be reachable.

---

**8. What is `<path-permission>` and why do you call it subtle?**

It applies permissions to specific URI paths within a provider, and it can **widen** access as well
as narrow it.

The trap: if a `<path-permission>` grants a weaker permission for a path than the provider's blanket
`android:permission`, that path becomes *more* accessible. And any path not covered by a
`<path-permission>` falls back to the provider-level permission — so a mistaken assumption that
"paths not listed are denied" is backwards.

Read every one carefully, and test the paths rather than reasoning about them.

---

**9. `root-path` in a FileProvider — how bad is it?**

Bad. `<root-path name="root" path="." />` maps the FileProvider onto the filesystem root, so any
file the app can read becomes shareable by URI.

Combined with an intent-redirection bug — an exported component that forwards an attacker-supplied
`Intent` — it becomes arbitrary file disclosure from the app's sandbox. It is a recurring High
finding and there is almost never a legitimate reason for it.

Use the narrowest of `files-path`, `cache-path` or `external-files-path` that does the job.

---

**10. The manifest I decoded has fewer components than `dumpsys package` reports. Am I reading it wrong?**

Probably not — you are reading the **source** manifest rather than the **merged** one.

Library manifests are merged into the app's at build time, and a third-party SDK can contribute
components the app developer never wrote, including exported ones. What ships is the merged result.

```bash
find . -path '*/build/intermediates/merged_manifest*' -name AndroidManifest.xml
cat app/build/outputs/logs/manifest-merger-*-report.txt
```

From an APK you get the merged version automatically, since it is what was packaged. From source you
must go looking. See [08-Build-System](../08-Build-System/README.md).

---

**11. I launched an exported activity with `am start` and it worked. Is that a finding?**

**No** — not yet, and this is the single most common false positive in Android reports.

`adb shell` runs as UID 2000 (`shell`), which holds privileges an ordinary app does not. Components
you can start from a shell may be entirely unreachable by a malicious app.

Build a minimal probe app with no permissions, try the same thing, and see whether it throws
`SecurityException`. Only then do you have a claim. [Lab 03](labs/lab-03-proving-reachability.md)
walks through it.

---

**12. Why does my probe app get `ActivityNotFoundException` when the component clearly exists?**

Package visibility. From targetSdk 30, an app cannot see other packages unless it declares them:

```xml
<queries>
    <package android:name="com.example.target" />
</queries>
```

Without that, resolution silently fails and you will misread it as "not reachable" — a false
negative that is just as wrong as the false positive in question 11.

---

**13. Where do API keys hide in a manifest?**

`<meta-data>`. SDKs conventionally read their configuration from it, so keys for maps, analytics,
crash reporting and ad networks routinely sit there in plaintext.

```bash
grep -oE '<meta-data[^>]*' work/AndroidManifest.xml
```

Whether a given key is a finding depends on what it authorises. A Google Maps API key is designed to
be client-visible and is only a finding if it is unrestricted. Validate before reporting — see
[52-StaticAnalysis](../52-StaticAnalysis/README.md).

---

**14. What is `sharedUserId` and why is it deprecated?**

It lets two or more apps signed with the same key share one Linux UID, and therefore one sandbox —
they can read each other's data directly.

It is deprecated because it makes the security boundary coarser: compromising the weakest app in the
set compromises all of them. It also cannot be removed later without breaking existing installs,
which is why you still meet it.

When you see it, enumerate every app sharing the UID and assess them as one unit.

---

**15. A custom permission with `protectionLevel="signature"` protects my component, right?**

Usually, but there is a real trap: **a custom permission is only as strong as the app that defines
it, and the first definition on the device wins**.

If a malicious app is installed *before* yours and defines the same permission name with
`protectionLevel="normal"`, that weaker definition can take effect. Your component ends up guarded by
a permission any app can hold.

This is permission squatting. See [23-Permissions](../23-Permissions/README.md).

---

**16. Why does `CATEGORY_DEFAULT` keep appearing in intent filters?**

Because an implicit intent cannot reach an activity without it.

The matching rule is: the action must match, and **every** category in the intent must be present in
the filter. `startActivity()` with an implicit intent automatically adds `CATEGORY_DEFAULT`, so a
filter lacking it will never match.

That also means adding it to a filter that did not have it *widens* the component's reachability —
worth noticing when auditing.

---

**17. `android:name` on `<application>` is a class I have never heard of. Does that matter?**

Possibly a great deal. That class's `attachBaseContext()` is the earliest app-controlled code in the
process, which makes it the natural home for a packer's decryption stub.

If it is `com.example.MyApplication`, fine. If it is `com.stub.a` or a name from a known protector,
you are probably looking at a packed app and your whole approach changes. See
[40-Obfuscation](../40-Obfuscation/README.md).

---

**18. What is `<instrumentation>` doing in a production manifest?**

It should not be there. It declares a test runner, and in a shipped build it means test scaffolding
survived into production. Depending on what the instrumentation does, it can be a way to execute code
in the app's context.

Low-to-Medium on its own, but it is a strong signal about the team's build hygiene — worth mentioning
alongside `testOnly` and `debuggable`.

---

**19. `usesCleartextTraffic` is absent. Is cleartext allowed or not?**

Depends on `targetSdk` again. From targetSdk 28 cleartext is **denied** by default; below that it is
allowed. And a `networkSecurityConfig` overrides both.

So "absent" means "check `targetSdk`, then check whether a network security config exists, then read
that config". Three steps, and skipping any of them gives the wrong answer. See
[44-NetworkSecurityConfig](../44-NetworkSecurityConfig/README.md).

---

**20. How do I know which permissions actually matter?**

Map each one to *what an attacker gains if this app is compromised*. That converts a list into an
assessment.

Ones worth flagging on sight because they confer disproportionate capability:
`SYSTEM_ALERT_WINDOW` (overlays → tapjacking), `BIND_ACCESSIBILITY_SERVICE` (full UI control),
`REQUEST_INSTALL_PACKAGES` (install other apps), `MANAGE_EXTERNAL_STORAGE` (all files),
`PACKAGE_USAGE_STATS` (behavioural surveillance), `QUERY_ALL_PACKAGES` (device fingerprinting).

Also check `android:maxSdkVersion` on each — a permission requested only up to some API level is easy
to skim past.

---

**21. My manifest audit script flags forty things. How do I prioritise?**

By demonstrated impact, not by count.

Work in this order: things that grant an attacker code execution or full data access (`debuggable`,
exported components performing sensitive actions); then data exposure (providers, backup); then
weakened transport (cleartext, network config); then hardening gaps (missing `FLAG_SECURE`, no
obfuscation).

And **validate every automated hit before it enters a report**. A scanner's output is a list of
leads. Turning forty leads into six confirmed findings is the work.

---

**22. Runtime-registered receivers do not appear in the manifest. How do I find them?**

You cannot, from the manifest — you have to read the code or hook at runtime.

```bash
grep -rn "registerReceiver" work/smali*/
```

From targetSdk 33 they must pass `RECEIVER_EXPORTED` or `RECEIVER_NOT_EXPORTED`, so the flag is
visible at the call site. At runtime, `dumpsys activity broadcasts` shows what is currently
registered. See [29-BroadcastReceivers](../29-BroadcastReceivers/README.md).

---

**23. Is there a fast way to do all of this?**

```bash
python3 scripts/manifest-audit.py app.apk
```

It applies the `targetSdk` matrix, checks every attribute in the chapter, and produces a
severity-rated table. Then use [`scripts/frida-manifest-runtime.js`](scripts/frida-manifest-runtime.js)
to compare against what `PackageManager` actually parsed.

But run the manual audit by hand at least a few times first. The script encodes judgements; you need
to be able to tell when one of them is wrong for the app in front of you.

---

**24. What is the one habit that most improves manifest auditing?**

Reading `targetSdk` before anything else, every single time.

Everything downstream — export defaults, cleartext policy, storage model, PendingIntent mutability,
receiver export — is conditioned on it. Auditors who skip it produce findings that are correct for
some other app.
