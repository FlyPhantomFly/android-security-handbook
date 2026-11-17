# 32 — AndroidManifest.xml · Examples

Every file here is an **audit target or an audit reference**, not a runnable project. They reference
classes and resources that do not exist in this directory. That is deliberate: the point is to read
manifests, and a real APK's manifest also references code you have not seen yet.

---

## The files

| File | What it is | Read it when |
|---|---|---|
| [`vulnerable-manifest.xml`](vulnerable-manifest.xml) | 34 planted issues plus 3 deliberate non-findings | You are doing [Lab 02](../labs/lab-02-full-audit.md) |
| [`vulnerable-manifest-ANSWERS.md`](vulnerable-manifest-ANSWERS.md) | The annotated answer key: vulnerable code → why developers write it → detection → exploit → fix as code → honest severity | **After** you have audited by hand |
| [`secure-manifest.xml`](secure-manifest.xml) | The corrected counterpart. Every decision commented with *why* | You need to write a remediation |
| [`enterprise-manifest.xml`](enterprise-manifest.xml) | An MDM-managed app: device admin, managed configuration, cross-profile provider | You are testing an enterprise or MDM app |
| [`AdminService.java`](AdminService.java) | The code behind the exported service in the vulnerable manifest, plus its secure rewrite | You want to see why "exported Service" is worse than "exported Activity" |
| [`file_paths_insecure.xml`](file_paths_insecure.xml) | A `FileProvider` `<paths>` resource with five defects | You found `android.support.FILE_PROVIDER_PATHS` in a manifest |
| [`file_paths_secure.xml`](file_paths_secure.xml) | The corrected `<paths>` resource, plus the code half that a correct `<paths>` file does not give you | You need to write the fix |

---

## Suggested order

1. **Audit `vulnerable-manifest.xml` by hand.** Use the checklist in
   [README §5.6](../README.md#56-how-pentesters-test-it--the-manifest-audit-checklist).
   Write down every finding with a severity, on paper, before you touch a tool.

2. **Run the script and diff your list against it.**

   ```bash
   # host
   python3 ../scripts/manifest-audit.py vulnerable-manifest.xml
   python3 ../scripts/manifest-audit.py vulnerable-manifest.xml --min-severity HIGH
   python3 ../scripts/manifest-audit.py vulnerable-manifest.xml --markdown > findings.md
   ```

   Every difference is either a gap in your process or a gap in the script. Work out which — the
   script is not authoritative, and it says so itself.

3. **Read the answer key.** It is structured so that each finding teaches the *class*, not the
   instance.

4. **Read `secure-manifest.xml` next to it.** The remediation half is what turns an audit into a
   report a team will act on.

5. **Then do the same on a real APK from your own phone**, three times. That is the assignment at the
   end of [README §12](../README.md#12-hands-on-labs), and it is what turns the checklist into
   instinct.

---

## Three things these files cannot teach you

> **Warning**
> Everything in this directory is a *declaration*. A manifest audit bounds the **static** attack
> surface and nothing more.

| Not visible in any manifest | Where you get it |
|---|---|
| Context-registered `BroadcastReceiver`s — effectively exported below `targetSdk` 33 | [`scripts/frida-manifest-runtime.js`](../scripts/frida-manifest-runtime.js) → `mf.watchReceivers()` |
| Components enabled or disabled at runtime | `adb shell dumpsys package <pkg>`; grep the DEX for `setComponentEnabledSetting` |
| What `ContentProvider.call()` exposes | Decompile the provider; [27-ContentProviders](../../27-ContentProviders/README.md) |
| Whether a `<meta-data>` value is a live credential | Use it, or say explicitly that you could not validate it |
| **Whether an exported component is genuinely attacker-reachable** | [Lab 03](../labs/lab-03-proving-reachability.md) — an unprivileged probe app |

> **Pentester's Note**
> That last row is the one that gets reports rejected. `adb shell` runs as UID 2000 and holds
> privileges an ordinary application does not. Reaching a component from `adb shell` is an
> observation. Reaching it from an app with no permissions is a finding. Keep the two claims separate
> in your notes and separate in your report.

---

## Safety

Every credential-shaped string in `vulnerable-manifest.xml` is fabricated and is not live. Every
insecure construct is there to be audited, not copied. Do not lift any part of the vulnerable files
into a real project, and do not test any of these techniques against an application you are not
authorised to test.
