# Worked example — one finding, mapped twice

> **Illustrative artefact.** The app and the evidence filenames are invented; the two write-ups and
> the difference between them are drawn from a pattern that recurs in real reports.

The same observation, written up two ways. Version A is what mechanical mapping produces: pick the
control whose words match, take a severity off a table, ship it. Version B is what happens when you
ask what the finding actually *is* first, and map afterwards.

The point of this document is not that Version B is longer. It is that **Version B reaches a
different answer** — a different severity, a different control set, and a different remediation. A
mechanical mapping is not a shorter version of a considered one. It is frequently a wrong one.

---

## The raw observation

```text
# host -- data directory diff across a full feature exercise
$ diff -rq before/ after/ | grep shared_prefs
Files before/shared_prefs/auth.xml and after/shared_prefs/auth.xml differ
```

```xml
<!-- /data/data/com.northfield.retail/shared_prefs/auth.xml -->
<map>
    <string name="refresh_token">eyJhbGciOiJI…</string>
    <boolean name="biometric_enabled" value="true" />
</map>
```

Two facts, both plainly visible. A refresh token sits in a plain preferences file. A boolean next to
it says biometric unlock is enabled.

---

## Version A — mapped mechanically

```markdown
## F-03 Sensitive data stored insecurely

**Severity:** Medium
**MASVS:** MASVS-STORAGE-1
**Affected:** com.northfield.retail 5.8.1

### Summary
The application stores a refresh token in SharedPreferences without encryption. An attacker with
physical access to an unlocked or rooted device could recover the token.

### Steps to reproduce
1. Log in to the application.
2. Run `adb shell run-as com.northfield.retail cat shared_prefs/auth.xml`.
3. Observe the `refresh_token` value in plaintext.

### Impact
Sensitive data stored on the device may be recovered by an attacker with device access.

### Remediation
Use `EncryptedSharedPreferences` or store the value in the Android KeyStore.
```

This is not a bad finding. It is true, correctly mapped, and reproducible. A competent reader would
accept it. It would also survive review at most firms, which is exactly why it is worth taking apart.

---

## What Version A gets wrong

Six things, in ascending order of how much they matter.

| # | Problem | Consequence |
|---|---|---|
| 1 | **Reproduction requires `run-as`** | `run-as` only works on a debuggable build. If the shipped build is not debuggable, these steps do not reproduce, and the client's developer will say so |
| 2 | **"An attacker with device access" is not a threat model** | It is the *category* of attacker. Which attacker, with what starting position? A thief with a locked phone and a fraud actor with an unlocked one are different findings |
| 3 | **Severity was inherited, not argued** | "Local storage issue → Medium" is a lookup. Nothing about *this* token entered the calculation |
| 4 | **The `biometric_enabled` line was not read** | It was three lines away in the same file and it changes the finding |
| 5 | **Only one control considered** | The observation touches at least two, and possibly a third |
| 6 | **The remediation may not fix anything** | `EncryptedSharedPreferences` moves the token behind a KeyStore key. If that key has no user-authentication requirement, an attacker with code execution as the app still gets the token. The fix addresses the symptom, not the property that was missing |

> **🧠 Mental Model**
> Mechanical mapping asks "which control does this look like?" Considered mapping asks "what is
> actually true about this system, and which controls does that touch?" The first question has one
> answer and it is often the wrong one. The second has several and they are all useful.

---

## The questions that were not asked

Version B is what you get by asking six questions of the observation before writing anything.

| Question | How to answer it | What it turned up here |
|---|---|---|
| What *is* this token? | Decode it; read the API's session behaviour | A refresh token with a 30-day lifetime, no device binding, and no rotation on use |
| What does it get an attacker? | Replay it from a different device | A full access token, from any device, no re-authentication |
| Is it anywhere else? | Search the whole data directory, memory, logs, backups | Also present in an unencrypted WebView cookie store, and included in `adb backup` output |
| Is anything relying on it being protected? | Read the code near it | The biometric gate. Its only job is to protect access to this token, and it is bypassed by reading the file |
| Does the server compensate? | Test revocation, rotation, anomaly detection | No revocation on logout; token stays valid until expiry |
| Who is the attacker, concretely? | Threat model | Not "someone with the device" — a device-resale buyer, a repair technician, and any app-level code execution on a rooted device |

The fourth question is the one that changes everything, and it was answerable from a line three lines
below the one that was reported.

---

## Version B — mapped after thinking

```markdown
## F-03 Refresh token stored unprotected, defeating the biometric gate that depends on it

**Severity:** High
**MASVS:** MASVS-STORAGE-1 (primary), MASVS-AUTH-2 (the biometric gate is decorative as a
  consequence), MASVS-STORAGE-2 (the same value leaves the device via backup)
**MASTG:** the tests covering local storage of sensitive data and local authentication on Android —
  identifiers resolved 2026-07-14, see the methodology section
**Standard version:** MASVS v2.x, resolved 2026-07-14
**Affected:** com.northfield.retail 5.8.1 (50801), APK SHA-256 a41c…, Pixel 6 / Android 14
**Status:** Confirmed, exploited from a second device

### Summary
The application stores a 30-day refresh token in a plain preferences file. The token is not bound to
the device, is not rotated on use, and is not revoked at logout, so anyone who reads the file obtains
persistent access to the customer's account from any device until the token expires. The application
also offers a biometric unlock, whose only function is to gate access to this token — reading the
file bypasses it entirely, so the biometric control provides no security property it appears to
provide.

### Threat model
Three concrete attackers, in decreasing order of prerequisites:

1. **A buyer of a resold or repaired device.** The app's data directory survives a factory reset on
   some OEM implementations, and survives a repair entirely. No root, no unlock code.
2. **Any code executing with the app's UID on a rooted device.** Includes the user themselves, and
   any malware that has obtained root.
3. **Anyone with USB access and the ability to run `adb backup`,** because the value is also carried
   in the backup stream (see Evidence E-12b).

None of the three require the device to be unlocked at the moment of attack, because the token has a
30-day life and no device binding.

### Technical detail
`/data/data/com.northfield.retail/shared_prefs/auth.xml` contains `refresh_token` as a plain string.
The adjacent `biometric_enabled` boolean is read by `AuthGateActivity`, which calls
`BiometricPrompt.authenticate()` without a `CryptoObject`; its `onAuthenticationSucceeded` callback
sets a field and proceeds. No key operation is bound to the biometric result, so the biometric
outcome and the token's availability are independent. Decompiled source in Evidence E-33.

The token decodes to a JWT with `exp` 30 days from issue and no device or installation claim.
Replayed from an unrelated device it yields a valid access token (Evidence E-12c).

### Steps to reproduce
1. Log in on device A and enable biometric unlock.
2. Extract the file. **Two independent routes, so the finding does not depend on a debuggable
   build:**
   a. Rooted device: `adb shell "su -c 'cat /data/data/com.northfield.retail/shared_prefs/auth.xml'"`
   b. Non-rooted: `adb backup -f out.ab com.northfield.retail`, unpack, read `shared_prefs/auth.xml`
3. On device B, with no prior session, POST the token to the refresh endpoint (Evidence E-12c).
4. Observe a valid access token returned, and full account access.
5. On device A, log out. Repeat step 3. Observe that it still succeeds.

### Evidence
- `E-12`  data-directory diff and the file contents
- `E-12b` `adb backup` extraction showing the same value leaving the device
- `E-12c` request/response pair proving cross-device replay, redacted
- `E-33`  decompiled `AuthGateActivity` and the runtime biometric trace

### Impact
Persistent account takeover from any device, for up to 30 days, from a single file read — with no
re-authentication and no server-side revocation path available to the customer. The biometric unlock
the customer believes protects their account contributes nothing.

### Remediation
Three changes, in priority order. The first is necessary; the first alone is not sufficient.

1. **Bind the token to a KeyStore key created with `setUserAuthenticationRequired(true)`**, and gate
   the biometric prompt on a `CryptoObject` wrapping that key. This makes the biometric control
   actually protect the token, which is what the current design only appears to do.
2. **Revoke refresh tokens server-side on logout, and rotate on use** so that a captured token has a
   single-use lifetime rather than a 30-day one.
3. **Exclude the preferences file from backup** via `dataExtractionRules`, covering both
   `<cloud-backup>` and `<device-transfer>`.

Note that applying only change 1 leaves an exfiltrated token valid for 30 days, and applying only
change 2 still leaves the biometric gate decorative. They address different halves.

### References
- MASVS-STORAGE-1, MASVS-STORAGE-2, MASVS-AUTH-2 — resolved 2026-07-14
- Android developer guidance on `BiometricPrompt` with `CryptoObject`
- Android developer guidance on `dataExtractionRules`
```

---

## The two versions side by side

| | Version A | Version B |
|---|---|---|
| Severity | Medium | **High** |
| Controls cited | STORAGE-1 | STORAGE-1, STORAGE-2, AUTH-2 |
| Attacker | "someone with device access" | Three named, with starting positions |
| Reproduction | One route, requires a debuggable build | Two independent routes, neither requiring one |
| Persistence | Not considered | 30 days, no revocation, no rotation |
| Cross-device | Not considered | Proven |
| Effect on other controls | Not considered | Renders the biometric gate decorative |
| Remediation | One line, may not fix it | Three changes, with a statement of why each alone is insufficient |
| Would a scanner produce it? | **Yes** | No |

The last row is the one that matters commercially. Version A is producible by a tool plus a lookup
table. If your report is made of Version A findings, a client is paying a professional rate for
something they could have automated — and the day they notice is the day you lose the account.

---

## What changed the answer

Not effort, and not length. **Four specific moves**, each of which is repeatable:

| Move | In this finding |
|---|---|
| **Read what is next to the thing you found** | `biometric_enabled` was three lines below `refresh_token` in the same file, and it changed the severity and the control set |
| **Ask what the value gets an attacker, not what it is** | "A token in plaintext" is an observation. "Account takeover from any device for 30 days" is a finding |
| **Find a second reproduction route** | The `adb backup` route removed the "only on a debuggable build" objection before anyone raised it |
| **Ask which of the app's own controls now do nothing** | This is the highest-yield question in mobile security and almost nobody asks it. A protection that depends on a broken assumption is a second finding hiding inside the first |

---

## The opposite failure

Version B is not "more". Over-elaboration is its own defect, and it is what happens when a tester
learns this lesson and over-applies it.

| Over-elaboration | Why it is also wrong |
|---|---|
| Rating a finding High because the write-up is long | Length is not evidence. The severity must follow from the threat model and nothing else |
| Citing five controls where one is violated and four are adjacent | Citing a control implies you assessed it. Four decorative citations dilute the one that matters and invite a reviewer to check all five |
| Speculating about impact you did not demonstrate | "An attacker could potentially pivot to…" is a hypothesis. Either prove it or label it as a hypothesis explicitly |
| Turning one finding into six to raise the count | The client is buying risk reduction, not a finding count. Related issues with one root cause are one finding with one fix |
| Inventing a control ID to make the mapping look complete | The single worst thing in this document's subject area. A wrong control ID is worse than none, because the reader follows it and then distrusts everything else |

The test for whether elaboration earned its place: **does it change what the client does?** Version
B's biometric analysis changes the remediation. A paragraph on the theoretical properties of JWTs
would not.

---

## Related

| Where | For |
|---|---|
| [`labs/lab-02-map-a-known-app.md`](../labs/lab-02-map-a-known-app.md) | Producing evidence of the kind Version B cites |
| [`labs/lab-03-find-the-gap.md`](../labs/lab-03-find-the-gap.md) | The finding that maps to no control at all — the next step past this one |
| [`assessment-result-table.md`](assessment-result-table.md) | Where F-03 lands in the coverage table |
| [80-Appendix §5](../../80-Appendix/README.md#5-severity-cvss-and-business-impact) | The severity rubric, and why "who, what, under what conditions" comes before any number |
| [80-Appendix §6](../../80-Appendix/README.md#6-report-templates) | The finding template both versions are built on |
| [49-KeyStore](../../49-KeyStore/README.md) | `setUserAuthenticationRequired` and `CryptoObject` binding, which is what remediation 1 actually requires |
