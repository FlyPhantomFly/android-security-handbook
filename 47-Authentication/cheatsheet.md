# 47 — Authentication · Cheat Sheet

Dense reference. Prose lives in [README.md](README.md).

---

## The one rule

> The party that **benefits** from the answer must never be the party that **computes** it.
> The app benefits. The server computes.

## The one test

```bash
# Replay ONE authenticated request without the app. This sets the severity
# of every other finding you will write.
curl -sS -i https://api.example.invalid/api/v1/dashboard -H 'User-Agent: okhttp/4.12.0'
```

| Result | Finding | Title it against |
|---|---|---|
| 401/403 | client-side gate bypass, **Informational** | the app (briefly) |
| 200 with data | missing server authorisation, **High–Critical** | **the endpoint** |

---

## Altitude ladder

| # | Decision lives in | Defeated by | Bypass severity |
|---|---|---|---|
| A | a boolean in memory | one Frida line | = whatever is behind it |
| B | a value on disk | `pm clear`, root, `run-as` | as A, but persistent |
| C | a credential the app holds | extract it | scope × lifetime |
| D | a credential the app can only *use* | code execution in-process | meaningfully higher |
| E | a server decision per request | **not bypassable on device** | target state |

Obfuscation moves nothing up this ladder. It makes A harder to *find*.

---

## Order of operations

```
1. proxy the app, capture the whole flow
2. replay without the app  <-- decides everything
3. only now: Frida / patching / storage
```

---

## Command reference

### Device posture — run before trusting anything

```bash
adb devices -l
adb shell getprop ro.build.version.release; adb shell getprop ro.build.version.sdk
adb shell dumpsys lock_settings | grep -E 'CredentialType|Quality|SID'   # no lock => no auth-bound keys
adb shell "dumpsys trust" | grep -o "deviceLocked=[01]"                  # keyguard blocks activity starts
adb shell mount | grep cacerts                                           # modified store => TLS tests lie
adb shell settings get secure autofill_service
adb shell service list | grep -iE 'credential|autofill|account|lock_settings'
```

### Static

```bash
apktool d -f -o out app.apk
python3 -B scripts/auth-surface-scan.py *.apk --verbose

# platform types survive R8; the app's own names do not
grep -rn 'Landroid/accounts/AccountManager;'      out/smali*/
grep -rn 'Landroidx/credentials/'                 out/smali*/
grep -rn 'Landroid/view/autofill/AutofillManager;' out/smali*/
grep -rn 'com/google/android/gms/fido'            out/smali*/

# the ONLY textual trace FLAG_SECURE leaves
grep -rn -B4 'Landroid/view/Window;->setFlags' out/smali*/ | grep -E '0x2000|8192'

# manifest
grep -nE 'GET_ACCOUNTS|READ_SMS|RECEIVE_SMS|BIND_NOTIFICATION_LISTENER|allowBackup|debuggable|autoVerify' \
     out/AndroidManifest.xml
grep -n -A3 'android.accounts.AccountAuthenticator' out/AndroidManifest.xml

# layouts
grep -rn -E 'inputType|autofillHints|importantForAutofill' out/res/layout/ | grep -iE 'pass|pin|otp|code'
```

### Dynamic

```bash
frida -U -f com.example.app -l scripts/auth-hooks.js
adb logcat -c && adb logcat | grep -iE 'password|token|bearer|otp|session|credential'
adb shell run-as com.example.app cat shared_prefs/session.xml
adb shell pm clear com.example.app          # then relaunch: still logged in?
adb shell screencap -p /sdcard/p.png        # black on the login screen = FLAG_SECURE

objection -g com.example.app explore
  android hooking list activities
  android intent launch_activity com.example.app.DashboardActivity
  android hooking set return_value com.example.app.Session.isLoggedIn true
```

### This chapter's scripts

```bash
python3 -B scripts/auth-surface-scan.py *.apk --json out.json
bash      scripts/accountmanager-audit.sh -s <serial>
python3 -B scripts/sms-retriever-hash.py app.apk
python3 -B scripts/enum-timing-probe.py --url <u> --known <a> --unknown <b> --samples 40
python3 -B scripts/session-lifecycle-probe.py --base https://api.example.invalid

python3 -B labs/authlab/auth_server.py --mode vulnerable   # port 8047
python3 -B labs/authlab/auth_server.py --mode secure --port 8048
python3 -B labs/ctf/vault_auth.py --verify
```

---

## Session lifecycle tests

| # | Test | Method | Severity if it fails |
|---|---|---|---|
| T1 | logout revokes | capture → logout → replay | **High** (CWE-613) |
| T2 | password change revokes others | 2 sessions, change in one, replay other | **High** (CWE-620) |
| T3 | "all devices" revokes | 2 sessions, logout/all, replay other | **High** |
| T4 | absolute lifetime | park a credential, retry tomorrow | Medium–High |
| T5 | pre-MFA credential rejected | present `mfa_token` at a data endpoint | **Critical** |
| T6 | per-object authorisation | account A's credential, account B's object id | High–Critical (CWE-639) |
| T7 | step-up on sensitive ops | ordinary session → money movement | High (CWE-306) |

**Session lifetime = lifetime of the longest-lived credential in the chain.**
1 h access + 90 d refresh = a **90-day session**.

---

## Enumeration — four oracles

| # | Channel | Survives "fix the message"? |
|---|---|---|
| 1 | response body | no |
| 2 | status code | **yes** |
| 3 | response length | **yes** |
| 4 | **response time** | **yes** — the early return skips the KDF |

**Fix:** a dummy verifier computed once at boot, so the KDF runs on both paths; one identical
message; and a rate limiter that treats non-existent accounts the same, or *it* becomes the
oracle.

**Measured** (lab server, 30 samples): vulnerable **+69.2 ms**, cleanly separated. Secure
**+10.9 ms**, interquartile ranges overlapping → **INCONCLUSIVE**. Refusing to call the second
one is the correct behaviour.

---

## OTP / MFA failure classes

| # | Flaw | Severity |
|---|---|---|
| 1 | OTP in the API response | **Critical** |
| 2 | OTP verified client-side | **Critical** |
| 3 | no attempt limit | **High** |
| 4 | not single-use | Medium |
| 5 | no expiry | Medium |
| 6 | predictable | Critical |
| 7 | MFA step skippable (pre-MFA token is a session) | **Critical** |
| 8 | factor 2 not bound to factor 1 | High |
| 9 | backup codes weaker | Medium |
| 10 | "remember this device" never expires | Low–Medium |

6-digit code, no limit: 10⁶ values, ~6 h at 50 req/s. With a 5-attempt cap: **0.0005%** per
challenge — so rate-limit the *challenge request* too.

---

## OTP delivery on Android

| Mechanism | Permission | Sees |
|---|---|---|
| **SMS Retriever** | **none** | ONE message matched by an 11-char hash |
| SMS User Consent | none | ONE message, after a user tap |
| `createAppSpecificSmsToken` | none | messages carrying a platform token |
| `READ_SMS`/`RECEIVE_SMS` | runtime | **the entire inbox, for ever** |
| `NotificationListenerService` | special | the OTP from the shade, **no SMS permission** |

```
hash = base64( SHA-256("<package> <hex of signing cert DER>")[0:9] )[0:11]

<#> Your code is 481203
FA+9qCX9VSu
```
Message ≤ 140 bytes, begins `<#>`, ends with the hash. Debug and release builds differ.

---

## `AccountManager` on disk

```
/data/system_ce/<user>/accounts_ce.db     0660 system:system  system_data_file
/data/system_de/<user>/accounts_de.db     0660 system:system  system_data_file
```

| Table | DB | Holds |
|---|---|---|
| `accounts` | CE | name, type, **`password` (plaintext TEXT)** |
| `authtokens` | CE | **`authtoken` (plaintext TEXT)** |
| `extras` | CE | key/value, incl. `EXP:<pkg>:<cert-sha1>:oauth2:<scope>` |
| `visibility` | DE | per-package visibility (the real ACL, API 26+) |
| `grants` | DE | legacy `ACCOUNT_ACCESS_TOKEN_TYPE` grants |
| `meta` | DE | `auth_uid_for_type:<type>` → authenticator uid (anti-hijack) |
| `debug_table` | DE | dated history + **caller uid** |

**Visibility constants:** 0 UNDEFINED · 1 VISIBLE · 2 USER_MANAGED_VISIBLE · 3 NOT_VISIBLE ·
4 USER_MANAGED_NOT_VISIBLE.

**`GET_ACCOUNTS` grants nothing since API 26.**
**`dumpsys account` masking is unconditional** — identical for root and shell.

**Measured** (Redmi M2101K6P, API 30): 4 accounts · **117 tokens, 0 JWTs**, 108 `ya29` ·
one account with a **352-char plaintext password** · 131 expiry rows, **106 expired and
retained** · max live TTL ~51 min · 17 visibility grants · 9 type→uid bindings.

---

## `FLAG_SECURE`

> **Grepping an APK for `FLAG_SECURE` has a true-positive rate of ZERO.**
> It is a `public static final int` (0x2000); javac inlines it and the name never reaches the
> `.class` file, let alone the DEX. Proven by compiling an Activity that provably sets it.

What survives:
```
0007: const/16 v0, #int 8192 // #2000
0009: invoke-virtual {v2, v0, v0}, Landroid/view/Window;.setFlags:(II)V
```

| Detect by | Reliability |
|---|---|
| string grep | **zero** |
| smali `0x2000` near `setFlags` | noisy (819 candidate sites in one 94 MB DEX) |
| Frida hook on `Window.setFlags` | **reliable, per-screen** |
| `adb shell screencap` → black image | **reliable, and it is the report evidence** |

| Stops | Does not stop |
|---|---|
| screenshot, screen record, recents thumbnail | a photograph |
| non-secure external displays | accessibility services |
| | a malicious IME |
| | anything, once the process is compromised |

Per **window**, not per app. `Dialog`s need their own. Set before the window is drawn.

---

## Device binding ladder

| Approach | Defeated by |
|---|---|
| `ANDROID_ID` in a header | one hook — **detection, not prevention** |
| random UUID in prefs | copying app data |
| software key pair in storage | root, backup, code execution |
| Keystore key, hardware-backed | code execution **in-process** (use, not extract) |
| + key attestation verified server-side | very little on the device |
| + `setUserAuthenticationRequired` | + a user-presence check |

**Measured across 17 real APKs:** OS identifier 15/17 · remote attestation 6/17 ·
**key attestation 3/17**.

---

## Honest severity

| Observation | Severity |
|---|---|
| Client gate, server re-checks | **Informational** |
| Client gate, server does *not* | **High–Critical**, titled on the endpoint |
| Session token in `SharedPreferences`, stock device | **not a finding alone** |
| ...over-scoped / long-lived / survives logout / readable by another app | Medium–High |
| **Password** persisted on device | High (argue on **reuse**) |
| Logout does not revoke | **High** |
| Password change does not revoke others | **High** |
| MFA bypass (any of flaws 1, 2, 7) | **Critical** |
| IDOR read of one record | Medium |
| IDOR enumerable across all users | **Critical** |
| IDOR write | one band above read |
| Enumeration alone | Low (rises when chained, or when existence *is* the disclosure) |
| No rate limiting | Medium (High with a 6-digit OTP) |
| Missing `FLAG_SECURE` on login | Low (Medium if a durable secret is displayed) |
| Predictable reset token | **Critical** |
| Account deletion does not delete | High — **MASVS-PRIVACY-4, not AUTH** |
| Hard-coded production credential | High–Critical |

---

## Version matrix

| API | Change |
|---:|---|
| 5 | `AccountManager` |
| 23 | runtime permissions; `setUserAuthenticationRequired` |
| **26** | **autofill framework**; **visibility replaces `GET_ACCOUNTS`**; `createAppSpecificSmsToken` |
| 28 | platform `BiometricPrompt` |
| 30 | package visibility filtering; `android.security.identity` (**not** Credential Manager) |
| 31 | `BiometricManager.Authenticators` |
| **34** | **platform `CredentialManager`**; passkeys first-class |

---

## CWE quick map

| CWE | Defect |
|---|---|
| 287 / 603 | improper / client-side authentication |
| 306 | missing authentication for a critical function |
| 307 | no throttling of authentication attempts |
| 203 / 204 | observable / response discrepancy (enumeration) |
| 256 / 522 | plaintext / insufficiently protected credentials |
| 613 | insufficient session expiration |
| 620 | unverified password change |
| 639 | authorisation bypass through a user-controlled key (IDOR/BOLA) |
| 640 | weak password recovery |
| 798 | hard-coded credentials |

MASVS: **AUTH-1** remote enforcement · **AUTH-2** local auth correctness · **AUTH-3** step-up ·
**STORAGE-1** · **PLATFORM-3** · **PRIVACY-4**.

---

## Traps

- **A sweep produces leads, not findings.** `LOCAL-GATE` hit 15/17 across real apps; that is a
  read list, not a finding list.
- **Scan every split APK.** A thin `base.apk` means the code is elsewhere.
- **Hook the platform, not the app.** Platform classes are not renamed and not inlined away.
- **A perfect patch can change nothing** — the method may be inlined or have other callers.
- **A modified system CA store** makes an intercept prove nothing about user-CA trust.
- **A locked keyguard** silently refuses app-originated activity starts on some OEM builds.
- **`run-as` refuses two ways**: `package not debuggable` vs `package not an application`.
- **`dumpsys` records broadcast extras in cleartext** — including anything you inject while testing.
- **A timing oracle on a 6-digit OTP did not reproduce** on real arm64 hardware, 200k samples,
  locally. Argue it from the code.
- **Writing about NUL bytes produces NUL bytes.** Always write the escape as six ASCII
  characters; this chapter tripped the repo's control-character check twice doing exactly that.
