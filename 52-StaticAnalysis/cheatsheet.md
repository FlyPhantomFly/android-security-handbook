# 52 — Static Analysis · Cheat Sheet

Printable. Tables and commands only. Full reasoning in [README.md](README.md).

---

## The pipeline

| # | Stage | One command that starts it |
|---|---|---|
| 1 | Acquire | `adb shell pm path PKG` then `adb pull` each path, then `sha256sum` |
| 2 | Unpack | `unzip -l target.apk` |
| 3 | Decompile | `jadx -d out target.apk` + `apktool d -f target.apk -o work` |
| 4 | Enumerate | entry points, package classification, `lib-inventory.sh` |
| 5 | Sweep | `python3 -B scripts/static-sweep.py ./out --app-package PKG` |
| 6 | Triage | the sweeper's queue: leads, confidence, next step |
| 7 | **Validate** | `bash scripts/validate-lead.sh --tree ./out --value 'X' --reach` |
| 8 | Report | findings + ledger + limits section |
| 0 | Blind spots | recorded throughout; measured with `blindspot-recorder.js` |

---

## Five-minute pass

```bash
APK=target.apk
sha256sum "$APK"
apksigner verify -v --print-certs "$APK" | grep -i "certificate DN"   # CN=Android Debug == High
aapt2 dump badging "$APK" | head -20
unzip -l "$APK" | grep -cE '\.dex$'
unzip -l "$APK" | grep -E 'lib/[^/]+/' | awk -F/ '{print $2}' | sort -u
unzip -l "$APK" | grep -E 'assets/' | sort -k1 -rn | head
aapt2 dump xmltree --file AndroidManifest.xml "$APK" \
  | grep -Ei 'debuggable|allowBackup|usesCleartextTraffic|networkSecurityConfig|testOnly'
```

---

## The grep catalogue

### Credentials — format class (precision 0.75; act on a hit)

| ID | Command |
|---|---|
| CRED-01 | `grep -rn -- '-----BEGIN' .` |
| CRED-02 | `grep -rnE 'AKIA[0-9A-Z]{16}' .` |
| CRED-03 | `grep -rnE 'AIza[0-9A-Za-z_-]{35}' .` |
| CRED-04 | `grep -rnE '[sr]k_(live\|test)_[0-9A-Za-z]{10,}' .` |
| CRED-05 | `grep -rnE 'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.' .` |
| CRED-06 | `grep -rnE 'gh[pousr]_[0-9A-Za-z]{20,}\|xox[abprs]-' .` |

### Credentials — keyword and shape class (precision 0.15 / 0.30; triage first)

| ID | Command |
|---|---|
| CRED-07 | `grep -rnEi 'api[_-]?key\|client[_-]?secret\|access[_-]?key\|x-api-key' .` |
| CRED-08 | `grep -rnEi 'password\s*=\s*"' .` |
| CRED-09 | `grep -rnoE '"[A-Za-z0-9+/=]{20,}"' . \| sort -u` |
| CRED-10 | `grep -rnoE '"[0-9a-fA-F]{40,}"' . \| sort -u` |

### Endpoints

| ID | Command | Note |
|---|---|---|
| NET-01 | `grep -rnoE 'http://[^"]+' . \| sort -u` | cleartext |
| NET-02 | `grep -rnoE 'https://[^"]+' . \| sort -u` | inventory, not a finding |
| NET-03 | `grep -rnoE '"([0-9]{1,3}\.){3}[0-9]{1,3}"' .` | `10.0.2.2` = emulator host |
| NET-04 | `grep -rnEi '(staging\|preprod\|uat\|sandbox\|qa)[0-9]*\.[a-z0-9-]+\.[a-z]{2,}' .` | often the best lead |

### Crypto — find here, rate in [34](../34-Cryptography/README.md)

| ID | Command |
|---|---|
| CRY-01 | `grep -rn 'ECB' .` |
| CRY-02 | `grep -rn 'IvParameterSpec\|GCMParameterSpec' .` |
| CRY-03 | `grep -rn 'setSeed\|new SecureRandom(' .` |
| CRY-04 | `grep -rnE 'getInstance\("(MD5\|SHA-?1)"\)' .` |
| CRY-05 | `grep -rn 'PBEKeySpec' .` |

### TLS — find here, rate in [35](../35-SSL/README.md) / [36](../36-CertificatePinning/README.md) / [44](../44-NetworkSecurityConfig/README.md)

| ID | Command |
|---|---|
| TLS-01 | `grep -rn 'checkServerTrusted\|X509TrustManager' .` |
| TLS-02 | `grep -rn 'HostnameVerifier\|ALLOW_ALL_HOSTNAME' .` |
| TLS-03 | `grep -rn 'onReceivedSslError' .` |
| TLS-04 | `grep -rn 'CertificatePinner\|pin-set\|network_security_config' .` |

### Storage and platform — find here, rate in [33](../33-Storage/README.md) / [43](../43-WebView/README.md)

| ID | Command |
|---|---|
| STO-01 | `grep -rn 'MODE_WORLD_READABLE\|MODE_WORLD_WRITEABLE' .` |
| STO-02 | `grep -rn 'getExternalStorage' .` |
| STO-03 | `grep -rnEi 'putString\("[^"]*(token\|password\|secret\|key\|pin\|session\|auth)' .` |
| STO-04 | `grep -rn 'addJavascriptInterface\|setJavaScriptEnabled(true)' .` |

### Debug residue

| ID | Command |
|---|---|
| DBG-01 | `grep -rn 'debuggable' AndroidManifest.xml` |
| DBG-02 | `grep -rn 'Log\.[dvi](' .` |
| DBG-03 | `grep -rnE 'TODO\|FIXME\|HACK\|XXX' .` |
| DBG-04 | `grep -rn 'printStackTrace' .` |

### Blind-spot markers — NOT leads; they go in the limits section

| ID | Command | What it means |
|---|---|---|
| BLIND-01 | `grep -rn 'registerReceiver' .` | 69% of the broadcast surface is invisible to you |
| BLIND-02 | `grep -rnE 'Class\.forName\|getDeclaredMethod\|\.invoke\(' .` | your call graph stops here |
| BLIND-03 | `grep -rn 'DexClassLoader\|InMemoryDexClassLoader' .` | code not in the artefact will run |
| BLIND-04 | `grep -rn 'loadLibrary\|System\.load(' .` | `RegisterNatives` hides the JNI surface |
| BLIND-05 | `grep -rni 'remoteconfig\|featureflag' .` | the server can disable a control after you leave |
| BLIND-06 | `unzip -l app.apk \| grep -E 'assets/.*\.(dex\|so\|bin\|dat\|enc)$'` | possible packer |

---

## The triage decision table

| What you have | Where it is | Decision | Next action |
|---|---|---|---|
| Format hit | App code | **Work now** | Read the class; establish scope |
| Format hit | Library code | Work, then reassign | Dependency section, phrased as a version |
| API hit | App code | Read the arguments | The construct is not the finding |
| API hit | Library code | Note, move on | Unless unmaintained or on a sensitive path |
| Shape hit | Anywhere | **Decode first** | Text: usually resolved in 10 s. 16/32 bytes near `Cipher`: escalate |
| Keyword hit | Library code | **Reject** | 136 of 137 measured |
| Keyword hit | App code | One look | Value next to the name, or a lookup? |
| Cleartext URL | Namespace / docs host | **Reject** | `schemas.android.com`, `w3.org`, `slf4j.org` |
| Cleartext URL | App code, resolves | Work it | Check the network security config first |
| Non-prod hostname | App code | **Work it** | Frequently the best lead in the run |
| Manifest flag | Manifest | Confirm on device | `dumpsys package PKG \| grep flags=` |
| Blind-spot marker | Anywhere | Not a lead | Limits section |
| Anything | `R.java`, `BuildConfig`, `*Binding` | **Reject** | No developer decisions in generated code |

---

## The four questions (severity comes from #4)

| # | Question | Fails ⇒ |
|---|---|---|
| 1 | Is the construct really there? | Reject: rule artefact |
| 2 | Is it reachable? | Reject or downgrade: dead code |
| 3 | Who can reach it? | Downgrade: self-reachable only |
| 4 | What does reaching it get them? | Downgrade: no asset behind it |

### Severity grid

| | Not reachable | App only | Another app | Network |
|---|---|---|---|---|
| No asset | Info | Info | Info | Low |
| Device metadata | Info | Info | Low | Low |
| User data | Info | Low | Medium | High |
| Credentials / financial | Low | Medium | High | Critical |

Overrides: a vendor-designed client credential (Google API key, Firebase app id, Play Billing public
key, translation-SDK token) is not automatically a finding — check the restriction. A control that a
remote flag can disable is capped at the strength of that flag.

---

## The kill list

1. App code or library?
2. A value, or a **name**?
3. Does it decode to something meaningful?
4. Dead code, or behind `BuildConfig.DEBUG`?
5. Was it the **shipped** artefact?
6. Is the mechanism dangerous *here*?
7. Does the control exist somewhere else (NSC XML, not code)?
8. Would the client's own logs corroborate it?

---

## Confidence model

```
base:  format 0.75 | api 0.55 | shape 0.30 | keyword 0.15
+0.25  site in the app's own package
+0.05  package not a known library
-0.30  only third-party            -0.35 only generated        -0.10 only resources
-0.25  value in >8 distinct files
+0.10  single site in app code     +0.10 construct with an app-code site
-0.15  construct with no app-code site
-0.45  known-noise value
+0.10  same file does crypto / networking / headers
clamp [0.05, 0.95]      HIGH >= 0.65     MEDIUM >= 0.40     LOW below
```

**Confidence is not severity.** There is no severity column and there must not be one.

---

## Tool invocations

```bash
# sweeper
python3 -B scripts/static-sweep.py ./out                       # basic
python3 -B scripts/static-sweep.py ./out --app-package PKG     # when no manifest in tree
python3 -B scripts/static-sweep.py ./out --files app           # big app, first pass (6x faster)
python3 -B scripts/static-sweep.py ./out --scope app           # only leads touching app code
python3 -B scripts/static-sweep.py ./out --min-confidence 0.5
python3 -B scripts/static-sweep.py ./out --show-suppressed     # audit the filter
python3 -B scripts/static-sweep.py ./out --csv leads.csv       # the ledger skeleton
python3 -B scripts/static-sweep.py --print-catalogue           # every rule + its hand-run grep

# validator
bash scripts/validate-lead.sh --tree ./out --value 'X'
bash scripts/validate-lead.sh --tree ./out --file sources/a/B.java --line 88
bash scripts/validate-lead.sh --tree ./out --value 'X' --reach
bash scripts/validate-lead.sh --tree ./out --value 'X' --package PKG --serial SERIAL
bash scripts/validate-lead.sh --tree ./out --value 'X' --out evidence/L001

# blind spots (needs frida-server + root)
frida -U -f PKG -l scripts/blindspot-recorder.js --no-pause
# then, in the REPL:  rpc.exports.report()
```

---

## Entry points, correctly

```bash
awk '/<(intent-filter|meta-data|action|category)[ \t>\/]/{t=0}
     /<(activity|activity-alias|service|receiver|provider|application)([ \t>\/]|$)/{t=1}
     t && match($0,/android:name="[^"]+"/){print substr($0,RSTART+14,RLENGTH-15);t=0}' \
    work/AndroidManifest.xml | sort -u
```

A bare `grep android:name` also collects `<action>`, `<category>` and `<meta-data>`, and then
`android.intent.action.MAIN` looks like a class. Do not use `\b` in awk — it is a backspace.

---

## Device confirmation (read-only)

```bash
adb shell pm path PKG                                   # every split
adb shell dumpsys package PKG | grep -E 'flags=|privateFlags=|targetSdk|versionName'
adb shell dumpsys package PKG | sed -n '/Activity Resolver Table/,/Service Resolver/p'
adb shell mount | grep cacerts                          # BEFORE any trust-store claim
adb shell "dumpsys trust" | grep -o "deviceLocked=[01]" # before any app-originated result
```

---

## Measured numbers to quote

| Number | What it is | Source |
|---|---|---|
| **132 / 132** | High-confidence leak-hunter hits on real Chrome data that were false positives | [33-Storage](../33-Storage/README.md) |
| **12 of 14 / 4 of 14** | Apps presenting a pinning surface / apps that actually pin | [36](../36-CertificatePinning/README.md) |
| **299 of 431 (69%)** | Broadcast actions registered at runtime with no manifest receiver anywhere | [29](../29-BroadcastReceivers/README.md) |
| **136 of 137** | `password` hits in library or generated code on a small app | this chapter §3.4 |
| **7,346 → 9** | Raw hits collapsed to leads on a 3,655-file tree (816×) | this chapter §9.3 |
| **16,836 → 168** | Raw hits collapsed to leads on a 20,091-file tree (100×) | this chapter §9.4 |
| **15 of 17** | HIGH-band leads rejected on inspection on a real commercial app (88%) | this chapter §9.4 |
| **3,591 of 7,346** | Hits killed by rule validators before a human saw them | this chapter §3.6 |
| **54%** | Share of a real app's tree that is neither obviously app nor obviously library | this chapter §9.4 |

---

## Language for the report

| Do not write | Write |
|---|---|
| "No issues found" | "The sweep produced no leads above threshold; see Limits" |
| "Unreachable" | "No static path found; the method did not execute in N minutes covering X, Y, Z" |
| "Hardcoded secret found" | "A `<vendor>` token is embedded at `Class.method`; its scope is `<scope>`" |
| "The app implements pinning" | "A pinning surface is present; pins are configured at `<location>` / no pin values are configured" |
| "The app is clean" | "Static analysis of the artefact found N leads, M validated; the following mechanisms are not observable from files" |

---

## Never

- Paste scanner output into a report.
- Report a string as a finding.
- Analyse a build you compiled instead of the shipped artefact.
- Analyse `base.apk` without its splits.
- Add a severity column to a sweeping tool.
- Claim anything about a trust store on a device whose trust store you have not checked.
