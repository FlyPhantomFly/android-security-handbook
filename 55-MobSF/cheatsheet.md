# 55 — MobSF cheat sheet

Dense. Tables and commands. The centre of this file is §3: **every MobSF finding category mapped to
what it actually detected and what you must do to confirm it.**

---

## 1. Install, run, authenticate

| Task | Command |
|---|---|
| Pull the image | `docker pull opensecurity/mobile-security-framework-mobsf:latest` |
| Run, **localhost only** | `docker run -it --rm -p 127.0.0.1:8000:8000 opensecurity/mobile-security-framework-mobsf:latest` |
| From source | `git clone https://github.com/MobSF/Mobile-Security-Framework-MobSF && ./setup.sh && ./run.sh` |
| From PyPI (4.x) | `python3 -m venv ~/venv/mobsf && . ~/venv/mobsf/bin/activate && pip install mobsf && mobsf` |
| Web UI | `http://127.0.0.1:8000` |
| API docs for **your** version | `http://127.0.0.1:8000/api_docs` |
| The key | Printed at startup; shown in the UI. `export MOBSF_API_KEY='<key>'` |
| Auth header | `Authorization: <key>` — a **bare** value, not `Bearer` |

---

## 2. REST API

```bash
export MOBSF_API_KEY='<key>'; export MOBSF_SERVER='http://127.0.0.1:8000'
AUTH="Authorization: $MOBSF_API_KEY"
```

| Endpoint | Method | Fields | Notes |
|---|---|---|---|
| `/api/v1/upload` | POST | multipart `file` | Returns `{hash, scan_type, file_name}` |
| `/api/v1/scan` | POST | `hash`, `scan_type`, `file_name` | **Slow.** Minutes on a large app. Set a 900 s timeout |
| `/api/v1/report_json` | POST | `hash` | The report, from the database |
| `/api/v1/scans` | GET | — | Recent scans |
| `/api/v1/delete_scan` | POST | `hash` | Required to force a genuine re-scan |
| `/api/v1/download_pdf` | POST | `hash` | — |
| `/api/v1/scorecard` | POST | `hash` | Just the `appsec` block |
| `/api/v1/compare` | POST | `hash1`, `hash2` | The right primitive for a re-test |

```bash
# upload -> scan -> fetch, in four lines
H=$(curl -s -H "$AUTH" -F "file=@target.apk" "$MOBSF_SERVER/api/v1/upload" \
    | python3 -B -c "import sys,json;print(json.load(sys.stdin)['hash'])")
curl -s -H "$AUTH" -X POST --data "hash=$H&scan_type=apk&file_name=target.apk" \
     "$MOBSF_SERVER/api/v1/scan" >/dev/null
curl -s -H "$AUTH" -X POST --data "hash=$H" "$MOBSF_SERVER/api/v1/report_json" > report.json
curl -s -H "$AUTH" -X POST --data "hash=$H" "$MOBSF_SERVER/api/v1/delete_scan"   # hygiene
```

| Symptom | Cause |
|---|---|
| `401` | Wrong key, or `Bearer ` prefix added |
| `404` on an endpoint | Different MobSF major version — read `/api_docs` |
| Identical report after a re-upload | **Cache hit on the hash.** `delete_scan` first |
| Client timeout, server fine | Default client timeouts are far too short for `/scan` |

---

## 3. Finding categories — what it detected, and how to confirm

**The core table.** Column 2 is what the tool *actually* observed, which is almost never what the
finding text says. Column 3 is the work that turns it into a report entry or kills it.

### 3.1 Manifest

| MobSF finding | What it actually detected | Confirm / kill it by |
|---|---|---|
| `android:debuggable=true` | One attribute in the parsed manifest | `aapt2 dump xmltree … \| grep -i debuggable`, then `adb shell dumpsys package <pkg> \| grep flags=` → `DEBUGGABLE`. Demonstrate with `run-as` |
| `allowBackup=true` | One attribute | Check for `dataExtractionRules`/`fullBackupContent`. **Then name the file that leaves the device** |
| `usesCleartextTraffic=true` | One attribute | An NSC, if present, **supersedes** it. Then find an actual `http://` endpoint the app uses |
| Activity/Service/Receiver **not protected** | `exported="true"`, or an `<intent-filter>` with no `exported` | Is it the LAUNCHER? Then reject. Otherwise start it **from an app**, not `adb shell`, and record what the caller gains |
| Provider **not protected** | `exported="true"`, no read/write permission | `content query --uri content://<authority>` from an app; then `openFile` |
| Provider **protected by a permission** | A permission attribute exists | **Resolve `protectionLevel`.** `normal`/`dangerous` = any app can hold it → the item is *under*-rated |
| Browsable activity | A `BROWSABLE` filter with scheme/host/path | `am start -a android.intent.action.VIEW -d '<uri>'`; read what the Activity does with the parameters |
| `taskAffinity` / `launchMode` | Attributes | Platform-dependent. 30-Activities measured affinities uid-namespaced, so the classic hijack fails; the unglamorous cross-app `startActivity` without `NEW_TASK` still works |
| **Vulnerable Android version** (`minSdk` low) | An integer comparison | **Reject** unless you can name the weakness and how this app touches it |
| Custom permission declared | A `<permission>` element | Read its `protectionLevel`. Squatting needs a victim that `<uses-permission>` a name it does not declare |

### 3.2 Certificate

| MobSF finding | What it actually detected | Confirm / kill it by |
|---|---|---|
| Signed with a **debug certificate** | Subject `CN=Android Debug` | `apksigner verify -v --print-certs`. **Usually a real High.** The debug key ships with the SDK |
| v1 signature present | A `META-INF/*.SF` entry | This is the Janus-relevant direction. Check `minSdk` |
| v1 signature **absent** | No `META-INF/*.SF` | A **compatibility** note on `minSdk >= 24`, not a weakness. Get the direction right |
| Weak signature/hash algorithm | Header fields | Real; rarely the most important thing in the report |
| Self-signed / short validity | Certificate fields | Normal for Android. Almost never a finding |

### 3.3 Code analysis

| MobSF finding | What it actually detected | Confirm / kill it by |
|---|---|---|
| Hardcoded sensitive information | A **shape** matched a string | **Split it per file.** Classify each value (§4). Most are hashes, ciphertexts or pins |
| ECB mode | The literal `AES/ECB` in a `Cipher.getInstance` | Open the file. **Read the KEY derivation too** — it is frequently worse and no rule covers it |
| DES / 3DES / RC4 | A transform string | Same. Then: what does it protect, and is it reachable? |
| MD5 / SHA-1 | An algorithm string | Used for integrity or for a password? Completely different severities |
| Insecure random | `new Random()` / `Math.random` | Used for a token or for a UI animation? |
| `addJavascriptInterface` | The call | **Join it**: (a) what the bridge method returns, (b) who controls the loaded URL, (c) is the Activity exported |
| `setJavaScriptEnabled(true)` | The call | **Not a finding alone.** Merge into the bridge/URL finding or drop |
| WebView ignores SSL errors | An `onReceivedSslError` override | Read the body. `proceed()` = real and serious; `cancel()` = fine |
| App logs information | `Log.*` calls | **What** is logged? A variable message is a lead; a token in a log line is a finding |
| World-readable/writable file | `MODE_WORLD_*` | Deprecated and usually in a library. Check the package |
| External storage use | `getExternalFilesDir` etc. | Scoped storage changed the impact. Name the file and the data |
| Temporary file created | A `File` write | **Frequently mis-categorised** — check it really is temporary |
| Runtime `exec` | `Runtime.getRuntime().exec` | Usually root detection (`which su`). Read the argument |
| Root detection present | Paths/`test-keys`/package names | Presence is not enforcement. Show the app **refusing to run** |
| SQL raw query | `rawQuery`/`execSQL` | Is any part of the string caller-controlled? |
| Reflection used | `Class.forName`, `getMethod` | Almost always benign. It is also a **blind-spot marker** — record it |
| Dynamic DEX loading | `DexClassLoader`, `InMemoryDexClassLoader` | **Stop and check whether the report describes a stub** |

### 3.4 Secrets, URLs, trackers

| MobSF finding | What it actually detected | Confirm / kill it by |
|---|---|---|
| Hardcoded secret | A regex over strings | Classify first (§4). Six of seven in this chapter's run were not secrets |
| Firebase URL | A `*.firebaseio.com` pattern | Test whether the database is world-readable; that is the finding |
| URL / domain list | Every string that looks like a URL | **Filter XML namespace URIs first.** One appeared in 627 of 3,655 files in 52's measurement |
| Email addresses | A regex | Informational |
| Trackers | A curated signature database | Name-based → unreliable under R8. Privacy/compliance topic, not a vulnerability |
| Domain "malware" flag | A reputation lookup | Verify independently before repeating it about a client's own domain |

### 3.5 Binary and network

| MobSF finding | What it actually detected | Confirm / kill it by |
|---|---|---|
| NX / PIE / canary / RELRO | ELF header fields | **A hardening table, not findings.** Report as configuration |
| Symbols not stripped | A symbol table | Informational; helps *you*, not the attacker much |
| `RPATH`/`RUNPATH` set | A dynamic-section entry | Real but rarely reachable on Android |
| Network security config findings | The `res/xml/` file, parsed | Read the file yourself. `<debug-overrides>` in a non-debuggable build is a false positive |
| "App does not implement pinning" | **A type name was absent** | **Check all four layers.** R8 renames the type; the pin value survives |
| "App implements pinning" | A type name was present | `okhttp3.CertificatePinner` is on the classpath of every OkHttp app. Find the **pin value** |

### 3.6 The scorecard

| Item | What it actually is | What to do |
|---|---|---|
| `security_score` | Rule-match counts × rule metadata | **Never report it.** Never let a client gate on it |
| `average_cvss` | The mean of rule constants | Same |
| `high` / `warning` / `info` / `secure` lists | **Restatements** of other sections | Validate the underlying section; never count these separately |
| `trackers` | A count | Informational |

---

## 4. Classify a "secret" before you name it

| Shape | It is | Verdict |
|---|---|---|
| `sha256/` + 43 base64 chars + `=` | An **SPKI pin** — a *public* key hash | **Not a secret.** Move it to the TLS section |
| 32 / 40 / 64 hex chars | MD5 / SHA-1 / SHA-256 **digest** | Not a key. If a password verifier, the finding is the algorithm |
| base64 → readable text | Obfuscation, defeated | Real. Severity from what it protects |
| base64 → high-entropy bytes | Ciphertext or a key blob | Finding **only if the key is also in the artefact** |
| `http(s)://…` | An endpoint | Endpoint inventory, not the secrets list |
| `AIza…`, Firebase app id, Play Billing key | A **client** credential designed to ship | The finding is the *restriction*, if any. Go and check |
| `AKIA[0-9A-Z]{16}` | An AWS access key id | High-precision format rule. Take it seriously |
| `-----BEGIN … PRIVATE KEY-----` | A private key | Take it very seriously |
| Under 8 chars | Too short | Reject |

```bash
# decode-and-look, in one line
python3 -B -c "import base64,sys;d=base64.b64decode(sys.argv[1]);print(repr(d[:120]))" '<value>'
```

---

## 5. Reading the JSON

```bash
# sections present
python3 -B -c "import json;print('\n'.join(sorted(json.load(open('report.json')))))"

# identity first, always
python3 -B -c "
import json;d=json.load(open('report.json'))
for k in ('package_name','version_name','sha256','min_sdk','target_sdk','size','version'):
    print('%-14s %s'%(k,d.get(k)))"

# manifest findings, severity first
python3 -B -c "
import json;d=json.load(open('report.json'));ma=d.get('manifest_analysis')
items=ma.get('manifest_anal',ma) if isinstance(ma,dict) else ma
[print('%-8s %s'%(i.get('severity'),i.get('title','')[:110])) for i in sorted(items,key=lambda x:x.get('severity',''))]"

# code findings with citations
python3 -B -c "
import json;d=json.load(open('report.json'));ca=d.get('code_analysis',{});f=ca.get('findings',ca)
for t,b in f.items():
    if not isinstance(b,dict):continue
    m=b.get('metadata',b);print('%-8s cvss=%-4s %s'%(m.get('severity'),m.get('cvss'),t[:80]))
    [print('             %s:%s'%(p,l)) for p,l in (b.get('files') or {}).items()]"

# every URL, http first, namespaces last
python3 -B -c "
import json;d=json.load(open('report.json'));u=set()
[u.update(e.get('urls',[]) if isinstance(e,dict) else [e]) for e in d.get('urls',[])]
[print(x) for x in sorted(u,key=lambda s:('schemas.android.com' in s, not s.startswith('http://'), s))]"
```

### Schema shapes a parser must accept

```python
report["manifest_analysis"]                       # bare list
report["manifest_analysis"]["manifest_anal"]      # dict + key
report["manifest_analysis"]["manifest_findings"]  # dict + renamed key
report["code_analysis"]["findings"]               # {title: {files, metadata}}
report["code_analysis"]                           # same map, flat, minus "summary"
report["certificate_analysis"]["certificate_findings"]   # 3-tuples OR dicts
```

---

## 6. This chapter's scripts

```bash
# rank a corpus (online)
export MOBSF_API_KEY='<key>'
python3 -B scripts/mobsf-triage.py --dir ./apks --cache ./reports --csv triage.csv

# rank saved reports (offline; works with the shipped fixtures)
python3 -B scripts/mobsf-triage.py --from-reports ./examples --explain

# validate every item in a report against the artefact
jadx -d out target.apk
python3 -B scripts/mobsf-validate.py --report report.json --apk target.apk \
        --tree ./out --csv ledger.csv
python3 -B scripts/mobsf-validate.py --report report.json --apk target.apk --only high,warning
python3 -B scripts/mobsf-validate.py --report report.json --apk target.apk --quiet
```

| Verdict | Meaning |
|---|---|
| `CORROBORATED` | The artefact shows the claimed construct where it is claimed |
| `REFUTED` | A measurement contradicts the report |
| `UNSUPPORTED` | The cited evidence is not where the report says |
| `UNDER-RATED` | Real, severity too low |
| `OVER-RATED` | Real, severity too high |
| `RESTATES` | A scorecard entry duplicating another section |
| `NEEDS-HUMAN` | No automated check applies |

**There is no `FINDING` verdict.** Findings are written by people who can name the asset.

---

## 7. The by-hand equivalent — ten commands

```bash
sha256sum target.apk
apksigner verify -v --print-certs target.apk | head -20
unzip -l target.apk | grep -cE '\.dex$'
unzip -l target.apk | grep -E 'lib/[^/]+/' | awk -F/ '{print $2}' | sort -u
unzip -l target.apk | grep -E 'assets/' | sort -k1 -rn | head
aapt2 dump xmltree --file AndroidManifest.xml target.apk > manifest-aapt2.txt
python3 -B ../32-Manifest/scripts/manifest-audit.py manifest-aapt2.txt
bash     ../17-Libraries/scripts/lib-inventory.sh target.apk -o inventory/
python3 -B ../36-CertificatePinning/scripts/pinning-surface.py --apk target.apk
jadx -d out target.apk && python3 -B ../52-StaticAnalysis/scripts/static-sweep.py ./out --app-package <pkg>
```

---

## 8. The checks the report does not contain

| Question | Command |
|---|---|
| Is this the whole app? | `adb shell pm path <pkg>` — **every** line |
| How much is native? | `unzip -l a.apk \| grep -E 'lib/.*\.so'` vs DEX size |
| Is it packed? | `apkid a.apk`; small DEX + large `assets/` + unfamiliar `Application` class + `loadLibrary` |
| Did the decompiler succeed? | `grep -rl 'JADX ERROR' out/sources \| wc -l` — **count the tree, not the console** |
| Registered natives? | `readelf --dyn-syms --wide lib/*/*.so \| grep -c ' Java_'` vs `grep -c JNI_OnLoad` |
| Real pin value? | `grep -a -o -h -E 'sha256/[A-Za-z0-9+/]{43}=' classes*.dex \| sort -u` |
| Real protection level? | `aapt2 dump xmltree … \| grep -A2 'E: permission'` |
| Platform's own view? | `adb shell dumpsys package <pkg> \| grep -E 'flags=\|targetSdk\|versionName'` |
| Runtime receivers? | `adb shell dumpsys activity broadcasts` |
| Is the device honest? | `adb shell mount \| grep cacerts`; `adb shell "dumpsys trust" \| grep -o "deviceLocked=[01]"` |

---

## 9. Blind spots — put these in the report

| Blind spot | Measured scale |
|---|---|
| Runtime-registered receivers | **299 of 431 actions (69%)** had no manifest-declared receiver anywhere; **67% (214/321)** independently at API 33 |
| `RegisterNatives` bindings | Universal in any library that wants to hide |
| Reflection | Present in essentially every app |
| Dynamically loaded DEX | Rare; almost always the most severe row when present |
| Server-side behaviour and remote config | Not on the device |
| Splits you were not given | One app in 18 had **zero** controls in `base.apk` |

---

## 10. Numbers to remember

| Number | What it is |
|---|---|
| **12 of 14 / 4** | Apps with a pinning **surface** vs apps that actually **pin** (36) |
| **15 of 17 rejected (88%)** | HIGH-band leads adjudicated by hand on a real 17 MB app (52) |
| **132 / 132** | High-confidence secret hits, all false positives, real Chrome data (33) |
| **18/18 → 13/18** | A detector agreeing with its author until its patterns were split STRONG/WEAK (38) |
| **69%** | Broadcast surface invisible to any artefact-based tool (29) |
| **30×** | jadx under-reporting its own decompilation failures (56) |
| **39 → 17 → 8** | This chapter: report items → corroborated → findings |
| **2 of 8** | Findings that did not originate from the scan at all |
| **11 of 39 (28%)** | Items that were the scorecard restating other sections |
| **34 vs 38** | Two builds' security scores, ranked **inversely** to attacker value |

---

## 11. Report hygiene

| Do | Do not |
|---|---|
| Record artefact SHA-256 **and MobSF version** | Compare reports from different MobSF versions |
| Publish the ledger of rejections with reasons | Report the item count as the finding count |
| Write a named limits section with numbers | Bury the blind spots in a footnote |
| Mark each line `(observed)` or `(static)` | Merge dynamic and static findings silently |
| Derive severity from the asset | Keep MobSF's severity or CVSS |
| Join across report sections | Report each half separately |
| Say how many splits you scanned | Scan `base.apk` and call it the app |
| `delete_scan` after an engagement | Leave client artefacts on a shared instance |
| Bind to `127.0.0.1` | `-p 8000:8000` |
