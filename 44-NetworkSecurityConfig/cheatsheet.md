# 44 — Network Security Config — Cheat Sheet

Dense reference. Prose lives in [README.md](README.md).

---

## 1. The complete schema

```
<network-security-config>                                   root, no attributes
├── <base-config cleartextTrafficPermitted hstsEnforced>     0..1
│   ├── <trust-anchors>                                      0..1
│   │   └── <certificates src overridePins/>                 1..n
│   └── <pin-set expiration>                                 0..1
│       └── <pin digest>base64</pin>                         1..n
├── <domain-config cleartextTrafficPermitted hstsEnforced>   0..n   NESTABLE
│   ├── <domain includeSubdomains>host</domain>              1..n
│   ├── <trust-anchors> …                                    0..1
│   ├── <pin-set> …                                          0..1
│   └── <domain-config> …                                    0..n
└── <debug-overrides>                                        0..1
    └── <trust-anchors>
        └── <certificates src overridePins/>
```

---

## 2. Every element and attribute

| Element | Attribute | Values | Default | Inherited | Effect |
|---|---|---|---|---|---|
| `network-security-config` | — | — | — | — | Root. Required |
| `base-config` | `cleartextTrafficPermitted` | `true`/`false` | targetSdk < 28 → `true`, ≥ 28 → `false` | n/a | Plaintext HTTP for hosts no `domain-config` matches |
| `base-config` | `hstsEnforced` | `true`/`false` | `false` | n/a | Marks hosts HSTS-preloaded. Undocumented, largely ignored |
| `domain-config` | `cleartextTrafficPermitted` | `true`/`false` | **inherited** | yes | As above, for matched hosts |
| `domain-config` | `hstsEnforced` | `true`/`false` | **inherited** | yes | As above |
| `domain` | `includeSubdomains` | `true`/`false` | `false` | n/a | Also match any host ending `.` + this name |
| `trust-anchors` | — | — | **inherited, REPLACED not merged** | yes | Container for `certificates` |
| `certificates` | `src` | `system` \| `user` \| `@raw/name` | **required** | n/a | Where anchors come from |
| `certificates` | `overridePins` | `true`/`false` | `false` outside `debug-overrides`, **`true` inside** | n/a | Chain ending here bypasses the `pin-set` |
| `pin-set` | `expiration` | `yyyy-MM-dd` | none = never | **inherited, REPLACED** | After this date pins are NOT enforced |
| `pin` | `digest` | `SHA-256` only | **required** | n/a | Anything else = parse error |
| `pin` | *(text)* | base64 of SHA-256(DER SPKI) | **required** | n/a | 32 bytes decoded |
| `debug-overrides` | — | — | — | n/a | Applied **only** when `FLAG_DEBUGGABLE` |

---

## 3. `src` values

| Value | Path on device | Class | Trusted by default? |
|---|---|---|---|
| `system` | `/system/etc/security/cacerts/` | `SystemCertificateSource` | Yes, always |
| `user` | `/data/misc/user/<id>/cacerts-added/` | `UserCertificateSource` | **No, since API 24** |
| `@raw/name` | `res/raw/name` in the APK (DER or PEM) | `ResourceCertificateSource` | Only if declared |
| *(removed)* | `/data/misc/user/<id>/cacerts-removed/` | — | Tombstones for disabled system CAs |

There is no `src="none"`. `<trust-anchors/>` with no children = nothing validates.

---

## 4. Version matrix

| API | Android | Change | Gated on |
|---|---|---|---|
| ≤ 23 | ≤ 6.0 | Mechanism does not exist; user CAs trusted | — |
| **24** | **7.0** | Mechanism added. **User CAs no longer trusted by default** | `targetSdkVersion` |
| 25–27 | 7.1–8.1 | no change | — |
| **28** | **9.0** | **Cleartext denied by default** | `targetSdkVersion` |
| 29–33 | 10–13 | no semantic change | — |
| 34+ | 14+ | no semantic change; `aapt2` compact resource entries affect some parsers | — |

---

## 5. Resolution order for one hostname

```
v2.api.example.com
  1. exact match on "v2.api.example.com"
  2. "api.example.com"     if declared with includeSubdomains
  3. "example.com"         if declared with includeSubdomains
  4. "com"                 if declared with includeSubdomains
  5. the DEFAULT config = <base-config>, else the platform default for targetSdk
```

Then, **per property independently**: this element → enclosing `domain-config`(s) → `base-config` →
platform default.

---

## 6. Three ways pinning silently does not happen

| Condition | Source |
|---|---|
| `PinSet.pins` is empty | No `pin-set` for this scope |
| `PinSet.expirationTime <= now` | `<pin-set expiration="…">` in the past |
| A trust anchor in the validated chain has `overridePins` | `overridePins="true"`, or **any** anchor in `<debug-overrides>` in a debuggable build |

None of the three logs, throws, or changes anything observable.
`PinSet.EMPTY_PINSET.expirationTime == Long.MAX_VALUE == 9223372036854775807`.

---

## 7. `<debug-overrides>` decision table

| `android:debuggable` | Block present | Verdict |
|---|---|---|
| `false` / absent | yes | **Inert.** Parsed and discarded. Not a finding |
| `true` | yes | **Live.** Anchors added AND pins overridden. CRITICAL |
| any | no | n/a |

---

## 8. Severity, honestly

| Observation | Severity | Condition |
|---|---|---|
| `src="user"` in `base-config`, release | HIGH | With a capture showing real traffic |
| `src="user"` in a `domain-config` over analytics hosts | MEDIUM | Name the SDK and the data |
| `src="user"` in `debug-overrides`, `debuggable=false` | **not a finding** | Note at most |
| `src="user"` in `debug-overrides`, `debuggable=true` | CRITICAL | Root cause is the debuggable flag |
| `cleartextTrafficPermitted="true"` on `base-config` | HIGH / LOW | HIGH with plaintext observed; LOW without |
| `cleartextTrafficPermitted="true"` on one analytics domain | MEDIUM | Rate on the data, not the flag |
| `pin-set` expired | HIGH | Chained with a trusted-CA path; often INFO for a bounty programme |
| `pin-set` with 1 pin | MEDIUM | Resilience, not confidentiality |
| `overridePins="true"` outside `debug-overrides` | HIGH | Pins are advisory for that anchor |
| No config at all, targetSdk ≥ 24 | **not a finding** | Defaults are correct |

---

## 9. Static analysis — the three steps

```bash
# host - 1. the manifest holds a resource ID, not a filename
python3 -B ../10-APK-Internals/examples/parse_axml.py --extract base.apk \
  | grep -iE 'networkSecurityConfig|usesCleartextTraffic|debuggable|targetSdk'

# host - 2. resolve it
aapt2 dump resources base.apk | grep -A2 '0x7f0b0000'

# host - 3. decode it
python3 -B ../10-APK-Internals/examples/parse_axml.py --extract base.apk \
        --entry res/xml/network_security_config.xml
```

All three at once, no Android SDK needed:

```bash
# host
python3 -B scripts/nsc-audit.py base.apk
python3 -B scripts/nsc-audit.py base.apk --xml
python3 -B scripts/nsc-audit.py base.apk --json
python3 -B scripts/nsc-audit.py base.apk --fail-on HIGH        # CI
python3 -B scripts/nsc-audit.py cfg.xml --target-sdk 30 --debuggable false
python3 -B scripts/nsc-audit.py base.apk --now 2027-01-01      # expiry what-if
```

Five-second triage without decoding anything:

```bash
# host
unzip -p base.apk res/xml/network_security_config.xml | strings | head -40
```

---

## 10. Grep, once you have decoded XML

```bash
CFG=work/res/xml/network_security_config.xml
grep -n 'cleartextTrafficPermitted="true"' "$CFG"
grep -n 'src="user"'                       "$CFG"
grep -n 'overridePins="true"'              "$CFG"
grep -n 'expiration='                      "$CFG"     # then compare to today
grep -n 'debug-overrides'                  "$CFG"
grep -n 'src="@raw'                        "$CFG"
grep -c '<pin '                            "$CFG"
```

Code that ignores the config entirely:

```bash
grep -rn "X509TrustManager\|SSLContext;->init\|HostnameVerifier" work/smali*/
grep -rn "CertificatePinner\|TrustKit"                            work/smali*/
grep -rn "onReceivedSslError"                                     work/smali*/
grep -rn "net/config/ApplicationConfig"                           work/smali*/
ls work/lib/*/ | grep -iE 'ssl|crypto|flutter|cronet'
```

---

## 11. Dynamic analysis

```bash
# host - what the platform actually built
frida -U -f com.example.app -l scripts/nsc-runtime.js
frida -U -p $(adb shell pidof com.example.app) -l scripts/nsc-runtime.js
```

Edit `CONFIG.hosts` / `CONFIG.trace` at the top of the script.
**`frida -P/--parameters` does NOT reach a plain agent script** — measured, frida-tools 16.1.6.

One-liners inside a running app:

```javascript
// frida REPL
var P = Java.use('android.security.NetworkSecurityPolicy').getInstance();
P.isCleartextTrafficPermitted();                 // default config's verdict
P.isCleartextTrafficPermitted('api.example.com'); // resolved through domain-configs

var AC = Java.use('android.security.net.config.ApplicationConfig').getDefaultInstance();
AC.hasPerDomainConfigs();
var c = AC.getConfigForHostname('api.example.com');
c.isCleartextTrafficPermitted();
c.getTrustAnchors().size();
c.getPins().pins.value.size();
c.getPins().expirationTime.value;                // Long.MAX_VALUE = never

// the app's effective trust set, in one call
var TMF = Java.use('javax.net.ssl.TrustManagerFactory');
var f = TMF.getInstance(TMF.getDefaultAlgorithm());
f.init.overload('java.security.KeyStore').call(f, null);
f.getTrustManagers()[0].getAcceptedIssuers().length;
```

Private fields worth reading (no public getters, API 30):

| Class | Field | Holds |
|---|---|---|
| `ApplicationConfig` | `mConfigs` | `Set<Pair<Domain, NetworkSecurityConfig>>`. **null** when the app has no config |
| `ApplicationConfig` | `mDefaultConfig` | The `base-config`, or the platform default |
| `NetworkSecurityConfig` | `mCertificatesEntryRefs` | Ordered `List<CertificatesEntryRef>` |
| `CertificatesEntryRef` | `mSource`, `mOverridesPins` | Which store, and whether it defeats pins |
| `PinSet` | `pins`, `expirationTime` | public fields |

---

## 12. Getting your CA trusted

| Route | Needs | Works when | Cost |
|---|---|---|---|
| CA in the **user store** | Nothing | Config trusts `src="user"`, or targetSdk < 24 | None. Try first |
| **Debug variant** with a debug config | You build the app | Always, for your own app | None |
| **Repackage** with your own config | apktool + a keystore | App is not signature-checked server-side | Breaks Play Integrity, Google Sign-In, app links |
| CA in the **system store** | Root (Magisk/APatch module) | Config trusts `src="system"` — nearly all | **Contaminates every default-trust measurement** |
| Frida bypass | Root or gadget | Anything | Chapter 36 |

```bash
# host - prepare a CA for either store
openssl x509 -inform DER -in burp.der -out burp.pem
openssl x509 -inform PEM -subject_hash_old -in burp.pem -noout    # -> 9a5ba575
cp burp.pem 9a5ba575.0

# host - proxy on / off
adb shell settings put global http_proxy 192.168.1.50:8080
adb shell settings put global http_proxy :0

# host - is the system store real, or a root module's tmpfs?
adb shell "su -c 'mount | grep cacerts'"
adb shell "ls /system/etc/security/cacerts | wc -l"
adb shell "su -c 'ls /data/misc/user/0/cacerts-added/'"
```

---

## 13. Compute a pin

```bash
# host - from a file
openssl x509 -in cert.pem -pubkey -noout \
  | openssl pkey -pubin -outform der \
  | openssl dgst -sha256 -binary | openssl enc -base64

# host - from a live server
openssl s_client -connect host:443 -servername host -showcerts </dev/null 2>/dev/null \
  | openssl x509 -pubkey -noout \
  | openssl pkey -pubin -outform der \
  | openssl dgst -sha256 -binary | openssl enc -base64
```

SHA-256 over the DER **SubjectPublicKeyInfo**, not over the certificate. 32 bytes → 44 base64 chars
ending in `=`.

---

## 14. Errors and what they mean

| Symptom | Cause |
|---|---|
| `java.net.UnknownServiceException: CLEARTEXT communication to X not permitted by network security policy` | `cleartextTrafficPermitted` is false for that host |
| `javax.net.ssl.SSLHandshakeException: … Trust anchor for certification path not found` | Your CA is not in the app's anchor set |
| `CertificateException` naming pin values | A live `pin-set` rejected the chain |
| **No error, and no traffic in the proxy** | The app is not using the platform stack, or ignores the system proxy |
| **No error, and pinning appears absent** | Check the `pin-set` expiration |
| `RuntimeException` on the first network call | Malformed config; parse is lazy |
| `aapt2`: "failed to load XML file" on a file that exists | A `--` inside an XML comment, or a `-` at a comment's end |

---

## 15. What `dumpsys` will NOT tell you

Measured, API 30:

```
$ dumpsys package com.vendor.socialmedia | grep flags=
    flags=[ HAS_CODE ALLOW_CLEAR_USER_DATA ]           # no FLAG_USES_CLEARTEXT_TRAFFIC
$ dumpsys package packages | grep -c CLEARTEXT
0                                                       # across all 49 third-party packages
```

`networkSecurityConfigRes` is not printed either. **There is no adb-only way to read this policy.**

---

## 16. One-line reminders

- The manifest stores a **number**, not a filename.
- API 24 = user CAs out. API 28 = cleartext out. Both by **targetSdkVersion**.
- Inheritance is **per property**; anchors and pins are **replaced**, not merged.
- `<debug-overrides>` needs `FLAG_DEBUGGABLE`, and sets `overridePins` to **true**.
- **Check every `expiration` against today.** Two of five large apps measured were expired.
- Config **beats** `android:usesCleartextTraffic`.
- The policy is **advisory**. Raw sockets and bundled stacks ignore it.
- `dumpsys` is silent. Frida is the authority.
- Your rooted phone's **system store is not the platform's**. Check `mount`.
- "No config" at targetSdk ≥ 24 is **not a finding**.
