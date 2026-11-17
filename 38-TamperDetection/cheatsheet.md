# 38 — Tamper Detection · Cheat Sheet

Printable. Tables and commands only. Full reasoning in [README.md](README.md).

---

## 1. THE CATALOGUE — what each check proves, and what it costs to defeat

The most useful table in this chapter. `Tier`: T0 container · T3 `.init_array` · T2 `JNI_OnLoad` ·
T1 Java · T4 remote.

| ID | Check | Tier | PROVES | Does NOT prove | Bypass cost |
|---|---|---|---|---|---|
| **D1** | Self-signature vs baseline | T1/T2 | The APK was signed by a specific key | Code unmodified in memory; device honest | **Minutes** — hook `getPackageInfo` or `Signature.toByteArray`, or patch the comparison |
| **D2** | `FLAG_DEBUGGABLE` on self | T1 | *This manifest* sets `debuggable` | Device-wide `ro.debuggable` | **Seconds** — one boolean |
| **D3** | Installer package | T1 | A string in `packages.xml` | Essentially nothing | **Seconds** — `pm install -i com.android.vending` |
| **D4** | DEX / APK hash | T1/T2 | File bytes match a baseline | In-memory patching; dynamically loaded code | **Minutes** — and adds nothing over D1 on a v2+ APK |
| **D5** | `TracerPid` | T1/T2/T3 | Somebody is ptracing **right now** | **JDWP debugging (measured: stays 0)**; non-ptrace hooking | **Minutes** — hook the read or patch the parse |
| **D6** | Frida default port 27042 | T1/T2 | Something listens on the *default* port | Frida on any other port | **Seconds** — `frida-server -l 127.0.0.1:1337` |
| **D7** | `/proc/self/maps` scan | T1/T2/T3 | A *named* artefact is mapped in | A renamed or memory-loaded agent | **Minutes–hours** — hook the read, or rename |
| **D8** | Thread names (`gmain`, `gum-js-loop`) | T1/T2 | Frida's runtime threads exist | Anything after renaming | Minutes |
| **D9** | `ptrace(PTRACE_TRACEME)` | T2/T3 | *Denies* attach. Detects only on a second call | Anything, if the attacker spawned you | **Zero** if attached first (`frida -f`) |
| **D10** | Native `.text` **file** hash | T2/T3 | The `.so` on disk is unmodified | **Any in-memory hook** | Minutes — often irrelevant |
| **D11** | Mapped-**page** hash | T2/T3 | The code in memory is unmodified | Data-only attacks; GOT/PLT if excluded | **Hours** — the most expensive local check to defeat |
| **D12** | Inline-hook detection (prologue check) | T2/T3 | One specific function is unhooked | Functions you did not check | Hours |
| **D13** | Timing | any | Something exceeded a threshold | Almost nothing. Huge false-positive rate | **Minutes** — hook the clock |
| **D14** | Peer-app signature | T1 | Another package's certificate | That the peer behaves | Minutes |
| **D15** | Play Integrity / attestation | T4 | **A Google-signed statement about device and app** | Nothing, if the verdict is evaluated on the client | **Hours→impossible** if server-verified with a server nonce; **seconds** if not |

---

## 2. THE THREE THREATS — do not conflate them

| | T‑A Repackaging | T‑B Instrumentation | T‑C Hostile environment |
|---|---|---|---|
| Attacker does | Edit + **re-sign** + distribute | Frida / LSPosed / debugger | Root, emulator, modified image |
| On disk | Different bytes, different cert | **Nothing** | Nothing |
| Caught by | D1, D4 | D5–D13 | ch 37 / ch 39 |
| **Not** caught by | D5–D13 | D1, D4 | this chapter |
| Owner | **this chapter** | **this chapter** | 37-RootDetection, 39 |

---

## 3. THE API

```java
// API 28+. The only correct form on a modern device.
PackageInfo pi = pm.getPackageInfo(pkg, PackageManager.GET_SIGNING_CERTIFICATES); // 0x08000000
SigningInfo si = pi.signingInfo;
Signature[] sigs = si.hasMultipleSigners()
        ? si.getApkContentsSigners()          // signed by N keys AT ONCE
        : si.getSigningCertificateHistory();  // one signer, possibly ROTATED
for (Signature s : sigs) {                    // EVERY cert. Never sigs[0]
    if (Arrays.equals(sha256(s.toByteArray()), EXPECTED)) return true;
}
return false;                                  // fail CLOSED
```

| Flag | Value | API | Field | Trap |
|---|---|---|---|---|
| `GET_SIGNATURES` | `0x00000040` | 1, dep. 28 | `pi.signatures` | Returns only the **original** signer on a rotated app |
| `GET_SIGNING_CERTIFICATES` | `0x08000000` | 28+ | `pi.signingInfo` | The correct one |

| Method | Valid when | Returns |
|---|---|---|
| `hasMultipleSigners()` | always | signed by several keys **simultaneously** |
| `hasPastSigningCertificates()` | always | the key has been **rotated** |
| `getApkContentsSigners()` | multi-signer | current signers |
| `getSigningCertificateHistory()` | single signer | lineage, **oldest first, current last** |
| `pm.hasSigningCertificate(pkg, der, CERT_INPUT_RAW_X509)` | any | rotation-aware peer check — **let the platform walk the lineage** |

---

## 4. VERSION MATRIX

| | 21–27 | 28–29 | 30–32 | 33+ |
|---|---|---|---|---|
| `GET_SIGNING_CERTIFICATES` / `SigningInfo` | — | | | |
| `GET_SIGNATURES` | only option | deprecated | deprecated | deprecated |
| `hasSigningCertificate()` | — | | | |
| `getInstallSourceInfo()` | — | — | | |
| `getInstallerPackageName()` | | | deprecated | deprecated |
| v3.1 signatures | — | — | — | |
| `<queries>` needed for peer checks | — | — | (targetSdk 30+) | |

---

## 5. TIER ORDERING — memorise this

```
zygote fork
  └─ System.loadLibrary("foo")
       └─ android_dlopen_ext
            ├─ T3  .init_array constructors      <-- inside dlopen(), before it returns
            └─ T2  JNI_OnLoad                    <-- before loadLibrary() returns
  ├─ ContentProvider.onCreate                    <-- BEFORE Application.onCreate
  ├─ Application.onCreate            T1
  └─ Activity.onCreate               T1
                                     T4  remote attestation
```

| If earliest tier is | Then |
|---|---|
| **T3** | Hook `android_dlopen_ext` and act in `onEnter`. Anything later has already lost |
| **T2** | Spawn with `-f`, hook at module base + offset |
| **T1** | Spawn with `-f`; Java hooks suffice |
| nothing found | Either there is no check, or strings are hidden. See §11 |

---

## 6. STATIC TRIAGE — in order

```bash
# host
apksigner verify -v --print-certs app.apk            # schemes, cert, debug key?
python3 -B scripts/tamper-surface-map.py app.apk     # surface by tier
python3 -B scripts/tamper-surface-map.py -v app.apk  # with matched strings
python3 -B scripts/tamper-surface-map.py --json dir/ # corpus, for diffing releases

apktool d -f -o out app.apk
grep -rn "0x8000000\|GET_SIGNING_CERTIFICATES" out/smali*/          # THE best grep

grep -rnE "getApkContentsSigners|getSigningCertificateHistory|hasSigningCertificate|\
FLAG_DEBUGGABLE|isDebuggerConnected|/proc/self/(status|maps|mem)|27042|\
getInstallerPackageName|getInstallSourceInfo|requestIntegrityToken" out/smali*/

jadx -d j app.apk && grep -rn "134217728" j/sources/  # jadx prints the flag in DECIMAL

llvm-readelf --dyn-syms out/lib/arm64-v8a/*.so | awk '$7=="UND"{print $8}' \
  | grep -E "^(ptrace|fork|syscall|dl_iterate_phdr|dladdr|mprotect|sigaction)$"
llvm-readelf --dyn-syms out/lib/arm64-v8a/*.so | grep -E "JNI_OnLoad|Java_"
llvm-readelf -S out/lib/arm64-v8a/*.so | grep init_array

aapt2 dump xmltree --file AndroidManifest.xml app.apk | grep -i debuggable
```

---

## 7. DYNAMIC TRIAGE — in order

```bash
# host — ALWAYS spawn. Most checks run before you could attach.
frida -U -f com.target.app -l scripts/which-check-fired.js

# device, root — ground truth a Frida hook cannot miss
strace -f -e trace=openat,ptrace,connect,newfstatat -p $(pidof -s com.target.app)

# host — the app "just closes"? Look before you leap
adb logcat -c; adb shell am start -n pkg/.Main; adb logcat -d \
  | grep -iE "integrity|tamper|signature|debugger|frida|FATAL|SIGABRT"

# host — is it debuggable? one command
adb shell "run-as com.target.app id"        # fails unless FLAG_DEBUGGABLE

# host — what the platform recorded
adb shell dumpsys package pkg | grep -E "signatures=|flags=|installerPackageName"
```

| Tracer output | Meaning |
|---|---|
| `[J]` + stack | Java tier → go to that class in jadx |
| `[N]` + `module+offset` | Native tier → open at that offset in Ghidra |
| `[N]` but no `[J]` | **Do not write Java hooks** |
| `[!]` | A consequence (`System.exit`, `killProcess`) — read the stack |
| nothing, but the app dies | Inline syscalls or a tier that ran first → `strace` |

---

## 8. FRIDA SNIPPETS

```javascript
// Hook the CONCRETE class. PackageManager is abstract; hooking it does nothing.
Java.use('android.app.ApplicationPackageManager').getPackageInfo
    .overload('java.lang.String','int').implementation = function (p, f) {
        console.log('getPackageInfo(' + p + ', 0x' + (f>>>0).toString(16) + ')');
        return this.getPackageInfo(p, f);
    };
```

```javascript
// The highest-value hook: every signature check ends here.
Java.use('android.content.pm.Signature').toByteArray.implementation = function () {
    console.log('[+] Signature.toByteArray');
    return this.toByteArray();
};
```

```javascript
// Find the CONSEQUENCE without finding the check. Three lines, usually enough.
Java.use('java.lang.System').exit.implementation = function (c) {
    console.log(Java.use('android.util.Log').getStackTraceString(
        Java.use('java.lang.Exception').$new()));
};
```

```javascript
// Native: which needle is the maps scan looking for?
Interceptor.attach(Module.getExportByName(null,'strstr'), {
  onEnter: function(a){ this.n = a[1].readCString(); },
  onLeave: function(r){ if(this.n && this.n.length>3)
      console.log('strstr("'+this.n+'") -> '+(r.isNull()?'miss':'HIT')); }
});
```

```javascript
// When did each library arrive? Its .init_array has ALREADY run by onLeave.
Interceptor.attach(Module.getExportByName(null,'android_dlopen_ext'), {
  onEnter: function(a){ console.log('dlopen '+a[0].readCString()); }
});
```

---

## 9. SMALI

```smali
const v2, 0x8000000                       # GET_SIGNING_CERTIFICATES — search for this
invoke-virtual {v0, v1, v2}, Landroid/content/pm/PackageManager;->getPackageInfo(...)
iget-object v0, v0, Landroid/content/pm/PackageInfo;->signingInfo:Landroid/content/pm/SigningInfo;
invoke-virtual {v0}, Landroid/content/pm/SigningInfo;->getApkContentsSigners()[...
invoke-virtual {v0}, Landroid/content/pm/Signature;->toByteArray()[B
sget-object v1, Lcom/example/a/b;->a:[B    # <-- THE BASELINE
invoke-static {v0, v1}, Ljava/util/Arrays;->equals([B[B)Z
```

| Want | Smali |
|---|---|
| Always true | `.locals 1` / `const/4 v0, 0x1` / `return v0` |
| Always false | `.locals 1` / `const/4 v0, 0x0` / `return v0` |
| Return void, do nothing | `.locals 0` / `return-void` |

> **Patching Smali means re-signing, which changes the certificate, which is what D1 detects.**
> Patch both or neither.

---

## 10. WHAT SURVIVES OBFUSCATION

| Element | Survives R8 |
|---|---|
| `getPackageInfo`, `SigningInfo`, `toByteArray` | platform API |
| `0x8000000` / `134217728` | constant — **best single search term** |
| `"SHA-256"` | unless string encryption |
| `Java_com_example_Foo_check` | **JNI resolved by name — best hook anchor** |
| The app's own method/field names | |
| Baseline `byte[]` **contents** | still in the DEX |

---

## 11. EMPTY REPORT — honestly empty, or hidden?

| Signal | Reading |
|---|---|
| Tiny `classes.dex` + large `.so` | Packed; the DEX is a loader |
| String table mostly short high-entropy blobs | String encryption |
| `.so` with big `.text`, almost no strings | Stack-built or encrypted strings |
| Behaves identically with and without Frida | **There probably is no check. Consider believing it** |
| Dies under Frida, mapper empty | Hidden → `strace` |
| Zero controls in `base.apk` | **Analyse the split APKs** |

---

## 12. SEVERITY — how to write it up

| Case | Severity | Wording |
|---|---|---|
| No tamper detection, threat model excludes compromised device | **Not a finding** | Informational at most: "hardening control, not applicable to this threat model, no action recommended" |
| No tamper detection, threat model **includes** it (banking, DRM, payments, MDM) | **Low**, as hardening | "Permits repackaging/instrumentation at negligible cost and removes a detection opportunity. Not exploitable alone" |
| You bypassed the checks | **Informational — methodology** | Record the cost in minutes. "Detection can be bypassed" is true of every app |
| Client-side control far weaker than the assurance the product claims | **Medium** | "The control does not deliver the assurance the design assumes" |
| **Server accepts a request with no / replayed / spoofed integrity token** | **High** | This is the actual finding |

**The eight real findings** (7 of 8 need no client bypass at all):

1. Attestation token replays
2. Endpoint accepts a request with **no** token ← *fastest test in the chapter*
3. Verdict evaluated on the client
4. Fail-open on attestation error
5. `requestPackageName` not checked server-side
6. App certificate digest not checked server-side
7. UI-only enforcement — call the API directly
8. Integrity signal never recorded (no residual value)

---

## 13. MEASURED NUMBERS (i9000S, Android 13 / API 33, unrooted)

| Measurement | Value |
|---|---|
| Packages by signing scheme | 186 v3, 1 v2, 2 v1, 9 v0 (of 198) |
| Packages with a rotation lineage | **6** — Play Store, GMS, GSF, TTS, calendar sync, restore |
| Clean vs repacked `classes.dex` CRC | **identical (`5e504f9e`)** — only D1 noticed |
| `FLAG_DEBUGGABLE` transition | `flags=0x30a83e44` → `0x30a83e46` |
| **TracerPid with `jdb` fully attached** | **0** — JDWP is not ptrace |
| Mappings in a live app process | **2,448**, 0 anonymous executable |
| 7 Java-tier checks, elapsed | 82 ms cold, 62 ms warm |
| Install a re-signed build over the original | `INSTALL_FAILED_UPDATE_INCOMPATIBLE` |
| `keytool` SHA256 = `apksigner` digest = `sha256(Signature.toByteArray())` | three tools, one value |

### Corpus, 18 APKs

| STRONG control | Count |
|---|---|
| v2+ signing block | 18 |
| APK/DEX self-hashing surface | 14 |
| Root-detection strings (ch 37) | 13 |
| **Self-signature verification** | **13** |
| Installer check | 10 |
| Emulator strings (ch 39) | 9 |
| `isDebuggerConnected` | 8 |
| `JNI_OnLoad` present | 7 |
| `TracerPid` | 5 |
| Peer signature | 5 |
| **Remote attestation** | **5** |
| maps scan (Java) | 3 |
| maps scan (native) | 2 |
| Frida artefacts | 2 |
| Key attestation | 2 |
| **`ptrace` imported** | **1** |

---

## 14. THE CORRECT SERVER-VERIFIED FLOW

```
1. digest  = sha256(requestBody)                  # bind to THIS request
2. nonce   = server.requestNonce(op, digest)      # SERVER issues, stores, single-use
3. token   = platform.requestToken(nonce)         # opaque — NEVER parse it
4. server.submit(op, requestBody, token)          # server ENFORCES
```

**Server must assert, in this order:**

```
verifyJwsSignature(token)
claims.requestDetails.requestPackageName == OUR_PACKAGE      # often omitted (3rd)
claims.appIntegrity.appRecognitionVerdict == PLAY_RECOGNIZED
claims.appIntegrity.certificateSha256Digest in OUR_CERTS      # often omitted (2nd)
record = nonceStore.consume(nonce)                            # often omitted (1st) -> REPLAY
record.operationId == op AND record.requestDigest == sha256(body)
now - record.issuedAt < 60s
```

**Three client anti-patterns:** client-generated nonce · client parses the verdict · fail open.

---

## 15. TOP DEVELOPER BUGS

| Bug | Fix |
|---|---|
| `catch (Exception e) { return true; }` | **Fail closed. UNKNOWN ≠ PASS.** Most common bug in the area |
| `sigs[0]` | Loop over every certificate |
| One hardcoded cert hash | Accept the lineage, or use `hasSigningCertificate` |
| Check once in `onCreate` | Re-check; treat a stale result as failed |
| `if (bad) System.exit(0)` | Best hook anchor for the attacker, worst UX for a false positive |
| Network/`/proc` on the main thread | `NetworkOnMainThreadException` / ANR |
| `null` installer treated as tampered | `null` = sideloaded = UNKNOWN |
| Hiding UI instead of enforcing | Enforce server-side |
| New check shipped enforcing on day one | Report-only first, always |
| 20 checks → one boolean | No boolean; many call sites; consequence separated from detection |
