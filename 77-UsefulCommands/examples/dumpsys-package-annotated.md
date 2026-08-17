# Reading `dumpsys package` — annotated

`adb shell dumpsys package <pkg>` is the authority on what the platform actually parsed. Everything
else — apktool, jadx, `aapt2`, MobSF — decodes the APK's *stored* manifest. This shows the result
after parsing, merging, version-dependent defaults and install-time policy have all been applied.

**When they disagree, this wins.** That is not a rare edge case: it is the entire basis of the
manifest parser-confusion technique in [10-APK-Internals](../../10-APK-Internals/README.md), where an
APK is crafted so that a static tool and `PackageManager` read different things.

The output below is representative and annotated section by section. Yours will differ in detail;
the structure and the reasoning will not.

```bash
adb shell dumpsys package com.example.vault > dumpsys-vault.txt
```

---

## 1. Identity and version

```
Packages:
  Package [com.example.vault] (5f3a91c):
    userId=10218
    pkg=Package{a1b2c3 com.example.vault}
    codePath=/data/app/~~kQ8f.../com.example.vault-Vd9j...
    resourcePath=/data/app/~~kQ8f.../com.example.vault-Vd9j...
    legacyNativeLibraryDir=/data/app/~~kQ8f.../com.example.vault-Vd9j.../lib
    primaryCpuAbi=arm64-v8a
    versionCode=1420 minSdk=26 targetSdk=33
    versionName=4.2.0
    firstInstallTime=2024-03-11 09:22:14
    lastUpdateTime=2024-03-11 09:22:14
```

| Field | Why it matters |
|---|---|
| `userId=10218` | The kernel UID enforcing the sandbox. Appears as `u0_a218` in `ls` output — the arithmetic is `10000 + 218`. See [21-App-Sandbox](../../21-App-Sandbox/README.md) |
| `codePath` | Where to pull the APK from. The `~~kQ8f` segment is randomised per install since Android 11 |
| `primaryCpuAbi` | Tells you which `.so` files are live. An app shipping both arm64 and armeabi-v7a runs only one — analyse the one that matches |
| `targetSdk=33` | **The single most consequential field.** It selects which defaults apply. A great many "vulnerabilities" are really just old `targetSdk` values re-enabling old behaviour |
| `firstInstallTime` vs `lastUpdateTime` | Identical here, so this is a fresh install and not an upgrade. An upgrade can leave data written under an older, weaker version |

---

## 2. Signing

```
    signatures=PackageSignatures{9c1d2e version:3, signatures:[3a7fc21e], past signatures:[]}
    installerPackageName=com.android.vending
```

`version:3` is the signature scheme block used to verify. `past signatures:[]` being empty means no
key rotation has occurred; a non-empty list means the app has rotated signing keys under v3, and
anything relying on a pinned certificate needs to account for the lineage.

`installerPackageName=com.android.vending` says Play installed it. `null` or an arbitrary package
means sideloaded — relevant when an app claims to verify its own install source.

---

## 3. Flags — read these carefully

```
    flags=[ HAS_CODE ALLOW_CLEAR_USER_DATA ALLOW_BACKUP ]
    privateFlags=[ PRIVATE_FLAG_ALLOW_AUDIO_PLAYBACK_CAPTURE HAS_DOMAIN_URLS ]
```

| Flag | Meaning |
|---|---|
| `HAS_CODE` | Ships DEX. Its absence means resource-only |
| `ALLOW_BACKUP` | `android:allowBackup` is on — candidate for `adb backup` extraction. Necessary but **not sufficient**: `dataExtractionRules` may exclude everything worthwhile |
| `DEBUGGABLE` | *Absent here.* If present on a production build, that is a finding on its own — it enables `run-as` and JDWP attach for any user |
| `TEST_ONLY` | *Absent here.* Would mean an `-t` install, never a Play build |
| `HAS_DOMAIN_URLS` | The app declares `autoVerify` app links — go check `assetlinks.json` actually exists and matches. See [45-OAuth](../../45-OAuth/README.md) for why a broken verification is exploitable |

> **The two flags worth grepping for on every engagement.** `DEBUGGABLE` and `TEST_ONLY` on a
> production build are near-automatic findings, and both are one `grep` away:
> `grep -E 'flags=.*(DEBUGGABLE|TEST_ONLY)' dumpsys-vault.txt`

---

## 4. Permissions — requested versus actually held

This is the part most people misread.

```
    requested permissions:
      android.permission.INTERNET
      android.permission.CAMERA
      android.permission.READ_EXTERNAL_STORAGE
      android.permission.ACCESS_FINE_LOCATION
      com.example.vault.permission.SYNC
    install permissions:
      android.permission.INTERNET: granted=true
    runtime permissions:
      android.permission.CAMERA: granted=false, flags=[ USER_SET ]
      android.permission.ACCESS_FINE_LOCATION: granted=false, flags=[ USER_SET ]
      android.permission.READ_EXTERNAL_STORAGE: granted=true, flags=[ USER_SET ]
```

Three separate lists, and conflating them produces wrong findings:

- **`requested`** — everything in the merged manifest. Includes permissions contributed by third-party
  SDKs that the app developer never wrote. See [08-Build-System](../../08-Build-System/README.md).
- **`install permissions`** — normal-protection permissions, granted automatically at install and not
  revocable.
- **`runtime permissions`** — dangerous-protection permissions, each with its **current grant state**.

`CAMERA: granted=false` means the app *can* ask but has not been given it. A report claiming "the app
has camera access" based on the manifest alone is wrong; this section is where you check.

Note `com.example.vault.permission.SYNC` in `requested` but in none of the grant lists — a custom
permission the app both defines and requests. Custom permissions are only as strong as the app
defining them, and are vulnerable to definition-squatting by whichever app installs first. See
[23-Permissions](../../23-Permissions/README.md).

---

## 5. The resolver tables — what is actually reachable

```
Activity Resolver Table:
  Non-Data Actions:
      android.intent.action.MAIN:
        5f3a91c com.example.vault/.ui.MainActivity filter 7d21ab
          Action: "android.intent.action.MAIN"
          Category: "android.intent.category.LAUNCHER"
  Schemes:
      vault:
        5f3a91c com.example.vault/.ui.DeepLinkActivity filter 9e44cd
          Action: "android.intent.action.VIEW"
          Category: "android.intent.category.DEFAULT"
          Category: "android.intent.category.BROWSABLE"
          Scheme: "vault"

Provider Resolver Table:
  Non-Data Actions:
Registered ContentProviders:
  com.example.vault/.data.VaultProvider:
    Provider{3c9f1a com.example.vault/.data.VaultProvider}
```

The resolver tables list components reachable **through intent resolution**. Two things to extract:

1. **`BROWSABLE` on the `vault:` scheme.** That means a web page can launch this activity by
   navigating to `vault://…`. The reachability is now remote, not just local, which usually raises
   severity. See [26-Intent](../../26-Intent/README.md).
2. **Custom schemes are not owned.** Any other app may register `vault:` too. Whichever the user
   picks wins — the basis of the scheme-hijack attack in
   [`45-OAuth/labs/lab-03-scheme-hijack.md`](../../45-OAuth/labs/lab-03-scheme-hijack.md).

For the provider, `dumpsys` shows registration but not the authority's protection. Get that from the
detail block:

```
  ContentProvider{3c9f1a com.example.vault/.data.VaultProvider}:
    authority=com.example.vault.files
    exported=true
    grantUriPermissions=true
    readPermission=null
    writePermission=null
```

`exported=true` with both permissions `null` — reachable by any app, no permission required.

---

## 6. Install state and user

```
User 0: ceDataInode=1966081 installed=true hidden=false suspended=false
        distractionFlags=0 stopped=false notLaunched=false enabled=0
        instant=false virtual=false
```

`enabled=0` is `COMPONENT_ENABLED_STATE_DEFAULT` — the manifest value applies. A `2` here would mean
explicitly disabled, and a component you found in the manifest would not actually be reachable.

`stopped=false` matters for broadcasts: an app in the stopped state does not receive implicit
broadcasts until launched at least once.

On a multi-user or work-profile device there will be a block per user, and the answers can differ
between them.

---

## Useful greps

```bash
# production build with debug flags -- near-automatic finding
grep -E 'flags=.*(DEBUGGABLE|TEST_ONLY)' dumpsys-vault.txt

# every exported component in one pass
grep -E 'exported=true' dumpsys-vault.txt

# providers with no protection at all
grep -B4 'readPermission=null' dumpsys-vault.txt

# what the user has actually granted, not merely what was requested
sed -n '/runtime permissions:/,/^    [a-z]/p' dumpsys-vault.txt

# version and SDK levels for the report header
grep -E 'versionName|versionCode=|targetSdk' dumpsys-vault.txt
```

---

## The comparison that finds parser confusion

Run all three and diff them. Agreement is the normal case; disagreement is a finding.

```bash
# 1. what the platform parsed
adb shell dumpsys package com.example.vault | grep -E 'exported=true' | sort > platform.txt

# 2. what apktool decoded
apktool d -f -o vault-src vault-base.apk
grep -oE 'android:name="[^"]+"[^>]*android:exported="true"' \
     vault-src/AndroidManifest.xml | sort > apktool.txt

# 3. what aapt2 read, independently of apktool
aapt2 dump xmltree vault-base.apk --file AndroidManifest.xml > aapt2.txt

diff platform.txt apktool.txt
```

A component that `apktool` shows as *not* exported but `dumpsys` reports as exported is a crafted
AXML divergence — the static tool was fooled and the platform was not. That is the technique
[32-Manifest](../../32-Manifest/README.md) covers as `rawValue` vs `typedValue` divergence, and
[`32-Manifest/labs/lab-01-three-way-read.md`](../../32-Manifest/labs/lab-01-three-way-read.md) walks
it end to end.

---

## Related

- [32-Manifest](../../32-Manifest/README.md) — the declaration audit, and the three-way read
- [27-ContentProviders](../../27-ContentProviders/README.md) — exploiting what section 5 exposes
- [23-Permissions](../../23-Permissions/README.md) — protection levels and custom-permission squatting
- [10-APK-Internals](../../10-APK-Internals/README.md) — AXML at byte level
- [`../labs/lab-02-live-manifest-audit.md`](../labs/lab-02-live-manifest-audit.md) — the guided version
