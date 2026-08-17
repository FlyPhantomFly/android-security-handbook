# 23 — Permissions · Cheat Sheet

Dense. Tables and commands only. Full argument in [README.md](README.md).
Every value marked **M** was measured on a physical device, Android 13 / API 33, arm64.

---

## 1. The three lists — and the fourth

| Block in `dumpsys package` | Has `granted=`? | What it is | Stored in |
|---|---|---|---|
| `requested permissions:` | **No** | Manifest intent. **Not held.** | Derived from the APK |
| `install permissions:` | Yes | Decided at install, never prompted, not revocable | `/data/system/packages.xml` |
| `runtime permissions:` | Yes | User-decided, per Android user, revocable | `/data/system/users/<n>/runtime-permissions.xml` |
| *(computed)* **unaccounted** | — | Requested and in **neither** grant block. Asked for, not received | nowhere |

```
held = granted install-time + granted runtime.   Nothing else.
```

**M** — Chrome on the test device: 59 requested, 25 install (24 granted / 1 refused), 12 runtime
(12 granted), **36 held**, **22 unaccounted**.

---

## 2. `protectionLevel` — base levels

| XML keyword | Constant | Value | Who gets it | Prompt? | Revocable? | Real boundary? |
|---|---|---|---|---|---|---|
| `normal` | `PROTECTION_NORMAL` | `0` | **Anyone who asks.** Silent, at install | No | No | **No** |
| `dangerous` | `PROTECTION_DANGEROUS` | `1` | Anyone, after one user dialog | Yes | Yes | **No** |
| `signature` | `PROTECTION_SIGNATURE` | `2` | Same signing certificate only | No | No | **Yes**, given key hygiene |
| `signatureOrSystem` | `PROTECTION_SIGNATURE_OR_SYSTEM` | `3` | Same cert **or** system image. Deprecated at API 23 | No | No | Weaker than `signature` |
| `internal` | `PROTECTION_INTERNAL` | `4` | Nobody on the base level; flags only (API 31+) | No | Flag-dependent | Flag-dependent |

**Default when the attribute is omitted: `normal`.**

`PROTECTION_MASK_BASE = 0xf` · `PROTECTION_MASK_FLAGS = 0xfff0` ·
`frameworks/base/core/java/android/content/pm/PermissionInfo.java`

---

## 3. `protectionLevel` — flags

> **Every `|` is an OR that ADDS a population. Flags widen; they never narrow.**
> `signature|privileged` is **weaker** than `signature`.

| Flag | Adds this population | Attacker-reachable? | Note for a report |
|---|---|---|---|
| `privileged` | Allow-listed apps in `/system/priv-app` (and product/system_ext/vendor priv-app) | No | Population is "whatever the OEM shipped". Every member is a candidate confused deputy |
| `preinstalled` | **Any** app on the system image | No | Wider than `privileged` |
| `appop` | Governed additionally by an App Op | **Effectively yes** | `dumpsys package` alone is insufficient — run `cmd appops get` |
| `development` | Grantable from the shell via `pm grant` | No | **Largest false-positive source.** You can grant it; an attacker cannot |
| `instant` | Instant Apps | Yes | |
| `pre23` | Install-granted to apps with `targetSdk < 23` | **Yes** | The attacker sets their own `targetSdk` |
| `runtime` | Runtime-only, never at install | No | Counterpart to `pre23` |
| `installer` | The installer-role app | No | Population ~1 |
| `verifier` | The package verifier | No | Population ~1 |
| `setup` | The setup wizard | No | Population 1 |
| `oem` | Allow-listed OEM apps | No | Read the device's `etc/permissions/` allow-lists |
| `vendorPrivileged` | Allow-listed privileged vendor apps | No | As above |
| `module` | An APEX / mainline module | No | |
| `role` | Whichever app **currently holds** a platform Role (browser, dialer, SMS) | No | Population is **user-changeable at runtime** |
| `knownSigner` | Any cert in the declaring app's `android:knownCerts` (API 31+) | No | "Signature-level" no longer means "same key". **Read the list** |
| `companion` | Companion-device manager | No | |
| `recents` | Recents / launcher | No | |
| `retailDemo` | Retail demo app | No | |
| `incidentReportApprover` | Incident-report approver | No | |
| `appPredictor` | App predictor | No | |
| `textClassifier` | System text classifier | No | |
| `wellbeing` | Digital wellbeing app | No | |
| `documenter` | Documenter | No | |
| `configurator` | Device configurator | No | |

---

## 4. Permission → GID map (`platform.xml`) **M**

Source: `frameworks/base/data/etc/platform.xml` → `/system/etc/permissions/platform.xml`
Parsed by `frameworks/base/core/java/com/android/server/SystemConfig.java`
Group names resolve via `system/core/libcutils/include/private/android_filesystem_config.h`

| Permission | Group name | AID | Kernel then allows |
|---|---|---|---|
| `INTERNET` | `inet` | **3003** | `AF_INET` / `AF_INET6` sockets — all networking |
| `BLUETOOTH` | `net_bt` | 3002 | Bluetooth sockets |
| `BLUETOOTH_ADMIN` | `net_bt_admin` | 3001 | Bluetooth administration |
| `BLUETOOTH_STACK` | `bluetooth`, `wakelock`, `uhid` | 1002, 3010, 3011 | Bluetooth stack device nodes |
| `NET_ADMIN` | `net_admin` | 3005 | Network configuration |
| `NET_TUNNELING` | `vpn` | 1016 | The TUN device |
| `MAINLINE_NETWORK_STACK` | `net_admin`, `net_raw` | 3005, 3004 | Raw sockets, net config |
| `READ_LOGS` | `log` | 1007 | The log device |
| `ACCESS_MTP` | `mtp` | 1024 | MTP device node |
| `DIAGNOSTIC` | `input`, `diag` | 1004, 2002 | Diagnostic device nodes |
| `ACCESS_CACHE_FILESYSTEM` | `cache` | 2001 | `/cache` |
| `READ_NETWORK_USAGE_HISTORY` | `net_bw_stats` | 3006 | Network accounting |
| `UPDATE_DEVICE_STATS` | `net_bw_acct` | 3007 | Modify network accounting |
| `VIRTUAL_INPUT_DEVICE` | `uhid` | 3011 | `/dev/uhid` |
| `MANAGE_VOICE_KEYPHRASES` | `audio` | 1005 | Audio device nodes |
| `ACCESS_BROADCAST_RADIO` | `media` | 1013 | `/dev/fm` |
| `USE_RESERVED_DISK` | `reserved_disk` | 1065 | Reserved disk quota |
| `WRITE_SECURITY_LOG` | `security_log_writer` | — | Security log |
| `LOOP_RADIO` | `loop_radio` | — | Loop radio device |

**M — `READ_EXTERNAL_STORAGE` and `WRITE_EXTERNAL_STORAGE` have NO `<group>` on API 33.** They are
declared in `platform.xml` with no child at all, under a comment explaining they survive only for
upgrade compatibility. Chrome held both and its `gids=` was `[3002, 3003]` — no 1015, no 1028.
Do not test shared-storage access by group membership on a modern device.

### GIDs Zygote adds that are NOT permissions **M**

| GID | Source |
|---|---|
| `9997` | `AID_EVERYBODY` — every app process, unconditionally |
| `20000 + appId'` | Per-app cache GID (quota accounting) |
| `50000 + appId'` | Per-app shared GID |

**M** — `dumpsys package … | grep gids=` → `[3002, 3003]`;
`/proc/<pid>/status` → `Groups: 1079 3002 3003 9997 20107 50107`. **Different lists, different
questions.**

### Other `platform.xml` element types **M**

| Element | Meaning |
|---|---|
| `<permission><group gid="…"/></permission>` | Permission → Linux group. May list **several** groups |
| `<assign-permission name="…" uid="shell"/>` | Permission given to a **UID**, not a package. Appears in no `dumpsys package` block. This is why `adb shell` holds `INTERNET` |
| `<split-permission name="A" targetSdk="N"><new-permission name="B"/></split-permission>` | Apps targeting **below** N that request A also receive B. **M** — 16 split blocks on the test device |

---

## 5. The `adb` command set

### Grant state

```bash
adb shell dumpsys package <pkg>                       # everything; 3 blocks
adb shell dumpsys package <pkg> | sed -n '/declared permissions/,/disabledComponents/p'
adb shell dumpsys package <pkg> | grep 'granted=false'   # decided: NO
adb shell dumpsys package <pkg> | grep 'gids='           # permission-derived GIDs
python3 scripts/grant-state.py dump.txt                  # the four sets, separated
python3 scripts/grant-state.py --pkg <pkg>               # capture + read in one step
```

### Resolve a level and an owner

```bash
adb shell dumpsys package permission <perm>   # sourcePackage=, prot=, gids=   <-- memorise this
adb shell pm list permissions -f -g | grep -A5 <perm>
adb shell pm list permissions -f -g           # every permission, full records
adb shell pm list permissions -d -g           # dangerous only
adb shell pm list permissions -g              # names only -- almost useless
```

| `pm list permissions` flag | Effect |
|---|---|
| `-f` | **Full record**, including `protectionLevel` and declaring package. Without it you learn nothing |
| `-g` | Group by permission group |
| `-d` | Dangerous only |
| `-u` | Only permissions users see |
| `-s` | Short summary |

### App Ops — the other half

```bash
adb shell cmd appops get <pkg>                # every op for the package
adb shell cmd appops get <pkg> <OP>           # one op
adb shell cmd appops set <pkg> <OP> allow     # test devices only; restore afterwards
adb shell cmd appops set <pkg> <OP> default
adb shell dumpsys appops                      # access TIMESTAMPS -- when, not just whether
```

| Op mode | Meaning |
|---|---|
| `allow` | Permitted |
| `ignore` | Silently returns empty data rather than throwing |
| `deny` | Refused, usually with an exception |
| `default` | **Not "deny".** No explicit decision; defer to the permission |
| `foreground` | Permitted only while the app is in use |

`rejectTime=` on an op records **when the app last attempted** something it was refused. Attempt
evidence, not capability evidence.

### Grant and revoke

```bash
adb shell pm grant  <pkg> <perm>              # runtime + `development` permissions ONLY
adb shell pm revoke <pkg> <perm>
adb shell pm reset-permissions                # whole device, back to defaults
```

**M** — `pm grant` on a `normal` permission:
`SecurityException: … is not a changeable permission type`. There is no per-app runtime state to
write; the grant lives in `packages.xml`.

### The kernel side

```bash
adb shell cat /proc/<pid>/status | grep -E '^(Uid|Gid|Groups)'   # the LIVE group list
adb shell cat /system/etc/permissions/platform.xml               # the mapping. No root needed
adb shell ls /system/etc/permissions/ /vendor/etc/permissions/ /product/etc/permissions/
adb shell cat /system/etc/permissions/privapp-permissions-platform.xml
```

### Prove reachability — never from `adb shell`

```bash
cd examples/probe-app && ./build-probe.sh && adb install -r out/probe-app.apk
adb logcat -c
adb shell am start -n com.probe.unprivileged/.ProbeActivity \
    --es probe query --es target 'content://authority/path'
adb logcat -d -s PROBE:V
```

**M** — probe UID 10146, no permissions, vs `adb shell` UID 2000 holding `INTERNET` by
`<assign-permission>` policy.

---

## 6. Where grant state lives on disk

| Path | Contents | Root needed? |
|---|---|---|
| `/data/system/packages.xml` | UIDs, certificates, declared permissions, **install grants** | Yes |
| `/data/system/packages.list` | Per package: name, UID, debuggable, data dir, seinfo, **GID list** | Yes |
| `/data/system/users/<n>/runtime-permissions.xml` | **Runtime grants + flags**, per Android user | Yes |
| `/data/system/appops.xml` | App-op modes | Yes |
| `/data/system/urigrants.xml` | Persisted URI grants (chapter 27) | Yes |
| `/system/etc/permissions/*.xml` | Permission→GID, UID assignments, splits, privapp allow-lists | **No** |

---

## 7. Runtime permission flags

| Flag | What it changes |
|---|---|
| `GRANTED_BY_DEFAULT` | Pre-granted by the platform or installer, **not by the user** |
| `USER_FIXED` | "Don't ask again". The app **cannot prompt again** — only Settings |
| `POLICY_FIXED` | An MDM fixed it. Your test device may not match the fleet |
| `AUTO_REVOKED` | Has been through the unused-app auto-revoke path |
| `ONE_TIME` | Session-scoped grant; expires when the app leaves the foreground |
| `USER_SENSITIVE_WHEN_GRANTED` / `_DENIED` | Surfaced in the privacy dashboard |
| `RESTRICTION_*_EXEMPT` | Exempt from a hard restriction, by installer / system / upgrade |
| `REVOKE_WHEN_REQUESTED` | Marked for revocation on next request |

---

## 8. Runtime permission states

| State | `checkSelfPermission` | `shouldShowRationale` | Way out |
|---|---|---|---|
| Never asked | DENIED | false | Ask |
| Granted | GRANTED | false | — |
| Refused once | DENIED | **true** | Ask again with an explanation |
| Permanently refused | DENIED | false | **Settings only** |
| One-time grant | GRANTED, until backgrounded | false | Ask next session |
| Auto-revoked | DENIED | varies | Ask again |

> `shouldShowRequestPermissionRationale` returns `false` for BOTH "never asked" and "permanently
> refused". Combine it with grant state and request history to tell them apart.

---

## 9. The check API family

| Method | Subject of the question | Safe for authorisation? |
|---|---|---|
| `checkCallingPermission(p)` | The current Binder caller. **`PERMISSION_DENIED` if there is no caller** | **Yes** — fail-closed |
| `enforceCallingPermission(p, msg)` | Same, but throws | **Yes** |
| `checkPermission(p, pid, uid)` | The named process | Yes, with `Binder.getCallingPid/Uid()` |
| `checkCallingOrSelfPermission(p)` | The caller — **or, if none, ME** | **NO. Vulnerability pattern** |
| `enforceCallingOrSelfPermission(p, msg)` | Same, but throws | **NO** |
| `checkSelfPermission(p)` | Myself | Not an authorisation check at all — feature detection |
| `PackageManager.checkPermission(p, pkg)` | A **package** | Reporting only. Package names are ambiguous under `sharedUserId` |

**The correct caller check, which nothing an attacker installs can influence:**

```java
int uid = Binder.getCallingUid();
if (uid == Process.myUid()) return;                        // ourselves
if (getPackageManager().checkSignatures(Process.myUid(), uid)
        != PackageManager.SIGNATURE_MATCH) {
    throw new SecurityException("uid " + uid + " is not same-signature");
}
```

`getPackagesForUid()` returns an **array**. Under `sharedUserId` a UID maps to several packages;
check every entry. `getCallingPackage()` gives you only the first, and `null` outside a
transaction.

---

## 10. `checkComponentPermission` — the five-condition ladder

```java
// ActivityManagerService.checkComponentPermission -- order matters
if (uid == 0 || uid == SYSTEM_UID)            return GRANTED;   // root/system pass everything
if (UserHandle.isSameApp(uid, owningUid))     return GRANTED;   // same UID: NO check at all
if (!exported)                                return DENIED;    // stronger than any permission
if (permission == null)                       return GRANTED;   // exported + unguarded = open
return checkUidPermission(permission, uid);                     // finally, the string compare
```

---

## 11. Squatting — the rules, measured

| Situation | Result on Android 13 **M** |
|---|---|
| Nobody owns the name; app A declares it | A owns it. `sourcePackage=A`, `prot=` whatever A chose |
| A owns it; B tries to declare the same name | **B cannot install.** `INSTALL_FAILED_DUPLICATE_PERMISSION` |
| B owns it; A tries to declare it | **A cannot install.** Symmetric, regardless of level or malice |
| Victim *uses* a name it never *declares*; attacker declares it at `normal` | **Attacker owns the rule.** Victim installs fine. **This still works** |
| Unrelated third app requests the squatted name | `granted=true` at install, no prompt, no signature relationship **M** |
| Definer is uninstalled | Definition and **every grant of it** disappear |

| Configuration | What squatting IS | Impact class |
|---|---|---|
| Both declare | **Install denial** — victim becomes uninstallable | Availability, Low–Medium |
| Used-but-undeclared | **Access-control bypass** | Confidentiality/Integrity, High |

**Fix (both parts required):**
1. Every app in the suite declares the permission **identically at `signature`** — no install order
   leaves the name unowned.
2. Re-check the caller in code with `checkSignatures`. It cannot be squatted.

---

## 12. Is this a finding?

| Observation | Finding? | Severity | What is missing |
|---|---|---|---|
| Permission in `requested permissions:` only | **No** | — | It is not held. Nothing to report |
| Permission in a grant block with `granted=false` | **No** | Informational | The platform refused it. Worth one sentence |
| Granted permission, no code path uses it | Yes | **Low** | Over-privilege. MASVS-PRIVACY-1. Fix is deleting lines |
| `<permission>` with no `protectionLevel` | Yes | **High** if it guards anything | The default is `normal`. One grep, zero false positives |
| Custom permission at `normal` guarding an exported component | Yes | **High** | Prove reachability from a probe app first |
| Custom permission at `dangerous` on an internal API | Yes | **Medium** | The user is the only control |
| Component guarded by a permission with `sourcePackage` ≠ the app | Yes | **High** | Squatted. Compare install times and certificates |
| Component guarded by a name **nobody** declares | Yes | **High** | Unowned, therefore squattable. Currently unreachable |
| Exported component guarded by `signature` | **No** | — | Control observed. Put it in that section |
| Exported component guarded by `signature\|privileged` on a third-party app | Marginal | Informational | The `privileged` population is empty for a third-party app; note the noise |
| `checkCallingOrSelfPermission` **off** the Binder thread | Yes | **High** | Full authorisation bypass. Read the threading first |
| `checkCallingOrSelfPermission` **on** the Binder thread | **No** | Informational | Works today; fragile. Recommend the non-`OrSelf` form |
| Privileged app, unguarded exported component, borrowable permission | Yes | **High–Critical** | Do the permission arithmetic and the negative control |
| `QUERY_ALL_PACKAGES` granted | **No** | Informational | `normal` level. Privacy signal, not escalation |
| `<permission-tree>` present | Lead | **Medium** if confirmed | grep the DEX for `addPermission`. Level can only be `normal`/`dangerous` |
| `BIND_ACCESSIBILITY_SERVICE` requested | **Not alone** | — | Read `res/xml/accessibility_service_config.xml`. The combination is the finding |
| Reached a component from `adb shell` | **No** | — | UID 2000 ≠ an app. Re-test from a probe |
| Reached it after `pm grant` of a `development` permission | **No** | — | You demonstrated what a USB cable can do |
| `appop`-flagged permission, `dumpsys` read only | **Unknown** | — | Read `cmd appops get` too, in either direction |

---

## 13. Grep set

```bash
# the single highest-value line: a permission that grants itself
grep -n '<permission ' AndroidManifest.xml | grep -v protectionLevel

grep -n 'uses-permission'                                        AndroidManifest.xml
grep -n '<permission ' -A3                                       AndroidManifest.xml
grep -nE 'android:(permission|readPermission|writePermission)='  AndroidManifest.xml
grep -n 'permission-tree'                                        AndroidManifest.xml

grep -rn 'checkCallingOrSelfPermission\|enforceCallingOrSelfPermission' jadx-out/   # the bug
grep -rn 'clearCallingIdentity'                                        jadx-out/
grep -rn 'Binder.getCallingUid\|checkSignatures\|getPackagesForUid'    jadx-out/   # good sign
grep -rn 'addPermission'                                               jadx-out/
grep -rn 'requestPermissions\|checkSelfPermission'                     jadx-out/
grep -rho 'android.permission.[A-Z_]*' jadx-out/ | sort -u                          # used
grep -o  'android.permission.[A-Z_]*' AndroidManifest.xml | sort -u                 # asked

cat out/res/xml/accessibility_service_config.xml     # if BIND_ACCESSIBILITY_SERVICE
cat out/res/xml/device_admin*.xml                    # if BIND_DEVICE_ADMIN
```

---

## 14. Version matrix — the grant model

| API | Change |
|---|---|
| ≤22 | Everything granted at install after one combined dialog. Nothing revocable |
| 19 | `android:maxSdkVersion` on `<uses-permission>` |
| **23** | **Runtime permissions.** `dangerous` → first-use, per-permission, revocable. `signatureOrSystem` deprecated |
| 26 | Permission-group auto-grant tightened |
| 29 | `ACCESS_BACKGROUND_LOCATION` split out; device identifiers need a privileged permission |
| **30** | **One-time permissions**; **auto-reset of unused permissions**; **package visibility filtering**; `MANAGE_EXTERNAL_STORAGE` |
| **31** | `internal` base level; `knownSigner` flag; Bluetooth split into SCAN/CONNECT/ADVERTISE |
| **33** | `POST_NOTIFICATIONS` becomes runtime; `READ_EXTERNAL_STORAGE` split into `READ_MEDIA_*`; `BODY_SENSORS_BACKGROUND` |
| 34 | Each foreground-service type needs its own permission; partial media access |
| 35 | Minimum installable `targetSdk` raised |

Declaration defaults and the full `targetSdk` matrix belong to
[32-Manifest](../32-Manifest/README.md). This table is the **grant model** only.

---

## 15. Special app access

| Permission | Settings surface | Why it transcends the sandbox |
|---|---|---|
| `BIND_ACCESSIBILITY_SERVICE` | Accessibility | Read every window, inject events. **Can operate the permission dialogs itself** |
| `BIND_NOTIFICATION_LISTENER_SERVICE` | Notification access | Every notification, including one-time codes |
| `SYSTEM_ALERT_WINDOW` | Display over other apps | Tapjacking and overlay phishing |
| `MANAGE_EXTERNAL_STORAGE` | All files access | Every other app's shared-storage files |
| `PACKAGE_USAGE_STATS` | Usage access | Which apps, when |
| `REQUEST_INSTALL_PACKAGES` | Install unknown apps | Dropper capability |
| `BIND_DEVICE_ADMIN` | Device admin | Lock, wipe, resist uninstall |
| `WRITE_SETTINGS` | Modify system settings | System configuration |
| `SCHEDULE_EXACT_ALARM` | Alarms and reminders | Persistence |

All are granted through a **Settings screen**, not a runtime dialog. Malware bridges that gap with
an overlay narrating the steps — which is why `SYSTEM_ALERT_WINDOW` + `BIND_ACCESSIBILITY_SERVICE`
is the combination to look for.

---

## 16. AOSP paths

| Path | What is in it |
|---|---|
| `frameworks/base/core/res/AndroidManifest.xml` | **Every platform permission and its level.** The authority |
| `frameworks/base/data/etc/platform.xml` | Permission→GID, `<assign-permission>`, `<split-permission>` |
| `frameworks/base/core/java/android/content/pm/PermissionInfo.java` | `PROTECTION_*`, `PROTECTION_FLAG_*`, the two masks |
| `frameworks/base/core/java/com/android/server/SystemConfig.java` | Parses `platform.xml` |
| `frameworks/base/services/core/java/com/android/server/pm/permission/PermissionManagerService.java` | The Binder-facing service |
| `frameworks/base/services/core/java/com/android/server/pm/permission/PermissionManagerServiceImpl.java` | Grant, revoke, GID computation |
| `frameworks/base/services/core/java/com/android/server/pm/PackageManagerShellCommand.java` | `pm grant` / `pm revoke` |
| `frameworks/base/services/core/java/com/android/server/am/ActivityManagerService.java` | `checkComponentPermission` |
| `frameworks/base/core/java/android/app/ContextImpl.java` | The `check*Permission` family |
| `frameworks/base/services/core/java/com/android/server/appop/AppOpsService.java` | App Ops |
| `frameworks/base/core/java/android/os/Binder.java` | `getCallingUid`, `clearCallingIdentity` |
| `system/core/libcutils/include/private/android_filesystem_config.h` | AID table: names → numbers |

---

## 17. This chapter's tools, and the two next door

| Tool | Chapter | Question | Input |
|---|---|---|---|
| `scripts/grant-state.py` | **23** | What does this app **hold**, and what is the gap from what it asked for? | `dumpsys package` capture |
| `scripts/permission-audit.py` | **23** | Which of its **own** permissions are enforceable, and who owns them? | Manifest ± `pm list permissions` ± `dumpsys` |
| `scripts/hook-permission-checks.js` | **23** | What does it ask about at runtime, and where does it use `OrSelf`? | Frida, live app |
| `manifest-exposure.py` | [21](../21-App-Sandbox/README.md) | What does the manifest do to the **UID boundary**? | Manifest |
| `manifest-audit.py` | [32](../32-Manifest/README.md) | Does it pass a severity checklist, given `targetSdk`? | Manifest |

Run all of them. They answer different questions and their outputs are meant to sit side by side.

---

## 18. One-line recall

- A permission is a **string** in a per-app **set**.
- Default `protectionLevel` is **`normal`**. `normal` protects **nothing**.
- Only **`signature`** requires something the attacker cannot obtain.
- Every `|` **adds** a population. `signature|privileged` < `signature`.
- **First installer** owns a permission name. The second **cannot install**.
- A name an app **uses but does not declare** is unowned and squattable.
- No custom permission is ever **kernel-enforced** (`gids=[]`, always).
- `INTERNET` is **group 3003**, fixed at fork, unhookable, unrevocable from a live process.
- `dumpsys` gids ≠ `/proc` Groups.
- `<split-permission>` grants permissions the manifest never names.
- For `appop` permissions, read **both** state machines.
- `checkCallingOrSelfPermission` off the Binder thread authorises **everyone**.
- `adb shell` is **UID 2000**, not an app.
- Requested ≠ granted. Granted ≠ used. Used ≠ exploitable.
