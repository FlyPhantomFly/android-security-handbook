# 26 — Intent · Cheat Sheet

Dense reference. Prose lives in [README.md](README.md).
Rows marked **M** were measured on a physical device (Redmi, Android 11 / API 30, arm64).

---

## 1. Intent fields

| Field | Setter | Getter | Notes |
|---|---|---|---|
| action | `setAction(String)` | `getAction()` | Null action matches every filter |
| data | `setData(Uri)` | `getData()`, `getDataString()` | **Clears type** |
| type | `setType(String)` | `getType()` | **Clears data** |
| both | `setDataAndType(Uri,String)` | — | The only way to keep both |
| identifier | `setIdentifier(String)` API 29 | `getIdentifier()` | Participates in `filterEquals` |
| categories | `addCategory(String)` | `getCategories()` | Set semantics |
| component | `setComponent` / `setClass` / `setClassName` | `getComponent()` | Non-null ⇒ **explicit**, no matching |
| package | `setPackage(String)` | `getPackage()` | Restricts resolution to one app |
| flags | `setFlags` / `addFlags` / `removeFlags` | `getFlags()` | Bitmask |
| extras | `putExtra(...)`, `putExtras(Bundle)` | `getExtras()`, `get*Extra()` | Can contain an `Intent` |
| selector | `setSelector(Intent)` API 15 | `getSelector()` | Resolution-only; outer must have no package/component |
| clipData | `setClipData(ClipData)` API 16 | `getClipData()` | Extra URIs that receive grants |
| sourceBounds | `setSourceBounds(Rect)` | `getSourceBounds()` | Cosmetic |

---

## 2. Common actions

| Action constant | String |
|---|---|
| `ACTION_MAIN` | `android.intent.action.MAIN` |
| `ACTION_VIEW` | `android.intent.action.VIEW` |
| `ACTION_EDIT` | `android.intent.action.EDIT` |
| `ACTION_SEND` | `android.intent.action.SEND` |
| `ACTION_SEND_MULTIPLE` | `android.intent.action.SEND_MULTIPLE` |
| `ACTION_SENDTO` | `android.intent.action.SENDTO` |
| `ACTION_GET_CONTENT` | `android.intent.action.GET_CONTENT` |
| `ACTION_OPEN_DOCUMENT` | `android.intent.action.OPEN_DOCUMENT` |
| `ACTION_CREATE_DOCUMENT` | `android.intent.action.CREATE_DOCUMENT` |
| `ACTION_PICK` | `android.intent.action.PICK` |
| `ACTION_DIAL` / `ACTION_CALL` | `android.intent.action.DIAL` / `.CALL` |
| `ACTION_SEARCH` | `android.intent.action.SEARCH` |
| `ACTION_INSTALL_PACKAGE` | `android.intent.action.INSTALL_PACKAGE` |
| `ACTION_BOOT_COMPLETED` | `android.intent.action.BOOT_COMPLETED` |
| `ACTION_MY_PACKAGE_REPLACED` | `android.intent.action.MY_PACKAGE_REPLACED` |
| `ACTION_PACKAGE_ADDED` | `android.intent.action.PACKAGE_ADDED` |
| `ACTION_USER_PRESENT` | `android.intent.action.USER_PRESENT` |
| `ACTION_SCREEN_ON` / `_OFF` | `android.intent.action.SCREEN_ON` / `_OFF` |
| `ACTION_POWER_CONNECTED` | `android.intent.action.ACTION_POWER_CONNECTED` |
| `ACTION_TIME_TICK` | `android.intent.action.TIME_TICK` |
| `ACTION_LOCALE_CHANGED` | `android.intent.action.LOCALE_CHANGED` |

## 3. Common categories

| Category | String | Meaning |
|---|---|---|
| `CATEGORY_DEFAULT` | `android.intent.category.DEFAULT` | **Required on Activity filters for implicit `startActivity`** |
| `CATEGORY_LAUNCHER` | `android.intent.category.LAUNCHER` | Shows in the app drawer |
| `CATEGORY_BROWSABLE` | `android.intent.category.BROWSABLE` | May be started by a web browser |
| `CATEGORY_HOME` | `android.intent.category.HOME` | Is a launcher |
| `CATEGORY_INFO` | `android.intent.category.INFO` | "About this app" screen |
| `CATEGORY_PREFERENCE` | `android.intent.category.PREFERENCE` | A settings panel |
| `CATEGORY_OPENABLE` | `android.intent.category.OPENABLE` | Returns openable `content://` URIs |
| `CATEGORY_APP_BROWSER` etc. | `android.intent.category.APP_*` | Semantic app-type hints |
| `CATEGORY_CAR_DOCK`, `_DESK_DOCK` | `android.intent.category.CAR_DOCK` | Dock modes |
| `CATEGORY_MONKEY` | `android.intent.category.MONKEY` | Runs under the Monkey stress tool |

---

## 4. Resolution matching rules

### Action test

| Intent action | Filter `<action>` set | Result |
|---|---|---|
| `null` | anything | **pass** |
| `"X"` | contains `"X"` | pass |
| `"X"` | lacks `"X"` | fail — `NO_MATCH_ACTION` (-3) |
| `"X"` | empty | fail |

### Category test

| Intent categories | Filter `<category>` set | Result |
|---|---|---|
| `{}` | anything | pass |
| `{A}` ⊆ filter | — | pass |
| `{A,B}`, filter has only `A` | — | fail — `NO_MATCH_CATEGORY` (-4) |
| `{}`, filter has `A,B,C` | — | pass (extras on the filter are ignored) |

**`startActivity`/`startActivityForResult` add `CATEGORY_DEFAULT` to implicit Intents.** Broadcasts and
services do not.

### Data test

| Intent has | Filter must | Result |
|---|---|---|
| no data, no type | declare no `<data>` | pass |
| data, no type | match scheme/host/port/path; declare no types (or `content:`/`file:` implied) | pass |
| type, no data | match the type; declare no schemes, or only `content:`/`file:` | pass |
| both | match both independently | pass |

### `<data>` attribute combination

**Sets, not tuples.** Every `<data>` element contributes into four independent sets: schemes,
authorities (host+port), paths, MIME types. Matching tests each set separately ⇒ **cross product**.

| Attribute | Match kind | API | Trap |
|---|---|---|---|
| `scheme` | exact, lowercase | 1 | Declare lowercase |
| `host` | exact, or leading `*.` | 1 | `*` matches everything |
| `port` | exact | 1 | Only with a host |
| `path` | exact | 1 | Query string excluded |
| `pathPrefix` | prefix | 1 | `/open` also matches `/openredirect` |
| `pathPattern` | **glob** | 1 | `*` = 0+ of the *preceding char*; `.*` = anything |
| `pathSuffix` | suffix | 31 | — |
| `pathAdvancedPattern` | restricted regex | 31 | Supports `\d`, ranges, `+`, `?` |
| `mimeType` | `type/sub`, `type/*`, `*/*` | 1 | Wildcards work **from both sides** |
| `mimeGroup` | runtime-mutable set | 30 | Manifest understates the surface |

### MIME matching — measured **M**

| Intent `-t` | Handlers found on the test device |
|---|---|
| `text/plain` | 14 |
| `text/*` | 14 |
| `*/*` | 25 |
| `image/png` | 18 |
| `application/pdf` | 11 |
| a made-up type | 11 (i.e. the components declaring `*/*`) |

### Match values

| Constant | Value | Meaning |
|---|---|---|
| `MATCH_CATEGORY_EMPTY` | `0x00100000` | action/category only **M** `0x108000` |
| `MATCH_CATEGORY_SCHEME` | `0x00200000` | scheme only **M** `0x208000` |
| `MATCH_CATEGORY_HOST` | `0x00300000` | scheme + host |
| `MATCH_CATEGORY_PORT` | `0x00400000` | scheme + host + port |
| `MATCH_CATEGORY_PATH` | `0x00500000` | scheme + host + path **M** `0x508000` |
| `MATCH_CATEGORY_SCHEME_SPECIFIC_PART` | `0x00580000` | `mailto:`-style |
| `MATCH_CATEGORY_TYPE` | `0x00600000` | MIME type **M** `0x608000` |
| `MATCH_ADJUSTMENT_NORMAL` | `0x00008000` | OR-ed into every match |
| `MATCH_CATEGORY_MASK` | `0x0fff0000` | — |
| `MATCH_ADJUSTMENT_MASK` | `0x0000ffff` | — |
| `NO_MATCH_TYPE` | `-1` | type failed |
| `NO_MATCH_DATA` | `-2` | URI failed |
| `NO_MATCH_ACTION` | `-3` | action failed |
| `NO_MATCH_CATEGORY` | `-4` | category failed |

---

## 5. `am` syntax — every extra type

```bash
# host — wrap the WHOLE device command in quotes; adb shell re-parses it with the device's sh
adb shell "am start -n PKG/CLS -a ACTION -d 'URI' -t 'MIME' -c CATEGORY -i IDENTIFIER"
```

| Argument | Meaning |
|---|---|
| `-n pkg/cls` | Explicit `ComponentName` (`pkg/.Cls` for a relative class) |
| `-a ACTION` | Action |
| `-d 'URI'` | Data URI |
| `-t 'MIME'` | MIME type |
| `-c CATEGORY` | Category (repeatable) |
| `-i IDENTIFIER` | Identifier (API 29+) |
| `-p PACKAGE` / trailing `PACKAGE` | Restrict resolution to one package |
| `-f 0xNNNN` | Raw flags |
| `--user N` \| `--user current` | Target user |
| `-W` | Wait for launch to complete |
| `-S` | Force-stop the target first |
| `-D` | Wait for a debugger |
| `--track-allocation` | Enable allocation tracking |

### Extras

| Flag | Java type | Example |
|---|---|---|
| `-e` / `--es` | `String` | `--es url 'https://x/'` |
| `--esn` | `String` = null | `--esn optional` |
| `--ez` | `boolean` | `--ez debug true` |
| `--ei` | `int` | `--ei count 7` |
| `--el` | `long` | `--el id 9000000000` |
| `--ef` | `float` | `--ef ratio 1.5` |
| `--eu` | `Uri` | `--eu link 'content://a/b'` |
| `--ecn` | `ComponentName` | `--ecn target pkg/.Cls` |
| `--eia` | `int[]` | `--eia nums 1,2,3` |
| `--eial` | `List<Integer>` | `--eial nums 1,2,3` |
| `--ela` / `--elal` | `long[]` / `List<Long>` | `--ela ids 1,2` |
| `--efa` / `--efal` | `float[]` / `List<Float>` | `--efa r 1.0,2.0` |
| `--esa` / `--esal` | `String[]` / `List<String>` | `--esa tags 'a,b\,c'` |

> **There is no `Parcelable` extra and no way to nest an `Intent`.** **M** — confirmed from the
> device's own `am` help. `Intent.parseUri` cannot express one either.

### Grant and receiver switches

| Switch | Flag it sets |
|---|---|
| `--grant-read-uri-permission` | `FLAG_GRANT_READ_URI_PERMISSION` (`0x1`) |
| `--grant-write-uri-permission` | `FLAG_GRANT_WRITE_URI_PERMISSION` (`0x2`) |
| `--grant-persistable-uri-permission` | `0x40` |
| `--grant-prefix-uri-permission` | `0x80` |
| `--activity-clear-top` | `FLAG_ACTIVITY_CLEAR_TOP` |
| `--activity-new-task` (via `-f 0x10000000`) | `FLAG_ACTIVITY_NEW_TASK` |
| `--activity-no-history` | `FLAG_ACTIVITY_NO_HISTORY` |
| `--activity-exclude-from-recents` | `FLAG_ACTIVITY_EXCLUDE_FROM_RECENTS` |
| `--activity-multiple-task` | `FLAG_ACTIVITY_MULTIPLE_TASK` |
| `--receiver-registered-only` | `FLAG_RECEIVER_REGISTERED_ONLY` |
| `--receiver-foreground` | `FLAG_RECEIVER_FOREGROUND` |
| `--receiver-no-abort` | `FLAG_RECEIVER_NO_ABORT` |
| `--receiver-include-background` | `FLAG_RECEIVER_INCLUDE_BACKGROUND` |
| `--include-stopped-packages` | `FLAG_INCLUDE_STOPPED_PACKAGES` |
| `--exclude-stopped-packages` | `FLAG_EXCLUDE_STOPPED_PACKAGES` |
| `--debug-log-resolution` | `FLAG_DEBUG_LOG_RESOLUTION` |
| `--selector` | Everything after it builds the selector Intent |

### Sub-commands

```bash
adb shell "am start        <INTENT>"
adb shell "am start-activity <INTENT>"
adb shell "am startservice <INTENT>"
adb shell "am start-foreground-service <INTENT>"
adb shell "am stopservice  <INTENT>"
adb shell "am broadcast    <INTENT>"
adb shell "am broadcast --user 0 -a ACTION -n PKG/CLS"
adb shell "am instrument -w PKG/RUNNER"
adb shell "am force-stop PKG"
```

---

## 6. Intent flags

### URI grants

| Flag | Hex | Dec |
|---|---|---|
| `FLAG_GRANT_READ_URI_PERMISSION` | `0x00000001` | 1 |
| `FLAG_GRANT_WRITE_URI_PERMISSION` | `0x00000002` | 2 |
| `FLAG_GRANT_PERSISTABLE_URI_PERMISSION` | `0x00000040` | 64 |
| `FLAG_GRANT_PREFIX_URI_PERMISSION` | `0x00000080` | 128 |

### Activity / task

| Flag | Hex |
|---|---|
| `FLAG_ACTIVITY_NEW_TASK` | `0x10000000` |
| `FLAG_ACTIVITY_CLEAR_TOP` | `0x04000000` |
| `FLAG_ACTIVITY_CLEAR_TASK` | `0x00008000` |
| `FLAG_ACTIVITY_SINGLE_TOP` | `0x20000000` |
| `FLAG_ACTIVITY_NO_HISTORY` | `0x40000000` |
| `FLAG_ACTIVITY_EXCLUDE_FROM_RECENTS` | `0x00800000` |
| `FLAG_ACTIVITY_MULTIPLE_TASK` | `0x08000000` |
| `FLAG_ACTIVITY_FORWARD_RESULT` | `0x02000000` |
| `FLAG_ACTIVITY_PREVIOUS_IS_TOP` | `0x01000000` |
| `FLAG_ACTIVITY_REORDER_TO_FRONT` | `0x00020000` |
| `FLAG_ACTIVITY_NO_ANIMATION` | `0x00010000` |
| `FLAG_ACTIVITY_LAUNCH_ADJACENT` | `0x00001000` |
| `FLAG_ACTIVITY_NEW_DOCUMENT` | `0x00080000` |
| `FLAG_ACTIVITY_RETAIN_IN_RECENTS` | `0x00002000` |
| `FLAG_ACTIVITY_MATCH_EXTERNAL` | `0x00000800` |

### Receiver / resolution

| Flag | Hex |
|---|---|
| `FLAG_RECEIVER_REGISTERED_ONLY` | `0x40000000` |
| `FLAG_RECEIVER_REPLACE_PENDING` | `0x20000000` |
| `FLAG_RECEIVER_FOREGROUND` | `0x10000000` |
| `FLAG_RECEIVER_NO_ABORT` | `0x08000000` |
| `FLAG_RECEIVER_VISIBLE_TO_INSTANT_APPS` | `0x00200000` |
| `FLAG_EXCLUDE_STOPPED_PACKAGES` | `0x00000010` |
| `FLAG_INCLUDE_STOPPED_PACKAGES` | `0x00000020` |
| `FLAG_FROM_BACKGROUND` | `0x00000004` |
| `FLAG_DEBUG_LOG_RESOLUTION` | `0x00000008` |

---

## 7. `PendingIntent`

### Creation

```java
PendingIntent.getActivity(ctx, requestCode, intent, flags)
PendingIntent.getActivities(ctx, requestCode, Intent[], flags)
PendingIntent.getBroadcast(ctx, requestCode, intent, flags)
PendingIntent.getService(ctx, requestCode, intent, flags)
PendingIntent.getForegroundService(ctx, requestCode, intent, flags)   // API 26+
```

### Flags

| Flag | Hex | Dec | Meaning |
|---|---|---|---|
| `FLAG_ONE_SHOT` | `0x40000000` | 1073741824 | Fires once, then cancelled |
| `FLAG_NO_CREATE` | `0x20000000` | 536870912 | Return `null` instead of creating |
| `FLAG_CANCEL_CURRENT` | `0x10000000` | 268435456 | Cancel any matching token first |
| `FLAG_UPDATE_CURRENT` | `0x08000000` | 134217728 | Keep the token, replace the extras |
| `FLAG_IMMUTABLE` | `0x04000000` | 67108864 | **Fill-in is ignored** (API 23+) |
| `FLAG_MUTABLE` | `0x02000000` | 33554432 | Explicitly mutable (API 31+) |
| `FLAG_ALLOW_UNSAFE_IMPLICIT_INTENT` | — | — | Opt back into implicit wrapping (API 34+) |

### `fillIn` semantics — what a mutable token lets an attacker set

| Base field | Taken from fill-in when | Override flag |
|---|---|---|
| action | base is `null` | `FILL_IN_ACTION` |
| data / type | base data **and** type are `null` | `FILL_IN_DATA` |
| categories | always unioned | `FILL_IN_CATEGORIES` |
| component | base is `null` | `FILL_IN_COMPONENT` (creator-only) |
| package | base is `null` | `FILL_IN_PACKAGE` |
| identifier | base is `null` | `FILL_IN_IDENTIFIER` |
| clipData | base is `null` | `FILL_IN_CLIP_DATA` |
| extras | **always merged** | — |
| `FLAG_GRANT_*` | copied through | — |

### Identity from a received token — the one trustworthy primitive

| Method | Returns |
|---|---|
| `getCreatorPackage()` | Creator's package, system-stamped |
| `getCreatorUid()` | Creator's UID, system-stamped |
| `getIntentSender()` | The underlying `IntentSender` |
| `getTargetPackage()` | Deprecated alias of `getCreatorPackage()` |

### Version matrix

| targetSdk | Default | Requirement |
|---|---|---|
| ≤ 22 | mutable | `FLAG_IMMUTABLE` does not exist |
| 23–30 | mutable | `FLAG_IMMUTABLE` available |
| **31+** | — | **Must pass `FLAG_IMMUTABLE` or `FLAG_MUTABLE`, else `IllegalArgumentException`** |
| 34+ | — | Mutable + implicit + non-exported creator target is blocked |

---

## 8. Caller identity

| Mechanism | Tier | Trustworthy | Available when |
|---|---|---|---|
| `Binder.getCallingUid()` in a Binder transaction | kernel | **yes** | Bound Service / AIDL only |
| `Activity.getCallingActivity()` / `getCallingPackage()` | system | yes | Only after `startActivityForResult` |
| `PendingIntent.getCreatorUid()` / `getCreatorPackage()` | system | yes | On a received `PendingIntent` |
| `Activity.getLaunchedFromPackage()` | system | yes | API 34+ |
| `Activity.getReferrer()` | message | **no** | Always (falls back to `EXTRA_REFERRER`) |
| `Intent.EXTRA_REFERRER` | message | **no** | Always |
| any custom `"caller"` extra | message | **no** | Always |
| `Binder.getCallingUid()` in `onCreate` / `onReceive` | — | **returns your own UID** | Always — a common bug |

---

## 9. App Links — the command set, by platform version

### API 31 (Android 12) and later

```bash
adb shell "pm get-app-links PKG"                       # per-domain verification state
adb shell "pm get-app-links --user 0 PKG"
adb shell "pm verify-app-links --re-verify PKG"        # trigger re-verification
adb shell "pm set-app-links --package PKG 0 all"       # force state 0 (none)
adb shell "pm set-app-links-user-selection --user 0 --package PKG true example.com"
adb shell "pm set-app-links-allowed --package PKG --user 0 true"
adb shell "pm reset-app-links PKG"
adb shell "dumpsys package domain-verification"
```

### API 30 (Android 11) and earlier — **M** the 31+ commands do not exist here

```bash
adb shell "pm get-app-link PKG"                        # singular; prints always|ask|never|undefined
adb shell "pm set-app-link PKG always"                 # always | ask | never | undefined
adb shell "dumpsys package domain-preferred-apps"      # the whole table
adb shell "dumpsys package d"                          # short alias on some builds
```

### Verification states

| State (31+) | Meaning | Finding? |
|---|---|---|
| `verified` | `assetlinks.json` fetched and matched | no |
| `none` | never attempted / no `autoVerify` | yes, if `autoVerify` is declared |
| `legacy_failure` | old verifier failed | yes |
| numeric code | internal failure (network, parse, mismatch) | yes — quote the code |
| `Selection state: enabled` | user chose manually | not verification |

| State (≤30) | Meaning |
|---|---|
| `always` | routes exclusively (a preference, not a cryptographic verification) |
| `ask` | chooser appears — a competing app can win |
| `never` | never routed here |
| `undefined` | no decision recorded |

### `assetlinks.json`

```json
[{
  "relation": ["delegate_permission/common.handle_all_urls"],
  "target": {
    "namespace": "android_app",
    "package_name": "com.example.target",
    "sha256_cert_fingerprints": ["AB:CD:...:EF"]
  }
}]
```

```bash
# host — the fingerprint that must appear
apksigner verify --print-certs target.apk | grep -i 'SHA-256 digest'
keytool -printcert -jarfile target.apk | grep -i SHA256
# host — fetch what the platform fetches
curl -sS "https://HOST/.well-known/assetlinks.json" | python3 -m json.tool
```

---

## 10. Recon and probing commands

```bash
# host — declared surface, as the PLATFORM parsed it
adb shell "dumpsys package PKG" | sed -n '/Activity Resolver Table/,/Key Set Manager/p'

# host — who would receive this Intent?
adb shell "cmd package query-activities -a ACTION -d 'URI'"
adb shell "cmd package query-activities -a ACTION -t 'MIME'"
adb shell "cmd package query-receivers  -a ACTION"
adb shell "cmd package query-services   -a ACTION"

# host — who WINS?
adb shell "pm resolve-activity --brief -a ACTION -d 'URI'"
adb shell "pm resolve-activity --components -a ACTION -d 'URI'"

# host — the intent: URI form (quote it — ';' is a device-shell separator)
adb shell "am start 'intent:#Intent;action=android.intent.action.VIEW;scheme=https;S.k=v;i.n=7;end'"

# host — what did the platform decide, and why?
adb logcat -c
adb shell "am start --debug-log-resolution -a ACTION -d 'URI'"
adb logcat -d | grep -Ei 'Permission Denial|SecurityException|ActivityNotFound|not exported'

# host — forensic history
adb shell "dumpsys activity activities" | grep -i intent
adb shell "dumpsys activity broadcasts" | head -100
```

### `intent:` URI grammar

```text
intent:<opt-uri>#Intent;
  action=<a>;  category=<c>;  scheme=<s>;  package=<p>;  component=<pkg>/<cls>;
  launchFlags=0x<hex>;
  S.<k>=<String>;  i.<k>=<int>;  l.<k>=<long>;  f.<k>=<float>;  d.<k>=<double>;
  B.<k>=<byte>;  b.<k>=<boolean>;  c.<k>=<char>;  s.<k>=<short>;
  SEL;<selector spec>;
  end
```
No `Parcelable` syntax exists ⇒ **an `intent:` URI cannot nest an Intent**.

---

## 11. Static-analysis grep set

```bash
# redirection — Java
grep -rn "getParcelableExtra" out/sources/ | grep -i intent

# redirection — Smali, obfuscation-proof
grep -rn -A3 'getParcelableExtra(Ljava/lang/String;)Landroid/os/Parcelable;' work/smali* \
  | grep -B1 'check-cast .*Landroid/content/Intent;'

# redirection — API 33 typed overload
grep -rn 'getParcelableExtra(Ljava/lang/String;Ljava/lang/Class;)' work/smali*

# redirection — string/URI flavour (web reachable)
grep -rn 'parseUri' out/sources/ work/smali*

# PendingIntent
grep -rn 'PendingIntent\.get' out/sources/ | grep -v 'FLAG_IMMUTABLE\|67108864'
grep -rn 'FLAG_MUTABLE\|33554432' out/sources/
grep -rn 'Landroid/app/PendingIntent;->get' work/smali*

# implicit sends that may leak
grep -rn 'sendBroadcast\|sendStickyBroadcast' out/sources/

# deep-link declarations
grep -n 'android:scheme\|BROWSABLE\|autoVerify\|android:host="\*"\|mimeType="\*/\*"' \
  work/AndroidManifest.xml
grep -n 'pathPrefix\|pathPattern\|pathSuffix\|pathAdvancedPattern' work/AndroidManifest.xml

# sinks
grep -rn 'loadUrl\|addJavascriptInterface\|Class\.forName\|Runtime\.exec' out/sources/
```

### Flag integers you will see in JADX

| Decimal | Hex | Meaning (namespace matters) |
|---|---|---|
| 1 / 2 / 64 / 128 | `0x1` `0x2` `0x40` `0x80` | Intent URI grants |
| 33554432 | `0x02000000` | `PendingIntent.FLAG_MUTABLE` |
| 67108864 | `0x04000000` | `PendingIntent.FLAG_IMMUTABLE` **or** `Intent.FLAG_ACTIVITY_CLEAR_TOP` |
| 134217728 | `0x08000000` | `PendingIntent.FLAG_UPDATE_CURRENT` **or** `Intent.FLAG_ACTIVITY_MULTIPLE_TASK` |
| 268435456 | `0x10000000` | `Intent.FLAG_ACTIVITY_NEW_TASK` **or** `PendingIntent.FLAG_CANCEL_CURRENT` |
| 1073741824 | `0x40000000` | `Intent.FLAG_ACTIVITY_NO_HISTORY` **or** `PendingIntent.FLAG_ONE_SHOT` |

---

## 12. Version matrix

| API | Change |
|---|---|
| 12 | Stopped packages excluded from broadcasts by default |
| 15 | `Intent.setSelector` |
| 16 | `ClipData` participates in URI grants |
| 21 | Implicit `startService`/`bindService` throws (client-side) |
| 23 | `PendingIntent.FLAG_IMMUTABLE`; `android:autoVerify` |
| 24 | `FileUriExposedException` for `file://` across apps |
| 26 | Manifest receivers stop getting most implicit broadcasts |
| 29 | `Intent.setIdentifier`; background Activity starts restricted |
| 30 | Package visibility filtering |
| **31** | `PendingIntent` mutability mandatory; notification trampolines blocked; `pm get-app-links` |
| 33 | `RECEIVER_EXPORTED`/`RECEIVER_NOT_EXPORTED` mandatory for context-registered receivers |
| 34 | Implicit Intents cannot reach non-exported components; mutable+implicit `PendingIntent` restricted |
| 35 | Further background-launch and `PendingIntent` tightening |

---

## 13. Fix templates

```java
// Redirection — validate before forwarding
ComponentName cn = next.resolveActivity(getPackageManager());
if (cn == null || !getPackageName().equals(cn.getPackageName())
        || !ALLOWED.contains(cn.getClassName())) { finish(); return; }
next.removeFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION
               | Intent.FLAG_GRANT_WRITE_URI_PERMISSION
               | Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION
               | Intent.FLAG_GRANT_PREFIX_URI_PERMISSION
               | Intent.FLAG_ACTIVITY_FORWARD_RESULT);
next.setComponent(cn);
startActivity(next);
```

```java
// PendingIntent — the default choice
PendingIntent.getActivity(ctx, code, new Intent(ctx, MyActivity.class),
        PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
```

```java
// Broadcast — do not fan out
Intent i = new Intent("com.example.EVENT").putExtra("token", t);
i.setPackage(getPackageName());
sendBroadcast(i);
```

```xml
<!-- Deep link — verified, narrow -->
<intent-filter android:autoVerify="true">
    <action android:name="android.intent.action.VIEW"/>
    <category android:name="android.intent.category.DEFAULT"/>
    <category android:name="android.intent.category.BROWSABLE"/>
    <data android:scheme="https" android:host="app.example.com" android:pathPrefix="/open/"/>
</intent-filter>
```

```xml
<!-- Cross-app API — the only real caller control -->
<permission android:name="com.example.permission.BRIDGE" android:protectionLevel="signature"/>
<service android:name=".BridgeService" android:exported="true"
         android:permission="com.example.permission.BRIDGE"/>
```

---

## 14. Chapter scripts

| Script | Purpose |
|---|---|
| [`scripts/intent-surface-map.py`](scripts/intent-surface-map.py) | Enumerate resolvable components for a given Intent; flag exported components that accept implicit Intents; list `<data>` cross products |
| [`scripts/intent-monitor.js`](scripts/intent-monitor.js) | Frida — log every Intent sent and received, recursively dumping nested `Intent` extras; taint mode flags redirection |
| [`scripts/appstate-linkcheck.sh`](scripts/appstate-linkcheck.sh) | Detect the platform version and report App Links verification state with the right command set |
