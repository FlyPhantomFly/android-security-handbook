# 25 — Binder — Cheat Sheet

Values marked **M** were measured on a physical device: Xiaomi M2101K6P, Android 11 / API 30,
arm64-v8a, kernel 4.14.180, from `adb shell` as uid 2000, no root. Everything else is from AOSP or
kernel source.

---

## 1. Device nodes

| Node | Context manager | Registry file | Openable by `shell` (**M**) | Serialisation |
|---|---|---|---|---|
| `/dev/binder` | `servicemanager` | `plat_service_contexts`, `system_ext_`, `product_` | yes | `Parcel` (AIDL) |
| `/dev/hwbinder` | `hwservicemanager` | `*_hwservice_contexts` | yes | `hwparcel` (HIDL) |
| `/dev/vndbinder` | `vndservicemanager` | `vndservice_contexts` | **no — EACCES** | `Parcel` (AIDL) |
| `/dev/binderfs/binder` | — | — | yes | — |

```bash
# adb shell
ls -lZ /dev/binder /dev/hwbinder /dev/vndbinder     # M: all three are symlinks into binderfs
ps -A -o PID,USER,LABEL,NAME | grep servicemanager  # M: pids 606/607/608, three domains
ls /dev/binderfs/binder_logs/                       # root only
```

---

## 2. ioctl commands

| Name | Encoding (arm64, **M**) | Argument | Purpose |
|---|---|---|---|
| `BINDER_WRITE_READ` | `0xc0306201` | `struct binder_write_read` | Everything |
| `BINDER_SET_IDLE_TIMEOUT` | `_IOW('b',3,__s64)` | `__s64` | Idle timeout |
| `BINDER_SET_MAX_THREADS` | `0x40046205` | `__u32` | Pool cap |
| `BINDER_SET_IDLE_PRIORITY` | `_IOW('b',6,__s32)` | `__s32` | Legacy |
| `BINDER_SET_CONTEXT_MGR` | `0x40046207` | `__s32` | Become handle 0 |
| `BINDER_THREAD_EXIT` | `_IOW('b',8,__s32)` | `__s32` | Thread leaving |
| `BINDER_VERSION` | `0xc0046209` | `struct binder_version` | 8 = 64-bit, 7 = 32-bit |
| `BINDER_GET_NODE_DEBUG_INFO` | `_IOWR('b',11,…)` | struct | Debug |
| `BINDER_GET_NODE_INFO_FOR_REF` | `_IOWR('b',12,…)` | struct | Debug |
| `BINDER_SET_CONTEXT_MGR_EXT` | `_IOW('b',13,flat_binder_object)` | struct | Context mgr with flags |
| `BINDER_FREEZE` | `_IOW('b',14,…)` | struct | Android 12+ cached apps |
| `BINDER_GET_FROZEN_INFO` | `_IOWR('b',15,…)` | struct | Android 12+ |
| `BINDER_ENABLE_ONEWAY_SPAM_DETECTION` | `_IOW('b',16,__u32)` | `__u32` | Android 12+ |

Magic letter is `'b'` (`0x62`) for ioctls, `'c'` (`0x63`) for `BC_`, `'r'` (`0x72`) for `BR_`.

---

## 3. Structures

```c
struct binder_write_read {          /* sizeof = 48 (M) */
    binder_size_t    write_size;
    binder_size_t    write_consumed;
    binder_uintptr_t write_buffer;
    binder_size_t    read_size;
    binder_size_t    read_consumed;
    binder_uintptr_t read_buffer;
};

struct binder_transaction_data {    /* sizeof = 64 (M) */
    union { __u32 handle; binder_uintptr_t ptr; } target;
    binder_uintptr_t cookie;
    __u32            code;
    __u32            flags;
    pid_t            sender_pid;    /* KERNEL-SET. 0 for oneway */
    uid_t            sender_euid;   /* KERNEL-SET. Forging is a no-op */
    binder_size_t    data_size;
    binder_size_t    offsets_size;
    union {
        struct { binder_uintptr_t buffer; binder_uintptr_t offsets; } ptr;
        __u8 buf[8];
    } data;
};

struct flat_binder_object {         /* sizeof = 24 (M) */
    __u32            type;          /* BINDER_TYPE_*  */
    __u32            flags;
    union { binder_uintptr_t binder; __u32 handle; };
    binder_uintptr_t cookie;
};

struct binder_version { __s32 protocol_version; };   /* 8 on arm64 (M) */
```

### Field offsets, 64-bit, for a Frida `Interceptor`

| Field of `binder_transaction_data` | Offset |
|---|---|
| `target.handle` / `target.ptr` | 0 |
| `cookie` | 8 |
| `code` | 16 |
| `flags` | 20 |
| `sender_pid` | 24 |
| `sender_euid` | 28 |
| `data_size` | 32 |
| `offsets_size` | 40 |
| `data.ptr.buffer` | 48 |
| `data.ptr.offsets` | 56 |

| Field of `binder_write_read` | Offset |
|---|---|
| `write_size` | 0 |
| `write_consumed` | 8 |
| `write_buffer` | 16 |
| `read_size` | 24 |
| `read_consumed` | 32 |
| `read_buffer` | 40 |

---

## 4. `BC_` — commands you send

| Command | Encoding | Argument |
|---|---|---|
| `BC_TRANSACTION` | `0x40406300` | `binder_transaction_data` |
| `BC_REPLY` | `_IOW('c',1,…)` | `binder_transaction_data` |
| `BC_ACQUIRE_RESULT` | `_IOW('c',2,__s32)` | `__s32` |
| `BC_FREE_BUFFER` | `_IOW('c',3,binder_uintptr_t)` | pointer |
| `BC_INCREFS` | `_IOW('c',4,__u32)` | handle |
| `BC_ACQUIRE` | `_IOW('c',5,__u32)` | handle |
| `BC_RELEASE` | `_IOW('c',6,__u32)` | handle |
| `BC_DECREFS` | `_IOW('c',7,__u32)` | handle |
| `BC_INCREFS_DONE` | `_IOW('c',8,…)` | ptr + cookie |
| `BC_ACQUIRE_DONE` | `_IOW('c',9,…)` | ptr + cookie |
| `BC_REGISTER_LOOPER` | `_IO('c',11)` | — |
| `BC_ENTER_LOOPER` | `_IO('c',12)` | — |
| `BC_EXIT_LOOPER` | `_IO('c',13)` | — |
| `BC_REQUEST_DEATH_NOTIFICATION` | `_IOW('c',14,…)` | handle + cookie |
| `BC_CLEAR_DEATH_NOTIFICATION` | `_IOW('c',15,…)` | handle + cookie |
| `BC_DEAD_BINDER_DONE` | `_IOW('c',16,binder_uintptr_t)` | cookie |
| `BC_TRANSACTION_SG` | `_IOW('c',17,…)` | scatter-gather |
| `BC_REPLY_SG` | `_IOW('c',18,…)` | scatter-gather |

## 5. `BR_` — events you receive

| Event | Encoding (**M** where shown) | Payload |
|---|---|---|
| `BR_ERROR` | `_IOR('r',0,__s32)` | `__s32` |
| `BR_OK` | `_IO('r',1)` | — |
| `BR_TRANSACTION_SEC_CTX` | `_IOR('r',2,…secctx)` | txn + SELinux context |
| `BR_TRANSACTION` | `_IOR('r',2,txn)` | `binder_transaction_data` |
| `BR_REPLY` | `0x80407203` (**M**) | `binder_transaction_data` |
| `BR_ACQUIRE_RESULT` | `_IOR('r',4,__s32)` | `__s32` |
| `BR_DEAD_REPLY` | `_IO('r',5)` | — |
| `BR_TRANSACTION_COMPLETE` | `0x00007206` (**M**) | — |
| `BR_INCREFS` | `_IOR('r',7,…)` | ptr + cookie |
| `BR_ACQUIRE` | `_IOR('r',8,…)` | ptr + cookie |
| `BR_RELEASE` | `_IOR('r',9,…)` | ptr + cookie |
| `BR_DECREFS` | `_IOR('r',10,…)` | ptr + cookie |
| `BR_NOOP` | `0x0000720c` (**M**) | — |
| `BR_SPAWN_LOOPER` | `_IO('r',13)` | — |
| `BR_FINISHED` | `_IO('r',14)` | — |
| `BR_DEAD_BINDER` | `_IOR('r',15,uintptr)` | cookie |
| `BR_CLEAR_DEATH_NOTIFICATION_DONE` | `_IOR('r',16,uintptr)` | cookie |
| `BR_FAILED_REPLY` | `_IO('r',17)` | — |
| `BR_FROZEN_REPLY` | `_IO('r',18)` | — |
| `BR_ONEWAY_SPAM_SUSPECT` | `_IO('r',19)` | — |

---

## 6. Transaction flags and object types

| `TF_` flag | Value | Meaning |
|---|---|---|
| `TF_ONE_WAY` | `0x01` | No reply. `void` only. `getCallingPid()` arrives as 0 |
| `TF_ROOT_OBJECT` | `0x04` | Contents are the root object |
| `TF_STATUS_CODE` | `0x08` | Contents are a 32-bit status |
| `TF_ACCEPT_FDS` | `0x10` | Receiver accepts file descriptors |
| `TF_CLEAR_BUF` | `0x20` | Zero the buffer on free (Android 11+) |
| `TF_UPDATE_TXN` | `0x40` | Replace a pending identical one-way txn |

| `BINDER_TYPE_` | Value | ASCII | Meaning |
|---|---|---|---|
| `BINDER_TYPE_BINDER` | `0x73622a85` | `sb*` | Local object |
| `BINDER_TYPE_WEAK_BINDER` | `0x77622a85` | `wb*` | Local, weak |
| `BINDER_TYPE_HANDLE` | `0x73682a85` | `sh*` | Remote reference |
| `BINDER_TYPE_WEAK_HANDLE` | `0x77682a85` | `wh*` | Remote, weak |
| `BINDER_TYPE_FD` | `0x66642a85` | `fd*` | Real file descriptor |
| `BINDER_TYPE_FDA` | `0x66646185` | `fda` | Descriptor array |
| `BINDER_TYPE_PTR` | `0x70742a85` | `pt*` | Scatter-gather buffer |

| `FLAT_BINDER_FLAG_` | Value | Meaning |
|---|---|---|
| `PRIORITY_MASK` | `0xff` | Minimum scheduling priority |
| `ACCEPTS_FDS` | `0x100` | Node accepts descriptors |
| `TXN_SECURITY_CTX` | `0x1000` | Deliver `BR_TRANSACTION_SEC_CTX` |

---

## 7. Transaction codes

| Code | Decimal | ASCII | Meaning |
|---|---|---|---|
| `0x00000001` | 1 | — | `FIRST_CALL_TRANSACTION` — method 1 of the `.aidl` |
| `0x00ffffff` | 16777215 | — | `LAST_CALL_TRANSACTION` |
| `0x5f4e5446` | 1598968902 | `_NTF` | `INTERFACE_TRANSACTION` — returns the descriptor |
| `0x5f444d50` | 1598311760 | `_DMP` | `DUMP_TRANSACTION` — `dumpsys` |
| `0x5f434d44` | 1598246212 | `_CMD` | `SHELL_COMMAND_TRANSACTION` — `cmd` |
| `0x5f504e47` | 1599098439 | `_PNG` | `PING_TRANSACTION` — `service check` |
| `0x5f535052` | 1599295570 | `_SPR` | `SYSPROPS_TRANSACTION` |
| `0x5f545754` | 1599362900 | `_TWT` | `TWEET_TRANSACTION` — real, unused |
| `0x5f4c494b` | 1598835019 | `_LIK` | `LIKE_TRANSACTION` — real, unused |

**Interface codes are the method's position in the `.aidl`, starting at 1.**

---

## 8. Parcel primitives

| Type | Wire format | Bytes |
|---|---|---|
| `int32`, `boolean` | LE int32 (`true` = 1) | 4 |
| `int64`, `double` | LE, aligned to 8 | 8 |
| `float` | LE IEEE-754 | 4 |
| `byte` | as an int32 | 4 |
| `String16` | int32 **char** count, UTF-16LE, UTF-16 NUL, pad to 4 | `4+2n+2` ↑4 |
| `String8` | int32 byte count, bytes, NUL, pad to 4 | `4+n+1` ↑4 |
| **null** string | int32 `-1`, nothing else | 4 |
| **empty** string | int32 `0`, then just the NUL | 8 |
| byte array | int32 length, bytes, pad to 4 | `4+n` ↑4 |
| null array | int32 `-1` | 4 |
| `IBinder` | `flat_binder_object` + an offsets entry (+ int32 stability) | 24 (+8) (+4) |
| file descriptor | `flat_binder_object`, `type=BINDER_TYPE_FD` | 24 (+8) |
| `Parcelable` | whatever `writeToParcel` wrote. No framing | varies |

### Interface token layout

| Order | Field | Measured value |
|---|---|---|
| 1 | int32 strict-mode policy | `00000000` |
| 2 | int32 work-source uid | `ffffffff` (−1, unset) |
| 3 | int32 header | `0x53595354` = `'SYST'` |
| 4 | `String16` descriptor | e.g. `android.os.IServiceManager` |

### Exception header

| Value | Exception |
|---|---|
| `0` | none (`writeNoException`) |
| `-1` | `SecurityException` |
| `-2` | `BadParcelableException` |
| `-3` | `IllegalArgumentException` |
| `-4` | `NullPointerException` |
| `-5` | `IllegalStateException` |
| `-6` | `NetworkOnMainThreadException` |
| `-7` | `UnsupportedOperationException` |
| `-8` | `ServiceSpecificException` |
| `-9` | `Parcelable` exception |
| `-129` | transaction failed |

After the message string, `writeStackTrace` may append: int32 header size, then a `String16` holding
up to 20 frames.

---

## 9. Identity API

| API | Source of truth | Trust for authorisation? |
|---|---|---|
| `Binder.getCallingUid()` | kernel `task_euid()` | **Yes** |
| `Binder.getCallingUidOrThrow()` | same, throws outside a txn | **Yes — preferred** |
| `Binder.getCallingPid()` | kernel; **0** for `oneway` | No |
| `Binder.getCallingSid()` | kernel; needs `TXN_SECURITY_CTX`; **not restored** after a clear/restore | Only if non-null |
| `Binder.getCallingUserHandle()` | derived from the uid | Yes |
| `Binder.getCallingWorkSourceUid()` | **the parcel** | **NO — caller-written** |
| `Binder.setCallingWorkSourceUid(int)` | sets it for outgoing calls | — |
| `Binder.clearCallingIdentity()` | returns `(uid << 32) \| pid` | It is a save slot, not a capability |
| `Binder.restoreCallingIdentity(long)` | unpacks that token, unvalidated | — |
| `Context.checkCallingPermission()` | wraps uid+pid | Yes |
| `Context.checkCallingOrSelfPermission()` | **falls back to self** | **Almost always wrong** |
| `Context.enforceCallingPermission()` | throws on failure | Yes |
| `Binder.getCallingUidOrThrow()` outside a txn | throws `IllegalStateException` | — |
| a value in the parcel | the caller | **Never** |

### The safe shape

```java
final int uid = Binder.getCallingUidOrThrow();   // 1. capture
enforceAuthorised(uid);                          // 2. decide
final File target = resolveInsideSandbox(name);  // 3. constrain the target
final long token = Binder.clearCallingIdentity();
try { doOnePrivilegedThing(target); }            // 4. one statement
finally { Binder.restoreCallingIdentity(token); } // 5. always
```

---

## 10. Limits

| Limit | Value | Notes |
|---|---|---|
| Receive buffer | `1 MiB - 2 * PAGE_SIZE` = **1040384** bytes (**M**) | Per **process**, all incoming transactions |
| Async (`oneway`) budget | `buffer_size / 2` | Separate exhaustion path |
| `TransactionTooLargeException` | thrown only when the outgoing parcel > **200 KiB** | Otherwise `DeadObjectException` / `RuntimeException` |
| Thread pool | 15 + main = 16 by default; `system_server` higher | Never shrinks |
| Stack trace in an exception parcel | up to 20 frames | `Parcel.writeStackTrace` |
| Transaction code range | 1 .. `0x00ffffff` | Above that is the `_XXX` space |

---

## 11. `service` command

```
service list
service check SERVICE
service call SERVICE CODE [i32 N | i64 N | f N | d N | s16 STR | null
                           | fd FILE | nfd N | afd FILE] ...
```

| Arg | Writes |
|---|---|
| `i32 N` | 32-bit int |
| `i64 N` | 64-bit int |
| `f N` | float |
| `d N` | double |
| `s16 STR` | UTF-16 string |
| `null` | a null binder |
| `fd FILE` | a descriptor for FILE |
| `nfd N` | descriptor number N |
| `afd FILE` | an **ashmem** descriptor holding FILE's contents |

**`service call` writes the interface token for you**, obtained by sending `'_NTF'` first.
It cannot write booleans (use `i32 1`), arrays, `Parcelable`s, `Bundle`s or `List`s.

```bash
# adb shell — the standard opening moves
service list | wc -l                       # M: 217
service check notification
service call notification 1598968902       # '_NTF' -> "android.app.INotificationManager"
service call notification 1599098439       # '_PNG'
service call notification 2                # M: SecurityException "Disallowed call for uid 2000"
service call package 1 s16 com.android.settings
```

---

## 12. `dumpsys` and `cmd` entry points

| Command | Underlying code | Notes |
|---|---|---|
| `dumpsys -l` | — | Lists services answering `'_DMP'`. **M: 211** |
| `dumpsys SERVICE [args]` | `'_DMP'` = 1598311760 | Runs in the *service's* process, writes to *your* fd |
| `dumpsys SERVICE --help` | `'_DMP'` | Many accept flags |
| `dumpsys activity services` | `'_DMP'` | Bound services and their clients |
| `dumpsys binder_calls_stats` | `'_DMP'` | Per-UID call counts. Forensics |
| `dumpsys package PKG` | `'_DMP'` | uid, permissions, components |
| `cmd -l` | — | Services answering `'_CMD'`. **M: 217** |
| `cmd SERVICE ARGS` | `'_CMD'` = 1598246212 | Passes stdin/stdout/stderr as real fds |
| `cmd package list packages` | `'_CMD'` | |
| `am` / `pm` | `'_CMD'` shims | |

Root-only forensic sources: `/dev/binderfs/binder_logs/state`, `/transactions`,
`/failed_transaction_log`, `/stats`. (**M**: `Permission denied` to uid 2000.)

---

## 13. This chapter's tools

```bash
# host — enumerate: name -> interface -> owner -> SELinux type
python3 -B scripts/binder-service-map.py
python3 -B scripts/binder-service-map.py --no-interface      # no token check
python3 -B scripts/binder-service-map.py --unlabelled        # default SELinux type
python3 -B scripts/binder-service-map.py --explain notification
python3 -B scripts/binder-service-map.py --capture ./snap
python3 -B scripts/binder-service-map.py --fixture examples/fixture-device-snapshot
python3 -B scripts/binder-service-map.py --json > snap.json

# host — decode a parcel dump from `service call` or from the C probe
python3 -B scripts/parcel-decode.py --paste          # then paste and Ctrl-D
python3 -B scripts/parcel-decode.py dump.txt --as token
adb shell service call activity 1598968902 | python3 -B scripts/parcel-decode.py -

# host — build and run the raw client
$NDK/aarch64-linux-android21-clang -Wall -Wextra -O2 examples/binder-probe.c -o binder-probe
adb push binder-probe /data/local/tmp/ && adb shell chmod 755 /data/local/tmp/binder-probe
adb shell /data/local/tmp/binder-probe
adb shell /data/local/tmp/binder-probe --getservice activity
adb shell /data/local/tmp/binder-probe --call notification 2
adb shell /data/local/tmp/binder-probe --call notification 2 --forge-uid 0
adb shell /data/local/tmp/binder-probe --call notification 2 --token android.os.IServiceManager

# host — trace transactions live
frida -U -f com.example.target -l scripts/trace-binder-transactions.js
frida -U -n system_server     -l scripts/trace-binder-transactions.js
```

---

## 14. Static-analysis greps

```bash
# services this app publishes
grep -rn "extends .*\.Stub\b" out/sources/
grep -rn "protected boolean onTransact" out/sources/

# THE headline query: onTransact with no interface token check
grep -rln "onTransact" out/sources/ | xargs grep -L "enforceInterface"

# onTransact with no caller check at all
grep -rln "onTransact" out/sources/ | xargs grep -L "getCallingUid\|checkCalling\|enforceCalling"

# descriptors -- these survive R8 and are often the original class names
grep -rhn 'DESCRIPTOR = "' out/sources/ | sed 's/.*= //' | tr -d '";' | sort -u

# transaction codes
grep -rn "FIRST_CALL_TRANSACTION" out/sources/

# identity misuse
grep -rn -B5 -A20 "clearCallingIdentity" out/sources/
grep -rn "checkCallingOrSelfPermission" out/sources/
grep -rn "getCallingWorkSourceUid"       out/sources/

# smali
grep -rn "enforceInterface" out_apktool/smali*/
grep -rn -A30 "sparse-switch" out_apktool/smali*/ | grep "0x5f4e5446"

# native
$NDK/llvm-nm -DC libx.so | grep -iE "onTransact|BnInterface|BpInterface|getCallingUid"
$NDK/llvm-strings libx.so | grep -E "^[a-z][a-z0-9_]*(\.[A-Za-z0-9_]+){2,}$" | sort -u
```

---

## 15. Triage table

| Observation | Severity | Next step |
|---|---|---|
| `onTransact` with no `enforceInterface` | High | Every code reachable with an arbitrary parcel. Enumerate codes |
| No `getCallingUid` anywhere in `onTransact` | High | Call every method from an unprivileged app |
| `clearCallingIdentity` before the check | Critical if the service is privileged | Confused deputy. Find the caller-controlled target |
| `clearCallingIdentity` with no `finally` | Medium | Force an exception inside the window |
| Empty interface descriptor from `'_NTF'` | Lead | Raw `BBinder`. Sweep codes on a spare device |
| SELinux type is `default_android_service` | Lead | Check whether `untrusted_app` has `find` on it |
| Persisted bare UID as authorisation | Medium | UID recycling after uninstall |
| Large `oneway` accepted with no size check | Medium (availability) | Ramp the size; report as DoS |
| `getCallingWorkSourceUid` used in a check | High | It is caller-written. Trivially bypassed |
| `ThreadLocal` in a Binder service | Medium | Pooled threads; cross-request leakage |
| Finding only reproducible from `adb shell` | **Not a finding yet** | Reproduce from an app or drop it |
