# 25 — Binder — FAQ

Real questions, including the ones people are embarrassed to ask. Answers marked **measured** were
verified on a Xiaomi M2101K6P, Android 11 / API 30, arm64, kernel 4.14.180, from `adb shell` as
uid 2000 with no root.

---

### 1. What actually *is* `/dev/binder`? Is it a file?

It is a **character device**: an entry in `/dev` that looks like a file to programs but has no
storage behind it. Opening it runs kernel code. Reading and writing it in the ordinary way does
almost nothing — everything happens through `ioctl()`, a system call for operations that do not fit
"read some bytes" or "write some bytes".

So when you see `open("/dev/binder")`, nothing is being read from disk. A driver called
`drivers/android/binder.c` is being handed a file descriptor you will use to send it commands.

**Measured** — on the test device it is not even a device node directly, but a symlink:

```
/dev/binder -> /dev/binderfs/binder
```

That is normal on any device using **binderfs** (question 3).

---

### 2. Why is there `/dev/hwbinder` and `/dev/vndbinder` too? Are they copies?

They are three **independent instances of the same driver**, each with its own object namespace, its
own manager process, and its own SELinux label. An object registered on one is invisible from the
others, and handle numbers do not carry across.

The reason is **Project Treble**, in Android 8.0. Before it, vendor code and framework code shared
one Binder world, so a vendor HAL and a framework service could quietly grow dependencies on each
other — and then updating one without the other broke the device. Splitting the namespaces made the
dependency impossible to *express* rather than merely discouraged.

| Node | Carries | Manager |
|---|---|---|
| `/dev/binder` | Everything an app ever sees. Framework AIDL | `servicemanager` |
| `/dev/hwbinder` | HIDL interfaces between framework and vendor | `hwservicemanager` |
| `/dev/vndbinder` | Vendor-to-vendor traffic only | `vndservicemanager` |

**Measured** — `shell` (uid 2000) could open `/dev/binder` and `/dev/hwbinder`, and was refused
`/dev/vndbinder` with `Permission denied`. An ordinary app is more restricted still.

Practical upshot: `service list` shows you **only** `/dev/binder`. Use `lshal` for the `hwbinder`
namespace. There is no convenient tool for `vndbinder` and it does not matter, because from an app
you cannot open the node at all.

---

### 3. What is binderfs and why did my `/dev/binder` become a symlink?

Binderfs is a tiny in-kernel filesystem (`drivers/android/binderfs.c`) that can be mounted more than
once, so each container — or each Android instance running inside one — gets its own private set of
binder devices instead of sharing the host's.

On a phone, two things change:

- `/dev/binder` and friends are symlinks into `/dev/binderfs/`.
- The debug interface moved. **Measured**: `/sys/kernel/debug/binder` did not exist, and
  `/dev/binderfs/binder_logs/stats` returned `Permission denied` to uid 2000. Those files need root.

If a tutorial tells you to `stat /dev/binder` and expect a character device, and you get a symlink,
nothing is broken. Follow the link.

---

### 4. Can I forge `getCallingUid()`?

**No.** And this is worth taking seriously rather than accepting on faith, because the structure you
fill in as the caller *contains* a `sender_euid` field. It is right there. It is writable. It is in
your own memory.

It is also never read on the way in. Inside the driver, `binder_transaction()` assigns:

```c
t->sender_euid = task_euid(proc->tsk);
```

`proc->tsk` is the kernel's own record of the calling process. The field exists in the structure only
because the *same* structure is reused for delivery, where the kernel fills it in for the receiver.

**Measured**, three times, with `examples/binder-probe.c` sending a hand-built transaction to
`INotificationManager` — a service that reports the UID it saw in its error message:

| We claimed | Service replied |
|---|---|
| nothing | `SecurityException: "Disallowed call for uid 2000"` |
| `sender_euid = 0` (root) | `SecurityException: "Disallowed call for uid 2000"` |
| `sender_euid = 1000` (system) | `SecurityException: "Disallowed call for uid 2000"` |

2000 is the real uid of `adb shell`. Reproduce it yourself:

```bash
# adb shell
/data/local/tmp/binder-probe --call notification 2
/data/local/tmp/binder-probe --call notification 2 --forge-uid 0
```

**What *does* work**, and is what you should look for instead: the **confused deputy**. Do not try to
become another UID; find a privileged service that will act on your behalf. README §5.2.4.

---

### 5. If it cannot be forged, why is `getCallingUid()` in so many vulnerability write-ups?

Because the failure is never the *value*, it is what the service does with it:

- It never calls it at all.
- It calls it **after** `clearCallingIdentity()`, so it is comparing the service against itself.
- It calls it on a **worker thread**, where the identity is not the caller's.
- It calls `getCallingWorkSourceUid()` by mistake, which *is* caller-written parcel data.
- It authorises on a bare UID that gets **recycled** after an uninstall.
- It resolves the UID to a package name and takes `getPackagesForUid(uid)[0]`, which is an arbitrary
  member of a set when a shared UID is involved.

The transport is sound. The two ends are where the bugs are.

---

### 6. Why did my big Parcel throw `TransactionTooLargeException`?

Because a process gets **one** buffer for all incoming Binder data, and yours or the target's ran
out.

**Measured** — that buffer is `1 MiB` minus two pages:

```
mmap(NULL, 1040384, PROT_READ, MAP_PRIVATE|MAP_NORESERVE, 3, 0)
  1048576 - (4096 * 2) = 1040384 bytes = 1016 KiB
```

Four things people get wrong about it:

1. **It is per process, not per call.** Every simultaneous incoming transaction shares it.
2. **It cannot be raised.** There is no setting, no manifest attribute, no system property.
3. **One-way transactions get only half of it**, tracked separately.
4. **The exception name lies about the frequency.** `TransactionTooLargeException` is thrown only
   when the *outgoing parcel exceeded 200 KiB*. Below that, the same underlying failure is reported
   as `DeadObjectException` (or `RuntimeException`), with a message saying the remote process
   probably died — and AOSP's own source comments admit the driver cannot tell the two apart.

So: **an intermittent `DeadObjectException` from a service that is definitely alive is very often
buffer exhaustion.** Look for unclosed `Cursor`s, retained `Bundle`s, and heavy one-way traffic in
the target.

The fix is never a bigger buffer. Pass an `ashmem`/`memfd` file descriptor, or a `content://` URI,
and let the receiver pull the data.

---

### 7. What is an interface token actually for? It looks like a formality.

It is a security control, and the reason is that **a parcel has no type information at all.** No
tags, no field names, no schema — just bytes in an agreed order.

Suppose interface `IAlpha` declares `method 1 = deleteFile(String)` and `IBravo` declares
`method 1 = setAdmin(boolean)`. A parcel built for `IAlpha.deleteFile("x")` is *also* a perfectly
well-formed parcel for `IBravo.setAdmin(...)` — the reader will take the string's length field as the
boolean and carry on happily. Without a token, any reachable object could be driven using a different
interface's calling convention.

The token forces the caller to **name the contract it believes it is using**, and the receiver
rejects a mismatch.

**Measured** — correct handle, correct code, wrong token:

```
we are claiming : "android.os.IServiceManager"
the object is   : "android.app.INotificationManager"
exception code  : -1  (SecurityException)
message         : "Binder invocation to an incorrect interface"
```

A `SecurityException`, not a parse error. That is the framework authors telling you what they thought
it was for.

**What it is not:** authentication. The descriptor is public — it is in the AIDL, in the DEX, and any
object will hand it to you if you ask with transaction code `1598968902`.

---

### 8. Is AIDL the same thing as Binder?

No, and the distinction matters.

| | Binder | AIDL |
|---|---|---|
| What it is | The kernel driver and the transport | A **code generator** |
| Where it lives | `drivers/android/binder.c`, `libbinder` | `system/tools/aidl`, at build time |
| Can you use one without the other? | Yes, both ways | Yes, both ways |

AIDL takes a `.aidl` file and writes the boring, error-prone code for you: a `Stub` that switches on
the transaction code and reads the parcel, and a `Proxy` that writes the parcel and calls
`transact`. Nothing it generates is magic. You can write both by hand — `examples/RawBinderClient.java`
does exactly that, and `examples/binder-probe.c` does it in C with no framework at all.

The practical consequence for an attacker: **the generated client is a convenience, not a gate.**
A service that assumes callers will use the client library it shipped is wrong. Anyone with the
descriptor string and a code number can build the parcel themselves.

---

### 9. Where do transaction codes come from? Why is `readSecret` code 1?

The method's **position in the `.aidl` file, starting at 1**. `IBinder.FIRST_CALL_TRANSACTION` is 1,
and the generated code is `FIRST_CALL_TRANSACTION + n` for the zero-based index.

```java
interface IVault {
    String readSecret(String n);   // code 1
    void   writeSecret(String n, String v);  // code 2
    boolean deleteSecret(String n);  // code 3
}
```

Two consequences:

- **Reordering methods in an `.aidl` is a breaking ABI change.** This is why AOSP interfaces only
  ever append.
- **You can call any method by number** once you have the `.aidl` or the decompiled `Stub`. That is
  the single most useful fact in the chapter for offensive work.

---

### 10. What are those huge numbers like 1598968902?

Four ASCII characters packed big-endian into a 32-bit integer.

| Decimal | Hex | ASCII | Meaning |
|---|---|---|---|
| 1598968902 | `0x5f4e5446` | `_NTF` | "What interface are you?" |
| 1598311760 | `0x5f444d50` | `_DMP` | What `dumpsys` sends |
| 1598246212 | `0x5f434d44` | `_CMD` | What `cmd` sends |
| 1599098439 | `0x5f504e47` | `_PNG` | Ping — what `service check` uses |
| 1599295570 | `0x5f535052` | `_SPR` | "Reload your system properties" |

They sit far above the interface range (1 to `0x00ffffff`), so they can never collide with a real
method. They work on **every** service because the AIDL-generated `switch` ends with
`return super.onTransact(...)`, and the base class implements them.

`'_TWT'` (`TWEET_TRANSACTION`) and `'_LIK'` (`LIKE_TRANSACTION`) are also real constants in
`IBinder.java`. They do nothing. They are a joke that shipped.

---

### 11. What is the difference between `oneway` and a normal call?

| | Synchronous | `oneway` |
|---|---|---|
| Caller blocks | yes | no |
| Return type | anything | must be `void` |
| Exceptions reach the caller | yes | **no** |
| `getCallingPid()` on the receiver | real PID | **0** |
| Buffer budget | the whole region | **half** |

The `getCallingPid() == 0` is the one that catches people. The driver only records a sending thread
for synchronous transactions — there is nobody to reply to otherwise — and the delivery path reports
0 when that record is absent. So any authorisation logic comparing the PID behaves differently on
`oneway` methods. (One more reason to authorise on the UID.)

The exception-swallowing is the one that causes outages. Convert a method to `oneway` for
performance and every caller that was relying on a thrown `SecurityException` silently stops
noticing failures.

---

### 12. Why does one `service call` show four `ioctl`s in `strace`?

Because a single visible call is several transactions.

**Measured** — `strace -f service call activity 1598968902` was 1,157 syscalls, of which eight were
Binder:

```
openat("/dev/binder", O_RDWR|O_CLOEXEC) = 3
ioctl(3, BINDER_VERSION, ...)
ioctl(3, BINDER_SET_MAX_THREADS, ...)
mmap(NULL, 1040384, PROT_READ, MAP_PRIVATE|MAP_NORESERVE, 3, 0)
ioctl(3, BINDER_WRITE_READ, ...)   x4
```

The four `BINDER_WRITE_READ` calls are: resolve the name through `servicemanager` (a transaction of
its own, to handle 0), send your transaction, collect the reply, and hand the reply buffer back with
`BC_FREE_BUFFER`.

---

### 13. Why does `service call` work at all — doesn't it need the interface token?

It writes it for you. `frameworks/native/cmds/service/service.cpp` does:

```cpp
data.writeInterfaceToken(service->getInterfaceDescriptor());
```

and `getInterfaceDescriptor()` obtains the string by sending `'_NTF'` to the object first. That is
why the tool works against AIDL services without you telling it anything.

It also explains a measured result in the README: calling `notification` code 2 from `adb shell`
produced *"Disallowed call for uid 2000"* — an identity refusal — rather than *"Binder invocation to
an incorrect interface"*. The token was right; we were not allowed.

What `service call` **cannot** write: booleans (use `i32 1`), byte arrays, `Parcelable`s, `Bundle`s,
`List`s, `Map`s, or a `String8`. This is where it runs out of road on most interesting methods and
you move to `examples/RawBinderClient.java` or `examples/binder-probe.c`.

---

### 14. A service shows `[]` for its interface in `service list`. Is that broken?

No — and it is probably the most interesting row on the page.

An empty descriptor means the object did not answer `INTERFACE_TRANSACTION` with a string, which
almost always means it is a **raw `BBinder`/`Binder` subclass with a hand-written `onTransact`**
rather than an AIDL-generated `Stub`. Consequences:

- There is no `enforceInterface`, so **no interface token is required**. Every transaction code is
  reachable with an arbitrary parcel.
- There is no generated argument parsing, so the field layout is whatever the author wrote — and in
  a native service, a length read from the parcel without validation is a memory-corruption
  primitive.

**Measured** — 35 of 217 services on the test device had an empty descriptor, including
`DockObserver`, `SchedBoostService`, `battery`, `app_binding`, `cacheinfo` and the AIDL HALs. Most
are ordinary native services that never had an AIDL interface; that is normal. But it is exactly the
set worth reading.

Find them with:

```bash
python3 -B scripts/binder-service-map.py --no-interface
```

---

### 15. Is it safe to sweep transaction codes on a service?

On a device you care about, **no**.

A service with no token check and no argument validation reads whatever happens to be at the current
parcel position. A native `onTransact` that takes a length from the parcel and uses it unchecked will
segfault. If that service is `system_server`, the device reboots. If it is a HAL, you may need a
factory reset.

Do it on an emulator or a spare device, attach a death recipient first so you know exactly which code
killed it, and go one code at a time:

```java
binder.linkToDeath(() -> Log.w(TAG, "died at code " + currentCode), 0);
```

`labs/lab-04-transaction-limits.md` and `labs/lab-05-ctf-the-unmarked-code.md` do this responsibly.

---

### 16. Can an app register its own service with `servicemanager`?

**No.** `ServiceManager::addService` refuses any caller whose app-id is `AID_APP` (10000) or above,
before SELinux is even consulted — and then asks SELinux for `service_manager:add` on the name's
type as well.

What an app *can* do is publish a `Service` with `onBind()`, which hands an `IBinder` to whoever
binds it. That object is a perfectly real Binder object; it is not in the global name
registry. Reaching it requires an `Intent` and `bindService()`, which is
[24 — IPC](../24-IPC/README.md)'s and [26 — Intent](../26-Intent/README.md)'s territory.

---

### 17. My service checks the manifest permission. Isn't that enough?

No. The manifest `android:permission` is checked **once, by ActivityManager, at bind time**. After
that the caller holds an `IBinder`, and an `IBinder` is a **capability**: it can be put in an
`Intent` extra, wrapped in a `Messenger`, or returned from another service, and whoever receives it
can call it without ever having satisfied the manifest permission.

So check inside `onTransact` as well, on every entry point, using `Binder.getCallingUidOrThrow()`.
The manifest permission decides who may *obtain* the object; your code decides who may *use* it, and
those are different populations.

---

### 18. Why is `checkCallingOrSelfPermission()` considered a bug?

Because of the "OrSelf". When there is no active Binder transaction — you are on a worker thread,
or the method was called internally — it falls back to checking the **service's own** permissions.
Services usually hold the permission they are guarding. So it passes.

During development it never fails, which is exactly why it survives to production.

Use `checkCallingPermission()` or `enforceCallingPermission()`. If you genuinely need the self case,
say so explicitly and comment why.

---

### 19. Does obfuscation hide an AIDL interface from me?

Barely. It removes the *meaning* and leaves the *protocol* entirely intact.

| Element | Survives R8? |
|---|---|
| The `DESCRIPTOR` string | **Always.** Both ends compare it at runtime, so it cannot be rewritten — and it is very often the *original, un-obfuscated* class name |
| The transaction codes | **Always.** They are inlined integer constants |
| The parcel layout | **Always.** It is calls on `android.os.Parcel`, a framework class |
| The `Stub` class name | Usually renamed |
| Method names | Usually renamed |

So you can call every method, with the right arguments, in the right order — you just do not know
what they are called. Recovering meaning is then a matter of calling them and watching, which is
Frida's job.

Start here:

```bash
grep -rhn 'DESCRIPTOR = "' out/sources/ | sed 's/.*= //' | sort -u
```

---

### 20. I found an exposed service from `adb shell`. Is that a finding?

**Not yet**, and this is the single most common false positive in Binder assessment.

`adb shell` runs as uid 2000 in the SELinux domain `shell`, which holds a large set of platform
permissions and `service_manager:find` rules that **no app has**. Plenty of services that answer you
happily from `adb shell` are completely unreachable from an app context.

Before you write anything up, reproduce it from an ordinary, unprivileged APK — uid 10xxx, domain
`untrusted_app`. `examples/RawBinderClient.java` is the code to drop into that APK.
If it does not reproduce, you have found a property of `shell`, not a vulnerability.

---

### 21. Where do I look for forensic evidence of Binder activity?

| Source | Gives you | Needs |
|---|---|---|
| `dumpsys binder_calls_stats` | Per-UID call counts and latencies — *who has been calling what* | `shell` |
| `dumpsys activity services` | Currently bound services and their clients | `shell` |
| logcat | `SecurityException` stack traces from refused calls, naming the guard and the caller UID | `shell` |
| `/dev/binderfs/binder_logs/state` | Live nodes, refs and transactions per process | **root** |
| `/dev/binderfs/binder_logs/transactions` | Recent transactions | **root** |
| `/dev/binderfs/binder_logs/failed_transaction_log` | Transactions the driver refused | **root** |

**Measured** — `binder_calls_stats` was registered on the test device, and the `binder_logs` paths
returned `Permission denied` to uid 2000, confirming the root requirement.

Do not overlook logcat. A refused call leaves a stack trace naming the guard method, its class, and
the line in the generated stub — free reconnaissance that a *successful* call would not have given
you.

---

### 22. Why is `/dev/binder` openable by every app? Isn't that dangerous?

It is, and it is also unavoidable: an app that cannot open the driver cannot start an activity, draw
a pixel, or ask what time it is. The whole framework is on the other side of it.

The consequence is real, though. `binder.c` is one of very few kernel drivers directly reachable from
an unprivileged, untrusted app sandbox **with no permission at all**, which is why Binder
use-after-free bugs have historically been among the most valuable Android kernel targets: they are a
direct route from an app to kernel code execution.

The mitigations are not access control but (a) keeping the driver small and its object-lifetime rules
strict, (b) putting everything *reachable through* it behind a context manager and two SELinux
checks, and (c) `seccomp` filtering and `isolatedProcess` for components that parse untrusted data.
