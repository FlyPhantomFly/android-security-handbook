# 25 — Binder — References

Annotated. Every entry says **why you would open it**, not just what it is called.

**No line numbers appear anywhere in this chapter.** They move every release, and a confident wrong
line number is worse than none at all. File paths in AOSP and in the Linux tree are stable and are
cited freely.

---

## 1. Kernel source — the driver itself

| Path | Why you would open it |
|---|---|
| `drivers/android/binder.c` | The whole driver. `binder_ioctl` dispatches; `binder_thread_write` consumes the `BC_` stream; `binder_thread_read` produces the `BR_` stream; **`binder_transaction()` is the function that matters** — it allocates in the target's mapping, copies the parcel, translates every embedded object, and assigns `t->sender_euid = task_euid(proc->tsk)`. That one assignment is why README §3.11 is true |
| `drivers/android/binder_alloc.c` | `binder_alloc_mmap_handler()` records the mapping and sets `free_async_space` to half of it; `binder_alloc_new_buf()` is the best-fit allocator whose failure becomes `BR_FAILED_REPLY` and eventually `TransactionTooLargeException`. Read this before arguing about the 1 MB limit |
| `drivers/android/binder_alloc.h` | The free-list and buffer structures the allocator manages |
| `drivers/android/binderfs.c` | Why `/dev/binder` is a symlink on modern devices, and where `binder_logs` went |
| `include/uapi/linux/android/binder.h` | The user-space ABI: every structure and constant transcribed in README §3 and in `examples/binder-probe.c`. This is the authoritative list of `BC_`, `BR_`, `TF_` and `BINDER_TYPE_` values |
| `include/uapi/linux/android/binderfs.h` | binderfs mount options and device control |
| `security/selinux/hooks.c` | `selinux_binder_transaction` and `selinux_binder_transfer_binder` — the LSM hooks behind the `binder:call` and `binder:transfer` checks. The policy side is [22 — SELinux](../../22-SELinux/README.md) |

Browse at `https://android.googlesource.com/kernel/common/` or, for the mainline versions,
`https://git.kernel.org/`. The Android common kernels are the ones that ship on devices.

---

## 2. AOSP — native user space (`libbinder`)

| Path | Why you would open it |
|---|---|
| `frameworks/native/libs/binder/ProcessState.cpp` | `open("/dev/binder")`, `BINDER_VERSION`, `BINDER_SET_MAX_THREADS`, and the `mmap` of `BINDER_VM_SIZE`. The definition of that constant is the answer to "why 1040384 bytes" |
| `frameworks/native/libs/binder/IPCThreadState.cpp` | `transact()`, `writeTransactionData()`, `waitForResponse()`, `talkWithDriver()` — the single place the `ioctl` happens — and `executeCommand()`, where `mCallingUid` and `mCallingPid` are set from the kernel's fields. Also `clearCallingIdentity()` and `restoreCallingIdentity()`, which are ten lines and worth reading in full |
| `frameworks/native/libs/binder/Parcel.cpp` | `writeInterfaceToken()` and `enforceInterface()` — the four-field header measured in README §3.16; `writeString16()`; `flattenBinder()`/`unflattenBinder()`, which is where the `BC_ACQUIRE`-before-`BC_FREE_BUFFER` rule lives; `ipcSetDataReference()`, the "single copy" |
| `frameworks/native/libs/binder/Binder.cpp` | `BBinder::transact` and the default `onTransact` that answers `'_NTF'`, `'_PNG'`, `'_DMP'` and `'_CMD'` on every object in the system. Also `BBinder::shellCommand` |
| `frameworks/native/libs/binder/BpBinder.cpp` | The client-side proxy: the handle number, `transact()`, and death-recipient bookkeeping |
| `frameworks/native/libs/binder/Stability.cpp` | The trailing int32 that appears after every `writeStrongBinder` — the `0c000000` in the measured dump in README §3.7.3 |
| `frameworks/native/libs/binder/IServiceManager.cpp` | The client side of name resolution, including the retry loop that makes `getService` different from `checkService` |
| `frameworks/native/libs/binder/include/binder/IBinder.h` | `FIRST_CALL_TRANSACTION`, `LAST_CALL_TRANSACTION`, and the `_XXX` constants as C++ |
| `frameworks/native/libs/binder/include/binder/Parcel.h` | The full read/write API. Useful when you are working out what a native `onTransact` is doing from its call sequence |
| `frameworks/native/libs/binder/include/binder/IInterface.h` | `DECLARE_META_INTERFACE` / `IMPLEMENT_META_INTERFACE` — the macros that generate the descriptor string you find in `.rodata` (README §6.4) |

---

## 3. AOSP — `servicemanager` and the command-line tools

| Path | Why you would open it |
|---|---|
| `frameworks/native/cmds/servicemanager/ServiceManager.cpp` | `addService`'s two gates — the `AID_APP` numeric refusal and the SELinux `service_manager:add` check — plus `getService`, `checkService`, `listServices` and `getServiceDebugInfo` |
| `frameworks/native/cmds/servicemanager/Access.cpp` | `canAdd`, `canFind`, `canList`.the caller's context comes from `IPCThreadState`, i.e. from the kernel, not from the parcel |
| `frameworks/native/cmds/servicemanager/main.cpp` | Where `BINDER_SET_CONTEXT_MGR` is issued, making this process handle 0 |
| `frameworks/native/libs/binder/aidl/android/os/IServiceManager.aidl` | Method order equals transaction code. `getService` is 1, `checkService` is 2, `addService` is 3, `listServices` is 4 |
| `frameworks/native/cmds/service/service.cpp` | What `service list` and `service call` actually send. Crucially, it calls `data.writeInterfaceToken(service->getInterfaceDescriptor())` for you — see FAQ 13 — and its argument vocabulary (`i32`, `s16`, `afd`, …) is the whole of what the tool can express |
| `frameworks/native/cmds/dumpsys/dumpsys.cpp` | `dumpsys` is `'_DMP'` plus a file descriptor and an argument array. Nothing more |
| `frameworks/native/cmds/cmd/cmd.cpp` | `cmd` is `'_CMD'` plus three real descriptors, an argument array, a `ShellCallback` and a `ResultReceiver` |
| `frameworks/native/cmds/lshal/` | The `hwbinder` equivalent of `service list`, and unlike it, `lshal` reports pids |

---

## 4. AOSP — Java framework

| Path | Why you would open it |
|---|---|
| `frameworks/base/core/java/android/os/Binder.java` | `Binder`, `BinderProxy`, `execTransact`/`execTransactInternal`, and the entire identity API: `getCallingUid`, `getCallingUidOrThrow`, `getCallingPid`, `getCallingSid`, `clearCallingIdentity`, `restoreCallingIdentity`, `getCallingWorkSourceUid` |
| `frameworks/base/core/java/android/os/IBinder.java` | `FIRST_CALL_TRANSACTION`, `INTERFACE_TRANSACTION`, `DUMP_TRANSACTION`, `SHELL_COMMAND_TRANSACTION`, `PING_TRANSACTION`, `TWEET_TRANSACTION`, `LIKE_TRANSACTION`, `FLAG_ONEWAY`, `FLAG_CLEAR_BUF` |
| `frameworks/base/core/java/android/os/Parcel.java` | `writeException`/`readException` and the exception-code table; `writeStackTrace`, which appends the remote trace that makes a refusal so informative; `writeInterfaceToken` |
| `frameworks/base/core/jni/android_util_Binder.cpp` | The JNI bridge. `android_os_Binder_getCallingUid` returns the `IPCThreadState` value straight through. **`signalExceptionForError` is where the 200 KiB heuristic lives** that decides whether `FAILED_TRANSACTION` becomes `TransactionTooLargeException` or `DeadObjectException` — and its comment admits the driver cannot distinguish the causes |
| `frameworks/base/core/java/android/os/ServiceManager.java` | The Java-side cache in front of `servicemanager`, and why a service looked up once stays looked up |
| `frameworks/base/core/java/android/app/ActivityThread.java` | `handleBindApplication` — the method that constructs your `Application`. See README §3.17.1 and [09](../../09-Android-App-Internals/README.md) |
| `frameworks/base/core/java/android/app/IApplicationThread.aidl` | The reverse-direction interface your app serves to `system_server`, including `bindApplication` |
| `frameworks/base/core/java/android/os/ParcelFileDescriptor.java` | The Java wrapper around `BINDER_TYPE_FD` — Binder's `SCM_RIGHTS` |

---

## 5. AIDL

| Resource | Why |
|---|---|
| `system/tools/aidl/` | The compiler. Reading its generator is the fastest way to internalise the `Stub`/`Proxy` shape you will spend your career recognising in JADX |
| Android Developers — *Android Interface Definition Language (AIDL)* | The developer-facing contract: types, `oneway`, `in`/`out`/`inout`, and what generated code looks like |
| Android Developers — *Bound services* | `onBind`, `bindService`, and how an `IBinder` is handed out in the first place |
| AOSP — *Stable AIDL* | Versioned interfaces, `@VintfStability`, and the `Stability` int32 in the measured parcel in README §3.7.3 |
| AOSP — *AIDL for HALs* | The Android 11+ replacement for HIDL, and why `hwbinder` traffic is shrinking |

---

## 6. Platform architecture

| Resource | Why |
|---|---|
| AOSP — *Treble* and the vendor interface | Why there are three binder device nodes rather than one |
| AOSP — *SELinux concepts* and *Implementing SELinux* | The `binder` and `service_manager` object classes. The two-stage decision is [22 §3.15](../../22-SELinux/README.md#315-binder-and-service_manager-a-two-stage-mac-decision) |
| Linux kernel documentation — `binderfs` | The filesystem behind `/dev/binderfs` |
| Android Security Bulletins (monthly index) | The authoritative source for actual Binder CVEs. **Use the index rather than any number quoted from memory** — that is how errors enter documents |
| Android Open Source Project — `platform_testing` binder benchmarks | If you need real numbers for latency and throughput rather than folklore |

---

## 7. Background and research

| Resource | Why |
|---|---|
| OpenBinder documentation (Palm / Be, archived) | The original design and its vocabulary. Explains why Binder is object-oriented rather than connection-oriented, and why there is no `connect()` |
| Norman Hardy, *The Confused Deputy* (1988) | The paper the term comes from. Two pages, and it reframes every `clearCallingIdentity` bug you will ever look at |
| Project Zero's Android kernel writeups | The canonical demonstrations of why a driver every app can open is worth hardening obsessively |
| *Android Internals: A Confectioner's Cookbook* — Jonathan Levin | The most detailed third-party treatment of Binder's internals in print |
| Karim Yaghmour, *Embedded Android* | Older, but the servicemanager and HAL chapters remain a good orientation |

---

## 8. OWASP MASVS / MASTG

| Identifier | Application here |
|---|---|
| **MASVS-PLATFORM-1** — IPC mechanisms are used securely | The chapter's core. Is `enforceInterface` present, is `getCallingUid` checked, is the `clearCallingIdentity` window narrow |
| **MASVS-PLATFORM-2** — WebView and platform interaction | Where a `@JavascriptInterface` is backed by an exported binder |
| **MASVS-CODE-4** — external input is validated | A parcel **is** external input. README §5.2.5 |
| **MASVS-AUTH-1** — authentication is enforced where it cannot be bypassed | An identity written into a parcel is a client-side claim. README §3.11.4 |
| **MASVS-STORAGE-2** — no sensitive data leaked to other apps | `TF_CLEAR_BUF`, and file descriptors passed over Binder. README §3.5.1, §3.7.4 |
| **MASTG** — the IPC testing chapter | The manual methodology this chapter's §5.6 expands on |

---

## 9. Tooling

| Tool | Use here |
|---|---|
| `adb`, `service`, `dumpsys`, `cmd` | Everything in README §7.1, no root required |
| `lshal` | The `hwbinder` namespace, **with pids** |
| [Frida](https://frida.re) | README §7.3–7.5, and `scripts/trace-binder-transactions.js` |
| [JADX](https://github.com/skylot/jadx) | Recovering `DESCRIPTOR` and the `TRANSACTION_*` constants |
| [apktool](https://apktool.org) | Smali when JADX fails — README §6.3 |
| Ghidra / IDA | Native `onTransact` — README §6.4 |
| Android NDK (`aarch64-linux-android21-clang`, `llvm-nm`, `llvm-strings`) | Building `examples/binder-probe.c`, and README §8.4 |
| `strace` | Confirming *that* a transaction happened. It cannot show you *what* — README §7.4 |
| Drozer | Testing from a genuine app context, which `adb shell` is not |

---

## 10. This chapter's own artefacts

| File | What it is |
|---|---|
| [`../examples/binder-probe.c`](../examples/binder-probe.c) | A raw `/dev/binder` client in C: no libbinder, no Java. Builds a `checkService` transaction by hand, decodes the reply's `flat_binder_object`, and demonstrates that `sender_euid` cannot be forged. **Compiles clean with `-Wall -Wextra`** and was run on a physical device |
| [`../examples/measured-binder-probe.txt`](../examples/measured-binder-probe.txt) | Its verbatim output, including the three forgery attempts and the token-mismatch experiment |
| [`../examples/measured-strace-binder.txt`](../examples/measured-strace-binder.txt) | The eight syscalls that constitute one Binder call, annotated line by line |
| [`../examples/fixture-device-snapshot/`](../examples/fixture-device-snapshot/README.md) | A real device's `service list`, `ps -Z` and every readable `*_service_contexts`, so every lab runs with no device attached |
| [`../examples/IVaultService.aidl`](../examples/IVaultService.aidl) | The interface behind the vulnerable/fixed pair |
| [`../examples/VaultService-vulnerable.java`](../examples/VaultService-vulnerable.java) | All four `clearCallingIdentity` misuse patterns, in one compilable file |
| [`../examples/VaultService-fixed.java`](../examples/VaultService-fixed.java) | The same interface, correct, with each fix annotated against a README section |
| [`../examples/RawBinderClient.java`](../examples/RawBinderClient.java) | Calling a service with no AIDL, no generated code and no dependency on the target — what an attacker actually writes |
| [`../scripts/binder-service-map.py`](../scripts/binder-service-map.py) | Name → interface → owning process → SELinux type, joined from four device sources. Reports its own confidence per row |
| [`../scripts/trace-binder-transactions.js`](../scripts/trace-binder-transactions.js) | Frida: every transaction with its code, interface token, caller UID and parcel, plus identity-boundary alarms |
| [`../scripts/parcel-decode.py`](../scripts/parcel-decode.py) | Turns a `service call` hex dump into fields |

---

## Related chapters

| Chapter | Relationship to this one |
|---|---|
| [24 — IPC](../../24-IPC/README.md) | Owns the IPC **attack surface** — what is reachable, abstract sockets, localhost, providers, and the enumeration methodology. It tells you *what* to attack; this chapter explains *how the transport works*. Its §3.21.2 catalogues the four `clearCallingIdentity` misuse patterns at application level; §3.12 here owns the mechanism underneath them |
| [22 — SELinux](../../22-SELinux/README.md) | Owns the **two-stage `service_manager:find` plus `binder:call` decision**, which runs in the kernel *before* delivery. Cited throughout this chapter and deliberately not restaged |
| [23 — Permissions](../../23-Permissions/README.md) | Owns what happens *after* delivery: `checkCallingPermission`, protection levels, and the permission model the service consults |
| [21 — App Sandbox](../../21-App-Sandbox/README.md) | Owns UIDs — the identity Binder stamps — plus shared UIDs and UID recycling, both of which limit what `getCallingUid()` can tell you |
| [26 — Intent](../../26-Intent/README.md) | Owns Intents, implicit resolution and redirection. Every Intent travels inside a Binder transaction, and an `IBinder` in an extra is a delegated capability |
| [27 — ContentProviders](../../27-ContentProviders/README.md) | Owns provider exploitation. A provider is a Binder object, and `openFile` hands out a real descriptor by the mechanism in §3.7.4 |
| [09 — Android App Internals](../../09-Android-App-Internals/README.md) | Owns `handleBindApplication` and app startup. The transaction that carries `bindApplication` is §3.17.1 here |
| [49 — KeyStore](../../49-KeyStore/README.md) | Every Keystore call is a transaction on this transport, authorised on the kernel-stamped UID — §3.17.2 |
| [11 — Android Runtime](../../11-Android-Runtime/README.md) | Where the Java half of every transaction executes |
| [19 — Memory](../../19-Memory/README.md) | Why `TF_CLEAR_BUF` exists: a freed binder buffer keeps its bytes |
| [53 — Frida](../../53-Frida/README.md) | The instrumentation used in §7.3–7.5 |
| [57 — Ghidra](../../57-Ghidra/README.md) | Reversing a native `onTransact` — §6.4 |
| [40 — Obfuscation](../../40-Obfuscation/README.md) | Why the `DESCRIPTOR` string and the transaction codes always survive R8 — §6.5 |
| [02 — Linux Basics](../../02-Linux-Basics/README.md) | `ioctl`, file descriptors, `mmap`, and what a character device is |
| [20 — Security Architecture](../../20-Security-Architecture/README.md) | Where Binder sits among Android's defence layers |
| [77 — Useful Commands](../../77-UsefulCommands/README.md) | `adb`, `service`, `dumpsys` and `cmd` invocations collected in one place |
