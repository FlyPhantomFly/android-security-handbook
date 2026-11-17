# Trace worksheet — following any Android API to its enforcement point

A reusable template, plus one fully worked example. Print it, fill it in, keep it with the engagement
notes. See [README.md §3.4 and §4](../README.md#34-reading-aosp-effectively--the-method).

---

## Before you start

```
Target device fingerprint : ______________________________________________
  (adb shell getprop ro.build.fingerprint)

Android release / API     : ______________________________________________

Build ID                  : ______________________________________________
  (adb shell getprop ro.build.id)

AOSP tag being read       : ______________________________________________
  (map the build ID at source.android.com/docs/setup/reference/build-numbers)

cs.android.com branch set : [ ] yes    <-- if not, stop and set it
```

> Reading `main` while testing an older device is the single most common cause of "the source says X
> but the device does Y". Set the branch first, every time.

---

## The worksheet

### Q. The question I am answering

```
____________________________________________________________________________
____________________________________________________________________________
```

### 1. The symbol I know is involved

```
Symbol            : ______________________________________________________
Code Search query : ______________________________________________________
File found        : ______________________________________________________
```

### 2. Is the declaration abstract or an interface?

```
[ ] abstract / interface   -> find the implementation (step 3)
[ ] concrete               -> go straight to step 4

Notes: ____________________________________________________________________
```

### 3. The implementation

```
Class             : ______________________________________________________
File              : ______________________________________________________
How I found it    : ______________________________________________________
  (usual answers: *Impl, the concrete subclass, or the symbol's
   "references" panel in Code Search)
```

### 4. Follow the call — what does the method body do?

```
Step  What it calls                              File
----  ----------------------------------------   -------------------------
 a.   ______________________________________     _________________________
 b.   ______________________________________     _________________________
 c.   ______________________________________     _________________________
 d.   ______________________________________     _________________________

Any checks performed IN MY PROCESS (these are NOT a boundary):
____________________________________________________________________________
```

### 5. Does it cross a process boundary?

```
[ ] no    -> skip to step 8
[ ] yes

The give-away I saw:
  [ ] SomethingManager.getService()
  [ ] ServiceManager.getService("...")
  [ ] an IBinder / I*.Stub.asInterface(...)
  [ ] other: ______________________________________________________________

AIDL file         : ______________________________________________________
Interface name    : ______________________________________________________
Code Search query : file:I__________________.aidl
```

### 6. The server implementation

```
Code Search query : content:"extends I______________.Stub" -path:test
Class             : ______________________________________________________
File              : ______________________________________________________
Process it runs in: [ ] system_server (UID 1000)  [ ] other: ______________
```

### 7. The check

```
Where the caller's identity is read:
  line/method     : ______________________________________________________
  [ ] Binder.getCallingUid()
  [ ] Binder.getCallingPid()
  [ ] getCallingUserId()

Enforcement calls found:
  [ ] enforceCallingPermission(...)          throws
  [ ] enforceCallingOrSelfPermission(...)    throws — check for confused deputy
  [ ] checkCallingPermission(...)            returns an int — WHAT HAPPENS TO IT?
  [ ] PermissionChecker.check...ForDataDelivery(...)
  [ ] an app-op check (AppOpsManager / noteOp / checkOp)
  [ ] a UID or package allow-list
  [ ] none found  <-- if this is a vendor service, see README 5.3.1

clearCallingIdentity() present?  [ ] no   [ ] yes
  If yes: is the permission check BEFORE or AFTER it?   [ ] before  [ ] AFTER
  AFTER = confused deputy. See README 5.3.2.

The exact condition that decides:
____________________________________________________________________________
____________________________________________________________________________
```

### 8. Does it go native?

```
[ ] no
[ ] yes — native method: ___________________________________________________
    JNI file  : ______________________________________________________
    (usually frameworks/base/core/jni/, or the module's own jni directory)
    Native fn : ______________________________________________________
```

### 9. Does it reach the kernel?

```
[ ] no
[ ] yes — syscall / ioctl: _________________________________________________
    Driver or subsystem   : _________________________________________________
```

### Answer

```
In one paragraph, in complete sentences, state what actually happens and
where the decision is made. If you cannot write this without the words
"somehow" or "under the hood", the trace is not finished.

____________________________________________________________________________
____________________________________________________________________________
____________________________________________________________________________
____________________________________________________________________________
```

### Verification on a device

```
Command(s) that confirm the behaviour:
____________________________________________________________________________
____________________________________________________________________________

Observed result:
____________________________________________________________________________
```

---

## Worked example — "What stops an app reading the clipboard in the background?"

Filled in, so you can see what a finished worksheet looks like.

### Q. The question

Since Android 10, an app that is not in the foreground cannot read the clipboard. Where exactly is that
enforced, what is the precise condition, and does the API throw or return nothing?

### 1. The symbol

```
Symbol            : ClipboardManager
Code Search query : class:ClipboardManager path:frameworks/base/core/java
File found        : frameworks/base/core/java/android/content/ClipboardManager.java
```

### 2. Abstract or concrete?

Concrete, but a thin wrapper. `getPrimaryClip()` delegates immediately, which means the real logic is
elsewhere — the classic sign of a manager class holding a Binder proxy.

### 3. The implementation

`ClipboardManager` holds an `IClipboard` obtained from `ServiceManager`. So the "implementation" is not
in this process at all; it is the Binder server.

### 4. Follow the call

```
 a.  ClipboardManager.getPrimaryClip()          android/content/ClipboardManager.java
 b.  mService.getPrimaryClip(pkg, ...)          the IClipboard proxy
 c.  (generated Proxy) mRemote.transact(...)    generated
 d.  kernel stamps sender_euid                  drivers/android/binder.c
```

Checks in my process: **none**. Everything is on the far side.

### 5. Process boundary

Yes — `mService` is an `IClipboard` proxy.

```
AIDL file         : frameworks/base/core/java/android/content/IClipboard.aidl
Interface name    : android.content.IClipboard
Code Search query : file:IClipboard.aidl
```

### 6. The server

```
Code Search query : content:"extends IClipboard.Stub" -path:test
Class             : ClipboardService
File              : frameworks/base/services/core/java/com/android/server/ClipboardService.java
Process           : system_server (UID 1000)
```

### 7. The check

Reading `ClipboardService.getPrimaryClip` and its helpers, the decision combines several conditions —
the calling UID from `Binder.getCallingUid()`, whether the calling package currently has window focus,
whether it is the default input method, the `READ_CLIPBOARD` app-op, the user and profile the caller
belongs to, and device-policy state.

The behaviour that surprises people is the **failure mode**: when the caller is not permitted, the
service returns `null` or an empty clip rather than throwing `SecurityException`. That is the app-op
`MODE_IGNORED` pattern from [README §4.3 step 4](../README.md#43-trace-c--a-permission-check-from-checkselfpermission-to-the-enforcement-point) — silent
denial, not an exception.

```
clearCallingIdentity() present?  yes, in places — and the checks precede it. Not a confused deputy.
```

### 8. Native?

No. The decision is entirely in Java, in `system_server`.

### 9. Kernel?

Only for the Binder transport, and for the identity stamp in `binder_transaction()`.

### Answer

An application's call to `ClipboardManager.getPrimaryClip()` performs no check in the application's own
process. It marshals a Binder transaction to `ClipboardService`, which runs inside `system_server` as
UID 1000. The kernel's binder driver stamps the calling UID and PID into that transaction, so the
service authorises against an identity the application cannot influence. `ClipboardService` then
combines several conditions — chiefly whether the calling package currently holds window focus or is the
active input method, plus the `READ_CLIPBOARD` app-op and the caller's user and device-policy state —
and if the caller does not satisfy them it returns an empty result rather than throwing. Consequently an
application that reads the clipboard in the background does not crash and does not see an exception; it
receives nothing, which is why this behaviour is so often misdiagnosed as an unrelated bug.

### Verification on a device

```bash
# adb shell
appops get com.example.app READ_CLIPBOARD
appops set com.example.app READ_CLIPBOARD ignore
# Background the app, trigger its clipboard read, and observe: empty clip, no exception.
appops set com.example.app READ_CLIPBOARD allow
```

```bash
# adb shell — watch the service's own view
dumpsys clipboard
```

---

## Suggested traces to practise on

Each of these is a good exercise, and each ends somewhere different.

| Question | Where it ends |
|---|---|
| What happens when an app calls `getSystemService(LOCATION_SERVICE)` and then `requestLocationUpdates`? | `LocationManagerService`, plus app-ops and the one-time-permission machinery |
| Why can one app not read another's files? | Unix DAC set at install by `PackageManagerService` and `installd`, plus SELinux |
| What does `startForegroundService` actually enforce? | `ActivityManagerService`, plus the notification requirement and background-start rules |
| How does `PendingIntent` mutability work? | `PendingIntentRecord` in `system_server` and the `FLAG_IMMUTABLE` handling |
| What verifies an APK's signature at install? | `PackageManagerService` install path, `ApkSignatureVerifier`, `apksig` |
| Why does `WebView` run in its own process? | The WebView Mainline module and the sandboxed renderer process model |
| What does `KeyStore` do that keeps a key out of my process? | `system/security/keystore2/` and the KeyMint HAL, then the TEE |
| Why is my `BroadcastReceiver` not receiving an implicit broadcast? | `ActivityManagerService` broadcast path and the API-26 implicit-broadcast restrictions |
