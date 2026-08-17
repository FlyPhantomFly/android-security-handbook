# 28 — Services — FAQ

Real questions, including the ones people are embarrassed to ask. Answers are
direct; the "why" is in [`README.md`](README.md).

---

### 1. What actually is the difference between a started service and a bound service?

A **started** service is a command. You call `startService(intent)`, the system
delivers the `Intent` to `onStartCommand()`, and that is the end of the
conversation — there is no way for the service to answer you. It keeps running
until it stops itself or somebody stops it.

A **bound** service is a phone line. You call `bindService(intent, conn, flags)`,
the system calls the service's `onBind()`, and hands you back whatever object
`onBind` returned. You now hold a handle into the other process and can call
methods on it and get answers. It stays alive as long as at least one client is
holding the line.

One `Service` object can be both at the same time. That trips people up: the
service is not destroyed until **both** the start claim and every bind claim are
released. See [README §2.3](README.md#23-the-lifecycle-as-a-state-machine).

---

### 2. Does a service run in the background, on its own thread?

No, and this is the most consequential misunderstanding in the whole topic.

A service runs on the **main thread of its process**, exactly like an Activity.
"Background" in "background service" refers to *the user not looking at it*, not
to threading. If you do network I/O or file parsing in `onStartCommand`, you
block the main thread and after five seconds the user gets "Application Not
Responding".

If you want a thread, make one. `IntentService` (deprecated) made one for you,
which is why so much old code looks like it does; `WorkManager` is the modern
answer for deferrable work.

---

### 3. Why did my service get killed?

Six candidate causes, and you need evidence to pick between them:

| Cause | Evidence |
|---|---|
| Low memory | `lowmemorykiller` in logcat; a low `adj` in `dumpsys activity processes` |
| The user swiped the task away | `onTaskRemoved` ran; `android:stopWithTask` is not `false` |
| Background execution limits (API 26+) | `ActivityManager` log about stopping a background service |
| **OEM power management** | Often nothing at all. On the MIUI device used for this chapter, `AutoStartManagerService: MIUILOG- Reject RestartService` |
| It stopped itself | `stopSelf()` with a second `startId` outstanding — [README §3.2](README.md) |
| It crashed | The stack trace |

The OEM row is not a footnote. On many Chinese-market ROMs, aggressive vendor
power management is the actual answer and no amount of AOSP knowledge predicts
it.

---

### 4. Is a foreground service actually in the foreground?

No. It has no UI, receives no input, and does not appear in recents. "Foreground"
is a statement about **process importance** — the out-of-memory band the process
sits in. The user is told about it with a notification, which is the deal: you
get lifetime, they get visibility.

It is the worst-named thing in the Android API and everybody trips over it once.

---

### 5. What is a sticky service?

Informally, a service whose `onStartCommand` returns `START_STICKY`, which tells
the system to recreate it if the process is killed.

Two things people get wrong:

- **The Intent is not preserved.** On the restart, `onStartCommand` is called
  with `intent == null`. Code that does `intent.getStringExtra(...)` on the first
  line crashes — and only ever in the field, after a real low-memory kill, never
  on a developer's desk. Use `START_REDELIVER_INTENT` if you need the Intent
  back.
- **The restart is not guaranteed.** Measured on the test device, the vendor's
  autostart manager refused it outright.

---

### 6. Why does my AIDL callback crash?

Four causes, in order of how often they are the answer:

1. **You are calling back on the wrong thread.** An AIDL method runs on a Binder
   pool thread. If your callback touches the UI, you must post to the main
   thread. `CalledFromWrongThreadException` is the symptom.
2. **The client went away.** You are holding an `IBinder` for a process that
   died. Calling it throws `DeadObjectException` (a `RemoteException`). Register
   a `linkToDeath` recipient and drop the reference; do not just catch and
   ignore.
3. **The callback's `Parcel` is too big.** A Binder transaction shares a ~1 MB
   per-process buffer, and the practical limit is far lower because other
   transactions are in flight. Sending a large `Bitmap` or list produces
   `TransactionTooLargeException`. See [25 §3.14](../25-Binder/README.md).
4. **You are storing the callback in a plain collection and mutating it from two
   Binder threads at once.** Use `RemoteCallbackList`, which handles both the
   locking and the death cleanup. Almost nobody does, and it is the right answer.

---

### 7. My service is `exported="false"`. Am I done?

For *other apps*, yes — `system_server` refuses the bind. But note what that
does **not** cover:

- Another package sharing your `sharedUserId` is the same UID and is not
  "another app" as far as this check is concerned.
- A manifest merge from a library can add an exported service you never wrote.
  Check the **merged** manifest, not yours.
- `enabled` and `exported` can both be changed at runtime by your own app via
  `PackageManager.setComponentEnabledSetting`.
- The system can still bind it if it holds a `BIND_*` permission you declared.

---

### 8. I put a `getCallingUid()` check in `onBind` and it never rejects anyone. Why?

Because it is checking your app against itself.

`onBind` is not called by the client. It is called by `ActivityThread` on your
own main thread, in response to a message from `system_server`. There is no
client Binder transaction in flight at that moment, so `Binder.getCallingUid()`
falls back to `Process.myUid()` and your comparison is `x != x`.

Measured: a service at uid 10310 being bound by an attacker at uid 10313 logged
`onBind ... callingUid=10310`. One millisecond later, inside an AIDL method, it
logged `getAuthToken() called by uid=10313`.

The same applies to `onCreate`, `onStartCommand`, `onUnbind`, `onRebind` and
`onDestroy`. The check belongs inside each method of the `IBinder` you returned.

---

### 9. So how *does* a started service know who started it?

It does not, and there is no public API that tells it. `Binder.getCallingUid()`
in `onStartCommand` returns your own UID for the reason above.

Two workarounds, one bad and one acceptable:

- **Bad:** require the caller to put its package name in an extra. That is a
  claim, not authentication, and any app can write any string.
- **Acceptable:** require the caller to pass a `PendingIntent` it created. The
  framework binds a `PendingIntent` to its creator's identity, and you can read
  it with `getCreatorUid()`. See [26 — Intent](../26-Intent/README.md).

If you need authenticated callers, use a **bound** service. That is what it is
for.

---

### 10. `bindService` returned `true` but `onServiceConnected` never fired. Is it broken?

No. `bindService` returning `true` means the request was accepted: the component
resolved, you passed the permission check, and the system will try. It does not
mean a binder came back.

The usual cause is that the service's `onBind` returned `null` — often because it
switches on `intent.getAction()` and you sent a component-only Intent. Measured
against `com.android.keychain/.KeyChainService`: `true`, and no connection ever.

From API 28, implement `ServiceConnection.onNullBinding` and you will be told
explicitly.

---

### 11. `bindService` returned `false` and threw nothing. What does that mean?

Almost certainly **package visibility filtering**. From API 30, an app whose
`targetSdk` is 30 or higher cannot see most other packages, and a filtered
package behaves exactly like a component that does not exist: `false`, no
exception, nothing in logcat.

Measured as a controlled experiment — same prober, same target, one manifest line
apart:

```text
without QUERY_ALL_PACKAGES:  BIND-RETURN ... => false
with    QUERY_ALL_PACKAGES:  BIND-RETURN ... => true, CONNECTED
```

Add `<uses-permission android:name="android.permission.QUERY_ALL_PACKAGES"/>` or
a `<queries>` block naming the target, and re-run. **Do not report package
visibility as a mitigation** — any app can request it, and a `<queries>` entry
for one specific package needs no permission at all.

---

### 12. Is an exported service a vulnerability?

No. It is a lead.

Plenty of services are exported deliberately and do nothing an attacker wants. On
the stock test device, 325 services were exported with no permission at all, and
the great majority of them are uninteresting — including one, the system
credential store, that could not actually be connected to.

The finding is what a caller can **make it do**. Bind it, call a method, show the
effect, and grade the severity by the effect. A report that lists exports without
demonstrations gets discounted as a whole, including the real findings in it.

---

### 13. When should I use `Messenger` and when AIDL?

| Use `Messenger` when | Use AIDL when |
|---|---|
| A simple command channel | You need typed arguments |
| You do not need a return value | You need a synchronous return value |
| You want serialisation for free | You need throughput or concurrency |
| The state is mutable and you would rather not think about locks | You are prepared to think about locks |

The difference that bites people: **`Messenger` posts everything to one `Handler`
thread**, so no two handlers overlap. **AIDL is dispatched on the Binder thread
pool**, so two clients — or one client with two threads — run your method
simultaneously. A `HashMap` that is fine under `Messenger` is a race under AIDL,
and it will never reproduce in a unit test, because `Stub.asInterface`
short-circuits to the real object when the binder is local.

---

### 14. What is `msg.replyTo` and why is it dangerous?

`Messenger` is asynchronous, so there is no return value. The convention is that
a client puts its own `Messenger` in `msg.replyTo` and the service sends the
answer there.

The danger is that `msg.replyTo` is **a Binder handle the caller chose**. A
service that answers by sending to `msg.replyTo` sends the data to whoever the
caller named — which need not be the caller. Even a service that correctly checks
`msg.sendingUid` and finds a trusted sender will happily deliver to an attacker's
`Messenger` if the trusted sender can be induced to pass one through.

The fix is to reply only on a channel the caller registered through an
authenticated path, keyed by its `sendingUid`. See
[`examples/MessengerCommandService.java`](examples/MessengerCommandService.java).

AIDL does not have this problem: the return value travels back on the caller's
own transaction and cannot be redirected.

---

### 15. Is the interface token (`enforceInterface`) a security control?

No. It is a **name tag, not a lock**.

The descriptor is a public string, and the binder will tell you what it is if you
ask — `getInterfaceDescriptor()`, transaction code `1598968902`, free to any
caller. Writing it into your parcel is not an exploit technique; it is the
protocol. Measured: the whole distance from "I can bind" to "I have the token"
was one call to get the descriptor and one `transact`.

Its actual job is to stop a client accidentally sending transaction code 3 to the
wrong object and corrupting memory.

---

### 16. Does obfuscation protect my service's API?

No. It hides the implementation, not the interface, and the interface is the
attack surface.

The service class name must survive, because the manifest names it. `onBind` and
`onStartCommand` must survive, because the framework calls them. The AIDL
descriptor string must survive, because `enforceInterface` compares it at
runtime. The transaction codes must survive, because they are the wire format.
Everything an attacker needs is exactly the set of things that cannot be renamed.

---

### 17. What is `isolatedProcess` and should I be pleased to see it?

Yes, be pleased, and say so in the report.

`android:isolatedProcess="true"` runs the service in a process with a throwaway
UID (99000–99999, or 90000–98999 with `useAppZygote`), **no permissions, no
network, no data directory, and almost no Binder access**. It is the strongest
sandbox a developer can ask for with one attribute, and the platform uses it for
WebView renderers and media codecs — the two places history says memory
corruption lives.

It is one of very few unambiguously positive findings available to a tester.
[21 §3.7](../21-App-Sandbox/README.md) owns the mechanics; this chapter owns what
it means for a service (in practice: bind-only, and you pass data in as file
descriptors).

Measured on the test device: three isolated processes live at once, at uids
90000, 99003 and 99046, with **empty supplementary groups** — which is precisely
why they have no network.

---

### 18. Someone told me `android:process=":remote"` isolates my service. Does it?

It gives it a separate process, which is useful for crash isolation and memory,
and it changes which pid you attach a debugger to. It is **not** a security
boundary: same UID, same data directory, same permissions, same SELinux domain.

`isolatedProcess` is the attribute that is a boundary. `process` is not.

---

### 19. My client says they need RPC and are using `ContentProvider.call()`. What do I tell them?

Move to a bound service with an AIDL interface, and tell them what it costs.

They gain: a `.aidl` file that **is** the schema (with `call()`, the API is a
`switch` statement invisible to the manifest and to every reviewer), typed
arguments, `Binder.getCallingUid()` in a place where it actually works, lifetime
control, and `oneway` for calls that need no reply.

They lose: some simplicity. It is more code, binding is asynchronous, and method
order in the `.aidl` becomes the wire format — appending is safe, reordering
silently breaks clients.

And be honest about the case where they should not bother: if the two apps ship
together, are signed with the same key, and the surface is one or two methods,
then a `signature`-level permission on the provider is a perfectly good control
and the migration is not worth two days.

[README §3.9](README.md) has the full recommendation with code.
[27 §5.5](../27-ContentProviders/README.md) has the vulnerability it replaces.

---

### 20. How do I detect a malicious accessibility service, and can I block it?

Detect: list them.

```bash
# adb shell
settings get secure enabled_accessibility_services
settings get secure enabled_notification_listeners
dumpsys accessibility
```

On a clean device both settings read `null` / `0`. Any package listed there can
read every word on the screen and, if its `res/xml` config requests
`canPerformGestures`, drive the UI.

Block: mostly, no, and be honest about it in a report.

- `importantForAccessibility="noHideDescendants"` removes specific views from the
  accessibility tree. It helps only for views you mark, and developers mark few.
- `FLAG_SECURE` blocks screenshots. It does **not** remove views from the
  accessibility tree.
- `setFilterTouchesWhenObscured` defeats tapjacking overlays. It does not defeat
  accessibility-synthesised gestures, which are not obscured touches.
- Enumerating enabled services and refusing to run is easy to bypass with an
  allow-listed name, and it punishes real screen-reader users. Use it to inform,
  not to block.

The durable control is server-side: transaction anomaly detection that does not
rely on device signals, because in this threat model the transaction genuinely
comes from the victim's own device and session.

Finally: **do not file this as a CVE.** It is a platform capability being used as
designed by an app the user was persuaded to enable. Write it as a threat-model
item plus specific missing defences.
