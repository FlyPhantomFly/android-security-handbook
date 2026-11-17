# Lab 03 — MCS and App-vs-App Isolation

**Difficulty:** Intermediate
**Time:** 90–120 minutes
**Prerequisites:** [Lab 01](lab-01-reading-contexts.md), [Lab 02](lab-02-denial-to-rule.md), [Chapter 22 §3.7](../README.md#37-mcs-the-category-encoding-and-what-it-actually-enforces). **No root required.** One optional step benefits from Android Studio.

---

## Objective

Establish, by measurement rather than assertion, the mechanism that separates one third-party app from another at the MAC layer — and demonstrate that it is *not* type enforcement, because every third-party app shares the same type.

By the end you will be able to:

- compute an app's MCS category set from its UID, in your head, and explain every term;
- prove the encoding against an observation where `appid > 255`, which is the only case that actually tests it;
- read the MLS constraints out of a real device's compiled policy and evaluate them by hand for a given pair of contexts;
- identify which domains on a device have **no** per-app isolation, and say what protects them instead;
- and explain why `chmod 777` does not defeat this layer.

## Why this matters

[Chapter 21](../../21-App-Sandbox/README.md) establishes that two apps have different UIDs and that DAC therefore keeps them apart. That is true and it is the load-bearing 80%.

But it leaves a question that chapter 21 explicitly defers here: **what happens if DAC fails?** A `chmod` mistake, a `sharedUserId`, a kernel VFS bug, a `MODE_WORLD_READABLE` in a legacy app — any of these removes the DAC barrier. If SELinux is to be a real second layer, it has to keep the apps apart *by itself*, and it cannot do so with types, because every third-party app is `untrusted_app`.

The answer is MCS. This lab is where you verify it rather than believe it.

> **Definition — MCS (Multi-Category Security)**
> The degenerate case of MLS in which there is exactly one sensitivity level and only the *categories* are used. Android uses `s0` as its only sensitivity and up to 1024 categories, `c0` through `c1023`, assigned arithmetically from the process's UID.

> **Definition — dominance**
> Level A *dominates* level B (written `dom l1 l2` in constraint syntax) when A's sensitivity is at least B's **and** A's category set is a **superset** of B's. With one sensitivity, dominance reduces entirely to set containment.

---

## Setup

```bash
# host
adb devices
adb shell getenforce                    # must be Enforcing
adb shell 'cat /sys/fs/selinux/mls'     # must be 1
```

> **If `/sys/fs/selinux/mls` returns `0`, this lab measures nothing.** MLS is not compiled into that kernel, there are no categories anywhere, and app-vs-app MAC isolation does not exist on that device. That is itself a serious platform finding — write it up and use a different device for the lab.

Have at least three third-party apps installed and running. You will need their UIDs.

```bash
# adb shell
pm list packages -3 -U
```

Pull the policy, which you will grep in Part 3:

```bash
# host
adb pull /system/etc/selinux/plat_sepolicy.cil
adb pull /system/etc/selinux/plat_seapp_contexts
adb pull /vendor/etc/selinux/vendor_seapp_contexts
```

---

## Part 1 — The arithmetic, by hand

### Step 1 — Decompose a UID

Take any app's UID and decompose it. The constants come from `system/core/libcutils/include/private/android_filesystem_config.h`:

```
AID_USER_OFFSET                 = 100000
AID_APP_START                   = 10000
AID_SDK_SANDBOX_PROCESS_START   = 20000
AID_ISOLATED_START              = 90000
```

```
userid = uid / AID_USER_OFFSET
appid  = uid % AID_USER_OFFSET

    appid >= AID_ISOLATED_START          ->  appid -= AID_ISOLATED_START
    appid >= AID_SDK_SANDBOX_PROCESS_START -> appid -= AID_SDK_SANDBOX_PROCESS_START
    appid >= AID_APP_START               ->  appid -= AID_APP_START
    otherwise                            ->  appid unchanged
```

**Question 1.** Decompose each of these by hand:

| uid | userid | raw appid | range | appid after subtraction |
|---|---|---|---|---|
| 10107 | | | | |
| 10156 | | | | |
| 1010150 | | | | |
| 90003 | | | | |
| 1068 | | | | |
| 1000 | | | | |

<details>
<summary>Answers</summary>

| uid | userid | raw appid | range | appid |
|---|---|---|---|---|
| 10107 | 0 | 10107 | application | 107 |
| 10156 | 0 | 10156 | application | 156 |
| 1010150 | 10 | 10150 | application | 150 |
| 90003 | 0 | 90003 | isolated | 3 |
| 1068 | 0 | 1068 | system/native AID | 1068 |
| 1000 | 0 | 1000 | system/native AID | 1000 |

Note `1010150`: that is package appId 150 running in Android user 10, i.e. a work profile. Same app, different profile, different UID and different categories.
</details>

### Step 2 — Build the level

```
levelFrom=app   ->  s0:c(appid & 0xff),c(256 + (appid >> 8))
levelFrom=user  ->  s0:c(512 + (userid & 0xff)),c(768 + (userid >> 8))
levelFrom=all   ->  both pairs, app pair first
(absent)        ->  s0
```

**Question 2.** For each row of the table above, compute the `levelFrom=all` level.

<details>
<summary>Answers</summary>

| uid | appid | userid | `levelFrom=all` |
|---|---|---|---|
| 10107 | 107 | 0 | `s0:c107,c256,c512,c768` |
| 10156 | 156 | 0 | `s0:c156,c256,c512,c768` |
| 1010150 | 150 | 10 | `s0:c150,c256,c522,c768` |
| 90003 | 3 | 0 | `s0:c3,c256,c512,c768` |
| 1068 | 1068 | 0 | `s0:c44,c260,c512,c768` |
| 1000 | 1000 | 0 | `s0:c232,c259,c512,c768` |

Check the work-profile row: `512 + (10 & 0xff)` = `c522`, and `768 + (10 >> 8)` = `c768`. Only the **third** category changes.

Check the 1068 row: `1068 & 0xff` = 44 (1068 = 4·256 + 44), and `256 + (1068 >> 8)` = `256 + 4` = 260.

Check the 1000 row: `1000 & 0xff` = 232 (1000 = 3·256 + 232), and `256 + 3` = 259.
</details>

### Step 3 — Measure

```bash
# adb shell
ps -A -Z | grep -E '_app' | sort
```

Reference output from the measured device:

```
u:r:untrusted_app:s0:c107,c256,c512,c768            u0_a107  com.android.chrome
u:r:untrusted_app:s0:c150,c256,c512,c768            u0_a150  com.synergyenfmanager
u:r:untrusted_app:s0:c156,c256,c512,c768            u0_a156  com.synergyenf
u:r:traceur_app:s0:c77,c256,c512,c768               u0_a77   com.android.traceur
u:r:mediaprovider_app:s0:c132,c256,c512,c768        u0_a132  com.android.providers.media.module
u:r:permissioncontroller_app:s0:c130,c256,c512,c768 u0_a130  com.android.permissioncontroller
u:r:gmscore_app:s0:c512,c768                        u0_a96   com.google.android.gms
u:r:priv_app:s0:c512,c768                           u0_a95   com.android.vending
u:r:platform_app:s0:c512,c768                       u0_a119  com.android.systemui
u:r:system_app:s0                                   system   com.android.keychain
```

**Question 3.** Do the arithmetic for five apps on **your** device before running any tool, then check with:

```bash
# host
bash ../scripts/selinux-posture.sh <package> --no-logcat
```

Record any mismatch. A mismatch is either a mistake in your arithmetic or something genuinely interesting — a vendor `seapp_contexts` rule, or a process that started under a different UID.

### Step 4 — The observation that actually tests the encoding

Every app on the reference device had `appid < 256`, which means `appid & 0xff` equals `appid` and `256 + (appid >> 8)` is always exactly `c256`. Those observations are *consistent with* the encoding but do not distinguish it from a simpler one — for example, "first category is the appId, second is always c256".

The measured record that settles it:

```
avc:  denied  { find } for pid=1672 uid=1068 name=nfc
  scontext=u:r:secure_element:s0:c44,c260,c512,c768
  tcontext=u:object_r:nfc_service:s0 tclass=service_manager permissive=0
```

`uid=1068`, and the context carries `c44,c260`. The mask and the shift are both exercised.

**Question 4.** Suppose someone proposed the simpler encoding "first category = appId, second category = always c256". Show, using the `uid=1068` observation, that this hypothesis is false. Then explain *why* the true encoding needs two categories per number.

<details>
<summary>Answer</summary>

Under the simpler hypothesis, uid 1068 would produce `c1068,c256`. The measurement shows `c44,c260`. Hypothesis falsified.

**Why two categories:** there are only 1024 categories total, split into four blocks of 256. A single category can therefore express only 256 distinct values — nowhere near enough for the 10,000 possible appIds. Two categories, each carrying one byte, express 65,536 values. The block structure (`c0`–`c255` for the low byte, `c256`–`c511` for the high byte) is what makes the two bytes unambiguous when they appear in the same set.
</details>

**Question 5.** Given the encoding, state the invariant about the range of the first and second categories. Then: someone shows you a context `u:r:untrusted_app:s0:c288,c256,c512,c768`. What can you say about it immediately?

<details>
<summary>Answer</summary>

- first category: always `c0`–`c255` (it is a masked byte)
- second category: always `c256`–`c511` (it is `256 +` a byte)
- third: always `c512`–`c767`
- fourth: always `c768`–`c1023`

`c288` in the **first** slot is arithmetically impossible. The context has been fabricated, mistyped, or copied from an illustration rather than a device. This check takes two seconds and catches a real class of error in write-ups.

`scripts/avc-decode.py` reports a malformed pair explicitly rather than producing a confident wrong number.
</details>

### Step 5 — Find a device with a work profile, if you can

If you have a device with a work profile or a secondary user:

```bash
# adb shell
pm list users
pm list packages --user 10 -U
ps -A -Z | grep u10_
```

**Question 6.** Compare an app's context in user 0 with the same app's context in user 10. Which categories change, and which do not? What does that tell you about whether MCS separates the same app across profiles?

If you have no such device, reason it out from the encoding and say what you would expect.

---

## Part 2 — What the categories are *for*

Categories on their own do nothing. Something has to consult them.

### Step 6 — Confirm that type enforcement does not separate apps

```bash
# host — what may untrusted_app do to app_data_file?
grep -nE '\(allow untrusted_app_all app_data_file ' plat_sepolicy.cil
```

Measured on the reference device:

```lisp
;; line 27666
(allow untrusted_app_all app_data_file
  (file (ioctl read getattr lock map execute open watch watch_reads)))
```

**Question 7.** That rule grants `read` on `app_data_file`. Chrome (`untrusted_app`, categories `c107,c256,c512,c768`) and the other app's `session.xml` (`app_data_file`, categories `c150,c256,c512,c768`) both match it — same source type, same target type, same class, and `read` is in the set.

So why can Chrome not read the file? Answer precisely, naming the mechanism.

<details>
<summary>Answer</summary>

Because type enforcement is not the only check. Even when an `allow` rule matches perfectly, the operation is refused if an applicable **MLS constraint** evaluates false. The `allow` rule above is satisfied; the constraint is not.

This is the single most commonly skipped step in people's mental model of SELinux, and it is exactly why "I found the allow rule, so it should work" is a wrong inference.
</details>

### Step 7 — Read the constraints out of the real policy

```bash
# host
grep -n 'mlsconstrain' plat_sepolicy.cil | head -30
```

The four that matter, measured verbatim:

```lisp
;; line 491 -- reading a file
(mlsconstrain (file (read getattr execute))
  (or (or (or (or (eq t2 app_data_file_type) (eq t2 appdomain_tmpfs))
              (dom l1 l2))
          (eq t1 mlstrustedsubject))
      (eq t2 mlstrustedobject)))

;; line 490 -- writing a file
(mlsconstrain (file (write setattr append unlink link rename))
  (or (or (or (or (eq t2 app_data_file_type) (eq t2 appdomain_tmpfs))
              (eq l1 l2))
          (eq t1 mlstrustedsubject))
      (eq t2 mlstrustedobject)))

;; line 501 -- directory operations. THE LOAD-BEARING ONE.
(mlsconstrain (dir (getattr setattr rename open add_name remove_name reparent search rmdir))
  (or (or (neq t2 app_data_file_type) (dom l1 l2)) (eq t1 mlstrustedsubject)))

;; line 483 -- domain transitions
(mlsconstrain (process (transition dyntransition))
  (or (and (eq h1 h2) (eq l1 l2)) (eq t1 mlstrustedsubject)))
```

The operators:

| Symbol | Meaning |
|---|---|
| `l1`, `l2` | the subject's and object's low level |
| `h1`, `h2` | the subject's and object's high level |
| `t1`, `t2` | the subject's and object's type |
| `eq` | equal |
| `neq` | not equal |
| `dom` | **dominates** — same or higher sensitivity **and** a superset of categories |

### Step 8 — Evaluate constraint 501 by hand

Subject: `u:r:untrusted_app:s0:c107,c256,c512,c768`, attempting `dir search` on
object: `u:object_r:app_data_file:s0:c150,c256,c512,c768`.

Walk the expression:

```
(or (or (neq t2 app_data_file_type) (dom l1 l2)) (eq t1 mlstrustedsubject))

  clause 1:  (neq t2 app_data_file_type)
             t2 is app_data_file, which HAS the app_data_file_type attribute
             -> FALSE

  clause 2:  (dom l1 l2)
             l1 categories = {c107, c256, c512, c768}
             l2 categories = {c150, c256, c512, c768}
             is l1 a superset of l2?  c150 is in l2 and NOT in l1
             -> FALSE

  clause 3:  (eq t1 mlstrustedsubject)
             untrusted_app does not carry that attribute
             -> FALSE

  or(or(F, F), F) = FALSE
```

**The constraint refuses.** Even though the `allow` rule matched.

**Question 8.** Now evaluate the *same* constraint for a subject reading its **own** data directory: subject `s0:c107,c256,c512,c768`, object `s0:c107,c256,c512,c768`. Show each clause.

**Question 9.** Now evaluate it for `dexoptanalyzer`, whose context is `u:r:dexoptanalyzer:s0` — **no categories at all** — attempting `dir search` on `privapp_data_file:s0:c512,c768`. Does the empty set dominate `{c512, c768}`? What does that tell you about the measured denial from Lab 02?

<details>
<summary>Answer to Question 9</summary>

The empty set is **not** a superset of `{c512, c768}` — it is missing both. So `dom l1 l2` is false, the other two clauses are false, and the constraint refuses.

This is exactly the measured denial:

```
avc: denied { search } for comm="main" name="com.google.android.gms" dev="dm-7"
  scontext=u:r:dexoptanalyzer:s0
  tcontext=u:object_r:privapp_data_file:s0:c512,c768 tclass=dir permissive=0
```

Note the counter-intuitive part: a subject with **fewer** categories is *more* restricted, not less. Categories are compartments you must hold, not clearances you must clear. A process at bare `s0` can touch nothing that carries any category at all.
</details>

### Step 9 — The read/write asymmetry

Compare constraint 491 (read) with constraint 490 (write):

| | Operator |
|---|---|
| read, getattr, execute | `dom l1 l2` — containment |
| write, setattr, append, unlink, link, rename | `eq l1 l2` — **exact equality** |

**Question 10.** A hypothetical process holds categories `{c107, c150, c256, c512, c768}` — a superset of both apps'. Under these constraints, may it *read* app 150's file? May it *write* to it? Explain what security property that asymmetry expresses.

<details>
<summary>Answer</summary>

**Read: yes.** `{c107, c150, c256, c512, c768}` ⊇ `{c150, c256, c512, c768}`, so `dom` is true.

**Write: no.** `eq l1 l2` requires the levels to be *identical*, and they are not.

This is the classic MLS **"no write down"** rule. A highly-categorised process may read from a lower one but may not write to it, which prevents information flowing downward and — more practically on Android — prevents a broadly-categorised process from silently corrupting an app's files.

The security consequence worth stating: **granting a domain a broad category set is much more dangerous for confidentiality than for integrity.** That is a genuinely useful distinction when assessing a vendor domain.
</details>

### Step 10 — `mlstrustedsubject`, the exemption

Every constraint ends with `(eq t1 mlstrustedsubject)`. Any domain carrying that attribute bypasses the entire MLS layer.

```bash
# host
grep -n 'typeattributeset mlstrustedsubject' plat_sepolicy.cil
grep -n 'typeattributeset mlstrustedsubject' vendor_sepolicy.cil
```

**Question 11.** List the domains on your device that carry `mlstrustedsubject`. For each, say in one sentence why it plausibly needs to touch every app's data. Flag any you cannot justify.

**Question 12.** Suppose a vendor added their own daemon to `mlstrustedsubject`. Write the finding in three sentences: what the rule does, what it removes, and why it is an *impact amplifier* rather than a vulnerability in itself.

<details>
<summary>Model answer for Question 12</summary>

"The vendor domain `<name>` carries the `mlstrustedsubject` attribute, which exempts it from every MLS constraint in the policy. As a result, the MCS categories that separate one application's private data from another's provide no protection against this domain, and the only remaining barrier is Unix DAC — which the domain also bypasses if it holds `CAP_DAC_OVERRIDE`. This is not itself an exploitable condition; its significance is that it converts any memory-corruption or command-injection bug in `<name>` from a single-component compromise into full disclosure of every application's private data on the device."
</details>

---

## Part 3 — Which domains have no per-app isolation

### Step 11 — Enumerate

```bash
# adb shell
grep 'levelFrom=user' /system/etc/selinux/plat_seapp_contexts
grep 'levelFrom=user' /vendor/etc/selinux/vendor_seapp_contexts
echo '--- and the ones with no levelFrom at all ---'
grep '^user=' /system/etc/selinux/plat_seapp_contexts | grep -v 'levelFrom='
```

Measured on the reference device, `levelFrom=user`:

```
user=_isolated domain=isolated_app levelFrom=user
user=_app seinfo=app_zygote domain=app_zygote levelFrom=user
user=_app seinfo=media domain=mediaprovider type=app_data_file levelFrom=user
user=_app seinfo=platform domain=platform_app type=app_data_file levelFrom=user
user=_app isPrivApp=true domain=priv_app type=privapp_data_file levelFrom=user
user=_app isPrivApp=true name=com.google.android.gms domain=gmscore_app type=privapp_data_file levelFrom=user
user=_app minTargetSdkVersion=26 domain=untrusted_app_27 type=app_data_file levelFrom=user
user=_app domain=untrusted_app_25 type=app_data_file levelFrom=user
user=_app fromRunAs=true domain=runas_app levelFrom=user
```

And with no `levelFrom` at all:

```
user=system seinfo=platform domain=system_app type=system_app_data_file
user=bluetooth seinfo=bluetooth domain=bluetooth type=bluetooth_data_file
user=network_stack seinfo=network_stack domain=network_stack type=radio_data_file
user=nfc seinfo=platform domain=nfc type=nfc_data_file
user=radio seinfo=platform domain=radio type=radio_data_file
user=webview_zygote seinfo=webview_zygote domain=webview_zygote
```

**Question 13.** For `platform_app` and `priv_app` — both `levelFrom=user` — confirm from `ps -A -Z` on your device that multiple *different* apps have identical contexts. Then answer: what separates them, if not MCS?

<details>
<summary>Answer</summary>

Two things.

**Their file type.** `priv_app`'s data directory is `privapp_data_file`, not `app_data_file`. That is a genuine type-enforcement boundary against ordinary apps — an `untrusted_app` has no rule granting it access to `privapp_data_file`. It is *not* a boundary between two `priv_app` processes, which share the type.

**DAC.** Different UIDs, `0700` directories. That is chapter 21, and it is the only thing standing between two privileged apps.

The design trade is deliberate: privileged apps are all signed by the same authority and frequently need to share state, so the platform accepts a weaker MAC boundary between them. It is worth knowing because people assume MCS separates everything, and it does not.
</details>

**Question 14.** The two most interesting rows in the `levelFrom=user` list are `untrusted_app_27` (for `targetSdk` 26–27) and `untrusted_app_25` (for `targetSdk` ≤ 25). Write the finding for an app under assessment that has `targetSdkVersion="26"`, in the form you would put in a report.

<details>
<summary>Model answer</summary>

"The application declares `targetSdkVersion="26"`. On Android, `seapp_contexts` assigns apps with a target SDK of 26 or 27 to the `untrusted_app_27` domain with `levelFrom=user`, which produces the security context `u:r:untrusted_app_27:s0:c512,c768` — carrying only the Android-user category pair and **no per-application categories**. Consequently every application on the device with a target SDK in this range shares an identical security context, and the MLS constraints that separate modern applications from one another provide no separation between them. The application's private data remains protected by Unix DAC (distinct UID, mode 0700), but one of the two independent isolation layers is absent. The same domain is additionally granted `file:execute_no_trans` and `file:execmod` on `app_data_file`, permitting the application to execute binaries it writes into its own data directory — an operation denied to applications targeting API 28 and above. **Remediation:** raise `targetSdkVersion` to 30 or higher, which places the application in `untrusted_app` with `levelFrom=all`."
</details>

---

## Part 4 — Demonstrate that `chmod` does not defeat it

This is the payoff, and it is the argument for MCS in one experiment.

### Step 12 — Without a debuggable app

On a stock device you cannot easily make an app world-readable. Reason it through instead, and verify the *policy* half:

```bash
# host — confirm the constraint applies to app_data_file
grep -n 'app_data_file_type' plat_sepolicy.cil | grep mlsconstrain
grep -n 'typeattributeset app_data_file_type' plat_sepolicy.cil
```

**Question 15.** Suppose app B ran `chmod 777` on `/data/user/0/com.example.b/files/secret.txt` **and** `chmod 711` on every directory above it. DAC would now permit app A to read the file. Walk through what happens at the LSM hook and state the outcome.

<details>
<summary>Answer</summary>

1. VFS path walk: DAC passes at every level, because the modes now permit it.
2. `security_inode_permission` is reached for each directory in the path, and for the file.
3. For the directory: constraint 501 applies. `t2` is `app_data_file`, which has `app_data_file_type`; `dom l1 l2` is false because A's categories do not contain B's; A is not `mlstrustedsubject`. **Refused.**
4. Result: `EACCES`, plus an `avc: denied { search }` record.

**MAC refuses it regardless of the permission bits.** That is the concrete, everyday value of this layer: the app cannot give its own data away by mistake, because the discretionary part of the decision is no longer the only part.
</details>

### Step 13 — With a debuggable app (optional, needs Android Studio)

If you can build and install two debuggable apps, do the experiment properly.

App B writes a file and makes it world-readable:

```java
// in app B
File f = new File(getFilesDir(), "secret.txt");
try (FileOutputStream out = new FileOutputStream(f)) {
    out.write("FLAG-B".getBytes(StandardCharsets.UTF_8));
}
f.setReadable(true, false);   // world readable
getFilesDir().setExecutable(true, false);
new File(getApplicationInfo().dataDir).setExecutable(true, false);
```

App A tries to read it:

```java
// in app A
File f = new File("/data/user/0/com.example.b/files/secret.txt");
try (FileInputStream in = new FileInputStream(f)) {
    Log.i("LAB3", "READ: " + new String(in.readAllBytes(), StandardCharsets.UTF_8));
} catch (IOException e) {
    Log.i("LAB3", "REFUSED: " + e.getMessage());
}
```

Then, in a cleared log:

```bash
# host
adb logcat -c
# trigger app A's read
adb logcat -d -b all | grep -a 'avc:'
```

**Question 16.** Record whether the read succeeded, and whether an `avc` record was produced. If a record appeared, decode it with `scripts/avc-decode.py` and confirm which constraint refused it. If the read *succeeded*, that is a much more interesting result — check `getenforce` and `mls` before concluding anything.

> **Note on `setReadable(true, false)`**
> On modern Android this may not have the effect you expect: `/data/data` is `0711` and the app's own directory is `0700`, and an app may not be able to loosen the mode on its own data directory in the way it expects. If the DAC part does not open, you have not tested the MAC part. Verify the modes with `run-as com.example.b ls -l` before concluding.

### Step 14 — Read the labels from inside the app

The Java API exposes no method to read a file's SELinux label. Use `scripts/selinux-probe.js`, which calls `lgetxattr("security.selinux")` directly:

```bash
# host (needs a rooted device for frida-server)
frida -U -f com.example.a -l ../scripts/selinux-probe.js
```

or use `examples/SelinuxProbe.java`, which reports the app's own context and the predicted-versus-observed comparison without needing root at all.

**Question 17.** Compare the label on app A's own `files/` directory with the label on app B's. Which fields differ? Which are identical?

---

## Hints

<details>
<summary>My app's observed level does not match my arithmetic</summary>

Three possibilities, in order:

1. The app has a low `targetSdkVersion` and got `levelFrom=user`, so only the *user* pair is present. Check `dumpsys package <pkg> | grep targetSdk`.
2. The app is privileged or platform-signed, and matched a `levelFrom=user` line.
3. A vendor `seapp_contexts` line matched. Check `/vendor/etc/selinux/vendor_seapp_contexts`.

Run `bash ../scripts/selinux-posture.sh <pkg>`, which prints all three predictions (`all`, `user`, `app`) and tells you which one matched.
</details>

<details>
<summary>What does h1 and h2 mean in the transition constraint?</summary>

A level can be a *range*: `low-high`. `l1` is the subject's low level and `h1` its high. Android uses single levels almost everywhere, so `l1` and `h1` are the same and the `(eq h1 h2)` clause is usually trivially satisfied alongside `(eq l1 l2)`. It matters for ranged contexts, which Android does not use for apps.
</details>

<details>
<summary>Why does a process with NO categories get refused more, not less?</summary>

Because categories are **compartments you must hold**, not clearances you must clear. `dom l1 l2` asks whether the subject's set *contains* the object's. The empty set contains nothing, so a bare-`s0` subject cannot touch any object that carries a category.

That is why `dexoptanalyzer` at `s0` cannot search a `privapp_data_file` at `s0:c512,c768` — and it is the mechanism behind the containment described in [§3.12](../README.md#312-dex2oat-in-its-own-domain-a-real-trust-property-not-a-slogan).
</details>

---

## Success criteria

You can, without notes:

1. Decompose any UID into an Android user id and an appId, naming the range constant subtracted.
2. Compute the four categories and explain what each of the four blocks of 256 encodes.
3. State the invariant on each category's range, and use it to spot a fabricated context.
4. Explain why two categories are needed per number.
5. Read an `mlsconstrain` line and evaluate it by hand for a given pair of contexts, clause by clause.
6. Explain why an `allow` rule matching is not sufficient.
7. Explain the read/write asymmetry (`dom` vs `eq`) and the security property it expresses.
8. Explain why a process with *fewer* categories is *more* restricted.
9. Name at least four domains on a real device that have **no** per-app MCS isolation, and say what separates their processes instead.
10. Explain why `chmod 777` does not defeat this layer, naming the hook and the constraint.
11. Write the `targetSdkVersion` finding, with the remediation.

## Deliverable

A table for your own device:

| Package | uid | appid | userid | Predicted `all` | Observed | `levelFrom` | Per-app isolation? |
|---|---|---|---|---|---|---|---|

Eight rows, including at least one `untrusted_app`, one `priv_app` or `platform_app`, one `system_app`, and — if your device has one — one app with `targetSdkVersion` ≤ 27.

Plus a short written answer to: *"Two apps on this device are separated by how many independent mechanisms, and what are they?"*

---

## Next

[Lab 04 — Reviewing a vendor policy](lab-04-vendor-policy-review.md), where you take everything from Labs 01–03 and go looking for actual findings in the third of the policy nobody outside the OEM has reviewed.
