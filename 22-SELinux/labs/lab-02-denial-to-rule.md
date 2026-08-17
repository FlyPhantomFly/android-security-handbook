# Lab 02 — From a Denial to the Rule That Would Allow It

**Difficulty:** Intermediate
**Time:** 90–120 minutes
**Prerequisites:** [Lab 01](lab-01-reading-contexts.md), [Chapter 22 §3.4](../README.md#34-object-classes-and-permissions-the-vocabulary), [§3.11](../README.md#311-reading-an-avc-denial-field-by-field-and-deriving-the-rule), [§3.16](../README.md#316-neverallow-dontaudit-auditallow-and-the-rules-that-are-not-rules). **No root required for any step.**

---

## Objective

**This is the lab to do if you only do one.**

Provoke real SELinux denials on a real device with commands whose effect you know exactly; read each resulting audit record field by field; derive the `allow` rule it is asking for; and then — the part that separates understanding from mechanics — state what that rule would *also* permit.

Every denial in the first half of this lab is one you will cause yourself, so there is no ambiguity about which action produced which record. Every denial in the second half was **measured on a physical Android 13 device** and is preserved in [`../examples/avc-denials-measured.log`](../examples/avc-denials-measured.log) with its provenance recorded, so you can check your derivation against ground truth.

## Why this matters

An `avc: denied` line is the only place in the entire system where the difference between a DAC refusal and a MAC refusal is written down. The app sees `EACCES`. `strace` sees `EACCES`. Your Java exception handler sees `FileNotFoundException: ... Permission denied`. All of them are identical whichever mechanism refused.

So the ability to find the record, read it correctly, and derive the rule is not a niche skill — it is the *only* diagnostic that exists. Everything else in this chapter is context for it.

And the second half of the skill matters just as much. The rule you derive covers **every object of that type**, not just the one in the record. That gap between "the operation I saw" and "the rule that would permit it" is exactly how vendor policy becomes over-permissive, one `audit2allow` paste at a time.

---

## Setup

```bash
# host
adb devices
adb shell getenforce          # must say Enforcing, or this lab measures nothing
adb shell getprop ro.build.type
```

> **⚠️ If `getenforce` says `Permissive`, stop.** Every denial you provoke will carry `permissive=1` and every operation will *succeed*. You would be measuring a different device. Set it back with `setenforce 1` if you have root, or use a device that has not been modified.

Open two terminals.

```bash
# terminal 1 — the log, live and filtered
adb logcat -c
adb logcat -b all | grep -a 'avc:'
```

```bash
# terminal 2 — where you will run the probes
adb shell
```

> **⚠️ Two flags that are not optional.**
> **`-b all`**: denials frequently land in the `events` or `kernel` buffer, and logcat's default is `main`. Without `-b all` you will see nothing and conclude there were no denials.
> **`grep -a`**: logcat output can contain bytes that make `grep` treat the stream as binary and print only "Binary file matches" — or, through a pipe, nothing at all. This looks exactly like success and has cost people hours.

---

## Part 1 — Provoke three denials and derive three rules

Each of the three probes below was run on the reference device and the resulting record is reproduced exactly. Run them yourself; your records should differ only in `pid`, `ino` and timestamp.

### Probe 1 — read a hardened `/proc` entry

```bash
# adb shell (terminal 2)
cat /proc/sys/kernel/kptr_restrict
```

Observed on the reference device:

```
cat: /proc/sys/kernel/kptr_restrict: Permission denied
```

Terminal 1 shows:

```
08-06 05:34:14.904 17892 17892 I auditd  : type=1400 audit(0.0:7170): avc: denied
  { read } for comm="cat" name="kptr_restrict" dev="proc" ino=1872582
  scontext=u:r:shell:s0 tcontext=u:object_r:proc_security:s0 tclass=file
  permissive=0
```

**Now work it out, field by field, before reading the answer.**

| Field | Value | What it tells you |
|---|---|---|
| `type=1400` | | |
| `{ read }` | | |
| `comm=` | | |
| `name=` | | |
| `dev=` | | |
| `scontext=` | | |
| `tcontext=` | | |
| `tclass=` | | |
| `permissive=` | | |

<details>
<summary>Answers</summary>

| Field | Value | What it tells you |
|---|---|---|
| `type=1400` | `AVC` | an ordinary SELinux denial. `1107` would be an init-wrapped property denial; `1326` would be **seccomp**, not SELinux at all. |
| `{ read }` | one permission | **the permission set that goes into the rule.** Multiple can appear: `{ read write open }`. |
| `comm="cat"` | the process name | truncated to 15 characters by the kernel; hex-encoded if it contains whitespace |
| `name="kptr_restrict"` | the object's **basename** | only the last path component. `path=` would carry the full path when the kernel has one. |
| `dev="proc"` | the filesystem | procfs, so this is a pseudo-file labelled by a `genfscon` statement, not by an xattr |
| `scontext=u:r:shell:s0` | **the subject** | field 3, `shell`, goes on the left of the rule |
| `tcontext=u:object_r:proc_security:s0` | **the target** | field 3, `proc_security`, goes in the middle |
| `tclass=file` | **the class** | goes after the colon |
| `permissive=0` | enforcement | **the operation FAILED** |

</details>

**The rule:**

```
allow shell proc_security:file read;
```

**In CIL**, which is what you would find in the device's own `plat_sepolicy.cil`:

```lisp
(allow shell proc_security (file (read)))
```

**Question 1.** The type is `proc_security`. Find at least two *other* files that carry that type. What would your rule permit that you did not intend?

<details>
<summary>Hint</summary>

```bash
# adb shell — try a few /proc/sys/kernel entries and see which ones fail the same way
cat /proc/sys/kernel/randomize_va_space
cat /proc/sys/kernel/dmesg_restrict
cat /proc/sys/kernel/perf_event_paranoid
```
</details>

### Probe 2 — stat a directory you cannot reach

```bash
# adb shell
ls -l /data/misc/keystore
```

Observed:

```
ls: /data/misc/keystore: Permission denied
```

Record:

```
08-06 05:34:14.928 17893 17893 I auditd  : type=1400 audit(0.0:7171): avc: denied
  { getattr } for comm="ls" path="/data/misc/keystore" dev="dm-7" ino=2342914
  scontext=u:r:shell:s0 tcontext=u:object_r:keystore_data_file:s0 tclass=dir
  permissive=0
```

**Question 2.** Write the rule.

<details>
<summary>Answer</summary>

```
allow shell keystore_data_file:dir getattr;
```

```lisp
(allow shell keystore_data_file (dir (getattr)))
```
</details>

**Question 3.** The class is `dir` and the permission is `getattr`, **not** `read` and **not** `search`. Explain why `ls -l <path>` produces `getattr` rather than `read`. Then say which permission you would expect if you ran `ls /data/misc/keystore/` (with a trailing slash, listing the contents), and which you would expect for `cat /data/misc/keystore/somefile`.

<details>
<summary>Answer</summary>

`ls -l <path>` on a *single path argument* `stat()`s it, which is `getattr`. It has not yet tried to open or list it.

Listing the *contents* would additionally need `dir:read` (readdir) and `dir:open`.

Reaching a file *inside* would need `dir:search` on the directory (to traverse it as a path component) plus `file:open` and `file:read` on the file itself.

Getting the class and permission right is what makes your derived rule minimal rather than a guess. A rule granting `dir:read` when only `dir:getattr` was needed is four times broader than necessary.
</details>

**Question 4.** This is `/data/misc/keystore` — the Keystore daemon's private directory. Would granting this rule be a good idea? Answer in terms of what `shell` would then be able to do, and note that granting `getattr` alone does *not* let you read the contents.

### Probe 3 — try to read the binary policy

```bash
# adb shell
cat /sys/fs/selinux/policy > /dev/null
echo "exit=$?"
```

Observed:

```
exit=1
```

Record:

```
08-06 05:34:14.952 17894 17894 I auditd  : type=1400 audit(0.0:7172): avc: denied
  { read_policy } for comm="cat" scontext=u:r:shell:s0
  tcontext=u:object_r:kernel:s0 tclass=security permissive=0
```

**Question 5.** Write the rule. Then notice what is **missing** from this record compared with the previous two, and explain why.

<details>
<summary>Answer</summary>

```
allow shell kernel:security read_policy;
```

```lisp
(allow shell kernel (security (read_policy)))
```

**Missing:** `name=`, `path=`, `dev=`, `ino=`. There is **no file involved at all.** The object class is `security` and the object is the SELinux security server itself, which is not a filesystem object.

A parser that assumes every record has a `path=` field falls over here. An analyst who expects one gets confused and starts looking for a file. Different classes name their objects in different fields — and some name nothing. The kernel's `dump_common_audit_data` is a `switch` statement on the audit data type, which is exactly why the format varies.
</details>

**Question 6.** This is the denial that stops you from dumping the binary policy on a stock device. Name **two** ways to obtain a binary policy anyway, without this permission.

<details>
<summary>Answer</summary>

1. Compile it yourself from the device's own CIL, which **is** world-readable:
   ```bash
   adb pull /system/etc/selinux/plat_sepolicy.cil
   adb pull /system_ext/etc/selinux/system_ext_sepolicy.cil
   adb pull /vendor/etc/selinux/vendor_sepolicy.cil
   secilc -m -M true -c 31 -o policy.bin -f /dev/null \
       plat_sepolicy.cil system_ext_sepolicy.cil vendor_sepolicy.cil
   ```
2. Extract it from an OTA or factory image, where the same files are present in the system and vendor partitions.

A third option is root, which gets you `/sys/fs/selinux/policy` directly — but a rooted device usually has a *patched* policy, so what you dump is not what the vendor shipped.
</details>

### Probe 4 — the one with a visible symptom

```bash
# adb shell
ls -l /system/etc/selinux/
```

Observed on the reference device — look carefully at three of the rows:

```
total 2124
-rw-r--r-- 1 root root    1510 2009-01-01 00:00 bug_map
drwxr-xr-x 2 root root    4096 2009-01-01 00:00 mapping
-rw-r--r-- 1 root root   50261 2009-01-01 00:00 plat_file_contexts
-????????? ? ?    ?          ?                ? plat_hwservice_contexts
-rw-r--r-- 1 root root    1152 2009-01-01 00:00 plat_keystore2_key_contexts
-????????? ? ?    ?          ?                ? plat_mac_permissions.xml
-rw-r--r-- 1 root root   85457 2009-01-01 00:00 plat_property_contexts
-rw-r--r-- 1 root root    3078 2009-01-01 00:00 plat_seapp_contexts
-rw-r--r-- 1 root root 1981460 2009-01-01 00:00 plat_sepolicy.cil
```

Records:

```
avc: denied { getattr } for comm="ls" path="/system/etc/selinux/plat_mac_permissions.xml"
  dev="dm-4" ino=2037 scontext=u:r:shell:s0
  tcontext=u:object_r:mac_perms_file:s0 tclass=file permissive=0

avc: denied { getattr } for comm="ls" path="/system/etc/selinux/plat_hwservice_contexts"
  dev="dm-4" ino=2035 scontext=u:r:shell:s0
  tcontext=u:object_r:hwservice_contexts_file:s0 tclass=file permissive=0
```

**Question 7.** `ls` printed the *filenames* of those two entries but every metadata column came out as `?`. Explain exactly which permissions `ls` had and which it lacked. Then state the general diagnostic: what does a row of question marks in `ls -l` output always mean?

<details>
<summary>Answer</summary>

`ls` had `dir:search` on `/system/etc/selinux` (it could traverse into it) and `dir:read` (it could `readdir` and obtain the entry names). It lacked `file:getattr` on those two specific files, so `stat()` failed and every metadata field is unknown.

**General diagnostic: a row of question marks in `ls -l` is an unread `getattr` denial.** Go and look at the log. It is one of the few SELinux symptoms that is visible without reading a single audit record, and it tells you precisely where to look.
</details>

**Question 8.** Write both rules. Then explain why `plat_sepolicy.cil` — the entire compiled policy, 1,981,460 bytes — is world-readable while `plat_mac_permissions.xml` is not. Is that inconsistent?

---

## Part 2 — Read denials you did not cause

Now work with the measured corpus, which contains shapes a stock unrooted device will not produce on demand.

```bash
# host
cd 22-SELinux
head -60 examples/avc-denials-measured.log
```

Read the provenance header first. The file is explicitly divided into **measured** records and **synthetic** ones, and the synthetic ones are individually marked. Never quote a synthetic line as evidence of platform behaviour.

### Denial A — a class where the object is a service name

```
avc:  denied  { find } for pid=2396 uid=10028 name=USDKPlus
  scontext=u:r:priv_app:s0:c512,c768
  tcontext=u:object_r:default_android_service:s0
  tclass=service_manager permissive=0
```

**Question 9.** Derive the rule. Then answer three things:
(a) what does `name=` refer to here, given `tclass=service_manager`?
(b) `uid=10028` and `scontext=u:r:priv_app:s0:c512,c768` are both present. Are they the same fact stated twice? Explain.
(c) why is the target type `default_android_service`, and what does that tell you about how the service was registered?

<details>
<summary>Answers</summary>

```
allow priv_app default_android_service:service_manager find;
```

(a) `name=` is the **Binder service name**, not a filename. This is one of the classes where the object is not a file at all, and where `name=` therefore means something completely different.

(b) No. `uid=10028` is the **DAC** identity; `scontext` is the **MAC** identity. They are set by different mechanisms and consulted by different code. `uid=10028` tells you appId 28 — and note that `priv_app` uses `levelFrom=user`, so the context carries only `c512,c768` and does *not* encode the appId. The two fields carry different information and you need both.

(c) `default_android_service` is the fallback type for a service name that appears in **no** `service_contexts` file. The vendor registered a service called `USDKPlus` and forgot to label it. No `find` rule exists for that default type, so even a privileged app cannot reach it — the vendor's own app is silently broken and retrying in a loop.
</details>

**Question 10.** Suppose a vendor engineer sees this denial and "fixes" it by adding exactly the rule you derived. Write two sentences explaining why that is a bad fix and what the correct one is.

### Denial B — the one that proves the MCS arithmetic

```
avc:  denied  { find } for pid=1672 uid=1068 name=nfc
  scontext=u:r:secure_element:s0:c44,c260,c512,c768
  tcontext=u:object_r:nfc_service:s0 tclass=service_manager permissive=0
```

**Question 11.** Decode `c44,c260` back to a UID and confirm it against the `uid=` field. Show your arithmetic. Then explain why this record is more valuable for understanding MCS than any of the `untrusted_app` records in the same file.

<details>
<summary>Answer</summary>

```
first  category = c(appid & 0xff)        -> 44
second category = c(256 + (appid >> 8))  -> 260, so (appid >> 8) = 4
appid = (4 << 8) | 44 = 1024 + 44 = 1068
```

And `uid=1068` on the same line confirms it. Note there is no subtraction: 1068 is below `AID_APP_START` (10000), so the raw appid is used directly.

**Why it is more valuable:** every third-party app on the reference device had an appId below 256, so `c(appid & 0xff)` and `c(appid)` were indistinguishable and `256 + (appid >> 8)` was always exactly `c256`. This record has `appid = 1068`, which exercises both the mask and the shift, and is therefore the only observation on the device that actually *tests* the encoding rather than being consistent with several.
</details>

### Denial C — the wrapped one

```
type=1107 audit(0.0:78): uid=0 auid=4294967295 ses=4294967295 subj=u:r:init:s0
  msg='avc: denied { set } for property=vendor.sms.md.ready pid=1113 uid=1001
  gid=1001 scontext=u:r:rild:s0 tcontext=u:object_r:vendor_default_prop:s0
  tclass=property_service permissive=0'
```

**Question 12.** There are **two** SELinux contexts on that line. Which one is the process that was refused, and what is the other one? Then derive the rule.

<details>
<summary>Answer</summary>

- `subj=u:r:init:s0` — this is **init**, the *reporter*. `init` is the property setter; a process asking to set a property sends a request to `init` over `/dev/socket/property_service`, and `init` performs the check on the caller's behalf and reports the refusal.
- `scontext=u:r:rild:s0` — this is the process that was **actually refused**.

```
allow rild vendor_default_prop:property_service set;
```

A parser that reads the outer `subj=` attributes every property denial to `init` and is wrong every single time. `scripts/avc-decode.py` unwraps the `msg='...'` and relabels the outer context `_reporter_context` so it cannot be confused.
</details>

**Question 13.** `type=1107` here, not `1400`. What is `1107`, and what is `1326`? Why does confusing `1326` with an SELinux denial send you to the wrong chapter?

### Denial D — extended permissions

```
avc: denied { ioctl } for comm="PackageManagerB"
  path="/system/priv-app/MtkMms/MtkMms.apk" dev="dm-4" ino=4089
  ioctlcmd=0x6686 scontext=u:r:system_server:s0
  tcontext=u:object_r:system_file:s0 tclass=file permissive=0
```

**Question 14.** Derive the rule. Then note the `ioctlcmd=` field — it means one rule is **not enough**. Write both rules.

<details>
<summary>Answer</summary>

```
allow system_server system_file:file ioctl;
allowxperm system_server system_file:file ioctl { 0x6686 };
```

A plain `allow ... :file ioctl;` permits *every* ioctl command on that type — thousands of them, many of which are effectively separate syscalls. Extended permissions (`allowxperm`) narrow it to specific command numbers. Writing only the first rule produces something that still does not work, which then tends to get "fixed" by adding something much broader.

`0x6686` is `FS_IOC_ENABLE_VERITY` — `system_server` trying to enable fs-verity on a system APK that lives on a read-only partition. It is benign.
</details>

### Denial E — the constraint case

```
avc: denied { search } for comm="main" name="com.google.android.gms" dev="dm-7"
  ino=999764 scontext=u:r:dexoptanalyzer:s0
  tcontext=u:object_r:privapp_data_file:s0:c512,c768 tclass=dir
  permissive=0 app=com.google.android.gms
```

**Question 15.** Derive the rule. Then compare the subject's category set with the object's and say what you notice. Finally, state the thing this record **cannot** tell you.

<details>
<summary>Answer</summary>

```
allow dexoptanalyzer privapp_data_file:dir search;
```

`dexoptanalyzer` has level `s0` with **no categories**. The object has `{c512, c768}`. The empty set does **not** contain `{c512, c768}`, so `dom l1 l2` is false.

The applicable constraint, measured verbatim from the device's policy:

```lisp
(mlsconstrain (dir (getattr setattr rename open add_name remove_name reparent search rmdir))
  (or (or (neq t2 app_data_file_type) (dom l1 l2)) (eq t1 mlstrustedsubject)))
```

Target *is* an `app_data_file_type`; `dom` is false; `dexoptanalyzer` is not `mlstrustedsubject`. **The constraint refuses it.**

**What the record cannot tell you:** whether it was type enforcement or the constraint that refused. The fields are identical either way. If you go and look up the policy, find a matching `allow` rule, and conclude the log is lying — it is not; you hit a constraint. Only `audit2why -p policy.bin` can settle it.

`scripts/avc-decode.py` flags exactly this case, and says explicitly that it cannot be certain.
</details>

**Question 16.** This denial fires repeatedly on a healthy device (14 times in one uptime on the reference device). Is it a finding? Answer in one sentence, and say what it is *evidence of*.

---

## Part 3 — Check yourself with the tool, and then argue with it

```bash
# host
python3 scripts/avc-decode.py examples/avc-denials-measured.log --group
```

Compare every rule the tool derives against the ones you wrote. Where they differ, work out which is right *before* assuming the tool is.

```bash
# just the rules
python3 scripts/avc-decode.py examples/avc-denials-measured.log --rules-only

# filter by subject
python3 scripts/avc-decode.py examples/avc-denials-measured.log --scontext shell
python3 scripts/avc-decode.py examples/avc-denials-measured.log --scontext untrusted_app

# filter by class
python3 scripts/avc-decode.py examples/avc-denials-measured.log --tclass keystore2_key
python3 scripts/avc-decode.py examples/avc-denials-measured.log --tclass security
```

**Question 17.** Run `--rules-only` and count the rules. Then run it against your own device:

```bash
adb logcat -d -b all | python3 scripts/avc-decode.py - --group --rules-only
```

How many records did it read, and how many distinct rules did they collapse to? On the reference device the answer was **5,993 records in 21,161 lines, collapsing to 33 distinct rules.** What does that ratio tell you about the value of grouping before triaging?

**Question 18.** The tool's header carries a "WHAT THIS WILL NOT TELL YOU" block. Read it. Which of the five limitations listed is the one most likely to make you write a wrong finding, and why?

---

## Part 4 — The half that is not mechanical

Deriving the rule is arithmetic. Knowing what you wrote is judgement.

For each of the rules you derived in Parts 1 and 2, answer:

| Rule | What else carries this type? | Would granting it be acceptable? | What is the better fix? |
|---|---|---|---|
| `allow shell proc_security:file read;` | | | |
| `allow shell keystore_data_file:dir getattr;` | | | |
| `allow shell kernel:security read_policy;` | | | |
| `allow priv_app default_android_service:service_manager find;` | | | |
| `allow rild vendor_default_prop:property_service set;` | | | |
| `allow dexoptanalyzer privapp_data_file:dir search;` | | | |

**Question 19.** Two of those six rules would, if shipped, be *significantly* worse than the others. Identify them and say why.

<details>
<summary>Answer</summary>

**`allow priv_app default_android_service:service_manager find;`** — `default_android_service` is the fallback type for *every* unlabelled service on the device, including ones that do not exist yet. This rule grows more permissive over time without anyone editing it. The correct fix is a `service_contexts` entry giving the service its own type.

**`allow shell kernel:security read_policy;`** — this lets the shell dump the entire binary policy. That is not catastrophic on its own (the CIL is world-readable anyway), but `security` is the class containing `setenforce` and `load_policy`, and granting *any* permission on it to a domain reachable by ADB is the kind of decision that should require a written justification.

`allow dexoptanalyzer privapp_data_file:dir search;` is arguably the worst of all in terms of what it would *undo* — it would defeat the containment described in [§3.12](../README.md#312-dex2oat-in-its-own-domain-a-real-trust-property-not-a-slogan) — but note that it may not even work, because the refusal may have been a constraint rather than a missing rule.
</details>

**Question 20.** Read [§3.16](../README.md#316-neverallow-dontaudit-auditallow-and-the-rules-that-are-not-rules) on `dontaudit`. For each of the six rules above, decide whether the *right* answer for a platform engineer is (a) grant it, (b) `dontaudit` it, or (c) fix the underlying labelling or data flow. Justify each in one sentence.

---

## Part 5 — Prove that DAC and MAC are distinguishable

This is the payoff.

```bash
# terminal 1
adb logcat -c
adb logcat -b all | grep -a 'avc:'
```

```bash
# terminal 2 — two failures that look identical to the caller
adb shell 'cat /data/misc/keystore/user_0/.masterkey 2>&1'
adb shell 'cat /data/data/com.android.chrome/shared_prefs/x.xml 2>&1'
```

Both produce `Permission denied`. Now look at terminal 1.

**Question 21.** Did both produce an `avc` record? If one did not, what does that prove about which mechanism refused it? And what is the *third* possibility that means you cannot be completely certain?

<details>
<summary>Answer</summary>

If a record appeared, MAC refused it — the LSM hook was reached, which means DAC had already passed.

If **no** record appeared, either DAC refused it first (in which case the LSM hook was never reached and no record could exist), **or** MAC refused it with a `dontaudit` rule suppressing the record.

That third possibility is why you cannot be completely certain from a stock shell. To settle it you need the policy:

```bash
sesearch --dontaudit -s shell policy.bin
```

The honest wording in a report is: *"no audit record was produced, which is consistent with a DAC refusal"* — not *"DAC refused it"*.
</details>

**Question 22.** Write the sentence you would put in a report for a refusal you have confirmed was MAC, naming the mechanism precisely. Then write the sentence for one where you could not distinguish. Both should be defensible to a developer who disagrees with you.

---

## Hints

<details>
<summary>I see no denials at all</summary>

Check, in order:

1. `adb shell getenforce` — if `Permissive`, everything succeeds and you get `permissive=1` records rather than failures.
2. Are you using `-b all`? Without it, logcat defaults to `main` and misses `events` and `kernel`.
3. Are you using `grep -a`? Without it, grep may decide the stream is binary and print nothing.
4. Are you grepping for `avc:` and not `denied`? Grepping for `denied` misses `avc: granted` records.
5. Some devices do not forward audit records to logcat at all. On those you need `dmesg`, which needs root.
</details>

<details>
<summary>My records look different from the reference ones</summary>

Expected differences: `pid`, `ino`, timestamps, `audit(...)` serial. Also the *type name* may differ — vendors relabel things. What should **not** differ is the class, the permission, and the shape of the record.

If your `scontext` is not `u:r:shell:s0`, check whether you are on an emulator (which sometimes runs a different `adbd` configuration) or a userdebug build.
</details>

<details>
<summary>The same record appears twice</summary>

That is normal. `auditd` forwards the record into logcat under its own tag (`I auditd :`), and the offending process's own logging often emits it too (`W cat :`). Both are the same event. `scripts/avc-decode.py --group` collapses them.
</details>

---

## Success criteria

You have completed this lab when you can, without notes:

1. Take any `avc: denied` line and write the `allow` rule in both `.te` and CIL syntax, using only four of its fields.
2. Name which four fields those are, and which fields are decoration.
3. Recognise `type=1400`, `type=1107` and `type=1326` and say what each means — including that one of them is not SELinux at all.
4. Unwrap a `type=1107` record and identify which of its two contexts is the offender.
5. Explain why a `security`-class or `capability`-class record has no path field.
6. Recognise `ioctlcmd=` and write the `allowxperm` rule alongside the `allow`.
7. Look at a record where the subject's categories do not contain the object's and say that the refusal *may* have been a constraint, and that the record cannot say which.
8. State what a derived rule would **also** permit, in terms of the type rather than the object.
9. Distinguish a MAC refusal from a DAC refusal by the presence of a record — and state the third possibility that stops it being certain.
10. Read `permissive=1` correctly, as "the operation succeeded".

## Deliverable

Produce a short table for your own device:

| # | Command run | Visible symptom | Record (abridged) | Derived rule | What else it would permit | Grant / dontaudit / fix? |
|---|---|---|---|---|---|---|

Eight rows minimum, of which at least two must be denials you provoked yourself and at least one must be from a class that has **no** filesystem object (`security`, `capability`, `process`, `service_manager` or `keystore2_key`).

---

## Next

[Lab 03 — MCS and app-vs-app isolation](lab-03-mcs-and-app-isolation.md), which takes the category arithmetic from Lab 01 and the denial-reading from this lab and puts them together on the mechanism that actually separates one app from another.
