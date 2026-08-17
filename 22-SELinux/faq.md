# 22 — SELinux FAQ

The questions people actually ask, including the ones they are embarrassed to ask. Answers are direct; where a claim was measured on a device rather than read in documentation, it says so.

The device referred to throughout as "the measured device" is a physical arm64 handset running Android 13 / API 33, stock `user` build, SELinux Enforcing, not rooted.

---

## The "dumb" questions, which are the important ones

### 1. Is SELinux the same thing as root?

No, and they are not even about the same subject.

**Root** (UID 0) is a *DAC* concept — Discretionary Access Control. It is an identity, and the kernel's file-permission code has a special case that lets that identity ignore permission bits.

**SELinux** is *MAC* — Mandatory Access Control. It labels every process with a **domain** and every object with a **type**, and permits an operation only when a system-wide policy contains a rule for that pair. **It never looks at the UID.** Not to be strict with root, not to be lenient with apps. The UID is simply not an input.

So they are orthogonal. A UID 0 process in a domain with no matching rule is refused. A UID 10156 process in a domain with a matching rule is permitted. And because both DAC and MAC run on the same system call, **both must say yes** for anything to happen.

### 2. Why does my root shell still get "Permission denied"?

Because you defeated DAC and did not touch MAC.

`su` gave you UID 0. The kernel's VFS permission check now short-circuits — root has `CAP_DAC_OVERRIDE`. But immediately after that check, control reaches an LSM hook where SELinux asks a different question entirely: *does policy permit a process in domain X to perform this operation on an object of type Y?* If there is no rule, the answer is no, and you get `EACCES` — the same error, from a completely different mechanism.

Find out which rule was missing:

```bash
# adb shell as root
dmesg | grep -i avc | tail
# or, usually without root
adb logcat -d -b all | grep -a 'avc:' | tail
```

Then read the record — [README §3.11](README.md#311-reading-an-avc-denial-field-by-field-and-deriving-the-rule) — or run it through `scripts/avc-decode.py`, which will tell you the exact `allow` rule that would have permitted it.

Recognising this instantly is a small but genuine mark of experience. It costs beginners hours.

### 3. What is a "context" and which part of it actually matters?

A context is a label. It looks like this:

```
u:r:untrusted_app:s0:c107,c256,c512,c768
```

Four colon-separated fields, and **only two of them carry information on Android**:

| Field | Value | Matters? |
|---|---|---|
| 1 — SELinux user | `u` | **No.** Android defines exactly one SELinux user. Full SELinux supports many; Android does not use the feature. |
| 2 — role | `r` (or `object_r` on an object) | **No.** Two fixed values, never anything else. |
| 3 — **type** | `untrusted_app` | **Yes — this is the whole game.** Every policy rule is written about types. When a type labels a *process* it is called a **domain**. |
| 4 — level | `s0:c107,c256,c512,c768` | **Yes**, for app-vs-app isolation. `s0` is the only sensitivity Android uses; the `cNNN` values are the MCS categories. |

When you read a context aloud, say fields 3 and 4 and skip the rest. Beginners spend time trying to interpret `u:` and `r:` and there is nothing there.

### 4. Can I just turn it off?

You can, on a device you control, and you should understand exactly what you are doing.

```bash
# adb shell as root
setenforce 0
getenforce
# Permissive
```

Four things happen, and the third is the one people miss:

1. **It is global and instantaneous.** Every domain on the device stops being confined at the same moment — `init`, `system_server`, every HAL, every app.
2. **Every denial in the log becomes a success.** After `setenforce 0` the log fills with `avc: denied ... permissive=1` records, and every one of those is an operation that *happened*. Reading that log as "look at all the things being blocked" is exactly backwards.
3. **It voids every measurement you take afterwards.** Any finding of the form "app X can reach Y" measured on a permissive device is worthless, and a developer will say so in one sentence. If your bypass only reproduces with SELinux off, you have demonstrated nothing about a stock device.
4. **It requires `security:setenforce`**, which essentially nothing on a stock device has. If you can run it, you are already root with a patched policy.

For a *product* the answer is a flat no: it fails CTS, so the device cannot ship with Google Mobile Services; it fails Play Integrity, so banking apps stop working; and it removes the only layer that constrains a compromised root process.

### 5. Why do two apps have different `c` numbers?

Because the numbers are computed from the app's UID, and the whole point is that they differ.

Every ordinary third-party app runs in the **same domain**, `untrusted_app`. Not a similar one — the same type, byte for byte. So type enforcement cannot tell them apart: every rule that names `untrusted_app` covers all of them.

What separates them is the **MCS category set**, derived arithmetically from the UID:

```
userid = uid / 100000
appid  = uid % 100000, minus 10000 for an ordinary app

c(appid & 0xff)            first category
c(256 + (appid >> 8))      second
c(512 + (userid & 0xff))   third
c(768 + (userid >> 8))     fourth
```

Measured on the device:

| Package | uid | appid | Context |
|---|---|---|---|
| `com.android.chrome` | 10107 | 107 | `u:r:untrusted_app:s0:c107,c256,c512,c768` |
| `com.synergyenfmanager` | 10150 | 150 | `u:r:untrusted_app:s0:c150,c256,c512,c768` |
| `com.synergyenf` | 10156 | 156 | `u:r:untrusted_app:s0:c156,c256,c512,c768` |

Same domain, different first category. The MLS constraints in policy then require the subject's category set to **contain** the object's before permitting a read or a directory traversal — and `{c107, c256, c512, c768}` does not contain `c150`, so Chrome cannot reach the other app's files even if DAC somehow allowed it.

The last two categories, `c512,c768`, are the same for all three because all three belong to Android user 0. On a work profile (user 10) they would be `c522,c768`.

### 6. What is the difference between a "type" and a "domain"?

None, technically. They are the same namespace and the same mechanism.

"Domain" is just the word people use when a type is labelling a *process*. `untrusted_app` is a type; when it is on a process we call it a domain. `app_data_file` is a type; it only ever labels files, so nobody calls it a domain.

AOSP formalises the distinction with an attribute: types intended for processes are given the `domain` attribute, and a large body of policy is written about that attribute rather than about individual types.

### 7. Do I need to be root to look at SELinux?

Mostly no, and this surprises people. Without root you can read:

- `getenforce`, and every file under `/sys/fs/selinux` except `policy`
- every process's context, with `ps -A -Z`
- the complete `seapp_contexts` for every partition
- the entire compiled policy in CIL form (`plat_sepolicy.cil`, `vendor_sepolicy.cil`) — these are world-readable
- `file_contexts`, `property_contexts`, `service_contexts`, `keystore2_key_contexts`
- every denial the device has logged, via `logcat -b all`

What you **cannot** do without root is read the *binary* policy at `/sys/fs/selinux/policy`, which needs `security:read_policy`. Measured on the device, the attempt produces:

```
avc: denied { read_policy } for comm="cat" scontext=u:r:shell:s0
  tcontext=u:object_r:kernel:s0 tclass=security permissive=0
```

You also cannot run `dmesg` without root on most builds — but `logcat -b all` usually has the same records, because `auditd` forwards them.

### 8. There are thousands of SELinux denials in my logs. Is my device compromised?

Almost certainly not. This is the single most common false alarm in this area.

During the writing of this chapter, a stock, unrooted, perfectly healthy Android 13 device produced **6,101 `avc` records in one uptime**. Decoded and grouped, those 6,101 records collapsed to **33 distinct rules**, of which five accounted for over 97% of the volume:

```
allow gmscore_app traced_producer_socket:sock_file write;   # x4885
allow system_suspend sysfs:dir read;                        # x551
allow system_suspend sysfs_batteryinfo:dir read;            # x429
allow vold persist_data_file:dir read;                      # x51
allow dexoptanalyzer privapp_data_file:dir search;          # x14
```

Every one is benign. The first is Google Play Services probing for a Perfetto tracing socket every thirty seconds and handling the failure. The second and third are the suspend HAL enumerating wakeup sources it cannot all read.

**A denial is an operation the platform refused.** That is the control working. Four things would change the answer, and only four:

1. Any record with `permissive=1` — that operation **succeeded**.
2. A denial naming a security-critical operation: `setenforce`, `load_policy`, `sys_module`, `manage_blob`, `use_dev_id`.
3. A denial you can causally link to a security-relevant action you performed.
4. A change in denial volume or pattern after installing or exercising a specific app.

See [README §5.9](README.md#59-honest-severity-an-avc-denial-is-not-a-finding), which includes a paragraph you can paste into a report.

---

## Practical questions

### 9. How do I tell whether a "Permission denied" was DAC or SELinux?

Look for an `avc` record with a matching timestamp. That is the only way — they produce the same `EACCES`, and `strace`, your exception handler and the app all see exactly the same thing.

```bash
# terminal 1
adb logcat -c && adb logcat -b all | grep -a 'avc:'
# terminal 2 -- now do exactly one thing
adb shell 'cat /some/path'
```

- Record appears → it was MAC.
- No record → it was DAC... **or** MAC with a `dontaudit` rule suppressing the record.

That ambiguity is real and there is no way around it from a stock shell. With the binary policy you can settle it with `sesearch --dontaudit` or `audit2why -p policy.bin`. Without it, say "no audit record was produced, which is consistent with a DAC refusal" rather than asserting.

### 10. Why does `grep avc` find nothing when I know there are denials?

Three causes, in order of frequency:

1. **You used `logcat` without `-b all`.** Denials often land in the `events` or `kernel` buffer, and the default is `main`.
2. **You used `grep` without `-a`.** Logcat output can contain bytes that make `grep` decide the stream is binary; it then prints only "Binary file matches", or nothing at all through a pipe. This looks exactly like "no denials found" and has cost people hours.
3. **You grepped for `denied`.** That misses every `avc: granted` record, which is where `auditallow` puts the sensitive *successes*.

The correct form:

```bash
adb logcat -d -b all | grep -a 'avc:'
```

### 11. Can I write my own SELinux policy for my app?

No. An app cannot request a domain, cannot add rules, cannot read the policy, and cannot change its own context after it starts.

The entire developer-facing surface is one manifest attribute:

```xml
<service android:name=".ParserService" android:isolatedProcess="true" />
```

which puts that service's process in `isolated_app`, a heavily restricted domain. That is it.

Indirectly, `targetSdkVersion` also matters — it selects which `untrusted_app` variant you get and therefore what permissions you have. See question 16.

If you are building a *platform* (an OEM, or a custom AOSP build), you write policy in `system/sepolicy/` or your vendor equivalent, and [README §9.5](README.md#95-enterprise--writing-the-policy-for-a-new-vendor-daemon-correctly) walks through doing it correctly.

### 12. What does `permissive=1` mean? Is that good or bad?

It means **the operation succeeded**. Policy would have refused it; the domain is in permissive mode, so the kernel logged the decision and allowed it anyway.

This is the most damaging misreading in the whole area, because the word `denied` is right there in the same line. `avc: denied { write } ... permissive=1` reads as "denied" and means "allowed".

Two ways a domain can be permissive:

- The whole device is permissive (`getenforce` says `Permissive`, someone ran `setenforce 0`).
- Policy contains `permissive <domain>;` for that one domain, while everything else is enforcing. `getenforce` still says `Enforcing` and gives you no clue.

The second is a genuine finding on a production build — it fails CTS and Play Integrity — and the `permissive=1` field is the only way to detect it without the binary policy:

```bash
adb logcat -d -b all | grep -a 'permissive=1'
```

### 13. Why did my app work on Android 7 and stop working on Android 10?

If the failure involves running a binary you wrote to your own data directory, the answer is the `seapp_contexts` ladder and the `file:execute_no_trans` permission.

An app targeting API ≤ 27 lands in `untrusted_app_25` or `untrusted_app_27`, and the measured policy grants those domains two extra permissions on their own data:

```lisp
(allow untrusted_app_25 app_data_file (file (execute_no_trans)))
(allow untrusted_app_25 app_data_file (file (execmod)))
(allow untrusted_app_27 app_data_file (file (execute_no_trans)))
(allow untrusted_app_27 app_data_file (file (execmod)))
```

A modern `untrusted_app` gets neither. So `chmod +x ./payload && ./payload` works on the old target and fails on the new one.

Note what did **not** change: `file:execute` is still granted, so `System.loadLibrary` / `dlopen` of a `.so` in your data directory still works. It is `execve` specifically that is closed.

If the failure involves a native library, it may be `execmod` — a library with text relocations needs the linker to write into a mapping it then executes, and that permission was withdrawn. Rebuild without TEXTRELs.

### 14. Does SELinux stop Frida?

Not directly, and the honest answer is more interesting.

`frida-server` runs as root, so it needs root, and root on a modern device means a modified boot image — which means Magisk, which means `magiskpolicy` has patched the loaded policy to permit what Magisk needs. So by the time Frida works at all, the policy is no longer the one the vendor shipped.

Frida's *gadget* injection into an app is a different matter and is constrained by the app domain's permissions — which is one reason the gadget is usually injected by repackaging the APK rather than by writing to the running process.

The practical consequence for you: **anything you measure with Frida on a rooted device may not hold on a stock one**, because you are measuring a device whose policy has been patched. Where a finding matters, reproduce it with an ordinary app on a stock device — `examples/SelinuxProbe.java` exists for exactly this.

### 15. Why does `run-as` behave differently from the app itself?

Because `run-as` puts you in a **different domain**. Measured `seapp_contexts` lines:

```
user=_app minTargetSdkVersion=28 fromRunAs=true domain=runas_app levelFrom=all
user=_app fromRunAs=true domain=runas_app levelFrom=user
```

You get `runas_app`, not `untrusted_app`. Different domain, different rule set. A command that works under `run-as` may fail in the app, and vice versa.

This is also an anti-analysis signal that malware uses: an app that reads `/proc/self/attr/current` and finds `runas_app` instead of `untrusted_app` knows an analyst is driving it.

### 16. Is a low `targetSdkVersion` an SELinux problem?

Yes, and this is not obvious.

The `seapp_contexts` ladder, measured verbatim:

```
user=_app minTargetSdkVersion=30 domain=untrusted_app    levelFrom=all
user=_app minTargetSdkVersion=29 domain=untrusted_app_29 levelFrom=all
user=_app minTargetSdkVersion=28 domain=untrusted_app_27 levelFrom=all
user=_app minTargetSdkVersion=26 domain=untrusted_app_27 levelFrom=user
user=_app                        domain=untrusted_app_25 levelFrom=user
```

An app targeting API 26 or 27 gets **`levelFrom=user`**, which means its context is `u:r:untrusted_app_27:s0:c512,c768` — with **no per-app categories at all**. Every such app on the device has an identical context, so the MLS constraint that separates modern apps from each other does not separate them. They are still separated by DAC, but a whole layer is gone.

And an app targeting ≤ 27 additionally gets `execute_no_trans` and `execmod` on its own data.

So "low `targetSdkVersion`" is a security finding with a one-line remediation, not merely a compatibility note. If a tool flags it as a compatibility issue, upgrade the finding.

### 17. What is the `keystore_key` class, and why does my app get denied on it?

The `keystore_key` (legacy) and `keystore2_key` (Android 12+) classes govern operations on Keystore **key namespaces** — not on individual keys, and not on files.

The namespaces are defined in `/system/etc/selinux/plat_keystore2_key_contexts`. Measured on the device, there are seven: `su_key`, `shell_key`, `vold_key`, `odsign_key`, `wifi_key`, `locksettings_key`, `resume_on_reboot_key`.

**Your app's keys are in none of them.** App keys live in a per-UID namespace reached through the generic `keystore` type, and your access to your own keys is mediated by UID inside `keystore2`, not by a per-app SELinux type.

If you are being denied, the likely cause is one of two permissions:

```lisp
;; measured -- exactly one domain has each
(allow system_server keystore (keystore2_key (... use_dev_id)))
(allow gmscore_app   keystore (keystore2_key (gen_unique_id)))
```

`use_dev_id` permits including the device's IMEI, MEID and serial number in an attestation. `gen_unique_id` permits requesting the attestation unique ID. If your app is trying either, it will be refused in the **kernel**, not in Java — and there is no app-side bypass on a stock device. Hooking the framework call does not help; the denial happens below it.

### 18. My app talks to a vendor daemon over a UNIX socket. Is that protected?

It depends entirely on whether the socket has a filesystem path.

- **A socket bound to a path** has an inode, an owner and mode bits, so DAC applies, plus a MAC label of class `sock_file`. Two mechanisms.
- **An abstract-namespace socket** — one whose name starts with a NUL byte, shown as `@name` in `/proc/net/unix` — has **no filesystem entry at all**. No inode, no owner, no permission bits. **DAC does not apply in any form.** SELinux is the only control that exists.

So for an abstract socket, whether an app can reach the daemon is decided *solely* by whether policy contains:

```
allow <app domain> <daemon domain>:unix_stream_socket connectto;
```

Measured on the device, an ordinary app may `connectto` exactly seven listeners: `tombstoned`, `logd`, `adbd`, `traced`, `heapprofd`, `traced_perf` and `runas_app`. That is the whole list.

If a vendor granted `connectto` from `appdomain` to their daemon, every app on the device can talk to it, and the daemon's own input handling is the entire boundary. Find them:

```bash
adb shell 'cat /proc/net/unix' | grep '@'
grep -nE 'unix_stream_socket .*connectto' vendor_sepolicy.cil
```

### 19. Why can't my app read another app's `/proc/<pid>/maps`, even as root?

Two separate mechanisms, and it is worth knowing which one you hit.

`/proc/<pid>/maps` is protected by `hidepid`-style restrictions (chapter 21) *and* by SELinux: reading another process's `/proc` entries needs `process:getattr` or `dir search` on `proc` types, and app domains do not have it for other apps.

This was measured during the writing of chapter 19 on the same device: `adb shell` is **SELinux-denied** from reading another app's `/proc/<pid>/maps` on Android 13, which is why that chapter's fixture file is synthetic and labelled as such.

If you have root and are still refused, look for the `avc` record — it will name the type and class.

### 20. What is the difference between `dontaudit` and `neverallow`?

They are almost opposites, and mixing them up produces confident wrong statements.

| | `dontaudit` | `neverallow` |
|---|---|---|
| When it acts | **runtime** | **compile time and CTS only** |
| What it does | suppresses the audit **record** for a denial | asserts that no matching `allow` rule may exist anywhere in the policy |
| Does it grant anything? | no | no |
| Does it block anything at runtime? | no — the denial still happens | **no. The kernel has never heard of it.** |
| Effect if violated | n/a | the policy fails to compile; CTS fails |

The consequence of `neverallow` being build-time only is important: **a device whose loaded policy was patched after boot — by Magisk, by an exploit, by a modified boot image — is bound by no `neverallow` at all**, because nothing re-checks.

The consequence of `dontaudit` is that **silence proves nothing.** If you probe something and see no denial, it might have succeeded, or it might have failed on DAC, or it might have failed on MAC with a `dontaudit` in place.

### 21. Where do I actually start on an engagement?

Three commands, then two files.

```bash
# 1. state, before anything else -- all three change what your results MEAN
adb shell getenforce
adb shell getprop ro.build.type
adb shell getprop ro.debuggable

# 2. full posture in one pass
bash scripts/selinux-posture.sh com.target.app

# 3. triage every denial the device has
adb logcat -d -b all | python3 scripts/avc-decode.py - --group
```

Then pull and read the two files that carry findings:

```bash
adb pull /vendor/etc/selinux/vendor_sepolicy.cil
adb pull /vendor/etc/selinux/vendor_seapp_contexts
```

Vendor policy is roughly a third of the total (measured: 1,072,684 bytes against 1,981,460 for platform) and has had **no external review**. That is where the findings are. [README §5.8](README.md#58-how-pentesters-test-it) has the full grep set.

### 22. Is SELinux worth learning if I only test apps, not platforms?

Yes, for four reasons that come up in ordinary app work.

1. **You will hit it constantly** while instrumenting, and misdiagnosing an `EACCES` wastes time.
2. **It changes the severity of your findings.** "This data is in the app's private directory" means something specific because of the MCS constraints; being able to say *why* makes the finding credible.
3. **It is half of every IPC finding.** Whether a component is reachable at all is a MAC decision, and a Drozer result that "works" implicitly passed it.
4. **Clients ask about the denials.** Being able to explain, with arithmetic, why 6,000 records are normal saves an argument on most engagements and is the kind of thing that gets you asked back.

### 23. Which single thing should I be able to do after this chapter?

Take a raw `avc: denied` line and write the `allow` rule it is asking for, then say what that rule would *also* permit.

The derivation is mechanical — four fields:

```
allow  <scontext field 3>  <tcontext field 3> : <tclass>  <the { } set> ;
```

```
avc: denied { read } ... scontext=u:r:shell:s0
  tcontext=u:object_r:proc_security:s0 tclass=file
      ->  allow shell proc_security:file read;
```

The second half is what separates understanding from mechanics. That rule permits `read` on **every** object of type `proc_security`, not just the file in the record. Types are coarse. Knowing that is what stops you — or a developer you are advising — from turning one denial into a permanent hole.

`labs/lab-02` is built entirely around this, using denials measured on a real device with the exact command that produced each one recorded, so you can check your answers against ground truth.
