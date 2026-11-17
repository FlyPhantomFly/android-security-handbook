# Lab 01 — Reading Contexts on a Real Device

**Difficulty:** Beginner
**Time:** 45–75 minutes
**Prerequisites:** [Chapter 22 §1–§3.6](../README.md#1-introduction), a device or emulator with `adb`. **No root required for any step.**

---

## Objective

Take one real device and establish, from the kernel's own records, the complete SELinux picture: which domains are running, which context every app has, where each of those contexts came from, and what the four fields mean. By the end you will be able to look at any process on any device and say what domain it is in, why it is in that domain, and which line of which file put it there.

## Why this matters

Three reasons, in increasing order of importance.

First, **it is the ground truth**. `dumpsys`, decompiled code and documentation all describe what the system *intends*. `ps -A -Z` describes what the kernel will actually enforce. When they disagree, the kernel wins.

Second, **almost every methodological error in Android testing is an identity error** — running a command in one security context and generalising the result to another. This lab makes the difference between `u:r:shell:s0` and `u:r:untrusted_app:s0:c107,c256,c512,c768` something you have *seen*, not something you have read.

Third, **the context is the input to everything else in this chapter.** You cannot read a denial, decode an MCS category, or evaluate a policy rule without first being fluent in the four-field format.

> **Definition — security context**
> The label SELinux attaches to every process and every object. Written `user:role:type:level`. On Android the first two fields are fixed and carry no information; the third — the **type**, called the **domain** when it labels a process — is what every policy rule is written about; the fourth carries the MCS categories that separate apps from each other.

---

## Setup

```bash
# host
adb devices
adb shell getprop ro.product.model
adb shell getprop ro.build.version.release
adb shell getprop ro.build.version.sdk
adb shell getprop ro.build.version.security_patch
adb shell getprop ro.build.type
adb shell getprop ro.debuggable
```

Record all seven. Every finding you ever write should state which kind of build it came from, because `ro.build.type` and `ro.debuggable` change what is possible.

The reference device used throughout this lab, for comparison:

```
model               i9000S
android release     13
api level           33
security patch      2021-11-05
build type          user
ro.debuggable       0
first api level     33
```

Have at least two third-party apps installed and running. Chrome plus anything else is fine.

---

## Steps

### Step 1 — Establish who *you* are, before looking at anything else

```bash
# adb shell
id
```

Reference output:

```
uid=2000(shell) gid=2000(shell) groups=2000(shell),1004(input),1007(log),1011(adb),
1015(sdcard_rw),1028(sdcard_r),1078(ext_data_rw),1079(ext_obb_rw),3001(net_bt_admin),
3002(net_bt),3003(inet),3006(net_bw_stats),3009(readproc),3011(uhid),3012(readtracefs)
context=u:r:shell:s0
```

That single line contains **both** identities: the DAC one (`uid=2000` plus a long list of supplementary groups) and the MAC one (`context=u:r:shell:s0`). They are independent mechanisms, and both will be consulted on every operation you perform for the rest of this lab.

```bash
# adb shell — the context alone
id -Z
# u:r:shell:s0
```

**Question 1.** Your context is `u:r:shell:s0` and it has **no MCS categories**. An app's context has four. What does that difference imply about whether an experiment run from this shell tells you anything about what an app can do?

**Question 2.** You are in the supplementary group `3003(inet)`. Which of the two mechanisms — DAC or MAC — does that group membership belong to? What is the MAC equivalent, if any?

### Step 2 — Read your own context the way the kernel stores it

```bash
# adb shell
cat /proc/self/attr/current
# u:r:shell:s0
```

`/proc/self/attr/current` is the authoritative source. `id -Z` is a convenience that reads the same thing.the kernel appends a NUL byte, so the output may look slightly odd in a pipeline:

```bash
# adb shell — see the trailing NUL
cat /proc/self/attr/current | xxd | tail -1
```

**Question 3.** `cat /proc/self/attr/current` works. Now try another process:

```bash
# adb shell
cat /proc/1/attr/current
```

What happens, and why? (Hint: this is not a DAC failure. Look for a denial.)

### Step 3 — Enumerate every domain on the device

```bash
# adb shell
ps -A -Z | head -5
```

Reference:

```
LABEL                          USER    PID  PPID     VSZ    RSS WCHAN  ADDR S NAME
u:r:init:s0                    root      1     0 10922352 15116 0         0 S init
u:r:kernel:s0                  root      2     0       0      0 0         0 S [kthreadd]
u:r:kernel:s0                  root      3     2       0      0 0         0 I [rcu_gp]
```

Now count the domains:

```bash
# adb shell — every distinct TYPE, with a process count
ps -A -Z | awk 'NR>1 {split($1,a,":"); if (a[3] != "") print a[3]}' | sort | uniq -c | sort -rn
```

Reference output, abridged (the full list on the reference device had over a hundred distinct domains):

```
    349 kernel
      9 priv_app
      5 system_app
      3 shell
      3 platform_app
      3 netd
      2 zygote
      2 untrusted_app
      2 radio
      2 gmscore_app
      2 crash_dump
      1 system_server
      1 installd
      1 vold
      1 keystore
      1 servicemanager
      1 adbd
      ...
```

**Question 4.** There are 349 processes in the `kernel` domain and one in `system_server`. Which of the two is a larger attack surface, and why is the process count the wrong metric?

**Question 5.** Count the distinct domains on your device. Roughly how many are AOSP domains and how many are vendor-specific? (Hint: vendor domains usually carry a vendor prefix — `mtk_`, `qti_`, `exynos_`, or the OEM's name.) What does the ratio tell you about where to look for findings?

### Step 4 — Read the app domains, and notice what differs

```bash
# adb shell
ps -A -Z | grep -E '_app|zygote|sandbox' | sort
```

Reference output from the device:

```
u:r:gmscore_app:s0:c512,c768                        u0_a96   com.google.android.gms
u:r:gmscore_app:s0:c512,c768                        u0_a96   com.google.android.gms.persistent
u:r:mediaprovider_app:s0:c132,c256,c512,c768        u0_a132  com.android.providers.media.module
u:r:permissioncontroller_app:s0:c130,c256,c512,c768 u0_a130  com.android.permissioncontroller
u:r:platform_app:s0:c512,c768                       u0_a119  com.android.systemui
u:r:platform_app:s0:c512,c768                       u0_a40   com.android.externalstorage
u:r:platform_app:s0:c512,c768                       u0_a48   com.android.documentsui
u:r:priv_app:s0:c512,c768                           u0_a109  com.android.launcher3
u:r:priv_app:s0:c512,c768                           u0_a95   com.android.vending
u:r:priv_app:s0:c512,c768                           u0_a96   com.google.process.gservices
u:r:simulate_app:s0:c512,c768                       u0_a62   com.android.simulate.printer.server
u:r:system_app:s0                                   system   com.android.keychain
u:r:system_app:s0                                   system   com.mediatek.voicecommand
u:r:traceur_app:s0:c77,c256,c512,c768               u0_a77   com.android.traceur
u:r:untrusted_app:s0:c107,c256,c512,c768            u0_a107  com.android.chrome
u:r:untrusted_app:s0:c150,c256,c512,c768            u0_a150  com.synergyenfmanager
u:r:untrusted_app:s0:c156,c256,c512,c768            u0_a156  com.synergyenf
u:r:webview_zygote:s0                               webview_zygote  webview_zygote
u:r:zygote:s0                                       root     zygote64
```

Stop and look at this properly. There are **four distinct patterns** in the level field:

| Pattern | Example | Which processes |
|---|---|---|
| four categories, first one varies | `s0:c107,c256,c512,c768` | `untrusted_app`, `traceur_app`, `mediaprovider_app`, `permissioncontroller_app` |
| two categories, always the same | `s0:c512,c768` | `gmscore_app`, `platform_app`, `priv_app`, `simulate_app` |
| no categories at all | `s0` | `system_app`, `zygote`, `webview_zygote` |
| — | | |

**Question 6.** Three `platform_app` processes — `com.android.systemui`, `com.android.externalstorage` and `com.android.documentsui` — have **identical** contexts, despite having three different UIDs. What does that mean about whether MCS separates them from each other? What *does* separate them?

**Question 7.** The three `untrusted_app` processes have different first categories (`c107`, `c150`, `c156`) but the same last two (`c512`, `c768`). Predict what the last two would be for an app running in a work profile (Android user 10). Check your prediction against the encoding in [§3.7](../README.md#37-mcs-the-category-encoding-and-what-it-actually-enforces).

### Step 5 — Verify the MCS arithmetic yourself

Pick one app and do the arithmetic by hand before running any tool.

```bash
# adb shell
pm list packages -U | grep chrome
# package:com.android.chrome uid:10107
```

Now compute:

```
userid = 10107 / 100000              = 0
appid  = 10107 % 100000              = 10107
         10107 >= 10000, so subtract = 107

c(107 & 0xff)          = c107
c(256 + (107 >> 8))    = c(256 + 0)   = c256
c(512 + (0 & 0xff))    = c512
c(768 + (0 >> 8))      = c768

predicted: s0:c107,c256,c512,c768
```

Now check:

```bash
# adb shell
ps -A -Z | grep com.android.chrome
# u:r:untrusted_app:s0:c107,c256,c512,c768  u0_a107  ... com.android.chrome
```

**Do this by hand for at least three apps on your own device before running any script.** The arithmetic is the point; automating it before you can do it teaches nothing.

Then check yourself:

```bash
# host
bash ../scripts/selinux-posture.sh com.android.chrome --no-logcat
```

which prints the whole derivation and compares it against the observed context.

**Question 8.** Find a process whose UID is **greater than 10255** (so `appid > 255`), or a system daemon with a UID above 255. What is its second category, and does it still equal `c256`? Explain.

If your device has no such app, the reference device provides one: `secure_element` runs as uid **1068**, and its measured context is:

```
u:r:secure_element:s0:c44,c260,c512,c768
```

Work through it: 1068 is below `AID_APP_START` (10000), so no subtraction. `1068 & 0xff` = 44 (because 1068 = 4·256 + 44). `256 + (1068 >> 8)` = `256 + 4` = 260. That is why the second category is `c260` and not `c256`.

**Question 9.** Given the encoding, what is the largest value the **first** category can ever take? What does it tell you if someone shows you a context whose first category is `c288`?

### Step 6 — Read `seapp_contexts` and explain every context you saw

```bash
# adb shell
cat /system/etc/selinux/plat_seapp_contexts
```

The complete annotated version from the reference device is in [`../examples/seapp_contexts-measured.txt`](../examples/seapp_contexts-measured.txt). The lines that matter for Step 4:

```
user=system seinfo=platform domain=system_app type=system_app_data_file
user=_app seinfo=platform domain=platform_app type=app_data_file levelFrom=user
user=_app isPrivApp=true domain=priv_app type=privapp_data_file levelFrom=user
user=_app isPrivApp=true name=com.google.android.gms domain=gmscore_app type=privapp_data_file levelFrom=user
user=_app seinfo=platform name=com.android.traceur domain=traceur_app type=app_data_file levelFrom=all
user=_app minTargetSdkVersion=30 domain=untrusted_app type=app_data_file levelFrom=all
user=_app minTargetSdkVersion=29 domain=untrusted_app_29 type=app_data_file levelFrom=all
user=_app minTargetSdkVersion=28 domain=untrusted_app_27 type=app_data_file levelFrom=all
user=_app minTargetSdkVersion=26 domain=untrusted_app_27 type=app_data_file levelFrom=user
user=_app domain=untrusted_app_25 type=app_data_file levelFrom=user
```

**Question 10.** For each of the four level patterns you identified in Step 4, find the `seapp_contexts` line that produced it and name the `levelFrom=` value responsible.

**Question 11.** `com.android.traceur` is a platform-signed app and gets `levelFrom=all`. `com.android.systemui` is also platform-signed and gets `levelFrom=user`. Look at the two lines and explain why.

**Question 12.** The file is read top to bottom by `cat`, but that is **not** how matching works. Read [§3.6](../README.md#36-seapp_contexts-where-the-domain-is-actually-decided) and state, in one sentence, how libselinux actually decides which line applies. Then explain why `com.google.android.gms` gets `gmscore_app` rather than `priv_app`, even though both lines could match.

### Step 7 — Now do the vendor file

```bash
# adb shell
cat /vendor/etc/selinux/vendor_seapp_contexts
```

Reference device:

```
user=_app seinfo=platform name=com.trustonic.tuiservice domain=mobicore_app type=app_data_file levelFrom=user
user=_app seinfo=platform name=com.mediatek.emcamera domain=emcamera_app type=app_data_file levelFrom=user
user=_app seinfo=platform name=com.mediatek.sensorhub.ui domain=sensorhub_app type=app_data_file levelFrom=user
user=_app seinfo=platform name=com.android.simulate.printer.server domain=simulate_app type=simulate_app_data_file levelFrom=user
```

**Question 13.** All four lines require `seinfo=platform`. What would happen if one of them did **not**? Write out the attack in two sentences.

Run the check:

```bash
# adb shell — a vendor line matching on name= with no signature requirement
cat /vendor/etc/selinux/vendor_seapp_contexts | grep 'name=' | grep -v 'seinfo=' | grep -v 'isPrivApp='
```

Empty output is the correct result. Non-empty is a finding.

### Step 8 — Labels on objects, not just processes

```bash
# adb shell — files
ls -Zd /system/bin/app_process64
# u:object_r:zygote_exec:s0  /system/bin/app_process64

ls -Zd /data/local/tmp
# u:object_r:shell_data_file:s0  /data/local/tmp

ls -Z /system/etc/selinux/
```

Note the role field on an object: `object_r`, not `r`. That is the only difference in field 2 that Android ever uses.

```bash
# adb shell — properties
getprop -Z ro.build.version.sdk
# u:object_r:build_prop:s0

getprop -Z ro.debuggable
getprop -Z sys.boot_completed
```

```bash
# adb shell — try your own app's data directory
ls -ldZ /data/data/com.android.chrome
```

**Question 14.** The last command fails. Two mechanisms could be responsible. Name both, and describe how you would determine which one it was. (You will do this properly in Lab 02.)

### Step 9 — Global state

```bash
# adb shell
getenforce
cat /sys/fs/selinux/enforce
cat /sys/fs/selinux/policyvers
cat /sys/fs/selinux/mls
cat /sys/fs/selinux/deny_unknown
cat /sys/fs/selinux/checkreqprot
ls /sys/fs/selinux/class | wc -l
```

Reference device:

```
Enforcing
1
31
1
1
0
103
```

**Question 15.** `getenforce` says `Enforcing`. Does that prove that *every* domain on the device is enforcing? If not, what would you check instead?

**Question 16.** `cat /sys/fs/selinux/mls` returns `1`. Suppose it returned `0` on a device you were assessing. Write the finding in two sentences, naming the specific consequence.

### Step 10 — Object classes and their permissions

```bash
# adb shell
ls /sys/fs/selinux/class | tr '\n' ' '
```

```bash
# adb shell — pick the ones this chapter cares about
ls /sys/fs/selinux/class/file/perms
ls /sys/fs/selinux/class/dir/perms
ls /sys/fs/selinux/class/process/perms
ls /sys/fs/selinux/class/capability/perms
ls /sys/fs/selinux/class/security/perms
ls /sys/fs/selinux/class/service_manager/perms
ls /sys/fs/selinux/class/binder/perms
ls /sys/fs/selinux/class/keystore2_key/perms
ls /sys/fs/selinux/class/unix_stream_socket/perms
```

**Question 17.** The `capability` class has permissions named `dac_override`, `sys_admin`, `sys_module` and so on — the Linux capabilities. Why does SELinux have an object class for capabilities at all, when the kernel already tracks which capabilities a process holds? Answer in terms of the chapter's thesis.

**Question 18.** The `property_service` class has exactly one permission: `set`. There is no `get`. How, then, is *reading* a system property controlled? (Hint: `getprop -Z` gave you a context that looks like a file label. It is one.)

### Step 11 — Put it together

Write a short table for your own device, filled in from what you have measured:

| Package | uid | appid | Predicted level | Observed context | `seapp_contexts` line responsible |
|---|---|---|---|---|---|
| | | | | | |
| | | | | | |
| | | | | | |

Five rows minimum, and they must include at least one `untrusted_app`, one `priv_app` or `platform_app`, and one `system_app`.

Then run the tool and check every row:

```bash
# host
bash ../scripts/selinux-posture.sh <each package> --no-logcat
```

---

## Hints

<details>
<summary>Hint for Question 3</summary>

`cat /proc/1/attr/current` fails. Look for a denial:

```bash
adb logcat -d -b all | grep -a 'avc:' | tail -5
```

The class you are looking for is `file` on a `proc` type, or `process` with `getattr`. Reading another process's attributes is a MAC-controlled operation, which is *why* an app cannot enumerate other processes' domains.
</details>

<details>
<summary>Hint for Question 6</summary>

Look at the `seapp_contexts` line for `platform_app`. It says `levelFrom=user`, not `levelFrom=all`. Then ask: if two processes have identical contexts, can any *constraint* over levels distinguish them? Then ask what else is different about them — their UIDs, and the type on their data directories.
</details>

<details>
<summary>Hint for Question 9</summary>

The first category is `c(appid & 0xff)`. What is the largest value of `x & 0xff`?
</details>

<details>
<summary>Hint for Question 12</summary>

libselinux sorts the parsed rules by specificity. A rule with `isPrivApp=` **and** `name=` is more specific than one with only `isPrivApp=`. The `cat` output order is a red herring.
</details>

<details>
<summary>Hint for Question 14</summary>

`/data/data` is mode `0711` and the directory inside is `0700` owned by another UID — that is DAC. And `shell` has no `allow` rule for `app_data_file:dir` — that is MAC. **Both** would refuse it. The only way to tell which one fired *first* is that if DAC refuses, the LSM hook is never reached and **no `avc` record is produced at all**.
</details>

<details>
<summary>Hint for Question 17</summary>

The kernel's `capable()` function checks the capability bit and *then* calls an LSM hook. So a root process holding `CAP_SYS_MODULE` is still refused if policy has no `allow <domain> self:capability sys_module;`. That is the mechanism behind "MAC constrains even root" — and it is the one place where the two models meet on the same object.
</details>

---

## Success criteria

You have completed this lab when you can, without looking anything up:

1. Read any context aloud and say which two fields carry information and what each means.
2. Compute the MCS category set for any UID and Android user id, and explain the `>> 8` in the second and fourth categories.
3. State the invariant that the first category is `c0`–`c255` and the second is `c256`–`c511`, and explain why.
4. Look at a process's context and name the `seapp_contexts` line that produced it.
5. Explain why matching in `seapp_contexts` is by specificity rather than file order, and give an example from your own device where the difference matters.
6. Name three domains on your device that have **no** per-app MCS isolation, and say what separates their processes instead.
7. Explain, in one sentence each, why `getenforce` is not sufficient to establish that a device is fully enforcing, and what you would check instead.
8. Say why an experiment run from `adb shell` does not establish what an app can do, naming the specific differences.

## Recording your work

Keep the following, because Labs 02 to 05 build on them:

```bash
# host
mkdir -p lab-output && cd lab-output
adb shell 'ps -A -Z'                                   > processes.txt
adb shell 'pm list packages -U'                        > packages.txt
adb shell 'cat /system/etc/selinux/plat_seapp_contexts' > plat_seapp_contexts.txt
adb shell 'cat /vendor/etc/selinux/vendor_seapp_contexts' > vendor_seapp_contexts.txt
adb shell 'ls /sys/fs/selinux/class'                   > classes.txt
bash ../../scripts/selinux-posture.sh --no-logcat      > posture.txt
```

---

## Next

[Lab 02 — From a denial to the rule that would allow it](lab-02-denial-to-rule.md). That is the lab that teaches the single most practical skill in the chapter, and it is built on denials measured on a real device with the exact command that produced each one recorded.
