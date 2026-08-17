# Example 02 — A raw vantage session, annotated

The unedited transcript behind the vantage table in [`../README.md`](../README.md) §5.2, with a note
on every line that surprised somebody.

**Device:** `sdk_gphone16k_x86_64` (`emu64xa16k`), `emulator-5554`, Android 15 / API 35, x86_64,
`userdebug`, SELinux `Enforcing`, rooted with **Magisk 30.7**.
**App vantage:** `com.devuser.helloworld`, flags `[ DEBUGGABLE HAS_CODE ALLOW_CLEAR_USER_DATA TEST_ONLY ALLOW_BACKUP ]`, uid **10207**.
**Date:** 2026-08-16.

Every block below was executed. Nothing is reconstructed.

---

## 0. Establish the device before anything else

```
$ adb devices -l
List of devices attached
emulator-5554   device product:sdk_gphone16k_x86_64 model:sdk_gphone16k_x86_64 device:emu64xa16k transport_id:2

$ adb shell getprop ro.build.fingerprint
google/sdk_gphone16k_x86_64/emu64xa16k:15/AE3A.240806.043/12960925:userdebug/dev-keys

$ adb shell getprop ro.build.version.sdk
35

$ adb shell getprop ro.build.type
userdebug

$ adb shell getenforce
Enforcing
```

> Two facts to carry forward. This is a `userdebug` build, so **refusals** measured here are solid —
> a permissive build cannot manufacture a refusal — while **successes** that might depend on
> permissiveness are upper bounds. And the fingerprint does **not** begin with `generic`, which
> already kills the most-copied `isEmulator()` implementation on the internet.

---

## 1. Which `su` form does this device take?

<!-- lint:allow -- transcript of the failing form, quoted on purpose -->
```
$ adb shell 'su -c id'
su: invalid uid/gid '-c'

$ echo $?
1

$ adb shell 'su 0 id'
uid=0(root) gid=0(root) groups=0(root),1004(input),1007(log),1011(adb),1015(sdcard_rw),1028(sdcard_r),
1078(ext_data_rw),1079(ext_obb_rw),3001(net_bt_admin),3002(net_bt),3003(inet),3006(net_bw_stats),
3009(readproc),3011(uhid),3012(readtracefs) context=u:r:su:s0
```

> `su -c` does not merely fail here; it fails **in the shape of "not rooted"**. A tester who runs
> only the first command records an unrooted device, and every subsequent measurement is taken with
> a wrong premise. This is the third time this repository has hit it, which is why it is now a
> session-start check rather than a footnote.
>
> Note also `context=u:r:su:s0` — the SELinux domain, which is what actually determines what root
> can read. Root defeats DAC; SELinux still applies.

---

## 2. The app vantage

```
$ adb shell "run-as com.devuser.helloworld id"
uid=10207(u0_a207) gid=10207(u0_a207) groups=10207(u0_a207),1004(input),1007(log),1011(adb),
1015(sdcard_rw),1028(sdcard_r),1078(ext_data_rw),1079(ext_obb_rw),3001(net_bt_admin),3002(net_bt),
3003(inet),3006(net_bw_stats),3009(readproc),3011(uhid),3012(readtracefs),50207(all_a207)
context=u:r:runas_app:s0:c207,c256,c512,c768
```

> Read the MCS label. `c207,c256` is the appId pair — `c[appId & 0xff]` and `c[256 + (appId >> 8)]`,
> which for appId 207 gives exactly `c207,c256`. `c512,c768` encode the **user id** (API 31+ form).
> An app's label carries **four** categories, not two.
>
> The invariant is also a diagnostic: the *first* category can never exceed `c255`, so a context
> whose first category is higher was fabricated rather than captured.
>
> One honest limit: the domain is `runas_app`, not `untrusted_app`. `run-as` is the closest cheap
> approximation to an app vantage, not an identical one. Where the difference could matter, build a
> probe APK.

---

## 3. The classic root check, from three heights

```
$ adb shell 'ls -l /system/xbin/su'
-rwsr-x--- 1 root shell 51224 2025-01-23 23:03 /system/xbin/su

$ adb shell "su 0 ls -l /system/xbin/su"
-rwsr-x--- 1 root shell 51224 2025-01-23 23:03 /system/xbin/su

$ adb shell "run-as com.devuser.helloworld ls -l /system/xbin/su"
ls: /system/xbin/su: Permission denied

$ adb shell "run-as com.devuser.helloworld sh -c 'test -e /system/xbin/su && echo EXISTS || echo NO'"
NO
```

> The file is `4750 root:shell` inside a directory that is `0750 root:shell`. `adb shell` is in the
> `shell` group. An app is not.
>
> The fourth command is the one that matters, because it is what `File.exists()` compiles down to.
> On a device that is **unambiguously rooted**, the most-copied root check in Android security
> returns `false`.
>
> And note which binary this is: `/system/xbin/su` on a `userdebug` AVD is **AOSP's own `su`**,
> included in the build by design. It is not what grants root here. Magisk is:

```
$ adb shell 'ls -l /system/bin/su /debug_ramdisk/su /debug_ramdisk/magisk'
ls: /system/bin/su: No such file or directory
lrwxrwxrwx 1 root root      8 2026-08-16 00:25 /debug_ramdisk/su -> ./magisk
-rwxr-xr-x 1 root root 428416 2026-08-16 00:25 /debug_ramdisk/magisk

$ adb shell "su 0 /debug_ramdisk/magisk -v"
30.7:MAGISK:R
```

> So a probe that checks `/system/xbin/su` fires from the shell **on a harmless binary** and misses
> the thing that actually grants root, from the vantage that actually matters. Both errors at once.

---

## 4. The signal that does work

```
$ adb shell 'grep -c magisk /proc/self/mountinfo'
3

$ adb shell "run-as com.devuser.helloworld grep -c magisk /proc/self/mountinfo"
3

$ adb shell "su 0 grep -c magisk /proc/self/mountinfo"
3
```

> Three identical answers. That is not a boring result — **it is what makes this a usable check.**
> A signal that needs no privilege is readable by the app that wants to make the decision.
>
> Be precise about what it proves: three mount entries whose source is literally `magisk` prove the
> *substrate*. They do not prove that any particular module, or LSPosed, is installed. A detector
> that answers the first while claiming the second is wrong.

---

## 5. The property census

```
$ adb shell "su 0 getprop" | wc -l
1062
$ adb shell 'getprop' | wc -l
678
$ adb shell "run-as com.devuser.helloworld getprop" | wc -l
638

$ adb shell "su 0 getprop" | grep -c 'ro.boottime'
111
$ adb shell 'getprop' | grep -c 'ro.boottime'
0
$ adb shell "run-as com.devuser.helloworld getprop" | grep -c 'ro.boottime'
0
```

> **These reproduce, to the property, figures another chapter had to publish a correction for.** Its
> first published numbers were `shell = 1,053` against `app = 634`, and a third chapter failed to
> reproduce them and correctly filed the divergence rather than editing someone else's work. The
> cause was that the "shell" figure had been taken through `su`. Two domains cannot see the same set
> when one of them is subject to `boottime_prop`.
>
> What the corrected numbers actually say is more useful than the dramatic version: **the shell is a
> decent proxy for an app (678 vs 638) and a terrible proxy for root (678 vs 1,062).** The error to
> guard against is not "I tested from the shell" but "I tested from root and called it shell".
>
> The `ro.boottime.*` family is the clean case: 111 properties visible to root and **zero** to
> either of the other two, because they carry the SELinux type `boottime_prop`. `getprop -Z` shows
> the types.

---

## 6. One emulator signal that still works

```
$ adb shell 'getprop ro.kernel.qemu'
1
$ adb shell "run-as com.devuser.helloworld getprop ro.kernel.qemu"
1
$ adb shell "su 0 getprop ro.kernel.qemu"
1
```

> Visible from all three vantages on this AVD. Worth recording precisely because so many neighbouring
> heuristics are dead or inverted: `/dev/qemu_pipe` is `ENOENT` (the node is now
> `/dev/goldfish_pipe_dprctd`), the fingerprint contains no `generic`, and a retail phone this
> repository has used sets `qemu.hw.mainkeys` while the AVD does not — a heuristic that calls the
> phone an emulator and the emulator a phone.
>
> One signal working does not rehabilitate the family. Report the one you measured.

---

## 7. The bind mount, since everyone gets this wrong

```
$ adb shell "su 0 ls -di /data/data /data/user/0"
344065 /data/data
344065 /data/user/0

$ adb shell "su 0 readlink /data/user/0"
$ echo $?
1
```

> Same inode; `readlink` returns nothing and exits 1. It is a **bind mount**, not a symlink. This
> matters to anyone reasoning about path canonicalisation or traversal — a canonicaliser will not
> collapse one path into the other, because there is no link to follow.

---

## 8. The one that surprised everybody

```
$ adb shell 'ps -A' | grep -i frida
$ echo $?
1

$ adb shell 'su 0 ps -A' | grep -i frida
$ echo $?
1

$ frida-ps -U
  PID  Name
-----  ------------------------------------------------------
24598  Chrome
26550  Drive
24667  Files
 2728  Google
 ...
 1885  zygote64
```

No `frida-server` process exists — checked as `shell` *and* as root — and `frida-ps -U` returns a
full, correct process list anyway.

```
$ frida -U -n zygote64 -e 'console.log("HOOKED")' -q
Failed to attach: unable to connect to remote frida-server: closed
$ echo $?
1
```

```
$ adb shell "su 0 /data/local/tmp/frida-server --version"
WARNING: linker: "/data/local/tmp/frida-server" unused DT entry: unknown (type 0xa0000a3 arg 0x0) (ignoring)
[... several more linker warnings ...]
CANNOT LINK EXECUTABLE "/data/local/tmp/frida-server": empty/missing DT_HASH/DT_GNU_HASH in
"/data/local/tmp/frida-server" (new hash type from the future?)

$ adb shell "su 0 sh -c '/data/local/tmp/frida-server --version >/dev/null 2>&1; echo devrc=$?'"
devrc=1
```

> `frida-ps -U` enumerates processes through Frida's Android backend, **over adb**, with no agent and
> no server. A successful `frida-ps` proves your adb connection works and says nothing whatsoever
> about whether you can instrument anything.
>
> This is the single most misleading "it's working" signal in the Android tooling stack, because it
> is the first command everybody runs and it produces a long, detailed, entirely genuine result.
> **The test for instrumentation is an attach.**
>
> There is a second lesson in the last block: the failing frida invocation exited 1, but the first
> time it was run through `| head` the pipeline reported 0. Exit status is not a reliable channel
> here either.

---

## Reproducing this session

```bash
# host — from 76-CheatSheets/
bash scripts/vantage.sh --posture --pkg <your-debuggable-package>
bash scripts/vantage.sh --file /system/xbin/su --pkg <your-debuggable-package>
bash scripts/vantage.sh --cmd 'getprop | wc -l' --pkg <your-debuggable-package>
bash scripts/vantage.sh --cmd 'grep -c magisk /proc/self/mountinfo' --pkg <your-debuggable-package>
```

The script auto-detects which `su` form the device takes, so it works unchanged on a Magisk phone and
on an AOSP `userdebug` build. Without `--pkg` the app column prints `no --pkg` rather than silently
reporting the shell's answer — which is the entire point of the tool.

---

## See also

- [`01-anatomy-of-a-sheet-row.md`](01-anatomy-of-a-sheet-row.md) — turning these numbers into rows
- [`../README.md`](../README.md) §5.2 — the summarised table
- [`../scripts/vantage.sh`](../scripts/vantage.sh) — the tool
- [`../../21-App-Sandbox/README.md`](../../21-App-Sandbox/README.md) — where the MCS categories come from
- [`../../60-ADB/README.md`](../../60-ADB/README.md) — why `adb shell` is not an app
