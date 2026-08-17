# 22 — SELinux Cheat Sheet

Printable. Tables and commands only. Everything marked **[M]** was measured on a physical arm64 device running Android 13 / API 33, stock `user` build, SELinux Enforcing, not rooted.

---

## 1. Context format

```
u  :  r  :  untrusted_app  :  s0 : c107,c256,c512,c768
|     |     |                 |    |
|     |     |                 |    +-- MCS categories (Android uses c0-c1023)
|     |     |                 +------- sensitivity (Android uses only s0)
|     |     +------------------------- TYPE. On a process this is the DOMAIN.
|     |                                 *** THE ONLY FIELD RULES ARE WRITTEN ABOUT ***
|     +------------------------------- role: "r" for processes, "object_r" for objects. Fixed.
+------------------------------------- SELinux user: always "u" on Android. No information.
```

| Field | Position | Process example | Object example | Carries information? |
|---|---|---|---|---|
| user | 1 | `u` | `u` | No — one user on Android |
| role | 2 | `r` | `object_r` | No — two fixed values |
| **type / domain** | 3 | `untrusted_app` | `app_data_file` | **Yes — everything** |
| level | 4 | `s0:c107,c256,c512,c768` | `s0` | Yes, for app isolation |

---

## 2. MCS category encoding

```
userid = uid / 100000
appid  = uid % 100000
    appid >= 90000  ->  appid -= 90000   (isolated process)
    appid >= 20000  ->  appid -= 20000   (SDK sandbox)
    appid >= 10000  ->  appid -= 10000   (ordinary app)
    else                appid unchanged  (system/native AID)
```

| `levelFrom=` | Level produced |
|---|---|
| (absent) | `s0` |
| `app` | `s0:c(appid & 0xff),c(256 + (appid >> 8))` |
| `user` | `s0:c(512 + (userid & 0xff)),c(768 + (userid >> 8))` |
| `all` | both pairs, app pair first |

| Category block | Encodes |
|---|---|
| `c0` – `c255` | low byte of appid |
| `c256` – `c511` | high byte of appid |
| `c512` – `c767` | low byte of Android user id |
| `c768` – `c1023` | high byte of Android user id |

**Invariant:** first category is always `c0`–`c255`; second is always `c256`–`c511`. A context with `c288` in the *first* slot is arithmetically impossible.

### Worked, measured **[M]**

| Package / process | uid | appid | Context |
|---|---|---|---|
| `com.android.chrome` | 10107 | 107 | `u:r:untrusted_app:s0:c107,c256,c512,c768` |
| `com.synergyenfmanager` | 10150 | 150 | `u:r:untrusted_app:s0:c150,c256,c512,c768` |
| `com.synergyenf` | 10156 | 156 | `u:r:untrusted_app:s0:c156,c256,c512,c768` |
| `com.android.traceur` | 10077 | 77 | `u:r:traceur_app:s0:c77,c256,c512,c768` |
| `secure_element` | 1068 | 1068 | `u:r:secure_element:s0:c44,c260,c512,c768` — 1068 = 4·256 + 44 |
| `com.google.android.gms` | 10096 | — | `u:r:gmscore_app:s0:c512,c768` — `levelFrom=user`, no app pair |
| `com.android.keychain` | 1000 | — | `u:r:system_app:s0` — no `levelFrom` at all |

---

## 3. Common domains

| Domain | Who runs in it | MCS scheme **[M]** |
|---|---|---|
| `untrusted_app` | third-party app, `targetSdk` ≥ 30 | `levelFrom=all` |
| `untrusted_app_29` | third-party app, `targetSdk` 29 | `levelFrom=all` |
| `untrusted_app_27` | third-party app, `targetSdk` 26–28 | `all` for 28, **`user` for 26–27** |
| `untrusted_app_25` | third-party app, `targetSdk` ≤ 25 | **`levelFrom=user`** + `execute_no_trans` + `execmod` |
| `priv_app` | app in a `priv-app/` directory | `levelFrom=user` |
| `platform_app` | app signed with the platform key, not privileged | `levelFrom=user` |
| `system_app` | app running as uid 1000 (`system`) | none — bare `s0` |
| `gmscore_app` | Google Play Services and friends | `levelFrom=user` |
| `ephemeral_app` | instant apps | `levelFrom=all` |
| `isolated_app` | `android:isolatedProcess="true"` | `levelFrom=user` |
| `sdk_sandbox` | Privacy Sandbox SDK Runtime | `levelFrom=all` |
| `runas_app` | a process created by `run-as` | `all` for `targetSdk` ≥ 28 |
| `shell` | `adb shell` — uid 2000 | none |
| `zygote` | `app_process32` / `app_process64` | none |
| `webview_zygote` | the WebView zygote | none |
| `app_zygote` | per-app zygote for isolated processes | none |
| `system_server` | the framework | none |
| `installd` | app data directory management | none |
| `dex2oat` | the AOT compiler | none |
| `vold` | volume/encryption daemon | none |
| `init` | pid 1 | none |
| `kernel` | kernel threads | none |
| `adbd` | the adb daemon | none |

### Attributes worth knowing **[M]**

| Attribute | Contains |
|---|---|
| `domain` | every process type |
| `appdomain` | `bluetooth ephemeral_app gmscore_app isolated_app mediaprovider network_stack nfc platform_app priv_app radio runas_app secure_element shared_relro **shell** simpleperf system_app traceur_app untrusted_app untrusted_app_29 untrusted_app_27 untrusted_app_25 mediaprovider_app permissioncontroller_app remote_prov_app sdk_sandbox vzwomatrigger_app` |
| `untrusted_app_all` | `runas_app simpleperf untrusted_app untrusted_app_29 untrusted_app_27 untrusted_app_25` — **note `shell` is NOT here** |
| `mlstrustedsubject` | exempt from **every** MLS constraint. Grep for it. |
| `coredomain` | everything on `/system` (Treble) |
| `binderservicedomain` | processes publishing Binder services |

---

## 4. Object classes and their key permissions

103 classes on the measured device (`ls /sys/fs/selinux/class | wc -l`). **[M]**

| Class | Object is | Permissions that matter |
|---|---|---|
| `file` | a file | `read write open getattr setattr execute execute_no_trans execmod entrypoint map ioctl unlink rename` |
| `dir` | a directory | **`search`** `read write add_name remove_name getattr rmdir` |
| `lnk_file` | a symlink | `read getattr` |
| `sock_file` | a socket node on disk | `write read getattr` |
| `fifo_file` | a named pipe | `read write` |
| `fd` | a passed descriptor | `use` |
| `process` | a process | `transition dyntransition setcurrent execmem execstack execheap ptrace signal sigkill getattr setsched share` |
| `capability` | a Linux capability | `dac_override dac_read_search sys_admin sys_module sys_ptrace setuid setgid net_raw net_admin chown fowner kill sys_boot` |
| `capability2` | capabilities 32+ | `mac_admin mac_override syslog wake_alarm block_suspend audit_read perfmon bpf checkpoint_restore` |
| `security` | the SELinux server | **`setenforce load_policy read_policy setbool`** `compute_av compute_create check_context` |
| `binder` | a Binder transaction | `call transfer impersonate set_context_mgr` |
| `service_manager` | a service NAME | `add find list` |
| `hwservice_manager` | a HIDL service name | `add find list` |
| `property_service` | a system property | `set` (there is no `get` — reading is `file:read`) |
| `keystore_key` | legacy key namespace | `get insert sign verify delete grant list gen_unique_id` |
| `keystore2_key` | Keystore 2.0 namespace | `use get_info delete rebind grant update manage_blob use_dev_id gen_unique_id req_forced_op convert_storage_key_to_ephemeral` |
| `keystore2` | the Keystore service | `add_auth clear_ns lock reset unlock change_password early_boot_ended report_off_body` |
| `unix_stream_socket` | AF_UNIX stream socket | **`connectto`** `create bind listen accept name_bind read write` |
| `unix_dgram_socket` | AF_UNIX datagram socket | `sendto create bind write` |
| `tcp_socket` / `udp_socket` | IP sockets | `name_bind node_bind name_connect create` |
| `anon_inode` | userfaultfd, memfd, eventfd | `create read write ioctl` |
| `bpf` | eBPF maps and programs | `map_create map_read map_write prog_load prog_run` |
| `filesystem` | a mounted filesystem | `mount unmount getattr remount associate quotamod` |
| `system` | whole-system ops | `syslog_read syslog_mod ipc_lock module_request` |

### Measured permission vectors **[M]**

```
file:              append audit_access create execmod execute execute_no_trans entrypoint
                   getattr ioctl link lock map mounton open quotaon read relabelfrom
                   relabelto rename setattr unlink watch watch_mount watch_reads
                   watch_sb watch_with_perm write

dir:               add_name append audit_access create execmod execute getattr ioctl link
                   lock map mounton open quotaon read relabelfrom relabelto remove_name
                   rename reparent rmdir search setattr unlink watch ... write

process:           dyntransition execheap execmem execstack fork getattr getcap getpgid
                   getrlimit getsched getsession noatsecure ptrace rlimitinh setcap
                   setcurrent setexec setfscreate setkeycreate setpgid setrlimit setsched
                   setsockcreate share sigchld siginh sigkill signal signull sigstop
                   transition

capability:        audit_control audit_write chown dac_override dac_read_search fowner
                   fsetid ipc_lock ipc_owner kill lease linux_immutable mknod net_admin
                   net_bind_service net_broadcast net_raw setfcap setgid setpcap setuid
                   sys_admin sys_boot sys_chroot sys_module sys_nice sys_pacct sys_ptrace
                   sys_rawio sys_resource sys_time sys_tty_config

service_manager:   add find list
binder:            call impersonate set_context_mgr transfer
property_service:  set
fd:                use

keystore2_key:     convert_storage_key_to_ephemeral delete gen_unique_id get_info grant
                   manage_blob rebind req_forced_op update use use_dev_id

keystore_key:      add_auth clear_uid delete duplicate exist gen_unique_id get get_state
                   grant insert is_empty list lock password reset sign unlock user_changed
                   verify

unix_stream_socket: accept append bind connect connectto create getattr getopt ioctl listen
                    lock map name_bind read recvfrom relabelfrom relabelto sendto setattr
                    setopt shutdown write
```

---

## 5. `avc` field decoder

```
avc: denied  { read }  for  comm="cat" name="kptr_restrict" dev="proc" ino=1872582
             scontext=u:r:shell:s0
             tcontext=u:object_r:proc_security:s0
             tclass=file  permissive=0
```

| Field | Meaning | Goes into the rule? |
|---|---|---|
| `avc: denied` / `avc: granted` | verdict. `granted` = an `auditallow` on a **successful** operation | no |
| `{ ... }` | **the permission set** | **yes** — the `{ }` |
| `for` | separator, no meaning | no |
| `comm=` | process name, 15 chars max, **hex-encoded if it contains whitespace** | no |
| `pid=` | process id | no |
| `uid=` | the DAC identity — orthogonal to `scontext` | no |
| `name=` | object basename, or a **service name** for `service_manager`, or a **property name** wrapper | no |
| `path=` | full path, when the kernel has one | no |
| `dev=` | filesystem: `proc`, `tmpfs`, `dm-4`, `mmcblk0p7` | no |
| `ino=` | inode number | no |
| `ioctlcmd=` | the ioctl command number — needs `allowxperm` too | separately |
| `capability=` | capability number, for `tclass=capability` | no |
| `scontext=` | **the SUBJECT.** Field 3 is the source type. | **yes** — left side |
| `tcontext=` | **the TARGET.** Field 3 is the target type. | **yes** — middle |
| `tclass=` | **the object class** | **yes** — after the colon |
| `permissive=` | `0` = operation FAILED. **`1` = operation SUCCEEDED.** | no |
| `app=` | logd's annotation, not an audit field | no |

### Record types

| `type=` | Name | Meaning |
|---|---|---|
| `1400` | `AVC` | an ordinary SELinux denial |
| `1107` | `USER_AVC` | init-wrapped — **the real `scontext` is inside the quoted `msg='...'`** |
| `1326` | `SECCOMP` | **not SELinux.** A seccomp-bpf kill or trap. Chapter 21. |
| `1327` | `PROCTITLE` | the full command line, hex-encoded |

### The derivation

```
allow  <scontext field 3>  <tcontext field 3> : <tclass>  <{ } set> ;
```

```
avc: denied { read } ... scontext=u:r:shell:s0 tcontext=u:object_r:proc_security:s0 tclass=file
    ->  allow shell proc_security:file read;
    ->  (allow shell proc_security (file (read)))
```

`tcontext == scontext` and class in {`process`, `capability`, `capability2`} → write `self`:

```
avc: denied { sys_module } ... scontext=u:r:shell:s0 tcontext=u:r:shell:s0 tclass=capability
    ->  allow shell self:capability sys_module;
```

`ioctlcmd=` present → **two** rules:

```
allow system_server system_file:file ioctl;
allowxperm system_server system_file:file ioctl { 0x6686 };
```

### Worked, measured **[M]**

| Command run | Denial | Derived rule |
|---|---|---|
| `cat /proc/sys/kernel/kptr_restrict` | `{ read } ... proc_security ... file` | `allow shell proc_security:file read;` |
| `ls -l /data/misc/keystore` | `{ getattr } ... keystore_data_file ... dir` | `allow shell keystore_data_file:dir getattr;` |
| `cat /sys/fs/selinux/policy` | `{ read_policy } ... kernel ... security` | `allow shell kernel:security read_policy;` |
| `ls -l /system/etc/selinux/` | `{ getattr } ... mac_perms_file ... file` | `allow shell mac_perms_file:file getattr;` |

---

## 6. The command set

### Identity and state

```bash
id                                   # uid AND context on one line
id -Z                                # context only
cat /proc/self/attr/current          # the kernel's own answer; works everywhere
cat /proc/<pid>/attr/current         # another process, needs process:getattr

getenforce                           # Enforcing | Permissive | Disabled  [GLOBAL only]
cat /sys/fs/selinux/enforce          # 1 | 0
cat /sys/fs/selinux/policyvers       # 31  [M]
cat /sys/fs/selinux/mls              # 1 = MLS/MCS compiled in  [M]
cat /sys/fs/selinux/deny_unknown     # 1 = deny unknown classes  [M]
cat /sys/fs/selinux/checkreqprot     # 0 = check applied prot, correct  [M]
ls /sys/fs/selinux/class             # 103 classes  [M]
ls /sys/fs/selinux/class/<c>/perms   # that class's permission names
cat /sys/fs/selinux/avc/cache_stats  # AVC hit/miss statistics

setenforce 0                         # needs security:setenforce. VOIDS EVERY MEASUREMENT.
setenforce 1
```

### Labels

```bash
ps -A -Z                             # every process with its context
ps -A -Z | grep -E '_app|zygote'     # app domains only
ps -A -Z | awk 'NR>1 {split($1,a,":"); print a[3]}' | sort | uniq -c | sort -rn

ls -Z <path>                         # file labels
ls -ldZ <dir>                        # directory label, not its contents
ls -Zd /system/bin/app_process64     # u:object_r:zygote_exec:s0  [M]
ls -Zd /data/local/tmp               # u:object_r:shell_data_file:s0  [M]

getprop -Z <property>                # a property's label
getprop -Z ro.build.version.sdk      # u:object_r:build_prop:s0  [M]

dumpsys -l                           # service names, to cross-reference service_contexts
cat /proc/net/unix | grep '@'        # abstract-namespace sockets (@ = a leading NUL)
```

### Denials

```bash
# with root
dmesg | grep -i 'avc:'
dmesg -w | grep -i 'avc:'

# without root  -- note -a and -b all, both required
adb logcat -d -b all | grep -a 'avc:'
adb logcat    -b all | grep -a 'avc:'

# clean correlation
adb logcat -c ; <do exactly one thing> ; adb logcat -d -b all | grep -a 'avc:'

# permissive domains -- the highest-value grep on a production device
adb logcat -d -b all | grep -a 'permissive=1'

# NEVER grep for "denied" alone -- it misses every avc: granted record
```

### This chapter's tools

```bash
python3 scripts/avc-decode.py <file>                       # full decode
python3 scripts/avc-decode.py - --group                    # collapse repeats
python3 scripts/avc-decode.py - --rules-only               # paste-ready rules
python3 scripts/avc-decode.py - --json                     # machine readable
python3 scripts/avc-decode.py - --scontext untrusted_app   # filter by subject type
python3 scripts/avc-decode.py - --tclass keystore2_key     # filter by class
python3 scripts/avc-decode.py - --quiet-noise              # drop known-benign shapes
adb logcat -d -b all | python3 scripts/avc-decode.py - --group

bash scripts/selinux-posture.sh                            # device posture
bash scripts/selinux-posture.sh com.target.app             # plus one package
bash scripts/selinux-posture.sh --no-logcat com.target.app

frida -U -f com.target.app -l scripts/selinux-probe.js
```

### Policy files on the device

```bash
adb shell ls -l /system/etc/selinux/
adb shell ls -l /system_ext/etc/selinux/
adb shell ls -l /vendor/etc/selinux/

adb pull /system/etc/selinux/plat_sepolicy.cil
adb pull /system/etc/selinux/plat_seapp_contexts
adb pull /system/etc/selinux/plat_file_contexts
adb pull /system/etc/selinux/plat_property_contexts
adb pull /system/etc/selinux/plat_service_contexts
adb pull /system/etc/selinux/plat_keystore2_key_contexts
adb pull /vendor/etc/selinux/vendor_sepolicy.cil
adb pull /vendor/etc/selinux/vendor_seapp_contexts
adb pull /vendor/etc/selinux/vendor_service_contexts
adb pull /vendor/etc/selinux/vendor_property_contexts
```

Measured sizes on the test device **[M]**:

| File | Bytes |
|---|---|
| `plat_sepolicy.cil` | 1,981,460 |
| `vendor_sepolicy.cil` | 1,072,684 |
| `plat_pub_versioned.cil` | 930,005 |
| `system_ext_sepolicy.cil` | 328,536 |
| `precompiled_sepolicy` | 1,047,781 |
| `plat_property_contexts` | 85,457 |
| `vendor_file_contexts` | 87,774 |
| `plat_file_contexts` | 50,261 |
| `plat_service_contexts` | 31,346 |
| `plat_seapp_contexts` | 3,078 |
| `vendor_seapp_contexts` | 459 |
| `plat_keystore2_key_contexts` | 1,152 |

### Policy analysis, off device

```bash
# needs the binary policy: root, or secilc on the CIL, or an OTA image
adb shell "su -c 'cat /sys/fs/selinux/policy'" > policy.bin   # outer quotes required

sepolicy-analyze policy.bin permissive          # permissive domains
sepolicy-analyze policy.bin dups                # duplicate types
sepolicy-analyze policy.bin attribute appdomain
sepolicy-analyze policy.bin attribute mlstrustedsubject

sesearch --allow -s untrusted_app -t app_data_file policy.bin
sesearch --allow -s untrusted_app -c keystore2_key policy.bin
sesearch --neverallow -s dex2oat policy.bin
sesearch --dontaudit -s untrusted_app policy.bin   # what is being SILENCED

audit2allow -i denials.txt
audit2why   -i denials.txt -p policy.bin           # distinguishes rule vs constraint
```

---

## 7. The finding-shaped greps

Run every one of these against `vendor_sepolicy.cil` first. That is the third of the policy nobody outside the OEM has reviewed.

```bash
# exempt from every MLS constraint -- reads every app's data
grep -n 'typeattributeset mlstrustedsubject' vendor_sepolicy.cil plat_sepolicy.cil

# dangerous capabilities
grep -nE '\(allow [a-z_0-9]+ self \(capability \(.*(dac_override|dac_read_search|sys_admin|sys_module|setuid|net_raw)' vendor_sepolicy.cil

# who can end the game
grep -nE '\(allow [a-z_0-9]+ kernel \(security \(.*(setenforce|load_policy|setbool)' vendor_sepolicy.cil

# app domains reaching things they should not
grep -nE '\(allow (appdomain|untrusted_app[a-z0-9_]*) ' vendor_sepolicy.cil

# abstract sockets -- no DAC at all
grep -nE 'unix_stream_socket \(.*connectto' vendor_sepolicy.cil
grep -nE 'unix_dgram_socket \(.*sendto'     vendor_sepolicy.cil

# default-label over-grants
grep -nE 'allow .* (default_android_service|default_prop|vendor_default_prop|unlabeled) ' vendor_sepolicy.cil

# Keystore
grep -nE 'keystore2_key \(.*(manage_blob|use_dev_id|gen_unique_id)' vendor_sepolicy.cil plat_sepolicy.cil

# app data reached directly rather than by fd passing
grep -nE '\(allow [a-z_0-9]+ (app_data_file|privapp_data_file) ' vendor_sepolicy.cil

# code execution
grep -nE 'process \(.*execmem'                 vendor_sepolicy.cil
grep -nE 'file \(.*(execute_no_trans|execmod)' vendor_sepolicy.cil

# can any third-party app claim a vendor domain by package name alone?
grep 'name=' vendor_seapp_contexts | grep -v 'seinfo=' | grep -v 'isPrivApp='

# which app domains have NO per-app MCS isolation?
grep 'levelFrom=user' plat_seapp_contexts vendor_seapp_contexts
grep -v 'levelFrom='  plat_seapp_contexts | grep '^user='
```

---

## 8. `seapp_contexts` quick reference

**Matching is by SPECIFICITY, not file order.** Predict, then measure with `ps -A -Z`.

### Input keys

| Key | Meaning | App-controllable? |
|---|---|---|
| `isSystemServer=` | the `system_server` fork | no |
| `user=` | `_app` \| `_isolated` \| `_sdksandbox` \| a named AID | no |
| `seinfo=` | from `mac_permissions.xml`, keyed on the **signing certificate** | **no** |
| `name=` | package name, `*` wildcard suffix | partly |
| `isPrivApp=` | in a `priv-app/` directory | no |
| `isEphemeralApp=` | instant app | no |
| `minTargetSdkVersion=` | `targetSdkVersion` at least this | **yes** |
| `fromRunAs=` | created by `run-as` | debuggable builds only |

### Output keys

| Key | Assigns |
|---|---|
| `domain=` | the process type |
| `type=` | the data-directory file type |
| `levelFrom=` | `none` \| `app` \| `user` \| `all` |
| `level=` | a fixed level string |

### The ladder that decides most apps **[M]**

```
user=_app minTargetSdkVersion=30 domain=untrusted_app    type=app_data_file levelFrom=all
user=_app minTargetSdkVersion=29 domain=untrusted_app_29 type=app_data_file levelFrom=all
user=_app minTargetSdkVersion=28 domain=untrusted_app_27 type=app_data_file levelFrom=all
user=_app minTargetSdkVersion=26 domain=untrusted_app_27 type=app_data_file levelFrom=user
user=_app                        domain=untrusted_app_25 type=app_data_file levelFrom=user
```

An app matches the **highest** `minTargetSdkVersion` that is ≤ its own `targetSdkVersion`.

---

## 9. Rule types

| Rule | Acts at | Grants? | Notes |
|---|---|---|---|
| `allow` | runtime | **yes** | the only rule that grants |
| `neverallow` | **compile time + CTS** | no | **the kernel never reads it.** A patched policy is bound by nothing. |
| `dontaudit` | runtime | no | suppresses the audit **record** only. The denial still happens. |
| `auditallow` | runtime | no | emits `avc: granted` on a permitted operation |
| `allowxperm` | runtime | yes | extended permissions, currently `ioctl` command numbers |
| `type_transition` | runtime | n/a | new label on `execve` or on file creation |
| `mlsconstrain` | runtime | no | **a predicate that must ALSO be true.** This is what enforces MCS. |

### The MLS constraints that enforce app isolation **[M]**

```lisp
(mlsconstrain (file (read getattr execute))
  (or (or (or (or (eq t2 app_data_file_type) (eq t2 appdomain_tmpfs))
              (dom l1 l2)) (eq t1 mlstrustedsubject)) (eq t2 mlstrustedobject)))

(mlsconstrain (dir (getattr setattr rename open add_name remove_name reparent search rmdir))
  (or (or (neq t2 app_data_file_type) (dom l1 l2)) (eq t1 mlstrustedsubject)))

(mlsconstrain (process (transition dyntransition))
  (or (and (eq h1 h2) (eq l1 l2)) (eq t1 mlstrustedsubject)))
```

`dom l1 l2` = the subject's categories **contain** the object's. Reads use `dom`; writes use `eq` (exact equality) — the classic "no write down".

---

## 10. Enforcement states

| | `getenforce` | `/sys/fs/selinux/enforce` | `permissive=` on records | Operation result |
|---|---|---|---|---|
| Enforcing | `Enforcing` | `1` | `0` | **FAILS** |
| Globally permissive | `Permissive` | `0` | `1` | **SUCCEEDS** |
| Per-domain permissive | `Enforcing` | `1` | `1` for that domain | **SUCCEEDS** |

**`permissive=1` means the operation succeeded.** Reading it as "blocked" is exactly backwards.

---

## 11. Severity — is this denial a finding?

| Condition | Finding? |
|---|---|
| A denial exists in `dmesg` | **No.** A measured healthy Android 13 device produced **6,101** in one uptime, all benign. |
| Thousands of denials | **No.** 5,993 records collapsed to 33 distinct rules; 4,885 were one shape (GMS probing a Perfetto socket). |
| No denials at all | **No, and it proves nothing.** `dontaudit` and DAC both produce silence. |
| `permissive=1` on any record | **Yes.** That operation succeeded despite policy. |
| A domain marked `permissive` on a `user` build | **Yes.** Fails CTS and Play Integrity too. |
| A denial naming `setenforce`, `load_policy`, `sys_module`, `manage_blob`, `use_dev_id` | **Worth investigating** — something is *trying* it. |
| A denial you can causally link to a security action you performed | **Useful** — it names the mechanism that blocked you. |
| Denial volume or pattern changed after installing an app | **Useful** — behavioural evidence. |
| A vendor domain with `mlstrustedsubject` or `dac_override` | **Yes.** Impact amplifier: converts a moderate bug into total data disclosure. |
| `connectto` granted from `appdomain` to a privileged daemon | **Yes.** Abstract sockets have no DAC at all. |
| Vendor `seapp_contexts` matching `name=` with no `seinfo=` | **Yes.** Any app can claim that domain. |

---

## 12. Traps

| Trap | Consequence |
|---|---|
| `grep` without `-a` on logcat | "Binary file matches", zero output, looks like "no denials" |
| `logcat` without `-b all` | denials in `events`/`kernel` are invisible |
| grepping for `denied` not `avc:` | misses every `avc: granted` |
| testing from `adb shell` | `shell` is in `appdomain` but **not** `untrusted_app_all`; uid 2000; no seccomp |
| testing under `run-as` | that is `runas_app`, a **different domain** |
| measuring after `setenforce 0` | every measurement void; every `permissive=1` is a success |
| `type=1326` | that is **seccomp**, not SELinux |
| the outer `subj=` on a `type=1107` record | that is `init`, the reporter — the offender is the inner `scontext=` |
| hex `comm=` | not corruption; audit hex-encodes values containing whitespace |
| a first category above `c255` | arithmetically impossible; the context is fabricated |
| `neverallow` treated as runtime | it is compile-time only |
| absence of a denial read as success | one of three explanations, and the least likely |
| pasting `audit2allow` output | grants everything of that **type**, not just the object in the record |
| `UID=` in a bash script | `UID` is readonly in bash; the assignment fails silently |
| `adb shell cat /path` from Git Bash | MSYS rewrites the path into a Windows path; returns nothing, exit 0 |
