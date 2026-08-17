# Lab 02 — Write a Magisk Module

**Difficulty:** Intermediate
**Time:** 3–4 hours, including three reboots you cannot avoid
**Prerequisites:** [Lab 01](lab-01-root-a-device.md) or an already-rooted device,
[Chapter 62 §3.5](../README.md#35-boot-stages-and-when-your-code-runs),
[§3.6](../README.md#36-module-structure), [§3.7](../README.md#37-resetprop-and-system-properties),
[02-Linux-Basics](../../02-Linux-Basics/README.md) for bind mounts

---

## Objective

Build two modules from an empty directory — a `system/` overlay module that installs a CA
certificate into the system trust store, and a scripts-only module that prepares a device for
testing — and **prove each one works at the level that matters**, not at the level that is easy to
check.

"The file is there" is the easy check. "An application that did not exist when the module was
installed trusts the certificate" is the check that matters, and the gap between the two is where
this lab lives.

## Why this matters

A Magisk module is the smallest complete example of Magisk's central trick. You will write one, and
in doing so you will exercise every mechanism in §3 of the chapter: the bind-mount overlay, the boot
stage table, `resetprop`, `magiskpolicy`, and the `/data/adb/modules` layout. Nothing explains the
overlay like watching `mount | grep magisk` grow by exactly one line because of a file you created.

There is also a practical reason. The system-CA module is the single most-used module in mobile
security work, because on Android 7 and later an app that does not opt in **ignores user-installed
CA certificates entirely** — so a proxy CA in the user store intercepts nothing from a normal app.
Getting the CA into the system store is the standard answer, and it is a Magisk module.

And a professional reason: you are going to be handed modules by other people. Writing two of them
is how you learn to read a third one critically, which is lab 04.

> **⚠️ Warning**
> Everything in this lab runs as root at boot, before any security software exists. A typo in
> `post-fs-data.sh` can bootloop the device. Part 4 makes you cause that failure deliberately, in a
> controlled way, so that the first time you meet it is not on the morning of an engagement. Do the
> recovery drills from [Lab 01 Step 9](lab-01-root-a-device.md#step-9--recovery-drills-do-these-while-nothing-is-wrong)
> before you start.

---

## Setup

```bash
# host — you need a rooted device and these tools
adb shell "su -c 'magisk -v'"    # confirms Magisk is alive; the OUTER quotes matter
adb shell getprop ro.build.version.sdk
which zip openssl                # host-side packaging and certificate handling
```

Record the Android version. It decides whether the CA module in Part 2 can work at all:

| API level | Android | System trust store lives at | A `system/etc/security/cacerts` overlay module |
|---|---|---|---|
| ≤ 33 | up to 13 | `/system/etc/security/cacerts/` | Works |
| ≥ 34 | 14 and later | `/apex/com.android.conscrypt/cacerts/` (managed by the Conscrypt APEX) | **Does not work as written.** Part 2 has you prove this rather than assume it |

```bash
# adb shell — measure it, do not assume
ls -d /apex/com.android.conscrypt/cacerts 2>/dev/null && echo "APEX trust store present"
ls /system/etc/security/cacerts/ | wc -l
```

Reference copies of both finished modules are in this chapter's
[`examples/`](../examples/) directory —
[`examples/system-ca-module/`](../examples/system-ca-module/) and
[`examples/pentest-prep-module/`](../examples/pentest-prep-module/). **Do not copy them yet.** Build
yours first; compare afterwards. The comparison is more useful than the copy.

---

## Part 1 — The smallest module that can possibly exist

Before anything complicated, prove the pipeline: that you can create a directory, package it,
install it, reboot, and see it. If this does not work, nothing later will, and you want to discover
that with three lines of content rather than three hundred.

```bash
# host
mkdir -p hello/
cat > hello/module.prop <<'EOF'
id=hellolab
name=Hello Lab
version=v1.0
versionCode=1
author=you
description=Does nothing. Proves the install pipeline works.
EOF
cd hello && zip -r ../hello.zip . -x '.*' && cd ..
unzip -l hello.zip          # module.prop MUST be at the archive root, not under hello/
```

> **⚠️ Warning — the packaging mistake everyone makes once**
> `zip -r hello.zip hello/` produces an archive whose entries are `hello/module.prop`. Magisk looks
> for `module.prop` at the **root** of the ZIP and will reject it. Always `cd` into the directory
> and zip `.` — and always check with `unzip -l` before you push. On macOS also exclude the resource
> forks: `zip -r ../m.zip . -x '.*' -x '__MACOSX/*'`.

```bash
# host
adb push hello.zip /sdcard/Download/
# Magisk app > Modules > Install from storage > hello.zip > Reboot
```

After the reboot:

```bash
# adb shell as root
ls -la /data/adb/modules/hellolab/
cat /data/adb/modules/hellolab/module.prop
```

**Q1.** Look at the directory Magisk created. What is in it that was not in your ZIP? What does the
presence of those files tell you about how Magisk tracks module state?

**Q2.** Package the same module again with `versionCode=2` and install it without rebooting. Where
does it land, and why is that directory called `modules_update` rather than `modules`?

```bash
# adb shell as root — answer Q2 by measurement
ls -la /data/adb/modules_update/ 2>/dev/null
```

---

## Part 2 — The system CA module

### Step 1 — Produce the certificate with the right filename

Android's system trust store does not scan files; it looks them up by the **old-style subject hash**
of the certificate, with a `.0` suffix. A correctly-formatted PEM under the wrong filename is
invisible to the runtime, and this is the most common reason a hand-built CA module "does nothing".

```bash
# host — export your proxy's CA. Burp: Proxy > Settings > Import/Export CA certificate > DER.
# mitmproxy writes ~/.mitmproxy/mitmproxy-ca-cert.pem already in PEM form.
openssl x509 -inform DER -in cacert.der -out proxy-ca.pem -outform PEM

# The lookup name:
HASH=$(openssl x509 -inform PEM -subject_hash_old -in proxy-ca.pem | head -1)
echo "trust store filename: ${HASH}.0"

# Sanity: it really is a CA, and it really is self-signed
openssl x509 -in proxy-ca.pem -noout -subject -issuer -dates
openssl x509 -in proxy-ca.pem -noout -text | grep -A1 'X509v3 Basic Constraints'
```

**Q3.** Why `-subject_hash_old` and not `-subject_hash`? What changed in OpenSSL 1.0 that made the
distinction necessary, and what happens if you use the wrong one?

### Step 2 — Build the tree

```bash
# host
mkdir -p systemca/system/etc/security/cacerts
cp proxy-ca.pem "systemca/system/etc/security/cacerts/${HASH}.0"

cat > systemca/module.prop <<'EOF'
id=systemca
name=Pentest System CA
version=v1.0
versionCode=1
author=you
description=Adds an interception CA to the system trust store, systemlessly. Testing devices only.
EOF

cat > systemca/customize.sh <<'EOF'
#!/system/bin/sh
# customize.sh — runs inside the Magisk installer at install time, as root.
# Its job here is ownership and mode. Magisk sets SELinux labels itself when it
# mounts the overlay, but it does not guess at your intended permissions.
ui_print "- Installing pentest system CA"
set_perm_recursive "$MODPATH/system/etc/security/cacerts" 0 0 0755 0644
ui_print "- Certificates in this module:"
for f in "$MODPATH"/system/etc/security/cacerts/*; do
  ui_print "    $(basename "$f")"
done
ui_print "- TESTING DEVICE ONLY. This makes every TLS connection interceptable."
ui_print "- Reboot to activate."
EOF

cd systemca && zip -r ../systemca.zip . -x '.*' && cd ..
unzip -l systemca.zip
```

> **📖 Definition — `set_perm_recursive`**
> A helper function defined in Magisk's own `util_functions.sh`, which is sourced into the
> environment your `customize.sh` runs in. The signature is
> `set_perm_recursive <dir> <owner> <group> <dirmode> <filemode> [context]`. `ui_print` is from the
> same place, and prints to the installer's console. These are not shell builtins and they do not
> exist in `post-fs-data.sh` or `service.sh` — only in the installer environment.

### Step 3 — Measure before you install

Take the baseline, or you cannot prove anything afterwards.

```bash
# adb shell
ls /system/etc/security/cacerts/ | wc -l    > /sdcard/before-count.txt
cat /sdcard/before-count.txt
```

```bash
# adb shell as root — how many mounts does Magisk have right now?
grep -ic magisk /proc/self/mountinfo
```

### Step 4 — Install and reboot

```bash
# host
adb push systemca.zip /sdcard/Download/
# Magisk app > Modules > Install from storage > systemca.zip
# Read the installer output. Your ui_print lines appear there — that is your first proof
# that customize.sh ran.
adb reboot
adb wait-for-device
```

### Step 5 — Prove it, at four increasing levels of rigour

**Level 1 — the file is visible.**

```bash
# adb shell
ls /system/etc/security/cacerts/ | wc -l         # baseline + 1
openssl x509 -in /system/etc/security/cacerts/${HASH}.0 -noout -subject 2>/dev/null \
  || echo "no openssl on device; pull the file and check on the host"
```

**Level 2 — it is a mount, not a copy.** This is the level at which you actually understand what
happened.

```bash
# adb shell as root
grep -i 'cacerts' /proc/self/mountinfo
grep -ic magisk /proc/self/mountinfo             # higher than the Step 3 baseline
```

**Q4.** Read the `mountinfo` line for the cacerts directory. Which field is the mount *source*, and
which is the mount *point*? Does the source point at your module's file directly, or at something
else — and if it is something else, what does that tell you about how Magisk assembles a directory
overlay? (Re-read [§3.6](../README.md#36-module-structure) on tmpfs directory cloning.)

**Q5.** Count the entries in `/system/etc/security/cacerts/` again. All the original certificates are
still there alongside yours. Explain, in one sentence, why a naive `mount --bind
mymodule/system/etc/security/cacerts /system/etc/security/cacerts` would have destroyed them.

**Level 3 — the physical partition is untouched.** This is the systemless claim, and you can check
it rather than believe it.

```bash
# adb shell as root — read the underlying partition, bypassing the overlay.
# Magisk keeps a mirror of the real root; its location is version-dependent, so find it:
magisk --path                     # e.g. /debug_ramdisk
ls /debug_ramdisk/.magisk/mirror/system/etc/security/cacerts/ 2>/dev/null | wc -l
# If that path does not exist on your Magisk version, the general technique still works:
# compare against a process whose namespace has no Magisk mounts (see lab 03).
```

**Level 4 — an application trusts it.** The only level a client cares about.

```bash
# host — point the device at your proxy
adb shell settings put global http_proxy 192.168.1.50:8080     # your host IP and Burp port
```

Now exercise an application that uses the **system** trust store with no pinning — the stock browser
or a WebView-based app is the usual choice — and confirm the request appears in the proxy with no
certificate warning.

```bash
# host — and undo it afterwards, always
adb shell settings put global http_proxy :0
```

**Q6.** Install the same CA into the **user** store instead (Settings → Security → Encryption &
credentials → Install a certificate) and repeat the Level 4 test with an app that targets API 24 or
higher. Does it work? Explain the difference in terms of the default
`network_security_config`, and state exactly what the system store buys you that the user store does
not.

### Step 6 — Now find the limit

```bash
# adb shell — is this device using the APEX trust store?
ls -d /apex/com.android.conscrypt/cacerts 2>/dev/null && echo "APEX"
getprop ro.build.version.sdk
```

If the APEX directory exists (Android 14+), your Level 1 check may pass while Level 4 fails: the
file is visible at the legacy path, but the runtime reads the APEX path.

**Q7.** On an Android 14+ device, run the Level 4 test. Did interception work? Now explain the
result in terms of *which directory the runtime actually reads*, and describe — without writing it —
what a module for Android 14+ would have to do differently and why it is harder. (Hint: APEX mounts
are established later in boot than `post-fs-data`.)

> **⚠️ Warning — the DenyList interaction you are about to hit in lab 03**
> If you later add your target app to DenyList, Magisk unmounts this module inside that app's mount
> namespace, and the certificate disappears for exactly the app you wanted to intercept. That is not
> a bug and it is not fixable by reinstalling the module. Lab 03 measures it precisely.

---

## Part 3 — The scripted module

Now a module with no `system/` overlay at all. It exists to run code at boot.

### Step 1 — Build it

```bash
# host
mkdir -p pentestprep

cat > pentestprep/module.prop <<'EOF'
id=pentestprep
name=Pentest Device Prep
version=v1.0
versionCode=1
author=you
description=Boot-time preparation for an authorised Android testing device.
EOF

# Scripts-only: tell Magisk not to look for a system/ overlay at all.
touch pentestprep/skip_mount

cat > pentestprep/system.prop <<'EOF'
# Applied through resetprop at boot.
# Keep the screen awake through long instrumented runs.
persist.sys.screen_off_timeout=1800000
EOF

cat > pentestprep/post-fs-data.sh <<'EOF'
#!/system/bin/sh
# post-fs-data.sh — BLOCKING. Runs after /data is mounted, before zygote.
# Nothing here may hang: the boot waits for this script and Magisk enforces a timeout.
MODDIR=${0%/*}
LOG=/data/local/tmp/pentestprep.log

echo "[$(date '+%Y-%m-%d %H:%M:%S')] post-fs-data  uptime=$(cut -d' ' -f1 /proc/uptime)" >> "$LOG"

mkdir -p /data/local/tmp/tools
chmod 0755 /data/local/tmp/tools
chown 0:0  /data/local/tmp/tools

echo "[$(date '+%Y-%m-%d %H:%M:%S')] post-fs-data done" >> "$LOG"
EOF

cat > pentestprep/service.sh <<'EOF'
#!/system/bin/sh
# service.sh — NON-BLOCKING. Runs at late_start, in parallel with the rest of boot.
# Safe to wait here, but always with a bound.
MODDIR=${0%/*}
LOG=/data/local/tmp/pentestprep.log

echo "[$(date '+%Y-%m-%d %H:%M:%S')] service.sh start uptime=$(cut -d' ' -f1 /proc/uptime)" >> "$LOG"

i=0
while [ "$(getprop sys.boot_completed)" != "1" ] && [ "$i" -lt 120 ]; do
  sleep 1
  i=$((i+1))
done

echo "[$(date '+%Y-%m-%d %H:%M:%S')] boot_completed after ${i}s uptime=$(cut -d' ' -f1 /proc/uptime)" >> "$LOG"
EOF

cd pentestprep && zip -r ../pentestprep.zip . -x '.*' && cd ..
```

### Step 2 — Install, reboot, and read the timings

```bash
# host
adb push pentestprep.zip /sdcard/Download/
# install via the Magisk app, then:
adb reboot && adb wait-for-device
sleep 60
adb shell "su -c 'cat /data/local/tmp/pentestprep.log'"
```

You now have four timestamps with uptimes attached. This is the boot stage table from
[§3.5](../README.md#35-boot-stages-and-when-your-code-runs), measured on your own device.

**Q8.** Fill this in from your log, in seconds of uptime:

| Event | Uptime |
|---|---|
| `post-fs-data.sh` entered | |
| `post-fs-data.sh` returned | |
| `service.sh` entered | |
| `sys.boot_completed` became 1 | |

**Q9.** How long is the gap between `post-fs-data` returning and `service.sh` starting? What is
happening on the device during that gap, and why does it mean anything that needs the framework must
not be in `post-fs-data.sh`?

### Step 3 — Prove the property was applied

```bash
# adb shell
getprop persist.sys.screen_off_timeout
```

```bash
# adb shell as root — and prove resetprop is what did it, by changing a read-only property
getprop ro.build.tags                       # release-keys
su -c 'resetprop ro.build.tags test-keys'
getprop ro.build.tags                       # test-keys — a "read-only" property, rewritten
su -c 'resetprop ro.build.tags release-keys'   # put it back
```

**Q10.** `ro.*` properties are documented as immutable after `init` sets them. Explain what
`resetprop` is actually doing to make that statement false, and then explain why doing it does
**not** change what the bootloader reported to the TEE. Both halves matter; the second is the one
people get wrong in reports.

### Step 4 — Add a SELinux rule and prove it took effect

Do not add a rule speculatively. Cause a denial, read it, and write the rule that the denial asks
for. That is the whole workflow.

```bash
# adb shell as root — watch for denials while you exercise whatever is failing
dmesg -w | grep -i avc
# In another shell, run the operation that fails. Copy the avc line.
```

A denial line names the source domain, the target type, the class and the permission — which is
exactly the shape of a `magiskpolicy` rule:

```
avc: denied { read } for ... scontext=u:r:SOURCE:s0 tcontext=u:object_r:TARGET:s0 tclass=file
                  ^^^^                    ^^^^^^                     ^^^^^^              ^^^^
                  perm                    source                     target             class
```

```bash
# adb shell as root — apply it live, without a reboot, and see whether the operation now works
magiskpolicy --live "allow SOURCE TARGET file { read open getattr }"
```

Once you know the rule is right, put it in the module so it survives reboots:

```bash
# host
cat > pentestprep/sepolicy.rule <<'EOF'
# Derived from a real avc denial observed with: dmesg | grep avc
# Replace with the rule YOUR device actually needed. Do not ship rules you did not need.
allow magisk self process execmem
EOF
```

**Q11.** You could have written `permissive untrusted_app` instead and made the denial go away in
one line. Give two concrete reasons that is a worse answer, one about the device and one about the
validity of your test results.

> **🔍 Pentester's Note**
> The temptation is always `setenforce 0`. Resist it. A permissive device is a different device:
> apps take different code paths, some detect `getenforce` directly, and any finding you produce is
> open to the objection that it only reproduces with SELinux disabled. Targeted `magiskpolicy --live`
> rules keep the device in `Enforcing` and keep your results defensible.

---

## Part 4 — Break it deliberately, then recover

Cause the failure now, under controlled conditions, so that the first time you see a module bootloop
you already know what it looks like and how to get out.

> **⚠️ Warning**
> Do this only on the device from lab 01, and only after you have practised safe mode. The device
> will take noticeably longer to boot, and on some Magisk versions the boot will proceed with the
> module's script killed. Do not extend the sleep beyond 90 seconds.

```bash
# host — a post-fs-data.sh that blocks for 90 seconds
cat > pentestprep/post-fs-data.sh <<'EOF'
#!/system/bin/sh
LOG=/data/local/tmp/pentestprep.log
echo "[$(date '+%H:%M:%S')] DELIBERATE BLOCK START uptime=$(cut -d' ' -f1 /proc/uptime)" >> "$LOG"
sleep 90
echo "[$(date '+%H:%M:%S')] DELIBERATE BLOCK END   uptime=$(cut -d' ' -f1 /proc/uptime)" >> "$LOG"
EOF
cd pentestprep && zip -r ../pentestprep-broken.zip . -x '.*' && cd ..
adb push pentestprep-broken.zip /sdcard/Download/
# install, reboot, and time the boot with a stopwatch
```

**Q12.** How long did the boot take? Did both log lines appear, or only the first? If only the first
appeared, what killed the script, and what does that tell you about the timeout mentioned in
[§3.5](../README.md#35-boot-stages-and-when-your-code-runs)?

Now recover, using each of the three routes in turn so you have done all of them:

```bash
# Route 1 — safe mode: power off, power on, hold Volume Down through the boot animation.
```

```bash
# host — Route 2: disable every module over adb
adb wait-for-device
adb shell "su -c 'touch /data/adb/modules/*/disable'"
adb reboot
```

```bash
# host — Route 3: mark this one module for removal
adb shell "su -c 'touch /data/adb/modules/pentestprep/remove'"
adb reboot
adb shell "su -c 'ls /data/adb/modules/'"    # pentestprep is gone
```

**Q13.** `disable` and `remove` are both empty files. Why did Magisk's authors choose an empty
sentinel file over, say, a field in `module.prop` or a row in `magisk.db`? Think about what state
Magisk can read at `post-fs-data` time, and what an adb shell can write on a device that will not
finish booting.

Finally, restore the good version:

```bash
# host
cd pentestprep && zip -r ../pentestprep.zip . -x '.*' && cd ..
# (put the non-blocking post-fs-data.sh back first!)
```

---

## Part 5 — Module lifecycle, completed

Fill in this table from your own device, by measurement:

| Action | Command or file | What you observed |
|---|---|---|
| Install without reboot | Magisk app, or `magisk --install-module x.zip` | staged in `/data/adb/modules_update/` |
| Activate | reboot | moved to `/data/adb/modules/` |
| Disable, keep installed | `touch .../disable` | |
| Re-enable | `rm .../disable` | |
| Remove at next boot | `touch .../remove` | |
| Run the uninstall hook | `uninstall.sh` in the module | |
| Update in place | install a higher `versionCode` | |
| Skip the `system/` overlay | `skip_mount` | |
| Replace a whole directory rather than merge | a `.replace` file inside it | |

```bash
# adb shell as root — install a module from the command line, no app needed
magisk --install-module /sdcard/Download/pentestprep.zip
```

**Q14.** Add an `uninstall.sh` to `pentestprep` that deletes `/data/local/tmp/pentestprep.log`.
Install, then remove the module, then check whether the log is gone. At what point in the boot did
`uninstall.sh` run, and what does that mean for what it can safely assume exists?

---

## Hints

<details>
<summary>Hint 1 — the module installed but nothing appears under /system</summary>

Check, in this order:

1. `ls /data/adb/modules/<id>/system/etc/...` — is the file actually inside the installed module? If
   not, your ZIP layout is wrong. `unzip -l` the archive and confirm `module.prop` is at the root.
2. `ls /data/adb/modules/<id>/skip_mount` — if that file exists, you told Magisk not to mount the
   overlay. It is easy to leave in place from a copy-pasted skeleton.
3. `ls /data/adb/modules/<id>/disable` — the module is installed but inert.
4. `grep -i magisk /proc/self/mountinfo` — if Magisk has no mounts at all, the problem is not your
   module.
</details>

<details>
<summary>Hint 2 — the certificate file is there but interception still fails</summary>

Separate the three possible causes before changing anything:

- **Wrong filename.** Recompute `openssl x509 -subject_hash_old` and compare to what is on the
  device. A `.pem` extension or a plain-hash name without `.0` will sit there being ignored.
- **APEX trust store.** On Android 14+ the runtime reads
  `/apex/com.android.conscrypt/cacerts`, not the legacy path. Check whether that directory exists.
- **The app does not use the system store.** Certificate pinning, a custom `TrustManager`, or a
  bundled trust store all ignore the system CAs completely. That is
  [36-CertificatePinning](../../36-CertificatePinning/README.md)'s territory, not this module's
  failure.

Testing with a WebView or the stock browser first isolates the first two causes from the third.
</details>

<details>
<summary>Hint 3 — your script does not seem to run</summary>

`post-fs-data.sh` and `service.sh` are run by Magisk with `sh`, so the shebang is documentation
rather than mechanism — but the **line endings** are not. A script saved with CRLF line endings from
a Windows editor fails with errors like `not found` on the first line, because the interpreter sees
a trailing carriage return as part of the command name.

```bash
# host
file pentestprep/service.sh          # "with CRLF line terminators" is the smoking gun
sed -i 's/\r$//' pentestprep/service.sh
```

Also: nothing is logged for you. If your script does not write a log, you have no evidence it ran.
Write the log line first, before the logic.
</details>

<details>
<summary>Hint 4 — proving the partition is untouched, without Magisk's mirror</summary>

If `magisk --path`'s mirror directory does not exist on your version, there is a version-independent
way: find any process whose mount namespace has no Magisk mounts (a DenyList'ed app is the easy
one), and read the path through its namespace.

```bash
# adb shell as root
PID=$(pidof -s <a denylisted package>)
nsenter --mount=/proc/$PID/ns/mnt -- ls /system/etc/security/cacerts/ | wc -l
```

That is the whole technique of lab 03, arriving early.
</details>

---

## Solutions and expected answers

<details>
<summary>Q1, Q2 — module state</summary>

Magisk's copy of the module contains files your ZIP did not: at minimum, `module.prop` is rewritten
or supplemented with state, and the directory may hold sentinel files. The important observation is
that **module state lives in the filesystem, not in a database** — `disable`, `remove`, `update` and
`skip_mount` are all empty files. That is a deliberate design choice (see Q13).

`modules_update/` exists because activating a module requires mounting it at `post-fs-data`, and
that stage has already passed by the time you install. Magisk stages the new version and swaps it in
on the next boot. This is also why installing an updated module does not disturb the running one.
</details>

<details>
<summary>Q3 — subject_hash_old</summary>

OpenSSL 1.0.0 changed the subject-name hashing algorithm used for trust-store lookups. Android's
trust store was built against the *older* algorithm and never migrated, so a store built with modern
`-subject_hash` produces filenames Android never looks for. The failure is completely silent: the
file exists, is a valid certificate, has correct permissions, and is never read.

This is a good example of a class of bug worth recognising generally — a lookup keyed on a hash you
computed with the wrong function fails by *absence*, and absence produces no error message anywhere.
</details>

<details>
<summary>Q4, Q5 — the tmpfs directory clone</summary>

The mount source is **not** your module's file. Magisk creates a tmpfs, populates it with bind
mounts back to every original certificate plus a bind mount for yours, and mounts that tmpfs over
`/system/etc/security/cacerts`. So `mountinfo` shows a tmpfs mounted at the cacerts path, plus
individual bind mounts underneath it.

A naive `mount --bind module/cacerts /system/etc/security/cacerts` would replace the directory
wholesale, so the ~140 original CAs would vanish and the device would fail to validate any ordinary
TLS connection. The clone-and-repopulate dance exists precisely to avoid that, and it is why a
single added file produces a long list of mounts — which is, in turn, why counting unexpected mounts
is such an effective root check ([37-RootDetection](../../37-RootDetection/README.md)).
</details>

<details>
<summary>Q6 — user store versus system store</summary>

From Android 7 (API 24), the default `network_security_config` trusts only the **system** CA store
for apps that target API 24 or higher. A CA in the user store is trusted by the browser and by apps
that explicitly opt in with `<certificates src="user" />`, and by nothing else.

So: the user store is enough to intercept a browser, and useless against the app you were actually
hired to test. That single behaviour change is why the system-CA Magisk module became standard
equipment. Chapters 35-SSL and 36-CertificatePinning cover the trust-store mechanics and the layer
above them; neither is written yet, so the authoritative reference for now is the Android
`network_security_config` documentation cited in [`references/`](../references/README.md).
</details>

<details>
<summary>Q8–Q9 — boot stage timings</summary>

Typical shape (your numbers will differ by device, and that is fine — the *ordering* and the *gaps*
are the lesson):

- `post-fs-data.sh` runs early, at a few seconds of uptime, and the boot is stopped while it runs.
- `service.sh` starts noticeably later, once zygote is up and the boot animation is showing.
- `sys.boot_completed` arrives tens of seconds after that.

The gap between `post-fs-data` and `service.sh` is zygote starting, `system_server` initialising,
and the framework coming up. Nothing that calls `getprop sys.boot_completed`, talks to a system
service, starts an activity, or expects the network can work in `post-fs-data.sh`, because none of
those exist yet — and worse, waiting for them there stops the boot from ever producing them. That is
a deadlock, and it is the classic module bootloop.
</details>

<details>
<summary>Q10 — what resetprop really does</summary>

Android properties live in a shared memory region (`/dev/__properties__`), mapped read-only into
every process and written only by `init` over a socket. The `ro.` immutability is enforced by
`init`'s property service refusing the write — it is a policy in a userspace daemon, not a hardware
or kernel guarantee. `resetprop` runs as root and writes into the property area directly, so the
policy simply never applies.

What it does **not** do: change anything the bootloader measured. `ro.boot.verifiedbootstate` is a
*copy*, made at boot, of a value the bootloader passed on the kernel command line. Rewriting the
copy does not alter what the bootloader reported to the TEE, and it does not alter the
`RootOfTrust` extension in a hardware-backed key attestation certificate, which is signed inside the
TEE. Claiming otherwise in a report is the fastest way to lose an audience of engineers. See
[49-KeyStore](../../49-KeyStore/README.md).
</details>

<details>
<summary>Q11 — why not just go permissive</summary>

Device-side: a permissive domain removes every restriction on that domain, not the one you needed,
so you have granted far more than the denial asked for, and you have done it persistently.

Result-validity: apps behave differently on a permissive device — some take different code paths,
some read `getenforce` and change behaviour, and a finding that only reproduces with SELinux
disabled is a finding a client can reject. Targeted rules keep the device representative.
</details>

<details>
<summary>Q13 — why empty sentinel files</summary>

Two properties, both load-bearing:

- **Readable at the earliest possible moment.** At `post-fs-data`, `/data` is mounted but almost
  nothing else exists. A `stat()` on a file works; opening a SQLite database and running a query is
  far more machinery, and more ways to fail, at a stage where failure is a bootloop.
- **Writable from a broken device.** `touch /data/adb/modules/*/disable` works from an adb shell on
  a device that never reaches the launcher. Editing a database or a structured config file from that
  position is much harder. The recovery path *is* the design constraint.

This is a good pattern to recognise generally: state that must be readable early and writable during
a failure wants to be filesystem-shaped.
</details>

---

## Success criteria

- [ ] You built a minimal module from an empty directory and confirmed the packaging layout with
      `unzip -l` before pushing it
- [ ] You produced the CA filename with `-subject_hash_old` and can say why
- [ ] The system CA module installs, and you verified it at all four levels, including an actual
      intercepted request
- [ ] You read the `mountinfo` lines your module produced and can explain the tmpfs directory clone
- [ ] You proved the underlying partition is unchanged, by mirror or by namespace
- [ ] You determined whether your device uses the legacy or APEX trust store, by measurement
- [ ] You built a scripts-only module with `skip_mount`, `system.prop`, `post-fs-data.sh` and
      `service.sh`
- [ ] You filled in the boot-timing table from your own log with real uptimes
- [ ] You rewrote a `ro.` property with `resetprop` and can explain both what that proves and what
      it does not
- [ ] You derived a `sepolicy.rule` from a real `avc` denial rather than copying one
- [ ] You deliberately blocked `post-fs-data.sh`, observed the effect, and recovered by all three
      routes
- [ ] You exercised `disable`, `remove`, `uninstall.sh` and a `versionCode` upgrade
- [ ] You answered Q1–Q14 in writing
- [ ] You compared your modules against
      [`examples/system-ca-module/`](../examples/system-ca-module/) and
      [`examples/pentest-prep-module/`](../examples/pentest-prep-module/) **after** finishing, and
      noted every difference

---

## Next

[Lab 03 — DenyList investigation](lab-03-denylist-investigation.md) takes the CA module you just
built and shows you, by measurement, why adding your target app to DenyList makes it stop working.
Keep both modules installed; lab 03 needs them.
