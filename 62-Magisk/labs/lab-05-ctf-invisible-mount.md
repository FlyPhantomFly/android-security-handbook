# Lab 05 — CTF: The Invisible Mount

**Difficulty:** CTF / Advanced
**Time:** 3–5 hours
**Prerequisites:** [Lab 02](lab-02-write-a-module.md) and, above all,
[Lab 03](lab-03-denylist-investigation.md) — this challenge is not solvable without the `nsenter`
technique and the mount-namespace model that lab builds.
[Chapter 62 §2.2](../README.md#22-the-overlay-illusion),
[§3.6](../README.md#36-module-structure), [§3.9](../README.md#39-denylist--what-it-really-does),
[02-Linux-Basics](../../02-Linux-Basics/README.md)

---

## The challenge

You are given an application, `com.magisklab.vault`, and a Magisk module,
`vault-provision.zip`, that the application's vendor ships to "provision" a device.

On an unmodified device with the module installed, the app opens its vault and shows a flag. On your
rooted device, whatever you do, it shows:

```
Vault not provisioned for this device.
```

There is only ever that one message. There is no root warning, no "device not supported", nothing in
logcat that mentions root, Magisk, or integrity, and the app never touches the network.

You have already tried the obvious things and they made it worse, not better:

| What you tried | What happened |
|---|---|
| Installed the provisioning module and rebooted | Same message |
| Added the app to DenyList and restarted it | Same message |
| **Both at once** | Same message |

**Open the vault on your rooted device.** The flag has the form `MAGISKLAB{...}`.

---

## Rules

- **No decrypting the flag offline.** You have the module and the APK; deriving the plaintext on your
  host is arithmetic and teaches nothing. The vault must open **on the device**, in the app's own
  process.
- **No patching the APK, and no Frida for your first solve.** Both work. Both are chapter 37's
  material and chapter 53's material, and reaching for them here skips the entire lesson. You may use
  Frida for your *second* solve, and the debrief asks you to compare.
- **No uninstalling Magisk.** "It works on a device without root" is not a solution to a lab about
  root.
- **Solve it twice, by two different mechanisms**, and be able to say which you would use on a real
  target and why.
- You must be able to state, in terms of specific mounts and specific namespaces, **why each of the
  three things in the table above failed.**

---

## Objective

Defeat a control whose two halves are individually satisfiable and jointly, apparently, are not —
because the mechanism that satisfies one is the mechanism that destroys the other.

The resolution is a fact about mount namespaces: **DenyList removes the mounts Magisk made.** It has
no opinion about mounts Magisk did not make, and no opinion about mounts made after its window has
closed. Everything in this lab follows from that sentence.

## How this differs from Lab 04 of chapter 37

Both are CTFs about a device that "detects something". They test different skills, and it is worth
being explicit about which is which before you start.

| | [37 Lab 04 — The Decoupled Check](../../37-RootDetection/labs/lab-04-ctf-decoupled.md) | 62 Lab 05 — The Invisible Mount |
|---|---|---|
| What is hidden | **The check.** It is in native code, uses raw syscalls, is named to look like key derivation, and its consequence is separated from its detection | **Nothing.** The check is ten lines of readable Java and you may read it before you start |
| What is hard | Finding the check, and realising that a correct crypto routine is being fed a bad input | Satisfying two conditions whose satisfying mechanisms are mutually destructive |
| The skill | Data-flow reasoning; static analysis of a stripped `.so`; recognising that your methodology, not your tools, has failed | Mount-namespace mechanics; knowing what DenyList does and does not touch; module design |
| The tools | Ghidra, `strace`, syscall-level Frida hooks | `nsenter`, `mount --bind`, `chcon`, a module you write yourself |
| Where the answer lives | Inside the process | **Outside the process**, in the kernel's per-namespace mount table |
| The transferable lesson | *Is the code wrong, or is the code being lied to?* | *Whose namespace is this path resolved in, and who put that mount there?* |

If you have not done 37's lab 04, do it — but do not expect its technique to help here, and do not
expect this one to help there.

---

## Building the challenge

Build it yourself. Implementing the control is half the education, and you will not recognise this
shape in the wild until you have written it once.

### Part 1 — The application

**`AndroidManifest.xml`**

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.magisklab.vault">
    <application android:label="Provisioning Vault" android:allowBackup="false">
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
```

**`app/src/main/java/com/magisklab/vault/Vault.java`**

```java
package com.magisklab.vault;

import android.util.Base64;

import java.io.BufferedReader;
import java.io.FileReader;
import java.nio.charset.StandardCharsets;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Two conditions, checked in the same process at the same moment.
 *
 *   A. INTEGRITY  -- this process's mount namespace shows no sign of a root
 *                    manager's overlay.
 *   B. PROVISION  -- this process can read a provisioning token that the vendor
 *                    delivers by modifying a system file.
 *
 * Nothing here is obfuscated and nothing is hidden. Read all of it. The
 * difficulty is not in finding the check; it is that the ordinary way to satisfy
 * B is a Magisk module, and the ordinary way to satisfy A removes Magisk modules
 * from this process's view.
 *
 * Note that both failures produce the SAME message. That is deliberate and it is
 * also realistic: a control that tells you which half you failed is a control
 * that helps you.
 */
public final class Vault {

    /** Substrings whose presence in this process's mount table we treat as disqualifying. */
    private static final String[] DIRTY = {
        "magisk", "/data/adb", "worker", "debug_ramdisk", "core/mirror", "core/img"
    };

    /** The vendor writes this marker into /system/etc/hosts when it provisions a device. */
    private static final String MARKER = "# vaultco-provision ";

    // Produced by tools/make-blob.py. AES-256-CBC over the flag, key = the
    // provisioning token, IV below.
    private static final String BLOB   = "REPLACE_ME_WITH_GENERATED_BASE64";
    private static final String IV_B64 = "REPLACE_ME_WITH_GENERATED_IV";

    public static String open() {
        try {
            if (!namespaceLooksClean()) return null;

            String token = readProvisionToken();
            if (token == null || token.length() != 64) return null;

            Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
            c.init(Cipher.DECRYPT_MODE,
                   new SecretKeySpec(hexToBytes(token), "AES"),
                   new IvParameterSpec(Base64.decode(IV_B64, Base64.NO_WRAP)));

            String s = new String(c.doFinal(Base64.decode(BLOB, Base64.NO_WRAP)),
                                  StandardCharsets.UTF_8);
            return s.startsWith("MAGISKLAB{") ? s : null;

        } catch (Throwable t) {
            // Every failure path is identical and none of them mentions root.
            return null;
        }
    }

    /**
     * Condition A. Reads THIS PROCESS's mount table -- which is resolved against
     * this process's mount namespace, not the device's. Two processes on the
     * same device can get different answers here, and that is the whole lab.
     */
    private static boolean namespaceLooksClean() {
        BufferedReader r = null;
        try {
            r = new BufferedReader(new FileReader("/proc/self/mountinfo"));
            String line;
            while ((line = r.readLine()) != null) {
                String l = line.toLowerCase();
                for (String d : DIRTY) {
                    if (l.contains(d)) return false;
                }
            }
            return true;
        } catch (Throwable t) {
            return false;
        } finally {
            closeQuietly(r);
        }
    }

    /**
     * Condition B. Reads a system file that a stock device does not contain the
     * marker in. The vendor's provisioning module supplies it.
     */
    private static String readProvisionToken() {
        BufferedReader r = null;
        try {
            r = new BufferedReader(new FileReader("/system/etc/hosts"));
            String line;
            while ((line = r.readLine()) != null) {
                int i = line.indexOf(MARKER);
                if (i >= 0) {
                    return line.substring(i + MARKER.length()).trim();
                }
            }
            return null;
        } catch (Throwable t) {
            return null;
        } finally {
            closeQuietly(r);
        }
    }

    private static byte[] hexToBytes(String hex) {
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    private static void closeQuietly(BufferedReader r) {
        if (r != null) { try { r.close(); } catch (Throwable ignored) { } }
    }

    private Vault() { }
}
```

**`app/src/main/java/com/magisklab/vault/MainActivity.java`**

```java
package com.magisklab.vault;

import android.app.Activity;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;

public class MainActivity extends Activity {

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);

        final TextView tv = new TextView(this);
        tv.setTextSize(16f);
        tv.setPadding(24, 24, 24, 24);
        tv.setText("Vault locked.");

        Button open = new Button(this);
        open.setText("Open Vault");
        open.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                // Re-reads both inputs on every press. Nothing is cached.
                String s = Vault.open();
                tv.setText(s != null ? s : "Vault not provisioned for this device.");
            }
        });

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(24, 96, 24, 24);
        root.addView(tv);
        root.addView(open);
        setContentView(root);
    }
}
```

> **Note the design decision in `onClick`.** The vault re-reads `/proc/self/mountinfo` and
> `/system/etc/hosts` on every press rather than caching a verdict at startup. That is what makes the
> challenge solvable at all, and it is also what a competent implementation would *not* do. Debrief
> question 7 is about that.

### Part 2 — The provisioning token and the vendor's module

```bash
# host — the token is 32 bytes of key material, written as 64 hex characters
TOKEN=$(openssl rand -hex 32)
echo "$TOKEN" | tee token.txt
```

```bash
# host — build the vendor's provisioning module
mkdir -p vault-provision/system/etc

cat > vault-provision/module.prop <<EOF
id=vaultprovision
name=VaultCo Device Provisioning
version=v1.0
versionCode=1
author=vaultco
description=Provisions this device for the VaultCo application.
EOF

# A hosts file that is a normal hosts file, plus one marker line.
cat > vault-provision/system/etc/hosts <<EOF
127.0.0.1       localhost
::1             ip6-localhost
$(printf '# vaultco-provision %s\n' "$TOKEN")
EOF

cd vault-provision && zip -qr ../vault-provision.zip . -x '.*' && cd ..
unzip -l vault-provision.zip
```

### Part 3 — Generate the ciphertext

Run this on the **host**, in a scratch directory, and paste the two base64 strings into `Vault.java`.

```python
#!/usr/bin/env python3
# host — make-blob.py. Produces BLOB and IV_B64 for Vault.java.
# The key IS the provisioning token, so the vault can only open where the
# token is readable.
import base64
import os
import sys

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

TOKEN = sys.argv[1] if len(sys.argv) > 1 else open("token.txt").read().strip()
FLAG = b"MAGISKLAB{the_mount_magisk_never_made}"

key = bytes.fromhex(TOKEN)
assert len(key) == 32, "token must be 64 hex characters"

iv = os.urandom(16)
pad = 16 - (len(FLAG) % 16)
pt = FLAG + bytes([pad]) * pad

enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
ct = enc.update(pt) + enc.finalize()

print("BLOB   =", base64.b64encode(ct).decode())
print("IV_B64 =", base64.b64encode(iv).decode())
```

> **Warning**
> Run this from a scratch directory outside the repository. It writes nothing itself, but Python
> writes `__pycache__` for anything it *imports*, and build artefacts do not belong in the repo.

### Part 4 — Build, install, and confirm all three failure states

```bash
# host
./gradlew assembleDebug
adb install -r app/build/outputs/apk/debug/app-debug.apk
adb push vault-provision.zip /sdcard/Download/
```

Confirm each of the three states yourself. Do not take the table at the top of this lab on trust —
reproducing it is the first measurement of the lab.

```bash
# host — state 1: module installed, no DenyList
adb shell "su -c 'magisk --install-module /sdcard/Download/vault-provision.zip'"
adb reboot && adb wait-for-device && sleep 40
adb shell am start -n com.magisklab.vault/.MainActivity
# tap Open Vault -> "Vault not provisioned for this device."
```

```bash
# host — state 2: DenyList on
# Magisk app > Settings > Configure DenyList > tick Provisioning Vault
adb shell am force-stop com.magisklab.vault
adb shell am start -n com.magisklab.vault/.MainActivity
# tap Open Vault -> same message
```

State 3 is states 1 and 2 together, which is where you already are.

---

## Your first three attempts, and why each fails

Do these, and measure each failure rather than assuming it. The measurement is the lab.

### Attempt 1 — the module alone

```bash
# adb shell as root
PID=$(pidof -s com.magisklab.vault)
grep -icE 'magisk|/data/adb|worker|debug_ramdisk' /proc/$PID/mountinfo
nsenter --mount=/proc/$PID/ns/mnt -- grep -c vaultco-provision /system/etc/hosts
```

**Q1.** Which of the two conditions passes and which fails? Quote the numbers.

**Q2.** The `grep` above counts lines matching Magisk's tokens. Some of those lines exist because of
the provisioning module you just installed, and some exist because Magisk is running at all. Separate
them. If you removed the provisioning module entirely, would condition A pass?

### Attempt 2 — DenyList alone

```bash
# adb shell as root — with the module REMOVED and DenyList ON
PID=$(pidof -s com.magisklab.vault)
grep -icE 'magisk|/data/adb|worker|debug_ramdisk' /proc/$PID/mountinfo
nsenter --mount=/proc/$PID/ns/mnt -- grep -c vaultco-provision /system/etc/hosts
```

**Q3.** Now which passes and which fails? State the mechanism in one sentence each.

### Attempt 3 — both

```bash
# adb shell as root — module installed AND DenyList on
PID=$(pidof -s com.magisklab.vault)
echo "--- global namespace:"
grep -c vaultco-provision /system/etc/hosts
echo "--- the app's namespace:"
nsenter --mount=/proc/$PID/ns/mnt -- grep -c vaultco-provision /system/etc/hosts
```

**Q4.** The same absolute path, at the same instant, gives two different answers. Explain why, in
terms of what `nsenter` did and what `/proc/self/mountinfo` is a table *of*.

**Q5.** Write the sentence that states the whole problem. It should contain the words "the mechanism
that satisfies B" and "the mechanism that satisfies A". Once you have written it, the shape of the
solution is visible in it.

---

## Investigation

### Step 1 — Enumerate exactly what DenyList removed

```bash
# host
adb push ../scripts/ns-diff.sh /data/local/tmp/
adb shell "su -c 'chmod 755 /data/local/tmp/ns-diff.sh'"
adb shell "su -c '/data/local/tmp/ns-diff.sh com.magisklab.vault -v'"
```

**Q6.** Is the `/system/etc/hosts` mount in the removed list? What is its **source** (field 4 and
field 10 of the mountinfo line)? Write both down; they are the key to Step 3.

### Step 2 — Establish the boundary of DenyList's authority

The question that unlocks everything: *what, exactly, does DenyList unmount?*

Not "Magisk's stuff" — that is a description, not a rule. Determine the rule empirically.

```bash
# adb shell as root — create a mount that Magisk knows nothing about,
# inside the app's namespace, while the app is running
PID=$(pidof -s com.magisklab.vault)
mkdir -p /data/local/tmp/.probe
echo "hello from a mount magisk never made" > /data/local/tmp/.probe/marker
nsenter --mount=/proc/$PID/ns/mnt -- \
    mount --bind /data/local/tmp/.probe/marker /system/etc/hosts
nsenter --mount=/proc/$PID/ns/mnt -- cat /system/etc/hosts
```

**Q7.** Did it work? Does the mount appear in `/proc/$PID/mountinfo`? Does it appear in
`/proc/1/mountinfo`? What does the second answer tell you about mount propagation between the app's
namespace and init's?

**Q8.** Force-stop the app and start it again. Is your mount still there? Explain the result — and note
why the ordering in the solutions below matters.

```bash
# adb shell as root — clean up before you continue
nsenter --mount=/proc/$(pidof -s com.magisklab.vault)/ns/mnt -- umount /system/etc/hosts 2>/dev/null
```

### Step 3 — The SELinux wall you are about to hit

Try to make the app actually *read* through a mount you created.

```bash
# adb shell as root
PID=$(pidof -s com.magisklab.vault)
nsenter --mount=/proc/$PID/ns/mnt -- mount --bind /data/local/tmp/.probe/marker /system/etc/hosts
# now, in the app, tap Open Vault
adb shell 'dmesg | grep -i avc | tail -5'
```

**Q9.** The app probably cannot read it, and `dmesg` will tell you why. Read the denial. What
**label** does the file carry, what label does the app expect at that path, and which tool fixes it?

**Q10.** A Magisk module's overlay files do not have this problem. What does Magisk do for module
files that you must do by hand for your own mounts? (Chapter
[§3.6](../README.md#36-module-structure) describes the mount; the labelling is the part that is easy
to miss until it bites.)

### Step 4 — Now solve it

You have everything. Write down your plan before you type anything, in three lines: what you mount,
where, and *when* relative to the app's fork.

---

## Hints

<details>
<summary>Hint 1 — stop trying to make DenyList spare your module</summary>

You cannot configure your way out of this. DenyList's job is to remove Magisk's modifications from
the target's namespace, and your module's overlay is a Magisk modification. There is no per-module
exemption to find in the settings.

So stop asking "how do I keep the module mounted" and start asking "**does the file have to arrive
by a Magisk mount at all?**" Condition B does not say "a Magisk module must be installed". It says
"this process must be able to read a token at this path". Those are very different requirements, and
you have been treating them as the same one.
</details>

<details>
<summary>Hint 2 — timing is a parameter you control</summary>

Lab 03, question 12, established when the DenyList unmount happens: in the Zygisk specialise hook,
after `fork()` and before any of the app's own code runs.

That is a *window*, and windows have two edges. Everything Magisk is going to unmount, it unmounts
inside that window. What happens to the namespace afterwards is not Magisk's business, and Magisk is
not watching.

The app re-reads both files on every button press.
</details>

<details>
<summary>Hint 3 — the two-word version of the answer</summary>

*Mount later.*

Or, if you would rather have the full sentence: DenyList removes the mounts Magisk made, in the
window Magisk controls. A mount that Magisk did not make, made after that window has closed, is not
Magisk's mount and is not in that window.
</details>

<details>
<summary>Hint 4 — the SELinux label, spelled out</summary>

A bind mount does not change the file's security context; SELinux checks the label on the inode, not
the path. A file created under `/data/local/tmp` by a root shell is labelled `shell_data_file`, and
`untrusted_app` may not read that — so the app gets `EACCES` through your beautiful mount.

Files under `/system/etc` are labelled `system_file`. Relabel the source before mounting:

```bash
# adb shell as root
chcon u:object_r:system_file:s0 /data/local/tmp/.prov/hosts
ls -Z /data/local/tmp/.prov/hosts
```

Confirm with `dmesg | grep avc` that the denial stops. Do **not** reach for `setenforce 0`: it
changes the device's behaviour globally, and it would also make this lab teach you nothing, because
the point is that the label is part of the mount's correctness.
</details>

<details>
<summary>Hint 5 — if you want to keep the module instead</summary>

There is a completely different family of answers in which you do **not** use DenyList at all, keep
the module mounted, and attack condition A instead.

Condition A reads a file. Files can be mounted over. Including files in `/proc`.
</details>

---

## Solutions

Do not read until you have solved it, or genuinely stopped.

<details>
<summary>Solution A — the mount Magisk never made (the intended route)</summary>

Keep DenyList on, so condition A is satisfied by Magisk itself. Then supply condition B with a mount
Magisk knows nothing about, created *after* the app has been forked and specialised.

```bash
# adb shell as root
set -e

# 1. Stage the provisioned hosts file somewhere outside /data/adb, so that
#    nothing about the mount looks like Magisk's work.
mkdir -p /data/local/tmp/.prov
cp /data/adb/modules/vaultprovision/system/etc/hosts /data/local/tmp/.prov/hosts
#    (or write the token line by hand if you removed the module)

# 2. Give it the label the app is allowed to read at that path.
chcon u:object_r:system_file:s0 /data/local/tmp/.prov/hosts
chmod 0644 /data/local/tmp/.prov/hosts
chown 0:0  /data/local/tmp/.prov/hosts

# 3. Start the app FIRST. The namespace must exist, and Magisk's unmount window
#    must already have closed.
am start -n com.magisklab.vault/.MainActivity
sleep 2
PID=$(pidof -s com.magisklab.vault)

# 4. Mount into that process's namespace, and nowhere else.
nsenter --mount=/proc/$PID/ns/mnt -- \
    mount --bind /data/local/tmp/.prov/hosts /system/etc/hosts

# 5. Verify from inside the namespace before you touch the app.
nsenter --mount=/proc/$PID/ns/mnt -- grep -c vaultco-provision /system/etc/hosts
nsenter --mount=/proc/$PID/ns/mnt -- grep -icE 'magisk|/data/adb|worker|debug_ramdisk' /proc/self/mountinfo
```

Now tap **Open Vault**:

```
MAGISKLAB{the_mount_magisk_never_made}
```

**Why condition A still passes.** Look at the mountinfo line your mount produced. Its root field is
something like `/local/tmp/.prov/hosts` and its source is the userdata block device. Nothing in it
contains `magisk`, `/data/adb`, `worker` or `debug_ramdisk`, so the app's substring scan does not
match it. That is a property of *this* check's dirty-list, and a stricter check would catch it — see
debrief question 5.

**Why it does not survive a restart.** The mount lives in that process's namespace. When the process
dies, so does the namespace, and the next fork gets a fresh copy of zygote's. This is a per-session
technique, and on a real engagement you would script it against the app's launch.
</details>

<details>
<summary>Solution B — a module that mounts for itself</summary>

Ask the question DenyList's implementation actually answers: *which mounts does it revert?* Magisk
reverts the mounts **it** made — the ones it created while applying module overlays, plus its own
tmpfs. A bind mount created by a module's `post-fs-data.sh`, from a source outside `/data/adb`, is
not in that set on some Magisk versions.

```sh
#!/system/bin/sh
# post-fs-data.sh of a scripts-only module (note the skip_mount file)
MODDIR=${0%/*}
STAGE=/dev/.vaultprov            # tmpfs, exists early, outside /data/adb
mkdir -p "$STAGE"
cp "$MODDIR/hosts.provisioned" "$STAGE/hosts"
chcon u:object_r:system_file:s0 "$STAGE/hosts"
chmod 0644 "$STAGE/hosts"
mount --bind "$STAGE/hosts" /system/etc/hosts
```

**Then measure whether it survives**, because the answer is version-dependent and you should never
assert it from memory:

```bash
# adb shell as root — with DenyList ON for the vault app
PID=$(pidof -s com.magisklab.vault)
nsenter --mount=/proc/$PID/ns/mnt -- grep -c vaultco-provision /system/etc/hosts
```

Both outcomes are informative:

- **It survived.** You have a persistent version of Solution A that needs no root shell at run time.
  Note what that means defensively: a module can place content into a DenyList'ed process's
  namespace, which is a real limitation of DenyList worth stating in a report.
- **It was reverted.** Your Magisk version reverts more broadly than "mounts I recorded" — plausibly
  by walking the target's mount table and unmounting anything over the system paths. Write down what
  you observed and on which version. That is a genuine, dated, measured fact, which is worth more
  than a confident claim from a forum post.

Either way, do not generalise from one device and one version. This is exactly the class of claim
that decays: see [`../references/README.md`](../references/README.md) on version-specific assertions.
</details>

<details>
<summary>Solution C — attack condition A instead, and keep the module</summary>

Turn DenyList **off**, so the module's overlay stays mounted and condition B is satisfied normally.
Now condition A fails — because the app can see Magisk's mounts.

But condition A is not a kernel query. It is a **file read**, of `/proc/self/mountinfo`. Files can be
mounted over, including procfs files, and `/proc/self/mountinfo` for the app resolves to
`/proc/<pid>/mountinfo`.

```bash
# adb shell as root
am start -n com.magisklab.vault/.MainActivity
sleep 2
PID=$(pidof -s com.magisklab.vault)

# Build a sanitised copy of the app's own mount table.
mkdir -p /data/local/tmp/.prov
grep -viE 'magisk|/data/adb|worker|debug_ramdisk|core/mirror|core/img' \
    /proc/$PID/mountinfo > /data/local/tmp/.prov/mountinfo
chcon u:object_r:proc_file:s0 /data/local/tmp/.prov/mountinfo 2>/dev/null || true
chmod 0444 /data/local/tmp/.prov/mountinfo

# Mount it over the app's view of its own mount table.
nsenter --mount=/proc/$PID/ns/mnt -- \
    mount --bind /data/local/tmp/.prov/mountinfo /proc/$PID/mountinfo

nsenter --mount=/proc/$PID/ns/mnt -- \
    grep -icE 'magisk|/data/adb|worker' /proc/$PID/mountinfo      # expect 0
```

Tap **Open Vault**. Both conditions now hold, and the vault opens.

**Why this is the most interesting of the three.** It inverts the whole problem. Solutions A and B
give the app something true that it could not otherwise see; this one gives it something false about
itself. Note the exact reason it works: the app trusts `/proc` to be `/proc`, and `/proc` is a
filesystem like any other, mounted at a path like any other, in a namespace you control.

**Note the label caveat honestly.** Relabelling a file to a procfs type may not be permitted on your
device, and the `|| true` above is there because of that. If the app gets `EACCES`, read the denial
and decide whether a different source label works. If none does, this route is closed on that device
and you should say so rather than claim it as a general technique.
</details>

<details>
<summary>Solution D — Frida (allowed only as your second solve)</summary>

```javascript
// frida -U -f com.magisklab.vault -l solve-d.js --no-pause
Java.perform(function () {
    var V = Java.use('com.magisklab.vault.Vault');
    // Both private static methods are hookable exactly like any others.
    V.namespaceLooksClean.implementation = function () { return true; };
    V.readProvisionToken.implementation = function () { return '<the token>'; };
});
```

It works, it takes ninety seconds, and it is the wrong answer *for this lab* — not because it is
inelegant, but because it answers a different question. You have not defeated the mount check; you
have replaced the code that performs it. That is chapter 37's and chapter 53's technique, and it
generalises to any client-side check whatsoever, which is precisely why it teaches you nothing
specific about mount namespaces.

Two things it does teach, which the debrief asks about: it requires Frida on the device (itself
detectable), and it needs the token, which means you still had to obtain the token from somewhere —
so it is not a complete solution on its own, it is a completion of one.
</details>

---

## Debrief questions

Answer in writing. These are the point of the lab.

1. Write the one-sentence rule for what DenyList removes. Then write the one-sentence corollary about
   what it does not. Your corollary should make Solution A obvious to a reader who has never seen it.
2. In Solution A, why must the app be started **before** the mount? Give the failure mode of doing it
   the other way round, precisely.
3. Your mount was visible in `/proc/<pid>/mountinfo` and not in `/proc/1/mountinfo`. Explain, in
   terms of mount propagation, why creating a mount inside an app's namespace does not leak into
   init's — and say what would have happened if the namespace had been created with shared
   propagation instead.
4. The SELinux label was not optional. State what a bind mount does and does not change about a file,
   and why that means `chcon` is part of the mount and not an afterthought.
5. Condition A is a substring scan of `mountinfo` against a fixed dirty-list. Rewrite the check so
   that Solution A no longer defeats it. Then rewrite it again so that Solution C no longer defeats
   it. Which of the two is harder, and why?
6. The app re-reads both inputs on every button press. Change the design so that it does not, and
   state exactly which of the four solutions each design change breaks. What does the developer pay
   for that robustness?
7. Rank solutions A, B, C and D by (a) speed on this target, (b) reusability against the next target,
   (c) how much of your understanding they demonstrate, (d) how likely they are to be detected by an
   app that also looks for Frida.
8. Solution C mounts a file over `/proc/<pid>/mountinfo`. Name two other files an app trusts to be
   authoritative that could be attacked the same way, and one that could not — and say what makes the
   third one different.
9. You are writing this up for the vendor. In two sentences, tell them what their control is worth.
   Be accurate: it is not worthless, and it is not sufficient. Then say which of the two conditions
   is doing the real work, and what you would tell them to do instead of the other one.
10. This lab's control could have been implemented server-side: the vendor issues the token after an
    attested check, and the vault content comes from the server. State what that changes, and what it
    does not.

---

## Success criteria

- [ ] You built the app, the module and the ciphertext yourself
- [ ] You reproduced all three failure states and measured each, rather than trusting the table
- [ ] You can quote the numbers that show which condition failed in each state
- [ ] You explained why the same path gives different answers in two namespaces
- [ ] You used `ns-diff.sh` (or the equivalent by hand) to enumerate what DenyList removed, and
      identified the `hosts` mount's source fields
- [ ] You created a mount inside the app's namespace and confirmed it did not appear in init's
- [ ] You hit the SELinux denial, read it, and fixed it with `chcon` rather than `setenforce 0`
- [ ] You opened the vault on a rooted device and recorded the flag
- [ ] You solved it a **second** time by a different mechanism
- [ ] For Solution B, you **measured** whether the module's own bind mount survived DenyList on your
      Magisk version, and recorded the version alongside the result
- [ ] You can state why Solution D, though fastest, is the wrong first answer here
- [ ] You wrote the improved version of condition A that defeats your own solution
- [ ] You answered all ten debrief questions in writing
- [ ] You cleaned up: mounts unmounted, staged files removed, DenyList and modules returned to a
      known state, and the device record updated

---

## Note for instructors

The pedagogical goal is **not** the flag. It is the moment a participant realises that the two
controls are not independent, and that the dependency is a fact about the Linux kernel rather than
about the application.

Run it in this order:

1. Give participants the APK and the module, and the sentence *"the vendor says this device is
   provisioned; the app disagrees."* Do not mention DenyList.
2. Let them find their way to installing the module. Let them find their way to DenyList. Let them
   do both. The twenty minutes after "both" is where the learning happens, and it should be
   uncomfortable.
3. Bring them back with one question: *"Who made the mount that DenyList removed?"* Almost everyone
   gets it from there.

Participants who reach for Frida within the first ten minutes should be required to solve it
mechanically as well, and the comparison in debrief question 7 is where that consolidates.

Two honest disclosures to make to the group at the end:

- **The flag was always on their device.** It is a blob in the APK and a token in the module, and any
  participant could have computed it on the host in a minute. The rules forbid it because the lab is
  about the mount, not the secret — but the deeper point is the same one chapter 37's CTF ends on:
  client-side decryption of a client-side blob protects nothing. Debrief question 10 is where to land
  that.
- **Solution B's outcome is version-dependent, and that is the lesson, not a defect.** Magisk changes
  fast. A participant who writes "it survived on Magisk 27.0 on this device on this date" has learned
  something more durable than one who memorises an answer, because the memorised answer expires and
  the habit of measuring does not.
