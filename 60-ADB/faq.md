# 60 — ADB FAQ

Real questions, including the ones people are embarrassed to ask. Answers are measured on the
devices described in [README.md](README.md) wherever a number appears.

---

### 1. What is `adbd`, in one paragraph?

`adbd` is a native program that runs on the Android device from boot until shutdown, and implements
the device end of the ADB protocol. `init` starts it when the `sys.usb.config` property contains
`adb`, which happens when the Developer Options toggle sets `Settings.Global.ADB_ENABLED`. On a
production build it runs as UID 2000 (`shell`) in the SELinux domain `adbd`, with no effective Linux
capabilities. Since Android 11 it lives inside the `com.android.adbd` APEX rather than at
`/system/bin/adbd`, so Google can update it without an OS release. Everything you do "over adb"
happens either inside that process or in a child it forked.

Prove it yourself in one command — the parent of your shell is `adbd`:

```bash
# adb shell
cat /proc/$(cut -d" " -f4 /proc/$$/stat)/cmdline | tr '\0' ' '
# /apex/com.android.adbd/bin/adbd --root_seclabel=u:r:su:s0
```

---

### 2. There are three things called "adb". Which is which?

| Name | Where it runs | What it does |
|---|---|---|
| The `adb` **client** | your workstation | the binary you type; connects to the server and exits |
| The `adb` **server** | your workstation, `127.0.0.1:5037` | owns the USB connection, holds your key, multiplexes every client |
| **`adbd`** | the device | the daemon that answers |

The client never touches USB. When you run `adb devices`, the client asks the *server*, and the
server answers from its own table. That is why `adb kill-server` fixes so many problems and why two
different SDK versions on one machine fight each other — there can only be one server on port 5037.

---

### 3. Why does my device say "unauthorized"?

Because the handshake got as far as authentication and stopped. In detail:

1. Your `adb` server sent `A_CNXN`.
2. `adbd` replied `A_AUTH(TOKEN)` with 20 random bytes, because `ro.adb.secure=1`.
3. Your server signed the token with `~/.android/adbkey` and sent `A_AUTH(SIGNATURE)`.
4. `adbd` compared it against every key in `/data/misc/adb/adb_keys` and none matched.
5. So it sent a **new** `A_AUTH(TOKEN)` — there is no "auth failed" message in the protocol.
6. Your server ran out of keys and sent `A_AUTH(RSAPUBLICKEY)`, which raises the dialog on the
   device.
7. Until a human taps Allow, `A_CNXN` never completes, so the device shows as `unauthorized`.

Common causes: a new workstation; a deleted or regenerated `~/.android/adbkey`; a factory reset;
somebody pressed "Revoke USB debugging authorizations"; the Android 11+ seven-day idle expiry fired;
or the device's screen is locked and the platform is suppressing the dialog.

The one that catches people: **the dialog will not appear if you never look at the phone.** Unlock
it and check.

---

### 4. What is the difference between `unauthorized` and `offline`?

`unauthorized` means step 6 above — the device is talking to you and waiting for consent.
`offline` means `A_CNXN` never completed at all: the transport is up but the session is not. Causes
include `adbd` restarting mid-handshake (which `adb root`, `adb tcpip` and `adb usb` all do), a
device still booting, or a version mismatch the client refused.

---

### 5. What is the difference between `adb root` and `su`?

They are unrelated mechanisms that happen to produce root.

`adb root` sends the service string `root:` to `adbd`, which **restarts itself as UID 0** — but only
if `ro.debuggable=1`, which means a `userdebug` or `eng` build. Everything you subsequently do over
ADB is root, because `adbd` itself is root. On a retail phone you get:

```
$ adb root
adbd cannot run as root in production builds
```

`su` is a separate binary installed by a rooting solution such as Magisk. `adbd` stays at UID 2000;
you run `su` *inside* a normal shell and only the command you give it runs as root.

They also land in different SELinux domains, which matters more than people expect. Measured on an
emulator:

```
$ adb root && adb shell 'ps -A -o USER,LABEL,NAME | grep adbd'
root  u:r:su:s0  adbd
```

A rooted `adbd` is in `u:r:su:s0`, not `u:r:adbd:s0`. That domain name comes from the
`--root_seclabel=u:r:su:s0` argument `init` passes it.

---

### 6. Why can `adb` read files my app cannot?

Because `adb shell` is not an app, and because UID 2000 is a privileged identity.

Two separate things are going on.

**It is not an app.** Your shell's parent is `adbd`, not `zygote`. There is no ART runtime, no
`Application` object, no package record — and therefore **no `targetSdkVersion`**. Every behaviour
change Android gates on `targetSdk` (scoped storage, background service limits, non-SDK interface
restrictions) does not apply to a process with no package.

**It is privileged.** UID 2000 is shared with `com.android.shell`, a `PRIVILEGED` system package in
`/system/priv-app/Shell`. Framework permission checks are made against the *UID*, so the `sh`
process inherits everything that package was granted. Measured on a stock API 30 device: 200
requested permissions, **183 install permissions granted**, and **16 runtime permissions
pre-granted with `SYSTEM_FIXED`** — including `CAMERA`, `RECORD_AUDIO`, `READ_SMS` and
`ACCESS_BACKGROUND_LOCATION`. `SYSTEM_FIXED` means the user cannot revoke them.

Contrary to a common belief, this does **not** come from `platform.xml`. The entire `platform.xml`
grant to `shell` on that device is one line:

```xml
<assign-permission name="android.permission.INTERNET" uid="shell" />
```

Everything else is `com.android.shell`'s own manifest.

**The consequence for testing:** anything you demonstrate from `adb shell` is evidence about
`shell`, not about an attacker's app. Reproduce it from a third-party APK at a `u0_aNNN` UID before
you write it up.

---

### 7. Is ADB over wifi safe?

It depends which "over wifi" you mean, and the two are completely different.

**`adb tcpip 5555` is not safe on any network you do not control.** The transport is **cleartext**.
The RSA handshake authenticates the host at connect time and protects nothing afterwards — no
encryption, no integrity, no channel binding. Anyone who can reach the port can attempt to connect,
and anyone who can see the traffic can read your entire session. On a device where `ro.adb.secure=0`
they do not even need a key.

**Wireless debugging (`adb pair`, Android 11+) is genuinely reasonable.** It runs over TLS 1.3 with
mutual certificate authentication, the certificates are enrolled through a SPAKE2 exchange keyed on
a six-digit code shown on the device, and the port is random and advertised over mDNS.

Either way, turn it off when you are done. mDNS advertisement means a debuggable
device announces itself to the whole local network — worth knowing before you enable it in a
client's office.

---

### 8. What does "Always allow from this computer" actually save?

Your host's **RSA public key**, appended as one line to `/data/misc/adb/adb_keys` by
`AdbDebuggingManager` inside `system_server`, plus an entry in
`/data/misc/adb/adb_temp_keys.xml` carrying a `lastConnection` timestamp in epoch milliseconds.

Measured on the test device:

```
-rw-r----- 1 system shell u:object_r:adb_keys_file:s0  714 ... adb_keys
-rw------- 1 system shell u:object_r:adb_keys_file:s0  854 ... adb_temp_keys.xml
```

714 bytes is exactly one key: a 700-character base64 blob, a space, a comment, and a newline. The
blob decodes to 524 bytes — a `mincrypt` `RSAPublicKey` struct with a 64-word (2048-bit) modulus and
exponent 65537.

The important part is what this *is*: **a permanent, transferable credential**. It authenticates a
file on your laptop — `~/.android/adbkey`, an unencrypted private key with no passphrase — not a
person and not a computer. Copy that one file and you have inherited every device that ever trusted
you.

Since Android 11 it expires after an idle period, controlled by
`Settings.Global.ADB_ALLOWED_CONNECTION_TIME` (default seven days).

---

### 9. Can I see which computers my phone has authorised?

Not from `adb shell`, and not from the UI. There is no screen anywhere in Android that lists them —
the only control is the all-or-nothing "Revoke USB debugging authorizations".

From `adb shell` you are stopped by SELinux, not by file permissions. Measured:

```
$ adb shell 'cat /data/misc/adb/adb_keys'
cat: /data/misc/adb/adb_keys: Permission denied

$ adb shell 'ls -ld /data/misc/adb'
ls: /data/misc/adb: Permission denied
```

The directory is `02750 system shell` — the group *is* `shell` and the group read bit *is* set — so
DAC would allow it. The kernel log shows what actually refused:

```
avc: denied { search } for comm="cat" name="adb" ino=240
     scontext=u:r:shell:s0 tcontext=u:object_r:adb_keys_file:s0 tclass=dir permissive=0
```

This is one of the cleanest demonstrations of SELinux overriding Unix permissions you will find on a
phone. With root you can read it. Without root, any tool that claims to list authorised keys is
reading something else or making it up.

---

### 10. Is `adb shell` a "root shell"? People keep saying it is.

No, and the confusion is worth unpicking because both halves of the popular belief are wrong.

It is not root: `id` says `uid=2000(shell)`, `CapEff` is zero, and SELinux confines it to
`u:r:shell:s0`. It cannot read another app's `/data/data` directory.

But it is also **far more privileged than any app** — 183 install permissions, 16 non-revocable
runtime permissions, and no `targetSdkVersion` to restrict it. "Not root" does not mean "harmless".

The accurate sentence is: *`adb shell` is a non-root, non-app identity with system-adjacent
platform privileges.* Which is exactly why it is a security-relevant thing to leave reachable.

---

### 11. Why is the checksum in the header always zero?

Because nothing computes it and nothing checks it. `protocol.txt` in AOSP calls the field a CRC32;
the implementation sums the payload bytes; and since protocol version `0x01000001` neither side
verifies it. Measured — every message this chapter's client received from `adbd`, including a
395-byte banner, carried `data_check = 0x00000000`.

Do not use it for integrity. There is no integrity protection on an ADB connection at all; that is
what the TLS upgrade (`A_STLS`) exists to provide, and it is only used for wireless debugging.

---

### 12. What is `magic` for, then?

Framing. It is `command ^ 0xffffffff`, so a receiver that has lost byte alignment notices
immediately rather than reading garbage as a header. It is not a checksum and has no security value
— an attacker who can write to the connection can compute it as easily as you can.

It is, however, extremely useful when *you* are parsing: a 24-byte buffer whose command is one of
the eight known values **and** whose magic is the complement is a header with near-certainty. That
is how the Frida script in this chapter distinguishes headers from payload.

---

### 13. How does `adb install` actually work? Is it a special message?

No. There is no install message type. `adb install` is the client running three ordinary commands
over three ordinary streams:

```
exec:cmd package install-create -r -S 8538      -> Success: created install session [1648417046]
exec:cmd package install-write -S 8538 1648417046 base -    (APK travels as A_WRTE payloads)
                                                -> Success: streamed 8538 bytes
exec:cmd package install-commit 1648417046      -> Success
```

That transcript is real — [`scripts/adb-install-transport.py`](scripts/adb-install-transport.py)
produced it with no `adb` binary involved, and `pm path` afterwards confirmed the package.

Between write and commit there is a real staging directory the package manager will not show you:

```
$ adb shell su 0 ls -l /data/app/vmdl1672322717.tmp
-rw-r--r-- 1 system system 8538 ... base
```

On Android 11+ with the `abb_exec` feature the same three commands go with NUL-delimited arguments
and no device-side shell at all.

---

### 14. `adb install` fails with `INSTALL_FAILED_USER_RESTRICTED` but `su -c 'pm install'` works. Why?

Because the transport is not what refused you. Every byte arrived; `install-write` returned
`Success: streamed N bytes`. What failed was `PackageManagerService`'s decision, and on this
repository's MIUI test device that decision is an OEM policy keyed on the *caller's identity* —
UID 2000 is gated, UID 0 is not.

Neither `settings put global verifier_verify_adb_installs 0` nor `pm install -i com.android.shell`
changes it. The fix on that device is to run the install as root:

```bash
adb push app.apk /data/local/tmp/app.apk
adb shell "su -c 'pm install -r /data/local/tmp/app.apk'"
```

The general lesson: read *which* of the three streams failed. Transport failures and package-manager
failures look nothing alike once you know to look.

---

### 15. Why did `adb shell cat file.bin > out.bin` corrupt my file?

Because `shell:` allocates a pseudo-terminal, and a PTY's line discipline translates every `\n`
(`0x0a`) into `\r\n` (`0x0d 0x0a`). Any byte sequence containing `0x0a` comes out longer and wrong.

Use `adb exec-out cat file.bin > out.bin`. `exec:` is a raw bidirectional stream with no PTY. On a
device advertising `shell_v2` you can also use the `shell,v2,raw:` service, which additionally gives
you separated stdout/stderr and a real exit code.

This is a genuine data-integrity trap in forensic work: a "pulled" file that silently differs from
the original.

---

### 16. Why does `adb shell false; echo $?` print 0?

Because the v1 `shell:` service **does not transmit an exit code at all**. It has no field for one.
The `adb` client works around it on old devices by appending `; echo $?` to your command and parsing
the trailing number, which is fragile and was the cause of years of quietly broken CI scripts.

The `shell_v2` feature (Android 7.0 / API 24) added a packet format inside the `A_WRTE` payload
with an id byte, and packet id `3` carries the exit status. Measured:

```
shell:echo hi          payload = 68 69 0a                  ("hi\n", no framing, no status)
shell,v2,raw:echo hi   payload = 01 03 00 00 00 68 69 0a   (id 1 = stdout, length 3, "hi\n")
                       then a second packet with id 3 carrying the exit code
```

---

### 17. I advertised `shell_v2` in my banner and the framing did not change. Why?

Because the banner advertises a **capability** and the service string selects the **behaviour**.
Advertising `shell_v2` tells the peer you *can* speak the v2 framing; you then have to ask for it by
opening `shell,v2,raw:cmd` instead of `shell:cmd`. Measured both ways in the same minute against the
same device, with `shell_v2` advertised in both cases — `shell:echo hi` still returned raw bytes.

---

### 18. Why does my hand-written client hang or get disconnected?

Almost always one of three things:

1. **You sent two `A_WRTE`s without waiting for the `A_OKAY`.** ADB's flow control is a window of
   exactly one message per stream. Send a second before the first is acknowledged and a strict peer
   drops the connection.
2. **You assumed the next message answers the request you just sent.** `adbd` interleaves streams,
   and the `A_CLSE` that ends stream 1 can arrive *after* you have sent the `A_OPEN` for stream 2.
   Demultiplex on `arg1` — your own local id, echoed back. This was a real bug in this chapter's own
   installer before it was fixed.
3. **You forgot the NUL terminator on the service string.** `A_OPEN`'s payload is a C string.

---

### 19. Can I speak the protocol to my phone over USB from Python?

Not with this chapter's client, and the reason is worth understanding. Over USB the transport is
FunctionFS bulk endpoints, reached through your operating system's USB host stack — and the
interface is already claimed exclusively by your running `adb` server. Talking to it needs libusb,
an exclusive claim, and platform-specific driver arrangements.

**The messages are byte-identical over both transports**, which is why TCP is the right place to
learn them. An emulator always listens on TCP (`127.0.0.1:5555` for `emulator-5554`), costs nothing,
and can be thrown away. Use one.

Do **not** run `adb tcpip` on a phone you care about just to try this.

---

### 20. Is "USB debugging is enabled" a finding?

On its own, no — and writing it up as one is a fast way to lose a reviewer's attention. It becomes a
finding when it is combined with something:

| Situation | Rating |
|---|---|
| Your own test device | not a finding; a methodology note |
| A user's phone, screen locked, authentication on | informational |
| No screen lock, device unattended | medium — thirty seconds of physical access is a shell |
| `adb tcpip` on a corporate or public network | medium/high |
| ADB over TCP with `ro.adb.secure=0` | **critical** — unauthenticated remote shell |
| Any of the above on a kiosk, till, TV or head unit | **critical** — nobody will notice or reboot it |
| `ro.debuggable=1` shipped | high — the remote shell becomes a remote *root* shell |

Always state the **device role** you assumed. [`scripts/adb-posture.sh`](scripts/adb-posture.sh)
prints the evidence and makes you commit to one.

---

### 21. Is port 5037 on my laptop a risk?

Yes, and it is under-discussed. The `adb` server listens on `127.0.0.1:5037` with **no
authentication of any kind**. Any process running as your user can connect to it and drive every
attached device — no key theft required, no prompt, no log.

Stealing `~/.android/adbkey` is the persistent version of the same problem: that file is an
unencrypted private key that authenticates to every device you have ever authorised, from any
machine.

The mitigations are unglamorous: do not run untrusted code on the machine that holds your test
devices; use full-disk encryption; and rotate the key when a laptop is decommissioned.

```bash
# host — rotate, then re-authorise the devices you still own
mv ~/.android/adbkey ~/.android/adbkey.retired
mv ~/.android/adbkey.pub ~/.android/adbkey.pub.retired
adb kill-server && adb devices
```

---

### 22. Why can't I find `/system/bin/adbd` on my device?

Because since Android 11 it is in the `com.android.adbd` APEX:

```
$ adb shell ls -l /system/bin/adbd
ls: /system/bin/adbd: No such file or directory
$ adb shell "su -c 'readlink /proc/\$(pidof adbd)/exe'"
/apex/com.android.adbd/bin/adbd
```

The `init` service definition still names `/system/bin/adbd`, but carries the keyword `updatable`,
which tells `init` to resolve it through the APEX mount. The practical consequence: `adbd` can be
patched by a Mainline update without a full OS release, so "this device is on an old security patch
level" does not by itself tell you `adbd` is unpatched.

---

### 23. What is `abb`, and why did Android add it?

`abb` is the Android Binder Bridge, added in Android 11. It removes the device-side shell from the
path for `cmd`-based operations: the arguments travel **NUL-delimited inside the service string**
and go straight into the `cmd` infrastructure over Binder, so nothing is ever word-split or
dequoted.

That matters because `exec:` runs your command through `sh -c`, and a device-side shell will
happily mangle it. This repository has already been bitten once: a printed script sent
`su -c "ls -ldZ /data/…"` and the device shell delivered `su -c ls -ldZ /data/…`, so `su -c` ran only
`ls`.

`abb:` uses the shell-v2 packet framing (so you get an exit code); `abb_exec:` is a raw byte stream.
Modern `adb install` uses `abb_exec` whenever the banner advertises it.

One practical gotcha: **argv cannot carry a NUL byte**, so a tool cannot accept the raw `abb`
service string on its command line. Build the delimiters inside the program.

---

### 24. What is `$ADB_VENDOR_KEYS`, and why should I care?

It is an environment variable naming additional private keys the `adb` client will try during
authentication. It exists so that OEMs and CI systems can use a provisioning key without touching
`~/.android/`.

The security-relevant half is the device side. Some vendor images ship a **pre-authorised public
key at `/adb_keys` on the ramdisk**, so a factory host can connect to any unit with no dialog. If
that key ever leaks, every device from that vendor with that image is authenticated to whoever holds
it. Look for it in a firmware dump:

```bash
find extracted/ -name adb_keys
grep -rl 'QAAA' extracted/ | head    # every 2048-bit adb public key starts QAAA
```

That `QAAA` trick works because the first field of the key struct is the modulus size in words,
always 64 for RSA-2048, so the base64 always begins the same way.

---

### 25. The token is 20 bytes and the signature is "over SHA-1". What is actually hashed?

Nothing. That is not a typo.

The host calls OpenSSL's `RSA_sign(NID_sha1, token, 20, ...)`. `RSA_sign` with a digest NID expects
an **already-computed digest** — it prepends the ASN.1 DigestInfo prefix for that algorithm and
applies PKCS#1 v1.5 padding. Because the token happens to be 20 bytes, the size of a SHA-1 digest,
it is fed straight in.

So the device verifies a signature over `SHA1-DigestInfo || <20 random bytes nobody hashed>`. It
works, it is not a weakness (the value being signed is a fresh random challenge, which is the whole
point), and it surprises everyone who reads the code for the first time. This chapter's client
implements exactly that and interoperates with real `adbd`.

---

### 26. My `adb` connection drops whenever I run a certain command. What happened?

Check whether the command restarts `adbd`. `adb root`, `adb unroot`, `adb tcpip`, `adb usb` and
`adb remount` all do, and the restart tears down every stream including the one you are typing into.
That is expected behaviour, not a fault, and `adb wait-for-device` is the correct way to script
around it.

If it drops with no such command, suspect the device's USB enumeration (a marginal cable is the
single most common cause of `device not found` in the wild) or a hook you attached to `adbd`.

---

### 27. Should I trust the banner a device sends me?

No. It is a string the peer chose. `ro.product.name`, `ro.product.model`, `ro.product.device` and
the feature list are all self-reported and trivially forged — a honeypot can claim to be a Pixel.

It is still useful: on an endpoint that requires no authentication you get it *before* doing
anything else, which makes it excellent for fast reconnaissance and for spotting inconsistency (a
"Pixel" advertising a feature set that no Pixel build ships is worth a second look).
