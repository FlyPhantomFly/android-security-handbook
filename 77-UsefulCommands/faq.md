# Useful Commands — FAQ

Real questions, answered directly. Including the ones people are embarrassed to ask.

---

**1. `adb devices` says "unauthorized". What now?**

The device has not accepted your workstation's RSA key. Unlock the screen and look for the "Allow USB
debugging?" dialog. If it never appears, revoke existing authorisations in Developer Options, unplug,
replug, and run `adb kill-server && adb devices`. If the dialog still does not appear, the screen may
be locked (Android will not show it on a locked screen) or the cable may be charge-only.

---

**2. `adb devices` shows nothing at all.**

In order: try a different cable (most "broken ADB" is a charge-only cable), check that USB debugging
is enabled in Developer Options, run `adb kill-server && adb start-server`, and on Windows check
Device Manager for a missing ADB driver. On Linux, add a udev rule for the vendor ID.

---

**3. Why does `adb root` say "adbd cannot run as root in production builds"?**

Because your device runs a `user` build. `adbd` only honours the request when `ro.debuggable` is 1,
which is true only on `userdebug` and `eng` builds. On a retail phone you get root through Magisk
instead, and then use `su` inside a normal `adb shell`. `adb root` and Magisk root are different
mechanisms — Magisk does not make `adb root` work.

---

**4. I have root through Magisk but `adb shell ls /data/data` still says permission denied.**

`adb shell` starts as UID 2000. Root is available but not automatic. Either run
`adb shell "su -c 'ls /data/data'"` — the **outer** quotes matter, because `adb shell` joins its
arguments with spaces before the device sees them — or run `adb shell` and then type `su` to elevate
the interactive session. If `su`
succeeds but you still get denied, you are hitting SELinux rather than DAC — check with `getenforce`
and see [22-SELinux](../22-SELinux/README.md).

---

**5. What is the actual difference between `adb forward` and `adb reverse`? I always mix them up.**

Think about which machine grows a new listening port.

`adb forward tcp:27042 tcp:27042` opens port 27042 **on your laptop**. Connecting to it reaches port
27042 on the device. You use this to reach `frida-server`.

`adb reverse tcp:8080 tcp:8080` opens port 8080 **on the device**. The app connecting to
`127.0.0.1:8080` reaches port 8080 on your laptop. You use this to point the app at Burp when there
is no network route between the two.

Mnemonic: *forward* pushes you forward onto the device; *reverse* brings the device back to you.

---

**6. I set the proxy with `settings put global http_proxy` but Burp sees nothing.**

Four common causes, in order of likelihood. The app uses OkHttp with an explicit `Proxy.NO_PROXY` or
a custom `ProxySelector`. The app uses Cronet, gRPC, or a native HTTP stack that never consults the
system proxy setting. The app pins certificates, the handshake fails, and it silently retries or
degrades. The traffic is not HTTP at all. Confirm which by dropping to packet capture with `tcpdump`,
because packet capture does not care about application-level conventions. See
[35-SSL](../35-SSL/README.md) and [36-CertificatePinning](../36-CertificatePinning/README.md).

---

**7. `frida-ps -U` returns "unable to connect to remote frida-server".**

Check, in order: is `frida-server` actually running (`adb shell "su -c 'ps -A | grep frida'"`); does
its version match your host `frida --version` exactly; is it the right architecture for the device
(`getprop ro.product.cpu.abi`); is it executable (`chmod 755`). Version mismatch is by far the most
common cause and produces error messages that look like connection problems.

---

**8. I patched an APK with apktool and now it will not install.**

Almost always one of three things. You did not re-sign it — every modified APK must be signed again,
because you invalidated the original signature. You signed before aligning — `zipalign` must run
first. Or the app has a `minSdkVersion`/`targetSdkVersion` that the device rejects. Run
`apksigner verify -v` on your output and read the error; `adb install` also prints a reason code,
and `adb logcat` during the install attempt gives the full story.

---

**9. Why does my repackaged app crash immediately when the original works fine?**

Either apktool could not faithfully rebuild the resources (common with heavily obfuscated or
protector-wrapped apps — try `apktool d --only-main-classes` or work at the Smali level only), or the
app has tamper detection and is killing itself because its signature changed. See
[38-TamperDetection](../38-TamperDetection/README.md). Check logcat during the crash; a tamper check
usually leaves a distinctive log line or a very early `System.exit`.

---

**10. Is `am start` working on a non-exported activity a vulnerability?**

No. This is the single most common false positive in junior Android reports. The `shell` user holds
privileges an ordinary app does not, and can start components a normal app cannot. To claim
reachability you must reproduce it from an ordinary third-party UID — write a minimal test app that
calls `startActivity()`, or use a tool that runs as a normal app. Put both results in the report.

---

**11. How do I read an app's private files without root?**

If the app is `debuggable`, `run-as <pkg>` gives you a shell running as that app's UID, and from
there you can read and tar the whole data directory. If it is not debuggable, your options are root,
a backup (if `allowBackup` is true and the platform still permits `adb backup`), or repackaging the
app with `debuggable="true"` and re-signing — which changes the signature and may trip tamper
detection.

---

**12. What is the fastest way to find out which Activity class the screen I am looking at belongs to?**

```bash
adb shell dumpsys window | grep mCurrentFocus
```

That one line is worth more than any amount of clicking through JADX looking for layout names.

---

**13. `logcat` is a firehose. How do I see only my target app?**

```bash
adb logcat --pid=$(adb shell pidof -s com.example.target)
```

Clear the buffer first with `adb logcat -c`, then reproduce the behaviour. If the app spawns several
processes via `android:process`, `pidof` returns several PIDs — use `pidof` without `-s` and filter,
or use `adb logcat | grep` on the process name.

---

**14. Can an app read other apps' logs?**

Not since Android 4.1. An app only sees its own log output unless it holds `READ_LOGS`, which is a
privileged permission not available to normal apps. This matters for severity: "sensitive data in
logcat" is a real finding, but its impact depends on who can read the log — a rooted device, a
debuggable app, a device with an installed log-collecting app, or a crash reporter that uploads logs
off-device. Say which in your report rather than defaulting to High.

---

**15. What does `service call` actually do, and when would I use it?**

It sends a raw Binder transaction to a named system service with a transaction code you supply.
Transaction codes are sequential integers assigned in AIDL declaration order starting at 1. If you can
read an AIDL interface — from AOSP or reconstructed from a decompiled `Stub` class — you can invoke
any method on any service by hand with no code at all. Use it when you need to reach a service method
that has no command-line front end. See [25-Binder](../25-Binder/README.md).

---

**16. Emulator or physical device?**

Emulator for speed, snapshots, and easy root; physical device for anything involving hardware-backed
keys, biometrics, real sensors, Play Integrity, or an app that refuses to run under emulation. Most
professionals keep both. Start on the emulator, and move to hardware the moment the app's behaviour
becomes suspicious — because emulator detection often disables features silently rather than showing
an error. See [39-EmulatorDetection](../39-EmulatorDetection/README.md).

---

**17. Which commands should I never run on a client's device?**

`pm clear` (wipes app data and your evidence), `content delete`/`content update` on production data,
`fastboot` anything (destroys the device), `adb tcpip` on an untrusted network, and `pm uninstall`.
Also avoid `am force-stop` before you have captured process memory if you might need it. When in
doubt, snapshot first.

---

**18. Why is `zipalign` before `apksigner` and not after?**

Signing computes digests over the final bytes of the archive. `zipalign` rewrites the archive to move
entries onto alignment boundaries, which changes those bytes. Align first, sign second, and the
signature covers the aligned file. Do it the other way round and verification fails.

---

**19. What is the minimum I should record about a device before starting an engagement?**

The build fingerprint, Android release and API level, security patch level, CPU ABI, verified boot
state, whether the bootloader is unlocked, whether the device is rooted and how, and the exact
versions of your own tooling. Without these, a finding cannot be reproduced six months later and a
developer can legitimately dispute it.

---

**20. Everything worked yesterday and nothing works today. Where do I start?**

`adb kill-server && adb start-server`, then `adb devices`. Then check that `frida-server` is still
running (it does not survive a reboot unless you made it), that the proxy setting survived (it does
not survive a factory reset or some OS updates), and that the app did not update itself in the
background to a new version. In that order. It is almost always one of those four.
