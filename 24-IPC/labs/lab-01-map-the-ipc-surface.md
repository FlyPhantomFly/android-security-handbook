# Lab 01 — Map the IPC Surface

**Difficulty:** Beginner
**Time:** 90–120 minutes
**Prerequisites:** [Chapter 24 §1–§3.13 and §3.22](../README.md), [21-App-Sandbox](../../21-App-Sandbox/README.md),
[23-Permissions](../../23-Permissions/README.md), a test device or emulator with `adb`

---

## Objective

Produce a complete, evidence-backed inventory of one application's IPC surface — **including the four
categories the manifest cannot show you** — and then classify every entry as *reachable by an
ordinary app*, *reachable only from the shell*, or *not reachable*.

You will finish with two artefacts: an inventory table, and a reachability table. The second one is
the one that matters.

## Why this matters

Ask ten testers to enumerate an app's attack surface and nine will hand you the exported-components
table from `dumpsys package` or MobSF. That table describes **mediated** IPC only: Intents, bound
services, broadcasts and providers. It is roughly half the surface.

The other half — abstract-namespace UNIX sockets, localhost listeners, shared memory, and file modes
— appears in no manifest, in no `aapt2 dump badging` output, and in no manifest-driven scanner. It is
where a large share of the genuinely interesting findings live, precisely *because* the tooling is
structurally blind to it.

This lab builds the habit of asking, every single time: **what channels exist that the manifest
cannot tell me about?**

It also drills the discipline that the rest of the chapter depends on. Everything you enumerate here
comes from `adb shell`, which runs as UID 2000 with privileges an app does not have. Enumeration
proves a channel *exists*. It never proves an attacker can *use* it.

---

## Setup

### Choose a target

Use a deliberately vulnerable app you are authorised to test — InsecureBankv2, OVAA, DIVA or Injured
Android from [80-Appendix](../../80-Appendix/README.md) are all rich enough. Any app you wrote
yourself also works.

Do **not** use a banking app you did not write, and do not use anything on a device with real data.

```bash
# host
export PKG=com.example.target
adb devices
adb shell pm path $PKG
```

### Get the APK and decompile it

```bash
# host
adb pull "$(adb shell pm path $PKG | head -1 | sed 's/package://' | tr -d '\r')" target.apk
apktool d -f target.apk -o work/ >/dev/null
jadx -d out/ target.apk >/dev/null 2>&1
```

### Launch the app before you enumerate

This step is skipped constantly and it invalidates everything after it.

```bash
# host
adb shell monkey -p $PKG -c android.intent.category.LAUNCHER 1
sleep 8
```

Sockets are usually opened **lazily** — on first playback, first WebView load, first sync. A socket
that has not been created yet does not appear in `/proc/net/unix`, and you will record "no sockets"
for an app that has three.

---

## Steps

### Step 1 — Record the ground truth

```bash
# host
aapt2 dump badging target.apk | grep -E "package:|sdkVersion|targetSdkVersion"
apksigner verify --print-certs target.apk | grep -i "SHA-256"
adb shell getprop ro.build.version.release
adb shell getprop ro.build.version.sdk
adb shell getprop ro.build.version.security_patch
adb shell getprop ro.build.fingerprint
adb shell getenforce
```

**Q1.** What is the app's `targetSdk`? Name three platform mitigations that **do not** apply to this
app because of that value, and one that does. (Use the version matrix in
[§3.2](../README.md#32-version-matrix--when-the-rules-changed).)

**Q2.** Why is the device's SDK level the *less* important of the two numbers you just recorded?

### Step 2 — The mediated surface, from the manifest

```bash
# host
grep -nE "<(activity|activity-alias|service|receiver|provider)" work/AndroidManifest.xml
grep -nE 'android:exported="true"' work/AndroidManifest.xml
grep -nE "<permission |protectionLevel" work/AndroidManifest.xml
grep -nE "grantUriPermissions|path-permission|android:authorities" work/AndroidManifest.xml
grep -n "sharedUserId\|android:process\|taskAffinity\|debuggable" work/AndroidManifest.xml
```

Cross-check, because a crafted APK can make two parsers disagree:

```bash
# host
aapt2 dump xmltree target.apk --file AndroidManifest.xml | grep -B2 -A2 exported
```

**Build inventory table A.** One row per component: type, fully-qualified name, `exported` value
(explicit or inferred), guarding permission, and **the protection level of that permission**.

```bash
# adb shell — resolve a declared permission's protection level on the device
dumpsys package permission com.example.target.permission.INTERNAL | grep -i protection
```

**Q3.** How many components are exported? How many of *those* have no guarding permission, or a
guard whose protection level is `normal` or `dangerous`? That second number is your working list.

**Q4.** Are there components with an `<intent-filter>` but no explicit `android:exported`? What is
their effective state, and what does the answer depend on?

### Step 3 — The mediated surface, from the live device

```bash
# host
adb shell dumpsys package $PKG > pkg.txt
grep -n "exported=true" pkg.txt
adb shell dumpsys activity services $PKG | head -60
adb shell service list > services.txt
```

**Q5.** Does the live `dumpsys` view agree with the manifest? If not, which do you trust and why?

**Q6.** Anything belonging to your target in `service list`? What does its presence or absence tell
you about how the app's own services are reached?

### Step 4 — The channels the manifest cannot show (the point of the lab)

Now go looking for direct IPC. Four categories, four commands.

```bash
# adb shell — 1. abstract-namespace UNIX sockets
cat /proc/net/unix | grep '@'
```

```bash
# adb shell — 2. listening TCP sockets; st==0A means LISTEN
cat /proc/net/tcp | awk 'NR>1 && $4=="0A" {print $2, $8, $10}'
cat /proc/net/tcp6 | awk 'NR>1 && $4=="0A" {print $2, $8, $10}'
netstat -tulpn 2>/dev/null
```

```bash
# adb shell as root — 3. open file descriptors, and shared memory
PID=$(pidof -s com.example.target)
ls -l /proc/$PID/fd
grep -E "ashmem|memfd|dmabuf" /proc/$PID/maps
```

```bash
# adb shell as root — 4. file modes and SELinux labels
ls -ldZ /data/data/com.example.target
ls -laZ /data/data/com.example.target/shared_prefs
find /data/data/com.example.target -type f -perm -o+r 2>/dev/null
```

**Q7.** Decode one line of `/proc/net/tcp` by hand. The `local_address` column is `IP:PORT` with the
IP in **little-endian hex**. What is `0100007F:1F90`? What is `00000000:1F90`, and why is the
difference important?

**Q8.** For each abstract socket you found, what protects it? Answer precisely — name the access
control that applies, or state that none does.

**Q9.** `/proc/net/unix` does not name the owning process. How do you attribute a socket to one?

### Step 5 — Corroborate statically

Everything you found at runtime should have a corresponding call in the code. Everything in the code
should have appeared at runtime — and if it did not, you did not exercise the right feature.

```bash
# host
grep -rn "LocalServerSocket\|LocalSocketAddress\|Namespace.ABSTRACT" out/sources/
grep -rnE "new ServerSocket\(|ServerSocketChannel|NanoHTTPD|MockWebServer" out/sources/
grep -rn "MemoryFile\|SharedMemory\|ashmem\|memfd" out/sources/
grep -rn "MODE_WORLD_READABLE\|MODE_WORLD_WRITEABLE\|setReadable(true, *false)" out/sources/
grep -rn "ClipboardManager\|setPrimaryClip" out/sources/
grep -rn "getCallingUid\|getCallingPid\|clearCallingIdentity" out/sources/
grep -rn "PendingIntent.get\|FLAG_MUTABLE" out/sources/
```

And the native libraries, because the Java layer can be clean while a bundled `.so` opens a socket:

```bash
# host
for so in $(find work/lib -name '*.so' 2>/dev/null); do
  echo "== $so"
  strings -a "$so" | grep -aE "^@[A-Za-z0-9._-]{3,}$|127\.0\.0\.1|0\.0\.0\.0|\.sock|/dev/socket"
  nm -D --defined-only "$so" 2>/dev/null | grep -iE "socket|bind|listen|accept"
done
```

**Q10.** Did the static sweep find any channel the runtime enumeration missed? What would explain
that?

**Q11.** Did the runtime enumeration find any channel the static sweep missed? What would explain
*that*?

### Step 6 — Run the scripted version and compare

```bash
# host
../scripts/enumerate-ipc-surface.sh $PKG ./out-$PKG
python3 ../scripts/ipc-surface-report.py ./out-$PKG/ipc-surface.txt \
        --manifest work/AndroidManifest.xml --md ./out-$PKG/report.md
```

**Q12.** Did the script find anything you missed by hand? Did you find anything it missed? A script
you cannot out-perform on a careful pass is a script you do not understand.

### Step 7 — Watch it happen from inside

```bash
# host
frida -U -f $PKG -l ../scripts/trace-ipc.js
```

Exercise the app: log in, open a media item, open anything that loads a WebView, trigger a sync.
Then in the Frida REPL:

```javascript
ipc.summary()
```

**Q13.** Which channels does the app actually *use*, as opposed to merely *declare*? Did anything
appear here that neither the static nor the runtime sweep found?

### Step 8 — The step that makes it a finding

Everything so far ran as `shell`, UID 2000. Now repeat the key results from an ordinary application.

```bash
# host
cd ../examples/attacker-app
# edit AndroidManifest.xml: put the target in <queries>, including provider authorities
gradle assembleDebug
adb install -r build/outputs/apk/debug/attacker-app-debug.apk
adb logcat -c
adb shell am start -n com.attacker.poc/.ProbeActivity --es target $PKG
adb logcat -s poc:I | tee ../../evidence-probe.txt
```

**Build reachability table B:**

| Channel | Reachable from `adb shell` | Reachable from the probe APK | Verdict |
|---|---|---|---|
| | | | |

**Q14.** How many entries are reachable from the shell but **not** from the app? Those are the false
positives you would have reported. What is the mechanism that explains the difference?

**Q15.** Did the probe app report `ABSENT` for anything you know exists? What is the first thing to
check, before concluding it is unreachable?

### Step 9 — Write it up

For every channel that is genuinely app-reachable, produce: the channel, the exact command or code
that reaches it, the observable result, the identity you used, the device fingerprint and the app's
`targetSdk`.

Then, for **at least one** channel, write the paragraph explaining why it is *not* a finding.

---

## Hints

<details>
<summary>Hint 1 — /proc/net/unix is empty of `@` entries</summary>

Three possibilities, in order of likelihood:

1. The app has not run the code path. Launch it, use it properly for a minute — play something, open
   a WebView, sign in — and look again.
2. You are grepping for the package name. `/proc/net/unix` shows only the socket *name*, and the name
   frequently has nothing to do with the package. Grep for `@` alone and read the whole list.
3. There genuinely are none, which is a legitimate result. Record it.

A before/after diff is the sharpest technique here:

```bash
# adb shell
cat /proc/net/unix > /data/local/tmp/before.txt
# ... use the app feature ...
cat /proc/net/unix > /data/local/tmp/after.txt
diff /data/local/tmp/before.txt /data/local/tmp/after.txt
```
</details>

<details>
<summary>Hint 2 — decoding /proc/net/tcp</summary>

The `local_address` field is `IP:PORT`. The port is straightforward big-endian hex. The IP is
**little-endian**, so you reverse the byte pairs:

```
0100007F  ->  7F 00 00 01  ->  127.0.0.1
00000000  ->  0.0.0.0      ->  ALL INTERFACES
1F90      ->  8080
```

`st` of `0A` is `TCP_LISTEN`; `01` is `ESTABLISHED`. The `uid` column maps back to a package:

```bash
# adb shell
cmd package list packages --uid 10199
```
</details>

<details>
<summary>Hint 3 — `netstat -tulpn` shows no process names</summary>

Process attribution in `netstat` needs privileges that plain `adb shell` may not have on your build.
Use the `uid` column of `/proc/net/tcp` and `cmd package list packages --uid` instead — that route
works unprivileged and is the one to learn.
</details>

<details>
<summary>Hint 4 — the probe APK reports everything ABSENT</summary>

Your `<queries>` block. On API 30+, package visibility filtering makes an undeclared package look
exactly like an uninstalled one: `NameNotFoundException`, `null` from `resolveActivity`,
`ActivityNotFoundException` from `startActivity`, `Unknown URL` from a provider query.

```xml
<queries>
    <package  android:name="com.example.target" />
    <provider android:authorities="com.example.target.provider" />
</queries>
```

Providers need the `<provider>` entry as well as the `<package>` one. Section 0 of the probe's output
tells you which explanation applies — read it first.
</details>

<details>
<summary>Hint 5 — `dumpsys package` output is enormous</summary>

Slice it by resolver table:

```bash
# host
sed -n '/Activity Resolver Table:/,/Receiver Resolver Table:/p' pkg.txt > activities.txt
sed -n '/Receiver Resolver Table:/,/Service Resolver Table:/p'  pkg.txt > receivers.txt
sed -n '/Service Resolver Table:/,/Provider Resolver Table:/p'  pkg.txt > services.txt
sed -n '/Provider Resolver Table:/,/Key Set Manager:/p'         pkg.txt > providers.txt
```
</details>

---

## Solution

<details>
<summary>Answers</summary>

**Q1–Q2.** The app's `targetSdk` decides which mitigations apply; the device's SDK level only decides
which mitigations *exist*. An app targeting API 22 running on Android 14 still gets: implicitly
exported components with intent filters, `MODE_WORLD_READABLE` working rather than throwing, implicit
broadcasts reaching manifest receivers, mutable `PendingIntent` by default, and no package visibility
filtering. Mitigations that apply regardless of `targetSdk` are the ones enforced device-wide, such
as the Android 10+ clipboard focus restriction. Record both numbers; judge with the first.

**Q3–Q4.** A component with an `<intent-filter>` and no explicit `android:exported` is **implicitly
exported** when `targetSdk` ≤ 30. From 31 the attribute is mandatory and the app would not have built
without it, so the ambiguity only exists for older targets. `ContentProvider`s are the special case:
they defaulted to exported even without a filter below `targetSdk` 17. The working list is exported
components whose guard is absent, `normal` or `dangerous` — because any app can hold a `normal`
permission silently and can ask the user for a `dangerous` one.

**Q5.** They should agree, and `dumpsys` — the platform's own view — is authoritative because it is
what `PackageManager` actually enforces. A disagreement between `apktool`, `aapt2` and `dumpsys` is
itself a high-value finding: it means the binary XML was crafted so that different parsers see
different manifests. See [10-APK-Internals](../../10-APK-Internals/README.md).

**Q6.** Almost certainly nothing. `service list` shows services registered with `servicemanager` by
name, which requires SELinux permission an ordinary app does not have. An app's own AIDL services are
not registered there; they are reached with `bindService()` and an explicit component or action. If
your target *does* appear, it is a system or privileged app and you should say so prominently.

**Q7.** `0100007F:1F90` is `127.0.0.1:8080` — loopback. `00000000:1F90` is `0.0.0.0:8080` — **all
interfaces**, so the same server is reachable from the local network as well as from every app on the
device. That difference is often one severity level, and it is invisible unless you decode the field.

**Q8.** *Nothing* protects an abstract socket. It has no inode, no owner, no group and no mode bits;
there is not even a permission to get wrong, and no directory permission applies because it is in no
directory. The only control is SELinux policy, and for app-to-app abstract connections that has
historically been permissive. This is the answer the whole chapter is built around.

**Q9.** By inode. The last-but-one column of `/proc/net/unix` is the socket's inode; `ls -l
/proc/<pid>/fd` shows entries of the form `socket:[12345]`. Match the numbers. This needs root on
modern releases, which is why enumeration and reachability proof are different activities with
different requirements.

**Q10.** A channel in the code but not at runtime means the code path did not execute. Either you did
not exercise the feature, or it is gated behind a build type, a server-side flag, or a device
condition. Never conclude "the code is dead" from one run — check for a `BuildConfig.DEBUG` guard and
whether the class is even referenced.

**Q11.** A channel at runtime but not in your grep means it came from somewhere your grep did not
look: a bundled native library, a third-party SDK in a package you skipped, a dynamically loaded DEX,
or string-encrypted names. This is exactly why the native triage and the Frida pass exist.

**Q12.** The script should broadly match a careful manual pass. If it finds more, you missed
something and should work out what. If you find more, extend the script — that is the correct
direction of travel, and a tool you cannot beat on a careful pass is a tool you are trusting rather
than using.

**Q13.** Frida shows *use*, which the other two methods cannot. Typical surprises: a socket opened by
an SDK you had not noticed, a `sendBroadcast` with no `setPackage`, a `PendingIntent` created without
`FLAG_IMMUTABLE`, or a `setReadable(true, false)`.

**Q14.** The difference is that `adb shell` runs as UID 2000 in the SELinux domain `shell`, while the
probe runs as an app UID in `untrusted_app`. Two mechanisms produce the gap: DAC (the shell user has
different group memberships and can traverse directories an app cannot) and SELinux (policy allows
`shell` to reach types that `untrusted_app` cannot). Every entry that is shell-reachable but not
app-reachable is a false positive you have just avoided reporting.

**Q15.** Check `<queries>` first, every time. Package visibility filtering is the overwhelmingly most
common cause of a spurious `ABSENT`, and its symptoms are indistinguishable from genuine absence
without that check.

</details>

---

## Success criteria

- [ ] You recorded the app's `targetSdk`, the device fingerprint, the patch level and the SELinux mode
- [ ] You produced inventory table A with the **protection level** of every guarding permission
- [ ] You cross-checked the manifest against `aapt2 dump xmltree` and `dumpsys package`
- [ ] You enumerated all four direct-IPC categories: abstract sockets, TCP listeners, FDs and shared
      memory, file modes
- [ ] You decoded at least one `/proc/net/tcp` line by hand and can explain `0100007F` vs `00000000`
- [ ] You attributed at least one socket to a process by matching its inode against `/proc/<pid>/fd`
- [ ] You corroborated the runtime findings against a static sweep, including native libraries, and
      explained every discrepancy in both directions
- [ ] You ran `enumerate-ipc-surface.sh` and `ipc-surface-report.py` and compared against your manual work
- [ ] You ran `trace-ipc.js` and identified at least one channel the app *uses* that you had not found
- [ ] You built and ran the unprivileged probe APK and produced reachability table B
- [ ] You can state how many shell-only entries would have been false positives
- [ ] You wrote at least one paragraph explaining why something is **not** a finding
- [ ] You can answer, in one sentence, why enumeration from `adb shell` never proves reachability
