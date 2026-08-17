# Lab 01 — First contact: two APKs and one command

> **Objective.** Build a target application and a test APK from source, without Gradle, install both,
> run `am instrument`, and read the target's private `SharedPreferences`, its private file and one of
> its `private static` fields — then write one of them back and watch the app agree.
>
> **Difficulty.** Beginner. This is the "hello world" of the chapter, and it is deliberately the only
> lab that does not ask you to disbelieve anything.
>
> **Time.** 40–60 minutes the first time, about six after that.

**Prerequisites:** [../README.md §1–§3.8](../README.md) ·
[10 — APK Internals](../../10-APK-Internals/README.md) for what `apksigner` is doing ·
[60 — ADB](../../60-ADB/README.md)

**Authorised testing only.** Both fixtures are purpose-built lab applications shipped as source in
`../examples/`. Install them on a device you own. Remove them at the end; step 9 tells you how.

---

## 0. What you are about to demonstrate

One sentence: **a second installed package can execute code inside the first package's process, at
the first package's UID, without root, without Frida, and without the first package agreeing to
anything.**

Everything else in this chapter is a refinement of that sentence. This lab establishes it.

---

## 1. Set up

### 1.1 Check your toolchain

```bash
# host
javac -version                 # any JDK 8 or newer; 24.0.2 was used here
keytool -help  >/dev/null 2>&1 && echo "keytool ok"
python3 --version              # used for the zip step
adb version
echo "$ANDROID_HOME"
ls "$ANDROID_HOME/build-tools"
ls "$ANDROID_HOME/platforms"
```

You need `aapt2`, `d8`, `zipalign` and `apksigner` under `build-tools`, and one `android.jar` under
`platforms`. If `ANDROID_HOME` is empty, set it — the build script will guess a few standard
locations but it is better to be explicit:

```bash
# host -- Linux/macOS
export ANDROID_HOME="$HOME/Android/Sdk"
# host -- Windows, Git Bash
export ANDROID_HOME="$LOCALAPPDATA/Android/Sdk"
```

### 1.2 Identify the device and record it

Never skip this. Half the surprising results in this repository came from somebody measuring the
wrong device.

```bash
# host
adb devices -l
adb shell getprop ro.product.model
adb shell getprop ro.build.version.sdk
adb shell getprop ro.build.type
adb shell getprop ro.debuggable
```

This lab was authored against:

```
emulator-5554   product:sdk_gphone16k_x86_64  model:sdk_gphone16k_x86_64  device:emu64xa16k
ro.product.model      sdk_gphone16k_x86_64
ro.build.version.sdk  35
ro.build.type         userdebug
ro.debuggable         1
```

Write down what *you* got. Lab 02 depends on `ro.build.type`, and every number you record later
should be attributed to this line.

### 1.3 Take the baseline

```bash
# host
adb shell pm list instrumentation
adb shell pm list packages | wc -l
```

On a stock Android 15 GMS image the first command prints **nothing at all** — measured here, with
247 packages installed. That zero is the point of taking a baseline: after step 3 the same command
prints one row, and you will know exactly where it came from.

---

## 2. Build the fixtures

```bash
# host
cd 66-Instrumentation/examples
OUTDIR=/tmp/ch66 ./build-instrumentation-fixtures.sh
```

Expected tail of the output:

```
=== fixture self-check ===
vault-release      debuggable=0
vault-debuggable   debuggable=1
probe-testonly     testOnly=1
probe-sigA         testOnly=0

signer digests (these must differ between sigA and sigB):
  vault-release    Signer #1 certificate SHA-256 digest: 4b7cce36...
  probe-sigA       Signer #1 certificate SHA-256 digest: 4b7cce36...
  probe-sigB       Signer #1 certificate SHA-256 digest: 7800573a...

done. Artefacts are under /tmp/ch66 -- nothing was written into the repository.
```

Read the self-check block rather than skipping past it. The whole of lab 02 rests on those five
artefacts differing in exactly one bit each, and this is where you confirm they do. `vault-release`
and `probe-sigA` share a digest; `probe-sigB` does not. That is the experimental apparatus.

### 2.1 What the script actually did

Worth understanding once, because you will need it against a real target:

| Stage | Command | Produces |
|---|---|---|
| Resources and manifest | `aapt2 link -I android.jar --manifest ... -o base.apk` | An APK with a binary manifest and no code |
| Compile | `javac --release 8 -classpath android.jar` | `.class` files |
| Dex | `d8 --lib android.jar --min-api 24` | `classes.dex` |
| Package | `python3 -B` writing `classes.dex` into the zip | an unaligned APK |
| Align | `zipalign -f -p 4` | an aligned APK |
| Sign | `apksigner sign --ks ...` | the final APK |

No Gradle anywhere. Gradle does exactly this, plus dependency resolution, plus resource merging,
plus a thousand conveniences. When you need to build a test APK against a target whose build system
you do not have, this six-stage pipeline is what you fall back to.

### 2.2 If `aapt2` complains about a file that plainly exists

Two causes, both recorded in this repository:

- On Git Bash the SDK tools are native Windows binaries and do not understand `/c/Users/...` paths.
  The script routes every path through `cygpath -w`; if you are invoking `aapt2` by hand, do the same.
- An XML comment containing a double hyphen makes `aapt2` reject the file with
  `error: not well-formed (invalid token)` and a line number that points at the comment rather than
  explaining it.

---

## 3. Install and confirm the binding

```bash
# host
adb install -r /tmp/ch66/vault-debuggable.apk
adb install -r /tmp/ch66/probe-sigA.apk
adb shell pm list instrumentation -f
```

Expected:

```
instrumentation:/data/app/~~.../com.pentest.ch66.vault.test-.../base.apk=
    com.pentest.ch66.vault.test/com.pentest.ch66.probe.VaultProbe (target=com.pentest.ch66.vault)
```

Three fields, and the third is the interesting one. `target=com.pentest.ch66.vault` is the binding
from the test APK's manifest, and it is the entire declaration of intent. Nothing in the *target's*
manifest mentions the test package; nothing was asked of it.

> If the install of `probe-sigA` fails with `INSTALL_FAILED_UPDATE_INCOMPATIBLE`, a differently-signed
> copy is already present from a previous run. `adb uninstall com.pentest.ch66.vault.test` first.
>
> If it fails with `INSTALL_FAILED_USER_RESTRICTED`, you are on an OEM device with "Install via USB"
> disabled. That is a vendor policy, not a fault in the APK; the pattern that works on a rooted device
> is `adb push` followed by `adb shell "su -c 'pm install -r /data/local/tmp/x.apk'"`, and note the
> quoting — the outer double quotes are load-bearing.

### 3.1 Look at the target first, the honest way

Start the app normally and see what it says about itself:

```bash
# host
adb shell am start -n com.pentest.ch66.vault/.MainActivity
adb shell pidof com.pentest.ch66.vault
```

The screen shows its pid, uid, `premium=false`, its session token and its data directory. Note the
pid; you will want it in step 6.

Now try to read its data from the shell, which is where most people start:

```bash
# host
adb shell "ls -l /data/data/com.pentest.ch66.vault"
adb shell "cat /data/data/com.pentest.ch66.vault/shared_prefs/vault.xml"
```

Both refused. `adb shell` is uid 2000 and the app's data directory is not its to read. That refusal
is the problem this lab solves.

---

## 4. Run the instrumentation

```bash
# host
adb shell am instrument -w -r \
    com.pentest.ch66.vault.test/com.pentest.ch66.probe.VaultProbe
```

You get about 55 `INSTRUMENTATION_RESULT` lines. Read them in groups.

### 4.1 Group `id.` — who you are

```
id.pid                   17935
id.uid                   10210
id.processName           com.pentest.ch66.vault
id.cmdline               com.pentest.ch66.vault
id.selinux               u:r:untrusted_app:s0:c210,c256,c512,c768
id.contextPackage        com.pentest.ch66.vault.test
id.targetContextPackage  com.pentest.ch66.vault
id.opPackage             com.pentest.ch66.vault
id.targetDataDir         /data/user/0/com.pentest.ch66.vault
id.testDataDir           /data/user/0/com.pentest.ch66.vault.test
```

**Stop and check three of these against step 3.1.** The `pid` is different from the one you noted —
the app was force-stopped and restarted, which lab 03 measures properly. The `uid` is the target's,
not 2000 and not the test package's. `processName` and `cmdline` are the target's, so a `ps` listing
shows nothing unusual at all.

The SELinux context is worth a moment. `u:r:untrusted_app:s0:c210,c256,...` — the domain and the MCS
categories are the *target's*. Work it through with
[22 — SELinux](../../22-SELinux/README.md)'s formula: the app ID is the UID minus `AID_APP`, so
`10210 - 10000 = 210`; the first category is `c[210 & 0xff] = c210` and the second is
`c[256 + (210 >> 8)] = c256`. Do that arithmetic against **your** UID, because the app ID depends on
your device's install history. The invariant to hold on to is that the **first** category can never
exceed `c255` — a value above that means the context was fabricated rather than captured.

### 4.2 Group `read.` — the payload

```
read.prefs.api_key        ch66-APIKEY-3f9a1c
read.prefs.refresh_token  ch66-RT-8b20e5d4
read.prefsXmlBytes        READ:229
read.file.secret          ch66-file-secret-7d41
read.static.sessionToken  sess-7a9a3cf2bb6
read.static.premiumBefore false
```

Three storage shapes, all read. Compare each against the refusal you got in step 3.1 from the shell.
Nothing about the app is misconfigured; `shared_prefs/vault.xml` is mode `0600` under a `0700`
directory exactly as it should be. The difference is entirely who is doing the reading.

The last two lines are the ones people underestimate. `sSessionToken` is a `private static String`
that never touches disk, and `sPremium` is a `private static boolean` — both read by reflection,
because the probe's class loader resolves the target's classes (see §3.7 of the chapter).

### 4.3 Group `write.` — and the app agrees

```
write.setPremium          ok
write.call.isPremiumAfter true
```

`LicenseGate.sPremium` was `false` a moment ago. It was set to `true` by reflection, and then the
app's own `isPremium()` method was **invoked, also by reflection**, and returned `true`. Invoking the
real method rather than re-reading the field matters: it rules out the possibility that you are
looking at your own copy of the value.

### 4.4 Make it readable

Fifty-five lines is a lot to eyeball. The chapter ships a parser:

```bash
# host
adb shell am instrument -w -r \
    com.pentest.ch66.vault.test/com.pentest.ch66.probe.VaultProbe \
  | python3 -B ../scripts/parse-instrumentation-results.py --key read. --key write.
```

```
verdict            PASS
INSTRUMENTATION_CODE -1  (RESULT_OK)
result keys        55
```

> **`INSTRUMENTATION_CODE: -1` means SUCCESS.** It is `android.app.Activity.RESULT_OK`.
> `RESULT_CANCELED` is `0`. Everybody misreads this once; the parser prints the constant name so you
> only misread it once.

---

## 5. See the change on screen

The write in step 4.3 happened inside a process that `finish()` then killed, so it did not persist.
Prove that to yourself, then arrange for it to be visible.

```bash
# host -- the app, started fresh, is back to premium=false
adb shell am start -n com.pentest.ch66.vault/.MainActivity
```

The screen shows `premium = false` again. That is correct and it is the honest limitation of the
technique: **the write lives as long as the process does.** `finish()` kills the process (chapter
§3.13), so an instrumentation that finishes leaves nothing behind.

To see it on screen, the instrumentation has to drive the UI itself while it is still alive. Add this
to `onStart()` in your own copy of the probe, before `finish()`:

```java
// inside onStart(), after the write
try {
    Intent i = new Intent();
    i.setClassName(getTargetContext(), "com.pentest.ch66.vault.MainActivity");
    i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
    Activity a = startActivitySync(i);   // returns the real Activity object
    waitForIdleSync();
    android.os.SystemClock.sleep(4000);  // long enough for you to look at it
} catch (Throwable t) {
    Log.w("ch66probe", "could not drive the UI", t);
}
```

Rebuild, reinstall, re-run, and watch the device: `premium = true`.

> **Why `startActivitySync` and not `startActivity`?** `startActivitySync` blocks until the activity
> is resumed and hands you the actual `Activity` instance — you are in the same process, so there is
> nothing to marshal. It must be called from the instrumentation thread, never from the main looper;
> the framework throws if you get that backwards.
>
> If the activity never appears and the call hangs, check whether the device's keyguard is up.
> Some OEM builds refuse app-originated activity starts while locked, log the refusal at debug level,
> and never tell the caller: `adb shell "dumpsys trust" | grep -o "deviceLocked=[01]"`.

---

## 6. Watch it from the outside

Open a second terminal before the run:

```bash
# host -- terminal 2
adb logcat -c && adb logcat -s ch66seq:I ch66probe:I ActivityManager:I
```

then run the instrumentation again in terminal 1. In terminal 2 you will see, interleaved:

```
I ActivityManager: Force stopping com.pentest.ch66.vault appid=10210 user=0: start instr
I ActivityManager: Killing 14796:com.pentest.ch66.vault/u0a210 (adj 0): stop ... due to start instr
I ch66seq : 1 Application() constructor      t=...
I ch66seq : 2 Application.attachBaseContext  t=...
I ch66seq : 3 ContentProvider.onCreate       t=...
I ch66probe: Instrumentation.onCreate reached at t=...
I ch66seq : 4 Application.onCreate           t=...
I ch66seq : 5 seed complete                  t=...
I ActivityManager: Force stopping com.pentest.ch66.vault appid=10210 user=0: finished inst
```

Two things to take away now and pursue in lab 03. First, the two `Force stopping` lines are emitted
by `system_server`, not by the app, so **an attacker inside the app cannot suppress them** — they are
the best forensic artefact this technique has. Second, look at where `ch66probe` falls in the
`ch66seq` sequence. It is between 3 and 4. That is not where the framework's own documentation says
it should be, and lab 03 makes the measurement properly.

---

## 7. Do it against something of your own

The lab has a fixture so you have a known answer. The skill is transferring it. Take any app **you
own the source of**, or any APK you are permitted to repackage, and:

1. Note its package name: `adb shell pm list packages | grep <something>`.
2. Copy `examples/vault-probe/` to a new directory.
3. Change `package=` in the manifest to `<their.package>.test`.
4. Change `android:targetPackage` to their package name.
5. Change `TARGET_PKG` in `VaultProbe.java` and the class names it reflects on.
6. Sign the test APK **with the same key as the app**. For an app you built, that is your debug or
   release keystore. For an app you are repackaging, re-sign both with a key you generate.
7. Install both and run.

Step 6 is the one that will stop you, and lab 02 is entirely about why.

---

## 8. Success criteria

You have finished this lab when all of the following are true and you can say *why* for each:

- [ ] `pm list instrumentation` printed nothing before the install and one row after it.
- [ ] `id.uid` from the instrumentation is the **target's** UID, not 2000 and not the test package's.
- [ ] `id.processName` and `id.cmdline` are the target's, so the process looks ordinary in `ps`.
- [ ] You read `api_key`, `refresh_token`, the raw `vault.xml` and `files/secret.txt` from inside,
      after being refused all of them from `adb shell`.
- [ ] You read a `private static` field that never touches disk.
- [ ] You set `sPremium` to `true` and the app's own `isPremium()` agreed.
- [ ] You saw the pid change across the run and can name the two `system_server` log lines that
      explain it.
- [ ] You can state, without looking it up, what `INSTRUMENTATION_CODE: -1` means.
- [ ] You can explain why the write did not survive to the next app launch.

---

## 9. Clean up

```bash
# host
cd 66-Instrumentation/examples
./build-instrumentation-fixtures.sh --uninstall

# host -- confirm
adb shell pm list instrumentation          # expect: nothing
adb shell pm list packages | grep ch66     # expect: nothing
```

Nothing was written to `/data/local/tmp`, so there is no residue there to sweep. The build artefacts
are under `$OUTDIR` on the host, outside the repository, and can be deleted or kept.

---

## 10. Hints

<details>
<summary>The build fails with "no classes" from javac</summary>

The script copies `*.java` from the source directory into a package-shaped tree and compiles that.
If you added a file whose `package` declaration does not match the directory the script builds
(`com/pentest/ch66/vault` or `com/pentest/ch66/probe`), `javac` writes the class somewhere the
collector does not look. Keep the package declaration and the script's `pkgpath` argument in step.
</details>

<details>
<summary>am instrument prints "Unable to find instrumentation info for ..."</summary>

The component you named does not match a declared `<instrumentation>` node. Check the exact class
name with `adb shell pm list instrumentation` and copy it from there. `am instrument` will not find a
class that exists in the DEX but is not declared in the manifest — the lookup goes through
`PackageManager`, not through the class loader.
</details>

<details>
<summary>am instrument prints "Unable to instantiate instrumentation"</summary>

Your class needs a **public no-argument constructor**. `ActivityThread.initInstrumentation()` calls
`cl.loadClass(name).newInstance()`. An inner class, a class with only a parameterised constructor, or
a non-public class all fail here.
</details>

<details>
<summary>The command returns instantly and prints nothing useful</summary>

You forgot `-w`. Without it, `am` does not wait, and the instrumentation's results arrive after the
command has exited.
</details>

<details>
<summary>All the read.* values are &lt;absent&gt; or ENOENT</summary>

You are racing the application. `Instrumentation.onCreate()` runs *before*
`Application.onCreate()`, and `onStart()` runs on a separate thread that starts immediately. If you
read the app's storage before the app has written it, you get nothing — and it looks exactly like an
app that stores nothing. The shipped probe waits for a marker the app sets on *exit* from its
`onCreate`. Lab 03 covers this properly, and chapter §11.2 records how this exact mistake produced a
confident wrong answer during the writing of this chapter.
</details>

<details>
<summary>Everything reads, but you wanted to know how the probe found the classes</summary>

`Class.forName(name, true, getContext().getClassLoader())`. The instrumentation context's class
loader has the *target's* loader as its parent, and the target's loader already lists **both** APKs.
Chapter §3.7 measured the whole graph. This is also why you must **not** compile the target's classes
into your test APK: yours would shadow theirs and every static field you read would be your own copy's
default value.
</details>

---

## 11. What to read next

- **[Lab 02 — the gate matrix](lab-02-the-gate-matrix.md)**: prove for yourself which of `debuggable`,
  signature and caller identity actually decides whether step 4 is allowed at all.
- **Chapter [§3.9](../README.md)** for the measured answer, if you want to know before you measure.
- **[65 — Hooking](../../65-Hooking/README.md)** for what to do when the decision you want to change
  is computed rather than stored.
