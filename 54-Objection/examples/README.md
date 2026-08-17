# 54 — Examples

What is here, what it is for, and how the files on disk relate to the paths printed inside
them.

---

## Contents

| File | What it is |
|---|---|
| [`build.sh`](build.sh) | Builds and installs the target app. No Gradle, no network, **out of tree** |
| [`target-app/`](target-app/) | The measuring instrument: five root checks, three inside Objection's canned envelope and two outside it |
| [`01-annotated-session.md`](01-annotated-session.md) | A complete Objection session, annotated line by line, with real output |
| [`02-when-objection-fails.md`](02-when-objection-fails.md) | One task, both tools, and an honest scoreboard |

---

## `target-app/` — the measuring instrument

This is not "a vulnerable app". It is a ruler.

Its five root checks were chosen so that three of them fall inside the three hooks
`android root disable` installs and two fall outside — which makes the coverage boundary
**observable** rather than asserted. Without a target you designed, you cannot tell a check that
was suppressed from a check that never fired, and every claim about a canned tool's coverage
stays folklore.

| Check | What it does | Inside Objection's envelope? |
|---|---|---|
| **A** | `new File("/system/xbin/su").exists()` | **Yes** — the path is one of the thirteen hard-coded strings |
| **B** | `new File("/sbin/magisk").exists()` | **No** — not on the list, and the list is matched by exact string equality |
| **C** | `Runtime.getRuntime().exec("/system/bin/su")` | **Yes** — the single-`String` overload is hooked |
| **D** | `Runtime.getRuntime().exec(new String[]{"/system/bin/which","su"})` | **No** — the array overload is not hooked |
| **E** | `Build.TAGS.contains("test-keys")` | **Yes** — `String.contains` is hooked |

Plus `MainActivity$AuthGate.checkPin(String)` and `checkPin(int)` — a two-overload,
boolean-returning method, which is the simplest thing to demonstrate
`android hooking watch class_method` and `android hooking set return_value` against.

### Design rules it follows, and why they matter

- **One probe per method.** A result is attributable to exactly one check.
- **No short-circuiting.** `evaluate()` runs all five every time. Short-circuiting would let one
  check hide another.
- **Per-check logging** under the tag `CH54`, so `adb logcat -s CH54` gives you a per-check
  result — which is precisely the information `android root disable` does not give you.
- **No networking at all.** No `INTERNET` permission, no HTTP client, no TLS, no pinning.
  Pinning belongs to [36-CertificatePinning](../../36-CertificatePinning/README.md); adding it
  here would make the app larger and the lab result less attributable. It also produces the
  chapter's sharpest measurement: `android sslpinning disable` reports **three successful hooks**
  against this app, which cannot open a socket.
- **Nothing native.** The point being measured is the coverage of a Java-layer canned script, not
  the Java/native boundary. [37 §3.12](../../37-RootDetection/README.md) owns that.

### What it deliberately is *not*

Easier than a real app, in one specific way: `SecurityGate.evaluate()` runs from
`Activity.onCreate`, not from `Application.attachBaseContext` or a static initialiser. A real
hardened app runs its toughest checks earlier than anything an attach-mode session can reach.
[`../labs/lab-04-ctf-the-confident-tool.md`](../labs/lab-04-ctf-the-confident-tool.md) builds
the harder version.

---

## Source layout — flat here, a package tree at build time

The Java sources in `target-app/` are stored **flat**, one annotated file each:

- [`target-app/MainActivity.java`](target-app/MainActivity.java)
- [`target-app/SecurityGate.java`](target-app/SecurityGate.java)
- [`target-app/GateActivity.java`](target-app/GateActivity.java)
- [`target-app/AndroidManifest.xml`](target-app/AndroidManifest.xml)

Their package is `com.pentest.ch54.target`, so `javac` needs them laid out under a matching
directory tree. `build.sh` performs that copy into `$OUTDIR` at build time; nothing in the
repository holds a nested package directory.

The flat layout is deliberate and matches the convention already used by
[`30-Activities/examples/`](../../30-Activities/examples/README.md): the repository stores one
annotated copy of each source, and the build script constructs the tree the compiler wants.

---

## Building and installing

```bash
# host
export ANDROID_HOME=/path/to/Android/Sdk

./build.sh                       # build only
./build.sh --install             # build and install
OUTDIR=/tmp/ch54 ./build.sh --install
./build.sh --uninstall           # remove it from the device
```

The pipeline is `aapt2 link` → `javac --release 8` → `d8` → zip in `classes.dex` → `zipalign` →
`apksigner`, using the newest build-tools and platform `android.jar` it can find. It needs a JDK
and `adb`; it needs no network and no Gradle.

**Everything lands under `$OUTDIR`, outside the repository.** `.apk`, `.dex` and `.class` are on
this repository's artefact blocklist, so the sources ship and the reader builds.

Two environment traps the script already handles, both of which cost real time when they are not
handled:

- **Git Bash paths.** The SDK tools are native Windows binaries and do not understand
  `/c/Users/...`. Every path is passed through `cygpath -w`. Without it, `aapt2` reports
  "failed to load XML file" on a file that plainly exists.
- **`INSTALL_FAILED_USER_RESTRICTED`.** On the MIUI device this chapter was written against,
  `adb install` refuses **any** APK because "Install via USB" is disabled at the vendor level.
  The script detects that exact failure and retries through root, which works. This is an OEM
  policy, not a fault in the APK.

An XML trap the script does **not** handle, because nothing can: an `AndroidManifest.xml`
comment must not contain two consecutive hyphens. `aapt2` rejects the file with
`error: not well-formed (invalid token)` and names a line number that is correct but
unilluminating. The manifest here says so in a comment, having hit it.

---

## Quick start

```bash
# host -- build, install, and see the baseline
export ANDROID_HOME=/path/to/Android/Sdk
./build.sh --install
adb logcat -c
adb shell am start -n com.pentest.ch54.target/.MainActivity
sleep 3 && adb logcat -d -s CH54
```

Expected on a Magisk-rooted device with DenyList active:

```
I CH54: A su-known-path        rooted=false
I CH54: B magisk-unknown-path  rooted=false
I CH54: C exec-su-String       rooted=false
I CH54: D which-su-String[]    rooted=false
I CH54: E build-tags           rooted=false (TAGS=release-keys)
I CH54: VERDICT score=0/5 rooted=false
```

**That baseline is the most important output in the chapter.** A score of 0/5 on a device that is
definitely rooted means Magisk is hiding the artefacts — and it means any root-bypass command you
run next cannot produce an observable change. Success and no-op become indistinguishable. Take
the baseline first, every time.

Then:

```bash
# host -- the canned tool
adb shell am force-stop com.pentest.ch54.target
objection -g com.pentest.ch54.target explore

# host -- the hand-written equivalent, with the reporting the canned one lacks
adb shell am force-stop com.pentest.ch54.target
frida -U -f com.pentest.ch54.target -l ../scripts/root-disable-equivalent.js
```

---

## Clean-up

```bash
# host
./build.sh --uninstall
```

These applications exist to be instrumented. Install them on a device you own, and remove them
when you are finished.

---

## Related

- [`../scripts/objection-doctor.py`](../scripts/objection-doctor.py) — run this before a session
- [`../scripts/split-agent.py`](../scripts/split-agent.py) — read what your canned commands do
- [`../scripts/root-disable-equivalent.js`](../scripts/root-disable-equivalent.js) — the same three hooks, fully reported
- [`../labs/lab-02-objection-versus-a-script.md`](../labs/lab-02-objection-versus-a-script.md) — the comparison, as an exercise
- Chapter README [§3.5](../README.md) — what the three hooks are
