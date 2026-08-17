# Lab 04 — Build a userdebug AOSP image and trace a module

**Difficulty:** Advanced
**Time:** 1 day of wall-clock time (2–6 hours of it is the build; plan for it)
**Chapter:** [08 — The Android Build System](../README.md) §3.1–§3.6, §4.1–§4.4
**Companion chapter:** [07 — AOSP](../../07-AOSP/README.md)

---

## Objective

Configure, build and boot a `userdebug` AOSP image; trace one module all the way from its `Android.bp`
declaration to the file on the running device; patch that module and get the change onto a running
system with `m snod` in under two minutes.

By the end you will own the single best Android security research environment there is: a device where
you have the source of everything, symbols for everything, root, and a one-minute edit-to-test loop.

---

## Prerequisites

| Requirement | Detail |
|---|---|
| Operating system | Linux (Ubuntu 22.04 LTS or Debian 12 are the well-trodden paths). macOS is possible and painful; Windows requires WSL2 with a **case-sensitive ext4** filesystem. |
| Disk | 400 GB free, on an SSD. The source is ~100 GB; `out/` is 150–250 GB. |
| RAM | 32 GB is comfortable; 16 GB works with `-j` reduced and swap. |
| CPU | More cores is linearly faster. 8 cores ≈ 3–5 hours for a first full build. |
| Network | The initial `repo sync` moves tens of gigabytes. |

```bash
# host — Debian/Ubuntu build dependencies
sudo apt update
sudo apt install -y git-core gnupg flex bison build-essential zip curl \
  zlib1g-dev libc6-dev-i386 x11proto-core-dev libx11-dev lib32z1-dev \
  libgl1-mesa-dev libxml2-utils xsltproc unzip fontconfig python3 \
  python3-pip ccache rsync
```

---

## Part A — Get the source

```bash
# host — install the repo launcher
mkdir -p ~/bin && export PATH=~/bin:$PATH
curl https://storage.googleapis.com/git-repo-downloads/repo > ~/bin/repo
chmod a+x ~/bin/repo

# host — initialise a tree. Cuttlefish (cf) is the virtual reference device:
# it boots on your workstation, needs no hardware, and is fully supported.
mkdir -p ~/aosp && cd ~/aosp
repo init -u https://android.googlesource.com/platform/manifest -b main --depth=1

# host — sync. -c fetches only the current branch; -j tunes parallelism.
repo sync -c -j8 --no-tags --no-clone-bundle
```

> **Hint.** `repo sync` is resumable. If it fails, run it again. Use `--force-sync` if a project's
> working tree diverged.

**Record:** the manifest branch you used and the output of `repo info -o | head`. You need this in any
report that references a source path, because AOSP paths move between releases.

---

## Part B — Configure and build

```bash
# host — from ~/aosp
source build/envsetup.sh
lunch aosp_cf_x86_64_phone-trunk_staging-userdebug
```

**Before building, record what `lunch` actually did:**

```bash
# host
printenv | grep -E "^TARGET_|^ANDROID_|^OUT" | sort
```

**Record:** `TARGET_PRODUCT`, `TARGET_BUILD_VARIANT`, `TARGET_ARCH`, `OUT_DIR`.

```bash
# host — measure the parse phase alone before committing to a full build
time m nothing
```

**Record:** the null-build time. This number is the entire justification for Soong's existence
(§3.5 of [07-AOSP](../../07-AOSP/README.md) and §1 of this chapter). On the pre-Soong Make build the
equivalent took minutes.

```bash
# host — the real build
m -j$(nproc) 2>&1 | tee ~/aosp-build.log
```

Go and do something else. Then:

```bash
# host — what did it produce?
ls -lh out/target/product/vsoc_x86_64/*.img
wc -l out/target/product/vsoc_x86_64/installed-files.txt
du -sh out/
```

---

## Part C — Boot it

```bash
# host
cd ~/aosp
launch_cvd --daemon
adb devices
adb shell getprop ro.build.type          # expect: userdebug
adb shell getprop ro.debuggable          # expect: 1
adb shell getprop ro.secure              # expect: 1
adb root && adb shell id                 # expect: uid=0(root)
```

**Record:** all four outputs. This is the property set that makes a `userdebug` image the research
platform it is — and the same property set that, found on a client's production device, is worth more
than the rest of an engagement (§3.1).

---

## Part D — Trace one module end to end

Pick `libbinder`. It is a good subject because it is central, it has many variants, and you will meet
it again in [25-Binder](../../25-Binder/README.md).

### D1. From the module name to the build file

```bash
# host
source build/envsetup.sh
lunch aosp_cf_x86_64_phone-trunk_staging-userdebug

# the module-info map: name -> path, class, installed location
python3 - <<'PY'
import json
mi = json.load(open("out/target/product/vsoc_x86_64/module-info.json"))
e = mi["libbinder"]
for k in ("path", "class", "installed", "srcs" if "srcs" in e else "path"):
    print(k, "=", e.get(k))
PY
```

**Record:** the source path, the module class, and every installed location.

### D2. Read the declaration

```bash
# host
sed -n '/cc_library_shared/,/^}/p' frameworks/native/libs/binder/Android.bp | head -60
```

**Record:** `srcs`, `shared_libs`, `export_include_dirs`, `sanitize`, `vendor_available`,
`apex_available`, `visibility`, and any `defaults:` you must follow to see the real flags.

### D3. Find the variants Soong created

```bash
# host
ls out/soong/.intermediates/frameworks/native/libs/binder/libbinder/
```

**Record:** how many variant directories exist and what their names encode (architecture, link type,
image, SDK version, sanitizer).

### D4. Find the actual compiler command

```bash
# host — the generated build graph is enormous but greppable
grep -n "libs/binder/Parcel.cpp" out/soong/build.ninja | head -3

# pull out one full command line
awk '/build .*Parcel\.o:/{p=1} p{print} p&&/^$/{exit}' out/soong/build.ninja | head -40
```

**Record:** the clang path (note it is under `prebuilts/`), the full flag list, and which of the
hardening flags from §3.17 are present.

### D5. Find the artefact on the image and on the device

```bash
# host
find out/target/product/vsoc_x86_64/system -name "libbinder.so"
ls -l out/target/product/vsoc_x86_64/symbols/system/lib64/libbinder.so

# host — compare the stripped and unstripped versions
readelf -S out/target/product/vsoc_x86_64/system/lib64/libbinder.so | grep -c debug
readelf -S out/target/product/vsoc_x86_64/symbols/system/lib64/libbinder.so | grep -c debug
nm -C out/target/product/vsoc_x86_64/symbols/system/lib64/libbinder.so | wc -l
```

**Record:** the symbol count in the `symbols/` copy. This is the gift described in §3.6 — load the
unstripped copy into Ghidra and apply its symbols to the on-device binary, and weeks of reversing
collapse into an afternoon.

```bash
# adb shell — the same file on the running device
ls -l /system/lib64/libbinder.so
```

### D6. Draw it

Write the chain out in one line, with real paths:

```
Android.bp declaration
  -> soong_build (build/soong/cc/builder.go)
  -> out/soong/build.ninja rule
  -> clang from prebuilts/clang/...
  -> out/soong/.intermediates/.../libbinder.so   (unstripped)
  -> out/target/product/vsoc_x86_64/symbols/system/lib64/libbinder.so
  -> out/target/product/vsoc_x86_64/system/lib64/libbinder.so   (stripped)
  -> system.img
  -> /system/lib64/libbinder.so on the device
```

---

## Part E — Patch, `snod`, reflash

This is the loop that makes platform research practical.

### E1. Make a visible change

Pick something harmless and observable. For example, add a log line to a frequently called framework
Java method, or to a native function you can trigger. Keep the change trivial — the point is the loop,
not the change.

```bash
# host — rebuild ONLY the module
time m libbinder
```

**Record:** the incremental build time versus the full build time.

### E2. Repack the image without a full build

```bash
# host
time m snod
ls -l out/target/product/vsoc_x86_64/system.img
```

**Record:** the `snod` time. It should be well under two minutes.

### E3. Get it onto the running device

```bash
# host — Cuttlefish: stop, relaunch with the new image
stop_cvd
launch_cvd --daemon
adb wait-for-device && adb root && adb remount

# or, for a single-file change on an already-running device:
adb root && adb remount
adb push out/target/product/vsoc_x86_64/system/lib64/libbinder.so /system/lib64/
adb reboot
```

**Record:** the total wall-clock time from edit to observing the change on the device.

> **⚠️** `m snod` repacks whatever is currently in `out/.../system/`, **without** re-deriving whether
> those files were legitimately produced by the tree. That is exactly why it is fast, and exactly why an
> `out/` directory produced by someone else must be treated as untrusted: it may contain files no source
> in the tree ever produced. See §3.1.

---

## Part F — Read the build's own security surface

```bash
# host — the entire product configuration, in one JSON file
python3 -m json.tool out/soong/soong.variables | head -60

# every shell escape in the tree
grep -rn --include=Android.bp -A6 "genrule\s*{" . 2>/dev/null | grep "cmd:" | head -20

# every app signed with the platform key
grep -rn --include=Android.bp -B6 'certificate: *"platform"' . 2>/dev/null \
  | grep "name:" | head -20

# every privileged app
ls out/target/product/vsoc_x86_64/system/priv-app/

# what signed the framework? (expect the PUBLIC AOSP test key, on your own build)
apksigner verify --print-certs \
  out/target/product/vsoc_x86_64/system/framework/framework-res.apk | head
```

**Record:** the certificate subject on `framework-res.apk`. On your self-built image it will be the
public AOSP test key — which is correct here and a total trust compromise on a shipped product. That
contrast is the lesson.

---

## Success criteria

- [ ] `m nothing` completes and you recorded the null-build time.
- [ ] A `userdebug` Cuttlefish image builds and boots, and `ro.build.type` reports `userdebug`.
- [ ] `adb root` succeeds and you have a root shell.
- [ ] You traced `libbinder` from `Android.bp` to `/system/lib64/libbinder.so` with every intermediate
      path named.
- [ ] You produced the actual clang command line from `build.ninja` and identified its hardening flags.
- [ ] You found the unstripped copy under `symbols/` and compared its symbol count to the shipped one.
- [ ] You made a change, rebuilt one module, ran `m snod`, and observed the change on the device — and
      you recorded the total time.
- [ ] You read `soong.variables` and can state three things about the product configuration from it.
- [ ] You verified what certificate signs `framework-res.apk` on your build and can explain why that
      matters for a shipped device.

---

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `repo sync` fails partway | Resumable — run it again. `--force-sync` if a project diverged. |
| Out of disk during build | `out/` grows to 150–250 GB. Free space or set `OUT_DIR` to another volume. |
| Java version errors | AOSP uses its own `prebuilts/jdk/`. Do not set `JAVA_HOME`; let the build choose. |
| `launch_cvd` cannot start | KVM must be available (`ls /dev/kvm`) and your user must be in the `kvm` group. Nested virtualisation must be enabled if you are in a VM. |
| Build succeeds but the device does not boot | `adb logcat` from the Cuttlefish console, and check `out/.../installed-files.txt` for the file you expected. |
| SELinux denials after a partial flash | Precompiled policy hash mismatch — see the "Under the Hood" note in §3.4. |

---

## Discussion questions

1. `m nothing` measures the parse phase. Explain, from §3.5, why that number was minutes before Soong
   and is seconds now, and what design decision bought that.
2. Your build's `framework-res.apk` is signed with the public AOSP test key. Describe, concretely, what
   an attacker could do on a *shipped* device with that property.
3. `m snod` skips dependency derivation. Give a scenario where that makes an `out/` directory you were
   handed by a vendor dangerous to trust.
4. You now have `symbols/` for every binary on the device. Write down the exact workflow you would use
   to apply those symbols to a *different*, stripped, vendor-supplied binary from the same device.
   (What would make it work, and what would make it fail?)
