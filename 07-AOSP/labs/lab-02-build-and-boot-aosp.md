# Lab 02 — Build and boot AOSP

**Difficulty:** Intermediate
**Time:** one day of wall-clock time (2–6 hours of it is the build; plan around it)
**Chapter:** [07 — AOSP](../README.md) §3.2, §3.9
**Companion:** [08-Build-System](../../08-Build-System/README.md) for what `m` actually does

---

## Objective

Sync a pinned AOSP tree, build a `userdebug` Cuttlefish image, boot it, and end the day with a research
device where you have root, matching source, full symbols, and a one-minute patch-test loop — plus a
recorded pinned manifest so you can rebuild exactly this image again next month.

---

## Prerequisites

| Requirement | Detail |
|---|---|
| OS | Linux. Ubuntu 22.04 LTS or Debian 12 are the well-trodden paths. macOS is possible and painful. Windows needs WSL2 with a **case-sensitive ext4** filesystem — an NTFS mount will fail in confusing ways hours in. |
| Disk | **400 GB free, on an SSD.** Source ~100 GB with `--depth=1`; `out/` grows to 150–250 GB. |
| RAM | 32 GB comfortable. 16 GB works with reduced `-j` and swap; below that, do not. |
| CPU | Scales nearly linearly. 8 cores ≈ 3–5 hours for a first build. |
| Network | The initial sync moves tens of gigabytes. |
| KVM | Required for Cuttlefish: `ls /dev/kvm` must exist and your user must be in the `kvm` group. In a VM, nested virtualisation must be enabled. |

```bash
# host — Debian/Ubuntu build dependencies
sudo apt update
sudo apt install -y git-core gnupg flex bison build-essential zip curl \
  zlib1g-dev libc6-dev-i386 x11proto-core-dev libx11-dev lib32z1-dev \
  libgl1-mesa-dev libxml2-utils xsltproc unzip fontconfig python3 \
  python3-pip ccache rsync

# host — check KVM
ls -l /dev/kvm && groups | grep -q kvm && echo "KVM OK" || \
  echo "Add yourself to the kvm group and re-login"
```

---

## Part A — Get the source

### A1. Install `repo`

```bash
# host
mkdir -p ~/bin && export PATH=~/bin:$PATH
curl https://storage.googleapis.com/git-repo-downloads/repo > ~/bin/repo
chmod a+x ~/bin/repo
repo --version
```

Add the `PATH` line to your shell profile.

### A2. Choose a release and initialise

```bash
# host
mkdir -p ~/aosp/android-15.0.0_r1 && cd ~/aosp/android-15.0.0_r1
repo init -u https://android.googlesource.com/platform/manifest \
          -b android-15.0.0_r1 --depth=1
```

> **Why a release tag rather than `main`?** Because you will spend the next month comparing this tree
> against devices, and devices ship releases. `main` moves daily. See §3.1.

### A3. Read the manifest *before* syncing

This is the step that makes the difference between running a command and understanding a tree.

```bash
# host
cat .repo/manifests/default.xml | head -40
grep -c "<project" .repo/manifests/default.xml
grep "<remote" .repo/manifests/default.xml
grep "<default" .repo/manifests/default.xml
ls .repo/manifests/
```

**Record:**
- How many projects are in the manifest.
- Every `<remote>` and its `fetch` URL.
- The `<default revision=...>` — is it a mutable branch name or an immutable tag?
- Every `<include>`, and what each included manifest adds.

> **🔍** On a *vendor* tree, this is where you find projects fetched from a chipset vendor's server, and
> `.repo/local_manifests/` is where you find whatever the vendor added locally. See §3.2.

### A4. Sync

```bash
# host
time repo sync -c -j$(nproc) --no-tags --no-clone-bundle
```

| Flag | Effect |
|---|---|
| `-c` | Fetch only the current branch — much less data |
| `-j N` | Parallel fetches |
| `--no-tags` | Skip tags — smaller |
| `--no-clone-bundle` | Skip the bundle optimisation; often faster on good connections |

`repo sync` is **resumable**. If it fails, run it again. Use `--force-sync` if a project diverged.

### A5. Pin what you synced

**Do not skip this.** It is the step that makes any later finding reproducible.

```bash
# host
repo manifest -r -o pinned-$(date +%F).xml
sha256sum pinned-$(date +%F).xml
head -20 pinned-$(date +%F).xml
```

**Record:** the SHA-256, and note the difference between this file and
`.repo/manifests/default.xml` — every `<project>` now carries an explicit `revision` that is a commit
SHA. This file is the only precise answer to "which source did you test against?", and it belongs
attached to any finding that cites AOSP.

### A6. Look around

```bash
# host
du -sh .
ls
repo info -o | head -20
git -C frameworks/base log --oneline -3
git -C art log --oneline -3
```

**Record:** the checkout size, and confirm that each directory really is an independent git repository.

---

## Part B — Configure and build

### B1. Set up the environment

```bash
# host
source build/envsetup.sh
hmm                                # lists every function envsetup defined
```

**Record:** what `m`, `mm`, `mma`, `croot` and `godir` do. You will use `m` and `croot` constantly.

### B2. `lunch`

```bash
# host
lunch                              # interactive menu
# or directly:
lunch aosp_cf_x86_64_phone-trunk_staging-userdebug
```

**Immediately record what it changed:**

```bash
# host
printenv | grep -E "^TARGET_|^ANDROID_|^OUT" | sort
```

**Record:** `TARGET_PRODUCT`, `TARGET_BUILD_VARIANT`, `TARGET_ARCH`, `TARGET_RELEASE`, `OUT_DIR`.

**Then answer:** the target name has three parts. What does each select, and what would change if you
had chosen `-user` instead of `-userdebug`? (§3.9 has the table.)

### B3. Measure the parse phase

```bash
# host
time m nothing
```

**Record:** the wall-clock time. This is the "null build" — Soong and Kati parse every build file and
produce the Ninja graph, and nothing is compiled.

**Then answer:** why is this number the entire justification for Soong's existence? (See
[08-Build-System §1](../../08-Build-System/README.md#1-introduction) — the pre-Soong equivalent took
minutes.)

`m nothing` also validates every `Android.bp` in the tree, which makes it the right first command after
any build-file change.

### B4. Build

```bash
# host
time m -j$(nproc) 2>&1 | tee ~/aosp-build-$(date +%F).log
```

Go and do something else. When it finishes:

```bash
# host
grep -ciE "warning|error" ~/aosp-build-*.log
du -sh out/
ls -lh out/target/product/vsoc_x86_64/*.img
wc -l out/target/product/vsoc_x86_64/installed-files.txt
```

**Record:** build time, `out/` size, the images produced and their sizes, and the number of files in the
image.

---

## Part C — Explore `out/`

Do this **before** booting. It is where a great deal of the value is, and people skip straight to the
device.

### C1. The product configuration, in one file

```bash
# host
python3 -m json.tool out/soong/soong.variables | head -80
python3 -m json.tool out/soong/soong.variables | grep -iE "debuggable|eng|selinux|sanitize|vndk|Aml"
```

**Record:** three things about the product configuration you can state from this file alone.

> **🔍** On an unfamiliar vendor tree, this file answers in thirty seconds what would otherwise be an
> hour of Makefile archaeology. See §3.9.

### C2. Symbols

```bash
# host
ls out/target/product/vsoc_x86_64/symbols/system/lib64/ | head -20
ls out/target/product/vsoc_x86_64/symbols/system/bin/ | head -20

# compare stripped against unstripped
nm -C out/target/product/vsoc_x86_64/system/lib64/libbinder.so 2>/dev/null | wc -l
nm -C out/target/product/vsoc_x86_64/symbols/system/lib64/libbinder.so | wc -l
readelf -S out/target/product/vsoc_x86_64/symbols/system/lib64/libbinder.so | grep -c debug
```

**Record:** the two symbol counts. Then answer: **why is this directory worth asking a client for
whenever they hand you a device and have a build tree?**

### C3. `module-info.json`

```bash
# host
python3 - <<'PY'
import json
mi = json.load(open("out/target/product/vsoc_x86_64/module-info.json"))
print("modules:", len(mi))
e = mi["libbinder"]
for k in ("path", "class", "installed"):
    print(k, "=", e.get(k))
PY
```

**Record:** how many modules there are, and what `module-info.json` lets you answer instantly that is
otherwise genuinely hard on an unfamiliar image.

### C4. The inventory

```bash
# host
grep -c "" out/target/product/vsoc_x86_64/installed-files.txt
grep "priv-app" out/target/product/vsoc_x86_64/installed-files.txt | head -20
```

---

## Part D — Boot it

```bash
# host
launch_cvd --daemon --cpus 4 --memory_mb 8192
adb wait-for-device
adb devices
```

The web UI is at <https://localhost:8443> — screen, input, and the serial console.

### D1. Confirm the variant

```bash
# adb shell
getprop ro.build.type
getprop ro.debuggable
getprop ro.secure
getprop ro.build.fingerprint
getenforce
```

**Record all five.** Then answer: which of these would be different on a `user` build, and why does
finding `userdebug` on a *production* device matter so much? (§3.9 and §5.2.)

### D2. Get root

```bash
# host
adb root
adb shell id
adb remount
adb shell touch /system/RESEARCH_MARKER && adb shell ls -l /system/RESEARCH_MARKER
adb shell rm /system/RESEARCH_MARKER
```

**Record:** that `/system` is writable. Compare with what it takes to achieve the same on a retail
device (Magisk, an unlocked bootloader, and third-party code in your trusted computing base).

### D3. Explore the running system

```bash
# adb shell
service list | wc -l
service list | head -30
dumpsys -l | head -20
pm list packages -s | wc -l
pm list packages --apex-only
ps -A | grep system_server
```

**Record:** the number of registered services. **Save this list** — it is the baseline you will diff OEM
devices against for the rest of your career:

```bash
# host
adb shell service list | awk '{print $2}' | tr -d ':' | sort -u \
  > ~/aosp/baseline-services-android15.txt
wc -l ~/aosp/baseline-services-android15.txt
```

### D4. Confirm what is missing

```bash
# adb shell
pm list packages | grep -i "com.google.android.gms"
pm list packages | grep -i "com.android.vending"
```

**Record:** both are absent. Then write one paragraph on what that means for testing an application on
this image, and what class of conclusion you must **not** draw here. (§1.5.)

---

## Part E — The fast loop

The point of all this is the iteration speed. Prove it.

### E1. Make a trivial, visible change

Pick something harmless. For example, add a log line to a framework method you can trigger easily.

```bash
# host
croot
vim frameworks/base/core/java/android/os/Binder.java
```

Keep the change trivial — the point is the loop, not the change.

### E2. Rebuild only what changed

```bash
# host
time m framework
```

**Record:** the incremental build time versus the full build time.

### E3. Repack the image

```bash
# host
time m snod
ls -l out/target/product/vsoc_x86_64/system.img
```

**Record:** the `snod` time. It should be well under two minutes.

### E4. Reflash and observe

```bash
# host
stop_cvd
launch_cvd --daemon
adb wait-for-device && adb root
adb logcat -s <your-tag>
```

**Record:** the total wall-clock time from edit to observing the change.

> **⚠️** `m snod` repacks whatever is in `out/.../system/` **without** re-deriving whether those files
> were legitimately produced by the tree. That is why it is fast — and why an `out/` directory produced
> by someone else must be treated as untrusted. See §3.9.

---

## Part F — Record the environment

```bash
# host
{
  echo "AOSP tag       : android-15.0.0_r1"
  echo "lunch target   : aosp_cf_x86_64_phone-trunk_staging-userdebug"
  echo "pinned manifest: pinned-$(date +%F).xml"
  echo "  sha256       : $(sha256sum pinned-$(date +%F).xml | cut -d' ' -f1)"
  echo "host           : $(uname -a)"
  echo
  grep -E "^ro\.build\.(fingerprint|id|type|version\.(release|sdk|security_patch))=" \
       out/target/product/vsoc_x86_64/system/build.prop
} > BUILD-RECORD-$(date +%F).txt

cat BUILD-RECORD-$(date +%F).txt
```

[`../examples/05-research-env/setup.sh`](../examples/05-research-env/setup.sh) automates this whole lab,
including the record. Read it once you have done it by hand — automating a process you have not
performed manually teaches nothing.

---

## Success criteria

- [ ] A pinned manifest exists and you can explain what it pins and why.
- [ ] You recorded the null-build time and can explain why that number justifies Soong.
- [ ] A Cuttlefish image builds and boots.
- [ ] `ro.build.type` reports `userdebug`, `ro.debuggable` is 1, and `getenforce` reports `Enforcing`.
- [ ] `adb root` and `adb remount` work, and you wrote a file to `/system`.
- [ ] You saved a baseline `service list` for diffing against OEM devices later.
- [ ] You confirmed GMS is absent and wrote down what conclusions that forecloses.
- [ ] You completed one edit → `m <module>` → `m snod` → reboot loop and recorded the time.
- [ ] You have a build record file pairing the pinned manifest with the resulting fingerprint.

---

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `repo sync` fails partway | Resumable. Run it again. `--force-sync` if a project diverged. |
| Out of disk mid-build | `out/` reaches 150–250 GB. Free space, or set `OUT_DIR` to another volume. |
| Java version errors | AOSP uses its own `prebuilts/jdk/`. **Unset `JAVA_HOME`** and let the build choose. |
| `ninja: error: ... missing and no known rule` | Usually an incomplete sync. `repo sync` again, then `m installclean`. |
| `launch_cvd` fails immediately | `ls /dev/kvm`; check group membership; check nested virtualisation if you are in a VM. |
| Device boots to a black screen | `adb logcat` from another terminal, and check the Cuttlefish web UI's serial console. |
| Build succeeds but a file is not on the image | Check `installed-files.txt` and `module-info.json` — the module may not be in `PRODUCT_PACKAGES`. |
| SELinux denials after a partial flash | Precompiled policy hash mismatch; see the note in [08-Build-System §3.4](../../08-Build-System/README.md). |
| Case-insensitive filesystem errors (macOS/WSL) | AOSP requires a case-sensitive filesystem. Create one. |

---

## Discussion questions

1. `m nothing` measures parsing only. Explain, from [08-Build-System](../../08-Build-System/README.md),
   why this took minutes before Soong and seconds now, and what design decision bought that.
2. You now have `symbols/` for every native binary. Write down the exact workflow for applying those
   symbols to a *different*, stripped, vendor-supplied binary from a real device — and say what would
   make it work and what would make it fail.
3. Compare this environment with a rooted retail phone running Magisk. List three things this gives you
   that Magisk cannot, and one thing Magisk gives you that this cannot.
4. What certificate signs `framework-res.apk` on the image you just built? Check it, then explain what
   it would mean to find the same certificate on a device you bought in a shop.
   ```bash
   apksigner verify --print-certs \
     out/target/product/vsoc_x86_64/system/framework/framework-res.apk | head
   ```
